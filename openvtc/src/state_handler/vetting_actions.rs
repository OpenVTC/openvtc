//! The Vetting page: applying to be vetted, and vetting others
//! (`docs/design/vetting-process.md` §12).
//!
//! State and sequencing live in `openvtc_core::vetting`. This module maps the
//! page's actions onto the book, signs what has to be sent on the loop (the
//! keys are local, so signing is quick), and hands the send itself to a
//! background job. A send that fails puts the book back the way it was, so the
//! step can simply be tried again.

use std::future::Future;
use std::sync::Arc;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use chrono::{DateTime, Utc};
use openvtc_core::config::Config;
use openvtc_core::config::account::PersonaId;
use openvtc_core::config::community_context::{self, ContextKind, ContextOption};
use openvtc_core::config::context_path::parse_sub_context_id;
use openvtc_core::didcomm::Messaging;
use openvtc_core::persona::claim_types::Registry;
use openvtc_core::persona::disclosure::{self, PresentError};
use openvtc_core::persona::pool::PoolAttribute;
use openvtc_core::persona::{binding, pool, profile};
use openvtc_core::vetting::VettingBook;
use openvtc_core::vetting::applicant::{
    Application, ChosenFace, GrantStatus, NextStep, RequestDraft, RequestState, SentCard,
    VetterEligibility, VettingPath,
};
use openvtc_core::vetting::book::{
    Adopted, CriterionPaths, DrawHold, FALLBACK_REQUIRED_CLAIMS, HiddenOutlook, HiddenVetterState,
    RequestVetting,
};
use openvtc_core::vetting::mode::{ModeFailure, VetterMode, age_words};
use openvtc_core::vetting::queries::{
    CommunityAnswer, CommunityQuery, QUERY_TIMEOUT, QueryKind, refusal_words, request_refusal_words,
};
use openvtc_core::vetting::registry::{
    EventDraft, ProfileDraft, ProfileState, VetterProfileRecord, listed_event_line,
    listed_location_line,
};
use openvtc_core::vetting::status::GrantCheck;
use openvtc_core::vetting::tickets::{DEFAULT_VALIDITY, Ticket};
use openvtc_core::vetting::vetter::{Attestation, DeskState};
use openvtc_core::vetting::wire::{self, Document};
use serde_json::Value;
use vta_sdk::client::VtaClient;
use vta_sdk::protocols::vetting::{
    VETTING_DECLINE_TYPE, VETTING_REQUEST_TYPE, VETTING_REVOKE_STATEMENT_TYPE,
    VETTING_SESSION_RESPONSE_TYPE, VETTING_SESSION_TYPE, VettingMethod, VettingRequirements,
    documentation, request, session, vetters,
};
use vta_sdk::trust_task_proof::TrustTaskVmResolver;
use vta_sdk::vetting::card::sign_card;
use vta_sdk::vetting::requirements::{Evaluation, Need};
use vta_sdk::vetting::statement::sign_statement;
use vta_sdk::vetting::status::StatusCheck;

use crate::state_handler::actions::VettingAction;
use crate::state_handler::background_dispatch::{self, DispatchDomain, DispatchOutcome, InFlight};
use crate::state_handler::dispatch_util::{self, Persist, SyncLog};
use crate::state_handler::join_flow;
use crate::state_handler::main_page::content::{
    ApplicationRow, AttestForm, CardPreview, DECLINE_MESSAGE_MAX, DECLINE_REASONS,
    DIRECTORY_FIELDS, DIRECTORY_LABELS, DIRECTORY_METHODS, DeskRow, DeskStage, DeskView,
    DirectoryCommunity, DirectoryView, EVENT_FIELDS, EVENT_LABELS, EventForm, EventOffer,
    FaceChoice, HiddenVettingRow, IssuedRow, JourneySteps, JourneyTarget, JourneyView, LineTone,
    ListedVetterRow, NewFaceForm, NewFaceStep, PROFILE_FIELDS, PROFILE_LABELS, PendingTicket,
    PoolRow, RequestRow, TicketRow, VETTING_METHODS, VETTING_RELATIONSHIPS, VETTING_TICKET_USES,
    VETTING_WITHDRAWAL_REASONS, VetterProfileForm, VetterStandingRow, VettingMembership,
    VettingMode, VettingPersona, VettingState, VettingTab, decline_reason_words, method_label,
    row_of,
};
use crate::state_handler::main_page::menu::MainMenu;
use crate::state_handler::main_page::{sanitize_display, shorten_did};
use crate::state_handler::runtime_actions::ActionCtx;
use crate::state_handler::save_coalesce::SaveScheduler;
use crate::state_handler::state::State;

// ============================================================================
// Config → display
// ============================================================================

/// A grant's standing in a few words.
///
/// The three cases say different things on purpose. `until <date>` is the
/// answer to "am I a vetter, and for how long" — the question the page exists
/// to answer and could not before. "expires in N days" is a prompt to ask for
/// it again while there is still time. "expired" is the explanation for a desk
/// that has gone quiet: requests made to a lapsed vetter are refused at the
/// applicant's end, so nothing arrives to hint at it.
fn grant_standing(
    standing: &openvtc_core::vetting::book::VetterStanding,
    now: DateTime<Utc>,
) -> String {
    let Some(until) = standing.valid_until else {
        // A grant with no `validUntil` is never live (`VetterGrant::is_live`),
        // so it is a credential that does nothing. Say that, rather than
        // leaving a blank where a date belongs.
        return "no expiry date — the community must reissue it".to_string();
    };
    if !standing.live {
        return format!("expired {}", until.format("%Y-%m-%d"));
    }
    if standing.expiring {
        let days = until.signed_duration_since(now).num_days();
        return match days {
            0 => format!("expires today, {}", until.format("%Y-%m-%d")),
            1 => format!("expires tomorrow, {}", until.format("%Y-%m-%d")),
            n => format!("expires in {n} days, {}", until.format("%Y-%m-%d")),
        };
    }
    format!("until {}", until.format("%Y-%m-%d"))
}

/// What a community holds of our vetter profile.
fn profile_standing(state: Option<&openvtc_core::vetting::registry::ProfileState>) -> String {
    use openvtc_core::vetting::registry::ProfileState;
    match state {
        None => "no profile sent".to_string(),
        Some(ProfileState::Sent { .. }) => "sent, no answer yet".to_string(),
        Some(ProfileState::Stored { listed: true, .. }) => "listed in the directory".to_string(),
        Some(ProfileState::Stored { listed: false, .. }) => "kept, not listed".to_string(),
        Some(ProfileState::Refused { code, .. }) => format!("refused: {code}"),
    }
}

/// A moment in words, as near as the reader needs it: the time alone today, the day and time
/// otherwise. UTC, as every hidden-vetting time on the page is.
pub(crate) fn when_words(at: DateTime<Utc>, now: DateTime<Utc>) -> String {
    if at.date_naive() == now.date_naive() {
        at.format("%H:%M UTC").to_string()
    } else {
        at.format("%a %d %b %H:%M UTC").to_string()
    }
}

/// Where a vetter stands for PCS ZKP attesting at one community, in one line: the tokens it
/// holds and when that changes — "3 tokens — next drip due Wed 07 Oct 00:00 UTC", "0 tokens —
/// the community has not answered; asking again at 15:31 UTC". From the engine and the book as
/// they are; nothing is estimated.
pub(crate) fn outlook_words(o: &HiddenOutlook, now: DateTime<Utc>) -> String {
    let tokens = |n: usize| format!("{n} token{}", if n == 1 { "" } else { "s" });
    if o.rekeyed {
        return format!(
            "{} — drawing stopped: the community publishes new keys (h for details)",
            tokens(o.usable)
        );
    }
    if !o.enrolled {
        // A short status: this line sits in the desk header and on the attest form, and the
        // full story is told once — where it is acted on ([`outlook_detail`]).
        return if o.enrolment_lost {
            "not enrolled — the community's answer to your enrolment was lost (h for details)"
                .to_string()
        } else if o.asking {
            "not enrolled yet — asking the community now".to_string()
        } else if let Some(at) = o.retry_at.filter(|_| o.unanswered > 0) {
            format!(
                "not enrolled yet — the community has not answered; asking again at {}",
                when_words(at, now)
            )
        } else if o.last_refusal.is_some() {
            "not enrolled — the community refused your enrolment (h for details)".to_string()
        } else {
            "not enrolled yet — enrolling now (k to get tokens)".to_string()
        };
    }
    let next = if o.asking {
        "drawing now".to_string()
    } else if let Some(at) = o.retry_at {
        if o.unanswered > 0 {
            format!(
                "the community has not answered; asking again at {}",
                when_words(at, now)
            )
        } else {
            format!("asking again at {}", when_words(at, now))
        }
    } else if let Some(at) = o.next_window {
        format!("next drip due {}", when_words(at, now))
    } else {
        "no drip scheduled — the community publishes no label for this month yet".to_string()
    };
    format!("{} — {next}", tokens(o.usable))
}

/// The whole of why a vetter that is not enrolled cannot attest, when the short line
/// ([`outlook_words`]) leaves out something it can act on: an enrolment whose answer was lost,
/// or one the community refused. `name` is the community's display name.
pub(crate) fn outlook_detail(o: &HiddenOutlook, name: &str, now: DateTime<Utc>) -> Option<String> {
    if o.enrolled {
        return None;
    }
    if o.enrolment_lost {
        return Some(lost_enrolment_words(name, o.owed.as_deref(), now));
    }
    o.last_refusal.as_ref().map(|r| {
        format!(
            "{name} refused your enrolment: {}",
            openvtc_core::vetting::hidden::refusal_words(&sanitize_display(&r.code, 120))
        )
    })
}

/// An enrolment the community made and this client could not open, in full: why it cannot be
/// recovered, when the vetter can attest again, and what to do until then.
///
/// Said once the schedule has asked again under the label and been refused that too: a
/// community may re-issue a lost answer to the identifier it enrolled (VTI #1972), and one that
/// refuses (`alreadyEnrolled`) does not, or has re-issued as often as it will. `k` asks once
/// more. The community's labels do not roll over by themselves either; its admins publish each
/// one, so the date is the soonest the next can start.
pub(crate) fn lost_enrolment_words(name: &str, period: Option<&str>, now: DateTime<Utc>) -> String {
    let label = period.map_or_else(
        || "its current label".to_string(),
        |p| format!("vetter/{p}"),
    );
    let next = match period.and_then(openvtc_core::vetting::mode::next_monthly_label) {
        Some((next, starts)) if starts > now.date_naive() => format!(
            "the next monthly one, vetter/{next}, can start on {} at the earliest, and only once \
             its admins publish it",
            starts.format("%a %d %b %Y")
        ),
        _ => "its admins have not published the next one yet".to_string(),
    };
    format!(
        "{name} already enrolled you under {label}, but this client lost the answer before it \
         could be opened, and it refused to issue it again (k asks once more). You can attest there once it enrols \
         you under a new label: {next}. To unblock \
         you today, ask its operator to publish hidden vetting again with a new live period \
         first in livePeriods (for example {}) — then press k on the desk to enrol and draw at once. \
         Meanwhile you can still vet for communities that name their vetters",
        period.map_or_else(|| "a new period".to_string(), |p| format!("{p}b"))
    )
}

/// Whether running the schedule now would bring tokens nearer: an enrolment to ask for, or a
/// window that has begun and is not drawn. Not when the enrolment was lost, the keys changed,
/// or this window is drawn already — then [`get_tokens_words`] says until when.
pub(crate) fn tokens_obtainable_now(
    book: &VettingBook,
    community: &str,
    persona: PersonaId,
    now: DateTime<Utc>,
) -> bool {
    let (Some(held), Some(o)) = (
        book.hidden_vetter(community, persona),
        book.hidden_outlook(community, persona, now),
    ) else {
        return true;
    };
    if o.rekeyed || o.enrolment_lost {
        return false;
    }
    !o.enrolled
        || held
            .clone()
            .plan(book.hidden_published.get(community), &[], now)
            .owed
            .iter()
            .any(|d| matches!(d, openvtc_core::vetting::hidden::Due::Draw { .. }))
}

/// Where getting tokens at one community stands, as the end of a sentence: what the schedule
/// will do now — enrol, draw the ticks that have begun — or exactly what blocks it and until
/// when. Said by `k` (get tokens) and by `t` when it cannot issue a ticket.
///
/// It never promises a draw ahead of the schedule: a tick is a window of time the community
/// publishes, served once, and every tick that has begun is drawable at once — a new vetter's
/// first allocation is the current window's, as soon as it is enrolled.
pub(crate) fn get_tokens_words(
    book: &VettingBook,
    community: &str,
    persona: PersonaId,
    name: &str,
    now: DateTime<Utc>,
) -> String {
    let (Some(held), Some(o)) = (
        book.hidden_vetter(community, persona),
        book.hidden_outlook(community, persona, now),
    ) else {
        return "enrolling you now; your first tokens are drawn the moment it answers".to_string();
    };
    let tokens = |n: usize| format!("{n} token{}", if n == 1 { "" } else { "s" });
    if o.rekeyed {
        return format!(
            "{name} now publishes different hidden-vetting keys, so drawing has stopped — ask \
             it whether it re-keyed (h for details)"
        );
    }
    if !o.enrolled {
        if o.enrolment_lost {
            return lost_enrolment_words(name, o.owed.as_deref(), now);
        }
        if o.asking {
            return "your enrolment is on its way; your first tokens are drawn the moment it is \
                    answered"
                .to_string();
        }
        if let Some(at) = o.retry_at {
            return format!(
                "{name} has not answered your enrolment; asking again at {}, and drawing straight \
                 after",
                when_words(at, now)
            );
        }
        // Refused last time, for a reason the vetter may have to act on: said in its words.
        if let Some(refused) = outlook_detail(&o, name, now) {
            return format!("{}; asking again now", clause(&refused));
        }
        return "enrolling you now; your first tokens are drawn the moment it answers".to_string();
    }
    if o.asking {
        return format!("a draw is on its way ({} usable now)", tokens(o.usable));
    }
    if let Some(DrawHold::Disagrees {
        asked, published, ..
    }) = held.draw_hold(false, now)
    {
        return format!(
            "{name} refused {asked} tokens a tick as more than it issues, yet still publishes \
             {published}, so drawing has stopped until it publishes a rate it serves ({} usable \
             now) — ask its operator",
            tokens(o.usable)
        );
    }
    if let Some(at) = o.retry_at {
        return format!(
            "{name} has not answered; asking again at {} ({} usable now)",
            when_words(at, now),
            tokens(o.usable)
        );
    }
    let owed = held
        .clone()
        .plan(book.hidden_published.get(community), &[], now)
        .owed
        .iter()
        .filter(|d| matches!(d, openvtc_core::vetting::hidden::Due::Draw { .. }))
        .count();
    if owed > 0 {
        return format!(
            "drawing {owed} window{} of tokens now ({} usable already)",
            if owed == 1 { "" } else { "s" },
            tokens(o.usable)
        );
    }
    match o.next_window {
        Some(at) => format!(
            "this window's tokens are already drawn ({} usable); the next window opens {}",
            tokens(o.usable),
            when_words(at, now)
        ),
        None => format!(
            "{} usable, and {name} publishes no token label to draw under yet",
            tokens(o.usable)
        ),
    }
}

/// `text` as a clause to continue a sentence: without the full stop it may end with, so a
/// composed message never reads "label.. A ticket".
fn clause(text: &str) -> &str {
    text.trim_end().trim_end_matches('.')
}

/// Whether `community` hides its vetters now, as its last-read manifest says
/// ([`VettingBook::vetter_mode`]). An engine we hold for it is not evidence: it says we enrolled
/// once, not that the community still counts proofs.
pub(crate) fn hides_vetters(book: &VettingBook, community: &str) -> bool {
    book.pcs_zkp(community)
}

/// Why a request cannot be attested at all: it carries no PCS identifier, under a criterion
/// that counts a PCS ZKP proof and nothing else — and what the applicant does about it.
pub(crate) fn hidden_without_id_words(criterion: &str) -> String {
    format!(
        "Cannot attest: this request carries no hidden-vetting identifier, and criterion \
         {criterion} accepts only a PCS ZKP proof — not a named statement — so there is nothing \
         to attest to. Nothing was sent; the request stays open. Ask the applicant to refresh \
         their requirements (m) and send you a new request: the identifier travels in the \
         request, so a new card alone does not carry it."
    )
}

/// Where `persona` stands for PCS ZKP attesting at `community`, in words, and whether that
/// means it cannot attest there now. `None` when the community names its vetters.
pub(crate) fn pcs_tokens_line(
    book: &VettingBook,
    community: &str,
    persona: PersonaId,
    now: DateTime<Utc>,
) -> Option<(String, bool)> {
    if !hides_vetters(book, community) {
        return None;
    }
    Some(match book.hidden_outlook(community, persona, now) {
        Some(o) => (outlook_words(&o, now), !o.enrolled || o.usable == 0),
        // The community hides its vetters and we hold no engine yet: the next pass makes one
        // and enrols.
        None => (
            "not enrolled yet — enrolling now (k to get tokens)".to_string(),
            true,
        ),
    })
}

/// How `community` vets, for the desk header, when that is not current knowledge: why the last
/// read failed (R6.4 — which kind of failure, beside what was last known), or how old a stale
/// reading is. `None` while the reading is fresh — the badge then says it all.
fn mode_note(book: &VettingBook, community: &str, now: DateTime<Utc>) -> Option<String> {
    let reading = book.vetter_mode(community);
    if let Some((failure, at)) = &reading.failed
        && reading.read.is_none_or(|r| *at >= r.read_at)
    {
        return Some(format!(
            "could not read how it vets now: {} — last known: {}",
            clause(&failure.words()),
            reading.last_known_words(now)
        ));
    }
    if !reading.is_stale(now) {
        return None;
    }
    Some(match reading.read {
        Some(r) => format!(
            "{} as of {} — reading it again",
            r.mode.words(),
            age_words(now - r.read_at)
        ),
        None => "how it vets is not known yet — asking".to_string(),
    })
}

/// The desk header's token line: [`pcs_tokens_line`], and a warning when the live tickets out
/// for this community admit more requests than the tokens held can attest.
fn standing_tokens(
    book: &VettingBook,
    community: &str,
    persona: PersonaId,
    now: DateTime<Utc>,
) -> Option<(String, bool)> {
    let (mut line, mut warn) = pcs_tokens_line(book, community, persona, now)?;
    let admits: u32 = book
        .tickets
        .iter()
        .filter(|t| t.community == community && t.persona == persona && t.is_live(now))
        .map(|t| t.uses_left)
        .sum();
    let usable = book
        .hidden_outlook(community, persona, now)
        .map_or(0, |o| o.usable);
    if admits as usize > usable {
        line.push_str(&format!(
            " — your live tickets admit {admits} request{}, more than you can attest now",
            if admits == 1 { "" } else { "s" }
        ));
        warn = true;
    }
    Some((line, warn))
}

/// A tick length in words: "3 days", "12 hours", "1 day 6 hours".
fn tick_length_words(length: chrono::Duration) -> String {
    let days = length.num_days();
    let hours = length.num_hours() - days * 24;
    let unit = |n: i64, one: &str| format!("{n} {one}{}", if n == 1 { "" } else { "s" });
    match (days, hours) {
        (0, h) => unit(h, "hour"),
        (d, 0) => unit(d, "day"),
        (d, h) => format!("{} {}", unit(d, "day"), unit(h, "hour")),
    }
}

/// When a community's hidden-vetting parameters were last read from it, as the desk says it
/// after the rate: "read 21:16 UTC" today, "read 2026-10-04 21:16 UTC" before, or "not read
/// from the community yet".
fn params_read_words(read_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> String {
    match read_at {
        Some(at) if at.date_naive() == now.date_naive() => {
            format!("read {}", at.format("%H:%M UTC"))
        }
        Some(at) => format!("read {}", at.format("%Y-%m-%d %H:%M UTC")),
        None => "not read from the community yet".to_string(),
    }
}

/// One community's hidden vetting, for the vetter's own view.
fn hidden_row(
    held: &HiddenVetterState,
    community: String,
    accent: Option<(u8, u8, u8)>,
    now: DateTime<Utc>,
) -> HiddenVettingRow {
    use openvtc_core::vetting::hidden;
    let when = |t: DateTime<Utc>| t.format("%Y-%m-%d %H:%M UTC").to_string();
    let events = held.event_draws(now.date_naive());
    let mut enrolled: Vec<(String, Option<String>)> = held
        .snapshot
        .credentials
        .keys()
        .rev()
        .map(|period| {
            (
                format!("vetter/{period}"),
                held.enrolled_at
                    .get(period)
                    .map(|t| t.format("%Y-%m-%d").to_string()),
            )
        })
        .collect();
    enrolled.truncate(4);
    let enrolment_owed = held
        .params
        .vetter_labels
        .first()
        .filter(|l| {
            !held
                .snapshot
                .credentials
                .contains_key(l.trim_start_matches("vetter/"))
        })
        .cloned();
    let (tokens_held, tokens_free) = held.tokens();
    let last_draw = held.last_draw.as_ref().map(|d| {
        format!(
            "{} tick {} — {} token{} at {}",
            d.label,
            d.tick,
            d.taken,
            if d.taken == 1 { "" } else { "s" },
            when(d.at)
        )
    });
    let next_window = hidden::next_window(&held.params, &events, now).map(when);
    let params_hold = match held.draw_hold(false, now) {
        Some(DrawHold::Disagrees {
            asked, published, ..
        }) => Some(format!(
            "The community refused {asked} tokens a tick as more than it issues, and still \
             publishes {published}. Nothing more is drawn until it publishes a rate it will \
             serve — ask its operator to check its dripPerTick."
        )),
        _ if held.reread_owed() => Some(
            "A draw was refused as over the community's rate; its parameters are being read \
             again, and nothing is drawn until they are."
                .to_string(),
        ),
        _ => None,
    };
    HiddenVettingRow {
        community,
        accent,
        enrolled,
        enrolment_lost: enrolment_owed
            .as_deref()
            .map(|l| l.trim_start_matches("vetter/"))
            == held.lost_enrolment.as_deref()
            && held.lost_enrolment.is_some()
            && held.lost_reasked,
        unanswered: held.unanswered,
        enrolment_owed,
        tokens_held,
        tokens_free,
        tokens_spent: held.tokens_spent,
        token_labels: held
            .params
            .token_labels
            .iter()
            .map(|l| sanitize_display(l, 128))
            .collect(),
        tick_length: tick_length_words(held.params.tick_length()),
        drip_per_tick: held.params.drip_per_tick,
        drawn_per_tick: held
            .params
            .token_labels
            .iter()
            .find(|l| hidden::month_of_label(l).is_some())
            .map_or(held.params.drip_per_tick, |l| {
                held.rate_for(l, now.date_naive())
            }),
        params_read: params_read_words(held.params_read_at, now),
        params_hold,
        last_draw,
        next_window,
        events: held
            .events
            .iter()
            .map(|e| {
                (
                    sanitize_display(&e.event_id, 128),
                    sanitize_display(&e.state, 32),
                    e.group_size,
                    e.group_floor,
                )
            })
            .collect(),
        last_refusal: held.last_refusal.as_ref().map(|r| {
            format!(
                "{} — {}: {}",
                when(r.at),
                r.what,
                hidden::refusal_words(&sanitize_display(&r.code, 120))
            )
        }),
        waiting_until: held.retry_at.filter(|t| *t > now).map(when),
        rekeyed: held.rekeyed_at.map(when),
    }
}

/// Rebuild the page's rows from the book.
pub(crate) fn sync(vetting: &mut VettingState, config: &Config) {
    let now = Utc::now();
    let book = &config.private.vetting;
    let name = |did: &str| config.agent_name_for(did).map(|n| sanitize_display(n, 256));
    // The membership's own name first; the name the community gives itself in
    // its branding only when there is none.
    let community_name = |did: &str| {
        config
            .account
            .memberships()
            .find(|m| m.vtc_did == did)
            .and_then(|m| m.display_name.as_deref())
            .or_else(|| book.branding(did).and_then(|b| b.display_name.as_deref()))
            .map(|n| sanitize_display(n, 128))
    };
    let accent = |did: &str| book.branding(did).and_then(|b| b.accent_rgb());

    vetting.personas = config
        .identities
        .iter()
        .map(|(persona, identity)| VettingPersona {
            persona: *persona,
            did: identity.persona_did().to_string(),
            label: sanitize_display(&config.persona_profile_label_for(*persona), 128),
        })
        .collect();

    vetting.memberships = config
        .account
        .memberships()
        .filter(|m| m.status.is_active())
        // Tickets are for communities that named us a vetter: a request made
        // with one to anyone else would be refused as not eligible.
        .filter(|m| book.vetter_grant(&m.vtc_did, m.persona_ref, now).is_some())
        .map(|m| VettingMembership {
            community: m.vtc_did.clone(),
            name: community_name(&m.vtc_did).unwrap_or_else(|| shorten_did(&m.vtc_did, 48)),
            persona: m.persona_ref,
            accent: accent(&m.vtc_did),
        })
        .collect();

    vetting.resend_candidates = book
        .resend_candidates(&config.account, now)
        .into_iter()
        .map(|m| VettingMembership {
            community: m.vtc_did.clone(),
            name: community_name(&m.vtc_did).unwrap_or_else(|| shorten_did(&m.vtc_did, 48)),
            persona: m.persona_ref,
            accent: accent(&m.vtc_did),
        })
        .collect();

    // The event menu, one row per (event, tier), with where our own request
    // stands beside it. Read from the parameters each community published —
    // what is on offer — never from anything that would say who else asked.
    let mut offers = Vec::new();
    for held in &book.hidden_vetter {
        let name =
            community_name(&held.community).unwrap_or_else(|| shorten_did(&held.community, 48));
        for event in &held.params.events {
            let ours = held.events.iter().find(|e| e.event_id == event.event_id);
            for tier in &event.tiers {
                offers.push(EventOffer {
                    community: held.community.clone(),
                    community_name: name.clone(),
                    persona: held.persona,
                    event_id: event.event_id.clone(),
                    tier: tier.name.clone(),
                    drip_per_tick: tier.drip_per_tick,
                    start_date: event.start_date,
                    end_date: event.end_date,
                    group_floor: event.group_floor,
                    state: ours.map(|e| e.state.clone()),
                    group_size: ours.map(|e| e.group_size),
                });
            }
        }
    }
    vetting.event_offers = offers.into();
    vetting.hidden = book
        .hidden_vetter
        .iter()
        .map(|held| {
            let name =
                community_name(&held.community).unwrap_or_else(|| shorten_did(&held.community, 48));
            hidden_row(held, name, accent(&held.community), now)
        })
        .collect();
    vetting.retired = book
        .retired
        .iter()
        .map(|note| sanitize_display(note, 320))
        .collect();

    // The desk's header. Built from `vetter_standing`, which — alone among the
    // vetter-side reads — keeps lapsed grants, so a vetter who has quietly
    // stopped being one can see that rather than infer it from an empty page.
    vetting.standing = book
        .vetter_standing(now)
        .into_iter()
        .map(|s| VetterStandingRow {
            community: community_name(&s.community)
                .unwrap_or_else(|| shorten_did(&s.community, 48)),
            accent: accent(&s.community),
            grant: grant_standing(&s, now),
            grant_warns: !s.live || s.expiring,
            profile: profile_standing(s.profile.as_ref()),
            tokens: standing_tokens(book, &s.community, s.persona, now).map(|(l, _)| l),
            tokens_warn: standing_tokens(book, &s.community, s.persona, now)
                .is_some_and(|(_, warn)| warn),
            mode_note: mode_note(book, &s.community, now),
        })
        .collect();

    // The directory is searched as a persona the community knows of: each
    // application's own persona, then each membership's for a community with
    // no application. One entry per application rather than per community, so
    // a search started from an application goes out as that application's
    // persona — not as whichever other application to the same community
    // happened to be listed first. A persona this account no longer holds
    // cannot sign the request, so it is never offered.
    let available = |persona: &PersonaId| config.identities.contains_key(persona);
    let mut directory: Vec<DirectoryCommunity> = Vec::new();
    let several = |community: &str| {
        book.applications
            .iter()
            .filter(|a| a.community == community && available(&a.persona))
            .count()
            > 1
    };
    for app in book.applications.iter().filter(|a| available(&a.persona)) {
        let community =
            community_name(&app.community).unwrap_or_else(|| shorten_did(&app.community, 48));
        directory.push(DirectoryCommunity {
            // Two applications to one community are told apart by who asks.
            name: if several(&app.community) {
                format!(
                    "{community} — as {}",
                    sanitize_display(&config.persona_profile_label_for(app.persona), 48)
                )
            } else {
                community
            },
            community: app.community.clone(),
            accent: accent(&app.community),
            persona: app.persona,
            application_id: Some(app.id.clone()),
        });
    }
    for m in config
        .account
        .memberships()
        .filter(|m| m.status.is_active() && available(&m.persona_ref))
    {
        if !directory.iter().any(|d| d.community == m.vtc_did) {
            directory.push(DirectoryCommunity {
                community: m.vtc_did.clone(),
                name: community_name(&m.vtc_did).unwrap_or_else(|| shorten_did(&m.vtc_did, 48)),
                accent: accent(&m.vtc_did),
                persona: m.persona_ref,
                application_id: None,
            });
        }
    }
    vetting.directory_communities = directory.into();

    vetting.documentation = book
        .policy
        .accepts_documentation
        .iter()
        .cloned()
        .chain(std::iter::once(documentation::NONE.to_string()))
        .collect();

    // A join that is done is not an application in progress: the list is the
    // joins still under way. A finished one stays in the book — leaving and
    // rejoining as that persona presents its statements again — and reappears
    // here if the membership ends.
    let joined = |app: &&openvtc_core::vetting::applicant::Application| {
        config.account.memberships().any(|m| {
            m.status.is_active() && m.vtc_did == app.community && m.persona_ref == app.persona
        })
    };
    vetting.applications = book
        .applications
        .iter()
        .filter(|app| !joined(app))
        .map(|app| {
            let required = required_claim_types(app);
            let identity = required
                .iter()
                .map(|claim_type| {
                    let value = app
                        .identity_claims
                        .iter()
                        .find(|c| c.type_.as_str() == claim_type.as_str())
                        .map(|c| claim_text(&c.value))
                        .unwrap_or_default();
                    (claim_type.clone(), value)
                })
                .collect();
            let evaluation = app.checklist(now);
            ApplicationRow {
                id: app.id.clone(),
                community: app.community.clone(),
                community_name: community_name(&app.community),
                accent: accent(&app.community),
                pcs_zkp: app.hidden.is_some(),
                next_step: Some(next_step_words(&app.next_step(now))),
                join_did: app.join_did.clone(),
                requirements: app.requirements.as_ref().map(|r| {
                    let mut line = requirements_line(r);
                    // The whole feature, in the one place the applicant reads what is being
                    // asked of them. Without it, a criterion that hides its vetters looks
                    // exactly like one that does not, and the difference is the point.
                    if app.hidden.is_some() {
                        line.push_str(" — their names never reach this community");
                    }
                    line
                }),
                criterion: criterion_words(book, app),
                progress: evaluation.as_ref().map(progress_line),
                satisfied: evaluation.as_ref().is_some_and(Evaluation::satisfied),
                face: app.face.as_ref().map(|f| f.name.clone()),
                identity,
                statements: app.statements.len(),
                requests: app
                    .requests
                    .iter()
                    .map(|r| {
                        let (state, match_code, card_session) = match &r.state {
                            RequestState::Sent => {
                                ("sent — waiting for the vetter".to_string(), None, None)
                            }
                            RequestState::Accepted { session_hint, .. } => (
                                match session_hint {
                                    Some(hint) => {
                                        format!("accepted — {}", sanitize_display(hint, 200))
                                    }
                                    None => "accepted — waiting for a session".to_string(),
                                },
                                None,
                                None,
                            ),
                            RequestState::Session {
                                session,
                                card: None,
                                ..
                            } => (
                                "session open — read the code together, then send your card"
                                    .to_string(),
                                Some(session.match_code.clone()),
                                Some(session.id.clone()),
                            ),
                            RequestState::Session { session, .. } => (
                                "card sent — waiting for their statement".to_string(),
                                Some(session.match_code.clone()),
                                None,
                            ),
                            RequestState::Attested { .. } => {
                                ("statement received".to_string(), None, None)
                            }
                            // The vetter's reason and note, when they gave
                            // them. A decline with neither says only that, and
                            // owes the applicant nothing more.
                            RequestState::Declined { code, message } => {
                                let mut said = "declined".to_string();
                                if let Some(code) = code {
                                    said.push_str(" — ");
                                    said.push_str(decline_reason_words(*code));
                                }
                                if let Some(note) = message {
                                    said.push_str(&format!(
                                        " · they wrote: \"{}\"",
                                        sanitize_display(note, 500)
                                    ));
                                }
                                (said, None, None)
                            }
                            RequestState::Refused { code, .. } => (
                                format!("refused ({})", sanitize_display(code, 80)),
                                None,
                                None,
                            ),
                        };
                        RequestRow {
                            vetter: r.vetter.clone(),
                            vetter_name: name(&r.vetter),
                            state,
                            match_code,
                            card_session,
                            eligibility: r.eligibility.as_ref().map(eligibility_line),
                            grant: r.grant_status.as_ref().map(grant_line),
                            // The code stays on the state line, because it is
                            // what to quote when asking anyone else about this;
                            // what it *means* gets a line of its own, because a
                            // wire code is not an instruction.
                            refusal: match &r.state {
                                RequestState::Refused { code, .. } => {
                                    Some(request_refusal_words(code).to_string())
                                }
                                _ => None,
                            },
                        }
                    })
                    .collect(),
            }
        })
        .collect();

    // Only requests still waiting on us. A finished one leaves at once — its
    // statement is under History, a decline is a line there too — rather than
    // sitting among the open ones with the person's card beside it.
    vetting.desk = book
        .desk
        .iter()
        .filter(|entry| entry.state.is_open())
        .map(|entry| {
            let (state, stage, session, card) = match &entry.state {
                DeskState::Accepted => (
                    "accepted — open a session when you are together",
                    DeskStage::Accepted,
                    None,
                    None,
                ),
                DeskState::Session { session } => (
                    "session open — waiting for their card",
                    DeskStage::Session,
                    Some(session),
                    None,
                ),
                DeskState::CardReceived { session, card } => (
                    "card verified — check the person, then attest or decline",
                    DeskStage::Card,
                    Some(session),
                    Some(card),
                ),
                DeskState::Attested { card, .. } => {
                    ("statement signed", DeskStage::Closed, None, Some(card))
                }
                DeskState::Declined { card, .. } => {
                    ("declined", DeskStage::Closed, None, card.as_ref())
                }
            };
            DeskRow {
                request_id: entry.request_id.clone(),
                applicant: entry.applicant.clone(),
                applicant_name: name(&entry.applicant),
                community: entry.community.clone(),
                pcs_zkp: book.pcs_zkp(&entry.community)
                    && book.request_vetting(&entry.request_id) == RequestVetting::Hidden,
                pcs_tokens: pcs_tokens_line(book, &entry.community, entry.persona, now)
                    .map(|(line, _)| line),
                pcs_events: book
                    .hidden_vetter(&entry.community, entry.persona)
                    .is_some_and(|h| !h.params.events.is_empty()),
                state: state.to_string(),
                stage,
                method: session.map(|s| method_label(s.method).to_string()),
                match_code: entry.match_code().map(str::to_string),
                claims: card
                    .map(|c| {
                        c.claims
                            .iter()
                            .map(|claim| {
                                (
                                    sanitize_display(claim.type_.as_str(), 64),
                                    sanitize_display(&claim_text(&claim.value), 256),
                                )
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
                required_claims: session
                    .map(|s| s.required_claims.clone())
                    .unwrap_or_default(),
                message: entry
                    .request
                    .message
                    .as_deref()
                    .map(|m| sanitize_display(m, 500)),
            }
        })
        .collect();

    vetting.tickets = book
        .tickets
        .iter()
        .map(|t| TicketRow {
            id: t.id.clone(),
            code: t.code.clone(),
            community: community_name(&t.community)
                .unwrap_or_else(|| shorten_did(&t.community, 48)),
            uses_left: t.uses_left,
            expires: t.expires_at.format("%Y-%m-%d").to_string(),
            live: t.is_live(now),
            // A ticket whose link the published URI cannot carry simply has no
            // link; its code still reads aloud.
            uri: persona_did(config, t.persona).and_then(|did| t.uri(&did).ok()),
            // Issued under a mode the community no longer runs: its requests are answered
            // under the one it runs now, which is worth knowing before handing it on.
            mode_note: t
                .mode
                .filter(|issued| {
                    book.vetter_mode(&t.community)
                        .mode()
                        .is_some_and(|current| current != *issued)
                })
                .map(|issued| format!("issued under {}", issued.words())),
        })
        .collect();

    vetting.issued = book
        .issued
        .iter()
        .map(|s| IssuedRow {
            id: s.id.clone(),
            applicant: s.applicant.clone(),
            community: community_name(&s.community)
                .unwrap_or_else(|| shorten_did(&s.community, 48)),
            method: method_label(s.method).to_string(),
            issued: s.issued_at.format("%Y-%m-%d").to_string(),
            valid_until: s.valid_until.format("%Y-%m-%d").to_string(),
            withdrawal: s.withdrawal.as_ref().map(|w| match w.recorded_at {
                Some(at) => format!("withdrawn — recorded {}", at.format("%Y-%m-%d")),
                None => "withdrawal sent — not yet recorded".to_string(),
            }),
            withdrawal_recorded: s
                .withdrawal
                .as_ref()
                .is_some_and(|w| w.recorded_at.is_some()),
        })
        .collect();

    // Declines, newest first: the ones still on the desk in their grace, then
    // the archived. Community and date only — a decline keeps no identifier.
    let mut declined: Vec<(chrono::DateTime<Utc>, String)> = book
        .desk
        .iter()
        .filter_map(|e| match &e.state {
            openvtc_core::vetting::vetter::DeskState::Declined { at, .. } => {
                Some((*at, e.community.clone()))
            }
            _ => None,
        })
        .chain(book.vetted.iter().filter_map(|r| match r.outcome {
            openvtc_core::vetting::book::VettedOutcome::Declined => {
                Some((r.closed_at, r.community.clone()))
            }
            openvtc_core::vetting::book::VettedOutcome::Signed { .. } => None,
        }))
        .collect();
    declined.sort_by_key(|(at, _)| std::cmp::Reverse(*at));
    vetting.declined = declined
        .into_iter()
        .map(|(at, community)| {
            (
                community_name(&community).unwrap_or_else(|| shorten_did(&community, 48)),
                at.format("%Y-%m-%d").to_string(),
            )
        })
        .collect();

    vetting.selected = vetting.selected.min(vetting.tab_len().saturating_sub(1));
    sync_journey(vetting, config, now);
}

/// Work the open journey out from the book again, so it follows every change
/// — a statement arriving, a session opening — without being asked.
///
/// Keeps the list's highlight on the journey's own row: every action the
/// journey offers is one the list already had, and those act on the
/// highlighted row. A journey whose application or request has gone closes,
/// rather than drawing steps for something that no longer exists.
pub(crate) fn sync_journey(vetting: &mut VettingState, config: &Config, now: DateTime<Utc>) {
    use openvtc_core::vetting::journey::{applicant_journey, vetter_journey};
    let book = &config.private.vetting;
    let view = match &vetting.journey_target {
        None => None,
        Some(JourneyTarget::Application(id)) => {
            book.applications.iter().find(|a| &a.id == id).map(|app| {
                if let Some(i) = vetting.applications.iter().position(|r| &r.id == id) {
                    vetting.tab = VettingTab::Applications;
                    vetting.selected = i;
                }
                JourneyView {
                    title: format!(
                        "Applying to {} as {}",
                        community_display(config, &app.community),
                        sanitize_display(&config.persona_profile_label_for(app.persona), 64)
                    ),
                    pcs_zkp: app.hidden.is_some(),
                    steps: JourneySteps::Applicant(applicant_journey(app, now)),
                }
            })
        }
        Some(JourneyTarget::Desk(id)) => book.desk_entry(id).map(|entry| {
            if let Some(i) = vetting.desk.iter().position(|r| &r.request_id == id) {
                vetting.tab = VettingTab::Desk;
                vetting.desk_view = DeskView::Requests;
                vetting.selected = i;
            }
            let (steps, ending) = vetter_journey(entry);
            JourneyView {
                title: format!(
                    "Vetting {} for {}",
                    openvtc_core::display::display_identifier(
                        config.agent_name_for(&entry.applicant),
                        &entry.applicant,
                        48
                    ),
                    community_display(config, &entry.community)
                ),
                pcs_zkp: book.pcs_zkp(&entry.community)
                    && book.request_vetting(&entry.request_id) == RequestVetting::Hidden,
                steps: JourneySteps::Vetter(steps, ending),
            }
        }),
    };
    if view.is_none() {
        vetting.journey_target = None;
    }
    vetting.journey = view;
}

fn claim_text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// What a vetter's acceptance showed, in a line, and whether it is good news.
fn eligibility_line(eligibility: &VetterEligibility) -> (bool, String) {
    match eligibility {
        VetterEligibility::Shown { valid_until, .. } => (
            true,
            format!("named a vetter until {}", valid_until.format("%Y-%m-%d")),
        ),
        VetterEligibility::NotShown => (
            false,
            "did not show that the community named them a vetter — their statement may not count"
                .to_string(),
        ),
        VetterEligibility::Failed { reason } => (
            false,
            format!(
                "their vetter credential did not verify ({}) — their statement may not count",
                sanitize_display(reason, 160)
            ),
        ),
    }
}

/// Whether the community revoked the vetter's grant, in a line.
fn grant_line(status: &GrantStatus) -> (LineTone, String) {
    match status {
        GrantStatus::Checking { .. } => (
            LineTone::Caution,
            "checking whether the community has revoked this vetter's grant…".to_string(),
        ),
        GrantStatus::Active { checked_at } => (
            LineTone::Good,
            format!(
                "not revoked when checked on {}",
                checked_at.format("%Y-%m-%d")
            ),
        ),
        GrantStatus::Revoked { .. } => (
            LineTone::Bad,
            "the community has revoked this vetter's grant — their statement will not count"
                .to_string(),
        ),
        GrantStatus::Unknown { reason, .. } => (
            LineTone::Caution,
            format!(
                "could not check whether the grant was revoked ({})",
                sanitize_display(reason, 200)
            ),
        ),
    }
}

/// What to do next on an application, with the key that does it.
pub(crate) fn next_step_words(step: &NextStep) -> String {
    match step {
        NextStep::SendCard { .. } => {
            "c — a vetter opened a session: read the code together, then send your card"
        }
        NextStep::LearnRequirements => "m — ask the community what it requires",
        NextStep::Join => "j — join now; your statements go with the request",
        NextStep::ChooseFace => "f — choose the face you show vetters, then ask a vetter",
        NextStep::AskVetter => "r — ask a vetter with their ticket, or v to find one",
        NextStep::WaitForVetters => "wait for your vetters — you are told when one answers",
    }
    .to_string()
}

/// Where an application stands, for the Communities panel's "Joining" row, and
/// whether its published requirements are met.
///
/// Deliberately key-free, unlike [`next_step_words`]: those keys are the
/// Vetting page's, and on the Communities panel `j` starts a fresh join and `c`
/// opens capabilities — advertising them there would send the holder somewhere
/// else. The row's one action is opening the application's journey, where the
/// keys are.
pub(crate) fn joining_standing(app: &Application, now: DateTime<Utc>) -> (String, bool) {
    // "n of m statements" when the community's requirements are known: it is
    // the measure the community will apply, so it is the one to read here.
    let count = app.checklist(now).and_then(|evaluation| {
        app.requirements.as_ref().map(|r| {
            let m = r.min_statements.get();
            format!(
                "{} of {m} statement{}",
                evaluation.counted.len(),
                if m == 1 { "" } else { "s" }
            )
        })
    });
    let (next, ready) = match app.next_step(now) {
        NextStep::SendCard { .. } => ("a vetter is waiting for your card", false),
        NextStep::LearnRequirements => ("the community's requirements are not read yet", false),
        NextStep::Join => ("ready to join", true),
        NextStep::ChooseFace => ("choose the face vetters see, then ask a vetter", false),
        NextStep::AskVetter => ("ask a vetter for a statement", false),
        NextStep::WaitForVetters => ("waiting for your vetters", false),
    };
    let standing = match count {
        Some(count) => format!("{count} — {next}"),
        None => next.to_string(),
    };
    (standing, ready)
}

/// A community's name for messages: the membership's, then the one it
/// publishes, then a verified agent name, then its DID.
pub(crate) fn community_display(config: &Config, did: &str) -> String {
    let named = config
        .account
        .memberships()
        .find(|m| m.vtc_did == did)
        .and_then(|m| m.display_name.clone())
        .or_else(|| {
            config
                .private
                .vetting
                .branding(did)
                .and_then(|b| b.display_name.clone())
        });
    sanitize_display(
        &crate::state_handler::community_label(config, did, named.as_deref(), 48),
        128,
    )
}

fn requirements_line(r: &VettingRequirements) -> String {
    let n = r.min_statements.get();
    let mut line = format!(
        "{n} statement{} from distinct vetters",
        if n == 1 { "" } else { "s" }
    );
    for (method, floor) in &r.min_by_method {
        line.push_str(&format!(", at least {floor} {}", method_label(*method)));
    }
    if let Some(age) = &r.max_statement_age {
        line.push_str(&format!(
            ", none older than {}",
            sanitize_display(age.as_str(), 32)
        ));
    }
    line
}

pub(crate) fn progress_line(evaluation: &Evaluation) -> String {
    if evaluation.satisfied() {
        return "meets the published requirements — press j to join".to_string();
    }
    let needs: Vec<String> = evaluation
        .needs
        .iter()
        .map(|need| match need {
            Need::Statements(n) => format!("{n} more statement{}", if *n == 1 { "" } else { "s" }),
            Need::Method(method, n) => format!("{n} more {}", method_label(*method)),
            other => other.to_wire(),
        })
        .collect();
    if needs.is_empty() {
        // Enough statements, but they disagree or a relationship cap is hit.
        "statements disagree or are not independent — the community will review".to_string()
    } else {
        format!(
            "{} counted — still needed: {}",
            evaluation.counted.len(),
            needs.join(", ")
        )
    }
}

// ============================================================================
// Actions
// ============================================================================

fn page<'a>(ctx: &'a mut ActionCtx<'_>) -> &'a mut VettingState {
    &mut ctx.state.main_page.content_panel.vetting
}

fn status(ctx: &mut ActionCtx<'_>, message: impl Into<String>) {
    page(ctx).status_message = Some(message.into());
}

/// Persist the book and show `message`.
fn persist(ctx: &mut ActionCtx<'_>, message: impl Into<String>) {
    let message = message.into();
    dispatch_util::save_and_sync(
        &mut ctx.state.main_page,
        ctx.config,
        ctx.save,
        Persist::SaveAndSync,
        |mp| &mut mp.content_panel.vetting.status_message,
        message.clone(),
        SyncLog::Plain(message),
    );
}

/// Handle one Vetting-page action.
pub(crate) async fn dispatch(ctx: &mut ActionCtx<'_>, action: VettingAction) {
    match action {
        VettingAction::OpenJourney => {
            let v = page(ctx);
            let target = match (v.tab, v.desk_view) {
                (VettingTab::Applications, _) => v
                    .applications
                    .get(v.selected)
                    .map(|r| JourneyTarget::Application(r.id.clone())),
                (VettingTab::Desk, DeskView::Requests) => v
                    .desk
                    .get(v.selected)
                    .map(|r| JourneyTarget::Desk(r.request_id.clone())),
                _ => None,
            };
            if let Some(target) = target {
                v.journey_target = Some(target);
                v.mode = VettingMode::List;
                v.status_message = None;
                sync_journey(
                    &mut ctx.state.main_page.content_panel.vetting,
                    ctx.config,
                    Utc::now(),
                );
            }
        }
        VettingAction::OpenApplication(application_id) => {
            if ctx
                .config
                .private
                .vetting
                .applications
                .iter()
                .any(|a| a.id == application_id)
            {
                focus_application(
                    ctx.state,
                    ctx.config,
                    &application_id,
                    "Where your application stands, and what happens next.".to_string(),
                );
            } else {
                // Finished or abandoned between the panel drawing it and the
                // key arriving: say so where the holder is looking.
                ctx.state.main_page.content_panel.communities.status_message =
                    Some("That application is no longer in progress.".to_string());
            }
        }
        VettingAction::CloseJourney => {
            let v = page(ctx);
            v.journey_target = None;
            v.journey = None;
            v.mode = VettingMode::List;
        }
        VettingAction::SwitchTab => {
            let v = page(ctx);
            v.tab = v.tab.next();
            v.selected = 0;
            v.mode = VettingMode::List;
            v.status_message = None;
            // Opening the desk: how each community vets is read again where the last reading
            // is stale, so the badges and the ticket gate are not shown from an old answer.
            if v.tab == VettingTab::Desk {
                refresh_stale_modes(ctx).await;
            }
        }
        VettingAction::ShowTicket => {
            let v = page(ctx);
            // Only a ticket that can still be redeemed is worth holding up to a
            // camera; a spent one would scan and then be refused.
            if v.tickets.get(v.selected).is_some_and(|t| t.live) {
                v.mode = VettingMode::ShowTicket { index: v.selected };
                v.status_message = None;
            }
        }
        VettingAction::SwitchDeskView(forward) => {
            let v = page(ctx);
            // The desk view is remembered across a tab switch, so this only
            // has to reset the cursor — the lists are different lengths and a
            // carried index would point at a different row, or at none.
            v.desk_view = v.desk_view.shifted(forward);
            v.selected = 0;
            v.status_message = None;
        }
        VettingAction::Select(i) => {
            let v = page(ctx);
            v.selected = i.min(v.tab_len().saturating_sub(1));
        }
        VettingAction::Back => back(page(ctx)),
        VettingAction::PasteTicket(text) => paste_ticket(ctx, &text),
        VettingAction::FindVetters => open_directory(ctx),
        VettingAction::DirectoryPage(forward) => directory_page(ctx, forward).await,
        VettingAction::AskListedVetter => ask_listed_vetter(ctx),
        VettingAction::EditProfile => open_profile(ctx),
        VettingAction::RemoveEvent => {
            if let VettingMode::Profile(form) = &mut page(ctx).mode
                && form.event.is_none()
                && let Some(i) = form.event_index()
            {
                form.draft.events.remove(i);
                form.field = form.field.min(form.rows() - 1);
                form.error = None;
            }
        }
        VettingAction::AskResend => {
            if page(ctx).resend_candidates.is_empty() {
                status(
                    ctx,
                    "Every community you are an active member of has already sent you a live \
                     vetter credential — or you are not an active member of any.",
                );
            } else {
                page(ctx).mode = VettingMode::Resend { index: 0 };
            }
        }
        VettingAction::AskEventMode => {
            if page(ctx).event_offers.is_empty() {
                status(
                    ctx,
                    "No community you vet for is running an event. Event mode is the exception, \
                     not the setting — an ordinary week is the slow drip.",
                );
            } else {
                page(ctx).mode = VettingMode::EventMode { index: 0 };
            }
        }
        VettingAction::Status(message) => status(ctx, message),
        VettingAction::Input(text) => {
            input(&mut page(ctx).mode, text);
            refresh_application_contexts(ctx);
        }
        VettingAction::NextField => move_field(page(ctx), true),
        VettingAction::PrevField => move_field(page(ctx), false),
        VettingAction::Cycle(forward) => {
            let before = profile_membership(page(ctx));
            cycle(page(ctx), forward);
            let after = profile_membership(page(ctx));
            if let Some(index) = after
                && before != after
            {
                // Each community has its own profile: show the one for this one.
                let form = profile_form(
                    &ctx.state.main_page.content_panel.vetting,
                    &ctx.config.private.vetting,
                    index,
                    0,
                );
                page(ctx).mode = VettingMode::Profile(Box::new(form));
            }
            refresh_application_contexts(ctx);
        }
        VettingAction::Toggle => match &mut page(ctx).mode {
            VettingMode::NewFace(form) => form.toggle(),
            VettingMode::Attest { form, .. } => match form.field {
                3 => form.liveness_confirmed = !form.liveness_confirmed,
                4 => form.attested = !form.attested,
                _ => {}
            },
            VettingMode::Profile(form) if form.event.is_none() => {
                match form.field {
                    1 => form.draft.listed = !form.draft.listed,
                    7 => form.draft.toggle_method(VettingMethod::InPerson),
                    8 => form.draft.toggle_method(VettingMethod::Video),
                    9 => form.draft.toggle_method(VettingMethod::PriorAcquaintance),
                    _ => {}
                }
                form.error = None;
            }
            _ => {}
        },
        VettingAction::StartApplication => {
            if page(ctx).personas.is_empty() {
                status(
                    ctx,
                    "Create a persona under My Identity first — it is the DID you join with.",
                );
            } else {
                page(ctx).mode = VettingMode::NewApplication {
                    community: String::new(),
                    persona_index: 0,
                    context_options: Vec::new(),
                    context_index: 0,
                    field: 0,
                };
                refresh_application_contexts(ctx);
            }
        }
        VettingAction::ChooseFace => {
            let v = page(ctx);
            // From a card, the card's application — not whichever row the list
            // behind it last had selected — and the card is where it returns.
            let id = match &v.mode {
                VettingMode::SendCard {
                    application_id,
                    session_id,
                    ..
                } => {
                    v.card_after_face = Some((application_id.clone(), session_id.clone()));
                    Some(application_id.clone())
                }
                // A retry after granting access keeps whichever card sent it.
                VettingMode::HolderGrant { .. } => v
                    .card_after_face
                    .as_ref()
                    .map(|(application_id, _)| application_id.clone())
                    .or_else(|| v.applications.get(v.selected).map(|row| row.id.clone())),
                _ => {
                    v.card_after_face = None;
                    v.applications.get(v.selected).map(|row| row.id.clone())
                }
            };
            if let Some(id) = id {
                list_faces(ctx, &id);
            }
        }
        VettingAction::RequestVetter => {
            let v = page(ctx);
            if let Some(row) = v.applications.get(v.selected).cloned() {
                v.mode = VettingMode::RequestVetter {
                    application_id: row.id,
                    entry: String::new(),
                    vetter: String::new(),
                    ticket: None,
                    note: None,
                };
            }
        }
        VettingAction::RefreshRequirements => {
            let v = page(ctx);
            if let Some(row) = v.applications.get(v.selected).cloned() {
                refresh_requirements(ctx, &row.id).await;
                // A hidden application also needs the community's challenge, and asking early
                // is free: the community keeps one per applicant, and asking again replaces it.
                ask_for_challenge(ctx, &row.id).await;
            }
            // A vetter has no application, so nothing else would ever fetch the manifest of a
            // community it vets for — and the manifest is where a community says it hides its
            // vetters. Asking here is what lets a vetter-only member reach the mode at all.
            refresh_vetter_side(ctx).await;
        }
        VettingAction::SwitchVettingPath => switch_vetting_path(ctx),
        VettingAction::RefreshVetterSide => refresh_vetter_side(ctx).await,
        VettingAction::OpenHiddenVetting => {
            if page(ctx).hidden.is_empty() {
                status(
                    ctx,
                    "None of the communities you vet for hides its vetters, so there is no \
                     hidden vetting to show.",
                );
            } else {
                page(ctx).mode = VettingMode::HiddenVetting { index: 0 };
            }
        }
        VettingAction::DrawNow => {
            // Get tokens, in one key: whatever the schedule owes, in order — enrol where not
            // enrolled, then draw every window that has begun — and, per community, exactly
            // what is happening or what blocks it and until when. Said from the book as it was
            // before the pass, which is what the pass acts on.
            let now = Utc::now();
            // Asked by hand: a lost enrolment is worth one more ask — the community may now
            // re-issue it to the same identifier, and it bounds how many times it will.
            for held in &mut ctx.config.private.vetting.hidden_vetter {
                held.lost_reasked = false;
            }
            let words: Vec<String> = {
                let book = &ctx.config.private.vetting;
                book.vetter_standing(now)
                    .into_iter()
                    .filter(|s| s.live && hides_vetters(book, &s.community))
                    .map(|s| {
                        let name = community_display(ctx.config, &s.community);
                        let why = get_tokens_words(book, &s.community, s.persona, &name, now);
                        format!("{name}: {}.", clause(&why))
                    })
                    .collect()
            };
            refresh_vetter_side(ctx).await;
            status(
                ctx,
                if words.is_empty() {
                    "None of the communities you vet for proves vetting with PCS ZKP, so there \
                     are no tokens to get — hand out tickets with t."
                        .to_string()
                } else {
                    format!("Getting tokens — {}", words.join(" "))
                },
            );
        }
        VettingAction::ReviewCard => {
            let v = page(ctx);
            let Some(row) = v.applications.get(v.selected).cloned() else {
                return;
            };
            match row.requests.iter().find_map(|r| r.card_session.clone()) {
                Some(session_id) => {
                    v.mode = VettingMode::SendCard {
                        application_id: row.id,
                        session_id,
                        preview: None,
                    };
                }
                None => status(ctx, "No vetter is waiting for your card."),
            }
        }
        VettingAction::NewTicket => {
            if page(ctx).memberships.is_empty() {
                status(
                    ctx,
                    "You can hand out tickets once a community you belong to has named you a \
                     vetter — ask its admins for the vetter role.",
                );
            } else {
                page(ctx).mode = VettingMode::NewTicket {
                    membership_index: 0,
                    uses_index: 0,
                    field: 0,
                };
            }
        }
        VettingAction::DeleteTicket => {
            let v = page(ctx);
            match v.tickets.get(v.selected).cloned() {
                Some(row) => v.mode = VettingMode::ConfirmDeleteTicket { ticket_id: row.id },
                None => status(ctx, "Highlight a ticket to delete."),
            }
        }
        VettingAction::OpenSession => {
            let v = page(ctx);
            match v.desk.get(v.selected).cloned() {
                Some(row) if matches!(row.stage, DeskStage::Accepted | DeskStage::Session) => {
                    v.mode = VettingMode::OpenSession {
                        request_id: row.request_id,
                        method_index: 0,
                    };
                }
                Some(_) => status(ctx, "That request has moved past opening a session."),
                None => {}
            }
        }
        VettingAction::StartAttest => {
            // The form opens on the method the session was opened with: the
            // statement says how the person was checked, and a default of "in
            // person" after a video call is a false statement one Enter away.
            let selected = {
                let v = page(ctx);
                v.desk.get(v.selected).cloned()
            };
            match selected {
                Some(row) if row.stage == DeskStage::Card => {
                    let method_index = match ctx
                        .config
                        .private
                        .vetting
                        .desk_entry(&row.request_id)
                        .map(|e| &e.state)
                    {
                        Some(DeskState::CardReceived { session, .. }) => VETTING_METHODS
                            .iter()
                            .position(|m| *m == session.method)
                            .unwrap_or(0),
                        _ => 0,
                    };
                    page(ctx).mode = VettingMode::Attest {
                        request_id: row.request_id,
                        form: AttestForm {
                            method_index,
                            ..AttestForm::default()
                        },
                    };
                }
                Some(_) => status(ctx, "You can attest once their card has arrived."),
                None => {}
            }
        }
        VettingAction::ArmDecline => {
            let v = page(ctx);
            match v.desk.get(v.selected).cloned() {
                Some(row) if row.stage != DeskStage::Closed => {
                    v.mode = VettingMode::ConfirmDecline {
                        request_id: row.request_id,
                        reason_index: 0,
                        message: String::new(),
                        field: 0,
                    };
                }
                Some(_) => status(ctx, "That request is already closed."),
                None => {}
            }
        }
        VettingAction::ArmAbandon => {
            let v = page(ctx);
            match v.applications.get(v.selected).cloned() {
                Some(row) => {
                    v.mode = VettingMode::ConfirmAbandon {
                        application_id: row.id,
                    };
                }
                None => status(ctx, "Highlight an application to abandon."),
            }
        }
        VettingAction::ArmWithdraw => {
            let v = page(ctx);
            match v.issued.get(v.selected).cloned() {
                // Sent but not recorded is not withdrawn: the community may
                // have refused it, or never heard it, and the core allows the
                // notice again until it is recorded. Refusing here left a
                // refused withdrawal with no way forward.
                Some(row) if !row.withdrawal_recorded => {
                    v.mode = VettingMode::Withdraw {
                        statement_id: row.id,
                        reason_index: 0,
                    };
                }
                Some(_) => status(
                    ctx,
                    "That statement is already withdrawn — the community recorded it.",
                ),
                None => {}
            }
        }
        VettingAction::Submit => submit(ctx).await,
    }
}

fn input(mode: &mut VettingMode, text: String) {
    // Editing the field discards what the last link was read as: the vetter and
    // the ticket both come out of that text, and leaving either behind would
    // send the request to whoever the *previous* link named.
    if let VettingMode::RequestVetter { ticket, vetter, .. } = mode {
        *ticket = None;
        vetter.clear();
    }
    if let Some(focused) = mode.focused_text_mut() {
        *focused = text;
    }
    match mode {
        VettingMode::Directory(view) => view.error = None,
        VettingMode::Profile(form) => {
            form.error = None;
            if let Some(event) = &mut form.event {
                event.error = None;
            }
        }
        _ => {}
    }
}

/// Esc: an open event form returns to its profile; anything else to the list.
fn back(v: &mut VettingState) {
    if let VettingMode::Profile(form) = &mut v.mode
        && form.event.is_some()
    {
        form.event = None;
        return;
    }
    // Backing out of choosing a face that a card asked for goes back to that
    // card: it is still open, and still the thing the holder was doing.
    if matches!(
        v.mode,
        VettingMode::ChooseFace { .. } | VettingMode::NewFace(_) | VettingMode::HolderGrant { .. }
    ) && let Some(card) = v.card_after_face.take()
    {
        v.mode = card_mode(card);
        return;
    }
    v.card_after_face = None;
    v.mode = VettingMode::List;
}

/// The card page for `(application_id, session_id)`, before its preview.
fn card_mode((application_id, session_id): (String, String)) -> VettingMode {
    VettingMode::SendCard {
        application_id,
        session_id,
        preview: None,
    }
}

fn profile_membership(v: &VettingState) -> Option<usize> {
    match &v.mode {
        VettingMode::Profile(form) => Some(form.membership_index),
        _ => None,
    }
}

fn move_field(v: &mut VettingState, forward: bool) {
    let step = |field: &mut usize, count: usize| {
        if count == 0 {
            return;
        }
        *field = if forward {
            (*field + 1) % count
        } else {
            (*field + count - 1) % count
        };
    };
    match &mut v.mode {
        // Two fields, not three: which context the application lives in is
        // taken rather than asked (a sub-context of its own).
        VettingMode::NewApplication { field, .. } => step(field, 2),
        VettingMode::NewTicket { field, .. } => step(field, 2),
        VettingMode::Directory(view) => {
            let rows = view.rows();
            step(&mut view.field, rows);
        }
        VettingMode::Profile(form) => match &mut form.event {
            Some(event) => step(&mut event.field, EVENT_FIELDS),
            None => {
                let rows = form.rows();
                step(&mut form.field, rows);
            }
        },
        // One past the faces is "make a new one" — a row, not a key, so that
        // every way out of this screen is in the list the eye is already on.
        VettingMode::ChooseFace { faces, index, .. } => step(index, faces.len() + 1),
        VettingMode::NewFace(form) => form.move_focus(forward),
        VettingMode::Attest { form, .. } => step(&mut form.field, AttestForm::FIELDS),
        VettingMode::ConfirmDecline { field, .. } => step(field, 2),
        _ => {}
    }
}

fn cycle(v: &mut VettingState, forward: bool) {
    let turn = |index: &mut usize, count: usize| {
        if count == 0 {
            return;
        }
        *index = if forward {
            (*index + 1) % count
        } else {
            (*index + count - 1) % count
        };
    };
    let (personas, memberships, documentation) =
        (v.personas.len(), v.memberships.len(), v.documentation.len());
    let (communities, resend) = (v.directory_communities.len(), v.resend_candidates.len());
    let offers = v.event_offers.len();
    let hidden = v.hidden.len();
    match &mut v.mode {
        VettingMode::HiddenVetting { index } => turn(index, hidden),
        VettingMode::Directory(view) => match view.field {
            0 => turn(&mut view.community_index, communities),
            5 => turn(&mut view.method_index, DIRECTORY_METHODS.len()),
            _ => {}
        },
        VettingMode::Profile(form) if form.event.is_none() && form.field == 0 => {
            turn(&mut form.membership_index, memberships);
        }
        VettingMode::Resend { index } => turn(index, resend),
        VettingMode::EventMode { index } => turn(index, offers),
        VettingMode::NewApplication {
            persona_index,
            field: 1,
            ..
        } => turn(persona_index, personas),
        VettingMode::NewTicket {
            membership_index,
            field: 0,
            ..
        } => turn(membership_index, memberships),
        VettingMode::NewTicket {
            uses_index,
            field: 1,
            ..
        } => turn(uses_index, VETTING_TICKET_USES.len()),
        VettingMode::OpenSession { method_index, .. } => {
            turn(method_index, VETTING_METHODS.len());
        }
        VettingMode::Attest { form, .. } => match form.field {
            0 => turn(&mut form.method_index, VETTING_METHODS.len()),
            1 => turn(&mut form.documentation_index, documentation),
            2 => turn(&mut form.relationship_index, VETTING_RELATIONSHIPS.len()),
            _ => {}
        },
        VettingMode::Withdraw { reason_index, .. } => {
            turn(reason_index, VETTING_WITHDRAWAL_REASONS.len());
        }
        VettingMode::ConfirmDecline {
            reason_index,
            field: 0,
            ..
        } => turn(reason_index, DECLINE_REASONS.len()),
        VettingMode::ChooseFace { faces, index, .. } => turn(index, faces.len() + 1),
        // Which of several attributes of one claim type the face shows.
        VettingMode::NewFace(form) => form.pick(forward),
        _ => {}
    }
}

async fn submit(ctx: &mut ActionCtx<'_>) {
    match page(ctx).mode.clone() {
        VettingMode::List => {}
        // Nothing to submit — it is a code being held up to a phone. Enter
        // closes it, the same as Esc, because both are what a hand reaches for
        // when the scan is done.
        VettingMode::ShowTicket { .. } => back(page(ctx)),
        // Nor here: it says what to run somewhere else. Enter closes it like
        // Esc, rather than being the one view where Enter does nothing.
        VettingMode::HolderGrant { .. } => back(page(ctx)),
        VettingMode::NewApplication {
            community,
            persona_index,
            context_options,
            context_index,
            ..
        } => {
            let context = context_options
                .get(context_index)
                .map(|o| o.context_id.clone());
            start_application(ctx, community.trim(), persona_index, context).await;
        }
        VettingMode::ConfirmAbandon { .. } => abandon_application(ctx),
        VettingMode::ConfirmDeleteTicket { ticket_id } => delete_ticket(ctx, &ticket_id),
        VettingMode::ChooseFace {
            application_id,
            faces,
            index,
            required,
        } => {
            if index == faces.len() {
                open_new_face(ctx, &application_id, required);
            } else {
                wear_face(ctx, &application_id, faces.get(index).cloned());
            }
        }
        VettingMode::NewFace(form) => create_face(ctx, *form),
        VettingMode::RequestVetter {
            application_id,
            entry,
            vetter,
            ticket,
            ..
        } => request_vetter(ctx, &application_id, entry.trim(), vetter.trim(), ticket).await,
        VettingMode::Directory(view) => match view.result_index() {
            Some(_) => ask_listed_vetter(ctx),
            None => search_directory(ctx, vec![None]).await,
        },
        VettingMode::Profile(form) => profile_submit(ctx, *form).await,
        VettingMode::Resend { index } => ask_resend(ctx, index).await,
        VettingMode::EventMode { index } => ask_event_mode(ctx, index).await,
        // Enter is "draw now", as `d` is: the view's one verb.
        VettingMode::HiddenVetting { .. } => {
            status(
                ctx,
                "Reading each community's requirements again and drawing what the schedule owes…",
            );
            refresh_vetter_side(ctx).await;
        }
        VettingMode::SendCard {
            application_id,
            session_id,
            preview,
        } => send_card(ctx, &application_id, &session_id, preview).await,
        VettingMode::NewTicket {
            membership_index,
            uses_index,
            ..
        } => issue_ticket(ctx, membership_index, uses_index).await,
        VettingMode::OpenSession {
            request_id,
            method_index,
        } => open_session(ctx, &request_id, method_index).await,
        VettingMode::Attest { request_id, form } => attest(ctx, &request_id, &form).await,
        VettingMode::ConfirmDecline {
            request_id,
            reason_index,
            message,
            ..
        } => {
            let code = DECLINE_REASONS.get(reason_index).and_then(|(c, _)| *c);
            let message = message.trim();
            if message.chars().count() > DECLINE_MESSAGE_MAX {
                return status(
                    ctx,
                    format!(
                        "The note is {} characters; a decline carries at most \
                         {DECLINE_MESSAGE_MAX}.",
                        message.chars().count()
                    ),
                );
            }
            let message = (!message.is_empty()).then(|| message.to_string());
            decline(ctx, &request_id, code, message).await
        }
        VettingMode::Withdraw {
            statement_id,
            reason_index,
        } => withdraw(ctx, &statement_id, reason_index).await,
    }
}

// ============================================================================
// Sending
// ============================================================================

/// Claim the vetting domain, or say why not.
fn begin(ctx: &mut ActionCtx<'_>) -> bool {
    if ctx.in_flight.try_begin(DispatchDomain::Vetting) {
        return true;
    }
    status(ctx, InFlight::busy_message(DispatchDomain::Vetting));
    false
}

/// Give up on a send before it started: release the domain, say why, and show
/// whatever the book now holds.
fn abandon(ctx: &mut ActionCtx<'_>, what: &str, error: impl std::fmt::Display) {
    ctx.in_flight.finish(DispatchDomain::Vetting);
    let message = format!("{what}: {error}");
    ctx.state.main_page.log(message.clone());
    ctx.state.main_page.sync_from_config(ctx.config);
    status(ctx, message);
}

fn persona_did(config: &Config, persona: PersonaId) -> Option<String> {
    config
        .identities
        .get(&persona)
        .map(|identity| identity.persona_did().to_string())
}

fn resolver(ctx: &ActionCtx<'_>) -> TrustTaskVmResolver {
    TrustTaskVmResolver::new(ctx.tdk.did_resolver().clone())
}

/// Sign `document` as `persona` — with its authentication key, under
/// `proofPurpose: authentication`, like every request — then hand the send
/// to a background job. The caller has claimed the domain; on error it is
/// still claimed.
async fn sign_and_send(
    ctx: &mut ActionCtx<'_>,
    persona: PersonaId,
    mut document: Document,
    sent: Sent,
) -> Result<(), String> {
    let keys = ctx
        .config
        .get_persona_keys_for(persona, ctx.tdk)
        .await
        .map_err(|e| e.to_string())?;
    wire::sign(&mut document, &keys.authentication.secret)
        .await
        .map_err(|e| e.to_string())?;
    let message = wire::to_message(&document).map_err(|e| e.to_string())?;
    let from = document.issuer.clone().unwrap_or_default();
    let to = document.recipient.clone().unwrap_or_default();
    // A manifest question is filed, as the join flow's is, so its answer —
    // and above all its refusal — has a question to land on. Unfiled, a
    // refusal threaded on it matched nothing and was dropped, which also
    // meant a community refusing the version asked was never asked again in
    // the one it serves (`vetting::protocol`).
    if let Sent::Manifest { community } = &sent {
        ctx.config.private.vetting.ask(CommunityQuery {
            document_id: document.id.clone(),
            community: community.clone(),
            persona,
            kind: QueryKind::Manifest,
            sent_at: chrono::Utc::now(),
        });
    }
    spawn_send(ctx, message, &from, &to, sent);
    Ok(())
}

fn spawn_send(ctx: &mut ActionCtx<'_>, message: Message, from: &str, to: &str, sent: Sent) {
    let job = SendJob {
        service: ctx.didcomm_service.clone(),
        listener_id: openvtc_core::didcomm::listener_id_for_did(from, ctx.config),
        to: to.to_string(),
        message: Box::new(message),
        sent,
    };
    background_dispatch::spawn_dispatch(
        ctx.dispatch_tx.clone(),
        DispatchDomain::Vetting,
        async move { DispatchOutcome::Vetting(job.run().await) },
    );
}

/// The criterion `app` gathers for and the path it takes, in words, and a note when one is
/// owed. `None` before its requirements are known.
pub(crate) fn criterion_words(
    book: &VettingBook,
    app: &Application,
) -> Option<(String, Option<String>)> {
    let shown = book.application_vetting(&app.id)?;
    let mut line = shown.criterion_id.clone();
    if let Some(description) = &shown.description {
        line.push_str(&format!(" — {}", sanitize_display(description, 120)));
    }
    line.push_str(&format!(" · {}", shown.path.words()));
    let options = book.vetting_options(&app.community);
    if options.len() > 1 {
        line.push_str(&format!(
            " · {} ways to be vetted here{}",
            options.len(),
            if app.holds_evidence() {
                ""
            } else {
                ", p switches"
            }
        ));
    }
    let note = if let Some(previous) = &app.criterion_repicked {
        Some(format!(
            "The community no longer publishes criterion {previous}; this application now \
             gathers for {} instead.",
            shown.criterion_id
        ))
    } else if shown.path == VettingPath::Named && shown.paths == CriterionPaths::Either {
        Some(format!(
            "This criterion also accepts PCS ZKP, which names no vetter; this application uses \
             named vetting{}.",
            if app.holds_evidence() {
                " — the statements it holds were made that way"
            } else if app.under_way() {
                " (its requests went out named). p switches to PCS ZKP; then send your vetter a \
                 new request"
            } else {
                ". p switches to PCS ZKP"
            }
        ))
    } else if shown.path == VettingPath::Named && book.pcs_zkp(&app.community) {
        Some(format!(
            "This community also accepts PCS ZKP vetting; your application uses criterion {} \
             (named).",
            shown.criterion_id
        ))
    } else {
        None
    };
    Some((line, note))
}

/// `p` on an application: move it to the next way its community offers to be vetted, and say
/// what that means for the requests already out.
fn switch_vetting_path(ctx: &mut ActionCtx<'_>) {
    let v = page(ctx);
    let Some(row) = v.applications.get(v.selected).cloned() else {
        return;
    };
    let had_requests = ctx
        .config
        .private
        .vetting
        .applications
        .iter()
        .any(|a| a.id == row.id && !a.requests.is_empty());
    match ctx.config.private.vetting.switch_vetting(&row.id) {
        Ok(now) => {
            let resend = if had_requests {
                match now.path {
                    VettingPath::Hidden => {
                        " The requests already sent went out named, so they cannot carry the \
                         identifier a PCS ZKP attestation is made to: send your vetter a new \
                         request (r)."
                    }
                    VettingPath::Named => {
                        " Requests already sent asked for a PCS ZKP attestation: send your \
                         vetter a new request (r)."
                    }
                }
            } else {
                ""
            };
            persist(
                ctx,
                format!(
                    "This application now uses criterion {} with {}.{resend}",
                    now.criterion_id,
                    now.path.words()
                ),
            );
        }
        Err(why) => status(ctx, why),
    }
}

async fn refresh_requirements(ctx: &mut ActionCtx<'_>, application_id: &str) {
    let Some(app) = ctx
        .config
        .private
        .vetting
        .applications
        .iter()
        .find(|a| a.id == application_id)
        .cloned()
    else {
        return;
    };
    if !begin(ctx) {
        return;
    }
    let protocol = ctx.config.private.vetting.protocol_for(&app.community);
    let document = match wire::manifest_request(&app.join_did, &app.community, protocol) {
        Ok(d) => d,
        Err(e) => return abandon(ctx, "Could not ask the community", e),
    };
    status(ctx, "Asking the community what it requires…");
    let sent = Sent::Manifest {
        community: app.community.clone(),
    };
    if let Err(e) = sign_and_send(ctx, app.persona, document, sent).await {
        abandon(ctx, "Could not ask the community", e);
    }
}

/// Recompute the contexts a new application can use, for the community and
/// persona on the form. An application that already exists keeps its own.
fn refresh_application_contexts(ctx: &mut ActionCtx<'_>) {
    let (community, persona) = {
        let v = page(ctx);
        let VettingMode::NewApplication {
            community,
            persona_index,
            ..
        } = &v.mode
        else {
            return;
        };
        (
            community.trim().to_string(),
            v.personas.get(*persona_index).map(|p| p.persona),
        )
    };
    let config: &Config = ctx.config;
    let existing = persona
        .and_then(|p| config.private.vetting.application(&community, p))
        .and_then(|a| a.context_id.clone());
    let options = match existing {
        Some(context_id) => vec![ContextOption {
            context_id,
            kind: ContextKind::Existing,
            communities: Vec::new(),
            holds_persona_keys: false,
        }],
        None => {
            let record = persona.and_then(|p| config.account.personas.get(&p));
            let suggested = join_flow::suggested_context(config, &community);
            community_context::context_options(&config.account, record, &suggested)
        }
    };
    if let VettingMode::NewApplication {
        context_options,
        context_index,
        ..
    } = &mut page(ctx).mode
    {
        if *context_options != options {
            *context_index = 0;
        }
        *context_options = options;
    }
}

async fn start_application(
    ctx: &mut ActionCtx<'_>,
    community: &str,
    persona_index: usize,
    context: Option<String>,
) {
    if !community.starts_with("did:") {
        return status(ctx, "Enter the community's DID (it starts with did:).");
    }
    let Some(persona) = page(ctx).personas.get(persona_index).cloned() else {
        return status(ctx, "Choose the persona you will join with.");
    };
    let application_id = match ctx.config.private.vetting.start_application(
        community,
        persona.persona,
        &persona.did,
        Utc::now(),
    ) {
        Ok(app) => {
            if app.context_id.is_none() {
                app.context_id = context;
            }
            app.id.clone()
        }
        Err(e) => return status(ctx, format!("Could not start the application: {e}")),
    };
    // Said, not dropped (R6.4): a criterion this build cannot honour is the one thing that
    // makes this application gather evidence the community will not count.
    let unadopted = ctx
        .config
        .private
        .vetting
        .adopt_known_requirements(&application_id)
        .err()
        .map(|e| format!(" Its requirements could not be taken up: {e}."))
        .unwrap_or_default();
    {
        let v = page(ctx);
        v.mode = VettingMode::List;
        v.tab = VettingTab::Applications;
    }
    persist(ctx, format!("Application started.{unadopted}"));
    if let Some(i) = page(ctx)
        .applications
        .iter()
        .position(|a| a.id == application_id)
    {
        page(ctx).selected = i;
    }
    refresh_requirements(ctx, &application_id).await;
}

/// Send a vetting request carrying the ticket from a `vetting-ticket:` link.
///
/// `entry` is the one field; `vetter` and `ticket` are what a paste already
/// read out of it. Enter with neither of those set — someone typed or pasted
/// without the paste hook firing — reads `entry` here, so the form behaves the
/// same whichever way the text arrived.
async fn request_vetter(
    ctx: &mut ActionCtx<'_>,
    application_id: &str,
    entry: &str,
    vetter: &str,
    ticket: Option<request::v0_1::Ticket>,
) {
    // Not yet read (typed rather than pasted): read it now, which also reports
    // a link for the wrong community or one that cannot be decoded.
    let (vetter, presentation) = match (ticket, vetter.starts_with("did:")) {
        (Some(ticket), true) => (vetter.to_string(), ticket),
        _ => {
            let Some(app) = ctx
                .config
                .private
                .vetting
                .applications
                .iter()
                .find(|a| a.id == application_id)
            else {
                return;
            };
            match app.ticket_from_uri(entry) {
                Ok(ticket) => (ticket.vetter, ticket.presentation),
                Err(_) if entry.is_empty() => {
                    return status(
                        ctx,
                        "Paste the link from the vetter's QR code — it carries their ticket, \
                         and a request without one is never answered.",
                    );
                }
                Err(e) => return status(ctx, sanitize_display(&e.to_string(), 400)),
            }
        }
    };
    let vetter = vetter.as_str();
    if !begin(ctx) {
        return;
    }
    let document_id = wire::new_id();
    let Some(app) = ctx
        .config
        .private
        .vetting
        .application_by_id_mut(application_id)
    else {
        return abandon(ctx, "Could not send the request", "the application is gone");
    };
    let (persona, join_did) = (app.persona, app.join_did.clone());
    let body = match app.prepare_request(
        &document_id,
        vetter,
        presentation,
        RequestDraft::default(),
        Utc::now(),
    ) {
        Ok(body) => body,
        Err(e) => return abandon(ctx, "Could not send the request", e),
    };
    let document = match wire::document(
        VETTING_REQUEST_TYPE,
        &join_did,
        vetter,
        document_id.clone(),
        &body,
    ) {
        Ok(d) => d,
        Err(e) => return abandon(ctx, "Could not send the request", e),
    };
    page(ctx).mode = VettingMode::List;
    persist(ctx, "Sending your request…");
    let sent = Sent::Request {
        application_id: application_id.to_string(),
        document_id: document_id.clone(),
        vetter: vetter.to_string(),
    };
    if let Err(e) = sign_and_send(ctx, persona, document, sent).await {
        if let Some(app) = ctx
            .config
            .private
            .vetting
            .application_by_id_mut(application_id)
        {
            app.forget_unsent(&document_id);
        }
        abandon(ctx, "Could not send the request", e);
    }
}

/// Fill the request form from a pasted `vetting-ticket:` link — the vetter's
/// DID and the scanned ticket — or say why it cannot be used.
fn paste_ticket(ctx: &mut ActionCtx<'_>, text: &str) {
    let VettingMode::RequestVetter { application_id, .. } = &page(ctx).mode else {
        return;
    };
    let application_id = application_id.clone();
    let Some(app) = ctx
        .config
        .private
        .vetting
        .applications
        .iter()
        .find(|a| a.id == application_id)
    else {
        return;
    };
    let pasted = text.trim().to_string();
    match app.ticket_from_uri(text) {
        Ok(ticket) => {
            let shown = shorten_did(&ticket.vetter, 64);
            if let VettingMode::RequestVetter {
                entry,
                vetter,
                ticket: slot,
                ..
            } = &mut page(ctx).mode
            {
                *entry = pasted;
                *vetter = ticket.vetter;
                *slot = Some(ticket.presentation);
            }
            status(
                ctx,
                format!("Read the ticket link. It goes to {shown} — Enter sends the request."),
            );
        }
        Err(e) => status(ctx, sanitize_display(&e.to_string(), 400)),
    }
}

fn open_directory(ctx: &mut ActionCtx<'_>) {
    let v = page(ctx);
    if v.directory_communities.is_empty() {
        return status(
            ctx,
            "The vetter directory is searched per community: start an application (n) or join a \
             community first.",
        );
    }
    // Opened from an application — the list, or its journey — the search
    // starts as that application, by id: two applications to one community
    // are two different personas asking.
    let from_application = (v.tab == VettingTab::Applications)
        .then(|| v.applications.get(v.selected))
        .flatten()
        .map(|a| (a.id.clone(), a.community.clone()));
    let community_index = from_application
        .and_then(|(id, community)| {
            v.directory_communities
                .iter()
                .position(|d| d.application_id.as_deref() == Some(id.as_str()))
                .or_else(|| {
                    v.directory_communities
                        .iter()
                        .position(|d| d.community == community)
                })
        })
        .unwrap_or(0);
    v.mode = VettingMode::Directory(Box::new(DirectoryView {
        community_index,
        ..DirectoryView::default()
    }));
    v.status_message = None;
}

/// Ask the directory's community for one page. `cursors` is what the view's
/// page stack becomes once the answer arrives; its last entry is the cursor
/// sent.
async fn search_directory(ctx: &mut ActionCtx<'_>, cursors: Vec<Option<String>>) {
    let prepared = {
        let v = page(ctx);
        let VettingMode::Directory(view) = &mut v.mode else {
            return;
        };
        if view.pending.is_some() {
            return;
        }
        let Some(target) = v.directory_communities.get(view.community_index).cloned() else {
            return;
        };
        let mut filter = view.filter.clone();
        filter.method = DIRECTORY_METHODS[view.method_index.min(DIRECTORY_METHODS.len() - 1)];
        match filter.to_body(cursors.last().cloned().flatten()) {
            Ok(body) => (target, body),
            Err(e) => {
                // The cursor goes to the row the message names — the filters
                // are nine rows, and a search is run from whichever one the
                // cursor happens to be on.
                if let Some(row) = e.row().and_then(|l| row_of(&DIRECTORY_LABELS, l)) {
                    view.field = row;
                }
                view.error = Some(e.to_string());
                return;
            }
        }
    };
    let (target, body) = prepared;
    let Some(asker) = persona_did(ctx.config, target.persona) else {
        return status(
            ctx,
            "The persona the directory would be searched as is not available.",
        );
    };
    if !begin(ctx) {
        return;
    }
    let document = match wire::vetter_list_request(&asker, &target.community, &body) {
        Ok(d) => d,
        Err(e) => return abandon(ctx, "Could not search the directory", e),
    };
    let document_id = document.id.clone();
    ctx.config.private.vetting.ask(CommunityQuery {
        document_id: document_id.clone(),
        community: target.community.clone(),
        persona: target.persona,
        kind: QueryKind::VetterList,
        sent_at: Utc::now(),
    });
    if let VettingMode::Directory(view) = &mut page(ctx).mode {
        view.pending = Some(document_id.clone());
        view.pending_cursors = Some(cursors);
        view.error = None;
    }
    status(
        ctx,
        format!("Asking {} for its vetter directory…", target.name),
    );
    let sent = Sent::Query {
        document_id: document_id.clone(),
        community: target.community.clone(),
        kind: QueryKind::VetterList,
    };
    if let Err(e) = sign_and_send(ctx, target.persona, document, sent).await {
        ctx.config.private.vetting.forget_query(&document_id);
        if let VettingMode::Directory(view) = &mut page(ctx).mode {
            view.pending = None;
            view.pending_cursors = None;
        }
        abandon(ctx, "Could not search the directory", e);
    }
}

async fn directory_page(ctx: &mut ActionCtx<'_>, forward: bool) {
    let (mut cursors, next) = match &page(ctx).mode {
        VettingMode::Directory(view) if view.pending.is_none() => {
            (view.cursors.clone(), view.next_cursor.clone())
        }
        _ => return,
    };
    if forward {
        let Some(next) = next else {
            return status(ctx, "That is the last page.");
        };
        cursors.push(Some(next));
    } else {
        if cursors.len() <= 1 {
            return status(ctx, "This is the first page.");
        }
        cursors.pop();
    }
    search_directory(ctx, cursors).await;
}

/// Open the request form for the highlighted directory vetter. The directory
/// finds a vetter; it does not let anyone skip the ticket, so the form says
/// how this vetter hands them out.
fn ask_listed_vetter(ctx: &mut ActionCtx<'_>) {
    let v = page(ctx);
    let VettingMode::Directory(view) = &v.mode else {
        return;
    };
    let Some(row) = view
        .result_index()
        .and_then(|i| view.results.get(i))
        .cloned()
    else {
        return;
    };
    let Some(target) = v.directory_communities.get(view.community_index).cloned() else {
        return;
    };
    let Some(application_id) = target.application_id.clone() else {
        return status(
            ctx,
            format!(
                "To ask {} you need an application to {} — start one on the Applications tab (n), \
                 then find them here again.",
                row.name, target.name
            ),
        );
    };
    let how = match &row.contact_hint {
        Some(hint) => format!("they say: {hint}"),
        None => "they have not said how, so ask them".to_string(),
    };
    let v = page(ctx);
    v.mode = VettingMode::RequestVetter {
        application_id,
        entry: String::new(),
        // Left empty on purpose. The directory knows who they are, but the
        // request goes to whoever the *ticket* names, and showing a vetter the
        // form is not going to use would be a claim about where this is going.
        vetter: String::new(),
        ticket: None,
        note: Some(format!(
            "{} still has to give you a ticket before they answer — {how}. Paste the link from \
             their QR code here.",
            row.name
        )),
    };
    v.tab = VettingTab::Applications;
}

/// The profile form for membership `membership_index`, from what was last sent
/// there — or a first profile from this vetter's own policy.
pub(crate) fn profile_form(
    v: &VettingState,
    book: &VettingBook,
    membership_index: usize,
    field: usize,
) -> VetterProfileForm {
    let record = v
        .memberships
        .get(membership_index)
        .and_then(|m| book.vetter_profile(&m.community, m.persona));
    VetterProfileForm {
        membership_index,
        draft: record.map_or_else(
            || ProfileDraft::new(&book.policy),
            |r| r.draft(&book.policy),
        ),
        field,
        event: None,
        error: None,
        state_line: record.map(profile_state_line),
    }
}

fn profile_state_line(record: &VetterProfileRecord) -> (LineTone, String) {
    let day = |at: &chrono::DateTime<Utc>| at.format("%Y-%m-%d").to_string();
    match &record.state {
        ProfileState::Sent { sent_at } => (
            LineTone::Caution,
            format!(
                "Sent {} — the community has not answered yet.",
                day(sent_at)
            ),
        ),
        ProfileState::Stored {
            listed: true,
            updated_at,
        } => (
            LineTone::Good,
            format!("Published {} and listed in the directory.", day(updated_at)),
        ),
        ProfileState::Stored { updated_at, .. } => (
            LineTone::Good,
            format!("Published {}, not listed.", day(updated_at)),
        ),
        ProfileState::Refused { code, at } => (
            LineTone::Bad,
            format!(
                "Refused {} ({}) — the community did not count you as a vetter then.",
                day(at),
                sanitize_display(code, 80)
            ),
        ),
    }
}

fn open_profile(ctx: &mut ActionCtx<'_>) {
    let v = &ctx.state.main_page.content_panel.vetting;
    if v.memberships.is_empty() {
        let hint = if v.resend_candidates.is_empty() {
            ""
        } else {
            " If one did and the credential never arrived, g asks it to send it again."
        };
        return status(
            ctx,
            format!(
                "A profile is published to a community that named you a vetter, and none has.{hint}"
            ),
        );
    }
    let form = profile_form(v, &ctx.config.private.vetting, 0, 0);
    page(ctx).mode = VettingMode::Profile(Box::new(form));
}

/// Enter on the profile form: keep an open event, open one, or publish.
async fn profile_submit(ctx: &mut ActionCtx<'_>, form: VetterProfileForm) {
    if let Some(event) = &form.event {
        let result = event.draft.to_event();
        if let VettingMode::Profile(open) = &mut page(ctx).mode {
            match result {
                Ok(_) => {
                    let kept = match event.index {
                        Some(i) if i < open.draft.events.len() => {
                            open.draft.events[i] = event.draft.clone();
                            i
                        }
                        _ => {
                            open.draft.events.push(event.draft.clone());
                            open.draft.events.len() - 1
                        }
                    };
                    open.event = None;
                    open.error = None;
                    open.field = PROFILE_FIELDS + kept;
                }
                Err(e) => {
                    if let Some(open_event) = &mut open.event {
                        if let Some(row) = e.row().and_then(|l| row_of(&EVENT_LABELS, l)) {
                            open_event.field = row;
                        }
                        open_event.error = Some(e.to_string());
                    }
                }
            }
        }
        return;
    }
    if let Some(i) = form.event_index() {
        if let VettingMode::Profile(open) = &mut page(ctx).mode {
            open.event = Some(EventForm {
                index: Some(i),
                draft: form.draft.events[i].clone(),
                field: 0,
                error: None,
            });
        }
        return;
    }
    if form.on_add_event() {
        if let VettingMode::Profile(open) = &mut page(ctx).mode {
            open.event = Some(EventForm {
                index: None,
                draft: EventDraft::default(),
                field: 0,
                error: None,
            });
        }
        return;
    }
    publish_profile(ctx, &form).await;
}

async fn publish_profile(ctx: &mut ActionCtx<'_>, form: &VetterProfileForm) {
    let Some(membership) = page(ctx).memberships.get(form.membership_index).cloned() else {
        return;
    };
    let body = match form.draft.to_body() {
        Ok(body) => body,
        Err(e) => {
            if let VettingMode::Profile(open) = &mut page(ctx).mode {
                // Put the cursor on the row the message names, so a refusal
                // read at the bottom of thirteen rows says where to go and
                // then goes there. An event's rows are the event form's, so a
                // refusal from one lands on the event's row here instead.
                if let Some(index) = e.event() {
                    open.field = PROFILE_FIELDS + index;
                } else if let Some(row) = e.row().and_then(|l| row_of(&PROFILE_LABELS, l)) {
                    open.field = row;
                }
                open.error = Some(e.to_string());
            }
            return;
        }
    };
    let Some(vetter_did) = persona_did(ctx.config, membership.persona) else {
        return status(
            ctx,
            "The persona this community named a vetter is not available.",
        );
    };
    if !begin(ctx) {
        return;
    }
    let document = match wire::vetter_profile_request(&vetter_did, &membership.community, &body) {
        Ok(d) => d,
        Err(e) => return abandon(ctx, "Could not publish your profile", e),
    };
    let document_id = document.id.clone();
    let now = Utc::now();
    let book = &mut ctx.config.private.vetting;
    let previous = book.record_profile_sent(&membership.community, membership.persona, &body, now);
    book.ask(CommunityQuery {
        document_id: document_id.clone(),
        community: membership.community.clone(),
        persona: membership.persona,
        kind: QueryKind::VetterProfile,
        sent_at: now,
    });
    {
        let v = page(ctx);
        v.mode = VettingMode::List;
        // Back to the desk, on whichever view it was left on: what happened to
        // the profile shows in the desk header, which every view carries.
        v.tab = VettingTab::Desk;
    }
    persist(ctx, format!("Sending your profile to {}…", membership.name));
    let sent = Sent::Profile {
        document_id: document_id.clone(),
        community: membership.community.clone(),
        persona: membership.persona,
        previous: previous.clone().map(Box::new),
    };
    if let Err(e) = sign_and_send(ctx, membership.persona, document, sent).await {
        let book = &mut ctx.config.private.vetting;
        book.restore_profile(&membership.community, membership.persona, previous);
        book.forget_query(&document_id);
        abandon(ctx, "Could not publish your profile", e);
    }
}

/// Ask a community to let us vet at one of its events, at one of its published tiers.
///
/// The window we ask for is the event's own. A vetter naming their own days would say which
/// days of a conference they expect to be at the desk, and a community that had to compare two
/// vetters' windows would learn more from the difference than from either.
///
/// What comes back is never a grant — approval is somebody else's act — so the answer is
/// recorded and the label opens later, or not at all.
async fn ask_event_mode(ctx: &mut ActionCtx<'_>, index: usize) {
    let Some(offer) = page(ctx).event_offers.get(index).cloned() else {
        return;
    };
    let Some(did) = persona_did(ctx.config, offer.persona) else {
        return status(
            ctx,
            "The persona that belongs to this community is not available.",
        );
    };
    if !begin(ctx) {
        return;
    }
    let body = openvtc_core::vetting::wire::pcs::EventModeRequest {
        event_id: offer.event_id.clone(),
        tier: offer.tier.clone(),
        window: openvtc_core::vetting::wire::pcs::EventWindow {
            start_date: offer.start_date,
            end_date: offer.end_date,
        },
    };
    let document = match wire::pcs_event_mode_request(&did, &offer.community, &body) {
        Ok(d) => d,
        Err(e) => return abandon(ctx, "Could not ask to vet at the event", e),
    };
    let document_id = document.id.clone();
    ctx.config.private.vetting.ask(CommunityQuery {
        document_id: document_id.clone(),
        community: offer.community.clone(),
        persona: offer.persona,
        kind: QueryKind::PcsEventMode,
        sent_at: Utc::now(),
    });
    page(ctx).mode = VettingMode::List;
    status(
        ctx,
        format!(
            "Asking {} to vet at {} ({})…",
            offer.community_name, offer.event_id, offer.tier
        ),
    );
    let sent = Sent::Query {
        document_id: document_id.clone(),
        community: offer.community.clone(),
        kind: QueryKind::PcsEventMode,
    };
    if let Err(e) = sign_and_send(ctx, offer.persona, document, sent).await {
        ctx.config.private.vetting.forget_query(&document_id);
        abandon(ctx, "Could not ask to vet at the event", e);
    }
}

async fn ask_resend(ctx: &mut ActionCtx<'_>, index: usize) {
    let Some(target) = page(ctx).resend_candidates.get(index).cloned() else {
        return;
    };
    let Some(did) = persona_did(ctx.config, target.persona) else {
        return status(
            ctx,
            "The persona that belongs to this community is not available.",
        );
    };
    if !begin(ctx) {
        return;
    }
    let document = match wire::vetter_resend_request(&did, &target.community) {
        Ok(d) => d,
        Err(e) => return abandon(ctx, "Could not ask for your vetter credential", e),
    };
    let document_id = document.id.clone();
    ctx.config.private.vetting.ask(CommunityQuery {
        document_id: document_id.clone(),
        community: target.community.clone(),
        persona: target.persona,
        kind: QueryKind::VetterResend,
        sent_at: Utc::now(),
    });
    page(ctx).mode = VettingMode::List;
    status(
        ctx,
        format!(
            "Asking {} to send your vetter credential again…",
            target.name
        ),
    );
    let sent = Sent::Query {
        document_id: document_id.clone(),
        community: target.community.clone(),
        kind: QueryKind::VetterResend,
    };
    if let Err(e) = sign_and_send(ctx, target.persona, document, sent).await {
        ctx.config.private.vetting.forget_query(&document_id);
        abandon(ctx, "Could not ask for your vetter credential", e);
    }
}

/// Drop the application the confirmation is armed on.
///
/// Delete a ticket, once the confirmation has been taken.
///
/// Irreversible and invisible to the people who matter: whoever is holding a
/// copy of this ticket — read off a screen, scanned from a QR code — finds
/// their request refused with `invalidTicket` and no way to tell that the
/// ticket was withdrawn rather than mistyped. That is why it is confirmed, and
/// why the message says what it costs rather than only that it happened.
fn delete_ticket(ctx: &mut ActionCtx<'_>, ticket_id: &str) {
    let Some(ticket) = ctx
        .config
        .private
        .vetting
        .tickets
        .iter()
        .find(|t| t.id == ticket_id)
        .cloned()
    else {
        back(page(ctx));
        return status(ctx, "That ticket is already gone.");
    };
    ctx.config
        .private
        .vetting
        .tickets
        .retain(|t| t.id != ticket_id);
    back(page(ctx));
    page(ctx).selected = 0;
    persist(
        ctx,
        format!(
            "Ticket {} deleted — anyone already holding it is now refused, and they are not \
             told why.",
            ticket.code
        ),
    );
}

/// Local only: vetting is client-side until the join is submitted, so nothing
/// was sent to the community and there is nothing to withdraw from it. What the
/// message says instead is the part that is *not* tidied — a vetter who already
/// accepted a request still holds it, and this cannot reach them.
fn abandon_application(ctx: &mut ActionCtx<'_>) {
    let VettingMode::ConfirmAbandon { application_id } = page(ctx).mode.clone() else {
        return;
    };
    let Some(app) = ctx
        .config
        .private
        .vetting
        .abandon_application(&application_id)
    else {
        back(page(ctx));
        return status(ctx, "That application is already gone.");
    };
    let community = community_display(ctx.config, &app.community);
    let asked = app.requests.len();
    back(page(ctx));
    ctx.state.main_page.content_panel.vetting.selected = 0;
    ctx.state.main_page.sync_from_config(ctx.config);
    ctx.save.mark_dirty();
    status(
        ctx,
        if asked == 0 {
            format!("Abandoned your application to {community}.")
        } else {
            format!(
                "Abandoned your application to {community}. {asked} vetter{} still \
                 hold{} your request — tell them, or they will open a session with \
                 nothing to answer.",
                if asked == 1 { "" } else { "s" },
                if asked == 1 { "s" } else { "" }
            )
        },
    );
}

/// What a failed card preview means, when we can tell.
///
/// One refusal has a specific cause and a specific answer: the face being worn
/// holds none of the claim types the vetter's session asked for. The agent says
/// so accurately — "none of the requested claim types are present in this
/// persona's profile" — in a sentence that names neither the claim types nor
/// the face nor the key that changes it, wrapped in two layers of protocol
/// framing. Everything else is passed through: a failure we cannot explain is
/// better verbatim than paraphrased into a guess (R6.4).
fn preview_refusal(error: &str, application_id: &str, config: &Config) -> String {
    // The persona wears no face in the community's context at all. Making an
    // application does not choose one — `f` does — so this is the first card of
    // any application whose face was never picked, and the agent's sentence
    // names the persona's DID and nothing the holder can press.
    if error.contains("has no profile bound") {
        return "This application has no face yet, so there is no card to show. Press f to \
                choose the face vetters see — you come back here once it is worn."
            .to_string();
    }
    if !error.contains("none of the requested claim types are present") {
        return format!("Could not preview the card: {error}");
    }
    let app = config
        .private
        .vetting
        .applications
        .iter()
        .find(|a| a.id == application_id);
    let wanted = app.map(required_claim_types).unwrap_or_default();
    let face = app.and_then(|a| a.face.as_ref()).map_or_else(
        || "The face you are wearing".to_string(),
        |f| f.name.clone(),
    );
    if wanted.is_empty() {
        return format!(
            "{face} holds none of the claims this vetter asked for. Press f to wear a face that \
             does — making a new one there asks for anything you have not added."
        );
    }
    format!(
        "{face} holds none of {}, which this community's card must carry. Press f to wear a \
         face that has them — making a new one there asks for anything you have not added.",
        wanted.join(", ")
    )
}

/// Open the make-a-face form, reading the pool to fill its tick list.
///
/// The read is what makes this worth doing inline: the community has already
/// said which claim types it needs, so the form opens with the matching
/// attributes already ticked and the holder's decision is usually just a name.
fn open_new_face(ctx: &mut ActionCtx<'_>, application_id: &str, required: Vec<String>) {
    let Some(client) = admin_client(ctx) else {
        return;
    };
    if !begin(ctx) {
        return;
    }
    status(ctx, "Reading your attributes…");
    let job = FaceJob::Pool {
        client,
        application_id: application_id.to_string(),
        required,
        registry: ctx
            .state
            .main_page
            .content_panel
            .identity
            .claim_types
            .clone(),
    };
    spawn_job(ctx, job.run());
}

/// Enter on the make-a-face form: save a value typed in place, or create the
/// face and wear it.
///
/// What Enter does is decided by [`NewFaceForm::enter`], which the form's
/// status line describes — so a refusal is never a second message contradicting
/// the first, it is the form moving to the row the status line names.
///
/// Making the face is one step, not two. A face made here exists only to be
/// worn by this application — leaving it created but unworn would put the
/// holder back on the picker to do the thing they had just asked for.
fn create_face(ctx: &mut ActionCtx<'_>, mut form: NewFaceForm) {
    let (name, live_refs) = match form.enter() {
        NewFaceStep::Wait => {
            page(ctx).mode = VettingMode::NewFace(Box::new(form));
            return;
        }
        NewFaceStep::Save(draft) => return save_attribute(ctx, form, draft),
        NewFaceStep::Make { name, live_refs } => (name, live_refs),
    };
    let Some(client) = admin_client(ctx) else {
        return;
    };
    let application_id = form.application_id.clone();
    let (context_id, persona_did) = match application_context(ctx.config, &application_id) {
        Ok(found) => found,
        Err(e) => return status(ctx, format!("Cannot make a face: {e}")),
    };
    if !begin(ctx) {
        return;
    }
    page(ctx).mode = VettingMode::List;
    status(ctx, format!("Making {name}…"));
    let job = FaceJob::Create {
        client,
        top_context_id: ctx.config.account.top_context_id.clone(),
        context_id,
        persona_did,
        application_id,
        name,
        live_refs,
    };
    spawn_job(ctx, job.run());
}

/// Save a value typed on the make-a-face form as an attribute of its own.
///
/// The same write My Identity makes (`pool::put`, self-asserted), so the value
/// lands in the pool as a real attribute that page lists and edits like any
/// other. The form stays open and waiting: when the write returns, the new
/// attribute is ticked and the holder is one Enter from the face.
fn save_attribute(
    ctx: &mut ActionCtx<'_>,
    mut form: NewFaceForm,
    draft: openvtc_core::persona::pool::AttributeDraft,
) {
    let client = admin_client(ctx);
    let started = client.is_some() && begin(ctx);
    if !started {
        // Not sent, so not saving: the form must not sit waiting on a write
        // that never left.
        form.saving = None;
    }
    let application_id = form.application_id.clone();
    page(ctx).mode = VettingMode::NewFace(Box::new(form));
    let Some(client) = client.filter(|_| started) else {
        return;
    };
    let job = FaceJob::AddAttribute {
        client,
        application_id,
        draft,
        registry: ctx
            .state
            .main_page
            .content_panel
            .identity
            .claim_types
            .clone(),
    };
    spawn_job(ctx, job.run());
}

/// The claim types any open session names as optional, for the make-a-face
/// form to offer — never to pre-tick.
fn optional_claim_types(app: &Application) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for request in &app.requests {
        if let RequestState::Session { session, .. } = &request.state {
            for claim in &session.optional_claims {
                if !out.contains(claim) {
                    out.push(claim.clone());
                }
            }
        }
    }
    out
}

/// What a face made for `community` is called until the holder renames it.
///
/// The community's agent name only once it has been verified (the cached
/// round-trip), never one read straight from a document: a face's name is
/// something the holder recognises it by, and an unverified name could put a
/// name of anyone's choosing there. Otherwise a plain word, so the field is
/// never blank and Enter is never refused for want of a name.
fn default_face_name(config: &Config, community: &str) -> String {
    config
        .agent_name_for(community)
        .map(|name| sanitize_display(name, 64))
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| "Vetting".to_string())
}

/// A pool attribute as a row on the make-a-face form, its value painted the way
/// the Identity page paints it.
fn pool_row(attribute: &PoolAttribute, registry: &Registry) -> PoolRow {
    PoolRow {
        label: sanitize_display(attribute.display_name(), 128),
        claim_type: attribute.claim_type.clone(),
        attribute_id: attribute.attribute_id.clone(),
        value: attribute
            .value
            .as_ref()
            .map(|_| sanitize_display(&attribute.display_value(registry, true), 128)),
    }
}

/// The claim types a card for this community must carry.
///
/// From the manifest when it has been read, and from the fallback set when it
/// has not — the same rule the identity block on the application already used,
/// lifted out so the face picker answers against the same list. A picker
/// judging faces by a different standard than the card is checked against would
/// be worse than one that says nothing.
fn required_claim_types(app: &Application) -> Vec<String> {
    app.requirements
        .as_ref()
        .map(|r| {
            r.required_claims
                .iter()
                .flatten()
                .map(|c| c.as_str().to_string())
                .collect::<Vec<_>>()
        })
        .filter(|claims| !claims.is_empty())
        .unwrap_or_else(|| {
            FALLBACK_REQUIRED_CLAIMS
                .iter()
                .map(ToString::to_string)
                .collect()
        })
}

/// The DID this install authenticates to its agent as, when it has one.
///
/// A BIP32 account has no agent credential at all — and, having no agent, will
/// not have produced a holder refusal in the first place.
fn agent_credential_did(config: &Config) -> Option<&str> {
    match &config.key_backend {
        openvtc_core::config::KeyBackend::Vta { credential_did, .. } => Some(credential_did),
        openvtc_core::config::KeyBackend::Bip32 { .. } => None,
    }
}

/// What a card's disclosure tells the VTA it is for.
const VETTING_PURPOSE: &str = "identity vetting";

/// The VTA session, or say why there is none.
fn admin_client(ctx: &mut ActionCtx<'_>) -> Option<VtaClient> {
    let client = ctx.admin_vta.cloned();
    if client.is_none() {
        status(
            ctx,
            "Faces live in your VTA, and it is not connected — try again once it is.",
        );
    }
    client
}

/// The VTA context an application's face is worn in, and its join DID.
/// Derived the first time it is needed and kept on the application, so the
/// membership reuses it when the join goes through.
fn application_context(
    config: &mut Config,
    application_id: &str,
) -> Result<(String, String), String> {
    let app = config
        .private
        .vetting
        .applications
        .iter()
        .find(|a| a.id == application_id)
        .ok_or("the application is gone")?;
    let join_did = app.join_did.clone();
    if let Some(id) = &app.context_id {
        return Ok((id.clone(), join_did));
    }
    // A persona whose keys live in a sub-context is presented from it;
    // otherwise the community gets a context of its own.
    let top = config.account.top_context_id.as_str();
    let id = match config
        .account
        .personas
        .get(&app.persona)
        .map(|p| community_context::persona_context(p, top))
        .filter(|home| community_context::is_sub_context(home, top))
    {
        Some(home) => home.to_string(),
        None => join_flow::suggested_context(config, &app.community.clone()),
    };
    if let Some(app) = config.private.vetting.application_by_id_mut(application_id) {
        app.context_id = Some(id.clone());
    }
    Ok((id, join_did))
}

fn spawn_job(ctx: &mut ActionCtx<'_>, job: impl Future<Output = VettingOutcome> + Send + 'static) {
    background_dispatch::spawn_dispatch(
        ctx.dispatch_tx.clone(),
        DispatchDomain::Vetting,
        async move { DispatchOutcome::Vetting(job.await) },
    );
}

/// Read the holder's faces, and which one the application wears.
fn list_faces(ctx: &mut ActionCtx<'_>, application_id: &str) {
    let Some(client) = admin_client(ctx) else {
        return;
    };
    let (context_id, persona_did) = match application_context(ctx.config, application_id) {
        Ok(found) => found,
        Err(e) => return status(ctx, format!("Cannot choose a face: {e}")),
    };
    if !begin(ctx) {
        return;
    }
    status(ctx, "Reading your faces…");
    let job = FaceJob::List {
        client,
        context_id,
        persona_did,
        application_id: application_id.to_string(),
    };
    spawn_job(ctx, job.run());
}

/// Wear `face` in the application's context.
fn wear_face(ctx: &mut ActionCtx<'_>, application_id: &str, face: Option<FaceChoice>) {
    let Some(face) = face else {
        return status(ctx, "Make a face under My Identity first.");
    };
    if face.worn {
        let v = page(ctx);
        v.mode = v
            .card_after_face
            .take()
            .map_or(VettingMode::List, card_mode);
        return status(
            ctx,
            format!("{} is already the face you show vetters.", face.name),
        );
    }
    let Some(client) = admin_client(ctx) else {
        return;
    };
    let (context_id, persona_did) = match application_context(ctx.config, application_id) {
        Ok(found) => found,
        Err(e) => return status(ctx, format!("Cannot wear that face: {e}")),
    };
    if !begin(ctx) {
        return;
    }
    page(ctx).mode = VettingMode::List;
    status(ctx, format!("Wearing {}…", face.name));
    let job = FaceJob::Wear {
        client,
        top_context_id: ctx.config.account.top_context_id.clone(),
        context_id,
        persona_did,
        application_id: application_id.to_string(),
        face,
    };
    spawn_job(ctx, job.run());
}

/// The card for `session_id`, in two steps: preview what the face would show
/// the vetter, then — once the holder has seen it — release, sign and send.
async fn send_card(
    ctx: &mut ActionCtx<'_>,
    application_id: &str,
    session_id: &str,
    preview: Option<CardPreview>,
) {
    let Some(application) = ctx
        .config
        .private
        .vetting
        .applications
        .iter()
        .find(|a| a.id == application_id)
        .cloned()
    else {
        return;
    };
    let Some((vetter, expires_at)) = application
        .session(session_id)
        .map(|(vetter, s)| (vetter.to_string(), s.expires_at))
    else {
        return status(ctx, "That session has closed.");
    };
    if expires_at <= Utc::now() {
        return status(
            ctx,
            "The session has expired — ask the vetter to open another.",
        );
    }
    if let Some(problem) = preview.as_ref().and_then(|p| p.problem.clone()) {
        return status(ctx, problem);
    }
    let Some(client) = admin_client(ctx) else {
        return;
    };
    let context_id = match application_context(ctx.config, application_id) {
        Ok((id, _)) => id,
        Err(e) => return status(ctx, format!("Cannot send a card: {e}")),
    };
    if !begin(ctx) {
        return;
    }
    let step = match preview {
        None => {
            status(ctx, "Asking your VTA what your face shows this vetter…");
            CardStep::Preview
        }
        Some(preview) => {
            // The card is signed here, as the persona DID, with the persona's
            // own assertionMethod key — the same path every other document
            // this client signs takes.
            let (signer, document_signer) = match ctx
                .config
                .get_persona_keys_for(application.persona, ctx.tdk)
                .await
            {
                Ok(keys) => (
                    keys.signing.secret.clone(),
                    keys.authentication.secret.clone(),
                ),
                Err(e) => return abandon(ctx, "Could not sign the card", e),
            };
            status(ctx, "Releasing and signing your card…");
            CardStep::Present(Box::new(Presenting {
                preview_id: preview.preview_id,
                signer,
                document_signer,
                resolver: resolver(ctx),
                service: ctx.didcomm_service.clone(),
                listener_id: openvtc_core::didcomm::listener_id_for_did(
                    &application.join_did,
                    ctx.config,
                ),
            }))
        }
    };
    let job = CardJob {
        client,
        context_id,
        vetter,
        application,
        session_id: session_id.to_string(),
        step,
    };
    spawn_job(ctx, job.run());
}

/// Why no ticket should be issued for `membership` now, if there is a reason: the community
/// proves vetting with a PCS zero-knowledge proof, and this vetter cannot attest there yet — no
/// credential, or no token. A ticket brings requests, and every one would end at "cannot
/// attest". Asked only once the community's mode has just been read as PCS ZKP
/// ([`ticket_check`]).
fn ticket_refusal(
    book: &VettingBook,
    membership: &VettingMembership,
    now: DateTime<Utc>,
) -> Option<String> {
    let (_, true) = pcs_tokens_line(book, &membership.community, membership.persona, now)? else {
        return None;
    };
    // The full story once, here, where it is acted on — what getting tokens takes now, or what
    // blocks it and until when; the desk header keeps the short line.
    let why = get_tokens_words(
        book,
        &membership.community,
        membership.persona,
        &membership.name,
        now,
    );
    Some(format!(
        "No ticket issued: {} vets by PCS ZKP now, and you cannot attest there yet — {}. A \
         ticket now would bring requests you could not attest.",
        membership.name,
        clause(&why)
    ))
}

/// The longest a ticket waits on its community's answer about how it vets. The question's own
/// reply window ([`QUERY_TIMEOUT`]) normally ends it first, as "no answer"; this is the bound
/// that holds even if that never fires (R1.2).
fn ticket_check_wait() -> chrono::Duration {
    QUERY_TIMEOUT + chrono::Duration::seconds(5)
}

/// Where a pending ticket stands.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TicketCheck {
    /// No answer about the community's mode since it was asked, and still within the wait.
    Waiting,
    /// The community answered: issue the ticket, under this mode.
    Issue(VetterMode),
    /// Not issued: the community runs PCS ZKP and this vetter holds no token to attest with.
    /// What getting tokens takes — or what blocks it, and until when — is said, and the
    /// schedule is run at once so they come without a second key.
    Gated(String),
    /// Not issued, and why.
    Refused(String),
}

/// Decide a pending ticket, on an answer about its community's mode that arrived **after** the
/// ticket was asked for — never on the remembered mode. Named vetting issues with no gate (it
/// does not matter that the community used to run PCS ZKP); PCS ZKP keeps the enrolment and
/// token gate ([`ticket_refusal`]); a failed read refuses, saying how it failed and what was
/// last known, rather than guessing either way.
pub(crate) fn ticket_check(
    book: &VettingBook,
    pending: &PendingTicket,
    now: DateTime<Utc>,
) -> TicketCheck {
    let reading = book.vetter_mode(&pending.membership.community);
    match reading.read_since(pending.asked_at) {
        Some(VetterMode::Named) => TicketCheck::Issue(VetterMode::Named),
        Some(VetterMode::PcsZkp) => match ticket_refusal(book, &pending.membership, now) {
            Some(refusal) => TicketCheck::Gated(refusal),
            None => TicketCheck::Issue(VetterMode::PcsZkp),
        },
        None => {
            let failure = reading.failed_since(pending.asked_at).cloned().or_else(|| {
                (now - pending.asked_at >= ticket_check_wait()).then_some(ModeFailure::Unanswered)
            });
            match failure {
                Some(failure) => TicketCheck::Refused(ticket_unconfirmed(
                    &pending.membership.name,
                    &failure,
                    &reading,
                    now,
                )),
                None => TicketCheck::Waiting,
            }
        }
    }
}

/// No ticket, because how the community vets now could not be read.
fn ticket_unconfirmed(
    name: &str,
    failure: &ModeFailure,
    reading: &openvtc_core::vetting::mode::ModeReading,
    now: DateTime<Utc>,
) -> String {
    format!(
        "No ticket issued: could not confirm how {name} vets now — {}. Last known: {}. A ticket \
         is issued only on a fresh answer, since it brings requests answered under that mode; \
         press t to try again.",
        clause(&failure.words()),
        reading.last_known_words(now)
    )
}

/// `t` on the Tickets view, confirmed: ask the community how it vets **now**, and issue the
/// ticket when it answers ([`settle_pending_tickets`]). Never decided here, from what the client
/// remembers — a community can switch between named vetting and PCS ZKP at any time, and the
/// ticket follows the mode it runs when it is handed out.
async fn issue_ticket(ctx: &mut ActionCtx<'_>, membership_index: usize, uses_index: usize) {
    let Some(membership) = page(ctx).memberships.get(membership_index).cloned() else {
        return;
    };
    let uses = VETTING_TICKET_USES[uses_index.min(VETTING_TICKET_USES.len() - 1)];
    page(ctx).mode = VettingMode::List;
    if let Some(waiting) = &page(ctx).pending_ticket {
        let name = waiting.membership.name.clone();
        return status(
            ctx,
            format!("Still asking {name} how it vets, for the last ticket — a moment."),
        );
    }
    let Some(did) = persona_did(ctx.config, membership.persona) else {
        return status(
            ctx,
            "No ticket issued: the persona you vet for that community as is not available.",
        );
    };
    if !begin(ctx) {
        return;
    }
    let now = Utc::now();
    let community = membership.community.clone();
    let protocol = ctx.config.private.vetting.protocol_for(&community);
    let document = match wire::manifest_request(&did, &community, protocol) {
        Ok(d) => d,
        Err(e) => return abandon(ctx, "No ticket issued: could not build the question", e),
    };
    ctx.config.private.vetting.mode_asked(&community, now);
    let sent = Sent::Manifest {
        community: community.clone(),
    };
    if let Err(e) = sign_and_send(ctx, membership.persona, document, sent).await {
        let failure = ModeFailure::Unsent(e);
        ctx.config
            .private
            .vetting
            .mode_failed(&community, failure.clone(), now);
        let reading = ctx.config.private.vetting.vetter_mode(&community);
        let words = ticket_unconfirmed(&membership.name, &failure, &reading, now);
        ctx.in_flight.finish(DispatchDomain::Vetting);
        ctx.state.main_page.log(words.clone());
        return status(ctx, words);
    }
    let name = membership.name.clone();
    page(ctx).pending_ticket = Some(PendingTicket {
        membership,
        uses,
        asked_at: now,
    });
    status(
        ctx,
        format!(
            "Asking {name} how it vets now — named vetting or PCS ZKP — before issuing the \
             ticket…"
        ),
    );
}

/// What a ticket issued under `mode` promises, in words. A community running PCS ZKP alongside
/// named vetters gets requests of both kinds — an applicant picks its path, and defaults to PCS
/// ZKP — so the ticket says so rather than promising a proof every time. The token gate still
/// holds there: most requests will ask for a proof.
pub(crate) fn ticket_mode_words(book: &VettingBook, community: &str, mode: VetterMode) -> String {
    if mode == VetterMode::PcsZkp && book.named_alongside_hidden(community) {
        format!(
            "{} (named vetting too: a request that asks for a named statement gets one)",
            mode.words()
        )
    } else {
        mode.words().to_string()
    }
}

/// Issue `pending` under `mode`, and show it. `lead` goes first: a switch of mode to say.
fn mint_ticket(
    state: &mut State,
    config: &mut Config,
    save: &mut SaveScheduler,
    pending: &PendingTicket,
    mode: VetterMode,
    lead: Option<&str>,
    now: DateTime<Utc>,
) {
    let membership = &pending.membership;
    let mut ticket = Ticket::issue(
        &membership.community,
        membership.persona,
        vec![],
        pending.uses,
        DEFAULT_VALIDITY,
        now,
    );
    ticket.mode = Some(mode);
    let code = ticket.code.clone();
    config.private.vetting.tickets.push(ticket);
    {
        let v = &mut state.main_page.content_panel.vetting;
        v.mode = VettingMode::List;
        // The new ticket's own view: the message below names `y`, which is a
        // key of that view.
        v.tab = VettingTab::Desk;
        v.desk_view = DeskView::Tickets;
    }
    let uses = pending.uses;
    let message = format!(
        "{}Ticket {code} for {}, under {} — press ⏎ to show its QR code, or u to copy its link. \
         It admits {uses} request{} for 14 days.",
        lead.map(|l| format!("{l} ")).unwrap_or_default(),
        membership.name,
        ticket_mode_words(&config.private.vetting, &membership.community, mode),
        if uses == 1 { "" } else { "s" }
    );
    dispatch_util::save_and_sync(
        &mut state.main_page,
        config,
        save,
        Persist::SaveAndSync,
        |mp| &mut mp.content_panel.vetting.status_message,
        message.clone(),
        SyncLog::Plain(message),
    );
    let v = &mut state.main_page.content_panel.vetting;
    v.selected = v.tickets.len().saturating_sub(1);
}

/// Say each community seen switching mode since last asked, and decide the pending ticket if
/// its answer is in. Run after community answers arrive, and on the loop's sweep — which is
/// what ends a ticket whose question was never answered.
pub(crate) fn settle_pending_tickets(
    state: &mut State,
    config: &mut Config,
    save: &mut SaveScheduler,
    now: DateTime<Utc>,
) {
    let switches = config.private.vetting.take_mode_switches();
    let said: Vec<String> = switches
        .iter()
        .map(|s| s.words(&community_display(config, &s.community)))
        .collect();
    for words in &said {
        state.main_page.log(words.clone());
    }
    let pending = state.main_page.content_panel.vetting.pending_ticket.clone();
    let check = pending
        .as_ref()
        .map(|p| ticket_check(&config.private.vetting, p, now));
    // The switch behind a pending ticket's answer leads its message, named as the ticket is.
    let lead = pending.as_ref().and_then(|p| {
        switches
            .iter()
            .rev()
            .find(|s| s.community == p.membership.community)
            .map(|s| s.words(&p.membership.name))
    });
    match (pending, check) {
        (Some(pending), Some(TicketCheck::Issue(mode))) => {
            state.main_page.content_panel.vetting.pending_ticket = None;
            mint_ticket(state, config, save, &pending, mode, lead.as_deref(), now);
        }
        (Some(pending), Some(TicketCheck::Gated(why))) => {
            let membership = &pending.membership;
            let obtainable = tokens_obtainable_now(
                &config.private.vetting,
                &membership.community,
                membership.persona,
                now,
            );
            // The one action that gets tokens, run now rather than offered: enrol if needed,
            // then draw every window that has begun (the loop takes the flag within seconds).
            // Nothing is drawn ahead of the schedule, so this says no more about the vetter's
            // activity than the schedule does. When there is nothing to run — a lost enrolment,
            // or this window drawn already — the words above say until when, and what to do.
            let then = if !obtainable {
                ""
            } else {
                config.private.vetting.vetter_refresh_due = true;
                " Getting them now — press t again once they arrive (k does this by hand)."
            };
            let words = match lead {
                Some(lead) => format!("{lead} {why}{then}"),
                None => format!("{why}{then}"),
            };
            let v = &mut state.main_page.content_panel.vetting;
            v.pending_ticket = None;
            v.status_message = Some(words.clone());
            state.main_page.log(words);
        }
        (Some(_), Some(TicketCheck::Refused(why))) => {
            let words = match lead {
                Some(lead) => format!("{lead} {why}"),
                None => why,
            };
            let v = &mut state.main_page.content_panel.vetting;
            v.pending_ticket = None;
            v.status_message = Some(words.clone());
            state.main_page.log(words);
        }
        _ => {
            if !said.is_empty() {
                state.main_page.content_panel.vetting.status_message = Some(said.join(" "));
            }
        }
    }
}

async fn open_session(ctx: &mut ActionCtx<'_>, request_id: &str, method_index: usize) {
    let Some(entry) = ctx.config.private.vetting.desk_entry(request_id).cloned() else {
        return;
    };
    let Some(vetter_did) = persona_did(ctx.config, entry.persona) else {
        return status(
            ctx,
            "The persona this request was made to is not available.",
        );
    };
    let (required, known) = ctx.config.private.vetting.required_claims_for(
        &entry.community,
        entry
            .request
            .requirements_digest
            .as_ref()
            .map(|d| d.as_str()),
    );
    let asked = page(ctx).requirements_requested.contains(&entry.community);
    if !known && !asked {
        // Every vetter of one application must ask for the same claims, or the
        // cards commit to different identities. Ask the community first.
        if !begin(ctx) {
            return;
        }
        page(ctx)
            .requirements_requested
            .push(entry.community.clone());
        let protocol = ctx.config.private.vetting.protocol_for(&entry.community);
        let document = match wire::manifest_request(&vetter_did, &entry.community, protocol) {
            Ok(d) => d,
            Err(e) => return abandon(ctx, "Could not ask the community", e),
        };
        status(
            ctx,
            "Asking the community which claims it requires — open the session again in a moment.",
        );
        let sent = Sent::Manifest {
            community: entry.community.clone(),
        };
        if let Err(e) = sign_and_send(ctx, entry.persona, document, sent).await {
            abandon(ctx, "Could not ask the community", e);
        }
        return;
    }
    if !begin(ctx) {
        return;
    }
    let session_id = wire::new_id();
    let method: VettingMethod = VETTING_METHODS[method_index.min(VETTING_METHODS.len() - 1)];
    let body = match ctx.config.private.vetting.open_session(
        request_id,
        method,
        required,
        vec![],
        &session_id,
        Utc::now(),
    ) {
        Ok(body) => body,
        Err(e) => return abandon(ctx, "Could not open the session", e),
    };
    let document = match wire::document(
        VETTING_SESSION_TYPE,
        &vetter_did,
        &entry.applicant,
        session_id,
        &body,
    ) {
        Ok(d) => d,
        Err(e) => return abandon(ctx, "Could not open the session", e),
    };
    // Signed here rather than in `sign_and_send`, because the desk keeps the
    // document exactly as it goes out: the Vetting Statement that closes this
    // session cites it by `taskDigestMultibase`, which `vetted/1` requires.
    // Signed and kept before `persist`, so the saved desk holds it.
    let mut document = document;
    let keys = match ctx
        .config
        .get_persona_keys_for(entry.persona, ctx.tdk)
        .await
    {
        Ok(keys) => keys,
        Err(e) => return abandon(ctx, "Could not send the session", e),
    };
    if let Err(e) = wire::sign(&mut document, &keys.authentication.secret).await {
        return abandon(ctx, "Could not send the session", e);
    }
    let recorded = serde_json::to_value(&document)
        .map_err(|e| e.to_string())
        .and_then(|value| {
            ctx.config
                .private
                .vetting
                .record_session_document(request_id, value)
                .map_err(|e| e.to_string())
        });
    if let Err(e) = recorded {
        return abandon(ctx, "Could not send the session", e);
    }
    let code = ctx
        .config
        .private
        .vetting
        .desk_entry(request_id)
        .and_then(|e| e.match_code().map(str::to_string))
        .unwrap_or_default();
    page(ctx).mode = VettingMode::List;
    persist(
        ctx,
        format!(
            "Session open. Read the match code {code} to each other{}.",
            if known {
                ""
            } else {
                " — the community's requirements are still unknown, so this asks for a legal name only"
            }
        ),
    );
    let sent = Sent::Session {
        request_id: request_id.to_string(),
    };
    let message = match wire::to_message(&document) {
        Ok(message) => message,
        Err(e) => return abandon(ctx, "Could not send the session", e),
    };
    let from = document.issuer.clone().unwrap_or_default();
    let to = document.recipient.clone().unwrap_or_default();
    spawn_send(ctx, message, &from, &to, sent);
}

/// Attest the hidden way: no statement, no signature, nothing that names this vetter.
///
/// Split from [`attest`] rather than branched inside it because the two paths diverge at every
/// step after the draft — what is produced, what is recorded, what is sent, and what the operator
/// is told. The refusals an operator can act on are surfaced in their own words: a vetter with no
/// tokens left has not failed, it is at capacity until the next drip.
/// Ask the community for the challenge this submission must bind.
///
/// Called when an applicant refreshes a hidden-vetting application. The join no longer depends
/// on it: a launch asks for a fresh challenge of its own and waits for it
/// (`join_flow::challenge_step`). The community issues one per applicant and spends it when the
/// proof is read, so asking twice replaces rather than accumulates — which is why this is safe
/// to call again on a retry.
pub(crate) async fn ask_for_challenge(ctx: &mut ActionCtx<'_>, application_id: &str) {
    let Some(app) = ctx
        .config
        .private
        .vetting
        .applications
        .iter()
        .find(|a| a.id == application_id && a.hidden.is_some())
        .cloned()
    else {
        return;
    };
    let document = match wire::pcs_challenge_request(&app.join_did, &app.community, None) {
        Ok(d) => d,
        Err(e) => return abandon(ctx, "Could not ask for a submission challenge", e),
    };
    let document_id = document.id.clone();
    ctx.config.private.vetting.ask(CommunityQuery {
        document_id: document_id.clone(),
        community: app.community.clone(),
        persona: app.persona,
        kind: QueryKind::PcsChallenge,
        sent_at: Utc::now(),
    });
    status(ctx, "Asking the community for a submission challenge…");
    let sent = Sent::Query {
        document_id,
        community: app.community.clone(),
        kind: QueryKind::PcsChallenge,
    };
    if let Err(e) = sign_and_send(ctx, app.persona, document, sent).await {
        abandon(ctx, "Could not ask for a submission challenge", e);
    }
}

/// Do whatever this community's hidden-vetting schedule owes it now: enrol under the current
/// class label, or draw every tick of the drip that has begun and not been served — under every
/// label it owes one for.
///
/// Driven by the clock and never by the wallet. A client that drew when it was running low
/// would publish, in the timing of its own requests, how much vetting it had been doing — which
/// is the one thing the whole exchange is built to withhold. So this runs on a schedule whether
/// the vetter has attested to nobody or to three people, and asks for the same number either way.
///
/// It runs on what the community publishes **now** (`hidden_published`, refreshed from its
/// manifest on the same schedule), under the keys we enrolled with. A month rolling over is new
/// labels under the same keys, and the engine follows them — re-enrolling, then drawing under the
/// new month. New keys stop the drip instead, and the vetter is told once.
///
/// A vetter in event mode owes draws under two labels, and the plan is why the ordinary one is
/// still among them: dropping the monthly draw for the three days of a conference would say, in
/// the timing of the requests alone, that those three days were a conference.
pub(crate) async fn hidden_vetting_tick(ctx: &mut ActionCtx<'_>, community: &str) {
    let now = Utc::now();
    ensure_hidden_vetter(ctx, community);
    let book = &mut ctx.config.private.vetting;
    let Some(index) = book
        .hidden_vetter
        .iter()
        .position(|h| h.community == community)
    else {
        return;
    };
    let live = book.hidden_published.get(community).cloned();
    // The draws whose answers are still on their way: the question is still open. One whose
    // question has gone (answered, refused, or timed out) is no longer in flight.
    let open: std::collections::HashSet<&str> = book
        .queries
        .iter()
        .filter(|q| q.community == community && q.kind == QueryKind::PcsTokens)
        .map(|q| q.document_id.as_str())
        .collect();
    let stale: Vec<String> = book
        .draws_in_flight
        .keys()
        .filter(|id| !open.contains(id.as_str()))
        .cloned()
        .collect();
    let in_flight: Vec<(String, u32)> = book
        .draws_in_flight
        .iter()
        .filter(|(id, _)| open.contains(id.as_str()))
        .map(|(_, draw)| draw.clone())
        .collect();
    for id in stale {
        book.draws_in_flight.remove(&id);
    }
    let mut plan = book.hidden_vetter[index].plan(live.as_ref(), &in_flight, now);
    // Never a draw on a rate the community may have moved off: only on parameters read from it
    // lately, and not before a read that followed an `overQuota` refusal. The read this pass
    // asked for (`refresh_vetter_communities`) runs the schedule again when it lands.
    let reading = book.waiting_on(community, QueryKind::Manifest).is_some();
    if let Some(hold) = book.hidden_vetter[index].draw_hold(reading, now) {
        let drops = plan
            .owed
            .iter()
            .any(|d| matches!(d, openvtc_core::vetting::hidden::Due::Draw { .. }));
        if drops {
            tracing::info!(community = %community, ?hold, "draws held for a fresh read of the community's parameters");
            plan.owed
                .retain(|d| !matches!(d, openvtc_core::vetting::hidden::Due::Draw { .. }));
            if !matches!(hold, DrawHold::Disagrees { .. }) {
                book.hidden_vetter[index].awaiting_read = true;
            }
        }
    }
    let state = book.hidden_vetter[index].clone();
    let changed = plan.settled || plan.adopted != Adopted::Unchanged;
    if let Adopted::Rekeyed { first } = plan.adopted {
        if first {
            let name = community_display(ctx.config, community);
            persist(
                ctx,
                format!(
                    "{name} now publishes different hidden-vetting keys from the ones you \
                     enrolled under. The tokens and credential you hold there count for nothing \
                     under the new keys, so drawing has stopped. Ask the community whether it \
                     re-keyed; see the Hidden vetting view (h on the desk)."
                ),
            );
            tracing::warn!(community = %community, "hidden-vetting keys changed since enrolment; the drip has stopped");
        }
        return;
    }
    if changed {
        ctx.save.mark_dirty();
        ctx.state.main_page.sync_from_config(ctx.config);
    }
    let Some(did) = persona_did(ctx.config, state.persona) else {
        return;
    };
    // Never a second enrolment while one is unanswered: the community answers the first and
    // refuses the second (`alreadyEnrolled`), and that refusal is what used to read as a lost
    // answer. The first's answer is taken whenever it lands — its blinding is stored.
    let enrolling = ctx
        .config
        .private
        .vetting
        .waiting_on(community, QueryKind::PcsRoot)
        .is_some();
    for owed in plan.owed {
        if enrolling && matches!(owed, openvtc_core::vetting::hidden::Due::Enrol { .. }) {
            continue;
        }
        hidden_vetting_send(ctx, community, &state, &did, owed, now).await;
    }
}

/// Keep this account's vetter side current with the communities it vets for: read each one's
/// requirements again, and run whatever its hidden-vetting schedule owes — enrolment the first
/// time, the ticks of the token drip after.
///
/// A community that turns on PCS ZKP vetting says so only in its manifest, and a month's new
/// labels are published there too, so this re-reads it every time. Run by the schedule
/// (`hidden_vetting_poll`) at each tick window and at least hourly, and by `m` / `d` by hand.
pub(crate) async fn refresh_vetter_side(ctx: &mut ActionCtx<'_>) {
    // A vetter has no application, so nothing else would ever fetch the manifest of a
    // community it vets for — and the manifest is where a community says it hides its
    // vetters, and which labels are live this month.
    refresh_vetter_communities(ctx, false).await;
    // And whatever each community's vetter schedule owes us — enrolment or the ticks of the
    // drip. On a schedule, never in response to a balance (design §5.1).
    //
    // Over the communities that publish the mode as well as those we already hold an engine
    // for: the first pass through has no engine yet, and `hidden_vetting_tick` is what makes one.
    let mut communities: Vec<String> = ctx
        .config
        .private
        .vetting
        .hidden_vetter
        .iter()
        .map(|h| h.community.clone())
        .collect();
    for community in ctx.config.private.vetting.hidden_published.keys() {
        if !communities.contains(community) {
            communities.push(community.clone());
        }
    }
    // Not a community that has switched to named vetting: the engine is kept — a credential
    // does not become worthless because the advertisement moved — but drawing tokens it no
    // longer counts would only collect refusals.
    communities
        .retain(|c| ctx.config.private.vetting.vetter_mode(c).mode() != Some(VetterMode::Named));
    for community in communities {
        hidden_vetting_tick(ctx, &community).await;
    }
}

/// Read again how each community we vet for vets, where the last reading is stale — on opening
/// the desk, and while it stays open. Bounded: a community is asked at most once per
/// [`MODE_REASK_AFTER`](openvtc_core::vetting::mode::MODE_REASK_AFTER), answered or not (R1.4).
pub(crate) async fn refresh_stale_modes(ctx: &mut ActionCtx<'_>) {
    refresh_vetter_communities(ctx, true).await;
}

/// Whether the vetter desk is what the operator is looking at — the one place a stale mode is
/// worth reading again outside the schedule.
pub(crate) fn desk_open(state: &State) -> bool {
    state.main_page.menu_panel.selected_menu == MainMenu::Vetting
        && state.main_page.content_panel.vetting.tab == VettingTab::Desk
}

/// Ask every community that has named us a vetter what it requires.
///
/// An applicant refreshes a manifest because it is applying. A vetter has no application, so
/// without this nothing ever asks — and a community that hides its vetters says so in its
/// manifest and nowhere else. The answer is what [`ensure_hidden_vetter`] acts on.
///
/// Including the communities we already hold an engine for: the manifest is where a new month's
/// labels appear, and an engine that never re-read it never moved past the month it enrolled
/// in. What changes there reaches the engine as the answer lands
/// ([`VettingBook::learn_mode`] → [`HiddenVetterState::take_reading`]), keeping the keys we
/// enrolled under.
///
/// `only_stale` asks only where how the community vets is older than
/// [`MODE_TTL`](openvtc_core::vetting::mode::MODE_TTL) and was not asked lately
/// ([`VettingBook::mode_refresh_due`]) — what opening the desk, and keeping it open, need.
async fn refresh_vetter_communities(ctx: &mut ActionCtx<'_>, only_stale: bool) {
    let standing: Vec<(String, PersonaId)> = {
        let book = &ctx.config.private.vetting;
        let now = Utc::now();
        book.vetter_standing(now)
            .into_iter()
            .filter(|s| s.live)
            .filter(|s| !only_stale || book.mode_refresh_due(&s.community, now))
            // Not again within seconds of the last ask or answer: `d` pressed three times, or a
            // pass chained on an answer, used to fetch the same manifest each time (R1.4). Unless
            // a draw was refused as over the community's rate since: that read is owed now, once.
            .filter(|s| {
                !book.manifest_recently_asked(&s.community, now)
                    || book.params_reread_owed(&s.community)
            })
            .map(|s| (s.community, s.persona))
            .collect()
    };
    for (community, persona) in standing {
        // A community we vet for as two personas is one manifest, asked once.
        let book = &ctx.config.private.vetting;
        if book.manifest_recently_asked(&community, Utc::now())
            && !book.params_reread_owed(&community)
        {
            continue;
        }
        let Some(did) = persona_did(ctx.config, persona) else {
            continue;
        };
        let protocol = ctx.config.private.vetting.protocol_for(&community);
        let Ok(document) = wire::manifest_request(&did, &community, protocol) else {
            continue;
        };
        let sent = Sent::Manifest {
            community: community.clone(),
        };
        let now = Utc::now();
        ctx.config.private.vetting.mode_asked(&community, now);
        match sign_and_send(ctx, persona, document, sent).await {
            Ok(()) => ctx.config.private.vetting.vetter_refresh_failures = 0,
            Err(e) => {
                tracing::warn!(community = %community, error = %e, "could not ask a community what it requires");
                ctx.config.private.vetting.mode_failed(
                    &community,
                    ModeFailure::Unsent(e.clone()),
                    now,
                );
                // Usually the listener is not up yet (start-up). Ask again on
                // the five-second sweep, a bounded number of times.
                let book = &mut ctx.config.private.vetting;
                if book.vetter_refresh_failures
                    < openvtc_core::vetting::book::VETTER_REFRESH_RETRIES
                {
                    book.vetter_refresh_failures += 1;
                    book.vetter_refresh_due = true;
                }
            }
        }
    }
}

/// Mint this vetter's engine for a community, the first time we learn it runs hidden vetting
/// and has named us a vetter.
///
/// Both halves of that condition matter. A community's published parameters say the mode exists,
/// never that we are in it; the grant says we vet here, and nothing about how. Only together do
/// they mean there is an engine to make — and making one we have no grant for would enrol us
/// into a refusal.
///
/// Once. The key pair is what every tag of ours derives from, so a second one would make the
/// same person count twice in one proof. An engine already held is left alone even if the
/// community republishes different parameters: the credential we hold was issued under the old
/// ones, and a rotation is an enrolment, which the schedule handles.
fn ensure_hidden_vetter(ctx: &mut ActionCtx<'_>, community: &str) {
    let book = &ctx.config.private.vetting;
    if book.hidden_vetter.iter().any(|h| h.community == community) {
        return;
    }
    let Some(params) = book.hidden_published.get(community).cloned() else {
        return;
    };
    let Some(standing) = book
        .vetter_standing(Utc::now())
        .into_iter()
        .find(|s| s.community == community && s.live)
    else {
        return;
    };
    let Some(did) = persona_did(ctx.config, standing.persona) else {
        return;
    };
    let snapshot = {
        let mut rng = rand::thread_rng();
        match openvtc_core::vetting::hidden::vetter_start(community, &params, &did, &mut rng) {
            Ok(snapshot) => snapshot,
            Err(e) => {
                return status(
                    ctx,
                    format!("Could not set up hidden vetting for this community: {e}"),
                );
            }
        }
    };
    let mut held = openvtc_core::vetting::book::HiddenVetterState::new(
        community,
        standing.persona,
        params,
        snapshot,
    );
    // The parameters are the last manifest's; dated by it, so the first draw follows a read.
    let reading = ctx.config.private.vetting.vetter_mode(community);
    held.params_read_at = reading
        .read
        .filter(|_| !reading.inferred)
        .map(|r| r.read_at);
    ctx.config.private.vetting.hidden_vetter.push(held);
    // The engine's key is what the community binds this vetter to at enrolment; one that was
    // never saved would be replaced by a fresh one after a restart, which the community refuses
    // (`identifierRebound`).
    ctx.save.mark_dirty();
    status(
        ctx,
        format!(
            "{} hides its vetters. Enrolling you — your attestations there will name nobody.",
            community_display(ctx.config, community)
        ),
    );
}

/// How long a save that must land before a send may take (R1.2). A config save is a local
/// encrypt-and-write; this only bounds a stuck keyring or disk.
const SAVE_BEFORE_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Write the config now, and wait for it — for state that must be on disk before the request
/// that depends on it leaves (an enrolment's blinding). Refused while a coalesced save is
/// already running, so two saves never race; the caller asks again shortly.
async fn save_before_send(ctx: &mut ActionCtx<'_>) -> Result<(), String> {
    if ctx.save.in_flight() {
        return Err("another save is still being written".into());
    }
    let pending = ctx
        .save
        .snapshot_now(ctx.config)
        .map_err(|e| e.to_string())?;
    match tokio::time::timeout(
        SAVE_BEFORE_SEND_TIMEOUT,
        tokio::task::spawn_blocking(move || pending.run()),
    )
    .await
    {
        Ok(Ok(Ok(()))) => {
            ctx.save.clear_after_external_save();
            Ok(())
        }
        Ok(Ok(Err(e))) => Err(format!("the save failed: {e}")),
        Ok(Err(e)) => Err(format!("the save did not finish: {e}")),
        Err(_) => Err(format!(
            "the save did not finish within {} seconds",
            SAVE_BEFORE_SEND_TIMEOUT.as_secs()
        )),
    }
}

/// Send one thing the schedule owes.
async fn hidden_vetting_send(
    ctx: &mut ActionCtx<'_>,
    community: &str,
    state: &openvtc_core::vetting::book::HiddenVetterState,
    did: &str,
    owed: openvtc_core::vetting::hidden::Due,
    now: DateTime<Utc>,
) {
    match owed {
        openvtc_core::vetting::hidden::Due::Nothing => {}
        openvtc_core::vetting::hidden::Due::Enrol { period } => {
            let mut rng = rand::thread_rng();
            let (body, blinding) = match openvtc_core::vetting::hidden::enrolment_request(
                community,
                &state.params,
                &state.snapshot,
                &period,
                &mut rng,
            ) {
                Ok(pair) => pair,
                Err(e) => return status(ctx, format!("Could not ask to enrol: {e}")),
            };
            let document = match wire::pcs_root_request(did, community, &body) {
                Ok(d) => d,
                Err(e) => return abandon(ctx, "Could not ask to enrol", e),
            };
            // Held in memory, and past the reply window: a late answer is still this vetter's
            // one credential under the label (`VettingBook::pending_enrolments`).
            let document_id = document.id.clone();
            // And on disk, before anything is sent: the community answers once per label and
            // keeps no copy, so an answer that lands after a restart must still be openable
            // (`HiddenVetterState::enrolments_asked`). A save that cannot be made now means no
            // ask now — the schedule asks again shortly, rather than risk a lost answer.
            let stored = match openvtc_core::vetting::hidden::blinding_text(&blinding) {
                Ok(text) => text,
                Err(e) => return status(ctx, format!("Could not ask to enrol: {e}")),
            };
            if let Some(held) = ctx
                .config
                .private
                .vetting
                .hidden_vetter_mut(community, state.persona)
            {
                held.remember_asked(openvtc_core::vetting::book::AskedEnrolment {
                    document_id: document_id.clone(),
                    period: period.clone(),
                    blinding: stored,
                    asked_at: now,
                });
            }
            if let Err(e) = save_before_send(ctx).await {
                if let Some(held) = ctx
                    .config
                    .private
                    .vetting
                    .hidden_vetter_mut(community, state.persona)
                {
                    held.take_asked(&document_id);
                }
                // Again on the sweep, a bounded number of times (R1.4); the schedule's own
                // pass after that.
                let book = &mut ctx.config.private.vetting;
                if book.vetter_refresh_failures
                    < openvtc_core::vetting::book::VETTER_REFRESH_RETRIES
                {
                    book.vetter_refresh_failures += 1;
                    book.vetter_refresh_due = true;
                }
                return status(
                    ctx,
                    format!(
                        "Not asking to enrol yet: what opens the community's answer could not be \
                         saved first ({e}). Trying again shortly."
                    ),
                );
            }
            ctx.config.private.vetting.remember_enrolment(
                openvtc_core::vetting::book::PendingEnrolment {
                    document_id: document_id.clone(),
                    community: community.to_string(),
                    persona: state.persona,
                    blinding: std::sync::Arc::new(blinding),
                },
            );
            ctx.config.private.vetting.ask(CommunityQuery {
                document_id: document_id.clone(),
                community: community.to_string(),
                persona: state.persona,
                kind: QueryKind::PcsRoot,
                sent_at: now,
            });
            status(ctx, format!("Asking to enrol as a vetter for {period}…"));
            let sent = Sent::Query {
                document_id,
                community: community.to_string(),
                kind: QueryKind::PcsRoot,
            };
            if let Err(e) = sign_and_send(ctx, state.persona, document, sent).await {
                abandon(ctx, "Could not ask to enrol", e);
            }
        }
        openvtc_core::vetting::hidden::Due::Draw { label, tick, rate } => {
            let mut rng = rand::thread_rng();
            // The engine as it stands now, not as it stood when the pass was planned: each draw
            // of a catch-up adds its serials to it, and starting from the planned copy would drop
            // the previous draw's.
            let Some(mut snapshot) = ctx
                .config
                .private
                .vetting
                .hidden_vetter(community, state.persona)
                .map(|h| h.snapshot.clone())
            else {
                return;
            };
            let body = match openvtc_core::vetting::hidden::drip_request(
                community,
                &state.params,
                &mut snapshot,
                tick,
                &label,
                rate,
                &mut rng,
            ) {
                Ok(body) => body,
                Err(e) => return status(ctx, format!("Could not draw tokens: {e}")),
            };
            if let Some(held) = ctx
                .config
                .private
                .vetting
                .hidden_vetter_mut(community, state.persona)
            {
                held.snapshot = snapshot;
            }
            let document = match wire::pcs_tokens_request(did, community, &body) {
                Ok(d) => d,
                Err(e) => return abandon(ctx, "Could not draw tokens", e),
            };
            let document_id = document.id.clone();
            ctx.config.private.vetting.ask(CommunityQuery {
                document_id: document_id.clone(),
                community: community.to_string(),
                persona: state.persona,
                kind: QueryKind::PcsTokens,
                sent_at: now,
            });
            ctx.config
                .private
                .vetting
                .draws_in_flight
                .insert(document_id.clone(), (label.clone(), tick));
            let sent = Sent::Query {
                document_id,
                community: community.to_string(),
                kind: QueryKind::PcsTokens,
            };
            if let Err(e) = sign_and_send(ctx, state.persona, document, sent).await {
                abandon(ctx, "Could not draw tokens", e);
            }
        }
    }
}

async fn attest_hidden(
    ctx: &mut ActionCtx<'_>,
    request_id: &str,
    entry: &openvtc_core::vetting::vetter::DeskEntry,
    vetter_did: &str,
    attestation: Attestation,
    now: DateTime<Utc>,
) -> () {
    let previous = entry.state.clone();
    let wire = {
        let mut rng = rand::thread_rng();
        match ctx.config.private.vetting.attest_hidden(
            request_id,
            vetter_did,
            attestation,
            now,
            &mut rng,
        ) {
            Ok(wire) => wire,
            Err(e) => {
                // No credential or no token is a state the vetter waits out: say how long,
                // from the schedule, rather than the engine's bare refusal.
                use openvtc_core::vetting::{hidden::HiddenError, vetter::VetterError};
                let waiting = matches!(
                    e,
                    VetterError::Hidden(HiddenError::NoToken | HiddenError::NotEnrolled)
                );
                let outlook = ctx
                    .config
                    .private
                    .vetting
                    .hidden_outlook(&entry.community, entry.persona, now)
                    .filter(|_| waiting);
                return status(
                    ctx,
                    match outlook {
                        Some(o) => format!(
                            "Cannot attest yet: {e}. Nothing was sent; the request stays open. \
                             {}: {}.{}",
                            community_display(ctx.config, &entry.community),
                            outlook_words(&o, now),
                            if o.events_offered {
                                " Vetting at one of its events (e) draws more."
                            } else {
                                ""
                            }
                        ),
                        None => format!("Cannot attest: {e}"),
                    },
                );
            }
        }
    };

    let Some(session_id) = session_id_of(entry) else {
        return status(ctx, "This request has no open session to attest on.");
    };
    let message = match wire::hidden_attestation(vetter_did, &entry.applicant, &wire, &session_id) {
        Ok(message) => message,
        Err(e) => {
            // Put the desk back: the token is spent either way, but the request is not closed on
            // a delivery that never left.
            if let Some(e2) = ctx.config.private.vetting.desk_entry_mut(request_id) {
                e2.state = previous;
            }
            return abandon(ctx, "Could not send the attestation", e);
        }
    };
    page(ctx).mode = VettingMode::List;
    persist(ctx, "Sending your attestation — it names nobody.");
    let sent = Sent::Attestation {
        request_id: request_id.to_string(),
        previous: entry.state.clone(),
    };
    spawn_send(ctx, message, vetter_did, &entry.applicant, sent);
}

/// The session id a desk entry is at, if it has one.
fn session_id_of(entry: &openvtc_core::vetting::vetter::DeskEntry) -> Option<String> {
    match &entry.state {
        DeskState::Session { session, .. } | DeskState::CardReceived { session, .. } => {
            Some(session.id.clone())
        }
        _ => None,
    }
}

async fn attest(ctx: &mut ActionCtx<'_>, request_id: &str, form: &AttestForm) {
    if !form.attested {
        return status(
            ctx,
            "Tick the attestation (the last line) — signing is attributable to you in this community.",
        );
    }
    let now = Utc::now();
    let Some(entry) = ctx.config.private.vetting.desk_entry(request_id).cloned() else {
        return;
    };
    let DeskState::CardReceived { session, .. } = &entry.state else {
        return status(ctx, "You can attest once their card has arrived.");
    };
    let Some(vetter_did) = persona_did(ctx.config, entry.persona) else {
        return status(
            ctx,
            "The persona this request was made to is not available.",
        );
    };
    let method = VETTING_METHODS[form.method_index.min(VETTING_METHODS.len() - 1)];
    let documentation_choice = page(ctx)
        .documentation
        .get(form.documentation_index)
        .cloned()
        .unwrap_or_else(|| documentation::NONE.to_string());
    // `none` is never listed in a statement: no document is the empty list. So
    // choosing it means relying on nothing, whichever method was used — and a
    // documentary method with nothing to rely on is refused by the desk.
    let document_classes = if documentation_choice == documentation::NONE {
        Vec::new()
    } else {
        vec![documentation_choice]
    };
    let attestation = Attestation {
        method,
        document_classes,
        claims_verified: session.required_claims.clone(),
        liveness_confirmed: form.liveness_confirmed,
        declared_relationship: VETTING_RELATIONSHIPS
            [form.relationship_index.min(VETTING_RELATIONSHIPS.len() - 1)],
        attestation_text_digest: None,
    };
    // Hidden vetting: this community counts a proof, not a signature. The desk builds the same
    // draft from the same checklist and then does not sign it — what goes to the applicant
    // carries a tag where an issuer would be, and nothing on the way names this persona.
    //
    // Only while the community runs PCS ZKP now: an engine says we enrolled once, and a
    // community that has switched back to named vetting counts signed statements, not proofs.
    //
    // And only for a request that asked for it. A community may publish hidden vetting
    // alongside named vetters, so the request decides, not the community: one carrying the
    // applicant's PCS identifier gets a proof, one without gets a named statement — unless the
    // criterion it names takes the proof alone, when there is nothing to attest to.
    let book = &ctx.config.private.vetting;
    let hidden_request = match book.request_vetting(request_id) {
        RequestVetting::Hidden => hides_vetters(book, &entry.community),
        RequestVetting::Named { .. } => false,
        RequestVetting::HiddenWithoutId { criterion } => {
            return status(ctx, hidden_without_id_words(&criterion));
        }
        RequestVetting::Unreadable(e) => return status(ctx, format!("Cannot attest: {e}")),
    };
    if hidden_request
        && book
            .hidden_vetter(&entry.community, entry.persona)
            .is_some()
    {
        return attest_hidden(ctx, request_id, &entry, &vetter_did, attestation, now).await;
    }
    // The request asks for a proof but this vetter is not enrolled yet:
    // signing now would make a named statement — one the applicant's
    // hidden-vetting application cannot use, carrying this vetter's DID to a
    // community that promised not to need it. Enrol first.
    if hidden_request {
        page(ctx).mode = VettingMode::List;
        status(
            ctx,
            "This community proves vetting with a PCS zero-knowledge proof, and you are not \
             enrolled for it yet, so nothing was signed. Enrolling now — attest again in a \
             moment.",
        );
        refresh_vetter_side(ctx).await;
        return;
    }

    let draft =
        match ctx
            .config
            .private
            .vetting
            .statement_draft(request_id, &vetter_did, attestation, now)
        {
            Ok(draft) => draft,
            Err(e) => return status(ctx, format!("Cannot attest yet: {e}")),
        };
    if !begin(ctx) {
        return;
    }
    let keys = match ctx
        .config
        .get_persona_keys_for(entry.persona, ctx.tdk)
        .await
    {
        Ok(keys) => keys,
        Err(e) => return abandon(ctx, "Could not sign the statement", e),
    };
    let statement = match sign_statement(draft, &keys.signing.secret).await {
        Ok(statement) => statement,
        Err(e) => return abandon(ctx, "Could not sign the statement", e),
    };
    let resolver = resolver(ctx);
    let issued = match ctx
        .config
        .private
        .vetting
        .record_statement(request_id, &statement, &resolver, now)
        .await
    {
        Ok(issued) => issued,
        Err(e) => return abandon(ctx, "The statement did not verify", e),
    };
    // The statement is signed with the assertionMethod key (a credential); the
    // delivery document carrying it with the authentication key, like every
    // other document this persona sends.
    let message = match wire::credential_delivery(
        &vetter_did,
        &entry.applicant,
        &statement,
        &session.id,
        &keys.authentication.secret,
    )
    .await
    {
        Ok(message) => message,
        Err(e) => {
            ctx.config
                .private
                .vetting
                .issued
                .retain(|s| s.id != issued.id);
            if let Some(e2) = ctx.config.private.vetting.desk_entry_mut(request_id) {
                e2.state = entry.state.clone();
            }
            return abandon(ctx, "Could not send the statement", e);
        }
    };
    page(ctx).mode = VettingMode::List;
    persist(ctx, "Sending your statement…");
    let sent = Sent::Statement {
        request_id: request_id.to_string(),
        statement_id: issued.id,
        previous: entry.state.clone(),
    };
    spawn_send(ctx, message, &vetter_did, &entry.applicant, sent);
}

/// Decline a desk request, with the reason and note the vetter chose — both
/// optional, and sent to the applicant only, never the community.
async fn decline(
    ctx: &mut ActionCtx<'_>,
    request_id: &str,
    code: Option<vta_sdk::protocols::vetting::decline::v0_1::PayloadCode>,
    message: Option<String>,
) {
    let Some(entry) = ctx.config.private.vetting.desk_entry(request_id).cloned() else {
        return;
    };
    let Some(vetter_did) = persona_did(ctx.config, entry.persona) else {
        return status(
            ctx,
            "The persona this request was made to is not available.",
        );
    };
    if !begin(ctx) {
        return;
    }
    let body = match ctx
        .config
        .private
        .vetting
        .decline(request_id, code, message, Utc::now())
    {
        Ok(body) => body,
        Err(e) => return abandon(ctx, "Could not decline", e),
    };
    let document = match wire::document(
        VETTING_DECLINE_TYPE,
        &vetter_did,
        &entry.applicant,
        wire::new_id(),
        &body,
    ) {
        Ok(d) => d,
        Err(e) => return abandon(ctx, "Could not decline", e),
    };
    page(ctx).mode = VettingMode::List;
    persist(ctx, "Declining…");
    let sent = Sent::Decline {
        request_id: request_id.to_string(),
        previous: entry.state.clone(),
    };
    if let Err(e) = sign_and_send(ctx, entry.persona, document, sent).await {
        if let Some(desk) = ctx.config.private.vetting.desk_entry_mut(request_id) {
            desk.state = entry.state;
        }
        abandon(ctx, "Could not send the decline", e);
    }
}

async fn withdraw(ctx: &mut ActionCtx<'_>, statement_id: &str, reason_index: usize) {
    let Some(issued) = ctx
        .config
        .private
        .vetting
        .issued
        .iter()
        .find(|s| s.id == statement_id)
        .cloned()
    else {
        return;
    };
    let Some(vetter_did) = persona_did(ctx.config, issued.persona) else {
        return status(
            ctx,
            "The persona that signed this statement is not available.",
        );
    };
    if !begin(ctx) {
        return;
    }
    let document_id = wire::new_id();
    let reason = VETTING_WITHDRAWAL_REASONS[reason_index.min(VETTING_WITHDRAWAL_REASONS.len() - 1)];
    let body = match ctx.config.private.vetting.withdrawal(
        statement_id,
        Some(reason),
        &document_id,
        Utc::now(),
    ) {
        Ok((body, _)) => body,
        Err(e) => return abandon(ctx, "Could not withdraw", e),
    };
    let document = match wire::document(
        VETTING_REVOKE_STATEMENT_TYPE,
        &vetter_did,
        &issued.community,
        document_id,
        &body,
    ) {
        Ok(d) => d,
        Err(e) => return abandon(ctx, "Could not withdraw", e),
    };
    page(ctx).mode = VettingMode::List;
    persist(ctx, "Telling the community…");
    let sent = Sent::Withdrawal {
        statement_id: statement_id.to_string(),
    };
    if let Err(e) = sign_and_send(ctx, issued.persona, document, sent).await {
        if let Some(s) = ctx
            .config
            .private
            .vetting
            .issued
            .iter_mut()
            .find(|s| s.id == statement_id)
        {
            s.withdrawal = None;
        }
        abandon(ctx, "Could not send the withdrawal", e);
    }
}

// ============================================================================
// The background send
// ============================================================================

/// What was sent, and what undoing it takes if the send fails.
pub(crate) enum Sent {
    Manifest {
        community: String,
    },
    Request {
        application_id: String,
        document_id: String,
        vetter: String,
    },
    Session {
        request_id: String,
    },
    Statement {
        request_id: String,
        statement_id: String,
        previous: DeskState,
    },
    /// A hidden attestation, which has no statement id because it names nobody.
    Attestation {
        request_id: String,
        previous: DeskState,
    },
    Decline {
        request_id: String,
        previous: DeskState,
    },
    Withdrawal {
        statement_id: String,
    },
    /// A question to a community: its directory, or a resend of our grant.
    Query {
        document_id: String,
        community: String,
        kind: QueryKind,
    },
    /// Our vetter profile, and the record it replaced, for undoing.
    Profile {
        document_id: String,
        community: String,
        persona: PersonaId,
        previous: Option<Box<VetterProfileRecord>>,
    },
}

/// One vetting send. I/O only.
pub(crate) struct SendJob {
    service: Messaging,
    listener_id: String,
    to: String,
    message: Box<Message>,
    sent: Sent,
}

impl SendJob {
    pub(crate) async fn run(self) -> VettingOutcome {
        let result = openvtc_core::didcomm::send_message_via(
            &self.service,
            &self.message,
            &self.listener_id,
            &self.to,
        )
        .await;
        VettingOutcome::Sent {
            sent: Box::new(self.sent),
            error: result.err().map(|e| e.to_string()),
        }
    }
}

/// Reading or wearing a face. I/O only.
pub(crate) enum FaceJob {
    List {
        client: VtaClient,
        context_id: String,
        persona_did: String,
        application_id: String,
    },
    /// Read the pool so the make-a-face form has something to tick.
    Pool {
        client: VtaClient,
        application_id: String,
        required: Vec<String>,
        /// The agent's claim-type table, so a value is masked here exactly as
        /// the Identity page masks it.
        registry: Registry,
    },
    /// Save a value typed on the make-a-face form as a new attribute.
    AddAttribute {
        client: VtaClient,
        application_id: String,
        draft: openvtc_core::persona::pool::AttributeDraft,
        registry: Registry,
    },
    /// Create a face and wear it, in one step.
    Create {
        client: VtaClient,
        top_context_id: String,
        context_id: String,
        persona_did: String,
        application_id: String,
        name: String,
        live_refs: Vec<String>,
    },
    Wear {
        client: VtaClient,
        top_context_id: String,
        context_id: String,
        persona_did: String,
        application_id: String,
        face: FaceChoice,
    },
}

/// Fill in what each face would disclose, as claim types.
///
/// **Metadata only.** A profile's entries are attribute *ids*, so the claim
/// types come from one pool listing read without values (`include_values:
/// false`) and joined against them. Resolving each profile instead would
/// decrypt the whole pool to answer a question about names, which is the
/// reason `profile::list` does not do it either.
///
/// Every failure degrades to an empty list rather than failing the picker: a
/// face whose contents could not be read is still a face the holder may want to
/// wear, and the list already treats a failed binding read the same way. The
/// reads are sequential because a holder has a handful of faces, and each
/// carries the client's own timeout (R1.2).
async fn fill_claim_types(client: &VtaClient, faces: &mut [FaceChoice]) {
    let Ok(pool) = pool::list(client, false, false).await else {
        return;
    };
    let claim_of: std::collections::HashMap<&str, &str> = pool
        .iter()
        .map(|a| (a.attribute_id.as_str(), a.claim_type.as_str()))
        .collect();
    for face in faces.iter_mut() {
        let Ok(detail) = profile::get(client, &face.profile_id, false).await else {
            continue;
        };
        let mut seen = std::collections::HashSet::new();
        face.claim_types = detail
            .live_refs
            .iter()
            .filter_map(|id| claim_of.get(id.as_str()).map(|t| (*t).to_string()))
            // Two attributes of the same type — a work and a personal email —
            // are one claim type on the card. `dedup` would only catch them
            // when they happened to sit next to each other.
            .filter(|t| seen.insert(t.clone()))
            .collect();
    }
}

impl FaceJob {
    pub(crate) async fn run(self) -> VettingOutcome {
        match self {
            FaceJob::List {
                client,
                context_id,
                persona_did,
                application_id,
            } => {
                let result = match profile::list(&client).await {
                    Ok(profiles) => {
                        // What is worn now is a nicety for the picker; a failed
                        // read leaves nothing marked rather than failing the list.
                        let worn = binding::get(&client, &context_id, &persona_did)
                            .await
                            .ok()
                            .filter(|b| b.bound)
                            .and_then(|b| b.profile_id);
                        let mut faces: Vec<FaceChoice> = profiles
                            .into_iter()
                            .map(|p| FaceChoice {
                                worn: worn.as_deref() == Some(p.profile_id.as_str()),
                                name: sanitize_display(p.display_name(), 128),
                                entries: p.entry_count,
                                profile_id: p.profile_id,
                                claim_types: Vec::new(),
                            })
                            .collect();
                        fill_claim_types(&client, &mut faces).await;
                        Ok(faces)
                    }
                    Err(e) => Err(e.to_string()),
                };
                VettingOutcome::Faces {
                    application_id,
                    result,
                }
            }
            FaceJob::Pool {
                client,
                application_id,
                required,
                registry,
            } => {
                // Values, but not sensitive ones. The holder is choosing which
                // of their values a vetter will read, and the value is the
                // check they can make — two attributes both labelled
                // `name.legal` are told apart by what they say. A
                // `sensitivity: high` value stays in the agent
                // (`include_sensitive: false`), as on the Identity page's own
                // listing, and a masked type is painted masked.
                let result = pool::list(&client, true, false)
                    .await
                    .map(|attributes| {
                        attributes
                            .iter()
                            .map(|a| pool_row(a, &registry))
                            .collect::<Vec<_>>()
                    })
                    .map_err(|e| e.to_string());
                VettingOutcome::Pool {
                    application_id,
                    required,
                    result,
                }
            }
            FaceJob::AddAttribute {
                client,
                application_id,
                draft,
                registry,
            } => {
                let claim_type = draft.claim_type.clone();
                let written = PoolAttribute {
                    claim_type: draft.claim_type.clone(),
                    label: draft.label.clone(),
                    value: Some(draft.value.clone()),
                    ..PoolAttribute::default()
                };
                let result = match pool::put(&client, draft).await {
                    Ok(pool::AttributeEdit::Written(attribute_id)) => Ok(pool_row(
                        &PoolAttribute {
                            attribute_id,
                            ..written
                        },
                        &registry,
                    )),
                    Ok(pool::AttributeEdit::Refused(why)) => Err(why.to_string()),
                    Err(e) => Err(e.to_string()),
                };
                VettingOutcome::AttributeSaved {
                    application_id,
                    claim_type,
                    result,
                }
            }
            FaceJob::Create {
                client,
                top_context_id,
                context_id,
                persona_did,
                application_id,
                name,
                live_refs,
            } => {
                // `other_entries` is empty because this creates: there is no
                // profile whose pinned or inline entries could be dropped. The
                // general editor has to carry them; here there is nothing yet
                // to carry.
                let created = profile::put(&client, None, &name, &live_refs, &[], None).await;
                let (profile_id, error) = match created {
                    Ok(id) => (id, None),
                    Err(e) => (String::new(), Some(e.to_string())),
                };
                // Wearing it is the point, so a face created but left unworn
                // would put the holder back on the picker to do what they had
                // just asked for. A failure to wear is still reported against
                // the face that now exists.
                let error = match error {
                    Some(e) => Some(e),
                    None => {
                        let slug = parse_sub_context_id(&context_id)
                            .map_or(context_id.as_str(), |(_, slug)| slug);
                        match community_context::ensure_context(
                            &client,
                            &top_context_id,
                            &context_id,
                            slug,
                        )
                        .await
                        {
                            Err(e) => Some(e.to_string()),
                            Ok(_) => {
                                binding::set(&client, &context_id, &persona_did, Some(&profile_id))
                                    .await
                                    .err()
                                    .map(|e| e.to_string())
                            }
                        }
                    }
                };
                VettingOutcome::FaceWorn {
                    error,
                    application_id,
                    profile_id,
                    name,
                }
            }
            FaceJob::Wear {
                client,
                top_context_id,
                context_id,
                persona_did,
                application_id,
                face,
            } => {
                // The context exists before a face is worn in it.
                let slug =
                    parse_sub_context_id(&context_id).map_or(context_id.as_str(), |(_, slug)| slug);
                let error = match community_context::ensure_context(
                    &client,
                    &top_context_id,
                    &context_id,
                    slug,
                )
                .await
                {
                    Err(e) => Some(e.to_string()),
                    Ok(_) => {
                        binding::set(&client, &context_id, &persona_did, Some(&face.profile_id))
                            .await
                            .err()
                            .map(|e| e.to_string())
                    }
                };
                VettingOutcome::FaceWorn {
                    error,
                    application_id,
                    profile_id: face.profile_id,
                    name: face.name,
                }
            }
        }
    }
}

/// Which half of the card's two steps a job runs.
pub(crate) enum CardStep {
    /// Ask what the face would show. Nothing leaves.
    Preview,
    /// Release what the preview showed, then sign, check and send the card.
    Present(Box<Presenting>),
}

/// What releasing and sending a card needs.
pub(crate) struct Presenting {
    preview_id: String,
    /// assertionMethod key — signs the card (a credential).
    signer: Secret,
    /// authentication key — signs the document that carries it.
    document_signer: Secret,
    resolver: TrustTaskVmResolver,
    service: Messaging,
    listener_id: String,
}

/// One step of sending a card. Works on a copy of the application; the
/// outcome carries back what the book has to record.
pub(crate) struct CardJob {
    client: VtaClient,
    context_id: String,
    vetter: String,
    application: Application,
    session_id: String,
    step: CardStep,
}

/// Why a card did not go.
pub(crate) enum CardFailure {
    /// The VTA wants a fresh approval; the preview is still good.
    StepUp,
    Failed(String),
}

fn failed(e: impl std::fmt::Display) -> CardFailure {
    CardFailure::Failed(e.to_string())
}

impl CardJob {
    pub(crate) async fn run(self) -> VettingOutcome {
        let CardJob {
            client,
            context_id,
            vetter,
            mut application,
            session_id,
            step,
        } = self;
        let application_id = application.id.clone();
        match step {
            CardStep::Preview => {
                let requested = application.requested_claims(&session_id);
                let result = disclosure::preview(
                    &client,
                    &context_id,
                    &application.join_did,
                    &vetter,
                    requested,
                    VETTING_PURPOSE,
                )
                .await
                .map(|preview| CardPreview {
                    problem: application
                        .card_claims(&session_id, &preview.claims)
                        .err()
                        .map(|e| e.to_string()),
                    claims: preview
                        .claims
                        .iter()
                        .map(|c| {
                            (
                                sanitize_display(&c.claim_type, 64),
                                match &c.value {
                                    Some(value) => sanitize_display(&claim_text(value), 256),
                                    None => "(proved without its value)".to_string(),
                                },
                            )
                        })
                        .collect(),
                    preview_id: preview.preview_id,
                })
                .map_err(|e| e.to_string());
                VettingOutcome::Previewed {
                    application_id,
                    session_id,
                    result,
                }
            }
            CardStep::Present(presenting) => {
                let Presenting {
                    preview_id,
                    signer,
                    document_signer,
                    resolver,
                    service,
                    listener_id,
                } = *presenting;
                let result = async {
                    let challenge = application
                        .session(&session_id)
                        .map(|(_, s)| s.challenge.clone())
                        .ok_or_else(|| failed("the session has closed"))?;
                    let presented =
                        disclosure::present(&client, &context_id, &preview_id, Some(&challenge))
                            .await
                            .map_err(|e| match e {
                                PresentError::StepUpRequired => CardFailure::StepUp,
                                PresentError::Failed(message) => CardFailure::Failed(message),
                            })?;
                    let now = Utc::now();
                    let claims = application
                        .card_claims(&session_id, &presented.claims)
                        .map_err(failed)?;
                    let draft = application
                        .card_draft(&session_id, claims.clone(), now)
                        .map_err(failed)?;
                    let card = sign_card(draft, &signer).await.map_err(failed)?;
                    let sent = application
                        .record_card(&session_id, &card, &resolver, now)
                        .await
                        .map_err(|e| failed(format!("the card did not verify: {e}")))?;
                    // The card travels as it was signed. Parsing it into the
                    // published response and writing it back out is not
                    // guaranteed to be the same bytes, and its digest is what
                    // the vetter's statement names.
                    let mut document = wire::document(
                        VETTING_SESSION_RESPONSE_TYPE,
                        &application.join_did,
                        &vetter,
                        wire::new_id(),
                        &serde_json::json!({ "card": card }),
                    )
                    .map_err(failed)?;
                    document.thread_id = Some(session_id.clone());
                    wire::sign(&mut document, &document_signer)
                        .await
                        .map_err(failed)?;
                    let message = wire::to_message(&document).map_err(failed)?;
                    openvtc_core::didcomm::send_message_via(
                        &service,
                        &message,
                        &listener_id,
                        &vetter,
                    )
                    .await
                    .map_err(failed)?;
                    Ok((sent, claims))
                }
                .await;
                VettingOutcome::CardSent {
                    application_id,
                    session_id,
                    result,
                }
            }
        }
    }
}

/// How a vetting job went. Applied on the loop thread.
pub(crate) enum VettingOutcome {
    /// A document went out, or did not.
    Sent {
        /// Boxed: a desk state carries the card, and dwarfs every other outcome.
        sent: Box<Sent>,
        error: Option<String>,
    },
    /// The holder's faces, for the picker.
    Faces {
        application_id: String,
        result: Result<Vec<FaceChoice>, String>,
    },
    /// The pool, for the make-a-face form.
    Pool {
        application_id: String,
        required: Vec<String>,
        result: Result<Vec<PoolRow>, String>,
    },
    /// A value typed on the make-a-face form is an attribute now, or is not.
    AttributeSaved {
        application_id: String,
        claim_type: String,
        result: Result<PoolRow, String>,
    },
    /// A face is worn, or is not.
    FaceWorn {
        application_id: String,
        profile_id: String,
        name: String,
        error: Option<String>,
    },
    /// What a card would show.
    Previewed {
        application_id: String,
        session_id: String,
        result: Result<CardPreview, String>,
    },
    /// A card went out — with what it showed — or did not.
    CardSent {
        application_id: String,
        session_id: String,
        result: Result<(SentCard, Vec<session::v0_1::VettingCardClaim>), CardFailure>,
    },
}

impl VettingOutcome {
    /// Fold the result into the book and the page.
    pub(crate) fn apply(self, state: &mut State, config: &mut Config, save: &mut SaveScheduler) {
        let v = &mut state.main_page.content_panel.vetting;
        let (message, persist) = match self {
            VettingOutcome::Sent { sent, error } => {
                if let (Sent::Query { document_id, .. }, Some(e)) = (&*sent, &error)
                    && let VettingMode::Directory(view) = &mut v.mode
                    && view.pending.as_deref() == Some(document_id.as_str())
                {
                    view.pending = None;
                    view.pending_cursors = None;
                    view.error = Some(format!("Could not ask the community: {e}"));
                }
                sent_result(*sent, error, config)
            }
            VettingOutcome::Faces {
                application_id,
                result: Ok(faces),
            } => {
                if let Some(worn) = faces.iter().find(|f| f.worn) {
                    v.worn_faces
                        .insert(application_id.clone(), worn.name.clone());
                    // The agent is authoritative about what is worn, so a list
                    // is also the chance to pick up a face chosen before this
                    // was recorded, and to refresh a name that has changed.
                    if let Some(app) = config
                        .private
                        .vetting
                        .application_by_id_mut(&application_id)
                    {
                        app.face = Some(ChosenFace {
                            profile_id: worn.profile_id.clone(),
                            name: worn.name.clone(),
                        });
                    }
                }
                let message = if faces.is_empty() {
                    "You have no faces yet — Enter makes one, and asks for anything this \
                     community needs that you have not added."
                } else {
                    "Choose the face you show vetters."
                };
                // From the list, the card page, or the access-granted retry —
                // every place `f` is offered. Any other mode is something the
                // holder moved on to while the read was in flight, and must not
                // be replaced under them. With no faces the picker still opens:
                // its last row makes one, and skipping it left only a pointer
                // to another page.
                if matches!(
                    v.mode,
                    VettingMode::List
                        | VettingMode::SendCard { .. }
                        | VettingMode::HolderGrant { .. }
                ) {
                    let index = faces.iter().position(|f| f.worn).unwrap_or(0);
                    let required = config
                        .private
                        .vetting
                        .applications
                        .iter()
                        .find(|a| a.id == application_id)
                        .map(required_claim_types)
                        .unwrap_or_default();
                    v.mode = VettingMode::ChooseFace {
                        application_id,
                        faces,
                        index,
                        required,
                    };
                }
                // The application may have just been given its context.
                (message.to_string(), true)
            }
            VettingOutcome::Pool {
                application_id,
                required,
                result: Ok(pool),
            } => {
                // Open with the required claim types already ticked. The
                // community has said what the card needs, so leaving the
                // holder to work that out from a list of thirty attributes
                // would be withholding the one thing that makes this inline.
                // What is still missing is the form's own status line to say;
                // this message only says the read is done, so the two never
                // disagree or repeat each other.
                let app = config
                    .private
                    .vetting
                    .applications
                    .iter()
                    .find(|a| a.id == application_id);
                let optional = app.map(optional_claim_types).unwrap_or_default();
                let name = app.map_or_else(
                    || "Vetting".to_string(),
                    |a| default_face_name(config, &a.community),
                );
                let form = NewFaceForm::open(application_id, required, optional, pool, name);
                v.mode = VettingMode::NewFace(Box::new(form));
                (
                    "Your attributes are read. What this community's card needs is below."
                        .to_string(),
                    true,
                )
            }
            VettingOutcome::AttributeSaved {
                application_id,
                claim_type,
                result,
            } => {
                let words = openvtc_core::vetting::guide::claim_words(&claim_type);
                match result {
                    Ok(row) => {
                        // My Identity's listing no longer has everything in the
                        // pool. Re-read once the domain is free, as after its
                        // own writes.
                        state.main_page.content_panel.identity.refresh_queued = true;
                        match &mut v.mode {
                            VettingMode::NewFace(form) if form.application_id == application_id => {
                                form.saved(row);
                                (
                                    format!(
                                        "Saved your {words} to My Identity, and ticked it for \
                                         this face."
                                    ),
                                    true,
                                )
                            }
                            _ => (format!("Saved your {words} to My Identity."), true),
                        }
                    }
                    // The pool sits above every context, so the write meets the
                    // same holder refusal as the read, with the same answer.
                    Err(e) if crate::holder_grant::needs_holder_grant(&e) => {
                        v.mode = VettingMode::HolderGrant {
                            credential_did: agent_credential_did(config).map(str::to_string),
                        };
                        (format!("Could not save your {words}."), true)
                    }
                    Err(e) => match &mut v.mode {
                        // The reason goes on the form, beside the value the
                        // holder typed and can now retry; the status line only
                        // says that it failed.
                        VettingMode::NewFace(form) if form.application_id == application_id => {
                            form.saving = None;
                            form.error = Some(format!("Could not save it: {e}"));
                            (format!("Could not save your {words}."), true)
                        }
                        _ => (format!("Could not save your {words}: {e}"), true),
                    },
                }
            }
            VettingOutcome::Pool { result: Err(e), .. } => {
                // The same refusal the faces read has, for the same reason:
                // the pool is what a face is built over.
                if crate::holder_grant::needs_holder_grant(&e) {
                    v.mode = VettingMode::HolderGrant {
                        credential_did: agent_credential_did(config).map(str::to_string),
                    };
                    ("Could not read your attributes.".to_string(), true)
                } else {
                    (format!("Could not read your attributes: {e}"), true)
                }
            }
            VettingOutcome::Faces { result: Err(e), .. } => {
                // Faces are built over the holder's attribute pool, which sits
                // above every context — so the commonest way this fails is the
                // one refusal with a specific answer. It opens a view of its
                // own: the answer is a command, and the status line wrapped it
                // mid-DID, where it could be neither read nor selected.
                //
                // Everything else stays a status line. A failure we do not
                // recognise has no command to offer, so a view would be a
                // bigger frame around the same sentence.
                if crate::holder_grant::needs_holder_grant(&e) {
                    v.mode = VettingMode::HolderGrant {
                        credential_did: agent_credential_did(config).map(str::to_string),
                    };
                    ("Could not read your faces.".to_string(), true)
                } else {
                    (format!("Could not read your faces: {e}"), true)
                }
            }
            VettingOutcome::FaceWorn {
                application_id,
                profile_id,
                name,
                error: None,
            } => {
                // Persisted as well as cached: `worn_faces` is this run only,
                // and the application's own next step has to know a face was
                // chosen after a restart too.
                if let Some(app) = config
                    .private
                    .vetting
                    .application_by_id_mut(&application_id)
                {
                    app.face = Some(ChosenFace {
                        profile_id,
                        name: name.clone(),
                    });
                }
                // Back to the card that asked for a face, if this is its
                // application and the holder is still waiting on the list the
                // wear left them on.
                let back_to_card = v
                    .card_after_face
                    .take_if(|(card_application, _)| *card_application == application_id)
                    .filter(|_| matches!(v.mode, VettingMode::List));
                v.worn_faces.insert(application_id, name.clone());
                let message = format!(
                    "Vetters are shown your {name} face, and the community sees the same one \
                     when you join."
                );
                match back_to_card {
                    Some(card) => {
                        v.mode = card_mode(card);
                        (format!("{message} Enter previews the card."), true)
                    }
                    None => (message, true),
                }
            }
            VettingOutcome::FaceWorn {
                name,
                error: Some(e),
                ..
            } => (format!("Could not wear {name}: {e}"), true),
            VettingOutcome::Previewed {
                application_id,
                session_id,
                result: Ok(preview),
            } => {
                let message = match &preview.problem {
                    Some(problem) => format!("This face cannot make the card: {problem}"),
                    None => "This is what the card shows. Enter approves and sends it.".to_string(),
                };
                if let VettingMode::SendCard {
                    application_id: open_application,
                    session_id: open,
                    preview: shown,
                } = &mut v.mode
                    && *open == session_id
                    && *open_application == application_id
                {
                    *shown = Some(preview);
                }
                (message, true)
            }
            VettingOutcome::Previewed {
                application_id,
                result: Err(e),
                ..
            } => (preview_refusal(&e, &application_id, config), true),
            VettingOutcome::CardSent {
                application_id,
                session_id,
                result: Ok((card, claims)),
            } => {
                if matches!(&v.mode, VettingMode::SendCard { session_id: open, .. } if *open == session_id)
                {
                    v.mode = VettingMode::List;
                }
                config
                    .private
                    .tasks
                    .remove(&Arc::new(format!("vetting-session-{session_id}")));
                let recorded = config
                    .private
                    .vetting
                    .application_by_id_mut(&application_id)
                    .map(|app| app.record_sent_card(&session_id, card, &claims, Utc::now()));
                match recorded {
                    Some(Ok(())) => (
                        "Card sent — the vetter checks it against you and your documents."
                            .to_string(),
                        true,
                    ),
                    Some(Err(e)) => (
                        format!("Card sent, but it could not be recorded: {e}"),
                        true,
                    ),
                    None => ("Card sent, but the application is gone.".to_string(), true),
                }
            }
            VettingOutcome::CardSent {
                result: Err(CardFailure::StepUp),
                ..
            } => (
                "Your VTA wants you to approve this disclosure. Approve it on your device, then \
                 press Enter again."
                    .to_string(),
                false,
            ),
            VettingOutcome::CardSent {
                session_id,
                result: Err(CardFailure::Failed(e)),
                ..
            } => {
                // The preview may be spent; the next Enter asks for a new one.
                if let VettingMode::SendCard {
                    session_id: open,
                    preview,
                    ..
                } = &mut v.mode
                    && *open == session_id
                {
                    *preview = None;
                }
                (
                    format!("Could not send the card: {e}. Enter previews it again."),
                    true,
                )
            }
        };
        // Every outcome is a moment the desk may have changed — a statement
        // sent, a decline delivered — so a card that has served its purpose
        // is forgotten now rather than at the next hourly sweep.
        let pruned = config.private.vetting.prune(Utc::now());
        let persist = persist || pruned;
        dispatch_util::save_and_sync(
            &mut state.main_page,
            config,
            save,
            if persist {
                Persist::SaveAndSync
            } else {
                Persist::SyncOnly
            },
            |mp| &mut mp.content_panel.vetting.status_message,
            message.clone(),
            SyncLog::Plain(message),
        );
    }
}

/// Report a send: clear the inbox task the step answered, or undo the step and
/// say why. Returns the message and whether the book changed.
fn sent_result(sent: Sent, error: Option<String>, config: &mut Config) -> (String, bool) {
    let tasks = &mut config.private.tasks;
    let book = &mut config.private.vetting;
    let clear = |tasks: &mut openvtc_core::tasks::Tasks, id: String| {
        tasks.remove(&Arc::new(id));
    };
    {
        match (sent, error) {
            (Sent::Manifest { community }, None) => (
                format!(
                    "Asked {} for its vetting requirements.",
                    shorten_did(&community, 48)
                ),
                false,
            ),
            (Sent::Request { vetter, .. }, None) => (
                format!(
                    "Request sent to {} — it is answered only if your ticket is valid.",
                    shorten_did(&vetter, 48)
                ),
                false,
            ),
            (Sent::Session { request_id }, None) => {
                clear(tasks, format!("vetting-request-{request_id}"));
                ("Session sent — waiting for their card.".to_string(), true)
            }
            (Sent::Statement { request_id, .. }, None) => {
                clear(tasks, format!("vetting-card-{request_id}"));
                ("Statement signed and sent.".to_string(), true)
            }
            (Sent::Attestation { request_id, .. }, None) => {
                clear(tasks, format!("vetting-card-{request_id}"));
                (
                    "Attestation sent. The community will count it without learning it was you."
                        .to_string(),
                    true,
                )
            }
            (Sent::Decline { request_id, .. }, None) => {
                clear(tasks, format!("vetting-card-{request_id}"));
                clear(tasks, format!("vetting-request-{request_id}"));
                ("Declined.".to_string(), true)
            }
            (Sent::Withdrawal { .. }, None) => (
                "Withdrawal sent — the community confirms when it has recorded it.".to_string(),
                false,
            ),
            (
                Sent::Query {
                    kind: QueryKind::VetterResend,
                    ..
                },
                None,
            ) => (
                "Asked — if the community holds a vetter credential for you, it arrives under \
                 Tickets."
                    .to_string(),
                false,
            ),
            (Sent::Query { .. }, None) => (
                "Asked the community — waiting for its answer.".to_string(),
                false,
            ),
            (Sent::Profile { .. }, None) => (
                "Profile sent — waiting for the community to store it.".to_string(),
                true,
            ),
            (
                Sent::Query {
                    document_id,
                    community,
                    kind,
                },
                Some(e),
            ) => {
                book.forget_query(&document_id);
                (
                    format!(
                        "Could not ask {} for {}: {e}",
                        shorten_did(&community, 48),
                        kind.describe()
                    ),
                    false,
                )
            }
            (
                Sent::Profile {
                    document_id,
                    community,
                    persona,
                    previous,
                },
                Some(e),
            ) => {
                book.restore_profile(&community, persona, previous.map(|p| *p));
                book.forget_query(&document_id);
                (format!("Could not send your profile: {e}"), true)
            }
            (
                Sent::Request {
                    application_id,
                    document_id,
                    ..
                },
                Some(e),
            ) => {
                if let Some(app) = book.application_by_id_mut(&application_id) {
                    app.forget_unsent(&document_id);
                }
                (format!("Could not send the request: {e}"), true)
            }
            (
                Sent::Statement {
                    request_id,
                    statement_id,
                    previous,
                },
                Some(e),
            ) => {
                book.issued.retain(|s| s.id != statement_id);
                if let Some(entry) = book.desk_entry_mut(&request_id) {
                    entry.state = previous;
                }
                (
                    format!("Could not send the statement, so it was not issued: {e}"),
                    true,
                )
            }
            (
                Sent::Attestation {
                    request_id,
                    previous,
                },
                Some(e),
            ) => {
                if let Some(entry) = book.desk_entry_mut(&request_id) {
                    entry.state = previous;
                }
                (
                    format!(
                        "Could not send the attestation: {e}. The token it spent is gone — \
                         attesting again draws on the next one."
                    ),
                    true,
                )
            }
            (
                Sent::Decline {
                    request_id,
                    previous,
                },
                Some(e),
            ) => {
                if let Some(entry) = book.desk_entry_mut(&request_id) {
                    entry.state = previous;
                }
                (format!("Could not send the decline: {e}"), true)
            }
            (Sent::Withdrawal { statement_id }, Some(e)) => {
                if let Some(s) = book.issued.iter_mut().find(|s| s.id == statement_id) {
                    s.withdrawal = None;
                }
                (format!("Could not send the withdrawal: {e}"), true)
            }
            // Asked in the background (start-up, the hourly sweep, a request
            // arriving), and asked again on its own — so the line says that,
            // rather than "try again" to someone who never asked.
            (Sent::Manifest { community }, Some(e)) => (
                {
                    book.mode_failed(&community, ModeFailure::Unsent(e.clone()), Utc::now());
                    format!(
                        "Could not yet ask {} what it requires ({e}) — asking again shortly.",
                        shorten_did(&community, 48)
                    )
                },
                false,
            ),
            (Sent::Session { .. }, Some(e)) => (format!("Could not send — try again: {e}"), false),
        }
    }
}

// ============================================================================
// Answers from communities, revocation checks, and the join flow's hand-off
// ============================================================================

/// Fold communities' answers into the page: a directory page into the view
/// that asked for it, everything else into the status line and the log.
pub(crate) fn apply_answers(state: &mut State, config: &Config, answers: Vec<CommunityAnswer>) {
    for answer in answers {
        let name = community_display(config, answer.community());
        let v = &mut state.main_page.content_panel.vetting;
        let message = match answer {
            // The challenge's notice already says it arrived; a join waiting on
            // one has taken its answer before this runs.
            CommunityAnswer::Manifest { .. } | CommunityAnswer::Challenge { .. } => None,
            CommunityAnswer::Vetters { query, page, .. } => match &mut v.mode {
                VettingMode::Directory(view) if view.pending.as_deref() == Some(query.as_str()) => {
                    view.pending = None;
                    if let Some(cursors) = view.pending_cursors.take() {
                        view.cursors = cursors;
                    }
                    view.results = page.vetters.iter().map(|l| listed_row(config, l)).collect();
                    view.next_cursor = page.next_cursor.map(|c| c.as_str().to_string());
                    view.searched = true;
                    view.error = None;
                    view.field = if view.results.is_empty() {
                        view.field.min(DIRECTORY_FIELDS - 1)
                    } else {
                        DIRECTORY_FIELDS
                    };
                    Some(match view.results.len() {
                        0 => format!("No vetter listed in {name} matches."),
                        1 => format!("1 vetter listed in {name} matches."),
                        n => format!("{n} vetters listed in {name} match, on this page."),
                    })
                }
                _ => None,
            },
            CommunityAnswer::ProfileStored { listed, .. } => Some(if listed {
                format!("{name} published your vetter profile and lists you in its directory.")
            } else {
                format!(
                    "{name} stored your vetter profile. You are not listed, so only people you \
                     give a ticket can reach you."
                )
            }),
            CommunityAnswer::Resent { valid_until, .. } => Some(format!(
                "{name} is sending your vetter credential again, valid until {}. It shows under \
                 Tickets when it arrives.",
                valid_until.format("%Y-%m-%d")
            )),
            CommunityAnswer::Refused { kind, code, .. } if !kind.refusal_is_news(&code) => None,
            CommunityAnswer::Refused {
                query,
                kind,
                code,
                message,
                ..
            } => {
                let mut words = refusal_words(kind, &name, &sanitize_display(&code, 120));
                if let Some(note) = message {
                    words.push_str(&format!(" They said: {}", sanitize_display(&note, 300)));
                }
                directory_failed(v, &query, &words);
                Some(words)
            }
            CommunityAnswer::Unreadable {
                query,
                kind,
                detail,
                ..
            } => {
                let words = format!(
                    "{name} answered about {} in a form this client cannot read — the two \
                     disagree about the task; it is not a refusal ({}).",
                    kind.describe(),
                    sanitize_display(&detail, 200)
                );
                directory_failed(v, &query, &words);
                Some(words)
            }
        };
        if let Some(message) = message {
            state.main_page.content_panel.vetting.status_message = Some(message.clone());
            state.main_page.log(message);
        }
    }
}

/// The directory view waiting on `query` stops waiting, and says why.
fn directory_failed(v: &mut VettingState, query: &str, why: &str) {
    if let VettingMode::Directory(view) = &mut v.mode
        && view.pending.as_deref() == Some(query)
    {
        view.pending = None;
        view.pending_cursors = None;
        view.error = Some(why.to_string());
    }
}

/// One listed vetter, ready to show. The name is the one they published — it
/// is shown beside their DID, never instead of it.
fn listed_row(config: &Config, listed: &vetters::list::v0_1::ListedVetter) -> ListedVetterRow {
    let join = |items: Vec<String>, none: &str| {
        if items.is_empty() {
            none.to_string()
        } else {
            sanitize_display(&items.join(", "), 300)
        }
    };
    let did = listed.vetter_did.as_str();
    ListedVetterRow {
        did: did.to_string(),
        name: listed
            .display_name
            .as_ref()
            .map(|n| n.as_str())
            .or_else(|| config.agent_name_for(did))
            .map(|n| sanitize_display(n, 128))
            .unwrap_or_else(|| shorten_did(did, 48)),
        languages: join(
            listed
                .languages
                .iter()
                .map(|l| l.as_str().to_string())
                .collect(),
            "no language listed",
        ),
        location: listed
            .location
            .as_ref()
            .map(|l| sanitize_display(&listed_location_line(l), 300)),
        // The listing carries its own copy of the method vocabulary, so each is
        // labelled by the token it spells.
        methods: listed
            .methods
            .0
            .iter()
            .map(|m| m.to_string())
            .collect::<Vec<_>>()
            .join(", "),
        documentation: join(
            listed
                .accepts_documentation
                .0
                .iter()
                .map(|d| d.as_str().to_string())
                .collect(),
            "no documentation listed — ask them",
        ),
        availability: listed
            .availability
            .as_ref()
            .map(|a| sanitize_display(a.as_str(), 500)),
        contact_hint: listed
            .contact_hint
            .as_ref()
            .map(|h| sanitize_display(h.as_str(), 300)),
        events: listed
            .events
            .iter()
            .map(|e| sanitize_display(&listed_event_line(e), 300))
            .collect(),
        grant_until: listed.grant_valid_until.format("%Y-%m-%d").to_string(),
    }
}

/// Tell whoever is waiting that a question went unanswered, and forget it. A
/// manifest question is the join flow's, which keeps its own, shorter clock.
pub(crate) fn expire_queries(state: &mut State, config: &mut Config, now: chrono::DateTime<Utc>) {
    let expired = config.private.vetting.expire_queries(now, QUERY_TIMEOUT);
    for query in expired {
        if query.kind == QueryKind::Manifest {
            // Nothing is said here — a waiting ticket or the desk header says it, where it
            // matters — but how the community vets now is unknown, not what it last was. A
            // failure already recorded since the question went (it could not be sent) is the
            // truer story, and stays.
            let book = &mut config.private.vetting;
            if book
                .vetter_mode(&query.community)
                .failed_since(query.sent_at)
                .is_none()
            {
                book.mode_failed(&query.community, ModeFailure::Unanswered, now);
            }
            continue;
        }
        let name = community_display(config, &query.community);
        // Enrolment and the drip are asked again on their own, backed off (R1.4), so the line
        // says when rather than sending the vetter to try something they never started. An
        // answer that arrives late is still taken.
        let retry = matches!(query.kind, QueryKind::PcsRoot | QueryKind::PcsTokens)
            .then(|| {
                config
                    .private
                    .vetting
                    .hidden_vetter_mut(&query.community, query.persona)
                    .map(|held| held.unanswered_at(now))
            })
            .flatten();
        let words = match retry {
            Some(at) => format!(
                "No answer from {name} about {} within {} seconds — its service may be offline \
                 or slow. Asking again at {}; an answer that arrives before then is still taken.",
                query.kind.describe(),
                QUERY_TIMEOUT.num_seconds(),
                when_words(at, now)
            ),
            None => format!(
                "No answer from {name} about {} within {} seconds — its service may be offline. \
                 Try again later.",
                query.kind.describe(),
                QUERY_TIMEOUT.num_seconds()
            ),
        };
        let v = &mut state.main_page.content_panel.vetting;
        directory_failed(v, &query.document_id, &words);
        v.status_message = Some(words.clone());
        state.main_page.log(words);
    }
}

/// Check, off the loop, whether the community revoked a vetter's grant.
///
/// Not claimed through the busy-guard: a check starts from an inbound
/// acceptance rather than a person, each is independent, and none may hold up
/// a vetting send the person is making.
pub(crate) fn spawn_grant_check(
    dispatch_tx: &tokio::sync::mpsc::UnboundedSender<DispatchOutcome>,
    tdk: &affinidi_tdk::TDK,
    check: GrantCheck,
) {
    let resolver = tdk.did_resolver().clone();
    background_dispatch::spawn_dispatch(
        dispatch_tx.clone(),
        DispatchDomain::VettingStatus,
        async move {
            let result = check.run(&resolver).await;
            DispatchOutcome::VettingStatus(GrantChecked { check, result })
        },
    );
}

/// A finished revocation check.
pub(crate) struct GrantChecked {
    pub(crate) check: GrantCheck,
    pub(crate) result: StatusCheck,
}

impl GrantChecked {
    /// Record the result on the request. A revocation is said on the page;
    /// the other results only change the request's line and the log.
    pub(crate) fn apply(self, state: &mut State, config: &mut Config, save: &mut SaveScheduler) {
        let GrantChecked { check, result } = self;
        let vetter = config
            .agent_name_for(&check.vetter)
            .map(|n| sanitize_display(n, 128))
            .unwrap_or_else(|| shorten_did(&check.vetter, 48));
        let community = community_display(config, &check.issuer);
        let message = match &result {
            StatusCheck::Active => format!("{community} has not revoked {vetter}'s vetter grant."),
            StatusCheck::Revoked => format!(
                "{community} has revoked {vetter}'s vetter grant — a statement from them will not \
                 count."
            ),
            StatusCheck::Unknown(reason) => format!(
                "Could not check whether {community} revoked {vetter}'s vetter grant: {}",
                sanitize_display(reason, 200)
            ),
        };
        let revoked = result == StatusCheck::Revoked;
        let recorded = config
            .private
            .vetting
            .application_by_id_mut(&check.application_id)
            .is_some_and(|app| {
                app.record_grant_status(
                    &check.request_document_id,
                    &check.vetter,
                    GrantStatus::from_check(result, Utc::now()),
                )
                .is_ok()
            });
        if !recorded {
            // The application or request went away while the check ran.
            state.main_page.log(message);
            return;
        }
        if revoked {
            dispatch_util::save_and_sync(
                &mut state.main_page,
                config,
                save,
                Persist::SaveAndSync,
                |mp| &mut mp.content_panel.vetting.status_message,
                message.clone(),
                SyncLog::Plain(message),
            );
        } else {
            save.mark_dirty();
            state.main_page.sync_from_config(config);
            state.main_page.log(message);
        }
    }
}

/// Show application `application_id` on the Vetting page, with `message`. Used
/// by the join flow when a person starts or continues an application there.
/// Go to where a vetting task is acted on: the card page for an applicant's
/// open session, or the request on the vetter's desk.
pub(crate) fn focus_vetting_target(
    state: &mut State,
    config: &Config,
    target: &crate::state_handler::main_page::content::VettingTarget,
) {
    use crate::state_handler::main_page::content::VettingTarget;
    match target {
        VettingTarget::Card {
            application_id,
            session_id,
        } => {
            focus_application(
                state,
                config,
                application_id,
                "A vetter opened a session. Read the match code to each other, then Enter \
                 previews your card."
                    .to_string(),
            );
            state.main_page.content_panel.vetting.mode = VettingMode::SendCard {
                application_id: application_id.clone(),
                session_id: session_id.clone(),
                preview: None,
            };
        }
        VettingTarget::Desk { request_id } => {
            state.main_page.sync_from_config(config);
            state.main_page.menu_panel.selected_menu = MainMenu::Vetting;
            state.main_page.menu_panel.selected = false;
            state.main_page.content_panel.selected = true;
            let v = &mut state.main_page.content_panel.vetting;
            v.tab = VettingTab::Desk;
            v.desk_view = DeskView::Requests;
            v.mode = VettingMode::List;
            match v.desk.iter().position(|r| &r.request_id == request_id) {
                Some(i) => {
                    v.selected = i;
                    v.status_message = None;
                    v.journey_target = Some(JourneyTarget::Desk(request_id.clone()));
                    sync_journey(v, config, Utc::now());
                }
                None => {
                    v.status_message = Some("That request is no longer on your desk.".to_string());
                }
            }
        }
    }
}

pub(crate) fn focus_application(
    state: &mut State,
    config: &Config,
    application_id: &str,
    message: String,
) {
    state.main_page.sync_from_config(config);
    state.main_page.menu_panel.selected_menu = MainMenu::Vetting;
    state.main_page.menu_panel.selected = false;
    state.main_page.content_panel.selected = true;
    let v = &mut state.main_page.content_panel.vetting;
    v.tab = VettingTab::Applications;
    v.mode = VettingMode::List;
    if let Some(i) = v.applications.iter().position(|a| a.id == application_id) {
        v.selected = i;
    }
    v.status_message = Some(message);
    // Every way here — starting from the join page, an Inbox entry — lands on
    // the application's journey, so the holder always arrives at the same
    // picture of where they are.
    v.journey_target = Some(JourneyTarget::Application(application_id.to_string()));
    sync_journey(v, config, Utc::now());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::dispatch_util::test_config;
    use crate::state_handler::main_page::content::NewFaceFocus;
    use openvtc_core::vetting::applicant::Application;
    use vta_sdk::protocols::vetting::VETTING_VETTER_RESEND_ERR_NOT_GRANTED;

    fn listed(did: &str) -> vetters::list::v0_1::ListedVetter {
        serde_json::from_value(serde_json::json!({
            "vetterDid": did,
            "displayName": "Carol",
            "languages": ["en"],
            "methods": ["inPerson"],
            "acceptsDocumentation": [],
            "contactHint": "ask at the LPC desk",
            "events": [],
            "grantValidUntil": "2027-09-01T00:00:00Z",
            "updatedAt": "2026-09-01T00:00:00Z"
        }))
        .unwrap()
    }

    fn directory_waiting_on(query: &str) -> State {
        let mut state = State::default();
        state.main_page.content_panel.vetting.mode =
            VettingMode::Directory(Box::new(DirectoryView {
                pending: Some(query.into()),
                pending_cursors: Some(vec![None, Some("page-2".into())]),
                cursors: vec![None],
                ..DirectoryView::default()
            }));
        state
    }

    /// A directory page lands only in the view that asked for it, and moves the
    /// focus onto the first result.
    #[test]
    fn a_directory_page_lands_only_where_it_was_asked_for() {
        let config = test_config();
        let mut state = directory_waiting_on("q1");
        let page = vetters::list::v0_1::Response::try_from(
            vetters::list::v0_1::Response::builder().vetters(vec![listed("did:key:zCarol")]),
        )
        .unwrap();
        apply_answers(
            &mut state,
            &config,
            vec![CommunityAnswer::Vetters {
                query: "someone-else".into(),
                community: "did:web:vtc".into(),
                page: page.clone(),
            }],
        );
        let VettingMode::Directory(view) = &state.main_page.content_panel.vetting.mode else {
            panic!("still the directory");
        };
        assert!(view.results.is_empty() && view.pending.is_some());

        apply_answers(
            &mut state,
            &config,
            vec![CommunityAnswer::Vetters {
                query: "q1".into(),
                community: "did:web:vtc".into(),
                page,
            }],
        );
        let VettingMode::Directory(view) = &state.main_page.content_panel.vetting.mode else {
            panic!("still the directory");
        };
        assert_eq!(view.results.len(), 1);
        assert_eq!(view.results[0].name, "Carol");
        assert_eq!(
            view.results[0].documentation,
            "no documentation listed — ask them"
        );
        assert_eq!(view.cursors.len(), 2, "this is page two");
        assert_eq!(view.result_index(), Some(0));
        assert!(view.pending.is_none());
    }

    /// A refusal reads as what to do next, on the page and in the view.
    #[test]
    fn refusals_are_said_plainly() {
        let config = test_config();
        let mut state = directory_waiting_on("q1");
        apply_answers(
            &mut state,
            &config,
            vec![CommunityAnswer::Refused {
                query: "q1".into(),
                community: "did:web:vtc".into(),
                kind: QueryKind::VetterList,
                code: "permissionDenied".into(),
                message: None,
            }],
        );
        let v = &state.main_page.content_panel.vetting;
        let VettingMode::Directory(view) = &v.mode else {
            panic!("still the directory");
        };
        assert!(view.pending.is_none());
        assert!(
            view.error
                .as_deref()
                .is_some_and(|e| e.contains("would not answer"))
        );

        apply_answers(
            &mut state,
            &config,
            vec![CommunityAnswer::Refused {
                query: "r1".into(),
                community: "did:web:vtc".into(),
                kind: QueryKind::VetterResend,
                code: VETTING_VETTER_RESEND_ERR_NOT_GRANTED.into(),
                message: None,
            }],
        );
        assert!(
            state
                .main_page
                .content_panel
                .vetting
                .status_message
                .as_deref()
                .is_some_and(|m| m.contains("has not named you a vetter"))
        );
    }

    /// A question nobody answered is said to be unanswered, not left spinning.
    #[test]
    fn an_unanswered_search_stops_waiting() {
        let mut config = test_config();
        let mut state = directory_waiting_on("q1");
        config.private.vetting.ask(CommunityQuery {
            document_id: "q1".into(),
            community: "did:web:vtc".into(),
            persona: PersonaId::new(),
            kind: QueryKind::VetterList,
            sent_at: Utc::now() - QUERY_TIMEOUT,
        });
        expire_queries(&mut state, &mut config, Utc::now());
        let VettingMode::Directory(view) = &state.main_page.content_panel.vetting.mode else {
            panic!("still the directory");
        };
        assert!(view.pending.is_none());
        assert!(
            view.error
                .as_deref()
                .is_some_and(|e| e.contains("No answer"))
        );
    }

    fn application_with_request(config: &mut Config) -> (String, String) {
        let mut app = Application::new(
            "did:web:vtc.example",
            PersonaId::new(),
            "did:key:zApplicant",
            Utc::now(),
        )
        .unwrap();
        app.prepare_request(
            "urn:uuid:r1",
            "did:key:zVetter",
            request::v0_1::Ticket::ShortCodeTicket(
                request::v0_1::ShortCodeTicket::try_from(
                    request::v0_1::ShortCodeTicket::builder().code("K7QF-2M9X"),
                )
                .unwrap(),
            ),
            RequestDraft::default(),
            Utc::now(),
        )
        .unwrap();
        let id = app.id.clone();
        config.private.vetting.applications.push(app);
        (id, "urn:uuid:r1".into())
    }

    /// A revoked grant is recorded on the request and said on the page.
    #[test]
    fn a_revoked_grant_is_recorded_and_said() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");
        let (application_id, request_document_id) = application_with_request(&mut config);
        GrantChecked {
            check: GrantCheck {
                application_id,
                request_document_id,
                vetter: "did:key:zVetter".into(),
                issuer: "did:web:vtc.example".into(),
                credential_status: serde_json::json!({}),
            },
            result: StatusCheck::Revoked,
        }
        .apply(&mut state, &mut config, &mut save);
        assert!(matches!(
            config.private.vetting.applications[0].requests[0].grant_status,
            Some(GrantStatus::Revoked { .. })
        ));
        let v = &state.main_page.content_panel.vetting;
        assert!(
            v.status_message
                .as_deref()
                .is_some_and(|m| m.contains("has revoked"))
        );
        assert_eq!(
            v.applications[0].requests[0]
                .grant
                .as_ref()
                .map(|(t, _)| *t),
            Some(LineTone::Bad)
        );
    }

    /// The form opens on what was last sent to that community.
    #[test]
    fn the_profile_form_opens_on_what_was_last_sent() {
        let mut book = VettingBook::default();
        let persona = PersonaId::new();
        let mut draft = ProfileDraft::new(&book.policy);
        draft.display_name = "Carol".into();
        book.record_profile_sent(
            "did:web:vtc",
            persona,
            &draft.to_body().unwrap(),
            Utc::now(),
        );
        let v = VettingState {
            memberships: vec![VettingMembership {
                community: "did:web:vtc".into(),
                name: "VTC".into(),
                persona,
                accent: None,
            }]
            .into(),
            ..VettingState::default()
        };
        let form = profile_form(&v, &book, 0, 0);
        assert_eq!(form.draft.display_name, "Carol");
        assert!(matches!(form.state_line, Some((LineTone::Caution, _))));
        let fresh = profile_form(&VettingState::default(), &book, 0, 0);
        assert!(!fresh.draft.listed, "a first profile is unlisted");
    }

    fn outcome(sent: Sent, error: Option<&str>) -> VettingOutcome {
        VettingOutcome::Sent {
            sent: Box::new(sent),
            error: error.map(ToString::to_string),
        }
    }

    /// A step-up refusal keeps the preview the holder approved, so pressing
    /// Enter after approving presents the same one; any other failure drops
    /// it, because the preview may already be spent.
    #[test]
    fn a_step_up_keeps_the_preview_and_a_failure_drops_it() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");
        let preview = CardPreview {
            preview_id: "01PREVIEW".into(),
            claims: vec![("name.legal".into(), "Alice Example".into())],
            problem: None,
        };
        state.main_page.content_panel.vetting.mode = VettingMode::SendCard {
            application_id: "a".into(),
            session_id: "s".into(),
            preview: Some(preview.clone()),
        };
        let card_sent = |result| VettingOutcome::CardSent {
            application_id: "a".into(),
            session_id: "s".into(),
            result,
        };

        card_sent(Err(CardFailure::StepUp)).apply(&mut state, &mut config, &mut save);
        let v = &state.main_page.content_panel.vetting;
        assert!(matches!(&v.mode, VettingMode::SendCard { preview: Some(p), .. } if *p == preview));
        assert!(
            v.status_message
                .as_deref()
                .is_some_and(|m| m.contains("approve"))
        );

        card_sent(Err(CardFailure::Failed("preview expired".into()))).apply(
            &mut state,
            &mut config,
            &mut save,
        );
        assert!(matches!(
            &state.main_page.content_panel.vetting.mode,
            VettingMode::SendCard { preview: None, .. }
        ));
    }

    /// `f` on the card page opens the picker — the read used to land and be
    /// dropped because the page was not the list — and wearing a face goes
    /// back to the card that asked for it, not to the list.
    #[test]
    fn a_face_chosen_from_the_card_returns_to_the_card() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");
        let v = &mut state.main_page.content_panel.vetting;
        v.mode = VettingMode::SendCard {
            application_id: "a".into(),
            session_id: "s".into(),
            preview: None,
        };
        v.card_after_face = Some(("a".into(), "s".into()));

        VettingOutcome::Faces {
            application_id: "a".into(),
            result: Ok(Vec::new()),
        }
        .apply(&mut state, &mut config, &mut save);
        // Opened even with no faces: its last row makes one.
        assert!(matches!(
            &state.main_page.content_panel.vetting.mode,
            VettingMode::ChooseFace { faces, index: 0, .. } if faces.is_empty()
        ));

        // Wearing leaves the page on the list while the job runs…
        state.main_page.content_panel.vetting.mode = VettingMode::List;
        VettingOutcome::FaceWorn {
            application_id: "a".into(),
            profile_id: "p".into(),
            name: "WORK".into(),
            error: None,
        }
        .apply(&mut state, &mut config, &mut save);
        // …and the answer puts the holder back on the card.
        let v = &state.main_page.content_panel.vetting;
        assert!(matches!(
            &v.mode,
            VettingMode::SendCard { application_id, session_id, preview: None }
                if application_id == "a" && session_id == "s"
        ));
        assert!(v.card_after_face.is_none());
    }

    /// Backing out of the picker a card opened returns to that card; from the
    /// list it returns to the list.
    #[test]
    fn backing_out_of_the_picker_returns_where_it_came_from() {
        let picker = || VettingMode::ChooseFace {
            application_id: "a".into(),
            faces: Vec::new(),
            index: 0,
            required: Vec::new(),
        };
        let mut v = VettingState {
            mode: picker(),
            card_after_face: Some(("a".into(), "s".into())),
            ..VettingState::default()
        };
        back(&mut v);
        assert!(matches!(&v.mode, VettingMode::SendCard { session_id, .. } if session_id == "s"));

        let mut v = VettingState {
            mode: picker(),
            ..VettingState::default()
        };
        back(&mut v);
        assert!(matches!(v.mode, VettingMode::List));
    }

    /// An inbox vetting task opens where its step is taken: the card page for
    /// an applicant's session, the desk for a vetter's request — and says so
    /// when the request has gone, rather than landing on an unrelated row.
    #[test]
    fn a_vetting_task_opens_where_its_step_is_taken() {
        use crate::state_handler::main_page::content::VettingTarget;
        let config = test_config();
        let mut state = State::default();
        focus_vetting_target(
            &mut state,
            &config,
            &VettingTarget::Card {
                application_id: "a".into(),
                session_id: "s".into(),
            },
        );
        assert_eq!(state.main_page.menu_panel.selected_menu, MainMenu::Vetting);
        assert!(matches!(
            &state.main_page.content_panel.vetting.mode,
            VettingMode::SendCard { application_id, session_id, .. }
                if application_id == "a" && session_id == "s"
        ));

        let mut state = State::default();
        focus_vetting_target(
            &mut state,
            &config,
            &VettingTarget::Desk {
                request_id: "gone".into(),
            },
        );
        let v = &state.main_page.content_panel.vetting;
        assert_eq!(v.tab, VettingTab::Desk);
        assert!(
            v.status_message
                .as_deref()
                .is_some_and(|m| m.contains("no longer on your desk"))
        );
    }

    /// An application made as a persona this account no longer holds is never
    /// offered as the one to search a community's directory as: it cannot sign
    /// the request, and offering it made every search fail.
    fn hidden_vetter_book(tokens: usize, enrolled: bool) -> (VettingBook, PersonaId) {
        use openvtc_core::vetting::hidden::HiddenParams;
        let persona = PersonaId::new();
        let params = HiddenParams {
            suite: openvtc_core::vetting::hidden::SUITE.into(),
            helper_key: "zHelper".into(),
            token_key: "zToken".into(),
            vetter_labels: vec!["vetter/2026-10".into()],
            token_labels: vec!["token/2026-10".into()],
            drip_per_tick: 10,
            events: Vec::new(),
            tick_length: None,
        };
        let mut held = HiddenVetterState::new(
            "did:web:first-vtc.example",
            persona,
            params,
            serde_json::from_value(serde_json::json!({ "member": "m", "usk": "", "id": "" }))
                .unwrap(),
        );
        let snapshot = &mut held.snapshot;
        if enrolled {
            snapshot
                .credentials
                .insert("2026-10".into(), "zOctober".into());
        }
        for i in 0..tokens {
            snapshot.tokens.push(
                serde_json::from_value(serde_json::json!({
                    "label": "token/2026-10",
                    "serial": format!("z{i}"),
                    "mintedTick": 0,
                    "credential": "z"
                }))
                .unwrap(),
            );
        }
        let mut book = VettingBook::default();
        book.hidden_vetter.push(held);
        read_as(
            &mut book,
            "did:web:first-vtc.example",
            VetterMode::PcsZkp,
            Utc::now(),
        );
        (book, persona)
    }

    /// Record that `community`'s manifest, read at `at`, said `mode`.
    fn read_as(book: &mut VettingBook, community: &str, mode: VetterMode, at: DateTime<Utc>) {
        use openvtc_core::vetting::book::KnownCommunity;
        use openvtc_core::vetting::mode::ModeRead;
        let read = Some(ModeRead { mode, read_at: at });
        match book
            .communities
            .iter_mut()
            .find(|c| c.community == community)
        {
            Some(known) => known.vetter_mode = read,
            None => book.communities.push(KnownCommunity {
                community: community.into(),
                branding: Default::default(),
                requested: Vec::new(),
                fetched_at: at,
                protocol: None,
                routes: Vec::new(),
                post_quantum_key: None,
                vetter_mode: read,
            }),
        }
    }

    /// A manifest payload whose one criterion names its vetters (`false`) or publishes
    /// hidden-vetting parameters (`true`).
    fn manifest_payload(pcs: bool) -> Value {
        let mut vetting = serde_json::json!({});
        if pcs {
            vetting["ext"] = serde_json::json!({
                openvtc_core::vetting::hidden::HIDDEN_VETTING_NS: {
                    "suite": openvtc_core::vetting::hidden::SUITE,
                    "helperKey": "zHelper",
                    "tokenKey": "zToken",
                    "vetterLabels": ["vetter/2026-10"],
                    "tokenLabels": ["token/2026-10"],
                }
            });
        }
        serde_json::json!({ "criteria": [ { "id": "c1", "vetting": vetting } ] })
    }

    /// The hidden-vetting view shows the rate the community publishes now, and when it was
    /// read from it: a read that moved the drip from 100 to 20 a tick is on the desk at once.
    #[test]
    fn the_hidden_view_shows_the_rate_read_and_when() {
        use chrono::TimeZone;
        let community = "did:web:first-vtc.example";
        let (mut book, _) = hidden_vetter_book(0, true);
        book.hidden_vetter[0].params.drip_per_tick = 100;
        let read = Utc.with_ymd_and_hms(2026, 10, 5, 21, 16, 0).unwrap();
        let row = hidden_row(&book.hidden_vetter[0], "first-vtc".into(), None, read);
        assert_eq!(row.params_read, "not read from the community yet");

        let mut payload = manifest_payload(true);
        payload["criteria"][0]["vetting"]["ext"]
            [openvtc_core::vetting::hidden::HIDDEN_VETTING_NS]["dripPerTick"] =
            serde_json::json!(20);
        book.learn_mode(community, &payload, None, read);
        let row = hidden_row(
            &book.hidden_vetter[0],
            "first-vtc".into(),
            None,
            read + chrono::Duration::minutes(3),
        );
        assert_eq!(row.drip_per_tick, 20);
        assert_eq!(row.drawn_per_tick, 20);
        assert_eq!(row.params_read, "read 21:16 UTC");
        assert!(row.params_hold.is_none());
        let next_day = hidden_row(
            &book.hidden_vetter[0],
            "first-vtc".into(),
            None,
            read + chrono::Duration::days(1),
        );
        assert_eq!(next_day.params_read, "read 2026-10-05 21:16 UTC");
    }

    fn pending_for(persona: PersonaId, asked_at: DateTime<Utc>) -> PendingTicket {
        PendingTicket {
            membership: VettingMembership {
                community: "did:web:first-vtc.example".into(),
                name: "first-vtc".into(),
                persona,
                accent: None,
            },
            uses: 1,
            asked_at,
        }
    }

    /// The desk shows how a community vets from a reading, and a fresh reading replaces a stale
    /// one — an engine held from an earlier month is not taken for PCS ZKP.
    #[test]
    fn a_fresh_mode_reading_replaces_a_stale_one() {
        let community = "did:web:first-vtc.example";
        let now = Utc::now();
        let (mut book, persona) = hidden_vetter_book(0, false);
        read_as(
            &mut book,
            community,
            VetterMode::PcsZkp,
            now - chrono::Duration::hours(5),
        );
        assert!(hides_vetters(&book, community));
        let note = mode_note(&book, community, now).expect("five hours is stale");
        assert!(note.contains("PCS ZKP as of 5 h ago"), "{note}");

        book.learn_mode(
            community,
            &manifest_payload(false),
            Some(VetterMode::PcsZkp),
            now,
        );
        assert!(
            !hides_vetters(&book, community),
            "the engine we still hold is not evidence of PCS ZKP"
        );
        assert!(mode_note(&book, community, now).is_none(), "fresh");
        assert!(
            pcs_tokens_line(&book, community, persona, now).is_none(),
            "no token line for a community that names its vetters"
        );
    }

    /// A community that switched from PCS ZKP to named vetting gets a named ticket, with no
    /// enrolment gate — even though this vetter's PCS ZKP enrolment would have refused one — and
    /// the switch is said.
    #[test]
    fn a_switch_to_named_vetting_issues_a_named_ticket_with_no_gate() {
        let community = "did:web:first-vtc.example";
        let now = Utc::now();
        let asked = now - chrono::Duration::seconds(2);
        let (mut book, persona) = hidden_vetter_book(0, false);
        read_as(
            &mut book,
            community,
            VetterMode::PcsZkp,
            now - chrono::Duration::days(3),
        );
        let pending = pending_for(persona, asked);
        assert_eq!(
            ticket_check(&book, &pending, now),
            TicketCheck::Waiting,
            "the three-day-old reading decides nothing"
        );
        book.learn_mode(
            community,
            &manifest_payload(false),
            Some(VetterMode::PcsZkp),
            now,
        );
        assert_eq!(
            ticket_check(&book, &pending, now),
            TicketCheck::Issue(VetterMode::Named)
        );

        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");
        config.private.vetting = book;
        state.main_page.content_panel.vetting.pending_ticket = Some(pending);
        settle_pending_tickets(&mut state, &mut config, &mut save, now);
        let tickets = &config.private.vetting.tickets;
        assert_eq!(tickets.len(), 1);
        assert_eq!(tickets[0].mode, Some(VetterMode::Named));
        let v = &state.main_page.content_panel.vetting;
        assert!(v.pending_ticket.is_none());
        let said = v.status_message.as_deref().unwrap_or_default();
        assert!(
            said.starts_with("first-vtc switched from PCS ZKP to named vetting."),
            "{said}"
        );
        assert!(said.contains("under named vetting"), "{said}");
    }

    /// A community that switched from named vetting to PCS ZKP gates the ticket on enrolment.
    #[test]
    fn a_switch_to_pcs_zkp_gates_the_ticket() {
        let community = "did:web:first-vtc.example";
        let now = Utc::now();
        let (mut book, persona) = hidden_vetter_book(0, false);
        book.hidden_vetter.clear();
        read_as(
            &mut book,
            community,
            VetterMode::Named,
            now - chrono::Duration::days(1),
        );
        let pending = pending_for(persona, now - chrono::Duration::seconds(1));
        book.learn_mode(
            community,
            &manifest_payload(true),
            Some(VetterMode::Named),
            now,
        );
        let TicketCheck::Gated(why) = ticket_check(&book, &pending, now) else {
            panic!("a vetter not enrolled under PCS ZKP is not given a ticket");
        };
        assert!(why.contains("first-vtc vets by PCS ZKP now"), "{why}");
        assert!(why.contains("enrolling you now"), "{why}");
        assert!(!why.contains(".."), "{why}");
        let switches = book.take_mode_switches();
        assert_eq!(switches.len(), 1);
        assert_eq!(switches[0].from, VetterMode::Named);
        assert_eq!(switches[0].to, VetterMode::PcsZkp);
    }

    /// A read that fails is said — which kind of failure, and what was last known — and no ticket
    /// is issued on the remembered mode either way.
    #[test]
    fn a_failed_mode_read_is_said_not_assumed() {
        let community = "did:web:first-vtc.example";
        let now = Utc::now();
        let asked = now - chrono::Duration::seconds(31);
        let (mut book, persona) = hidden_vetter_book(3, true);
        read_as(
            &mut book,
            community,
            VetterMode::PcsZkp,
            now - chrono::Duration::hours(2),
        );
        let pending = pending_for(persona, asked);
        book.mode_failed(community, ModeFailure::Unanswered, now);
        let TicketCheck::Refused(why) = ticket_check(&book, &pending, now) else {
            panic!("a ticket is not issued on a remembered mode");
        };
        assert!(
            why.contains("could not confirm how first-vtc vets now"),
            "{why}"
        );
        assert!(why.contains("no answer within 30 seconds"), "{why}");
        assert!(why.contains("Last known: PCS ZKP, read 2 h ago"), "{why}");
        assert!(!why.contains(".."), "{why}");

        // The desk header says the same of the community.
        let note = mode_note(&book, community, now).expect("a failure is shown");
        assert!(note.contains("could not read how it vets now"), "{note}");

        // A contract mismatch reads differently from silence (R6.4).
        book.mode_failed(
            community,
            ModeFailure::Unreadable("missing field `criteria`".into()),
            now,
        );
        let TicketCheck::Refused(why) = ticket_check(&book, &pending, now) else {
            panic!("refused");
        };
        assert!(why.contains("cannot read"), "{why}");

        // And with nothing recorded at all, the wait is still bounded (R1.2).
        let (mut book, persona) = hidden_vetter_book(3, true);
        read_as(
            &mut book,
            community,
            VetterMode::PcsZkp,
            now - chrono::Duration::hours(2),
        );
        let pending = pending_for(persona, now - chrono::Duration::seconds(10));
        assert_eq!(ticket_check(&book, &pending, now), TicketCheck::Waiting);
        let pending = pending_for(persona, now - chrono::Duration::seconds(60));
        assert!(matches!(
            ticket_check(&book, &pending, now),
            TicketCheck::Refused(_)
        ));
    }

    /// The enrolment whose answer was lost: the desk header says so briefly, the refusal says it
    /// once in full — with the date the next label can start and what to do meanwhile — and no
    /// sentence ends twice.
    #[test]
    fn a_lost_enrolment_is_said_once_in_full_with_the_next_label_date() {
        let community = "did:web:first-vtc.example";
        let now = chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 10, 5, 15, 14, 0).unwrap();
        let membership = |persona| VettingMembership {
            community: community.into(),
            name: "first-vtc".into(),
            persona,
            accent: None,
        };
        // As recorded now, and as an older record has it: only the refusal, no lost label.
        for recorded in [true, false] {
            let (mut book, persona) = hidden_vetter_book(0, false);
            let held = &mut book.hidden_vetter[0];
            if recorded {
                held.lost_enrolment = Some("2026-10".into());
                held.lost_reasked = true;
            }
            held.last_refusal = Some(openvtc_core::vetting::book::HiddenRefusal {
                what: "your hidden-vetting credential".into(),
                code: "vtc/vetting/vetters/pcs-root:alreadyEnrolled".into(),
                at: now,
            });
            let (short, warn) = standing_tokens(&book, community, persona, now).unwrap();
            assert!(warn);
            assert!(
                short.contains("answer to your enrolment was lost"),
                "{short}"
            );
            assert!(
                !short.contains("already enrolled you"),
                "the header keeps it short: {short}"
            );
            let refusal = ticket_refusal(&book, &membership(persona), now).expect("refused");
            assert!(!refusal.contains(".."), "{refusal}");
            assert!(refusal.contains("vetter/2026-11"), "{refusal}");
            assert!(refusal.contains("Sun 01 Nov 2026"), "{refusal}");
            assert!(refusal.contains("Meanwhile"), "{refusal}");
            assert_eq!(
                refusal.matches("already enrolled you").count(),
                1,
                "said once: {refusal}"
            );
            assert!(
                !refusal.contains(&short),
                "the short line is not repeated: {refusal}"
            );
        }
    }

    /// A ticket issued under one mode is marked once the community runs the other.
    #[test]
    fn a_ticket_from_another_mode_is_marked() {
        let community = "did:web:first-vtc.example";
        let now = Utc::now();
        let mut config = test_config();
        let mut ticket = Ticket::issue(
            community,
            PersonaId::new(),
            vec![],
            1,
            DEFAULT_VALIDITY,
            now,
        );
        ticket.mode = Some(VetterMode::PcsZkp);
        config.private.vetting.tickets.push(ticket);
        read_as(
            &mut config.private.vetting,
            community,
            VetterMode::Named,
            now,
        );
        let mut v = VettingState::default();
        sync(&mut v, &config);
        assert_eq!(
            v.tickets[0].mode_note.as_deref(),
            Some("issued under PCS ZKP")
        );
        read_as(
            &mut config.private.vetting,
            community,
            VetterMode::PcsZkp,
            now,
        );
        sync(&mut v, &config);
        assert_eq!(v.tickets[0].mode_note, None);
    }

    /// Settle a gated ticket for `book` at `now`: the status said, and whether the vetter side
    /// was set to run.
    fn settle_gated(book: VettingBook, persona: PersonaId, now: DateTime<Utc>) -> (String, bool) {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");
        config.private.vetting = book;
        let pending = pending_for(persona, now - chrono::Duration::seconds(1));
        read_as(
            &mut config.private.vetting,
            "did:web:first-vtc.example",
            VetterMode::PcsZkp,
            now,
        );
        assert!(matches!(
            ticket_check(&config.private.vetting, &pending, now),
            TicketCheck::Gated(_)
        ));
        state.main_page.content_panel.vetting.pending_ticket = Some(pending);
        settle_pending_tickets(&mut state, &mut config, &mut save, now);
        assert!(config.private.vetting.tickets.is_empty(), "no ticket");
        (
            state
                .main_page
                .content_panel
                .vetting
                .status_message
                .clone()
                .unwrap_or_default(),
            config.private.vetting.vetter_refresh_due,
        )
    }

    /// `t` with nothing to attest with does not just refuse: a vetter not enrolled yet is
    /// enrolled and drawn for at once — one key, no hunting for the hidden-vetting view.
    #[test]
    fn t_without_tokens_gets_them_when_it_can() {
        let now = chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 10, 5, 15, 14, 0).unwrap();
        let community = "did:web:first-vtc.example";
        let (book, persona) = hidden_vetter_book(0, false);
        assert!(tokens_obtainable_now(&book, community, persona, now));
        let (said, runs) = settle_gated(book, persona, now);
        assert!(said.contains("enrolling you now"), "{said}");
        assert!(said.contains("Getting them now"), "{said}");
        assert!(runs, "the schedule runs at once: enrol, then draw");

        // Enrolled, and a window has begun undrawn: it is drawn now.
        let (book, persona) = hidden_vetter_book(0, true);
        let words = get_tokens_words(&book, community, persona, "first-vtc", now);
        assert!(
            words.starts_with("drawing 2 windows of tokens now"),
            "{words}"
        );
        assert!(tokens_obtainable_now(&book, community, persona, now));
    }

    /// Enrolled, with this window drawn already: nothing to run, and the vetter is told exactly
    /// when the next window opens rather than being sent to press something that cannot help.
    #[test]
    fn t_after_this_windows_draw_says_when_the_next_opens() {
        let now = chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 10, 5, 15, 14, 0).unwrap();
        let community = "did:web:first-vtc.example";
        let (mut book, persona) = hidden_vetter_book(0, true);
        book.hidden_vetter[0]
            .last_ticks
            .insert("token/2026-10".into(), 1);
        assert!(!tokens_obtainable_now(&book, community, persona, now));
        let words = get_tokens_words(&book, community, persona, "first-vtc", now);
        assert_eq!(
            words,
            "this window's tokens are already drawn (0 tokens usable); the next window opens \
             Wed 07 Oct 00:00 UTC"
        );
        let (said, runs) = settle_gated(book, persona, now);
        assert!(
            said.contains("the next window opens Wed 07 Oct 00:00 UTC"),
            "{said}"
        );
        assert!(!said.contains("Getting them now"), "{said}");
        assert!(!runs);
    }

    /// A lost enrolment answer: nothing to run until the community publishes a new label, so
    /// the words give the dates and what its operator can do today.
    #[test]
    fn t_after_a_lost_enrolment_says_what_unblocks_it() {
        let now = chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 10, 5, 15, 14, 0).unwrap();
        let community = "did:web:first-vtc.example";
        let (mut book, persona) = hidden_vetter_book(0, false);
        book.hidden_vetter[0].lost_enrolment = Some("2026-10".into());
        // Not yet asked once more: that ask is still to run.
        assert!(tokens_obtainable_now(&book, community, persona, now));
        book.hidden_vetter[0].lost_reasked = true;
        assert!(!tokens_obtainable_now(&book, community, persona, now));
        let (said, runs) = settle_gated(book, persona, now);
        assert!(said.contains("Sun 01 Nov 2026"), "{said}");
        assert!(
            said.contains("livePeriods (for example 2026-10b)"),
            "{said}"
        );
        assert!(said.contains("press k on the desk"), "{said}");
        assert!(!said.contains("Getting them now"), "{said}");
        assert!(!said.contains(".."), "{said}");
        assert!(!runs);
    }

    /// The token line says what is held and when that changes, in time — never a raw tick.
    #[test]
    fn the_token_line_says_what_is_held_and_when_it_changes() {
        let now = chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 10, 5, 15, 14, 0).unwrap();
        let community = "did:web:first-vtc.example";
        let (mut book, persona) = hidden_vetter_book(0, true);
        let (line, warn) = pcs_tokens_line(&book, community, persona, now).unwrap();
        assert!(warn);
        assert_eq!(line, "0 tokens — next drip due Wed 07 Oct 00:00 UTC");

        book.hidden_vetter[0].unanswered_at(now);
        let (line, _) = pcs_tokens_line(&book, community, persona, now).unwrap();
        assert_eq!(
            line,
            "0 tokens — the community has not answered; asking again at 15:15 UTC"
        );

        let (book, persona) = hidden_vetter_book(3, true);
        let (line, warn) = pcs_tokens_line(&book, community, persona, now).unwrap();
        assert!(!warn);
        assert!(line.starts_with("3 tokens — next drip due"), "{line}");

        let (book, persona) = hidden_vetter_book(0, false);
        let (line, warn) = pcs_tokens_line(&book, community, persona, now).unwrap();
        assert!(warn);
        assert_eq!(line, "not enrolled yet — enrolling now (k to get tokens)");

        // A community that names its vetters has no token line at all.
        assert!(pcs_tokens_line(&book, "did:web:other.example", persona, now).is_none());
    }

    /// A vetter that cannot attest under PCS ZKP is not given a ticket that would bring requests
    /// it cannot honour; one with tokens is.
    #[test]
    fn no_ticket_is_issued_for_requests_that_cannot_be_attested() {
        let now = Utc::now();
        let membership = |persona| VettingMembership {
            community: "did:web:first-vtc.example".into(),
            name: "first-vtc".into(),
            persona,
            accent: None,
        };
        let (book, persona) = hidden_vetter_book(0, true);
        let refusal = ticket_refusal(&book, &membership(persona), now).expect("refused");
        assert!(refusal.contains("first-vtc"), "{refusal}");
        assert!(
            refusal.contains("drawing 2 windows of tokens now (0 tokens usable already)"),
            "{refusal}"
        );
        let (book, persona) = hidden_vetter_book(0, false);
        assert!(ticket_refusal(&book, &membership(persona), now).is_some());
        let (book, persona) = hidden_vetter_book(2, true);
        assert!(ticket_refusal(&book, &membership(persona), now).is_none());
        // A named community is never gated on tokens.
        let named = VettingMembership {
            community: "did:web:named.example".into(),
            ..membership(persona)
        };
        assert!(ticket_refusal(&book, &named, now).is_none());
    }

    /// The desk header warns when the live tickets out admit more requests than the tokens held.
    #[test]
    fn the_desk_header_warns_of_tickets_beyond_the_tokens_held() {
        let now = Utc::now();
        let (mut book, persona) = hidden_vetter_book(2, true);
        let community = "did:web:first-vtc.example";
        let (line, warn) = standing_tokens(&book, community, persona, now).unwrap();
        assert!(!warn, "{line}");
        book.tickets.push(Ticket::issue(
            community,
            persona,
            vec![],
            5,
            DEFAULT_VALIDITY,
            now,
        ));
        let (line, warn) = standing_tokens(&book, community, persona, now).unwrap();
        assert!(warn);
        assert!(
            line.contains("your live tickets admit 5 requests"),
            "{line}"
        );
    }

    #[test]
    fn the_directory_never_searches_as_a_persona_that_is_gone() {
        let mut config = test_config();
        let app = Application::new(
            "did:web:vtc.example",
            PersonaId::new(),
            "did:key:zGone",
            Utc::now(),
        )
        .unwrap();
        config.private.vetting.applications.push(app);
        let mut v = VettingState::default();
        sync(&mut v, &config);
        assert!(
            v.directory_communities.is_empty(),
            "a deleted persona's application is not a searcher: {:?}",
            v.directory_communities
        );
    }

    /// The picker opens on the face already worn, and the page remembers it.
    #[test]
    fn the_face_picker_opens_on_the_worn_face() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");
        let face = |id: &str, worn| FaceChoice {
            profile_id: id.into(),
            name: id.to_uppercase(),
            entries: 2,
            worn,
            claim_types: vec!["name.legal".into()],
        };
        VettingOutcome::Faces {
            application_id: "a".into(),
            result: Ok(vec![face("home", false), face("work", true)]),
        }
        .apply(&mut state, &mut config, &mut save);
        let v = &state.main_page.content_panel.vetting;
        assert!(matches!(&v.mode, VettingMode::ChooseFace { index: 1, .. }));
        assert_eq!(v.worn_faces.get("a").map(String::as_str), Some("WORK"));
    }

    fn held(id: &str, claim_type: &str, value: &str) -> PoolRow {
        PoolRow {
            attribute_id: id.into(),
            claim_type: claim_type.into(),
            label: claim_type.to_uppercase(),
            value: Some(value.into()),
        }
    }

    /// Open the make-a-face form over `pool`, as the pool read does.
    fn open_form(config: &mut Config, application_id: &str, pool: Vec<PoolRow>) -> State {
        let mut state = State::default();
        let mut save = SaveScheduler::new("test");
        VettingOutcome::Pool {
            application_id: application_id.into(),
            required: vec!["name.legal".into()],
            result: Ok(pool),
        }
        .apply(&mut state, config, &mut save);
        state
    }

    fn form_of(state: &mut State) -> &mut NewFaceForm {
        match &mut state.main_page.content_panel.vetting.mode {
            VettingMode::NewFace(form) => form,
            _ => panic!("the form did not open"),
        }
    }

    /// The whole point of making the face *here*: the community has already
    /// said what its card needs, so the holder should not have to work that out
    /// again from a list of attributes. What it did not ask for stays unticked:
    /// a face shows what it holds, and showing more is the holder's choice.
    #[test]
    fn the_new_face_form_opens_with_only_the_required_claims_ticked() {
        let mut config = test_config();
        let mut state = open_form(
            &mut config,
            "a",
            vec![
                held("attr-email", "email.work", "a@work.example"),
                held("attr-name", "name.legal", "Alice Example"),
            ],
        );
        let form = form_of(&mut state);
        assert_eq!(form.ticked, vec!["attr-name".to_string()]);
        assert!(form.still_missing().is_empty());
        assert_eq!(form.extras().len(), 1, "the email is offered, unticked");
        // Unticking it is said against the selection, not the pool, so the
        // status line changes at the moment the choice is made.
        form.focus = NewFaceFocus::Asked(0);
        form.toggle();
        assert_eq!(form.still_missing(), vec!["name.legal"]);
        assert!(
            form.status().contains("choose your legal name"),
            "{}",
            form.status()
        );
    }

    /// A requirement already held needs nothing from the holder: the name is
    /// filled in and the claim ticked, so the first Enter makes the face.
    #[test]
    fn a_held_requirement_makes_the_face_on_the_first_enter() {
        let mut config = test_config();
        let mut state = open_form(
            &mut config,
            "a",
            vec![held("attr-name", "name.legal", "Alice Example")],
        );
        let form = form_of(&mut state);
        assert!(form.ready(), "{}", form.status());
        assert_eq!(
            form.status(),
            "1 of 1 required attribute ready — Enter: make the face and wear it"
        );
        match form.enter() {
            NewFaceStep::Make { name, live_refs } => {
                assert_eq!(name, "Vetting");
                assert_eq!(live_refs, vec!["attr-name".to_string()]);
            }
            other => panic!("expected the face to be made, got {other:?}"),
        }
    }

    /// The case that stranded people: nothing in the pool. The form asks for
    /// the value on the row that needs it, Enter saves it as a real attribute
    /// under the right type key, and the saved attribute comes back ticked —
    /// one more Enter makes the face. The holder never types `name.legal`.
    #[test]
    fn with_no_attributes_the_value_is_typed_saved_and_ticked_in_place() {
        let mut config = test_config();
        let mut state = open_form(&mut config, "a", Vec::new());
        let mut save = SaveScheduler::new("test");
        {
            let form = form_of(&mut state);
            assert_eq!(
                form.focus,
                NewFaceFocus::Asked(0),
                "opens on what is needed"
            );
            assert!(form.needs_input("name.legal"));
            assert!(
                form.status().contains("type your legal name below"),
                "{}",
                form.status()
            );
            // Enter with nothing typed sends nothing, and adds no second voice.
            assert!(matches!(form.enter(), NewFaceStep::Wait));
            assert!(form.error.is_none());
        }
        // Typed through the page's own input path, spaces and all.
        input(
            &mut state.main_page.content_panel.vetting.mode,
            "Alice Example".into(),
        );
        let draft = match form_of(&mut state).enter() {
            NewFaceStep::Save(draft) => draft,
            other => panic!("expected a save, got {other:?}"),
        };
        assert_eq!(draft.claim_type, "name.legal");
        assert_eq!(draft.value, serde_json::json!("Alice Example"));
        assert!(draft.attribute_id.is_none(), "a create, not an update");
        assert!(
            form_of(&mut state)
                .status()
                .starts_with("Saving your legal name"),
            "{}",
            form_of(&mut state).status()
        );
        // A second Enter while the write is out sends nothing.
        assert!(matches!(form_of(&mut state).enter(), NewFaceStep::Wait));

        VettingOutcome::AttributeSaved {
            application_id: "a".into(),
            claim_type: "name.legal".into(),
            result: Ok(held("attr-new", "name.legal", "Alice Example")),
        }
        .apply(&mut state, &mut config, &mut save);

        assert!(
            state.main_page.content_panel.identity.refresh_queued,
            "My Identity re-reads the pool it no longer matches"
        );
        let form = form_of(&mut state);
        assert_eq!(form.ticked, vec!["attr-new".to_string()]);
        assert!(form.saving.is_none());
        assert!(form.draft("name.legal").is_empty());
        assert!(form.ready(), "{}", form.status());
        assert!(matches!(
            form.enter(),
            NewFaceStep::Make { live_refs, .. } if live_refs == vec!["attr-new".to_string()]
        ));
    }

    /// A save the agent refuses leaves the typed value where it was, with the
    /// reason beside it, and the form ready to try again.
    #[test]
    fn a_refused_save_keeps_the_value_and_says_why() {
        let mut config = test_config();
        let mut state = open_form(&mut config, "a", Vec::new());
        let mut save = SaveScheduler::new("test");
        input(
            &mut state.main_page.content_panel.vetting.mode,
            "Alice Example".into(),
        );
        assert!(matches!(form_of(&mut state).enter(), NewFaceStep::Save(_)));
        VettingOutcome::AttributeSaved {
            application_id: "a".into(),
            claim_type: "name.legal".into(),
            result: Err("persona attribute write failed: timed out".into()),
        }
        .apply(&mut state, &mut config, &mut save);
        let form = form_of(&mut state);
        assert!(form.saving.is_none());
        assert_eq!(form.draft("name.legal"), "Alice Example");
        assert!(
            form.error
                .as_deref()
                .is_some_and(|e| e.contains("timed out")),
            "{:?}",
            form.error
        );
        assert!(matches!(form.enter(), NewFaceStep::Save(_)), "retryable");
    }

    /// Two legal names: one is pre-ticked, and ←/→ or Space swaps which —
    /// never both, and never neither.
    #[test]
    fn several_attributes_of_a_required_type_are_chosen_between() {
        let mut config = test_config();
        let mut state = open_form(
            &mut config,
            "a",
            vec![
                held("attr-1", "name.legal", "Alice Example"),
                held("attr-2", "name.legal", "Alice B. Example"),
            ],
        );
        let v = &mut state.main_page.content_panel.vetting;
        let VettingMode::NewFace(form) = &mut v.mode else {
            panic!("the form did not open");
        };
        assert_eq!(form.ticked, vec!["attr-1".to_string()]);
        form.focus = NewFaceFocus::Asked(0);
        cycle(v, true);
        let VettingMode::NewFace(form) = &mut v.mode else {
            unreachable!()
        };
        assert_eq!(form.ticked, vec!["attr-2".to_string()]);
        form.toggle();
        assert_eq!(form.ticked, vec!["attr-1".to_string()], "Space steps too");
        form.pick(false);
        assert_eq!(form.ticked, vec!["attr-2".to_string()]);
        assert!(form.ready());
    }

    /// The face's name is the community's agent name only once that name has
    /// been verified; with none verified it is a plain word, never a name read
    /// from the community's own document.
    #[test]
    fn the_face_is_named_after_the_community_only_by_a_verified_name() {
        let community = "did:webvh:QmScid:club.example";
        let mut config = test_config();
        let app = Application::new(community, PersonaId::new(), "did:key:zJoin", Utc::now())
            .expect("application");
        let id = app.id.clone();
        config.private.vetting.applications.push(app);

        let mut state = open_form(&mut config, &id, Vec::new());
        assert_eq!(form_of(&mut state).name, "Vetting");

        config.set_cached_agent_name(community, Some("club.example/@club".into()), Utc::now());
        let mut state = open_form(&mut config, &id, Vec::new());
        assert_eq!(form_of(&mut state).name, "club.example/@club");
    }

    /// The pool is what a face is built over, so it meets the same refusal the
    /// faces read does — and must answer it the same way rather than passing
    /// the agent's paragraph through.
    #[test]
    fn the_pool_read_routes_the_holder_refusal_to_the_same_view() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");

        VettingOutcome::Pool {
            application_id: "a".into(),
            required: Vec::new(),
            result: Err("forbidden: requires an unscoped holder credential".into()),
        }
        .apply(&mut state, &mut config, &mut save);

        assert!(matches!(
            &state.main_page.content_panel.vetting.mode,
            VettingMode::HolderGrant { .. }
        ));
    }

    /// The card preview's one explicable refusal. The agent's sentence names
    /// neither the claims, nor the face, nor the key that changes it — and it
    /// arrives three steps after the choice that caused it.
    #[test]
    fn the_preview_refusal_names_the_claims_and_the_key() {
        let mut config = test_config();
        let mut app = Application::new(
            "did:web:vtc.example",
            PersonaId::new(),
            "did:key:zApplicant",
            Utc::now(),
        )
        .unwrap();
        app.face = Some(ChosenFace {
            profile_id: "p1".into(),
            name: "OSS Developer".into(),
        });
        let id = app.id.clone();
        config.private.vetting.applications.push(app);

        let out = preview_refusal(
            "VTA Error: persona disclosure preview failed: protocol error: trust task failed \
             [malformedRequest]: validation error: none of the requested claim types are present \
             in this persona's profile",
            &id,
            &config,
        );
        // The face it is actually wearing, so there is no doubt which to change.
        assert!(out.contains("OSS Developer"), "{out}");
        // And the key that changes it.
        assert!(out.contains("Press f"), "{out}");
        // The agent's framing does not survive into the sentence.
        assert!(!out.contains("malformedRequest"), "{out}");
    }

    /// No face worn at all: making an application does not choose one, so the
    /// first card of an application whose face was never picked meets this.
    /// The agent's sentence names a DID; this one names the key.
    #[test]
    fn a_card_with_no_face_worn_says_to_choose_one() {
        let out = preview_refusal(
            "VTA Error: persona disclosure preview failed: not found: not found: persona \
             did:webvh:QmS:dids-wonderland.ic3.dev:march-issue has no profile bound, so there \
             is nothing to disclose",
            "no-such-application",
            &test_config(),
        );
        assert!(out.contains("no face yet"), "{out}");
        assert!(out.contains("Press f"), "{out}");
        assert!(!out.contains("did:webvh"), "{out}");
    }

    /// Anything else is passed through. A failure we cannot explain is better
    /// verbatim than paraphrased into a guess (R6.4).
    #[test]
    fn other_preview_failures_are_reported_as_they_came() {
        let config = test_config();
        let out = preview_refusal("connection refused", "no-such-application", &config);
        assert_eq!(out, "Could not preview the card: connection refused");
    }

    /// The refusal with an answer opens a view, so the command it names gets a
    /// line to itself. As a status line it wrapped at the panel's width, which
    /// fell mid-DID.
    #[test]
    fn the_holder_refusal_opens_a_view_and_everything_else_does_not() {
        let mut save = SaveScheduler::new("test");

        let mut state = State::default();
        let mut config = test_config();
        VettingOutcome::Faces {
            application_id: "a".into(),
            result: Err("forbidden: requires an unscoped holder credential".into()),
        }
        .apply(&mut state, &mut config, &mut save);
        assert!(matches!(
            &state.main_page.content_panel.vetting.mode,
            VettingMode::HolderGrant { .. }
        ));

        // A failure we do not recognise has no command to offer, so a view
        // would be a bigger frame around the same sentence — and inventing a
        // cause for it is what R6.4 forbids.
        let mut state = State::default();
        let mut config = test_config();
        VettingOutcome::Faces {
            application_id: "a".into(),
            result: Err("connection refused".into()),
        }
        .apply(&mut state, &mut config, &mut save);
        assert!(matches!(
            &state.main_page.content_panel.vetting.mode,
            VettingMode::List
        ));
    }

    /// A request that never left is forgotten, so retrying is not shadowed by
    /// a record the vetter never saw.
    #[test]
    fn a_failed_request_is_forgotten() {
        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");
        let mut app = Application::new(
            "did:web:vtc.example",
            PersonaId::new(),
            "did:key:zApplicant",
            Utc::now(),
        )
        .unwrap();
        app.prepare_request(
            "urn:uuid:r1",
            "did:key:zVetter",
            request::v0_1::Ticket::ShortCodeTicket(
                request::v0_1::ShortCodeTicket::try_from(
                    request::v0_1::ShortCodeTicket::builder().code("K7QF-2M9X"),
                )
                .unwrap(),
            ),
            RequestDraft::default(),
            Utc::now(),
        )
        .unwrap();
        let application_id = app.id.clone();
        config.private.vetting.applications.push(app);

        outcome(
            Sent::Request {
                application_id,
                document_id: "urn:uuid:r1".into(),
                vetter: "did:key:zVetter".into(),
            },
            Some("mediator unreachable"),
        )
        .apply(&mut state, &mut config, &mut save);

        assert!(config.private.vetting.applications[0].requests.is_empty());
        assert!(
            state
                .main_page
                .content_panel
                .vetting
                .status_message
                .as_deref()
                .is_some_and(|m| m.contains("unreachable"))
        );
    }

    /// The page lists what the book holds.
    #[test]
    fn sync_lists_applications_and_tickets() {
        use affinidi_tdk::messaging::profiles::{ATMProfile, ATMProfileInner};
        let mut config = test_config();
        let persona = PersonaId::new();
        // A persona this account holds: only one of those can sign a search.
        config.identities.insert(
            persona,
            openvtc_core::identity::IdentityContext {
                persona_id: persona,
                did: "did:key:zA".to_string(),
                document: serde_json::from_value(serde_json::json!({ "id": "did:key:zA" }))
                    .expect("minimal DID document"),
                profile: std::sync::Arc::new(ATMProfile {
                    inner: std::sync::Arc::new(ATMProfileInner {
                        did: "did:key:zA".to_string(),
                        alias: "did:key:zA".to_string(),
                        mediator: std::sync::Arc::new(None),
                    }),
                }),
                mediator_did: None,
            },
        );
        config
            .private
            .vetting
            .start_application("did:web:vtc.example", persona, "did:key:zA", Utc::now())
            .unwrap();
        config.private.vetting.tickets.push(Ticket::issue(
            "did:web:vtc.example",
            persona,
            vec![],
            1,
            DEFAULT_VALIDITY,
            Utc::now(),
        ));
        let mut v = VettingState::default();
        sync(&mut v, &config);
        assert_eq!(v.applications.len(), 1);
        assert_eq!(
            v.applications[0].next_step.as_deref(),
            Some(next_step_words(&NextStep::LearnRequirements).as_str())
        );
        assert_eq!(
            v.directory_communities.len(),
            1,
            "an application can search"
        );
        assert_eq!(
            v.applications[0].identity,
            vec![("name.legal".to_string(), String::new())],
            "without requirements the page asks for a legal name"
        );
        assert_eq!(v.tickets.len(), 1);
        assert!(v.tickets[0].live);
        assert!(v.documentation.iter().any(|d| d == "none"));
    }

    /// first-vtc's live manifest: `vetted-member` runs PCS ZKP alongside named vetters.
    fn first_vtc_book() -> (VettingBook, String) {
        let document: Value = serde_json::from_str(include_str!(
            "../../../openvtc-core/tests/fixtures/first-vtc-manifest-0.3.json"
        ))
        .unwrap();
        let payload = document["payload"].clone();
        let community = payload["communityDid"].as_str().unwrap().to_string();
        let protocol = openvtc_core::vetting::protocol::JoinProtocol::V0_3;
        let (parsed, meta) =
            openvtc_core::vetting::protocol::read_manifest(protocol, &payload).unwrap();
        let mut book = VettingBook::default();
        let now = Utc::now();
        book.learn_manifest_in(&community, &parsed, Some(protocol), &meta, now);
        book.learn_mode(&community, &payload, None, now);
        (book, community)
    }

    /// A request that cannot be attested says why, under which criterion, and what the
    /// applicant does — not one fixed hint (R6.4).
    #[test]
    fn a_request_without_an_identifier_under_a_hidden_only_criterion_says_what_to_do() {
        let words = hidden_without_id_words("vetted-member");
        assert!(words.contains("criterion vetted-member"), "{words}");
        assert!(words.contains("accepts only a PCS ZKP proof"), "{words}");
        assert!(words.contains("refresh their requirements (m)"), "{words}");
        assert!(words.contains("send you a new request"), "{words}");
    }

    /// The application names its criterion and path, and a named one under a criterion that
    /// also offers PCS ZKP says so — the two badges no longer contradict each other unexplained.
    #[test]
    fn an_application_shows_its_criterion_and_path() {
        let (mut book, community) = first_vtc_book();
        let persona = PersonaId::new();
        let id = book
            .start_application(&community, persona, "did:key:zA", Utc::now())
            .unwrap()
            .id
            .clone();
        book.adopt_known_requirements(&id).unwrap();
        let app = book.applications[0].clone();
        let (line, note) = criterion_words(&book, &app).unwrap();
        assert_eq!(
            line,
            "vetted-member — One vetter must confirm who you are · PCS ZKP · 2 ways to be \
             vetted here, p switches"
        );
        assert!(note.is_none());

        // The live case: a named application whose request already went out.
        book.switch_vetting(&id).unwrap();
        let app = book.applications[0].clone();
        let (line, note) = criterion_words(&book, &app).unwrap();
        assert!(line.contains("· named vetting ·"), "{line}");
        let note = note.expect("named where PCS ZKP is on offer is explained");
        assert!(note.contains("also accepts PCS ZKP"), "{note}");
    }

    /// A ticket where PCS ZKP runs alongside named vetting does not promise a proof every time.
    #[test]
    fn a_ticket_in_a_community_offering_both_paths_says_so() {
        let (book, community) = first_vtc_book();
        let words = ticket_mode_words(&book, &community, VetterMode::PcsZkp);
        assert!(words.starts_with("PCS ZKP (named vetting too"), "{words}");
        assert_eq!(
            ticket_mode_words(&VettingBook::default(), &community, VetterMode::PcsZkp),
            "PCS ZKP"
        );
    }
}
