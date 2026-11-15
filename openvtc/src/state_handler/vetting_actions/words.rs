//! Config to display: the words and lines the Vetting page shows for grants,
//! hidden-vetting standing, tokens, next steps and requirements.

use chrono::{DateTime, Utc};
use openvtc_core::config::Config;
use openvtc_core::config::account::PersonaId;
use openvtc_core::vetting::VettingBook;
use openvtc_core::vetting::applicant::{Application, GrantStatus, NextStep, VetterEligibility};
use openvtc_core::vetting::book::{DrawHold, HiddenOutlook, HiddenVetterState};
use openvtc_core::vetting::mode::age_words;
use serde_json::Value;
use vta_sdk::protocols::vetting::VettingRequirements;
use vta_sdk::vetting::requirements::{Evaluation, Need};

use crate::state_handler::main_page::content::{
    HiddenKeyLine, HiddenVettingRow, LineTone, method_label,
};
use crate::state_handler::main_page::sanitize_display;

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
pub(super) fn grant_standing(
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
pub(super) fn profile_standing(
    state: Option<&openvtc_core::vetting::registry::ProfileState>,
) -> String {
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
        } else if o.key_held {
            "not enrolled — the community knows you by another hidden-vetting key (h for details)"
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
    if o.rekeyed || o.enrolment_lost || o.key_held {
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
        if o.key_held
            && let Some(words) = key_words(held, name)
        {
            return words;
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

/// Where getting back to the hidden-vetting key `name` bound us to stands, in one sentence —
/// `None` when nothing is wrong with the key.
pub(crate) fn key_words(held: &HiddenVetterState, name: &str) -> Option<String> {
    let check = held.key.as_ref()?;
    Some(
        openvtc_core::vetting::binding::key_lines(check, name, |s| sanitize_display(s, 200))
            .into_iter()
            .map(|l| format!("{} {}", l.label.to_lowercase(), l.text))
            .collect::<Vec<_>>()
            .join("; "),
    )
}

/// `text` as a clause to continue a sentence: without the full stop it may end with, so a
/// composed message never reads "label.. A ticket".
pub(super) fn clause(text: &str) -> &str {
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
pub(super) fn mode_note(book: &VettingBook, community: &str, now: DateTime<Utc>) -> Option<String> {
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
pub(super) fn standing_tokens(
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
pub(super) fn hidden_row(
    held: &HiddenVetterState,
    community: String,
    accent: Option<(u8, u8, u8)>,
    now: DateTime<Utc>,
) -> HiddenVettingRow {
    use openvtc_core::vetting::hidden;
    let when = |t: DateTime<Utc>| t.format("%Y-%m-%d %H:%M UTC").to_string();
    let community_name = community.clone();
    let events = held.event_draws(now.date_naive());
    let mut enrolled: Vec<(String, Option<String>)> = held
        .engine
        .enrolled_labels
        .iter()
        .map(|label| {
            (
                label.clone(),
                held.enrolled_at
                    .get(label.trim_start_matches("vetter/"))
                    .map(|t| t.format("%Y-%m-%d").to_string()),
            )
        })
        .collect();
    enrolled.truncate(4);
    let enrolment_owed = held
        .params
        .vetter_labels
        .first()
        .filter(|l| !held.engine.enrolled_for(l.trim_start_matches("vetter/")))
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
        key: held
            .key
            .as_ref()
            .map(|check| {
                openvtc_core::vetting::binding::key_lines(check, &community_name, |s| {
                    sanitize_display(s, 200)
                })
                .into_iter()
                .map(|l| HiddenKeyLine {
                    label: l.label,
                    text: l.text,
                    act: l.act,
                })
                .collect()
            })
            .unwrap_or_default(),
        enrolment_held: held.enrolment_held(),
    }
}

pub(super) fn claim_text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// What a vetter's acceptance showed, in a line, and whether it is good news.
pub(super) fn eligibility_line(eligibility: &VetterEligibility) -> (bool, String) {
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
pub(super) fn grant_line(status: &GrantStatus) -> (LineTone, String) {
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

pub(super) fn requirements_line(r: &VettingRequirements) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::dispatch_util::test_config;
    use crate::state_handler::save_coalesce::SaveScheduler;
    use crate::state_handler::state::State;
    use crate::state_handler::vetting_actions::test_support::{
        hidden_vetter_book, manifest_payload, pending_for, read_as,
    };
    use crate::state_handler::vetting_actions::tickets::{
        TicketCheck, settle_pending_tickets, ticket_check,
    };
    use chrono::{DateTime, Utc};
    use openvtc_core::config::account::PersonaId;
    use openvtc_core::vetting::VettingBook;
    use openvtc_core::vetting::mode::VetterMode;
    use openvtc_core::vetting::tickets::{DEFAULT_VALIDITY, Ticket};

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

    /// A vetter the community knows by another hidden-vetting key is told where getting it back
    /// stands — on the hidden view, in the desk's token line and when asking for tokens — and
    /// enrolment waits on it until the key is restored or a reset opens.
    #[test]
    fn a_key_bound_elsewhere_is_said_until_a_reset_opens() {
        use openvtc_core::vetting::binding::{Binding, RecoverRefusal, ResetState};
        let community = "did:web:first-vtc.example";
        let (mut book, persona) = hidden_vetter_book(0, false);
        let now = Utc::now();
        let bound = |reset: Option<ResetState>| Binding {
            id: Some("zOld".into()),
            reset,
        };
        let held = &mut book.hidden_vetter[0];
        held.on_rebound(now);
        held.on_binding_shown(&bound(None), now);
        let row = hidden_row(&book.hidden_vetter[0], "first-vtc".into(), None, now);
        assert!(row.enrolment_held);
        assert!(row.key[0].text.contains("asking your VTA to restore it"));
        assert!(!row.key[0].act, "nothing for the vetter to do yet");

        book.hidden_vetter[0].on_recover_refused(RecoverRefusal::NotFound, now);
        let row = hidden_row(&book.hidden_vetter[0], "first-vtc".into(), None, now);
        assert_eq!(row.key.len(), 1);
        assert!(row.key[0].act);
        assert!(
            row.key[0]
                .text
                .contains("ask an admin of first-vtc to reset your hidden-vetting key"),
            "{}",
            row.key[0].text
        );
        let words = get_tokens_words(&book, community, persona, "first-vtc", now);
        assert!(words.contains("reset your hidden-vetting key"), "{words}");
        assert!(!tokens_obtainable_now(&book, community, persona, now));
        let outlook = book.hidden_outlook(community, persona, now).unwrap();
        assert!(outlook_words(&outlook, now).contains("another hidden-vetting key"));

        // An admin reset it; last month's label is still live.
        let waiting = ResetState {
            reset_at: now,
            waiting_on: vec!["vetter/2026-10".into()],
            open: false,
        };
        book.hidden_vetter[0].on_binding_shown(&bound(Some(waiting)), now);
        let row = hidden_row(&book.hidden_vetter[0], "first-vtc".into(), None, now);
        assert!(row.enrolment_held);
        assert_eq!(row.key[1].label, "Reset");
        assert!(
            row.key[1]
                .text
                .contains("waiting for vetter/2026-10 to retire")
        );

        // The label retired: enrolment goes ahead with the current key.
        let open = ResetState {
            reset_at: now,
            waiting_on: Vec::new(),
            open: true,
        };
        book.hidden_vetter[0].on_binding_shown(&bound(Some(open)), now);
        let row = hidden_row(&book.hidden_vetter[0], "first-vtc".into(), None, now);
        assert!(!row.enrolment_held);
        assert_eq!(row.key[0].label, "Reset");
        assert!(row.key[0].text.starts_with("open — enrolling now"));
        assert!(tokens_obtainable_now(&book, community, persona, now));
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
                .map(|s| s.text)
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
}
