//! The vetter desk: opening sessions, attesting, declining and withdrawing,
//! and keeping the vetter side current with its communities.
//!
//! Each desk action is planned here (`plan_*`), purely, on the state and the
//! book; what it still owes the loop is the [`VettingEffect`] it returns. The
//! vetter side's refresh asks each community how it vets and which key it
//! bound us to as planned effects too, then runs the hidden-vetting schedule
//! (`hidden_vetting_tick`, `start_pcs_work`), which works on the loop.

use crate::state_handler::main_page::status::Status;
use chrono::{DateTime, Utc};
use openvtc_core::config::Config;
use openvtc_core::config::account::PersonaId;
use openvtc_core::vetting::book::RequestVetting;
use openvtc_core::vetting::mode::{ModeFailure, VetterMode};
use openvtc_core::vetting::queries::{CommunityQuery, QueryKind};
use openvtc_core::vetting::vetter::{Attestation, DeskEntry, DeskState};
use openvtc_core::vetting::wire;
use vta_sdk::protocols::vetting::decline::v0_1::PayloadCode;
use vta_sdk::protocols::vetting::{
    VETTING_DECLINE_TYPE, VETTING_REVOKE_STATEMENT_TYPE, VETTING_SESSION_TYPE, VettingMethod,
    documentation,
};
use vta_sdk::vetting::statement::{StatementDraft, sign_statement};

use super::dispatch::{panel, persist, show};
use super::effect::{Abort, Followup, Step, Undo, VettingEffect, run};
use super::hidden::hidden_vetting_tick;
use super::jobs::Sent;
use super::pcs::start_pcs_work;
use super::send::{Claim, abandon, claimable, give_up, persona_did, resolver, spawn_send};
use super::tickets::{ticket_sent, ticket_unsent};
use super::words::{community_display, hidden_without_id_words, hides_vetters};
use crate::state_handler::main_page::content::{
    AttestForm, DECLINE_MESSAGE_MAX, PendingTicket, VETTING_METHODS, VETTING_RELATIONSHIPS,
    VETTING_WITHDRAWAL_REASONS, VettingMode, VettingTab,
};
use crate::state_handler::main_page::menu::MainMenu;
use crate::state_handler::runtime_actions::ActionCtx;
use crate::state_handler::state::State;

// ============================================================================
// Opening a session
// ============================================================================

/// Enter on the open-session form: ask the community what it requires first
/// when that is unknown and not yet asked; otherwise open the session, sign
/// it, keep the signed document in the desk, save, and send it.
pub(super) fn plan_open_session(
    state: &mut State,
    config: &mut Config,
    busy: bool,
    request_id: &str,
    method_index: usize,
) -> VettingEffect {
    let Some(entry) = config.private.vetting.desk_entry(request_id).cloned() else {
        return VettingEffect::none();
    };
    let Some(vetter_did) = persona_did(config, entry.persona) else {
        show(
            state,
            Status::error("The persona this request was made to is not available."),
        );
        return VettingEffect::none();
    };
    let (required, known) = config.private.vetting.required_claims_for(
        &entry.community,
        entry
            .request
            .requirements_digest
            .as_ref()
            .map(|d| d.as_str()),
    );
    let asked = panel(state)
        .requirements_requested
        .contains(&entry.community);
    if !known && !asked {
        // Every vetter of one application must ask for the same claims, or the
        // cards commit to different identities. Ask the community first.
        if !claimable(state, busy) {
            return VettingEffect::none();
        }
        panel(state)
            .requirements_requested
            .push(entry.community.clone());
        // Marked asked only while the question can still go: a failure before
        // it does un-marks it, so the next Enter asks again rather than opening
        // the session without the requirements.
        let abort = Abort::undoing(
            "Could not ask the community",
            vec![Undo::NotRequested(entry.community.clone())],
        );
        let protocol = config.private.vetting.protocol_for(&entry.community);
        let document = match wire::manifest_request(&vetter_did, &entry.community, protocol) {
            Ok(d) => d,
            Err(e) => {
                abort.apply(state, config, e);
                return VettingEffect::none();
            }
        };
        show(
            state,
            Status::progress(
                "Asking the community which claims it requires — open the session again in a moment.",
            ),
        );
        let sent = Sent::Manifest {
            community: entry.community.clone(),
        };
        return VettingEffect::sign_and_send([], entry.persona, document, sent, Claim::Held, abort);
    }
    if !claimable(state, busy) {
        return VettingEffect::none();
    }
    const OPEN: &str = "Could not open the session";
    let session_id = wire::new_id();
    let method: VettingMethod = VETTING_METHODS[method_index.min(VETTING_METHODS.len() - 1)];
    let previous = DeskSnapshot(Box::new(entry.state.clone()));
    let body = match config.private.vetting.open_session(
        request_id,
        method,
        required,
        vec![],
        &session_id,
        Utc::now(),
    ) {
        Ok(body) => body,
        Err(e) => {
            give_up(state, config, OPEN, e);
            return VettingEffect::none();
        }
    };
    // From here the book holds the session: a failure before it goes out puts
    // the request back where it stood.
    let restore = vec![Undo::RestoreDesk {
        request_id: request_id.to_string(),
        previous: previous.clone(),
    }];
    let document = match wire::document(
        VETTING_SESSION_TYPE,
        &vetter_did,
        &entry.applicant,
        session_id,
        &body,
    ) {
        Ok(d) => d,
        Err(e) => {
            Abort::undoing(OPEN, restore).apply(state, config, e);
            return VettingEffect::none();
        }
    };
    // Signed, then kept in the desk exactly as it goes out, before the save:
    // the Vetting Statement that closes this session cites it by
    // `taskDigestMultibase`, which `vetted/1` requires.
    VettingEffect(vec![
        Step::Sign {
            persona: entry.persona,
            document: Box::new(document),
            abort: Abort::undoing(SEND_SESSION, restore.clone()),
        },
        Step::KeepSession {
            request_id: request_id.to_string(),
            abort: Abort::undoing(SEND_SESSION, restore),
        },
        Step::Then(Followup::SessionKept {
            request_id: request_id.to_string(),
            known,
            previous,
        }),
    ])
}

/// How a session that could not be signed, kept or sent is given up.
pub(super) const SEND_SESSION: &str = "Could not send the session";

/// Keep `document`, signed, as `request_id`'s session document
/// ([`Step::KeepSession`]).
pub(super) fn keep_session(
    config: &mut Config,
    request_id: &str,
    document: &wire::Document,
) -> Result<(), String> {
    serde_json::to_value(document)
        .map_err(|e| e.to_string())
        .and_then(|value| {
            config
                .private
                .vetting
                .record_session_document(request_id, value)
                .map_err(|e| e.to_string())
        })
}

/// The session's signed document is kept: close the form, then save saying
/// the match code, and send the document [`Step::Sign`] signed. A send that
/// cannot start puts the request back to `previous`, and the pending save
/// writes it so.
pub(super) fn plan_session_kept(
    state: &mut State,
    config: &Config,
    request_id: &str,
    known: bool,
    previous: DeskSnapshot,
) -> VettingEffect {
    let code = config
        .private
        .vetting
        .desk_entry(request_id)
        .and_then(|e| e.match_code().map(str::to_string))
        .unwrap_or_default();
    panel(state).mode = VettingMode::List;
    VettingEffect(vec![
        Step::Persist(format!(
            "Session open. Read the match code {code} to each other{}.",
            if known {
                ""
            } else {
                " — the community's requirements are still unknown, so this asks for a legal name only"
            }
        )),
        Step::Send {
            sent: Box::new(Sent::Session {
                request_id: request_id.to_string(),
            }),
            claim: Claim::Held,
            abort: Abort::undoing(
                SEND_SESSION,
                vec![Undo::RestoreDesk {
                    request_id: request_id.to_string(),
                    previous,
                }],
            ),
        },
    ])
}

// ============================================================================
// The vetter side
// ============================================================================

/// Keep this account's vetter side current with the communities it vets for: read each one's
/// requirements again, and run whatever its hidden-vetting schedule owes — enrolment the first
/// time, the ticks of the token drip after.
///
/// A community that turns on PCS ZKP vetting says so only in its manifest, and a month's new
/// labels are published there too, so this re-reads it every time. Run by the schedule
/// (`hidden_vetting_poll`) at each tick window and at least hourly, and by `m` / `d` by hand.
///
/// The questions are planned effects; the schedule's ticks and the PCS job they gather work on
/// the loop, so this stays a loop-side helper.
pub(crate) async fn refresh_vetter_side(ctx: &mut ActionCtx<'_>) {
    // A vetter has no application, so nothing else would ever fetch the manifest of a
    // community it vets for — and the manifest is where a community says it hides its
    // vetters, and which labels are live this month.
    let effect = plan_vetter_communities(ctx.config, false);
    run(ctx, effect).await;
    // And whatever each community's vetter schedule owes us — enrolment or the ticks of the
    // drip. On a schedule, never in response to a balance (design §5.1).
    let communities = vetter_schedule_communities(ctx.config);
    // Where the community refused us as another key, ask it which key it bound us to — or, while
    // an admin's reset is awaited, how that reset stands.
    let effect = plan_ask_bindings(ctx.config, Utc::now());
    run(ctx, effect).await;
    let mut work = Vec::new();
    for community in communities {
        hidden_vetting_tick(ctx, &community, &mut work);
    }
    // One job for the whole pass. Busy with another: the sweep runs the schedule again shortly,
    // and what is owed is planned afresh then.
    if !work.is_empty() && !start_pcs_work(ctx, work) {
        ctx.config.private.vetting.vetter_refresh_due = true;
    }
}

/// The communities whose hidden-vetting schedule a refresh runs.
///
/// Over the communities that publish the mode as well as those we already hold an engine
/// for: the first pass through has no engine yet, and `hidden_vetting_tick` is what makes one.
/// Not a community that has switched to named vetting: the engine is kept — a credential
/// does not become worthless because the advertisement moved — but drawing tokens it no
/// longer counts would only collect refusals.
fn vetter_schedule_communities(config: &Config) -> Vec<String> {
    let book = &config.private.vetting;
    let mut communities: Vec<String> = book
        .hidden_vetter
        .iter()
        .map(|h| h.community.clone())
        .collect();
    for community in book.hidden_published.keys() {
        if !communities.contains(community) {
            communities.push(community.clone());
        }
    }
    communities.retain(|c| book.vetter_mode(c).mode() != Some(VetterMode::Named));
    communities
}

/// Ask each community that refused our enrolment as another key which key it bound us to
/// (`vtc/vetting/vetters/pcs-binding/show`), where the engine's key check wants it read
/// ([`HiddenVetterState::binding_read_due`](openvtc_core::vetting::book::HiddenVetterState::binding_read_due)): once to start the check, then at most every
/// [`BINDING_REASK`](openvtc_core::vetting::binding::BINDING_REASK) while a reset is awaited, and
/// never while a question is open or the community's silence is being backed off (R1.4).
///
/// Each question is a [`Followup::AskBinding`], planned in turn after the one before it went.
fn plan_ask_bindings(config: &mut Config, now: DateTime<Utc>) -> VettingEffect {
    let mut steps = Vec::new();
    // A record kept before this client could recover a key: its last word from the community
    // is `identifierRebound` and no check is running. Start one rather than wait for the next
    // enrolment to collect the same refusal.
    let mut rechecked = false;
    for held in &mut config.private.vetting.hidden_vetter {
        if held.key.is_none() && held.recheck_key(now) {
            rechecked = true;
        }
    }
    if rechecked {
        steps.push(Step::MarkDirty);
    }
    let book = &config.private.vetting;
    steps.extend(
        book.hidden_vetter
            .iter()
            .filter(|h| h.binding_read_due(now))
            .filter(|h| h.retry_at.is_none_or(|t| t <= now))
            .filter(|h| {
                book.waiting_on(&h.community, QueryKind::PcsBinding)
                    .is_none()
            })
            .map(|h| {
                Step::Then(Followup::AskBinding {
                    community: h.community.clone(),
                    persona: h.persona,
                    now,
                })
            }),
    );
    VettingEffect(steps)
}

/// Ask `community` which key it bound `persona` to: mark the engine's check asked and file
/// the question, then send it as the client's own. A signing that fails un-files the question,
/// as a send that fails off the loop does, and is said; the check keeps the time it was asked,
/// so it is asked again only after [`BINDING_REASK`](openvtc_core::vetting::binding::BINDING_REASK).
pub(super) fn plan_ask_binding(
    config: &Config,
    community: &str,
    persona: PersonaId,
    now: DateTime<Utc>,
) -> VettingEffect {
    let Some(did) = persona_did(config, persona) else {
        return VettingEffect::none();
    };
    let document = match wire::pcs_binding_show_request(&did, community) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(community = %community, error = %e, "could not build the binding question");
            return VettingEffect::none();
        }
    };
    let document_id = document.id.clone();
    VettingEffect(vec![
        Step::Book(BookChange::BindingAsked(CommunityQuery {
            document_id: document_id.clone(),
            community: community.to_string(),
            persona,
            kind: QueryKind::PcsBinding,
            sent_at: now,
        })),
        Step::MarkDirty,
        Step::Ask {
            persona,
            document: Box::new(document),
            sent: Box::new(Sent::Query {
                document_id: document_id.clone(),
                community: community.to_string(),
                kind: QueryKind::PcsBinding,
            }),
            claim: Claim::Unheld,
            then: Asked::Binding {
                community: community.to_string(),
                document_id,
            },
        },
    ])
}

/// Read again how each community we vet for vets, where the last reading is stale — on opening
/// the desk, and while it stays open. Bounded: a community is asked at most once per
/// [`MODE_REASK_AFTER`](openvtc_core::vetting::mode::MODE_REASK_AFTER), answered or not (R1.4).
pub(crate) async fn refresh_stale_modes(ctx: &mut ActionCtx<'_>) {
    let effect = plan_vetter_communities(ctx.config, true);
    run(ctx, effect).await;
}

/// The vetting page's tab key: the next tab, on its list. Opening the desk
/// reads again how each community vets where the last reading is stale, so
/// the badges and the ticket gate are not shown from an old answer.
pub(super) fn plan_switch_tab(state: &mut State, config: &Config) -> VettingEffect {
    let v = panel(state);
    v.tab = v.tab.next();
    v.selected = 0;
    v.mode = VettingMode::List;
    v.status_message = None;
    if v.tab == VettingTab::Desk {
        plan_vetter_communities(config, true)
    } else {
        VettingEffect::none()
    }
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
/// manifest and nowhere else. The answer is what [`ensure_hidden_vetter`](crate::state_handler::vetting_actions::hidden::ensure_hidden_vetter) acts on.
///
/// Including the communities we already hold an engine for: the manifest is where a new month's
/// labels appear, and an engine that never re-read it never moved past the month it enrolled
/// in. What changes there reaches the engine as the answer lands
/// ([`VettingBook::learn_mode`](openvtc_core::vetting::VettingBook::learn_mode) → [`HiddenVetterState::take_reading`](openvtc_core::vetting::book::HiddenVetterState::take_reading)), keeping the keys we
/// enrolled under.
///
/// `only_stale` asks only where how the community vets is older than
/// [`MODE_TTL`](openvtc_core::vetting::mode::MODE_TTL) and was not asked lately
/// ([`VettingBook::mode_refresh_due`](openvtc_core::vetting::VettingBook::mode_refresh_due)) — what opening the desk, and keeping it open, need.
///
/// Each community is a [`Followup::AskManifest`], planned only once the one before it was
/// asked: whether that ask went is what decides whether a second persona asks again.
fn plan_vetter_communities(config: &Config, only_stale: bool) -> VettingEffect {
    let book = &config.private.vetting;
    let now = Utc::now();
    VettingEffect(
        book.vetter_standing(now)
            .into_iter()
            .filter(|s| s.live)
            .filter(|s| !only_stale || book.mode_refresh_due(&s.community, now))
            // Not again within seconds of the last ask or answer: `d` pressed three times, or a
            // pass chained on an answer, would fetch the same manifest each time (R1.4). Unless
            // a draw was refused as over the community's rate since: that read is owed now, once.
            .filter(|s| {
                !book.manifest_recently_asked(&s.community, now)
                    || book.params_reread_owed(&s.community)
            })
            .map(|s| {
                Step::Then(Followup::AskManifest {
                    community: s.community,
                    persona: s.persona,
                })
            })
            .collect(),
    )
}

/// Ask `community` for its manifest as `persona`, as the client's own send, unless it was
/// asked moments ago.
pub(super) fn plan_ask_manifest(
    config: &Config,
    community: &str,
    persona: PersonaId,
) -> VettingEffect {
    // A community we vet for as two personas is one manifest, asked once.
    let book = &config.private.vetting;
    if book.manifest_recently_asked(community, Utc::now()) && !book.params_reread_owed(community) {
        return VettingEffect::none();
    }
    let Some(did) = persona_did(config, persona) else {
        return VettingEffect::none();
    };
    let protocol = book.protocol_for(community);
    let Ok(document) = wire::manifest_request(&did, community, protocol) else {
        return VettingEffect::none();
    };
    let now = Utc::now();
    VettingEffect(vec![
        Step::Book(BookChange::ModeAsked {
            community: community.to_string(),
            now,
        }),
        Step::Ask {
            persona,
            document: Box::new(document),
            sent: Box::new(Sent::Manifest {
                community: community.to_string(),
            }),
            claim: Claim::Unheld,
            then: Asked::Manifest {
                community: community.to_string(),
                now,
            },
        },
    ])
}

/// A book change made at its place among the sends of a run ([`Step::Book`]),
/// because a send before it decides what it finds.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum BookChange {
    /// We are asking `community` for its manifest at `now`.
    ModeAsked {
        community: String,
        now: DateTime<Utc>,
    },
    /// We are asking the question's community which key it bound the
    /// question's persona to: its engine's check is marked asked, and the
    /// question filed.
    BindingAsked(CommunityQuery),
}

impl BookChange {
    pub(super) fn apply(self, config: &mut Config) {
        let book = &mut config.private.vetting;
        match self {
            BookChange::ModeAsked { community, now } => book.mode_asked(&community, now),
            BookChange::BindingAsked(query) => {
                if let Some(held) = book.hidden_vetter_mut(&query.community, query.persona) {
                    held.binding_asked(query.sent_at);
                }
                book.ask(query);
            }
        }
    }
}

/// What a [`Step::Ask`] does once its send went, or once it could not be
/// signed or handed off.
#[derive(Clone, Debug)]
pub(super) enum Asked {
    /// The client's own manifest question to `community`, asked at `now`:
    /// a send that went resets the count of failed ones; one that did not is
    /// recorded against the community, and asked again on the sweep a bounded
    /// number of times.
    Manifest {
        community: String,
        now: DateTime<Utc>,
    },
    /// The client's own binding question `document_id` to `community`: a
    /// failure un-files it, and is said and logged.
    Binding {
        community: String,
        document_id: String,
    },
    /// A ticket's question about how its community vets: it waits on the
    /// answer, or is refused as unconfirmed.
    Ticket(PendingTicket),
}

impl Asked {
    /// The send went.
    pub(super) fn went(self, state: &mut State, config: &mut Config) {
        match self {
            Asked::Manifest { .. } => config.private.vetting.vetter_refresh_failures = 0,
            Asked::Binding { .. } => {}
            Asked::Ticket(pending) => ticket_sent(state, pending),
        }
    }

    /// The send could not be signed or handed off, with `error`.
    pub(super) fn failed(self, state: &mut State, config: &mut Config, error: String) {
        match self {
            Asked::Manifest { community, now } => {
                tracing::warn!(community = %community, error = %error, "could not ask a community what it requires");
                config.private.vetting.mode_failed(
                    &community,
                    ModeFailure::Unsent(error.clone()),
                    now,
                );
                // Usually the listener is not up yet (start-up). Ask again on
                // the five-second sweep, a bounded number of times.
                let book = &mut config.private.vetting;
                if book.vetter_refresh_failures
                    < openvtc_core::vetting::book::VETTER_REFRESH_RETRIES
                {
                    book.vetter_refresh_failures += 1;
                    book.vetter_refresh_due = true;
                }
            }
            Asked::Binding {
                community,
                document_id,
            } => {
                config.private.vetting.forget_query(&document_id);
                let message = format!(
                    "Could not ask {} which hidden-vetting key it holds for you: {error}",
                    community_display(config, &community)
                );
                tracing::warn!(community = %community, "{message}");
                state.main_page.log(message.clone());
                show(state, Status::error(message));
            }
            Asked::Ticket(pending) => ticket_unsent(state, config, pending, error),
        }
    }
}

/// The session id a desk entry is at, if it has one.
pub(super) fn session_id_of(entry: &DeskEntry) -> Option<String> {
    match &entry.state {
        DeskState::Session { session, .. } | DeskState::CardReceived { session, .. } => {
            Some(session.id.clone())
        }
        _ => None,
    }
}

// ============================================================================
// Attesting
// ============================================================================

/// What attesting comes to.
pub(super) enum Attesting {
    /// A named statement to sign and send, or nothing more (refused, or said
    /// why not).
    Effect(VettingEffect),
    /// A proof: the hidden-vetting attestation (`attest_hidden`).
    Hidden(Box<HiddenAttest>),
    /// The request asks for a proof and this vetter is not enrolled: the
    /// vetter side is refreshed, which enrols it.
    Enrol,
}

/// What `attest_hidden` takes.
pub(super) struct HiddenAttest {
    pub(super) request_id: String,
    pub(super) entry: DeskEntry,
    pub(super) vetter_did: String,
    pub(super) attestation: Attestation,
    pub(super) now: DateTime<Utc>,
}

/// A named Vetting Statement drafted for a request, to sign, record and send
/// ([`Step::Statement`]).
pub(super) struct NamedStatement {
    pub(super) request_id: String,
    pub(super) entry: DeskEntry,
    pub(super) vetter_did: String,
    pub(super) session_id: String,
    pub(super) draft: StatementDraft,
    pub(super) now: DateTime<Utc>,
}

/// Enter on the attest form: attest as a proof where the request asks for one
/// and this vetter is enrolled, enrol first where it is not, and otherwise
/// draft the named statement to sign.
pub(super) fn plan_attest(
    state: &mut State,
    config: &Config,
    busy: bool,
    request_id: &str,
    form: &AttestForm,
) -> Attesting {
    let said = |state: &mut State, message: Status| {
        show(state, message);
        Attesting::Effect(VettingEffect::none())
    };
    if !form.attested {
        return said(
            state,
            Status::warning(
                "Tick the attestation (the last line) — signing is attributable to you in this community.",
            ),
        );
    }
    let now = Utc::now();
    let Some(entry) = config.private.vetting.desk_entry(request_id).cloned() else {
        return Attesting::Effect(VettingEffect::none());
    };
    let DeskState::CardReceived { session, .. } = &entry.state else {
        return said(
            state,
            Status::warning("You can attest once their card has arrived."),
        );
    };
    let session_id = session.id.clone();
    let claims_verified = session.required_claims.clone();
    let Some(vetter_did) = persona_did(config, entry.persona) else {
        return said(
            state,
            Status::error("The persona this request was made to is not available."),
        );
    };
    let method = VETTING_METHODS[form.method_index.min(VETTING_METHODS.len() - 1)];
    let documentation_choice = panel(state)
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
        claims_verified,
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
    let book = &config.private.vetting;
    let hidden_request = match book.request_vetting(request_id) {
        RequestVetting::Hidden => hides_vetters(book, &entry.community),
        RequestVetting::Named { .. } => false,
        RequestVetting::HiddenWithoutId { criterion } => {
            return said(state, Status::warning(hidden_without_id_words(&criterion)));
        }
        RequestVetting::Unreadable(e) => {
            return said(state, Status::error(format!("Cannot attest: {e}")));
        }
    };
    if hidden_request
        && book
            .hidden_vetter(&entry.community, entry.persona)
            .is_some()
    {
        return Attesting::Hidden(Box::new(HiddenAttest {
            request_id: request_id.to_string(),
            entry,
            vetter_did,
            attestation,
            now,
        }));
    }
    // The request asks for a proof but this vetter is not enrolled yet:
    // signing now would make a named statement — one the applicant's
    // hidden-vetting application cannot use, carrying this vetter's DID to a
    // community that promised not to need it. Enrol first.
    if hidden_request {
        panel(state).mode = VettingMode::List;
        show(
            state,
            Status::warning(
                "This community proves vetting with a PCS zero-knowledge proof, and you are not \
             enrolled for it yet, so nothing was signed. Enrolling now — attest again in a \
             moment.",
            ),
        );
        return Attesting::Enrol;
    }

    let draft = match book.statement_draft(request_id, &vetter_did, attestation, now) {
        Ok(draft) => draft,
        Err(e) => return said(state, Status::error(format!("Cannot attest yet: {e}"))),
    };
    if !claimable(state, busy) {
        return Attesting::Effect(VettingEffect::none());
    }
    Attesting::Effect(VettingEffect(vec![Step::Statement(Box::new(
        NamedStatement {
            request_id: request_id.to_string(),
            entry,
            vetter_did,
            session_id,
            draft,
            now,
        },
    ))]))
}

/// Sign the drafted statement with the persona's assertion key, record it
/// (verified first, so what is kept is what the applicant receives), wrap it
/// in a delivery signed with the authentication key, save, and send it,
/// claiming the vetting domain. A failure before the send gives up, putting
/// the request back where a recorded statement had moved it.
pub(super) async fn deliver_statement(ctx: &mut ActionCtx<'_>, statement: NamedStatement) {
    let NamedStatement {
        request_id,
        entry,
        vetter_did,
        session_id,
        draft,
        now,
    } = statement;
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
        .record_statement(&request_id, &statement, &resolver, now)
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
        &session_id,
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
            if let Some(e2) = ctx.config.private.vetting.desk_entry_mut(&request_id) {
                e2.state = entry.state.clone();
            }
            return abandon(ctx, "Could not send the statement", e);
        }
    };
    panel(ctx.state).mode = VettingMode::List;
    persist(ctx, "Sending your statement…");
    let sent = Sent::Statement {
        request_id,
        statement_id: issued.id,
        previous: entry.state.clone(),
    };
    spawn_send(
        ctx,
        message,
        &vetter_did,
        &entry.applicant,
        sent,
        Claim::Held,
    );
}

// ============================================================================
// Declining and withdrawing
// ============================================================================

/// Enter on the decline form: refuse a note longer than a decline carries,
/// else decline with the reason and note the vetter chose.
pub(super) fn plan_decline_submit(
    state: &mut State,
    config: &mut Config,
    busy: bool,
    request_id: &str,
    code: Option<PayloadCode>,
    message: &str,
) -> VettingEffect {
    let message = message.trim();
    if message.chars().count() > DECLINE_MESSAGE_MAX {
        show(
            state,
            Status::warning(format!(
                "The note is {} characters; a decline carries at most \
                 {DECLINE_MESSAGE_MAX}.",
                message.chars().count()
            )),
        );
        return VettingEffect::none();
    }
    let message = (!message.is_empty()).then(|| message.to_string());
    plan_decline(state, config, busy, request_id, code, message)
}

/// Decline a desk request, with the reason and note the vetter chose — both
/// optional, and sent to the applicant only, never the community.
pub(super) fn plan_decline(
    state: &mut State,
    config: &mut Config,
    busy: bool,
    request_id: &str,
    code: Option<PayloadCode>,
    message: Option<String>,
) -> VettingEffect {
    let Some(entry) = config.private.vetting.desk_entry(request_id).cloned() else {
        return VettingEffect::none();
    };
    let Some(vetter_did) = persona_did(config, entry.persona) else {
        show(
            state,
            Status::error("The persona this request was made to is not available."),
        );
        return VettingEffect::none();
    };
    if !claimable(state, busy) {
        return VettingEffect::none();
    }
    const WHAT: &str = "Could not decline";
    let body = match config
        .private
        .vetting
        .decline(request_id, code, message, Utc::now())
    {
        Ok(body) => body,
        Err(e) => {
            give_up(state, config, WHAT, e);
            return VettingEffect::none();
        }
    };
    // From here the book holds the request declined: a failure before the
    // decline goes out puts it back where it stood.
    let restore = vec![Undo::RestoreDesk {
        request_id: request_id.to_string(),
        previous: DeskSnapshot(Box::new(entry.state.clone())),
    }];
    let document = match wire::document(
        VETTING_DECLINE_TYPE,
        &vetter_did,
        &entry.applicant,
        wire::new_id(),
        &body,
    ) {
        Ok(d) => d,
        Err(e) => {
            Abort::undoing(WHAT, restore).apply(state, config, e);
            return VettingEffect::none();
        }
    };
    panel(state).mode = VettingMode::List;
    let sent = Sent::Decline {
        request_id: request_id.to_string(),
        previous: entry.state.clone(),
    };
    VettingEffect::sign_and_send(
        [Step::Persist("Declining…".to_string())],
        entry.persona,
        document,
        sent,
        Claim::Held,
        Abort::undoing("Could not send the decline", restore),
    )
}

/// Tell the community a statement is withdrawn, for the reason chosen.
pub(super) fn plan_withdraw(
    state: &mut State,
    config: &mut Config,
    busy: bool,
    statement_id: &str,
    reason_index: usize,
) -> VettingEffect {
    let Some(issued) = config
        .private
        .vetting
        .issued
        .iter()
        .find(|s| s.id == statement_id)
        .cloned()
    else {
        return VettingEffect::none();
    };
    let Some(vetter_did) = persona_did(config, issued.persona) else {
        show(
            state,
            Status::error("The persona that signed this statement is not available."),
        );
        return VettingEffect::none();
    };
    if !claimable(state, busy) {
        return VettingEffect::none();
    }
    const WHAT: &str = "Could not withdraw";
    let document_id = wire::new_id();
    let reason = VETTING_WITHDRAWAL_REASONS[reason_index.min(VETTING_WITHDRAWAL_REASONS.len() - 1)];
    let body = match config.private.vetting.withdrawal(
        statement_id,
        Some(reason),
        &document_id,
        Utc::now(),
    ) {
        Ok((body, _)) => body,
        Err(e) => {
            give_up(state, config, WHAT, e);
            return VettingEffect::none();
        }
    };
    // From here the book holds the withdrawal as sent: a failure before it
    // goes out clears it.
    let unwithdraw = vec![Undo::NotWithdrawn(statement_id.to_string())];
    let document = match wire::document(
        VETTING_REVOKE_STATEMENT_TYPE,
        &vetter_did,
        &issued.community,
        document_id,
        &body,
    ) {
        Ok(d) => d,
        Err(e) => {
            Abort::undoing(WHAT, unwithdraw).apply(state, config, e);
            return VettingEffect::none();
        }
    };
    panel(state).mode = VettingMode::List;
    let sent = Sent::Withdrawal {
        statement_id: statement_id.to_string(),
    };
    VettingEffect::sign_and_send(
        [Step::Persist("Telling the community…".to_string())],
        issued.persona,
        document,
        sent,
        Claim::Held,
        Abort::undoing("Could not send the withdrawal", unwithdraw),
    )
}

/// Where a desk request stood, for [`Undo::RestoreDesk`]. Compared by its
/// serialised form: the desk state carries generated wire types that derive
/// no `PartialEq`.
#[derive(Clone, Debug)]
pub(super) struct DeskSnapshot(pub(super) Box<DeskState>);

impl PartialEq for DeskSnapshot {
    fn eq(&self, other: &Self) -> bool {
        serde_json::to_value(&self.0).ok() == serde_json::to_value(&other.0).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::dispatch_util::test_config;
    use crate::state_handler::main_page::status::Severity;
    use openvtc_core::vetting::book::VetterGrant;

    const VTC: &str = "did:web:vtc.example";

    /// A persona the config holds an identity for — enough for a plan, which
    /// never looks up keys.
    fn persona(config: &mut Config) -> PersonaId {
        let persona = PersonaId::new();
        let did = format!("did:key:z{}", persona);
        let document =
            serde_json::from_value(serde_json::json!({ "id": did })).expect("a DID document");
        config.identities.insert(
            persona,
            openvtc_core::identity::IdentityContext {
                persona_id: persona,
                did: did.clone(),
                document,
                profile: std::sync::Arc::new(affinidi_tdk::messaging::profiles::ATMProfile {
                    inner: std::sync::Arc::new(
                        affinidi_tdk::messaging::profiles::ATMProfileInner {
                            did: did.clone(),
                            alias: did,
                            mediator: std::sync::Arc::new(None),
                        },
                    ),
                }),
                mediator_did: None,
            },
        );
        persona
    }

    fn grant(config: &mut Config, persona: PersonaId) {
        let now = Utc::now();
        config.private.vetting.vetter_grants.push(VetterGrant {
            community: VTC.into(),
            persona,
            credential_id: None,
            valid_until: Some(now + chrono::Duration::days(30)),
            received_at: now,
            credential: serde_json::json!({}),
        });
    }

    fn desk_entry(config: &mut Config, persona: PersonaId) -> String {
        use vta_sdk::protocols::vetting::request;
        let body = request::v0_1::Payload::try_from(
            request::v0_1::Payload::builder()
                .community(VTC)
                .join_did("did:key:zApplicant"),
        )
        .expect("a request");
        let now = Utc::now();
        let request_id = "r1".to_string();
        config.private.vetting.desk.push(DeskEntry {
            request_id: request_id.clone(),
            request_document_id: "d1".into(),
            applicant: "did:key:zApplicant".into(),
            community: VTC.into(),
            persona,
            ticket_id: None,
            request: body,
            state: DeskState::Accepted,
            received_at: now,
            updated_at: now,
        });
        request_id
    }

    /// Each stale community is a follow-up planned in turn, so a second
    /// persona sees whether the first one's question went.
    #[test]
    fn opening_the_desk_plans_a_question_per_community_in_turn() {
        let mut config = test_config();
        let mut state = State::default();
        let first = persona(&mut config);
        let second = persona(&mut config);
        grant(&mut config, first);
        grant(&mut config, second);

        let effect = plan_switch_tab(&mut state, &config);

        assert_eq!(panel(&mut state).tab, VettingTab::Desk);
        assert_eq!(effect.0.len(), 2);
        assert!(effect.0.iter().all(|s| matches!(
            s,
            Step::Then(Followup::AskManifest { community, .. }) if community == VTC
        )));
        // Nothing is marked asked until the follow-up runs.
        assert!(
            !config
                .private
                .vetting
                .manifest_recently_asked(VTC, Utc::now())
        );
    }

    /// A community asked moments ago is not asked again; otherwise the ask is
    /// recorded before the send, in order.
    #[test]
    fn a_manifest_question_is_recorded_then_asked_unless_just_asked() {
        let mut config = test_config();
        let persona = persona(&mut config);

        let effect = plan_ask_manifest(&config, VTC, persona);
        let [Step::Book(change), Step::Ask { claim, then, .. }] = effect.0.as_slice() else {
            panic!("record, then ask");
        };
        assert!(matches!(claim, Claim::Unheld));
        assert!(matches!(then, Asked::Manifest { community, .. } if community == VTC));
        change.clone().apply(&mut config);

        assert!(plan_ask_manifest(&config, VTC, persona).0.is_empty());
    }

    /// A binding question starts the key check, marks dirty once, and plans
    /// the question as a follow-up.
    #[test]
    fn a_rebound_engine_plans_its_binding_question() {
        use openvtc_core::vetting::book::{HiddenRefusal, HiddenVetterState};
        let mut config = test_config();
        let persona = persona(&mut config);
        let (book, _) =
            crate::state_handler::vetting_actions::test_support::hidden_vetter_book(0, false);
        let mut held: HiddenVetterState = book.hidden_vetter[0].clone();
        held.persona = persona;
        held.last_refusal = Some(HiddenRefusal {
            what: "credential".into(),
            code: "x:identifierRebound".into(),
            at: Utc::now(),
        });
        config.private.vetting.hidden_vetter.push(held);
        let now = Utc::now();

        let effect = plan_ask_bindings(&mut config, now);

        assert!(config.private.vetting.hidden_vetter[0].key.is_some());
        let [
            Step::MarkDirty,
            Step::Then(Followup::AskBinding { persona: p, .. }),
        ] = effect.0.as_slice()
        else {
            panic!("marked dirty, then the question");
        };
        assert_eq!(*p, persona);
        let community = config.private.vetting.hidden_vetter[0].community.clone();
        let asked = plan_ask_binding(&config, &community, persona, now);
        assert!(matches!(
            asked.0.as_slice(),
            [
                Step::Book(BookChange::BindingAsked(_)),
                Step::MarkDirty,
                Step::Ask { .. }
            ]
        ));
    }

    /// A session needing the requirements first asks for them and marks them
    /// asked; with them asked, the book opens the session and the plan signs,
    /// keeps, then follows up.
    #[test]
    fn a_session_asks_first_then_opens() {
        let mut config = test_config();
        let mut state = State::default();
        let persona = persona(&mut config);
        let id = desk_entry(&mut config, persona);

        let effect = plan_open_session(&mut state, &mut config, false, &id, 0);
        assert!(matches!(
            effect.0.as_slice(),
            [
                Step::Sign { .. },
                Step::Send {
                    claim: Claim::Held,
                    ..
                }
            ]
        ));
        assert_eq!(
            panel(&mut state).requirements_requested,
            vec![VTC.to_string()]
        );
        assert!(matches!(
            config.private.vetting.desk_entry(&id).unwrap().state,
            DeskState::Accepted
        ));
        // A question that cannot go un-marks it as asked.
        let Step::Send { abort, .. } = &effect.0[1] else {
            panic!("the send");
        };
        assert_eq!(
            abort,
            &Abort::undoing(
                "Could not ask the community",
                vec![Undo::NotRequested(VTC.into())],
            )
        );
        abort.clone().apply(&mut state, &mut config, "no keys");
        assert!(panel(&mut state).requirements_requested.is_empty());
        panel(&mut state).requirements_requested.push(VTC.into());

        let effect = plan_open_session(&mut state, &mut config, false, &id, 0);
        let [
            Step::Sign { abort, .. },
            Step::KeepSession { abort: kept, .. },
            Step::Then(Followup::SessionKept {
                known: false,
                previous,
                ..
            }),
        ] = effect.0.as_slice()
        else {
            panic!("sign, keep, then follow up");
        };
        assert!(matches!(
            config.private.vetting.desk_entry(&id).unwrap().state,
            DeskState::Session { .. }
        ));
        // A session that cannot be signed, kept or sent puts the request back.
        let restore = Abort::undoing(
            SEND_SESSION,
            vec![Undo::RestoreDesk {
                request_id: id.clone(),
                previous: DeskSnapshot(Box::new(DeskState::Accepted)),
            }],
        );
        assert_eq!(abort, &restore);
        assert_eq!(kept, &restore);
        assert_eq!(previous, &DeskSnapshot(Box::new(DeskState::Accepted)));
        restore.apply(&mut state, &mut config, "no keys");
        assert!(matches!(
            config.private.vetting.desk_entry(&id).unwrap().state,
            DeskState::Accepted
        ));
    }

    /// Busy refuses before the book changes.
    #[test]
    fn a_busy_desk_changes_nothing() {
        let mut config = test_config();
        let mut state = State::default();
        let persona = persona(&mut config);
        let id = desk_entry(&mut config, persona);
        panel(&mut state).requirements_requested.push(VTC.into());

        assert!(
            plan_open_session(&mut state, &mut config, true, &id, 0)
                .0
                .is_empty()
        );
        assert!(
            plan_decline(&mut state, &mut config, true, &id, None, None)
                .0
                .is_empty()
        );
        assert!(matches!(
            config.private.vetting.desk_entry(&id).unwrap().state,
            DeskState::Accepted
        ));
        let said = panel(&mut state).status_message.clone().unwrap();
        assert_eq!(said.severity, Severity::Warning);
    }

    /// A decline records the request declined, closes the form, saves, and
    /// undoes to where the request stood.
    #[test]
    fn a_decline_saves_then_sends_and_undoes_to_where_it_stood() {
        let mut config = test_config();
        let mut state = State::default();
        let persona = persona(&mut config);
        let id = desk_entry(&mut config, persona);

        let effect = plan_decline(&mut state, &mut config, false, &id, None, None);

        assert!(matches!(
            config.private.vetting.desk_entry(&id).unwrap().state,
            DeskState::Declined { .. }
        ));
        assert!(matches!(panel(&mut state).mode, VettingMode::List));
        let [
            Step::Persist(said),
            Step::Sign { .. },
            Step::Send { abort, .. },
        ] = effect.0.as_slice()
        else {
            panic!("save, sign, send");
        };
        assert_eq!(said, "Declining…");
        assert_eq!(
            abort,
            &Abort::undoing(
                "Could not send the decline",
                vec![Undo::RestoreDesk {
                    request_id: id.clone(),
                    previous: DeskSnapshot(Box::new(DeskState::Accepted)),
                }],
            )
        );
        // The same undo a document that cannot be built applies: the request
        // stands where it stood.
        abort.clone().apply(&mut state, &mut config, "no keys");
        assert!(matches!(
            config.private.vetting.desk_entry(&id).unwrap().state,
            DeskState::Accepted
        ));
    }

    /// A decline note over the limit is refused before anything else.
    #[test]
    fn a_long_decline_note_is_refused_first() {
        let mut config = test_config();
        let mut state = State::default();
        let max = crate::state_handler::main_page::content::DECLINE_MESSAGE_MAX;
        let effect = plan_decline_submit(
            &mut state,
            &mut config,
            true,
            "gone",
            None,
            &"x".repeat(max + 1),
        );
        assert!(effect.0.is_empty());
        let said = panel(&mut state).status_message.clone().unwrap();
        assert_eq!(said.severity, Severity::Warning);
        assert!(said.text.starts_with("The note is "), "{}", said.text);
    }
}
