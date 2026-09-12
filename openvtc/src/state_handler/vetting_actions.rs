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
use chrono::Utc;
use openvtc_core::config::Config;
use openvtc_core::config::account::PersonaId;
use openvtc_core::config::community_context::{self, ContextKind, ContextOption};
use openvtc_core::config::context_path::parse_sub_context_id;
use openvtc_core::didcomm::Messaging;
use openvtc_core::persona::disclosure::{self, PresentError};
use openvtc_core::persona::{binding, profile};
use openvtc_core::vetting::VettingBook;
use openvtc_core::vetting::applicant::{
    Application, GrantStatus, NextStep, RequestDraft, RequestState, SentCard, VetterEligibility,
};
use openvtc_core::vetting::book::FALLBACK_REQUIRED_CLAIMS;
use openvtc_core::vetting::queries::{
    CommunityAnswer, CommunityQuery, QUERY_TIMEOUT, QueryKind, refusal_words,
};
use openvtc_core::vetting::registry::{
    EventDraft, ProfileDraft, ProfileState, VetterProfileRecord, listed_event_line,
    listed_location_line,
};
use openvtc_core::vetting::status::GrantCheck;
use openvtc_core::vetting::tickets::{DEFAULT_VALIDITY, Ticket, normalise_code};
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
    ApplicationRow, AttestForm, CardPreview, DIRECTORY_FIELDS, DIRECTORY_METHODS, DeskRow,
    DeskStage, DirectoryCommunity, DirectoryView, EVENT_FIELDS, EventForm, FaceChoice, IssuedRow,
    LineTone, ListedVetterRow, PROFILE_FIELDS, RequestRow, TicketRow, VETTING_METHODS,
    VETTING_RELATIONSHIPS, VETTING_TICKET_USES, VETTING_WITHDRAWAL_REASONS, VetterProfileForm,
    VettingMembership, VettingMode, VettingPersona, VettingState, VettingTab, method_label,
};
use crate::state_handler::main_page::menu::MainMenu;
use crate::state_handler::main_page::{sanitize_display, shorten_did};
use crate::state_handler::runtime_actions::ActionCtx;
use crate::state_handler::save_coalesce::SaveScheduler;
use crate::state_handler::state::State;

// ============================================================================
// Config → display
// ============================================================================

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

    // The directory is searched as a persona the community knows of: the
    // application's join DID first, else the membership's.
    let mut directory: Vec<DirectoryCommunity> = Vec::new();
    for app in &book.applications {
        if !directory.iter().any(|d| d.community == app.community) {
            directory.push(DirectoryCommunity {
                community: app.community.clone(),
                name: community_name(&app.community)
                    .unwrap_or_else(|| shorten_did(&app.community, 48)),
                accent: accent(&app.community),
                persona: app.persona,
                application_id: Some(app.id.clone()),
            });
        }
    }
    for m in config
        .account
        .memberships()
        .filter(|m| m.status.is_active())
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

    vetting.applications = book
        .applications
        .iter()
        .map(|app| {
            let required: Vec<String> = app
                .requirements
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
                });
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
                next_step: Some(next_step_words(&app.next_step(now))),
                join_did: app.join_did.clone(),
                requirements: app.requirements.as_ref().map(requirements_line),
                progress: evaluation.as_ref().map(progress_line),
                satisfied: evaluation.as_ref().is_some_and(Evaluation::satisfied),
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
                            RequestState::Declined { .. } => ("declined".to_string(), None, None),
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
                        }
                    })
                    .collect(),
            }
        })
        .collect();

    vetting.desk = book
        .desk
        .iter()
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
        })
        .collect();

    vetting.selected = vetting.selected.min(vetting.tab_len().saturating_sub(1));
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
        NextStep::Join => "join from Communities (j) — your statements go with the request",
        NextStep::ChooseFace => "f — choose the face vetters are shown, then ask a vetter",
        NextStep::AskVetter => "r — ask a vetter with their ticket, or v to find one",
        NextStep::WaitForVetters => "wait for your vetters — you are told when one answers",
    }
    .to_string()
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
        return "meets the published requirements — join from Communities".to_string();
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
        VettingAction::SwitchTab => {
            let v = page(ctx);
            v.tab = v.tab.next();
            v.selected = 0;
            v.mode = VettingMode::List;
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
            if let Some(row) = v.applications.get(v.selected).cloned() {
                list_faces(ctx, &row.id);
            }
        }
        VettingAction::RequestVetter => {
            let v = page(ctx);
            if let Some(row) = v.applications.get(v.selected).cloned() {
                v.mode = VettingMode::RequestVetter {
                    application_id: row.id,
                    vetter: String::new(),
                    code: String::new(),
                    ticket: None,
                    note: None,
                    field: 0,
                };
            }
        }
        VettingAction::RefreshRequirements => {
            let v = page(ctx);
            if let Some(row) = v.applications.get(v.selected).cloned() {
                refresh_requirements(ctx, &row.id).await;
            }
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
            if let Some(row) = v.tickets.get(v.selected).cloned() {
                ctx.config
                    .private
                    .vetting
                    .tickets
                    .retain(|t| t.id != row.id);
                persist(
                    ctx,
                    format!("Ticket {} deleted — it admits nothing now.", row.code),
                );
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
            let v = page(ctx);
            match v.desk.get(v.selected).cloned() {
                Some(row) if row.stage == DeskStage::Card => {
                    v.mode = VettingMode::Attest {
                        request_id: row.request_id,
                        form: AttestForm::default(),
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
                    };
                }
                Some(_) => status(ctx, "That request is already closed."),
                None => {}
            }
        }
        VettingAction::ArmWithdraw => {
            let v = page(ctx);
            match v.issued.get(v.selected).cloned() {
                Some(row) if row.withdrawal.is_none() => {
                    v.mode = VettingMode::Withdraw {
                        statement_id: row.id,
                        reason_index: 0,
                    };
                }
                Some(_) => status(ctx, "That statement is already withdrawn."),
                None => {}
            }
        }
        VettingAction::Submit => submit(ctx).await,
    }
}

fn input(mode: &mut VettingMode, text: String) {
    // Typing a code replaces a ticket read from a link.
    if let VettingMode::RequestVetter {
        ticket, field: 1, ..
    } = mode
    {
        *ticket = None;
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
    v.mode = VettingMode::List;
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
        VettingMode::NewApplication { field, .. } => step(field, 3),
        VettingMode::RequestVetter { field, .. } | VettingMode::NewTicket { field, .. } => {
            step(field, 2);
        }
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
        VettingMode::ChooseFace { faces, index, .. } => step(index, faces.len()),
        VettingMode::Attest { form, .. } => step(&mut form.field, AttestForm::FIELDS),
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
    match &mut v.mode {
        VettingMode::Directory(view) => match view.field {
            0 => turn(&mut view.community_index, communities),
            5 => turn(&mut view.method_index, DIRECTORY_METHODS.len()),
            _ => {}
        },
        VettingMode::Profile(form) if form.event.is_none() && form.field == 0 => {
            turn(&mut form.membership_index, memberships);
        }
        VettingMode::Resend { index } => turn(index, resend),
        VettingMode::NewApplication {
            persona_index,
            field: 1,
            ..
        } => turn(persona_index, personas),
        VettingMode::NewApplication {
            context_options,
            context_index,
            field: 2,
            ..
        } => turn(context_index, context_options.len()),
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
        VettingMode::ChooseFace { faces, index, .. } => turn(index, faces.len()),
        _ => {}
    }
}

async fn submit(ctx: &mut ActionCtx<'_>) {
    match page(ctx).mode.clone() {
        VettingMode::List => {}
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
        VettingMode::ChooseFace {
            application_id,
            faces,
            index,
        } => wear_face(ctx, &application_id, faces.get(index).cloned()),
        VettingMode::RequestVetter {
            application_id,
            vetter,
            code,
            ticket,
            ..
        } => request_vetter(ctx, &application_id, vetter.trim(), &code, ticket).await,
        VettingMode::Directory(view) => match view.result_index() {
            Some(_) => ask_listed_vetter(ctx),
            None => search_directory(ctx, vec![None]).await,
        },
        VettingMode::Profile(form) => profile_submit(ctx, *form).await,
        VettingMode::Resend { index } => ask_resend(ctx, index).await,
        VettingMode::SendCard {
            application_id,
            session_id,
            preview,
        } => send_card(ctx, &application_id, &session_id, preview).await,
        VettingMode::NewTicket {
            membership_index,
            uses_index,
            ..
        } => issue_ticket(ctx, membership_index, uses_index),
        VettingMode::OpenSession {
            request_id,
            method_index,
        } => open_session(ctx, &request_id, method_index).await,
        VettingMode::Attest { request_id, form } => attest(ctx, &request_id, &form).await,
        VettingMode::ConfirmDecline { request_id } => decline(ctx, &request_id).await,
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

/// Sign `document` as `persona`, then hand the send to a background job. The
/// caller has claimed the domain; on error it is still claimed.
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
    wire::sign(&mut document, &keys.signing.secret)
        .await
        .map_err(|e| e.to_string())?;
    let message = wire::to_message(&document).map_err(|e| e.to_string())?;
    let from = document.issuer.clone().unwrap_or_default();
    let to = document.recipient.clone().unwrap_or_default();
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
    let document = match wire::manifest_request(&app.join_did, &app.community) {
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
    ctx.config
        .private
        .vetting
        .adopt_known_requirements(&application_id);
    {
        let v = page(ctx);
        v.mode = VettingMode::List;
        v.tab = VettingTab::Applications;
    }
    persist(ctx, "Application started.");
    if let Some(i) = page(ctx)
        .applications
        .iter()
        .position(|a| a.id == application_id)
    {
        page(ctx).selected = i;
    }
    refresh_requirements(ctx, &application_id).await;
}

async fn request_vetter(
    ctx: &mut ActionCtx<'_>,
    application_id: &str,
    vetter: &str,
    code: &str,
    ticket: Option<request::v0_1::Ticket>,
) {
    // A link typed into the DID field is read the same as a pasted one.
    if vetter.to_ascii_lowercase().starts_with("vetting-ticket:") {
        return paste_ticket(ctx, vetter);
    }
    if !vetter.starts_with("did:") {
        return status(ctx, "Enter the vetter's DID (it starts with did:).");
    }
    let presentation = match ticket {
        Some(ticket) if code.is_empty() => ticket,
        // The published short code is upper-case Crockford base32, so the code
        // is normalised into that form before the ticket is built rather than
        // sent as it was typed.
        _ => match normalise_code(code).and_then(|code| {
            request::v0_1::ShortCodeTicket::try_from(
                request::v0_1::ShortCodeTicket::builder().code(code),
            )
            .ok()
        }) {
            Some(code) => request::v0_1::Ticket::ShortCodeTicket(code),
            None => {
                return status(
                    ctx,
                    "That is not a ticket code — they look like K7QF-2M9X. Or paste the link \
                     from their QR code.",
                );
            }
        },
    };
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
    match app.ticket_from_uri(text) {
        Ok(ticket) => {
            let shown = shorten_did(&ticket.vetter, 64);
            if let VettingMode::RequestVetter {
                vetter,
                code,
                ticket: slot,
                field,
                ..
            } = &mut page(ctx).mode
            {
                *vetter = ticket.vetter;
                code.clear();
                *slot = Some(ticket.presentation);
                *field = 1;
            }
            status(
                ctx,
                format!("Filled in from the ticket link: {shown}. Enter sends the request."),
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
    let from_application = (v.tab == VettingTab::Applications)
        .then(|| v.applications.get(v.selected))
        .flatten()
        .map(|a| a.community.clone());
    let community_index = from_application
        .and_then(|c| {
            v.directory_communities
                .iter()
                .position(|d| d.community == c)
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
        vetter: row.did.clone(),
        code: String::new(),
        ticket: None,
        note: Some(format!(
            "{} still has to give you a ticket before they answer — {how}. Paste the link from \
             their QR code, or type the code they read to you.",
            row.name
        )),
        field: 1,
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
        v.tab = VettingTab::Tickets;
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
        page(ctx).mode = VettingMode::List;
        return status(
            ctx,
            format!("{} is already the face vetters are shown.", face.name),
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
            let signer = match ctx
                .config
                .get_persona_keys_for(application.persona, ctx.tdk)
                .await
            {
                Ok(keys) => keys.signing.secret.clone(),
                Err(e) => return abandon(ctx, "Could not sign the card", e),
            };
            status(ctx, "Releasing and signing your card…");
            CardStep::Present(Box::new(Presenting {
                preview_id: preview.preview_id,
                signer,
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

fn issue_ticket(ctx: &mut ActionCtx<'_>, membership_index: usize, uses_index: usize) {
    let Some(membership) = page(ctx).memberships.get(membership_index).cloned() else {
        return;
    };
    let uses = VETTING_TICKET_USES[uses_index.min(VETTING_TICKET_USES.len() - 1)];
    let ticket = Ticket::issue(
        &membership.community,
        membership.persona,
        vec![],
        uses,
        DEFAULT_VALIDITY,
        Utc::now(),
    );
    let code = ticket.code.clone();
    ctx.config.private.vetting.tickets.push(ticket);
    {
        let v = page(ctx);
        v.mode = VettingMode::List;
        v.tab = VettingTab::Tickets;
    }
    persist(
        ctx,
        format!(
            "Ticket {code} for {} — read it to the person, or copy it with y. It admits {uses} \
             request{} for 14 days.",
            membership.name,
            if uses == 1 { "" } else { "s" }
        ),
    );
    let last = page(ctx).tickets.len().saturating_sub(1);
    page(ctx).selected = last;
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
        let document = match wire::manifest_request(&vetter_did, &entry.community) {
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
    if let Err(e) = sign_and_send(ctx, entry.persona, document, sent).await {
        abandon(ctx, "Could not send the session", e);
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
    let message =
        match wire::credential_delivery(&vetter_did, &entry.applicant, &statement, &session.id) {
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

async fn decline(ctx: &mut ActionCtx<'_>, request_id: &str) {
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
        .decline(request_id, None, None, Utc::now())
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
    Wear {
        client: VtaClient,
        top_context_id: String,
        context_id: String,
        persona_did: String,
        application_id: String,
        face: FaceChoice,
    },
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
                        Ok(profiles
                            .into_iter()
                            .map(|p| FaceChoice {
                                worn: worn.as_deref() == Some(p.profile_id.as_str()),
                                name: sanitize_display(p.display_name(), 128),
                                entries: p.entry_count,
                                profile_id: p.profile_id,
                            })
                            .collect())
                    }
                    Err(e) => Err(e.to_string()),
                };
                VettingOutcome::Faces {
                    application_id,
                    result,
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
    signer: Secret,
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
                    wire::sign(&mut document, &signer).await.map_err(failed)?;
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
    /// A face is worn, or is not.
    FaceWorn {
        application_id: String,
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
                }
                let message = if faces.is_empty() {
                    "You have no faces yet — make one under My Identity with the claims the \
                     community requires, then press f again."
                } else {
                    "Choose the face vetters are shown."
                };
                if matches!(v.mode, VettingMode::List) && !faces.is_empty() {
                    let index = faces.iter().position(|f| f.worn).unwrap_or(0);
                    v.mode = VettingMode::ChooseFace {
                        application_id,
                        faces,
                        index,
                    };
                }
                // The application may have just been given its context.
                (message.to_string(), true)
            }
            VettingOutcome::Faces { result: Err(e), .. } => {
                (format!("Could not read your faces: {e}"), true)
            }
            VettingOutcome::FaceWorn {
                application_id,
                name,
                error: None,
            } => {
                v.worn_faces.insert(application_id, name.clone());
                (
                    format!(
                        "Vetters are shown your {name} face, and the community sees the same one \
                         when you join."
                    ),
                    true,
                )
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
            VettingOutcome::Previewed { result: Err(e), .. } => {
                (format!("Could not preview the card: {e}"), true)
            }
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
            (Sent::Manifest { .. } | Sent::Session { .. }, Some(e)) => {
                (format!("Could not send — try again: {e}"), false)
            }
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
            CommunityAnswer::Manifest { .. } => None,
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
            continue;
        }
        let name = community_display(config, &query.community);
        let words = format!(
            "No answer from {name} about {} within {} seconds — its service may be offline. Try \
             again later.",
            query.kind.describe(),
            QUERY_TIMEOUT.num_seconds()
        );
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
    let resolver = TrustTaskVmResolver::new(tdk.did_resolver().clone());
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::dispatch_util::test_config;
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
        let mut config = test_config();
        let persona = PersonaId::new();
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
}
