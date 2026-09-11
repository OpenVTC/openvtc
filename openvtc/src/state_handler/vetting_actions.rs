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
use openvtc_core::config::context_path::build_sub_context_id;
use openvtc_core::didcomm::Messaging;
use openvtc_core::persona::disclosure::{self, PresentError};
use openvtc_core::persona::{binding, profile};
use openvtc_core::vetting::applicant::{Application, RequestDraft, RequestState, SentCard};
use openvtc_core::vetting::book::FALLBACK_REQUIRED_CLAIMS;
use openvtc_core::vetting::tickets::{DEFAULT_VALIDITY, Ticket, normalise_code};
use openvtc_core::vetting::vetter::{Attestation, DeskState};
use openvtc_core::vetting::wire::{self, Document};
use serde_json::Value;
use vta_sdk::client::VtaClient;
use vta_sdk::protocols::vetting::{
    CardClaim, TicketPresentation, VETTING_DECLINE_TYPE, VETTING_REQUEST_TYPE,
    VETTING_REVOKE_STATEMENT_TYPE, VETTING_SESSION_RESPONSE_TYPE, VETTING_SESSION_TYPE,
    VettingMethod, VettingRequirements, VettingSessionResponseBody, documentation,
};
use vta_sdk::trust_task_proof::TrustTaskVmResolver;
use vta_sdk::vetting::card::sign_card;
use vta_sdk::vetting::requirements::{Evaluation, Need};
use vta_sdk::vetting::statement::sign_statement;

use crate::state_handler::actions::VettingAction;
use crate::state_handler::background_dispatch::{self, DispatchDomain, DispatchOutcome, InFlight};
use crate::state_handler::dispatch_util::{self, Persist, SyncLog};
use crate::state_handler::main_page::content::{
    ApplicationRow, AttestForm, CardPreview, DeskRow, DeskStage, FaceChoice, IssuedRow, RequestRow,
    TicketRow, VETTING_METHODS, VETTING_RELATIONSHIPS, VETTING_TICKET_USES,
    VETTING_WITHDRAWAL_REASONS, VettingMembership, VettingMode, VettingPersona, VettingState,
    VettingTab, method_label,
};
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
    let community_name = |did: &str| {
        config
            .account
            .memberships()
            .find(|m| m.vtc_did == did)
            .and_then(|m| m.display_name.as_deref())
            .map(|n| sanitize_display(n, 128))
    };

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
        .map(|m| VettingMembership {
            community: m.vtc_did.clone(),
            name: m
                .display_name
                .as_deref()
                .map(|n| sanitize_display(n, 128))
                .unwrap_or_else(|| shorten_did(&m.vtc_did, 48)),
            persona: m.persona_ref,
        })
        .collect();

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
                .map(|r| r.required_claims.clone())
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
                        .find(|c| &c.claim_type == claim_type)
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
                                    sanitize_display(&claim.claim_type, 64),
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

fn requirements_line(r: &VettingRequirements) -> String {
    let mut line = format!(
        "{} statement{} from distinct vetters",
        r.min_statements,
        if r.min_statements == 1 { "" } else { "s" }
    );
    for (method, n) in &r.min_by_method {
        line.push_str(&format!(", at least {n} {}", method_label(*method)));
    }
    if let Some(age) = &r.max_statement_age {
        line.push_str(&format!(", none older than {}", sanitize_display(age, 32)));
    }
    line
}

fn progress_line(evaluation: &Evaluation) -> String {
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
        VettingAction::Back => page(ctx).mode = VettingMode::List,
        VettingAction::Status(message) => status(ctx, message),
        VettingAction::Input(text) => input(&mut page(ctx).mode, text),
        VettingAction::NextField => move_field(page(ctx), true),
        VettingAction::PrevField => move_field(page(ctx), false),
        VettingAction::Cycle(forward) => cycle(page(ctx), forward),
        VettingAction::Toggle => {
            if let VettingMode::Attest { form, .. } = &mut page(ctx).mode {
                match form.field {
                    3 => form.liveness_confirmed = !form.liveness_confirmed,
                    4 => form.attested = !form.attested,
                    _ => {}
                }
            }
        }
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
                    field: 0,
                };
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
                    "You can hand out tickets once you are an active member of a community.",
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
    match mode {
        VettingMode::NewApplication {
            community,
            field: 0,
            ..
        } => *community = text,
        VettingMode::RequestVetter {
            vetter, field: 0, ..
        } => *vetter = text,
        VettingMode::RequestVetter { code, field: 1, .. } => *code = text,
        _ => {}
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
        VettingMode::NewApplication { field, .. }
        | VettingMode::RequestVetter { field, .. }
        | VettingMode::NewTicket { field, .. } => step(field, 2),
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
    match &mut v.mode {
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
            ..
        } => start_application(ctx, community.trim(), persona_index).await,
        VettingMode::ChooseFace {
            application_id,
            faces,
            index,
        } => wear_face(ctx, &application_id, faces.get(index).cloned()),
        VettingMode::RequestVetter {
            application_id,
            vetter,
            code,
            ..
        } => request_vetter(ctx, &application_id, vetter.trim(), &code).await,
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

async fn start_application(ctx: &mut ActionCtx<'_>, community: &str, persona_index: usize) {
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
        Ok(app) => app.id.clone(),
        Err(e) => return status(ctx, format!("Could not start the application: {e}")),
    };
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

async fn request_vetter(ctx: &mut ActionCtx<'_>, application_id: &str, vetter: &str, code: &str) {
    if !vetter.starts_with("did:") {
        return status(ctx, "Enter the vetter's DID (it starts with did:).");
    }
    let Some(code) = normalise_code(code) else {
        return status(ctx, "That is not a ticket code — they look like K7QF-2M9X.");
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
        TicketPresentation::Code { code },
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
    let community = app.community.clone();
    let name = config.agent_name_for(&community).map(ToString::to_string);
    let id = build_sub_context_id(
        &config.account.top_context_id,
        name.as_deref(),
        &community,
        |id| {
            config.account.memberships().any(|m| m.sub_context_id == id)
                || config
                    .private
                    .vetting
                    .applications
                    .iter()
                    .any(|a| a.context_id.as_deref() == Some(id))
        },
    )
    .map_err(|e| e.to_string())?;
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
        entry.request.requirements_digest.as_deref(),
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
    let document_classes = if method == VettingMethod::PriorAcquaintance
        && documentation_choice == documentation::NONE
    {
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
                context_id,
                persona_did,
                application_id,
                face,
            } => VettingOutcome::FaceWorn {
                error: binding::set(&client, &context_id, &persona_did, Some(&face.profile_id))
                    .await
                    .err()
                    .map(|e| e.to_string()),
                application_id,
                name: face.name,
            },
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
                    let mut document = wire::document(
                        VETTING_SESSION_RESPONSE_TYPE,
                        &application.join_did,
                        &vetter,
                        wire::new_id(),
                        &VettingSessionResponseBody { card, ext: None },
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
        result: Result<(SentCard, Vec<CardClaim>), CardFailure>,
    },
}

impl VettingOutcome {
    /// Fold the result into the book and the page.
    pub(crate) fn apply(self, state: &mut State, config: &mut Config, save: &mut SaveScheduler) {
        let v = &mut state.main_page.content_panel.vetting;
        let (message, persist) = match self {
            VettingOutcome::Sent { sent, error } => sent_result(*sent, error, config),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::dispatch_util::test_config;
    use openvtc_core::vetting::applicant::Application;

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
            TicketPresentation::Code {
                code: "K7QF-2M9X".into(),
            },
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
            v.applications[0].identity,
            vec![("name.legal".to_string(), String::new())],
            "without requirements the page asks for a legal name"
        );
        assert_eq!(v.tickets.len(), 1);
        assert!(v.tickets[0].live);
        assert!(v.documentation.iter().any(|d| d == "none"));
    }
}
