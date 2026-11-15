//! PCS work at the VTA: deciding when it is due, starting it, and applying
//! what comes back (results, recoveries, and inbound PCS messages).

use std::sync::Arc;

use chrono::{DateTime, Utc};
use openvtc_core::config::Config;
use openvtc_core::config::account::PersonaId;
use openvtc_core::vetting::queries::{CommunityQuery, QueryKind};
use openvtc_core::vetting::wire;
use serde_json::Value;

use super::dispatch::{persist, status};
use super::faces::application_context;
use super::hidden::{cannot_attest_hidden, vetter_context};
use super::jobs::Sent;
use super::send::{sign_and_send, spawn_send};
use super::words::community_display;
use crate::state_handler::background_dispatch::{self, DispatchDomain, DispatchOutcome};
use crate::state_handler::hidden_vetting_vta::{PcsDone, PcsJob, PcsOutcome, PcsWork};
use crate::state_handler::main_page::sanitize_display;
use crate::state_handler::runtime_actions::ActionCtx;
use openvtc_core::logs::LogFamily;
use openvtc_core::vetting::book::PcsInbound;
use openvtc_core::vetting::inbound::Notice;
use openvtc_core::vetting::pcs_vta::PcsError;

/// Whether there is hidden-vetting work the VTA should be asked to do now: something queued for
/// it, or an application without its engine — and the VTA is not in its backoff.
pub(crate) fn pcs_work_due(config: &Config, now: DateTime<Utc>) -> bool {
    let book = &config.private.vetting;
    let owed = book.pcs_due
        || !book.pcs_inbox.is_empty()
        || book.applications.iter().any(|a| a.hidden_app_owed());
    owed && book.pcs_retry_at.is_none_or(|t| t <= now)
}

/// Start a job at the VTA: `extra` (a pass of the vetter schedule, or an attestation) with
/// whatever else is owed — every answer queued for the VTA, and each application that needs its
/// engine. Returns whether a job started: `false` when one is already running (the queue is
/// asked again when it finishes) or the VTA is not connected.
pub(crate) fn start_pcs_work(ctx: &mut ActionCtx<'_>, extra: Vec<PcsWork>) -> bool {
    let Some(client) = ctx.admin_vta.cloned() else {
        // Kept queued: the sweep asks again once the VTA is connected.
        return false;
    };
    let book = &ctx.config.private.vetting;
    let mut work = Vec::new();
    for item in &book.pcs_inbox {
        work.push(inbound_work(ctx.config, item));
    }
    let inbox_taken = book.pcs_inbox.len();
    let owed: Vec<String> = book
        .applications
        .iter()
        .filter(|a| a.hidden_app_owed())
        .map(|a| a.id.clone())
        .collect();
    for application in owed {
        let Ok((context_id, join_did)) = application_context(ctx.config, &application) else {
            continue;
        };
        let Some(app) = ctx.config.private.vetting.application_by_id(&application) else {
            continue;
        };
        let Some(params) = app.hidden.clone() else {
            continue;
        };
        work.push(PcsWork::Create {
            application,
            context_id,
            community: app.community.clone(),
            join_did,
            params,
        });
    }
    work.extend(extra);
    if work.is_empty() {
        ctx.config.private.vetting.pcs_due = false;
        return true;
    }
    if !ctx.in_flight.try_begin(DispatchDomain::HiddenVetting) {
        // The job running now takes what it carried; this is asked for when it is back.
        ctx.config.private.vetting.pcs_due = true;
        return false;
    }
    ctx.config.private.vetting.pcs_due = false;
    let job = PcsJob {
        client,
        inbox_taken,
        work,
    };
    background_dispatch::spawn_dispatch(
        ctx.dispatch_tx.clone(),
        DispatchDomain::HiddenVetting,
        async move { DispatchOutcome::HiddenVetting(Box::new(job.run().await)) },
    );
    true
}

/// The call that hands `item` to the VTA, with what it needs that the item does not carry.
fn inbound_work(config: &Config, item: &PcsInbound) -> PcsWork {
    let book = &config.private.vetting;
    let (context_id, params, vta_application) = match item {
        PcsInbound::Enrolled {
            community, persona, ..
        }
        | PcsInbound::TokensServed {
            community, persona, ..
        }
        | PcsInbound::DrawRefused {
            community, persona, ..
        } => (
            vetter_context(config, *persona),
            book.hidden_vetter(community, *persona)
                .map(|h| h.params.clone()),
            None,
        ),
        PcsInbound::Attestation { application, .. } => {
            let app = book.application_by_id(application);
            (
                None,
                app.and_then(|a| a.hidden.clone()),
                app.and_then(|a| a.hidden_app.as_ref())
                    .map(|v| v.application_id.clone()),
            )
        }
        PcsInbound::DeleteApplication { .. } => (None, None, None),
    };
    PcsWork::Inbound {
        item: item.clone(),
        context_id,
        params,
        vta_application,
    }
}

/// Record a notice as an inbound message's would be: in the community log, and as a task where
/// it asks something of the person.
fn pcs_notice(ctx: &mut ActionCtx<'_>, notice: Notice, persona: Option<PersonaId>) {
    ctx.config
        .private
        .logs
        .insert(LogFamily::Community, notice.describe());
    if let Some((id, task)) = notice.task() {
        ctx.config
            .private
            .tasks
            .new_task_for(&Arc::new(id), task, persona);
    }
}

/// Take what a hidden-vetting job at the VTA answered: record it, and send the community or the
/// applicant whatever the VTA built.
pub(crate) async fn apply_pcs_outcome(ctx: &mut ActionCtx<'_>, outcome: PcsOutcome) {
    let now = Utc::now();
    let PcsOutcome {
        inbox_taken,
        results,
    } = outcome;
    // The inbox entries the job carried, and which of them it finished with. A VTA that could not
    // be reached finished nothing: those stay, in order, for the next job.
    let mut finished = vec![false; inbox_taken];
    let mut position = 0usize;
    let mut unreachable = None;
    for (work, result) in results {
        if let Err(e @ PcsError::Unreachable(_)) = &result {
            unreachable.get_or_insert_with(|| e.to_string());
        }
        if let PcsWork::Inbound { .. } = &work {
            if position < inbox_taken {
                finished[position] = !matches!(result, Err(PcsError::Unreachable(_)));
            }
            position += 1;
        }
        apply_pcs_result(ctx, work, result, now).await;
    }
    {
        let book = &mut ctx.config.private.vetting;
        let kept: Vec<PcsInbound> = book
            .pcs_inbox
            .drain(..)
            .enumerate()
            .filter(|(i, _)| *i >= inbox_taken || !finished[*i])
            .map(|(_, item)| item)
            .collect();
        book.pcs_inbox = kept;
        match &unreachable {
            Some(e) => {
                book.pcs_failures = book.pcs_failures.saturating_add(1);
                let retry =
                    now + openvtc_core::vetting::book::hidden_retry_after(book.pcs_failures);
                book.pcs_retry_at = Some(retry);
                tracing::warn!(error = %e, %retry, "could not reach the VTA for hidden-vetting work; asking again later");
            }
            None => {
                book.pcs_failures = 0;
                book.pcs_retry_at = None;
            }
        }
        // Anything that arrived while the job ran goes on the next sweep.
        book.pcs_due = !book.pcs_inbox.is_empty();
    }
    ctx.save.mark_dirty();
    ctx.state.main_page.sync_from_config(ctx.config);
}

async fn apply_pcs_result(
    ctx: &mut ActionCtx<'_>,
    work: PcsWork,
    result: Result<PcsDone, PcsError>,
    now: DateTime<Utc>,
) {
    match (work, result) {
        (PcsWork::VetterShow { .. }, Err(e)) => {
            tracing::debug!(error = %e, "could not read a hidden-vetting engine from the VTA");
        }
        (
            PcsWork::VetterShow {
                community, persona, ..
            },
            Ok(PcsDone::Viewed(view)),
        ) => {
            if let (Some(view), Some(held)) = (
                view,
                ctx.config
                    .private
                    .vetting
                    .hidden_vetter_mut(&community, persona),
            ) {
                held.take_engine(view);
            }
        }
        (
            PcsWork::Owed {
                community,
                persona,
                did,
                ..
            },
            Ok(PcsDone::Root(request)),
        ) => send_enrolment(ctx, &community, persona, &did, &request, now).await,
        (
            PcsWork::Owed {
                community,
                persona,
                did,
                ..
            },
            Ok(PcsDone::Tokens(request)),
        ) => send_draw(ctx, &community, persona, &did, &request, now).await,
        (
            PcsWork::Owed {
                community, owed, ..
            },
            Err(e),
        ) => {
            let what = match owed {
                openvtc_core::vetting::hidden::Due::Enrol { .. } => "ask to enrol",
                _ => "draw tokens",
            };
            tracing::warn!(community = %community, error = %e, "the VTA could not {what}");
            if !matches!(e, PcsError::Unreachable(_)) {
                status(
                    ctx,
                    format!(
                        "Could not {what} for {}: {e}",
                        community_display(ctx.config, &community)
                    ),
                );
            }
        }
        (
            PcsWork::Recover {
                community, persona, ..
            },
            result,
        ) => apply_recovery(ctx, &community, persona, result, now),
        (PcsWork::Inbound { item, .. }, result) => apply_pcs_inbound(ctx, item, result, now),
        (PcsWork::Create { application, .. }, Ok(PcsDone::Created(view))) => {
            if let Some(app) = ctx
                .config
                .private
                .vetting
                .application_by_id_mut(&application)
            {
                app.hidden_app = Some(view);
            }
        }
        (PcsWork::Create { community, .. }, Err(e)) => {
            if !matches!(e, PcsError::Unreachable(_)) {
                status(
                    ctx,
                    format!(
                        "Could not set up PCS ZKP vetting for {} at your VTA: {e}",
                        community_display(ctx.config, &community)
                    ),
                );
            }
        }
        (
            PcsWork::Attest {
                job,
                vetter_did,
                session_id,
                ..
            },
            Ok(PcsDone::Attested(attestation)),
        ) => send_attestation(ctx, &job, &vetter_did, &session_id, &attestation, now),
        (PcsWork::Attest { job, .. }, Err(e)) => {
            use openvtc_core::vetting::pcs_vta::tasks::attest::v0_1::error_codes as codes;
            let waiting = e.is(codes::NO_TOKEN) || e.is(codes::NOT_ENROLLED);
            let why = if e.is(codes::NO_TOKEN) {
                openvtc_core::vetting::hidden::HiddenError::NoToken.to_string()
            } else if e.is(codes::NOT_ENROLLED) {
                openvtc_core::vetting::hidden::HiddenError::NotEnrolled.to_string()
            } else {
                e.to_string()
            };
            if let Some(entry) = ctx
                .config
                .private
                .vetting
                .desk_entry(&job.request_id)
                .cloned()
            {
                cannot_attest_hidden(ctx, &entry, &why, waiting, now);
            }
        }
        (work, Ok(done)) => {
            tracing::warn!(
                ?work,
                ?done,
                "a hidden-vetting answer from the VTA that fits nothing asked"
            );
        }
    }
}

/// Take the VTA's answer to restoring the key the community bound us to: enrol again on a key
/// restored or already held, or say what is in the way — each refusal in its own words (R6.4).
fn apply_recovery(
    ctx: &mut ActionCtx<'_>,
    community: &str,
    persona: PersonaId,
    result: Result<PcsDone, PcsError>,
    now: DateTime<Utc>,
) {
    use openvtc_core::vetting::binding::{KeyPhase, RecoverRefusal, key_lines};
    let name = community_display(ctx.config, community);
    let book = &mut ctx.config.private.vetting;
    let Some(held) = book.hidden_vetter_mut(community, persona) else {
        return;
    };
    match result {
        Ok(PcsDone::Recovered(answer)) => {
            tracing::info!(community = %community, recovered = answer.recovered, "the VTA holds the hidden-vetting key the community bound us to");
            held.on_recovered(answer.recovered, answer.vetter, now);
        }
        // Not reached: the identifier is still held, and the next pass asks again (R1.4: the
        // VTA's own backoff paces it).
        Err(PcsError::Unreachable(e)) => {
            tracing::warn!(community = %community, error = %e, "could not reach the VTA to restore a hidden-vetting key");
            return;
        }
        Err(PcsError::Refused { code, message }) => {
            tracing::warn!(community = %community, %code, "the VTA could not restore the hidden-vetting key the community bound us to");
            held.on_recover_refused(RecoverRefusal::from_code(&code, &message), now);
        }
        Err(PcsError::Unreadable(e)) => {
            // A contract mismatch, not a refusal (R6.4): said as such, and asked again by hand.
            held.on_recover_refused(
                RecoverRefusal::Refused {
                    code: "unreadable".to_string(),
                    message: format!(
                        "this client and your VTA disagree about vta/pcs/vetter/recover — update                          one or the other ({e})"
                    ),
                },
                now,
            );
        }
        Ok(other) => {
            tracing::warn!(?other, "unexpected answer to vetter/recover");
            return;
        }
    }
    // Enrolling again — on the key restored, or the current one where a reset is open: now,
    // not at the next pass.
    let retrying = matches!(
        held.key.as_ref().map(|k| &k.phase),
        Some(KeyPhase::Retrying { .. })
    );
    let words = held.key.as_ref().map(|check| {
        key_lines(check, &name, |s| sanitize_display(s, 200))
            .into_iter()
            .map(|l| format!("{}: {}", l.label, l.text))
            .collect::<Vec<_>>()
            .join(". ")
    });
    if retrying {
        book.vetter_refresh_due = true;
    }
    if let Some(words) = words {
        persist(ctx, format!("Hidden vetting at {name} — {words}."));
    }
}

/// Send the community the enrolment request the VTA built.
async fn send_enrolment(
    ctx: &mut ActionCtx<'_>,
    community: &str,
    persona: PersonaId,
    did: &str,
    request: &openvtc_core::vetting::wire::pcs::RootRequest,
    now: DateTime<Utc>,
) {
    let document = match wire::pcs_root_request(did, community, request) {
        Ok(d) => d,
        Err(e) => return status(ctx, format!("Could not ask to enrol: {e}")),
    };
    let document_id = document.id.clone();
    if let Some(held) = ctx
        .config
        .private
        .vetting
        .hidden_vetter_mut(community, persona)
    {
        held.enrol_asked_at = Some(now);
    }
    ctx.config.private.vetting.ask(CommunityQuery {
        document_id: document_id.clone(),
        community: community.to_string(),
        persona,
        kind: QueryKind::PcsRoot,
        sent_at: now,
    });
    status(
        ctx,
        format!("Asking to enrol as a vetter under {}…", request.label),
    );
    let sent = Sent::Query {
        document_id,
        community: community.to_string(),
        kind: QueryKind::PcsRoot,
    };
    if let Err(e) = sign_and_send(ctx, persona, document, sent).await {
        status(ctx, format!("Could not ask to enrol: {e}"));
    }
}

/// Send the community a draw the VTA built.
async fn send_draw(
    ctx: &mut ActionCtx<'_>,
    community: &str,
    persona: PersonaId,
    did: &str,
    request: &openvtc_core::vetting::wire::pcs::TokensRequest,
    now: DateTime<Utc>,
) {
    let document = match wire::pcs_tokens_request(did, community, request) {
        Ok(d) => d,
        Err(e) => return status(ctx, format!("Could not draw tokens: {e}")),
    };
    let document_id = document.id.clone();
    ctx.config.private.vetting.ask(CommunityQuery {
        document_id: document_id.clone(),
        community: community.to_string(),
        persona,
        kind: QueryKind::PcsTokens,
        sent_at: now,
    });
    ctx.config
        .private
        .vetting
        .draws_in_flight
        .insert(document_id.clone(), (request.label.clone(), request.tick));
    let sent = Sent::Query {
        document_id,
        community: community.to_string(),
        kind: QueryKind::PcsTokens,
    };
    if let Err(e) = sign_and_send(ctx, persona, document, sent).await {
        status(ctx, format!("Could not draw tokens: {e}"));
    }
}

/// Close the request and send the applicant the attestation the VTA made.
fn send_attestation(
    ctx: &mut ActionCtx<'_>,
    job: &openvtc_core::vetting::book::HiddenAttestJob,
    vetter_did: &str,
    session_id: &str,
    attestation: &Value,
    now: DateTime<Utc>,
) {
    let Some(previous) = ctx
        .config
        .private
        .vetting
        .desk_entry(&job.request_id)
        .map(|e| e.state.clone())
    else {
        return;
    };
    let message =
        match wire::hidden_attestation(vetter_did, &job.applicant, attestation, session_id) {
            Ok(message) => message,
            // The token is spent either way, but the request is not closed on a delivery that never
            // left.
            Err(e) => return status(ctx, format!("Could not send the attestation: {e}")),
        };
    if let Err(e) = ctx
        .config
        .private
        .vetting
        .hidden_attested(&job.request_id, now)
    {
        return status(ctx, format!("Could not record the attestation: {e}"));
    }
    persist(ctx, "Sending your attestation — it names nobody.");
    let sent = Sent::Attestation {
        request_id: job.request_id.clone(),
        previous,
    };
    spawn_send(ctx, message, vetter_did, &job.applicant, sent);
}

/// Take the VTA's answer to an item a community or a vetter sent.
fn apply_pcs_inbound(
    ctx: &mut ActionCtx<'_>,
    item: PcsInbound,
    result: Result<PcsDone, PcsError>,
    now: DateTime<Utc>,
) {
    use openvtc_core::vetting::pcs_vta::tasks;
    if let Err(PcsError::Unreachable(_)) = &result {
        // Still queued; the next job hands it on.
        return;
    }
    match (item, result) {
        (
            PcsInbound::Enrolled {
                community,
                persona,
                answer,
            },
            result,
        ) => {
            let period = answer.label.trim_start_matches("vetter/").to_string();
            let book = &mut ctx.config.private.vetting;
            let Some(held) = book.hidden_vetter_mut(&community, persona) else {
                return;
            };
            match result {
                Ok(PcsDone::Enrolled(view)) => {
                    held.take_engine(view);
                    held.key_settled();
                    held.enrolled_at.insert(period, now);
                    held.enrol_asked_at = None;
                    held.last_refusal = None;
                    held.lost_enrolment = None;
                    held.lost_reasked = false;
                    // Draw now rather than at the next pass, which can be an hour away: every
                    // tick of the label that has begun is owed already. Driven by the
                    // enrolment, never by a balance.
                    book.vetter_refresh_due = true;
                    pcs_notice(
                        ctx,
                        Notice::HiddenVetterEnrolled {
                            community,
                            label: answer.label,
                        },
                        Some(persona),
                    );
                }
                Err(e) => {
                    // An answer the VTA did not ask for under this label, or one that does not
                    // open: the community issues one credential per label, so this label is lost.
                    tracing::warn!(community = %community, error = %e, "the VTA could not take in an enrolment answer");
                    if held.lost_enrolment.as_deref() != Some(period.as_str()) {
                        held.lost_reasked = false;
                    }
                    held.lost_enrolment = Some(period);
                    pcs_notice(
                        ctx,
                        Notice::HiddenEnrolmentLost {
                            community,
                            label: answer.label,
                        },
                        Some(persona),
                    );
                }
                Ok(other) => tracing::warn!(?other, "unexpected answer to root-accept"),
            }
        }
        (
            PcsInbound::TokensServed {
                community,
                persona,
                answer,
            },
            result,
        ) => match result {
            Ok(PcsDone::Drawn(taken, view)) => {
                if let Some(held) = ctx
                    .config
                    .private
                    .vetting
                    .hidden_vetter_mut(&community, persona)
                {
                    held.take_engine(view);
                    held.last_draw = Some(openvtc_core::vetting::book::HiddenDraw {
                        label: answer.label.clone(),
                        tick: answer.tick,
                        taken: usize::try_from(taken).unwrap_or(usize::MAX),
                        at: now,
                    });
                }
                pcs_notice(
                    ctx,
                    Notice::HiddenTokensDrawn {
                        community,
                        taken: usize::try_from(taken).unwrap_or(usize::MAX),
                    },
                    Some(persona),
                );
            }
            Err(e) if e.is(tasks::tokens::accept::v0_1::error_codes::NO_DRAW_IN_FLIGHT) => {
                tracing::info!(community = %community, label = %answer.label, tick = answer.tick, "the VTA was not waiting on this draw — already taken in");
            }
            Err(e) => {
                tracing::warn!(community = %community, error = %e, "served tokens were not taken in");
            }
            Ok(other) => tracing::warn!(?other, "unexpected answer to tokens/accept"),
        },
        (
            PcsInbound::DrawRefused {
                community, persona, ..
            },
            result,
        ) => match result {
            Ok(PcsDone::Abandoned(Some(view))) => {
                if let Some(held) = ctx
                    .config
                    .private
                    .vetting
                    .hidden_vetter_mut(&community, persona)
                {
                    held.take_engine(view);
                }
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(community = %community, error = %e, "could not drop a refused draw at the VTA");
            }
        },
        (PcsInbound::Attestation { application, .. }, result) => match result {
            Ok(PcsDone::Verified(view)) => {
                let held = view.attestations.len();
                let persona = ctx
                    .config
                    .private
                    .vetting
                    .application_by_id(&application)
                    .map(|a| a.persona);
                if let Some(app) = ctx
                    .config
                    .private
                    .vetting
                    .application_by_id_mut(&application)
                {
                    app.hidden_app = Some(view);
                }
                pcs_notice(
                    ctx,
                    Notice::AttestationReceived {
                        application_id: application,
                        held,
                    },
                    persona,
                );
            }
            Err(e) => {
                // Not one that counts: it does not verify under the community's published
                // parameters, or is not bound to this application. Said, and never kept.
                tracing::warn!(error = %e, "hidden attestation refused");
                status(
                    ctx,
                    format!("A vetter's attestation was refused by your VTA: {e}"),
                );
            }
            Ok(other) => tracing::warn!(?other, "unexpected answer to verify-attestation"),
        },
        (PcsInbound::DeleteApplication { .. }, Err(e)) => {
            tracing::warn!(error = %e, "could not delete a hidden-vetting application at the VTA");
        }
        (PcsInbound::DeleteApplication { .. }, Ok(_)) => {}
    }
}
