//! PCS work at the VTA: deciding when it is due, starting it, and applying
//! what comes back (results, recoveries, and inbound PCS messages).
//!
//! Starting is planned by [`plan_pcs_work`], which gathers what is owed into a
//! [`PcsStart`]; [`start`] claims the hidden-vetting domain for it. A job's
//! answers are planned one at a time ([`PcsAnswer`], through
//! [`Step::PcsAnswer`]) on the state the answer before left, so the sends one
//! answer owes go out before the next answer is read, and the bookkeeping that
//! closes the job ([`PcsAnswer::Settled`]) comes last.

use crate::state_handler::main_page::status::Status;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use openvtc_core::config::Config;
use openvtc_core::config::account::PersonaId;
use openvtc_core::vetting::queries::{CommunityQuery, QueryKind};
use openvtc_core::vetting::wire;
use serde_json::Value;

use super::dispatch::show;
use super::effect::{Step, Undo, VettingEffect, run};
use super::faces::{application_context, keep_context};
use super::hidden::{cannot_attest_hidden, vetter_context};
use super::jobs::Sent;
use super::send::Claim;
use super::words::community_display;
use crate::state_handler::background_dispatch;
use crate::state_handler::hidden_vetting_vta::{PcsDone, PcsJob, PcsOutcome, PcsWork};
use crate::state_handler::main_page::sanitize_display;
use crate::state_handler::runtime_actions::ActionCtx;
use crate::state_handler::state::State;
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

/// What [`plan_pcs_work`] made of the work owed to the VTA.
#[derive(Debug)]
pub(super) enum PcsStart {
    /// No VTA session: nothing is gathered, and the queue is asked for again once one is
    /// connected.
    Unconnected,
    /// Nothing owed: the book no longer says there is.
    Nothing,
    /// A job to start: the inbox's first `inbox_taken` entries and the rest of `work`.
    Job {
        inbox_taken: usize,
        work: Vec<PcsWork>,
    },
}

/// Start a job at the VTA: `extra` (a pass of the vetter schedule, or an attestation) with
/// whatever else is owed — every answer queued for the VTA, and each application that needs its
/// engine. Returns whether a job started: `false` when one is already running (the queue is
/// asked again when it finishes) or the VTA is not connected.
pub(crate) fn start_pcs_work(ctx: &mut ActionCtx<'_>, extra: Vec<PcsWork>) -> bool {
    let planned = plan_pcs_work(ctx.config, ctx.admin_vta.is_some(), extra);
    start(ctx, planned)
}

/// Plan [`start_pcs_work`]: gather what is owed, after `extra`'s place in it. `connected` is
/// whether an admin VTA session is held. Owing nothing says so in the book.
pub(super) fn plan_pcs_work(config: &mut Config, connected: bool, extra: Vec<PcsWork>) -> PcsStart {
    if !connected {
        // Kept queued: the sweep asks again once the VTA is connected.
        return PcsStart::Unconnected;
    }
    let book = &config.private.vetting;
    let mut work = Vec::new();
    for item in &book.pcs_inbox {
        work.push(inbound_work(config, item));
    }
    let inbox_taken = book.pcs_inbox.len();
    let owed: Vec<String> = book
        .applications
        .iter()
        .filter(|a| a.hidden_app_owed())
        .map(|a| a.id.clone())
        .collect();
    for application in owed {
        let Ok(context) = application_context(config, &application) else {
            continue;
        };
        // Kept now: the job's answers are saved when they are settled.
        keep_context(config, &application, &context);
        let (context_id, join_did) = (context.id, context.join_did);
        let Some(app) = config.private.vetting.application_by_id(&application) else {
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
        config.private.vetting.pcs_due = false;
        return PcsStart::Nothing;
    }
    PcsStart::Job { inbox_taken, work }
}

/// Start what [`plan_pcs_work`] planned, claiming the hidden-vetting domain. Returns whether it
/// started — or, owing nothing, whether there was nothing to start.
pub(super) fn start(ctx: &mut ActionCtx<'_>, planned: PcsStart) -> bool {
    let (inbox_taken, work) = match planned {
        PcsStart::Unconnected => return false,
        PcsStart::Nothing => return true,
        PcsStart::Job { inbox_taken, work } => (inbox_taken, work),
    };
    // The plan read the session on this arm, so it is still held.
    let Some(client) = ctx.admin_vta.cloned() else {
        return false;
    };
    let job = PcsJob {
        client,
        inbox_taken,
        work,
    };
    let started = background_dispatch::dispatch(job, ctx.in_flight, ctx.dispatch_tx, |_| {
        // The job running now takes what it carried; this is asked for when it is back.
        ctx.config.private.vetting.pcs_due = true;
    });
    if started {
        ctx.config.private.vetting.pcs_due = false;
    }
    started
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
fn pcs_notice(config: &mut Config, notice: Notice, persona: Option<PersonaId>) {
    config
        .private
        .logs
        .insert(LogFamily::Community, notice.describe());
    if let Some((id, task)) = notice.task() {
        config
            .private
            .tasks
            .new_task_for(&Arc::new(id), task, persona);
    }
}

/// Take what a hidden-vetting job at the VTA answered: record it, and send the community or the
/// applicant whatever the VTA built.
pub(crate) async fn apply_pcs_outcome(ctx: &mut ActionCtx<'_>, outcome: PcsOutcome) {
    run(ctx, plan_pcs_outcome(outcome, Utc::now())).await;
}

/// One step of applying a job's answers, planned when it is reached.
#[derive(Debug)]
pub(super) enum PcsAnswer {
    /// What the VTA answered for one piece of work.
    Result {
        work: Box<PcsWork>,
        result: Box<Result<PcsDone, PcsError>>,
        now: DateTime<Utc>,
    },
    /// Every answer is in: drop the inbox entries the job finished with, and set the backoff.
    Settled {
        inbox_taken: usize,
        /// For each inbox entry the job carried, whether it finished with it.
        finished: Vec<bool>,
        /// The first unreachable error, if the VTA could not be reached.
        unreachable: Option<String>,
        now: DateTime<Utc>,
    },
}

/// Plan [`apply_pcs_outcome`] at `now`: one [`Step::PcsAnswer`] per answer, in the order the
/// job did the work, then the job's bookkeeping. Which inbox entries it finished with, and
/// whether the VTA was reached, are read from the answers alone.
pub(super) fn plan_pcs_outcome(outcome: PcsOutcome, now: DateTime<Utc>) -> VettingEffect {
    let PcsOutcome {
        inbox_taken,
        results,
    } = outcome;
    // The inbox entries the job carried, and which of them it finished with. A VTA that could not
    // be reached finished nothing: those stay, in order, for the next job.
    let mut finished = vec![false; inbox_taken];
    let mut position = 0usize;
    let mut unreachable = None;
    let mut steps = Vec::with_capacity(results.len() + 1);
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
        steps.push(Step::PcsAnswer(Box::new(PcsAnswer::Result {
            work: Box::new(work),
            result: Box::new(result),
            now,
        })));
    }
    steps.push(Step::PcsAnswer(Box::new(PcsAnswer::Settled {
        inbox_taken,
        finished,
        unreachable,
        now,
    })));
    VettingEffect(steps)
}

/// Plan one [`PcsAnswer`] on the state and book as the steps before it left them.
pub(super) fn plan_pcs_answer(
    state: &mut State,
    config: &mut Config,
    answer: PcsAnswer,
) -> VettingEffect {
    match answer {
        PcsAnswer::Result { work, result, now } => {
            plan_pcs_result(state, config, *work, *result, now)
        }
        PcsAnswer::Settled {
            inbox_taken,
            finished,
            unreachable,
            now,
        } => {
            let book = &mut config.private.vetting;
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
            state.main_page.sync_panels(
                config,
                crate::state_handler::main_page::Panels::FROM_VETTING_BOOK,
            );
            VettingEffect(vec![Step::MarkDirty])
        }
    }
}

fn plan_pcs_result(
    state: &mut State,
    config: &mut Config,
    work: PcsWork,
    result: Result<PcsDone, PcsError>,
    now: DateTime<Utc>,
) -> VettingEffect {
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
                config
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
        ) => return plan_enrolment(state, config, &community, persona, &did, &request, now),
        (
            PcsWork::Owed {
                community,
                persona,
                did,
                ..
            },
            Ok(PcsDone::Tokens(request)),
        ) => return plan_draw(state, config, &community, persona, &did, &request, now),
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
                show(
                    state,
                    Status::error(format!(
                        "Could not {what} for {}: {e}",
                        community_display(config, &community)
                    )),
                );
            }
        }
        (
            PcsWork::Recover {
                community, persona, ..
            },
            result,
        ) => return plan_recovery(config, &community, persona, result, now),
        (PcsWork::Inbound { item, .. }, result) => {
            apply_pcs_inbound(state, config, item, result, now);
        }
        (PcsWork::Create { application, .. }, Ok(PcsDone::Created(view))) => {
            if let Some(app) = config.private.vetting.application_by_id_mut(&application) {
                app.hidden_app = Some(view);
            }
        }
        (PcsWork::Create { community, .. }, Err(e)) => {
            if !matches!(e, PcsError::Unreachable(_)) {
                show(
                    state,
                    Status::error(format!(
                        "Could not set up PCS ZKP vetting for {} at your VTA: {e}",
                        community_display(config, &community)
                    )),
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
        ) => {
            return plan_attestation(
                state,
                config,
                &job,
                &vetter_did,
                &session_id,
                &attestation,
                now,
            );
        }
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
            if let Some(entry) = config.private.vetting.desk_entry(&job.request_id).cloned() {
                cannot_attest_hidden(state, config, &entry, &why, waiting, now);
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
    VettingEffect::none()
}

/// Take the VTA's answer to restoring the key the community bound us to: enrol again on a key
/// restored or already held, or say what is in the way — each refusal in its own words (R6.4).
/// What is said is saved with it.
fn plan_recovery(
    config: &mut Config,
    community: &str,
    persona: PersonaId,
    result: Result<PcsDone, PcsError>,
    now: DateTime<Utc>,
) -> VettingEffect {
    use openvtc_core::vetting::binding::{KeyPhase, RecoverRefusal, key_lines};
    let name = community_display(config, community);
    let book = &mut config.private.vetting;
    let Some(held) = book.hidden_vetter_mut(community, persona) else {
        return VettingEffect::none();
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
            return VettingEffect::none();
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
                        "this client and your VTA disagree about vta/pcs/vetter/recover — update one or the other ({e})"
                    ),
                },
                now,
            );
        }
        Ok(other) => {
            tracing::warn!(?other, "unexpected answer to vetter/recover");
            return VettingEffect::none();
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
    match words {
        Some(words) => VettingEffect(vec![Step::Persist(format!(
            "Hidden vetting at {name} — {words}."
        ))]),
        None => VettingEffect::none(),
    }
}

/// Plan sending the community the enrolment request the VTA built: recorded as asked and its
/// question filed, then signed and sent as the client's own step. A signing that fails un-files
/// the question, as a send that fails off the loop does, and is said. The time asked stays: the
/// VTA holds the request it built either way, and asking again within
/// [`ENROLMENT_ANSWER_WAIT`](openvtc_core::vetting::book::ENROLMENT_ANSWER_WAIT) would replace it.
fn plan_enrolment(
    state: &mut State,
    config: &mut Config,
    community: &str,
    persona: PersonaId,
    did: &str,
    request: &openvtc_core::vetting::wire::pcs::RootRequest,
    now: DateTime<Utc>,
) -> VettingEffect {
    let document = match wire::pcs_root_request(did, community, request) {
        Ok(d) => d,
        Err(e) => {
            show(state, Status::error(format!("Could not ask to enrol: {e}")));
            return VettingEffect::none();
        }
    };
    let document_id = document.id.clone();
    if let Some(held) = config.private.vetting.hidden_vetter_mut(community, persona) {
        held.enrol_asked_at = Some(now);
    }
    config.private.vetting.ask(CommunityQuery {
        document_id: document_id.clone(),
        community: community.to_string(),
        persona,
        kind: QueryKind::PcsRoot,
        sent_at: now,
    });
    show(
        state,
        Status::progress(format!(
            "Asking to enrol as a vetter under {}…",
            request.label
        )),
    );
    let sent = Sent::Query {
        document_id: document_id.clone(),
        community: community.to_string(),
        kind: QueryKind::PcsRoot,
    };
    VettingEffect(vec![Step::SendOrSay {
        persona,
        document: Box::new(document),
        sent: Box::new(sent),
        failed: "Could not ask to enrol",
        undo: vec![Undo::ForgetQuery(document_id)],
    }])
}

/// Plan sending the community a draw the VTA built: its question filed and the draw recorded
/// in flight, then signed and sent as the client's own step. A signing that fails takes both
/// back and is said; the schedule owes the draw again on its next pass.
fn plan_draw(
    state: &mut State,
    config: &mut Config,
    community: &str,
    persona: PersonaId,
    did: &str,
    request: &openvtc_core::vetting::wire::pcs::TokensRequest,
    now: DateTime<Utc>,
) -> VettingEffect {
    let document = match wire::pcs_tokens_request(did, community, request) {
        Ok(d) => d,
        Err(e) => {
            show(state, Status::error(format!("Could not draw tokens: {e}")));
            return VettingEffect::none();
        }
    };
    let document_id = document.id.clone();
    config.private.vetting.ask(CommunityQuery {
        document_id: document_id.clone(),
        community: community.to_string(),
        persona,
        kind: QueryKind::PcsTokens,
        sent_at: now,
    });
    config
        .private
        .vetting
        .draws_in_flight
        .insert(document_id.clone(), (request.label.clone(), request.tick));
    let sent = Sent::Query {
        document_id: document_id.clone(),
        community: community.to_string(),
        kind: QueryKind::PcsTokens,
    };
    VettingEffect(vec![Step::SendOrSay {
        persona,
        document: Box::new(document),
        sent: Box::new(sent),
        failed: "Could not draw tokens",
        undo: vec![
            Undo::ForgetQuery(document_id.clone()),
            Undo::NotDrawing(document_id),
        ],
    }])
}

/// Plan closing the request and sending the applicant the attestation the VTA made: the
/// request is closed and saved, then the message handed to the client's own send.
fn plan_attestation(
    state: &mut State,
    config: &mut Config,
    job: &openvtc_core::vetting::book::HiddenAttestJob,
    vetter_did: &str,
    session_id: &str,
    attestation: &Value,
    now: DateTime<Utc>,
) -> VettingEffect {
    let Some(previous) = config
        .private
        .vetting
        .desk_entry(&job.request_id)
        .map(|e| e.state.clone())
    else {
        return VettingEffect::none();
    };
    let message =
        match wire::hidden_attestation(vetter_did, &job.applicant, attestation, session_id) {
            Ok(message) => message,
            // The token is spent either way, but the request is not closed on a delivery that never
            // left.
            Err(e) => {
                show(
                    state,
                    Status::error(format!("Could not send the attestation: {e}")),
                );
                return VettingEffect::none();
            }
        };
    if let Err(e) = config.private.vetting.hidden_attested(&job.request_id, now) {
        show(
            state,
            Status::error(format!("Could not record the attestation: {e}")),
        );
        return VettingEffect::none();
    }
    let sent = Sent::Attestation {
        request_id: job.request_id.clone(),
        previous,
    };
    VettingEffect(vec![
        Step::Persist("Sending your attestation — it names nobody.".to_string()),
        Step::SendMessage {
            message: Box::new(message),
            from: vetter_did.to_string(),
            to: job.applicant.clone(),
            sent: Box::new(sent),
            claim: Claim::Unheld,
        },
    ])
}

/// Take the VTA's answer to an item a community or a vetter sent.
fn apply_pcs_inbound(
    state: &mut State,
    config: &mut Config,
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
            let book = &mut config.private.vetting;
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
                        config,
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
                        config,
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
                if let Some(held) = config
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
                    config,
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
                if let Some(held) = config
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
                let persona = config
                    .private
                    .vetting
                    .application_by_id(&application)
                    .map(|a| a.persona);
                if let Some(app) = config.private.vetting.application_by_id_mut(&application) {
                    app.hidden_app = Some(view);
                }
                pcs_notice(
                    config,
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
                show(
                    state,
                    Status::error(format!(
                        "A vetter's attestation was refused by your VTA: {e}"
                    )),
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

#[cfg(test)]
mod tests {
    use super::super::dispatch::panel;
    use super::super::test_support::hidden_vetter_book;
    use super::*;
    use crate::state_handler::dispatch_util::test_config;
    use openvtc_core::vetting::hidden::Due;
    use openvtc_core::vetting::wire::pcs::RootRequest;

    const FIRST: &str = "did:web:first-vtc.example";

    fn refused_draw(persona: PersonaId) -> PcsInbound {
        PcsInbound::DrawRefused {
            community: FIRST.into(),
            persona,
            label: "token/2026-10".into(),
            tick: 1,
        }
    }

    fn show_work(persona: PersonaId) -> PcsWork {
        PcsWork::VetterShow {
            community: FIRST.into(),
            persona,
            context_id: "openvtc/ctx".into(),
        }
    }

    #[test]
    fn work_is_gathered_only_with_a_vta_and_owing_nothing_says_so() {
        let mut config = test_config();
        let (book, persona) = hidden_vetter_book(0, true);
        config.private.vetting = book;
        config.private.vetting.pcs_due = true;

        let planned = plan_pcs_work(&mut config, false, vec![show_work(persona)]);
        assert!(matches!(planned, PcsStart::Unconnected));
        assert!(config.private.vetting.pcs_due, "kept for the sweep");

        let planned = plan_pcs_work(&mut config, true, Vec::new());
        assert!(matches!(planned, PcsStart::Nothing));
        assert!(!config.private.vetting.pcs_due);

        config.private.vetting.queue_for_vta(refused_draw(persona));
        let planned = plan_pcs_work(&mut config, true, vec![show_work(persona)]);
        let PcsStart::Job { inbox_taken, work } = planned else {
            panic!("a job");
        };
        assert_eq!(inbox_taken, 1);
        assert!(matches!(
            work.as_slice(),
            [PcsWork::Inbound { .. }, PcsWork::VetterShow { .. }]
        ));
        assert!(
            config.private.vetting.pcs_due,
            "claimed only when it starts"
        );
    }

    #[test]
    fn an_outcome_is_one_answer_a_step_then_the_bookkeeping() {
        let persona = PersonaId::new();
        let now = Utc::now();
        let effect = plan_pcs_outcome(
            PcsOutcome {
                inbox_taken: 2,
                results: vec![
                    (
                        PcsWork::Inbound {
                            item: refused_draw(persona),
                            context_id: None,
                            params: None,
                            vta_application: None,
                        },
                        Ok(PcsDone::Abandoned(None)),
                    ),
                    (
                        PcsWork::Inbound {
                            item: refused_draw(persona),
                            context_id: None,
                            params: None,
                            vta_application: None,
                        },
                        Err(PcsError::Unreachable("down".into())),
                    ),
                ],
            },
            now,
        );

        let [
            Step::PcsAnswer(first),
            Step::PcsAnswer(second),
            Step::PcsAnswer(last),
        ] = effect.0.as_slice()
        else {
            panic!("two answers, then the bookkeeping");
        };
        assert!(matches!(&**first, PcsAnswer::Result { result, .. } if result.is_ok()));
        assert!(matches!(&**second, PcsAnswer::Result { result, .. } if result.is_err()));
        let PcsAnswer::Settled {
            inbox_taken,
            finished,
            unreachable,
            ..
        } = &**last
        else {
            panic!("the bookkeeping last");
        };
        assert_eq!(*inbox_taken, 2);
        assert_eq!(finished, &vec![true, false]);
        assert!(unreachable.as_deref().is_some_and(|e| e.contains("down")));
    }

    #[test]
    fn settling_keeps_what_was_not_finished_and_backs_off() {
        let mut config = test_config();
        let mut state = State::default();
        let persona = PersonaId::new();
        for tick in [1, 2, 3] {
            config
                .private
                .vetting
                .pcs_inbox
                .push(PcsInbound::DrawRefused {
                    community: FIRST.into(),
                    persona,
                    label: "token/2026-10".into(),
                    tick,
                });
        }

        let effect = plan_pcs_answer(
            &mut state,
            &mut config,
            PcsAnswer::Settled {
                inbox_taken: 2,
                finished: vec![true, false],
                unreachable: Some("down".into()),
                now: Utc::now(),
            },
        );

        assert!(matches!(effect.0.as_slice(), [Step::MarkDirty]));
        let book = &config.private.vetting;
        let ticks: Vec<u32> = book
            .pcs_inbox
            .iter()
            .map(|i| match i {
                PcsInbound::DrawRefused { tick, .. } => *tick,
                _ => 0,
            })
            .collect();
        assert_eq!(ticks, vec![2, 3], "the unfinished one, then the new");
        assert_eq!(book.pcs_failures, 1);
        assert!(book.pcs_retry_at.is_some());
        assert!(book.pcs_due);
    }

    #[test]
    fn an_enrolment_is_recorded_and_filed_then_sent_or_said() {
        let mut config = test_config();
        let mut state = State::default();
        let (book, persona) = hidden_vetter_book(0, false);
        config.private.vetting = book;
        let now = Utc::now();
        let params = config.private.vetting.hidden_vetter[0].params.clone();

        let effect = plan_pcs_answer(
            &mut state,
            &mut config,
            PcsAnswer::Result {
                work: Box::new(PcsWork::Owed {
                    community: FIRST.into(),
                    persona,
                    context_id: "openvtc/ctx".into(),
                    did: "did:key:zVetter".into(),
                    params,
                    owed: Due::Enrol {
                        period: "2026-10".into(),
                    },
                }),
                result: Box::new(Ok(PcsDone::Root(RootRequest {
                    label: "vetter/2026-10".into(),
                    id: "z3Vetter".into(),
                    request: serde_json::json!({}),
                }))),
                now,
            },
        );

        assert_eq!(
            config.private.vetting.hidden_vetter[0].enrol_asked_at,
            Some(now)
        );
        assert!(
            config
                .private
                .vetting
                .waiting_on(FIRST, QueryKind::PcsRoot)
                .is_some()
        );
        assert_eq!(
            panel(&mut state).status_message,
            Some(Status::progress(
                "Asking to enrol as a vetter under vetter/2026-10…"
            ))
        );
        let [
            Step::SendOrSay {
                persona: signer,
                failed,
                undo,
                ..
            },
        ] = effect.0.as_slice()
        else {
            panic!("signed and sent, or said");
        };
        assert_eq!(*signer, persona);
        assert_eq!(*failed, "Could not ask to enrol");
        let filed = config
            .private
            .vetting
            .waiting_on(FIRST, QueryKind::PcsRoot)
            .unwrap()
            .document_id
            .clone();
        assert_eq!(undo, &vec![Undo::ForgetQuery(filed)]);
    }

    #[test]
    fn an_attestation_for_a_request_gone_from_the_desk_is_dropped() {
        let mut config = test_config();
        let mut state = State::default();
        let persona = PersonaId::new();
        let effect = plan_pcs_answer(
            &mut state,
            &mut config,
            PcsAnswer::Result {
                work: Box::new(PcsWork::Attest {
                    job: openvtc_core::vetting::book::HiddenAttestJob {
                        request_id: "gone".into(),
                        community: FIRST.into(),
                        persona,
                        applicant: "did:key:zJoiner".into(),
                        applicant_id: "zId".into(),
                        meta: serde_json::json!({}),
                        params: hidden_vetter_book(0, false).0.hidden_vetter[0]
                            .params
                            .clone(),
                    },
                    context_id: "openvtc/ctx".into(),
                    vetter_did: "did:key:zVetter".into(),
                    session_id: "s".into(),
                }),
                result: Box::new(Ok(PcsDone::Attested(serde_json::json!({})))),
                now: Utc::now(),
            },
        );
        assert!(effect.0.is_empty());
        assert!(panel(&mut state).status_message.is_none());
    }
}
