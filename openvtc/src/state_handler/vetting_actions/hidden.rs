//! Hidden vetting from the vetter's side: the token schedule tick, minting the
//! engine, and attesting without a statement; plus the applicant's challenge request.

use crate::state_handler::main_page::status::Status;
use chrono::{DateTime, Utc};
use openvtc_core::config::Config;
use openvtc_core::config::account::PersonaId;
use openvtc_core::config::community_context;
use openvtc_core::vetting::book::{Adopted, DrawHold};
use openvtc_core::vetting::queries::{CommunityQuery, QueryKind};
use openvtc_core::vetting::vetter::Attestation;
use openvtc_core::vetting::wire;

use super::desk::session_id_of;
use super::dispatch::{page, persist, status};
use super::jobs::Sent;
use super::pcs::start_pcs_work;
use super::send::{Claim, abandon, persona_did, sign_and_send};
use super::words::{community_display, outlook_words};
use crate::state_handler::background_dispatch::{DispatchDomain, InFlight};
use crate::state_handler::hidden_vetting_vta::PcsWork;
use crate::state_handler::main_page::content::VettingMode;
use crate::state_handler::runtime_actions::ActionCtx;
use openvtc_core::vetting::book::PcsInbound;

/// Attest the hidden way: no statement, no signature, nothing that names this vetter.
///
/// Split from [`attest`](crate::state_handler::vetting_actions::desk::attest) rather than branched inside it because the two paths diverge at every
/// step after the draft — what is produced, what is recorded, what is sent, and what the operator
/// is told. The refusals an operator can act on are surfaced in their own words: a vetter with no
/// tokens left has not failed, it is at capacity until the next drip.
/// Ask the community for the challenge this submission must bind.
///
/// Called when an applicant refreshes a hidden-vetting application. The join does not depend
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
    status(
        ctx,
        Status::progress("Asking the community for a submission challenge…"),
    );
    let sent = Sent::Query {
        document_id,
        community: app.community.clone(),
        kind: QueryKind::PcsChallenge,
    };
    if let Err(e) = sign_and_send(ctx, app.persona, document, sent, Claim::Unheld).await {
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
///
/// What is owed goes into `work`, for the VTA to build: the pass runs one job for every
/// community ([`refresh_vetter_side`](crate::state_handler::vetting_actions::desk::refresh_vetter_side)), and what the VTA builds is sent when the job is back
/// ([`apply_pcs_outcome`](crate::state_handler::vetting_actions::pcs::apply_pcs_outcome)).
pub(crate) fn hidden_vetting_tick(
    ctx: &mut ActionCtx<'_>,
    community: &str,
    work: &mut Vec<PcsWork>,
) {
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
    let Some(context_id) = vetter_context(ctx.config, state.persona) else {
        return;
    };
    // Never a second enrolment while one is unanswered: the community answers the first and
    // refuses the second (`alreadyEnrolled`), and that refusal would read as a lost answer.
    // The first's answer is taken whenever it lands — the VTA holds its blinding.
    let enrolling = |owed: &openvtc_core::vetting::hidden::Due| match owed {
        openvtc_core::vetting::hidden::Due::Enrol { period } => {
            ctx.config
                .private
                .vetting
                .waiting_on(community, QueryKind::PcsRoot)
                .is_some()
                || state.enrolment_pending(period, now)
        }
        _ => false,
    };
    // What the VTA holds first, so the screens and the next plan read its word, then what the
    // schedule owes — each built by the VTA and sent from the loop when the job is back.
    work.push(PcsWork::VetterShow {
        community: community.to_string(),
        persona: state.persona,
        context_id: context_id.clone(),
    });
    // The community bound us to a key the engine does not hold: the VTA is asked to restore
    // it, once ([`openvtc_core::vetting::binding`]). Enrolment is held in the plan until then.
    if let Some(bound_id) = state.recovery_due() {
        work.push(PcsWork::Recover {
            community: community.to_string(),
            persona: state.persona,
            context_id: context_id.clone(),
            did: did.clone(),
            bound_id: bound_id.to_string(),
        });
    }
    for owed in plan.owed {
        if enrolling(&owed) {
            continue;
        }
        // A tick the VTA still holds a draw for, whose question here is gone (it timed out, or a
        // restart forgot it): the VTA refuses a second draw for it (`alreadyInFlight`), so its
        // stale draw is dropped first and the tick asked for afresh.
        if let openvtc_core::vetting::hidden::Due::Draw { label, tick, .. } = &owed
            && state
                .engine
                .draws_in_flight
                .iter()
                .any(|d| &d.label == label && d.tick == *tick)
        {
            work.push(PcsWork::Inbound {
                item: PcsInbound::DrawRefused {
                    community: community.to_string(),
                    persona: state.persona,
                    label: label.clone(),
                    tick: *tick,
                },
                context_id: Some(context_id.clone()),
                params: Some(state.params.clone()),
                vta_application: None,
            });
        }
        work.push(PcsWork::Owed {
            community: community.to_string(),
            persona: state.persona,
            context_id: context_id.clone(),
            did: did.clone(),
            params: state.params.clone(),
            owed,
        });
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
pub(super) fn ensure_hidden_vetter(ctx: &mut ActionCtx<'_>, community: &str) {
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
    if persona_did(ctx.config, standing.persona).is_none() {
        return;
    }
    // The engine itself is the VTA's, created by the first enrolment request: one key per
    // (context, community) for life, bound to this persona's DID (`vta/pcs/root-request`).
    let mut held =
        openvtc_core::vetting::book::HiddenVetterState::new(community, standing.persona, params);
    // The parameters are the last manifest's; dated by it, so the first draw follows a read.
    let reading = ctx.config.private.vetting.vetter_mode(community);
    held.params_read_at = reading
        .read
        .filter(|_| !reading.inferred)
        .map(|r| r.read_at);
    ctx.config.private.vetting.hidden_vetter.push(held);
    ctx.save.mark_dirty();
    status(
        ctx,
        Status::progress(format!(
            "{} hides its vetters. Enrolling you — your attestations there will name nobody.",
            community_display(ctx.config, community)
        )),
    );
}

pub(super) async fn attest_hidden(
    ctx: &mut ActionCtx<'_>,
    request_id: &str,
    entry: &openvtc_core::vetting::vetter::DeskEntry,
    vetter_did: &str,
    attestation: Attestation,
    now: DateTime<Utc>,
) {
    let job = match ctx.config.private.vetting.hidden_attestation_job(
        request_id,
        vetter_did,
        attestation,
        now,
    ) {
        Ok(job) => job,
        Err(e) => return cannot_attest_hidden(ctx, entry, &e.to_string(), is_wait(&e), now),
    };
    let Some(session_id) = session_id_of(entry) else {
        return status(
            ctx,
            Status::warning("This request has no open session to attest on."),
        );
    };
    let Some(context_id) = vetter_context(ctx.config, entry.persona) else {
        return status(
            ctx,
            Status::error("The persona this request was made to is not available."),
        );
    };
    let work = PcsWork::Attest {
        job,
        context_id,
        vetter_did: vetter_did.to_string(),
        session_id,
    };
    if start_pcs_work(ctx, vec![work]) {
        page(ctx).mode = VettingMode::List;
        status(
            ctx,
            Status::progress("Your VTA is making the attestation — it names nobody…"),
        );
    } else {
        status(
            ctx,
            Status::warning(format!(
                "{} — attest again in a moment. Nothing was sent; the request stays open.",
                InFlight::busy_message(DispatchDomain::HiddenVetting)
            )),
        );
    }
}

/// Whether a refusal to attest is a state the vetter waits out: no credential yet, or no token.
fn is_wait(e: &openvtc_core::vetting::vetter::VetterError) -> bool {
    use openvtc_core::vetting::{hidden::HiddenError, vetter::VetterError};
    matches!(
        e,
        VetterError::Hidden(HiddenError::NoToken | HiddenError::NotEnrolled)
    )
}

/// Say why nothing was attested. No credential or no token is a state the vetter waits out: say
/// how long, from the schedule, rather than a bare refusal.
pub(super) fn cannot_attest_hidden(
    ctx: &mut ActionCtx<'_>,
    entry: &openvtc_core::vetting::vetter::DeskEntry,
    why: &str,
    waiting: bool,
    now: DateTime<Utc>,
) {
    let outlook = ctx
        .config
        .private
        .vetting
        .hidden_outlook(&entry.community, entry.persona, now)
        .filter(|_| waiting);
    status(
        ctx,
        Status::error(match outlook {
            Some(o) => format!(
                "Cannot attest yet: {why}. Nothing was sent; the request stays open. {}: {}.{}",
                community_display(ctx.config, &entry.community),
                outlook_words(&o, now),
                if o.events_offered {
                    " Vetting at one of its events (e) draws more."
                } else {
                    ""
                }
            ),
            None => format!("Cannot attest: {why}"),
        }),
    );
}

/// The VTA context a persona's vetter engines live in: the persona's own.
pub(super) fn vetter_context(config: &Config, persona: PersonaId) -> Option<String> {
    let top = config.account.top_context_id.as_str();
    config
        .account
        .personas
        .get(&persona)
        .map(|p| community_context::persona_context(p, top).to_string())
}
