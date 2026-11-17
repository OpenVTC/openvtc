//! Hidden (PCS ZKP) vetting on the Vetting page: the vetter schedule's pass
//! for one community, minting the vetter's engine, attesting without a
//! statement, the key check and the draw asked for by hand, and the
//! applicant's request for a submission challenge.
//!
//! Each is a pure plan over the state, the book, and the time it was asked
//! (`plan_*`, [`hidden_vetting_tick`]'s plan, [`ensure_hidden_vetter`]) that
//! returns a [`VettingEffect`]; the sends are the client's own
//! ([`Claim::Unheld`]), and the work for the VTA goes through
//! [`super::pcs`]. [`hidden_vetting_tick`] keeps the signature its loop-side
//! caller uses, and plans then runs.

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
use super::dispatch::{panel, show};
use super::effect::{Abort, PcsCommit, Step, Undo, VettingEffect, run_local};
use super::jobs::Sent;
use super::pcs::plan_pcs_work;
use super::send::{Claim, give_up, persona_did};
use super::words::{clause, community_display, get_tokens_words, hides_vetters, outlook_words};
use crate::state_handler::background_dispatch::{DispatchDomain, InFlight};
use crate::state_handler::hidden_vetting_vta::PcsWork;
use crate::state_handler::runtime_actions::ActionCtx;
use crate::state_handler::state::State;
use openvtc_core::vetting::book::PcsInbound;

/// What a challenge request that cannot be sent gives up saying.
const CHALLENGE_FAILED: &str = "Could not ask for a submission challenge";

/// Ask the community for the challenge this submission must bind.
///
/// Called when an applicant refreshes a hidden-vetting application. The join does not depend
/// on it: a launch asks for a fresh challenge of its own and waits for it
/// (`join_flow::challenge_step`). The community issues one per applicant and spends it when the
/// proof is read, so asking twice replaces rather than accumulates — which is why this is safe
/// to call again on a retry. `announce` is whether to say it is asking: not when the status
/// already says why something asked for alongside it did not happen.
///
/// The plan files the question and says so (when `announce`); the effect signs and sends it as
/// the client's own step, never refused for a busy domain. A signing or send that fails
/// un-files the question, as a send that fails off the loop does.
pub(super) fn plan_ask_for_challenge(
    state: &mut State,
    config: &mut Config,
    application_id: &str,
    announce: bool,
) -> VettingEffect {
    let Some(app) = config
        .private
        .vetting
        .applications
        .iter()
        .find(|a| a.id == application_id && a.hidden.is_some())
        .cloned()
    else {
        return VettingEffect::none();
    };
    let document = match wire::pcs_challenge_request(&app.join_did, &app.community, None) {
        Ok(d) => d,
        Err(e) => {
            give_up(state, config, CHALLENGE_FAILED, e);
            return VettingEffect::none();
        }
    };
    let document_id = document.id.clone();
    config.private.vetting.ask(CommunityQuery {
        document_id: document_id.clone(),
        community: app.community.clone(),
        persona: app.persona,
        kind: QueryKind::PcsChallenge,
        sent_at: Utc::now(),
    });
    if announce {
        show(
            state,
            Status::progress("Asking the community for a submission challenge…"),
        );
    }
    let sent = Sent::Query {
        document_id: document_id.clone(),
        community: app.community.clone(),
        kind: QueryKind::PcsChallenge,
    };
    VettingEffect::sign_and_send(
        [],
        app.persona,
        document,
        sent,
        Claim::Unheld,
        Abort::undoing(CHALLENGE_FAILED, vec![Undo::ForgetQuery(document_id)]),
    )
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
///
/// Planned by [`plan_hidden_vetting_tick`]; its steps are local (a save, a status), so they are
/// run here without awaiting, before the pass moves on to the next community.
pub(crate) fn hidden_vetting_tick(
    ctx: &mut ActionCtx<'_>,
    community: &str,
    work: &mut Vec<PcsWork>,
) {
    let effect = plan_hidden_vetting_tick(ctx.state, ctx.config, community, Utc::now(), work);
    run_local(ctx, effect);
}

/// Plan [`hidden_vetting_tick`] at `now`: make the book changes the schedule owes, push the
/// VTA's work onto `work`, and return the saves and statuses left — a minted engine's mark and
/// word, then a re-key's save, or the schedule's mark.
pub(super) fn plan_hidden_vetting_tick(
    state: &mut State,
    config: &mut Config,
    community: &str,
    now: DateTime<Utc>,
    work: &mut Vec<PcsWork>,
) -> VettingEffect {
    let mut steps = ensure_hidden_vetter(config, community, now);
    let book = &mut config.private.vetting;
    let Some(index) = book
        .hidden_vetter
        .iter()
        .position(|h| h.community == community)
    else {
        return VettingEffect(steps);
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
    let held = book.hidden_vetter[index].clone();
    let changed = plan.settled || plan.adopted != Adopted::Unchanged;
    if let Adopted::Rekeyed { first } = plan.adopted {
        if first {
            let name = community_display(config, community);
            steps.push(Step::Persist(format!(
                "{name} now publishes different hidden-vetting keys from the ones you \
                 enrolled under. The tokens and credential you hold there count for nothing \
                 under the new keys, so drawing has stopped. Ask the community whether it \
                 re-keyed; see the Hidden vetting view (h on the desk)."
            )));
            tracing::warn!(community = %community, "hidden-vetting keys changed since enrolment; the drip has stopped");
        }
        return VettingEffect(steps);
    }
    if changed {
        steps.push(Step::MarkDirty);
        state.main_page.sync_panels(
            config,
            crate::state_handler::main_page::Panels::FROM_VETTING_BOOK,
        );
    }
    let Some(did) = persona_did(config, held.persona) else {
        return VettingEffect(steps);
    };
    let Some(context_id) = vetter_context(config, held.persona) else {
        return VettingEffect(steps);
    };
    // Never a second enrolment while one is unanswered: the community answers the first and
    // refuses the second (`alreadyEnrolled`), and that refusal would read as a lost answer.
    // The first's answer is taken whenever it lands — the VTA holds its blinding.
    let enrolling = |owed: &openvtc_core::vetting::hidden::Due| match owed {
        openvtc_core::vetting::hidden::Due::Enrol { period } => {
            config
                .private
                .vetting
                .waiting_on(community, QueryKind::PcsRoot)
                .is_some()
                || held.enrolment_pending(period, now)
        }
        _ => false,
    };
    // What the VTA holds first, so the screens and the next plan read its word, then what the
    // schedule owes — each built by the VTA and sent from the loop when the job is back.
    work.push(PcsWork::VetterShow {
        community: community.to_string(),
        persona: held.persona,
        context_id: context_id.clone(),
    });
    // The community bound us to a key the engine does not hold: the VTA is asked to restore
    // it, once ([`openvtc_core::vetting::binding`]). Enrolment is held in the plan until then.
    if let Some(bound_id) = held.recovery_due() {
        work.push(PcsWork::Recover {
            community: community.to_string(),
            persona: held.persona,
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
            && held
                .engine
                .draws_in_flight
                .iter()
                .any(|d| &d.label == label && d.tick == *tick)
        {
            work.push(PcsWork::Inbound {
                item: PcsInbound::DrawRefused {
                    community: community.to_string(),
                    persona: held.persona,
                    label: label.clone(),
                    tick: *tick,
                },
                context_id: Some(context_id.clone()),
                params: Some(held.params.clone()),
                vta_application: None,
            });
        }
        work.push(PcsWork::Owed {
            community: community.to_string(),
            persona: held.persona,
            context_id: context_id.clone(),
            did: did.clone(),
            params: held.params.clone(),
            owed,
        });
    }
    VettingEffect(steps)
}

/// Mint this vetter's engine for a community, the first time we learn it runs hidden vetting
/// and has named us a vetter. Returns the steps that follow minting one — the save, and the
/// word that enrolment is starting — or none.
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
pub(super) fn ensure_hidden_vetter(
    config: &mut Config,
    community: &str,
    now: DateTime<Utc>,
) -> Vec<Step> {
    let book = &config.private.vetting;
    if book.hidden_vetter.iter().any(|h| h.community == community) {
        return Vec::new();
    }
    let Some(params) = book.hidden_published.get(community).cloned() else {
        return Vec::new();
    };
    let Some(standing) = book
        .vetter_standing(now)
        .into_iter()
        .find(|s| s.community == community && s.live)
    else {
        return Vec::new();
    };
    if persona_did(config, standing.persona).is_none() {
        return Vec::new();
    }
    // The engine itself is the VTA's, created by the first enrolment request: one key per
    // (context, community) for life, bound to this persona's DID (`vta/pcs/root-request`).
    let mut held =
        openvtc_core::vetting::book::HiddenVetterState::new(community, standing.persona, params);
    // The parameters are the last manifest's; dated by it, so the first draw follows a read.
    let reading = config.private.vetting.vetter_mode(community);
    held.params_read_at = reading
        .read
        .filter(|_| !reading.inferred)
        .map(|r| r.read_at);
    config.private.vetting.hidden_vetter.push(held);
    vec![
        Step::MarkDirty,
        Step::Status(Status::progress(format!(
            "{} hides its vetters. Enrolling you — your attestations there will name nobody.",
            community_display(config, community)
        ))),
    ]
}

/// Plan the key check (`k` on the hidden view): restart the check of the key the community
/// bound us to, where it is in question, then run the vetter pass that asks the community.
pub(super) fn plan_check_hidden_key(
    state: &mut State,
    config: &mut Config,
    now: DateTime<Utc>,
) -> VettingEffect {
    let index = match panel(state).mode {
        crate::state_handler::main_page::content::VettingMode::HiddenVetting { index } => index,
        _ => 0,
    };
    let Some(held) = config.private.vetting.hidden_vetter.get_mut(index) else {
        return VettingEffect::none();
    };
    let community = held.community.clone();
    let started = held.recheck_key(now);
    let name = community_display(config, &community);
    if started {
        VettingEffect(vec![
            Step::MarkDirty,
            Step::Status(Status::progress(format!(
                "Asking {name} which hidden-vetting key it holds for you, to restore it at \
                 your VTA…"
            ))),
            Step::RefreshVetterSide,
        ])
    } else {
        show(
            state,
            Status::warning(format!(
                "Nothing to check at {name}: your hidden-vetting key is not in question, or a \
                 check is already running."
            )),
        );
        VettingEffect::none()
    }
}

/// Plan "get tokens" (`d`): whatever the schedule owes, in order — enrol where not enrolled,
/// then draw every window that has begun — and, per community, exactly what is happening or
/// what blocks it and until when. Said from the book as it was before the pass, which is what
/// the pass acts on, once the pass has run — unless the pass said a warning or an error, which
/// stays on the status line ([`Step::Summary`]).
pub(super) fn plan_draw_now(config: &mut Config, now: DateTime<Utc>) -> VettingEffect {
    // Asked by hand: a lost enrolment is worth one more ask — the community may now re-issue it
    // to the same identifier, and it bounds how many times it will.
    for held in &mut config.private.vetting.hidden_vetter {
        held.lost_reasked = false;
    }
    let words: Vec<String> = {
        let book = &config.private.vetting;
        book.vetter_standing(now)
            .into_iter()
            .filter(|s| s.live && hides_vetters(book, &s.community))
            .map(|s| {
                let name = community_display(config, &s.community);
                let why = get_tokens_words(book, &s.community, s.persona, &name, now);
                format!("{name}: {}.", clause(&why))
            })
            .collect()
    };
    VettingEffect(vec![
        Step::RefreshVetterSide,
        Step::Summary(Status::info(if words.is_empty() {
            "None of the communities you vet for proves vetting with PCS ZKP, so there are no \
             tokens to get — hand out tickets with t."
                .to_string()
        } else {
            format!("Getting tokens — {}", words.join(" "))
        })),
    ])
}

/// Plan Enter on the hidden view: "draw now", as `d` is — the view's one verb.
pub(super) fn plan_hidden_view_submit(state: &mut State) -> VettingEffect {
    show(
        state,
        Status::progress(
            "Reading each community's requirements again and drawing what the schedule owes…",
        ),
    );
    VettingEffect(vec![Step::RefreshVetterSide])
}

/// Attest the hidden way: no statement, no signature, nothing that names this vetter.
///
/// Split from [`plan_attest`](crate::state_handler::vetting_actions::desk::plan_attest) rather
/// than branched inside it because the two paths diverge at every step after the draft — what is produced, what is recorded, what is sent, and what the operator
/// is told. The refusals an operator can act on are surfaced in their own words: a vetter with no
/// tokens left has not failed, it is at capacity until the next drip.
///
/// The plan builds the job, and hands it to the VTA with whatever else is owed there. `connected` is whether an admin VTA session is held: without one nothing can be
/// attested this way, and that is said first, apart from a busy VTA (R6.4). The list view and
/// the progress word follow only a job that started; one that did not says so and leaves the
/// request open.
#[allow(clippy::too_many_arguments)]
pub(super) fn plan_attest_hidden(
    state: &mut State,
    config: &mut Config,
    connected: bool,
    request_id: &str,
    entry: &openvtc_core::vetting::vetter::DeskEntry,
    vetter_did: &str,
    attestation: Attestation,
    now: DateTime<Utc>,
) -> VettingEffect {
    if !connected {
        show(state, Status::error(ATTEST_UNCONNECTED));
        return VettingEffect::none();
    }
    let job = match config.private.vetting.hidden_attestation_job(
        request_id,
        vetter_did,
        attestation,
        now,
    ) {
        Ok(job) => job,
        Err(e) => {
            cannot_attest_hidden(state, config, entry, &e.to_string(), is_wait(&e), now);
            return VettingEffect::none();
        }
    };
    let Some(session_id) = session_id_of(entry) else {
        show(
            state,
            Status::warning("This request has no open session to attest on."),
        );
        return VettingEffect::none();
    };
    let Some(context_id) = vetter_context(config, entry.persona) else {
        show(
            state,
            Status::error("The persona this request was made to is not available."),
        );
        return VettingEffect::none();
    };
    let work = PcsWork::Attest {
        job,
        context_id,
        vetter_did: vetter_did.to_string(),
        session_id,
    };
    VettingEffect(vec![Step::StartPcs {
        start: plan_pcs_work(config, connected, vec![work]),
        commit: Some(PcsCommit::Attesting),
        refused: Some(Status::warning(format!(
            "{} — attest again in a moment. Nothing was sent; the request stays open.",
            InFlight::busy_message(DispatchDomain::HiddenVetting)
        ))),
    }])
}

/// What a hidden attestation says with no VTA session to make it.
const ATTEST_UNCONNECTED: &str = "A hidden attestation is made by your VTA, and it is not \
     connected — attest again once it is. Nothing was sent; the request stays open.";

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
    state: &mut State,
    config: &Config,
    entry: &openvtc_core::vetting::vetter::DeskEntry,
    why: &str,
    waiting: bool,
    now: DateTime<Utc>,
) {
    let outlook = config
        .private
        .vetting
        .hidden_outlook(&entry.community, entry.persona, now)
        .filter(|_| waiting);
    show(
        state,
        Status::error(match outlook {
            Some(o) => format!(
                "Cannot attest yet: {why}. Nothing was sent; the request stays open. {}: {}.{}",
                community_display(config, &entry.community),
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

#[cfg(test)]
mod tests {
    use super::super::effect::Abort;
    use super::super::test_support::hidden_vetter_book;
    use super::*;
    use crate::state_handler::dispatch_util::test_config;
    use crate::state_handler::main_page::content::VettingMode;
    use crate::state_handler::main_page::status::Severity;
    use openvtc_core::vetting::book::HiddenRefusal;
    use openvtc_core::vetting::hidden::HiddenParams;

    const FIRST: &str = "did:web:first-vtc.example";

    fn said(state: &mut State) -> Status {
        panel(state)
            .status_message
            .clone()
            .expect("the page says something")
    }

    #[test]
    fn a_challenge_is_filed_said_then_signed_and_sent_unheld() {
        let mut config = test_config();
        let mut state = State::default();
        let persona = PersonaId::new();
        let id = config
            .private
            .vetting
            .start_application(FIRST, persona, "did:key:zJoin", Utc::now())
            .unwrap()
            .id
            .clone();

        // Not a hidden application: nothing asked.
        let effect = plan_ask_for_challenge(&mut state, &mut config, &id, true);
        assert!(effect.0.is_empty());
        assert!(config.private.vetting.queries.is_empty());

        let params = hidden_vetter_book(0, false).0.hidden_vetter[0]
            .params
            .clone();
        config
            .private
            .vetting
            .application_by_id_mut(&id)
            .unwrap()
            .hidden = Some(params);
        let effect = plan_ask_for_challenge(&mut state, &mut config, &id, true);

        assert!(
            config
                .private
                .vetting
                .waiting_on(FIRST, QueryKind::PcsChallenge)
                .is_some()
        );
        assert_eq!(
            said(&mut state),
            Status::progress("Asking the community for a submission challenge…")
        );
        let [
            Step::Sign {
                persona: signer,
                abort,
                ..
            },
            Step::Send {
                claim: Claim::Unheld,
                abort: same,
                ..
            },
        ] = effect.0.as_slice()
        else {
            panic!("signed, then sent unheld");
        };
        assert_eq!(*signer, persona);
        // A failure before it goes out un-files the question.
        let filed = config.private.vetting.queries[0].document_id.clone();
        assert_eq!(
            abort,
            &Abort::undoing(CHALLENGE_FAILED, vec![Undo::ForgetQuery(filed)])
        );
        assert_eq!(same, abort);

        // Asked quietly, it leaves the status line to what said why before it.
        let refused = Status::warning("refused");
        panel(&mut state).status_message = Some(refused.clone());
        let effect = plan_ask_for_challenge(&mut state, &mut config, &id, false);
        assert_eq!(effect.0.len(), 2, "still signed and sent");
        assert_eq!(said(&mut state), refused);
    }

    #[test]
    fn a_tick_with_no_engine_and_no_grant_owes_nothing() {
        let mut config = test_config();
        let mut state = State::default();
        let params = hidden_vetter_book(0, false).0.hidden_vetter[0]
            .params
            .clone();
        config
            .private
            .vetting
            .hidden_published
            .insert(FIRST.into(), params);
        let mut work = Vec::new();

        let effect =
            plan_hidden_vetting_tick(&mut state, &mut config, FIRST, Utc::now(), &mut work);

        assert!(effect.0.is_empty());
        assert!(work.is_empty());
        assert!(config.private.vetting.hidden_vetter.is_empty());
    }

    #[test]
    fn a_rekeyed_community_is_saved_and_said_once_and_owes_the_vta_nothing() {
        let mut config = test_config();
        let mut state = State::default();
        let (book, _) = hidden_vetter_book(0, true);
        let rekeyed = HiddenParams {
            token_key: "zSomeOtherTokenKey".into(),
            ..book.hidden_vetter[0].params.clone()
        };
        config.private.vetting = book;
        config
            .private
            .vetting
            .hidden_published
            .insert(FIRST.into(), rekeyed);
        let mut work = Vec::new();

        let effect =
            plan_hidden_vetting_tick(&mut state, &mut config, FIRST, Utc::now(), &mut work);
        let [Step::Persist(message)] = effect.0.as_slice() else {
            panic!("saved and said");
        };
        assert!(
            message.contains("now publishes different hidden-vetting keys"),
            "{message}"
        );
        assert!(work.is_empty());

        let effect =
            plan_hidden_vetting_tick(&mut state, &mut config, FIRST, Utc::now(), &mut work);
        assert!(effect.0.is_empty(), "said once");
        assert!(work.is_empty());
    }

    #[test]
    fn checking_a_key_restarts_the_check_then_runs_the_pass() {
        let mut config = test_config();
        let mut state = State::default();
        config.private.vetting = hidden_vetter_book(0, true).0;
        panel(&mut state).mode = VettingMode::HiddenVetting { index: 0 };

        let effect = plan_check_hidden_key(&mut state, &mut config, Utc::now());
        assert!(effect.0.is_empty());
        assert_eq!(said(&mut state).severity, Severity::Warning);

        config.private.vetting.hidden_vetter[0].last_refusal = Some(HiddenRefusal {
            what: "enrol".into(),
            code: "vtc/pcs:identifierRebound".into(),
            at: Utc::now(),
        });
        let effect = plan_check_hidden_key(&mut state, &mut config, Utc::now());
        assert!(config.private.vetting.hidden_vetter[0].key.is_some());
        let [Step::MarkDirty, Step::Status(word), Step::RefreshVetterSide] = effect.0.as_slice()
        else {
            panic!("saved, said, then the pass");
        };
        assert!(word.text.starts_with("Asking "), "{}", word.text);

        // An index past the engines: nothing.
        panel(&mut state).mode = VettingMode::HiddenVetting { index: 5 };
        assert!(
            plan_check_hidden_key(&mut state, &mut config, Utc::now())
                .0
                .is_empty()
        );
    }

    #[test]
    fn drawing_by_hand_reasks_then_runs_the_pass_then_says_what_it_did() {
        let mut config = test_config();
        config.private.vetting = hidden_vetter_book(0, true).0;
        config.private.vetting.hidden_vetter[0].lost_reasked = true;

        let effect = plan_draw_now(&mut config, Utc::now());

        assert!(!config.private.vetting.hidden_vetter[0].lost_reasked);
        let [Step::RefreshVetterSide, Step::Summary(word)] = effect.0.as_slice() else {
            panic!("the pass, then what it did");
        };
        assert_eq!(word.severity, Severity::Info);
        assert!(
            word.text.starts_with("None of the communities"),
            "no live grant: {}",
            word.text
        );
    }

    #[test]
    fn enter_on_the_hidden_view_says_so_then_runs_the_pass() {
        let mut state = State::default();
        let effect = plan_hidden_view_submit(&mut state);
        assert!(matches!(effect.0.as_slice(), [Step::RefreshVetterSide]));
        assert_eq!(said(&mut state).severity, Severity::Progress);
    }

    #[test]
    fn attesting_on_a_request_not_yet_attestable_or_without_a_vta_says_why_and_starts_nothing() {
        use openvtc_core::vetting::vetter::{DeskEntry, DeskState};
        use vta_sdk::protocols::vetting::request;
        let mut config = test_config();
        let mut state = State::default();
        let now = Utc::now();
        let ticket = request::v0_1::Ticket::ShortCodeTicket(
            request::v0_1::ShortCodeTicket::try_from(
                request::v0_1::ShortCodeTicket::builder().code("0000-0000"),
            )
            .unwrap(),
        );
        let entry = DeskEntry {
            request_id: "req-1".into(),
            request_document_id: "doc-1".into(),
            applicant: "did:key:zJoiner".into(),
            community: FIRST.into(),
            persona: PersonaId::new(),
            ticket_id: None,
            request: request::v0_1::Payload::try_from(
                request::v0_1::Payload::builder()
                    .community(FIRST)
                    .join_did("did:key:zJoiner")
                    .ticket(Some(ticket)),
            )
            .unwrap(),
            state: DeskState::Accepted,
            received_at: now,
            updated_at: now,
        };
        config.private.vetting.desk.push(entry.clone());
        let attestation = Attestation {
            method: crate::state_handler::main_page::content::VETTING_METHODS[0],
            document_classes: Vec::new(),
            claims_verified: Vec::new(),
            liveness_confirmed: false,
            declared_relationship: crate::state_handler::main_page::content::VETTING_RELATIONSHIPS
                [0],
            attestation_text_digest: None,
        };

        let effect = plan_attest_hidden(
            &mut state,
            &mut config,
            true,
            "req-1",
            &entry,
            "did:key:zVetter",
            attestation.clone(),
            now,
        );

        assert!(effect.0.is_empty());
        let word = said(&mut state);
        assert_eq!(word.severity, Severity::Error);
        assert!(word.text.starts_with("Cannot attest: "), "{}", word.text);

        // With no VTA session it says so, not that the VTA is busy.
        let effect = plan_attest_hidden(
            &mut state,
            &mut config,
            false,
            "req-1",
            &entry,
            "did:key:zVetter",
            attestation,
            now,
        );
        assert!(effect.0.is_empty());
        assert_eq!(said(&mut state), Status::error(ATTEST_UNCONNECTED));
        assert!(ATTEST_UNCONNECTED.contains("not connected"));
        assert!(!ATTEST_UNCONNECTED.contains("busy"));
    }
}
