//! Shared sending helpers: checking the vetting domain is free, giving up on
//! a send before it started, signing a message on the loop and handing its
//! send to a background job, which claims the domain when it is dispatched.
//!
//! The pure halves ([`claimable`], [`give_up`]) are what a plan uses; the
//! effect runner ([`super::effect::run`]) and the handlers not yet planned use
//! the rest.

use crate::state_handler::main_page::status::Status;
use affinidi_tdk::didcomm::Message;
use openvtc_core::config::Config;
use openvtc_core::config::account::PersonaId;
use openvtc_core::vetting::queries::{CommunityQuery, QueryKind};
use openvtc_core::vetting::wire::{self, Document};
use vta_sdk::trust_task_proof::TrustTaskVmResolver;

use super::dispatch::show;
use super::jobs::{SendJob, Sent};
use crate::state_handler::background_dispatch::{self, DispatchDomain, InFlight};
use crate::state_handler::runtime_actions::ActionCtx;
use crate::state_handler::state::State;

// ============================================================================
// Sending
// ============================================================================

/// Whether the vetting domain is free for a job a person starts, or say why
/// not. Decided before any preparation, so nothing is prepared for a job that
/// would be refused; the job claims the domain when it is dispatched
/// ([`Claim::Held`]). `busy` is the vetting domain as the loop found it when
/// the action arrived. The loop runs one arm at a time, so a domain free
/// here is still free when the effect's send claims it.
pub(super) fn claimable(state: &mut State, busy: bool) -> bool {
    if !busy {
        return true;
    }
    show(
        state,
        Status::warning(InFlight::busy_message(DispatchDomain::Vetting)),
    );
    false
}

/// Whether a vetting job holds the vetting domain while it runs.
#[derive(Clone, Copy)]
pub(super) enum Claim {
    /// A job a person started, after [`claimable`]: it holds the domain, so a
    /// second one is refused until it finishes.
    Held,
    /// A send the client makes on its own — a refresh, a step of hidden
    /// vetting the VTA finished — which is never refused and holds nothing.
    Unheld,
}

/// Hand `job` to the background, claiming the vetting domain if it is a
/// person's ([`Claim::Held`]).
pub(super) fn spawn<J: background_dispatch::Job>(ctx: &mut ActionCtx<'_>, job: J, claim: Claim) {
    match claim {
        Claim::Held => {
            background_dispatch::dispatch(job, ctx.in_flight, ctx.dispatch_tx, |busy| {
                ctx.state.main_page.content_panel.vetting.status_message =
                    Some(Status::warning(busy));
            });
        }
        Claim::Unheld => background_dispatch::spawn_unclaimed(job, ctx.dispatch_tx),
    }
}

/// Give up on a send before it started: say why, and show whatever the book
/// now holds. Nothing was dispatched, so nothing holds the domain.
pub(super) fn abandon(ctx: &mut ActionCtx<'_>, what: &str, error: impl std::fmt::Display) {
    give_up(ctx.state, ctx.config, what, error);
}

/// [`abandon`] for a plan, which has the state and the config but no loop.
pub(super) fn give_up(
    state: &mut State,
    config: &Config,
    what: &str,
    error: impl std::fmt::Display,
) {
    let message = format!("{what}: {error}");
    state.main_page.log(message.clone());
    state.main_page.sync_panels(
        config,
        crate::state_handler::main_page::Panels::FROM_VETTING_BOOK,
    );
    show(state, Status::error(message));
}

pub(super) fn persona_did(config: &Config, persona: PersonaId) -> Option<String> {
    config
        .identities
        .get(&persona)
        .map(|identity| identity.persona_did().to_string())
}

pub(super) fn resolver(ctx: &ActionCtx<'_>) -> TrustTaskVmResolver {
    TrustTaskVmResolver::new(ctx.tdk.did_resolver().clone())
}

/// Sign `document` as `persona` — with its authentication key, under
/// `proofPurpose: authentication`, like every request — then hand the send
/// to a background job, held as `claim` says. On error nothing was sent.
pub(super) async fn sign_and_send(
    ctx: &mut ActionCtx<'_>,
    persona: PersonaId,
    mut document: Document,
    sent: Sent,
    claim: Claim,
) -> Result<(), String> {
    sign(ctx, persona, &mut document).await?;
    send_signed(ctx, persona, document, sent, claim)
}

/// Look up `persona`'s keys and sign `document` with its authentication key.
pub(super) async fn sign(
    ctx: &mut ActionCtx<'_>,
    persona: PersonaId,
    document: &mut Document,
) -> Result<(), String> {
    let keys = ctx
        .config
        .get_persona_keys_for(persona, ctx.tdk)
        .await
        .map_err(|e| e.to_string())?;
    wire::sign(document, &keys.authentication.secret)
        .await
        .map_err(|e| e.to_string())
}

/// Hand a signed `document` to a background job, held as `claim` says. On
/// error nothing was sent.
pub(super) fn send_signed(
    ctx: &mut ActionCtx<'_>,
    persona: PersonaId,
    document: Document,
    sent: Sent,
    claim: Claim,
) -> Result<(), String> {
    let message = wire::to_message(&document).map_err(|e| e.to_string())?;
    let from = document.issuer.clone().unwrap_or_default();
    let to = document.recipient.clone().unwrap_or_default();
    // A manifest question is filed, as the join flow's is, so its answer —
    // and above all its refusal — has a question to land on. Unfiled, a
    // refusal threaded on it would match nothing and be dropped, and a
    // community refusing the version asked would never be asked again in the
    // one it serves (`vetting::protocol`).
    if let Sent::Manifest { community } = &sent {
        ctx.config.private.vetting.ask(CommunityQuery {
            document_id: document.id.clone(),
            community: community.clone(),
            persona,
            kind: QueryKind::Manifest,
            sent_at: chrono::Utc::now(),
        });
    }
    spawn_send(ctx, message, &from, &to, sent, claim);
    Ok(())
}

pub(super) fn spawn_send(
    ctx: &mut ActionCtx<'_>,
    message: Message,
    from: &str,
    to: &str,
    sent: Sent,
    claim: Claim,
) {
    let job = SendJob {
        service: ctx.didcomm_service.clone(),
        listener_id: openvtc_core::didcomm::listener_id_for_did(from, ctx.config),
        to: to.to_string(),
        message: Box::new(message),
        sent,
    };
    spawn(ctx, job, claim);
}
