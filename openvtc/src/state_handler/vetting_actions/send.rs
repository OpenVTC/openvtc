//! Shared sending helpers: claiming the vetting domain, signing a message
//! on the loop and handing its send to a background job.

use affinidi_tdk::didcomm::Message;
use openvtc_core::config::Config;
use openvtc_core::config::account::PersonaId;
use openvtc_core::vetting::queries::{CommunityQuery, QueryKind};
use openvtc_core::vetting::wire::{self, Document};
use vta_sdk::trust_task_proof::TrustTaskVmResolver;

use super::dispatch::status;
use super::jobs::{SendJob, Sent};
use crate::state_handler::background_dispatch::{self, DispatchDomain, DispatchOutcome, InFlight};
use crate::state_handler::runtime_actions::ActionCtx;

// ============================================================================
// Sending
// ============================================================================

/// Claim the vetting domain, or say why not.
pub(super) fn begin(ctx: &mut ActionCtx<'_>) -> bool {
    if ctx.in_flight.try_begin(DispatchDomain::Vetting) {
        return true;
    }
    status(ctx, InFlight::busy_message(DispatchDomain::Vetting));
    false
}

/// Give up on a send before it started: release the domain, say why, and show
/// whatever the book now holds.
pub(super) fn abandon(ctx: &mut ActionCtx<'_>, what: &str, error: impl std::fmt::Display) {
    ctx.in_flight.finish(DispatchDomain::Vetting);
    let message = format!("{what}: {error}");
    ctx.state.main_page.log(message.clone());
    ctx.state.main_page.sync_from_config(ctx.config);
    status(ctx, message);
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
/// to a background job. The caller has claimed the domain; on error it is
/// still claimed.
pub(super) async fn sign_and_send(
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

pub(super) fn spawn_send(
    ctx: &mut ActionCtx<'_>,
    message: Message,
    from: &str,
    to: &str,
    sent: Sent,
) {
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
