//! The hand-over of a persona's received notifications to the member's VTA (VTI-NTF-054).
//!
//! This client holds the persona's mediator socket, so a `notifications/notify` or
//! `notifications/relay` addressed to the persona arrives here rather than at the VTA. Each one
//! is handed over off the loop, as soon as it arrives — the VTA applies the acceptance window
//! at the hand-over, so a document held back is a late delivery (VTI-NTF-055):
//!
//! 1. **Deposit** it (`vta/notifications/deposit/0.1`) exactly as received, in the trust context
//!    of the persona it was addressed to. Every one: this client applies no acceptance policy,
//!    and declining is the VTA's decision.
//! 2. **Answer the sender** with the receipt the task defines (`notificationId`, `revision` of
//!    the innermost notification) — the receipt the VTA answered the deposit with, which is
//!    the same whether it held the document, declined it under the principal's acceptance
//!    policy, or already held it (VTI-NTF-023, VTI-NTF-054, VTI-NTF-055). This client runs no
//!    verification of its own to decide whether to answer: the VTA is the recipient that
//!    verifies, and the answer must be the one it would give had it collected the document
//!    itself (VTI-NTF-086). A second verification here could come out differently from the
//!    VTA's — another resolver cache, another clock — and an answer turned on it would set a
//!    document this client collected apart from one the VTA collected.
//!
//! A sender is not answered when no receipt was given: the VTA could not be reached (or none
//! is connected), or it refused the document — as not addressed to a DID it holds, or as one it
//! would not have accepted delivered directly (`documentInvalid`: not a notification it can
//! verify, outside its acceptance window). None of those is a decision about holding it, so
//! none says anything of the member's relationships, and an unanswered sender delivers again
//! (VTI-NTF-021, VTI-TRN-046). Nor is a document whose transport sender is not its issuer, as
//! the VTA does not answer one it collects (the document must be bound to the party that
//! delivered it) — a check on the delivery alone, made before anything is decided.
//!
//! Nothing here opens the thing a notification points at, or tells its holder anything
//! (VTI-NTF-053).

use std::sync::{Arc, LazyLock};

use affinidi_tdk::TDK;
use openvtc_core::config::Config;
use openvtc_core::notifications::{self, Deposited, Received};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};
use vta_sdk::client::VtaClient;

use crate::state_handler::repos_actions::{Sender, sender};

/// How many hand-overs run at once. One beyond that is not handed over and not answered, so
/// its sender delivers it again later — a burst never queues unbounded work here.
const MAX_IN_FLIGHT: usize = 8;

static IN_FLIGHT: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MAX_IN_FLIGHT)));

/// Hand `received` to the member's VTA and answer its sender, off the loop.
pub(crate) async fn hand_over(
    config: &Config,
    tdk: &TDK,
    vta: Option<&VtaClient>,
    received: Received,
) {
    let Some(persona) = config.account.persona_id_for_did(&received.addressee) else {
        return;
    };
    let Some(context_id) = config.account.personas.get(&persona).map(|p| {
        openvtc_core::config::community_context::persona_context(
            p,
            config.account.top_context_id.as_str(),
        )
        .to_string()
    }) else {
        return;
    };
    let Some(vta) = vta.cloned() else {
        warn!(
            from = %received.sender,
            "notification received with no VTA connected — not handed over and not answered, \
             so its sender delivers it again"
        );
        return;
    };
    // The persona's messaging identity and key, for the receipt. Resolved now (in memory, not
    // I/O); the job owns them. Only a document its sender issued is answered (above).
    let issued_by_sender = received
        .document
        .get("issuer")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|issuer| vta_sdk::did_scid::same_reference(issuer, &received.sender));
    let answer_as = match sender(config, tdk, persona, &received.sender).await {
        Ok(_) if !issued_by_sender => None,
        Ok(s) => Some(s),
        Err(e) => {
            warn!(from = %received.sender, "the receipt cannot be sent: {e}");
            None
        }
    };
    let Ok(permit) = IN_FLIGHT.clone().try_acquire_owned() else {
        warn!(
            from = %received.sender,
            "too many notifications being handed over — this one is left for its sender to \
             deliver again"
        );
        return;
    };
    tokio::spawn(async move {
        let _permit = permit;
        run(vta, context_id, received, answer_as).await;
    });
}

async fn run(vta: VtaClient, context_id: String, received: Received, answer_as: Option<Sender>) {
    // 1. The deposit, exactly as received; its answer is the receipt.
    let receipt = match notifications::deposit(&vta, &context_id, &received.document).await {
        Ok(Deposited::Answered(receipt)) => {
            info!(from = %received.sender, "notification handed to the VTA");
            receipt
        }
        Ok(Deposited::Refused(code)) => {
            // No receipt was given, so none is sent; the sender delivers again.
            debug!(from = %received.sender, %code, "the VTA refused a deposited notification — not answered");
            return;
        }
        Err(e) => {
            warn!(
                from = %received.sender,
                "the VTA could not be reached to hand a notification over ({e}) — not answered, \
                 so its sender delivers it again"
            );
            return;
        }
    };

    // 2. The sender answered with the VTA's receipt, whatever the VTA did with the document.
    let Some(answer_as) = answer_as else {
        debug!(from = %received.sender, "a notification its sender did not issue is not answered");
        return;
    };
    if let Err(e) = answer(&answer_as, &received, receipt).await {
        warn!(from = %received.sender, "the notification's receipt was not sent: {e}");
    }
}

/// Sign the receipt as the addressee and send it to the sender, on the transport the
/// notification arrived on.
async fn answer(s: &Sender, received: &Received, receipt: serde_json::Value) -> Result<(), String> {
    let mut doc = notifications::receipt_document(received, receipt).map_err(|e| e.to_string())?;
    openvtc_core::capabilities::sign_document(&mut doc, &s.signer)
        .await
        .map_err(|e| e.to_string())?;
    let body = serde_json::to_value(&doc).map_err(|e| e.to_string())?;
    let tsp_mediator =
        openvtc_core::community_send::tsp_mediator_for(received.over_tsp, &received.sender).await;
    openvtc_core::community_send::send_document(
        &openvtc_core::community_send::Delivery {
            atm: &s.atm,
            profile: &s.profile,
            member_did: &received.addressee,
            vtc_did: &received.sender,
            mediator_did: &s.mediator,
            tsp_mediator_did: tsp_mediator.as_deref(),
        },
        doc.id.clone(),
        body,
    )
    .await
    .map_err(|e| e.to_string())
}
