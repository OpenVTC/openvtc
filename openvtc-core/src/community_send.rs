//! One send for every Trust Task a member puts to its community.
//!
//! A membership is spoken to on the transport it was joined over: TSP when the
//! join went over TSP, the DIDComm Trust Task binding envelope otherwise. A
//! persona that joined over TSP may have no DIDComm route the community can
//! answer on, so a request sent to it over DIDComm is processed, answered over
//! DIDComm — and the answer never arrives. That is how the Repos view
//! (`git-ns/view`) came to wait out its 30 s for a reply the community had
//! already sent, while the profile ask beside it, sent over TSP, was answered
//! at once.
//!
//! Every member-to-community send goes through [`send_document`], so the
//! transport choice is made in one place rather than re-spelled per verb.

use std::sync::Arc;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;
use chrono::Utc;
use serde_json::Value;

use crate::errors::OpenVTCError;

/// Where a member's request is going and who is sending it, resolved by the
/// caller.
pub struct Delivery<'a> {
    pub atm: &'a ATM,
    pub profile: &'a Arc<ATMProfile>,
    /// The member acting — the authcrypt sender / TSP sender VID, and so the
    /// identity the community proves the request came from.
    pub member_did: &'a str,
    /// The community being addressed.
    pub vtc_did: &'a str,
    /// The member's own mediator, for the DIDComm leg.
    pub mediator_did: &'a str,
    /// The community's advertised TSP mediator, when the membership was joined
    /// over TSP: the document then goes over TSP rather than DIDComm.
    /// Resolve it with [`tsp_mediator_for`].
    pub tsp_mediator_did: Option<&'a str>,
}

/// The TSP hop for a membership: the community's advertised TSP mediator when
/// the membership was joined over TSP (`over_tsp`), else `None` (DIDComm).
///
/// Resolved fresh on every send, as the join poll does: it is the hop the
/// routing layer seals to, and the community's document may have changed since
/// the join. A community that no longer advertises `#tsp` degrades to DIDComm.
pub async fn tsp_mediator_for(over_tsp: bool, vtc_did: &str) -> Option<String> {
    if over_tsp {
        crate::config::peer_tsp_mediator(vtc_did).await
    } else {
        None
    }
}

/// The DIDComm carriage of a Trust Task request: the binding envelope with the
/// document as its body. A community refuses a Trust Task typed as itself
/// (`bindings/didcomm/0.2` §2–§4, VTI #1687).
pub fn didcomm_request(
    document_id: String,
    body: Value,
    member_did: &str,
    vtc_did: &str,
) -> Message {
    let now = Utc::now().timestamp().max(0) as u64;
    Message::build(
        document_id,
        crate::capabilities::TRUST_TASK_ENVELOPE_TYPE.to_string(),
        body,
    )
    .from(member_did.to_string())
    .to(vtc_did.to_string())
    .created_time(now)
    .finalize()
}

/// Send a signed Trust Task `document` (id `document_id`) to the community on
/// the membership's own transport: TSP when the route names the community's TSP
/// mediator, the DIDComm Trust Task envelope otherwise.
///
/// Fire-and-forget: `Ok` means handed to the transport, never that the
/// community received it; the caller owns a reply timeout.
pub async fn send_document(
    route: &Delivery<'_>,
    document_id: String,
    document: Value,
) -> Result<(), OpenVTCError> {
    if let Some(tsp_mediator) = route.tsp_mediator_did {
        return crate::tsp::send_trust_task(
            route.atm,
            route.profile,
            &document,
            route.vtc_did,
            tsp_mediator,
        )
        .await;
    }
    let msg = didcomm_request(document_id, document, route.member_did, route.vtc_did);
    crate::pack_and_send(
        route.atm,
        route.profile,
        &msg,
        route.member_did,
        route.vtc_did,
        route.mediator_did,
    )
    .await
}
