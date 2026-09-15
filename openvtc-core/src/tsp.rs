/*!
 * The TSP send leg for VTC-facing ceremonies (#185 item 2f).
 *
 * ## Carriage
 *
 * A Trust Task goes out in the TSP binding envelope
 * (`{"type": ".../binding/tsp/0.1/envelope", "document": …}`), applied by
 * `vta_sdk::tsp_binding::wrap_envelope` — the same function `vta-service` and
 * the VTI SDK's own sessions use, so there is one implementation of the
 * binding rather than one per sender. See [`send_trust_task`].
 *
 * ## Why this is send-only
 *
 * Inbound TSP is **already arriving**. `DidCommTransport` owns the one mediator
 * websocket and surfaces both protocols off it, unpacking each TSP frame with
 * `atm.tsp().unpack` — which authenticates the sender VID — and tagging it
 * `Protocol::TSP`. So receiving needed no new transport, only routing: see
 * `didcomm::tsp_frame_to_message`, where those frames used to be dropped.
 *
 * What was missing is the other direction. `ATM::forward_and_send_message` — the
 * send half of [`crate::pack_and_send`] — builds a DIDComm `routing/2.0` forward
 * unconditionally, so it cannot carry a Trust Task document as TSP. This module
 * is that one missing call and nothing more.
 *
 * ## The peer is not on our mediator
 *
 * A community is addressed by the mediator *it* advertises, which is only our
 * own in a single-mediator deployment. Everywhere else the send is a federated
 * one: we post to our mediator, it forwards to theirs, theirs delivers. That is
 * carried entirely by the hop list — see `hops` (not an intra-doc link: it is
 * private) — and it is the part this module got wrong for as long as every
 * deployment shared one mediator.
 *
 * Send-only is also why there is **no second websocket**. The mediator permits
 * one channel per DID and evicts a second as `duplicate-channel`; a TSP send is
 * an HTTP post through the mediator, holding no socket of its own, so it cannot
 * duel with the DIDComm one. Same shape as the VTA leg
 * (`enable_tsp_trust_tasks`) and for the same reason.
 *
 * ## Why this is not a `MessageTransport`
 *
 * The delivery layer would take one — `MessagingService` holds any number of
 * transports over a single outbox, which is what `OutboxEntry::via` exists for —
 * and an earlier draft of this change registered a TSP leg that way.
 *
 * It was the wrong fit *here*. The ceremony sends do not go through the delivery
 * layer at all: [`crate::pack_and_send`] posts straight through the ATM, so a
 * TSP leg on the outbox would have given TSP joins durability that DIDComm joins
 * do not have, and would have meant threading a `Messaging` handle down into
 * `join_flow.rs`. Matching the transport this change is *about* — same call
 * shape, same failure semantics, only the wire differs — keeps the swap
 * reviewable and the two paths comparable.
 *
 * Putting the ceremony sends behind the outbox is worth doing, but for **both**
 * transports at once and as its own change; doing it here would have hidden a
 * durability change inside a transport change.
 */

use std::sync::Arc;

use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;
use serde_json::Value;

use crate::errors::OpenVTCError;

/// Build the TSP hop list for a send from `our_mediator` to `to_did`, whose
/// advertised TSP mediator is `their_mediator`.
///
/// `route[0]` must be **our own** mediator. `send_routed` posts the frame to the
/// profile's mediator `/inbound`, and that mediator has to be the routing
/// layer's receiver in order to hold the key that unwraps it. A hop list opening
/// with the peer's mediator arrives at ours as an envelope addressed to someone
/// else, which it can only take as an opaque message for one of its own
/// accounts — so a cross-mediator send died at the *first* hop with
/// `404 e.p.direct_delivery.recipient.unknown`, "TSP recipient is not local to
/// this mediator (remote forwarding not yet enabled)". Nothing was wrong with
/// the peer's mediator; ours was never asked to forward.
///
/// Naming ours first is what turns the send into a forward: our mediator unwraps
/// its layer, sees a next hop that is not one of its accounts, resolves that
/// hop's `TSPTransport` endpoint and POSTs onward. The peer's mediator is then
/// the routing-layer receiver of the frame it actually gets, and delivers the
/// end-to-end-sealed inner to `to_did` locally.
///
/// When the two mediators coincide — every single-mediator deployment, which is
/// why this held up for so long — the list stays two hops: ours already *is* the
/// peer's, and naming it twice would ask it to forward to itself
/// (`protocol.forwarding.loop_detected`).
fn hops(our_mediator: &str, their_mediator: &str, to_did: &str) -> Vec<String> {
    if our_mediator == their_mediator {
        vec![their_mediator.to_string(), to_did.to_string()]
    } else {
        vec![
            our_mediator.to_string(),
            their_mediator.to_string(),
            to_did.to_string(),
        ]
    }
}

/// Seal a Trust Task `document` to `to_did` and route it through that peer's
/// advertised TSP mediator.
///
/// The TSP counterpart of [`crate::pack_and_send`], and deliberately the same
/// signature shape so the two are directly comparable at a call site.
///
/// `tsp_mediator_did` is the peer's **advertised** `#tsp` mediator — the hop that
/// hands the document to the peer — not ours. That is the addressing information
/// the peer published for exactly this purpose (`discover_tsp_mediator`). It is
/// the *last* mediator on the route rather than the first: the private `hops`
/// explains why the route has to open with our own mediator, and what it cost
/// when it did not.
///
/// Unlike the DIDComm path the caller does **not** pack: `send_routed` seals the
/// payload end-to-end to `route.last()` and wraps that in a routing layer sealed
/// to `route[0]`, so the document goes in as plaintext JSON.
///
/// # Errors
///
/// Returns [`OpenVTCError`] if the profile cannot name the mediator the route is
/// built from, if the document will not serialise, or if the mediator did not
/// accept the frame. The message names the peer, the routing hop, **and the
/// mediator the frame was actually posted to** (R6.4), so an operator can tell a
/// wrong advertised mediator from a refused send from an unreachable hop.
///
/// Naming all three is not belt-and-braces. `send_routed` posts to the
/// *profile's* mediator — the onward hops are sealed into the frame, not dialled
/// — so a rejection quoting only the advertised mediator sends an operator to
/// inspect a host that never received the request. That happened twice: a
/// mediator built without its `tsp` feature answered `400
/// w.m.message.deserialize` (it fed the CESR frame to the DIDComm JSON parser),
/// and our own mediator answered `404 direct_delivery.recipient.unknown` for a
/// hop list that did not start with it — both under an error naming the peer's
/// perfectly healthy TSP mediator.
pub async fn send_trust_task(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    document: &Value,
    to_did: &str,
    tsp_mediator_did: &str,
) -> Result<(), OpenVTCError> {
    // Not best-effort any more: our mediator is the first hop, so a profile that
    // cannot name it has no route to build and must fail before the send.
    let our_mediator = profile
        .dids()
        .map(|(_, mediator)| mediator.to_string())
        .map_err(|e| {
            OpenVTCError::Config(format!(
                "TSP send to {to_did}: profile cannot name its own mediator, \
                 which the route has to start from: {e}"
            ))
        })?;

    // Sealed in the TSP **binding envelope**, not as the bare document.
    //
    // The binding (`https://trusttasks.org/binding/tsp/0.1`) is how a TSP
    // payload says "this is a Trust Task": TSP carries a sender VID, a
    // recipient VID and opaque bytes, with no message `type` and no request
    // path to say it in, so the JSON wrapper is the only place it can go. The
    // wrapper comes from `vta_sdk::tsp_binding`, which is the one
    // implementation both ends of the VTI workspace use, rather than a fourth
    // local spelling of the same JSON.
    //
    // This module sent the bare document until now. It reached the VTC only
    // because that service accepts both shapes; a conformant peer refuses it,
    // and the VTA does — `refused a TSP frame that is not a binding envelope`,
    // which the sender experiences as a reply that never comes (VTI #1488).
    let document = serde_json::to_vec(document)
        .map_err(|e| OpenVTCError::Config(format!("serialise Trust Task document for TSP: {e}")))?;
    let payload = vta_sdk::tsp_binding::wrap_envelope(&document);
    let route = hops(&our_mediator, tsp_mediator_did, to_did);

    atm.tsp()
        .send_routed(profile, &route, &payload)
        .await
        .map_err(|e| {
            OpenVTCError::Config(format!(
                "TSP send to {to_did} (routed via its advertised mediator \
                 {tsp_mediator_did}, posted through our own mediator \
                 {our_mediator}): {e}"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::hops;

    const OURS: &str = "did:webvh:example:our-mediator";
    const THEIRS: &str = "did:webvh:example:their-mediator";
    const TO: &str = "did:webvh:example:vtc";

    /// The invariant the whole module turns on, and the one that is impossible
    /// to see in a signature: whatever else the route contains, it opens with
    /// the mediator the frame is posted to, because only that mediator holds the
    /// key to the routing layer.
    #[test]
    fn route_always_starts_at_our_own_mediator() {
        for (ours, theirs) in [(OURS, THEIRS), (OURS, OURS)] {
            let route = hops(ours, theirs, TO);
            assert_eq!(
                route[0], ours,
                "route[0] must be the mediator we post to ({ours} → {theirs})"
            );
            assert_eq!(
                route.last().map(String::as_str),
                Some(TO),
                "route.last() must be the final recipient ({ours} → {theirs})"
            );
        }
    }

    /// A peer on another mediator needs the forwarding hop spelled out: ours
    /// unwraps and forwards to theirs, theirs delivers locally. Without the
    /// middle hop ours has nobody to forward to and refuses the send.
    #[test]
    fn cross_mediator_route_names_both_mediators() {
        assert_eq!(hops(OURS, THEIRS, TO), vec![OURS, THEIRS, TO]);
    }

    /// A peer on our own mediator stays two hops. Repeating the mediator would
    /// ask it to forward to itself, which it rejects as a routing loop.
    #[test]
    fn same_mediator_route_does_not_repeat_the_hop() {
        assert_eq!(hops(OURS, OURS, TO), vec![OURS, TO]);
    }
}
