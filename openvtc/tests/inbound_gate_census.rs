//! Every type the inbound dispatcher routes on must be admitted by the gate.
//!
//! ## The failure this closes
//!
//! `openvtc_core::didcomm` drops any inbound message whose `type` is not matched
//! by `OPENVTC_CATCH_ALL_PATTERN`, with a `debug!` and no reply. Not a refusal —
//! a *drop*. The sender sees no error, no problem-report, and nothing but a wait
//! that never ends.
//!
//! So a handler added to `process_inbound_message` without a matching prefix in
//! that pattern is a verb that fails totally and silently. That is not
//! hypothetical: `capabilities::send_capability_document` sent the binding
//! envelope, `message_dispatch` had a branch for exactly that type, and every
//! reply was dropped between them. Nothing was red; the symptom was capability
//! writes that appeared to go unacknowledged.
//!
//! The gate and the dispatcher are two descriptions of one fact — "which types
//! does this client handle" — and two descriptions agree right up until someone
//! edits one. This test is the check that they still do.
//!
//! ## Why a list and not something cleverer
//!
//! The honest fix is a registry the gate is *derived* from, so the two cannot
//! differ at all — the direction `vtc-service` took for its `rooms/*` family,
//! where `registered_uris()` is the served list rather than a copy of one.
//! `process_inbound_message` cannot go there yet: it threads `&mut Config` and
//! `&mut InboundEffects` through every arm, and a type-keyed dispatcher requires
//! handlers whose futures are `'static`, so the change is to the app's state
//! model rather than to its routing.
//!
//! Until then this list is the seam. It is deliberately written out rather than
//! generated, because the thing being checked is exactly "did someone add a
//! branch and not tell the gate" — and a list that derived itself from the
//! branches would answer yes by construction and prove nothing.

use openvtc_core::didcomm::routes_inbound_type;

/// Every `type` `process_inbound_message` compares against, in the order it
/// tests them.
///
/// When you add a branch there, add it here. The test below is what turns
/// forgetting into a failure instead of a silence.
fn routed_types() -> Vec<&'static str> {
    vec![
        openvtc_core::protocol_urls::TRUST_PONG,
        openvtc_core::capabilities::TRUST_TASK_ENVELOPE_TYPE,
        vta_sdk::protocols::join_requests::JOIN_REQUEST_SUBMIT_RECEIPT_TYPE,
        vta_sdk::protocols::join_requests::JOIN_REQUEST_SUBMIT_RESPONSE_TYPE,
        vta_sdk::protocols::join_requests::JOIN_REQUEST_STATUS_RESPONSE_TYPE,
        vta_sdk::protocols::credential_exchange::ISSUE,
        vta_sdk::protocols::PROBLEM_REPORT_TYPE,
        openvtc_core::personhood::PERSONHOOD_CHALLENGE_RESPONSE_TYPE,
        openvtc_core::personhood::PERSONHOOD_ASSERT_RESPONSE_TYPE,
        vta_sdk::protocols::members::MEMBER_VMC_RESPONSE_TYPE,
        vta_sdk::protocols::members::MEMBER_REQUEST_VMC_TYPE,
    ]
}

/// **The census.** Every routed type reaches the handler.
#[test]
fn every_routed_type_is_admitted_by_the_gate() {
    let mut dropped = Vec::new();
    for uri in routed_types() {
        if !routes_inbound_type(uri) {
            dropped.push(uri);
        }
    }

    assert!(
        dropped.is_empty(),
        "these types are routed by `process_inbound_message` but dropped by the \
         inbound gate before they reach it. A dropped message produces no error \
         and no reply — the verb simply never works, and nothing goes red. Add \
         the prefix to `OPENVTC_CATCH_ALL_PATTERN`:\n  {}",
        dropped.join("\n  ")
    );
}

/// The trust-task error family, which the dispatcher matches by *prefix* rather
/// than by an exact constant (`is_trust_task_error_type`). Every version has to
/// pass the gate, not just the one that happens to be current.
#[test]
fn every_trust_task_error_version_is_admitted() {
    for uri in [
        "https://trusttasks.org/spec/trust-task-error/0.1",
        "https://trusttasks.org/spec/trust-task-error/0.2",
        "https://trusttasks.org/spec/trust-task-error/0.5",
        "https://trusttasks.org/spec/trust-task-error/9.9",
    ] {
        assert!(
            routes_inbound_type(uri),
            "{uri} is refused by the gate — a peer on a different framework \
             version would have its refusals silently dropped, which reads as a \
             request that was never answered"
        );
    }
}

/// The gate is a routing decision, not a catch-everything: something this client
/// does not handle must still be refused, or the census above would be
/// satisfied by a pattern that matched the world.
#[test]
fn the_gate_still_refuses_what_this_client_does_not_route() {
    for uri in [
        "https://trusttasks.org/spec/acl/list/0.1",
        "https://trusttasks.org/spec/policy/upsert/0.2",
        "https://example.com/whatever",
    ] {
        assert!(
            !routes_inbound_type(uri),
            "{uri} must not be routed here — if the gate now admits it, the \
             census above proves nothing"
        );
    }
}
