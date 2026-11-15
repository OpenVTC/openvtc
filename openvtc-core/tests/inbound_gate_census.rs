//! The inbound gate and the dispatcher agree, because both are the registry.
//!
//! ## The failure this closes
//!
//! `openvtc_core::didcomm` drops any inbound message whose `type` the gate
//! refuses, with no reply. Not a refusal — a *drop*: the sender sees nothing but
//! a wait that never ends. A handler for a type the gate refuses is therefore a
//! verb that fails totally and silently, and that is not hypothetical:
//! `capabilities::send_capability_document` sent the binding envelope, the
//! dispatcher had a branch for exactly that type, and every reply was dropped
//! between them. A TSP-joined member's `git-ns` answers went the same way.
//!
//! The gate and the dispatcher used to be two descriptions of one fact — a
//! regex and a chain of branches — and this file was a hand-written list
//! reconciling them. Both are now derived from
//! [`openvtc_core::inbound::registry::ROUTES`] (issue #531), so the checks here
//! are about the registry itself: every family reachable, the routes disjoint,
//! the gate exactly the registry, and the types this client is known to
//! receive all routed.

use openvtc_core::didcomm::routes_inbound_type;
use openvtc_core::inbound::registry::{Family, ROUTES, classify};

/// Types this client is known to receive, from the constants that define
/// them where a constant exists — so a change of version upstream is a change
/// here too. Each with the family that must handle it.
fn routed_types() -> Vec<(&'static str, Family)> {
    use openvtc_core::protocol_urls as p;
    vec![
        (p::RELATIONSHIP_REQUEST, Family::RelationshipRequest),
        (
            p::RELATIONSHIP_REQUEST_REJECT,
            Family::RelationshipRequestRejected,
        ),
        (
            p::RELATIONSHIP_REQUEST_ACCEPT,
            Family::RelationshipRequestAccepted,
        ),
        (
            p::RELATIONSHIP_REQUEST_FINALIZE,
            Family::RelationshipRequestFinalize,
        ),
        (p::TRUST_PING, Family::TrustPing),
        (p::TRUST_PONG, Family::TrustPong),
        (p::VRC_REQUEST, Family::VrcRequest),
        (p::VRC_REJECTED, Family::VrcRequestRejected),
        (p::VRC_ISSUED, Family::VrcIssued),
        (
            openvtc_core::capabilities::TRUST_TASK_ENVELOPE_TYPE,
            Family::BindingEnvelope,
        ),
        (
            vta_sdk::protocols::join_requests::JOIN_REQUEST_SUBMIT_RECEIPT_TYPE,
            Family::JoinSubmitReceipt,
        ),
        (
            openvtc_core::vetting::protocol::JoinProtocol::V0_4.submit_response_type(),
            Family::JoinVerdict,
        ),
        (
            vta_sdk::protocols::join_requests::JOIN_REQUEST_STATUS_RESPONSE_TYPE,
            Family::JoinStatusResponse,
        ),
        (
            vta_sdk::protocols::credential_exchange::ISSUE,
            Family::CredentialIssue,
        ),
        (
            vta_sdk::protocols::PROBLEM_REPORT_TYPE,
            Family::ProblemReport,
        ),
        (
            openvtc_core::personhood::PERSONHOOD_CHALLENGE_RESPONSE_TYPE,
            Family::PersonhoodChallengeResponse,
        ),
        (
            openvtc_core::personhood::PERSONHOOD_ASSERT_RESPONSE_TYPE,
            Family::PersonhoodAssertResponse,
        ),
        (
            openvtc_core::renewal::MEMBERS_RENEW_RESPONSE_TYPE,
            Family::RenewalResponse,
        ),
        (
            vta_sdk::protocols::members::MEMBER_VMC_RESPONSE_TYPE,
            Family::MemberVmcResponse,
        ),
        (
            vta_sdk::protocols::members::MEMBER_REQUEST_VMC_TYPE,
            Family::MemberRequestVmc,
        ),
        (
            vta_sdk::protocols::members::MEMBER_REMOVAL_NOTICE_TYPE,
            Family::MemberRemovalNotice,
        ),
        (
            openvtc_core::join::COMMUNITY_PROFILE_SHOW_RESPONSE_TYPE,
            Family::CommunityProfileResponse,
        ),
        (
            "https://trusttasks.org/spec/governance/capability/list/0.1#response",
            Family::CapabilityReply,
        ),
        (
            "https://trusttasks.org/spec/governance/capability/enable/0.1#response",
            Family::CapabilityReply,
        ),
        // TSP opens the binding envelope before the gate, so these arrive typed
        // as the task; missing from the gate, every Repos answer to a
        // TSP-joined member was dropped and the view timed out.
        (
            "https://trusttasks.org/spec/git-ns/view/0.6#response",
            Family::GitNsReply,
        ),
        (
            "https://trusttasks.org/spec/git-ns/repo/create/0.4#response",
            Family::GitNsReply,
        ),
        (
            "https://trusttasks.org/spec/git-ns/right/grant/0.4#response",
            Family::GitNsReply,
        ),
        (
            "https://trusttasks.org/spec/vtc/rooms/memberships/list/0.2#response",
            Family::RoomsReply,
        ),
        (
            "https://trusttasks.org/spec/vtc/rooms/offers/accept/0.1#response",
            Family::RoomsReply,
        ),
        (
            "https://trusttasks.org/spec/vtc/elections/list/0.5#response",
            Family::ElectionsReply,
        ),
        (
            "https://trusttasks.org/spec/vtc/elections/tickets/issue/0.3#response",
            Family::ElectionsReply,
        ),
        (
            openvtc_core::notifications::NOTIFY_TYPE,
            Family::Notification,
        ),
        (
            openvtc_core::notifications::RELAY_TYPE,
            Family::Notification,
        ),
        (
            "https://trusttasks.org/spec/witness/session/0.2#response",
            Family::WitnessReply,
        ),
        (
            "https://trusttasks.org/spec/witness/session/submit/0.2#response",
            Family::WitnessReply,
        ),
        // Peer vetting travels member to member under its own prefix.
        (
            "https://trusttasks.org/spec/vetting/request/0.1",
            Family::Vetting,
        ),
        (
            "https://trusttasks.org/spec/vetting/session/0.1#response",
            Family::Vetting,
        ),
        (
            "https://trusttasks.org/spec/vetting/decline/0.1",
            Family::Vetting,
        ),
        (
            vta_sdk::protocols::vetting::VETTING_VETTER_LIST_RESPONSE_TYPE,
            Family::Vetting,
        ),
        (
            openvtc_core::vetting::wire::VETTER_RESEND_RESPONSE_TYPE,
            Family::Vetting,
        ),
        (
            "https://trusttasks.org/spec/trust-task-error/0.5",
            Family::TrustTaskError,
        ),
    ]
}

/// **The census.** Every type this client receives is admitted by the gate and
/// routed to the family that handles it.
#[test]
fn every_routed_type_is_admitted_and_reaches_its_family() {
    let mut wrong = Vec::new();
    for (uri, family) in routed_types() {
        if !routes_inbound_type(uri) {
            wrong.push(format!("{uri}: dropped by the gate"));
        }
        if classify(uri) != Some(family) {
            wrong.push(format!(
                "{uri}: routed to {:?}, expected {family:?}",
                classify(uri)
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// Every family has a route, so none is a handler the gate never reaches.
#[test]
fn every_family_is_reachable() {
    for family in Family::ALL {
        assert!(
            ROUTES.iter().any(|r| r.family == *family),
            "{family:?} has a handler but no route"
        );
    }
}

/// Routes are disjoint: no type is claimed by two of them, so their order in
/// the table means nothing. (Families that share traffic — a credential
/// delivery vetting reads first — do so inside their handler, not by
/// overlapping routes.)
#[test]
fn no_type_is_claimed_by_two_routes() {
    for (uri, _) in routed_types() {
        let claims: Vec<_> = ROUTES
            .iter()
            .filter(|r| r.matcher.matches(uri))
            .map(|r| r.family)
            .collect();
        assert!(claims.len() <= 1, "{uri} is claimed by {claims:?}");
    }
}

/// The gate is the registry: it admits exactly what [`classify`] routes.
#[test]
fn the_gate_is_the_registry() {
    for (uri, _) in routed_types() {
        assert_eq!(routes_inbound_type(uri), classify(uri).is_some(), "{uri}");
    }
    for uri in not_routed() {
        assert_eq!(routes_inbound_type(uri), classify(uri).is_some(), "{uri}");
    }
}

/// The trust-task error family is matched by *prefix*: every version has to
/// pass, not just the one that happens to be current.
#[test]
fn every_trust_task_error_version_is_admitted() {
    for uri in [
        "https://trusttasks.org/spec/trust-task-error/0.1",
        "https://trusttasks.org/spec/trust-task-error/0.2",
        "https://trusttasks.org/spec/trust-task-error/0.5",
        "https://trusttasks.org/spec/trust-task-error/9.9",
    ] {
        assert_eq!(
            classify(uri),
            Some(Family::TrustTaskError),
            "{uri} — a peer on a different framework version would have its \
             refusals silently dropped"
        );
    }
}

/// Types this client does not handle. The old regex admitted some of these
/// (whole namespaces: `spec/vtc/*`, `openvtc/vtc/*`, any `linuxfoundation.org/
/// openvtc/*`) and the dispatcher then dropped them as unknown; the gate now
/// drops them first, with the same outcome.
fn not_routed() -> Vec<&'static str> {
    vec![
        "https://trusttasks.org/spec/acl/list/0.1",
        "https://trusttasks.org/spec/policy/upsert/0.2",
        "https://example.com/whatever",
        "https://didcomm.org/messagepickup/3.0/status",
        // Requests we send, never receive.
        "https://trusttasks.org/spec/vtc/members/self-remove/0.1",
        // The pre-migration VTC authority: no handler speaks it.
        "https://trusttasks.org/openvtc/vtc/spec/join-requests/submit/1.0",
        "https://linuxfoundation.org/openvtc/1.0/something-new",
        // A TSP binding envelope over DIDComm: only TSP opens it, before the gate.
        "https://trusttasks.org/binding/tsp/0.1/envelope",
    ]
}

/// The gate is a routing decision, not a catch-everything.
#[test]
fn the_gate_refuses_what_no_handler_claims() {
    for uri in not_routed() {
        assert!(
            !routes_inbound_type(uri),
            "{uri} must not be routed — no handler claims it"
        );
    }
}
