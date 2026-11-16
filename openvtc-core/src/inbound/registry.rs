//! The one list of inbound message types this client handles.
//!
//! The transport's accept gate and the dispatcher describe the same fact, so
//! both are derived from one table rather than kept in step by hand. Were they
//! separate, a dispatcher branch added without a matching gate prefix would be
//! a verb that fails totally and silently — the message dropped at `debug!`
//! before the dispatcher sees it, and the sender waiting out its timeout.
//!
//! Both are derived from [`ROUTES`]:
//!
//! - the gate ([`crate::didcomm::routes_inbound_type`]) admits a type exactly
//!   when [`classify`] gives it a [`Family`];
//! - the dispatcher matches on that [`Family`], exhaustively, so every family
//!   has a handler or the crate does not compile.
//!
//! So a handler cannot exist for a type the gate refuses, and the gate admits
//! nothing no handler claims. The routes are disjoint — at most one matches a
//! type — so their order carries no meaning; a test holds them to that.
//!
//! A family's handler may still decline a message (unsigned, from a stranger,
//! threading on nothing of ours); that is the handler's decision, logged there.
//! A few families are *shared*: a `trust-task-error` may answer any request we
//! sent, so its handler offers it to each view in turn, and vetting reads some
//! credential deliveries and problem reports before the join handlers do. The
//! sharing is inside those handlers, written out once, not spread across the
//! routing.

use crate::capabilities::TRUST_TASK_ENVELOPE_TYPE;
use crate::join::COMMUNITY_PROFILE_SHOW_RESPONSE_TYPE;
use crate::messaging::{TRUST_TASK_ERROR_TYPE_PREFIX, is_trust_task_error_type};
use crate::personhood::{PERSONHOOD_ASSERT_RESPONSE_TYPE, PERSONHOOD_CHALLENGE_RESPONSE_TYPE};
use crate::protocol_urls;
use crate::vetting::protocol::JoinProtocol;
use vta_sdk::protocols::PROBLEM_REPORT_TYPE;
use vta_sdk::protocols::credential_exchange::ISSUE as CREDENTIAL_ISSUE_TYPE;
use vta_sdk::protocols::join_requests::{
    JOIN_REQUEST_STATUS_RESPONSE_TYPE, JOIN_REQUEST_SUBMIT_RECEIPT_TYPE,
};
use vta_sdk::protocols::members::{
    MEMBER_REMOVAL_NOTICE_TYPE, MEMBER_REQUEST_VMC_TYPE, MEMBER_VMC_RESPONSE_TYPE,
};

/// Declares [`Family`] and [`Family::ALL`] from one list, so a new family is
/// in `ALL` by construction.
macro_rules! families {
    ($($(#[$meta:meta])* $variant:ident,)*) => {
        /// What an inbound message is, for routing: one handler per family.
        ///
        /// Exhaustively matched by the dispatcher, so a family without a handler
        /// does not compile.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Family {
            $($(#[$meta])* $variant,)*
        }

        impl Family {
            /// Every family, in declaration order.
            pub const ALL: &'static [Family] = &[$(Family::$variant,)*];
        }
    };
}

families! {
    /// `notifications/notify` and `notifications/relay`, for the member's VTA.
    Notification,
    /// `governance/capability/*` answers.
    CapabilityReply,
    /// `git-ns/*` answers, for the Repos panel.
    GitNsReply,
    /// `vtc/rooms/*` answers, for the Rooms panel.
    RoomsReply,
    /// `vtc/elections/*` answers, for the Elections panel.
    ElectionsReply,
    /// A witness's `witness/session/*#response`.
    WitnessReply,
    /// Peer identity vetting, and a community's answers to vetting questions.
    Vetting,
    /// `join-requests/submit-receipt`.
    JoinSubmitReceipt,
    /// `credential-exchange/issue`. Vetting reads it first.
    CredentialIssue,
    /// `join-requests/submit#response`: the admission verdict.
    JoinVerdict,
    /// A DIDComm problem-report. Vetting reads it first.
    ProblemReport,
    /// `vtc/members/renew#response`.
    RenewalResponse,
    /// A `trust-task-error`, offered to every request it may refuse.
    TrustTaskError,
    /// `join-requests/status#response`.
    JoinStatusResponse,
    /// `vtc/profile/show#response`.
    CommunityProfileResponse,
    /// The personhood challenge.
    PersonhoodChallengeResponse,
    /// The personhood assertion's result.
    PersonhoodAssertResponse,
    /// `members/vmc#response`: the community took our VMC.
    MemberVmcResponse,
    /// `members/request-vmc`: the community asks for our VMC.
    MemberRequestVmc,
    /// `vtc/members/removal-notice`.
    MemberRemovalNotice,
    /// The DIDComm binding envelope, opened before routing. One that does not
    /// open is dropped.
    BindingEnvelope,
    /// OpenVTC relationship request.
    RelationshipRequest,
    /// OpenVTC relationship request rejected.
    RelationshipRequestRejected,
    /// OpenVTC relationship request accepted.
    RelationshipRequestAccepted,
    /// OpenVTC relationship finalize.
    RelationshipRequestFinalize,
    /// DIDComm trust-ping. The transport answers it; the dispatcher records it.
    TrustPing,
    /// DIDComm trust-ping response.
    TrustPong,
    /// VRC request.
    VrcRequest,
    /// VRC request rejected.
    VrcRequestRejected,
    /// VRC issued.
    VrcIssued,
}

/// How a route recognises its types.
#[derive(Clone, Copy)]
pub enum TypeMatcher {
    /// Exactly this type URI.
    Exact(&'static str),
    /// Any type URI starting with this prefix (every version of a family).
    Prefix(&'static str),
    /// A family whose membership is defined by its own module — kept there so
    /// the module that parses the types is the one that names them.
    Predicate(fn(&str) -> bool),
}

impl TypeMatcher {
    /// Whether `typ` is one of this route's types.
    #[must_use]
    pub fn matches(&self, typ: &str) -> bool {
        match self {
            TypeMatcher::Exact(t) => typ == *t,
            TypeMatcher::Prefix(p) => typ.starts_with(p),
            TypeMatcher::Predicate(f) => f(typ),
        }
    }
}

impl std::fmt::Debug for TypeMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TypeMatcher::Exact(t) => write!(f, "Exact({t})"),
            TypeMatcher::Prefix(p) => write!(f, "Prefix({p})"),
            TypeMatcher::Predicate(_) => f.write_str("Predicate(..)"),
        }
    }
}

/// One entry of the registry: these types are this family's.
#[derive(Debug, Clone, Copy)]
pub struct Route {
    /// Which types.
    pub matcher: TypeMatcher,
    /// Whose.
    pub family: Family,
}

const fn exact(typ: &'static str, family: Family) -> Route {
    Route {
        matcher: TypeMatcher::Exact(typ),
        family,
    }
}

const fn prefix(prefix: &'static str, family: Family) -> Route {
    Route {
        matcher: TypeMatcher::Prefix(prefix),
        family,
    }
}

const fn predicate(f: fn(&str) -> bool, family: Family) -> Route {
    Route {
        matcher: TypeMatcher::Predicate(f),
        family,
    }
}

/// Vetting's own types: everything [`crate::vetting::inbound::may_claim`]
/// names except the three it shares with other families (a credential
/// delivery, a problem-report, a `trust-task-error`), whose handlers offer
/// them to vetting first.
fn vetting_owned(typ: &str) -> bool {
    crate::vetting::inbound::may_claim(typ)
        && typ != CREDENTIAL_ISSUE_TYPE
        && typ != PROBLEM_REPORT_TYPE
        && !is_trust_task_error_type(typ)
}

/// Every inbound type this client handles, and whose it is. The gate and the
/// dispatcher both read this; nothing else decides either.
pub const ROUTES: &[Route] = &[
    exact(crate::notifications::NOTIFY_TYPE, Family::Notification),
    exact(crate::notifications::RELAY_TYPE, Family::Notification),
    prefix(
        crate::capabilities::CAPABILITY_TYPE_PREFIX,
        Family::CapabilityReply,
    ),
    prefix(crate::git_ns::TYPE_PREFIX, Family::GitNsReply),
    prefix(crate::community_rooms::TYPE_PREFIX, Family::RoomsReply),
    prefix(crate::elections::TYPE_PREFIX, Family::ElectionsReply),
    predicate(crate::witness::is_reply_type, Family::WitnessReply),
    predicate(vetting_owned, Family::Vetting),
    exact(JOIN_REQUEST_SUBMIT_RECEIPT_TYPE, Family::JoinSubmitReceipt),
    exact(CREDENTIAL_ISSUE_TYPE, Family::CredentialIssue),
    predicate(JoinProtocol::is_submit_response, Family::JoinVerdict),
    exact(PROBLEM_REPORT_TYPE, Family::ProblemReport),
    exact(
        crate::renewal::MEMBERS_RENEW_RESPONSE_TYPE,
        Family::RenewalResponse,
    ),
    prefix(TRUST_TASK_ERROR_TYPE_PREFIX, Family::TrustTaskError),
    exact(
        JOIN_REQUEST_STATUS_RESPONSE_TYPE,
        Family::JoinStatusResponse,
    ),
    exact(
        COMMUNITY_PROFILE_SHOW_RESPONSE_TYPE,
        Family::CommunityProfileResponse,
    ),
    exact(
        PERSONHOOD_CHALLENGE_RESPONSE_TYPE,
        Family::PersonhoodChallengeResponse,
    ),
    exact(
        PERSONHOOD_ASSERT_RESPONSE_TYPE,
        Family::PersonhoodAssertResponse,
    ),
    exact(MEMBER_VMC_RESPONSE_TYPE, Family::MemberVmcResponse),
    exact(MEMBER_REQUEST_VMC_TYPE, Family::MemberRequestVmc),
    exact(MEMBER_REMOVAL_NOTICE_TYPE, Family::MemberRemovalNotice),
    exact(TRUST_TASK_ENVELOPE_TYPE, Family::BindingEnvelope),
    exact(
        protocol_urls::RELATIONSHIP_REQUEST,
        Family::RelationshipRequest,
    ),
    exact(
        protocol_urls::RELATIONSHIP_REQUEST_REJECT,
        Family::RelationshipRequestRejected,
    ),
    exact(
        protocol_urls::RELATIONSHIP_REQUEST_ACCEPT,
        Family::RelationshipRequestAccepted,
    ),
    exact(
        protocol_urls::RELATIONSHIP_REQUEST_FINALIZE,
        Family::RelationshipRequestFinalize,
    ),
    exact(protocol_urls::TRUST_PING, Family::TrustPing),
    exact(protocol_urls::TRUST_PONG, Family::TrustPong),
    exact(protocol_urls::VRC_REQUEST, Family::VrcRequest),
    exact(protocol_urls::VRC_REJECTED, Family::VrcRequestRejected),
    exact(protocol_urls::VRC_ISSUED, Family::VrcIssued),
];

/// The family `typ` belongs to, or `None` when no handler claims it — in
/// which case the gate drops it before dispatch.
#[must_use]
pub fn classify(typ: &str) -> Option<Family> {
    ROUTES
        .iter()
        .find(|route| route.matcher.matches(typ))
        .map(|route| route.family)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every family is reachable: some route names it. A family with a
    /// handler and no route would be dead code the gate never admits.
    #[test]
    fn every_family_has_a_route() {
        for family in Family::ALL {
            assert!(
                ROUTES.iter().any(|r| r.family == *family),
                "{family:?} has no route, so the gate never admits a message for it"
            );
        }
    }
}
