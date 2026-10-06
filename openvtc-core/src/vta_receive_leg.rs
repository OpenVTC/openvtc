//! The receive-leg adapter: OpenVTC's own count of reply timeouts on the admin
//! VTA session, standing in for the SDK's until it can be used.
//!
//! A session whose mediator inbox is not being collected still *sends* — every
//! request reaches the VTA — but no reply comes back. Each request ends in a
//! reply timeout, while a session that is merely slow, or a VTA that answers
//! with a refusal, still produces replies. So "N reply timeouts in a row, with
//! no reply between them" is the signal, and it is what this module counts.
//!
//! Every admin-session call that can be wrapped cheaply feeds a
//! [`ReceiveLegTracker`] with [`observe`](ReceiveLegTracker::observe): the
//! device-presence registration, listing and heartbeat (a periodic probe), the
//! launch-time context fetch, and the probe sent on a rebuilt session. The
//! tracker is shared by clone, so every observer counts into the same leg.
//!
//! TODO(vta-sdk 0.64): replace this module with the SDK's own receive-leg
//! health — `VtaClient::receive_health()` / `ReceiveLegHealth` and
//! `VtaError::RepliesNotArriving` (VTI #1978) — which counts every request on
//! every clone of the session, not only the ones wrapped here. Blocked: OpenVTC
//! cannot take vta-sdk 0.64 until `did-git-sign` (VGI) releases on it, and that
//! release is blocked on a `trql-client` (affinidi-trust-registry-rs) release on
//! trust-tasks 0.27 / TDK 0.23. [`ReceiveHealth`] mirrors `ReceiveLegHealth`
//! field for field and [`REPLY_TIMEOUT_BREAKER`] mirrors the SDK's constant, so
//! the switch is local to this module and its callers' `observe` lines.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use vta_sdk::error::VtaError;

/// Reply timeouts in a row after which replies are taken to have stopped
/// arriving. Matches the SDK's `REPLY_TIMEOUT_BREAKER` (vta-sdk 0.64): one
/// timeout may be a lost frame the SDK's own self-repair answers; two in a row,
/// with no reply between, is a receive leg that has stopped.
pub const REPLY_TIMEOUT_BREAKER: u32 = 2;

/// The message prefix of a TSP reply timeout, from the SDK's
/// `TSP_REPLY_TIMEOUT_PREFIX` (`pub(crate)` there, as is `is_tsp_reply_timeout`,
/// so it is matched as the literal the SDK documents as stable).
const TSP_REPLY_TIMEOUT_PREFIX: &str = "timed out waiting for the TSP reply";

/// The text of a DIDComm reply timeout, which `vta-sdk` 0.63 keeps verbatim
/// ("Preserve the exact timeout message callers/tests match on today").
const DIDCOMM_REPLY_TIMEOUT: &str = "timeout waiting for DIDComm response";

/// What one call's outcome says about the receive leg.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyOutcome {
    /// Something came back from the VTA — an answer, or a refusal it sent.
    Replied,
    /// The request went out and no reply arrived in time.
    TimedOut,
    /// Nothing either way: the request may never have left (a transport or
    /// local failure), so it says nothing about replies.
    Unknown,
}

/// Whether `e` is a reply timeout: sent, and no reply in time.
#[must_use]
pub fn is_reply_timeout(e: &VtaError) -> bool {
    match e {
        VtaError::TspTransport(msg) => msg.starts_with(TSP_REPLY_TIMEOUT_PREFIX),
        VtaError::DidcommTransport(msg) => msg.contains(DIDCOMM_REPLY_TIMEOUT),
        _ => false,
    }
}

/// Classify one call's outcome for the receive leg.
#[must_use]
pub fn classify<T>(outcome: &Result<T, VtaError>) -> ReplyOutcome {
    match outcome {
        Ok(_) => ReplyOutcome::Replied,
        Err(e) if is_reply_timeout(e) => ReplyOutcome::TimedOut,
        // Typed answers the VTA sent back: a reply arrived, even if a refusal.
        Err(
            VtaError::Auth(_)
            | VtaError::NotFound(_)
            | VtaError::Validation(_)
            | VtaError::Forbidden(_)
            | VtaError::Conflict(_)
            | VtaError::Gone(_)
            | VtaError::Server { .. }
            | VtaError::DidcommRemote { .. }
            | VtaError::ConsentRequired { .. }
            | VtaError::LastServiceRefused
            | VtaError::ServiceNotPresent
            | VtaError::ServiceAlreadyEnabled
            | VtaError::DrainTtlOutOfBounds { .. }
            | VtaError::NoPriorMutation
            | VtaError::NoMatchingProtocol { .. }
            | VtaError::UnsupportedTaskType { .. }
            | VtaError::Unavailable { .. }
            | VtaError::RateLimited { .. },
        ) => ReplyOutcome::Replied,
        Err(_) => ReplyOutcome::Unknown,
    }
}

/// Whether replies are reaching this app. Mirrors vta-sdk 0.64's
/// `ReceiveLegHealth`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReceiveHealth {
    /// Requests in a row whose reply did not arrive in time. Reset by any reply.
    pub consecutive_reply_timeouts: u32,
    /// Time since the last reply. `None` before the first.
    pub since_last_reply: Option<Duration>,
    /// Time since the last reply timeout. `None` if there has been none.
    pub since_last_timeout: Option<Duration>,
}

impl ReceiveHealth {
    /// Whether replies have stopped arriving: [`REPLY_TIMEOUT_BREAKER`] or more
    /// timeouts in a row.
    #[must_use]
    pub fn replies_not_arriving(&self) -> bool {
        self.consecutive_reply_timeouts >= REPLY_TIMEOUT_BREAKER
    }
}

#[derive(Debug, Default)]
struct Leg {
    consecutive_timeouts: u32,
    last_reply: Option<Instant>,
    last_timeout: Option<Instant>,
}

/// Counts reply timeouts on the admin session. Cheap to clone; clones share the
/// count, so every observer of the session feeds one leg.
#[derive(Clone, Debug, Default)]
pub struct ReceiveLegTracker {
    leg: Arc<Mutex<Leg>>,
}

impl ReceiveLegTracker {
    /// A fresh leg: no replies, no timeouts.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn with<R>(&self, f: impl FnOnce(&mut Leg) -> R) -> R {
        // A poisoned lock only means an observer panicked mid-update of three
        // plain fields; the counts are still usable.
        let mut leg = self
            .leg
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut leg)
    }

    /// Record one call's outcome, and hand it back unchanged so a call site
    /// reads `tracker.observe(client.op().await)`.
    pub fn observe<T>(&self, outcome: Result<T, VtaError>) -> Result<T, VtaError> {
        self.record(classify(&outcome), Instant::now());
        outcome
    }

    /// Record an already-classified outcome at `now`.
    pub fn record(&self, outcome: ReplyOutcome, now: Instant) {
        self.with(|leg| match outcome {
            ReplyOutcome::Replied => {
                leg.consecutive_timeouts = 0;
                leg.last_reply = Some(now);
            }
            ReplyOutcome::TimedOut => {
                leg.consecutive_timeouts = leg.consecutive_timeouts.saturating_add(1);
                leg.last_timeout = Some(now);
            }
            ReplyOutcome::Unknown => {}
        });
    }

    /// Start counting afresh — for a rebuilt session, whose leg is new.
    pub fn reset(&self) {
        self.with(|leg| *leg = Leg::default());
    }

    /// The leg's health as of `now`.
    #[must_use]
    pub fn health_at(&self, now: Instant) -> ReceiveHealth {
        self.with(|leg| ReceiveHealth {
            consecutive_reply_timeouts: leg.consecutive_timeouts,
            since_last_reply: leg.last_reply.map(|t| now.saturating_duration_since(t)),
            since_last_timeout: leg.last_timeout.map(|t| now.saturating_duration_since(t)),
        })
    }

    /// The leg's health now.
    #[must_use]
    pub fn health(&self) -> ReceiveHealth {
        self.health_at(Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tsp_timeout() -> VtaError {
        VtaError::TspTransport(format!(
            "{TSP_REPLY_TIMEOUT_PREFIX} to request 'urn:uuid:1'"
        ))
    }

    fn didcomm_timeout() -> VtaError {
        VtaError::DidcommTransport(DIDCOMM_REPLY_TIMEOUT.into())
    }

    #[test]
    fn reply_timeouts_are_recognised_on_both_transports() {
        assert!(is_reply_timeout(&tsp_timeout()));
        assert!(is_reply_timeout(&didcomm_timeout()));
        assert_eq!(classify::<()>(&Err(tsp_timeout())), ReplyOutcome::TimedOut);
        assert_eq!(
            classify::<()>(&Err(didcomm_timeout())),
            ReplyOutcome::TimedOut
        );
    }

    #[test]
    fn a_failure_to_send_says_nothing_about_replies() {
        for e in [
            VtaError::TspTransport("failed to seal frame".into()),
            VtaError::DidcommTransport("message pickup error: socket closed".into()),
            VtaError::Protocol("bad shape".into()),
            VtaError::Other("x".into()),
        ] {
            assert!(!is_reply_timeout(&e));
            assert_eq!(classify::<()>(&Err(e)), ReplyOutcome::Unknown);
        }
    }

    #[test]
    fn a_refusal_from_the_vta_is_a_reply() {
        for e in [
            VtaError::NotFound("x".into()),
            VtaError::Auth("expired".into()),
            VtaError::Server {
                status: 500,
                body: String::new(),
            },
        ] {
            assert_eq!(classify::<()>(&Err(e)), ReplyOutcome::Replied);
        }
        assert_eq!(classify::<u8>(&Ok(1)), ReplyOutcome::Replied);
    }

    #[test]
    fn two_timeouts_in_a_row_mean_replies_are_not_arriving() {
        let t = ReceiveLegTracker::new();
        assert_eq!(t.health(), ReceiveHealth::default());
        let _ = t.observe::<()>(Err(tsp_timeout()));
        assert!(
            !t.health().replies_not_arriving(),
            "one is below the breaker"
        );
        // A send failure in between neither counts nor resets.
        let _ = t.observe::<()>(Err(VtaError::TspTransport("failed to seal frame".into())));
        let _ = t.observe::<()>(Err(didcomm_timeout()));
        let h = t.health();
        assert_eq!(h.consecutive_reply_timeouts, 2);
        assert!(h.replies_not_arriving());
        assert!(h.since_last_timeout.is_some());
    }

    #[test]
    fn any_reply_resets_the_count() {
        let t = ReceiveLegTracker::new();
        let _ = t.observe::<()>(Err(tsp_timeout()));
        let _ = t.observe::<()>(Err(tsp_timeout()));
        let _ = t.observe::<()>(Err(VtaError::NotFound("no such device".into())));
        let h = t.health();
        assert_eq!(h.consecutive_reply_timeouts, 0);
        assert!(h.since_last_reply.is_some());
    }

    #[test]
    fn clones_share_one_leg_and_reset_starts_afresh() {
        let t = ReceiveLegTracker::new();
        let other = t.clone();
        let _ = other.observe::<()>(Err(tsp_timeout()));
        let _ = t.observe::<()>(Err(tsp_timeout()));
        assert!(t.health().replies_not_arriving());
        t.reset();
        assert_eq!(other.health(), ReceiveHealth::default());
    }

    #[test]
    fn observe_hands_the_outcome_back_unchanged() {
        let t = ReceiveLegTracker::new();
        assert_eq!(t.observe::<u8>(Ok(7)).ok(), Some(7));
        assert!(matches!(
            t.observe::<u8>(Err(VtaError::NotFound("x".into()))),
            Err(VtaError::NotFound(_))
        ));
    }
}
