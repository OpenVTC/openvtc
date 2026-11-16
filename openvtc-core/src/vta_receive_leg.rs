//! The receive leg of a VTA session: whether replies reach this app.
//!
//! A session whose mediator inbox is not being collected still *sends* — every
//! request reaches the VTA — but no reply comes back. Each request ends in a
//! reply timeout, while a session that is merely slow, or a VTA that answers
//! with a refusal, still produces replies. So "N reply timeouts in a row, with
//! no reply between them" is the signal.
//!
//! vta-sdk counts it on the session itself: [`VtaClient::receive_health`]
//! reads it, every clone of a client shares one count, and once
//! [`REPLY_TIMEOUT_BREAKER`] timeouts have happened in a row a request returns
//! [`VtaError::RepliesNotArriving`] instead of re-forming the relationship.
//! This module re-exports those, under the names OpenVTC uses, and classifies
//! a single error as a reply timeout ([`is_reply_timeout`]) for the words an
//! operator is shown (R6.4).
//!
//! The SDK counts Trust-Task requests sent over TSP. A session whose VTA does
//! not advertise TSP sends over DIDComm, which the SDK does not count, so its
//! health stays at rest.
//!
//! [`VtaClient::receive_health`]: vta_sdk::client::VtaClient::receive_health

use vta_sdk::error::VtaError;

pub use vta_sdk::client::REPLY_TIMEOUT_BREAKER;

/// Whether replies are reaching this app: reply timeouts in a row, and the
/// time since the last reply and the last timeout. vta-sdk's
/// `ReceiveLegHealth`, read with `VtaClient::receive_health`.
pub type ReceiveHealth = vta_sdk::client::ReceiveLegHealth;

/// The message prefix of a TSP reply timeout, from the SDK's
/// `TSP_REPLY_TIMEOUT_PREFIX` (`pub(crate)` there, as is `is_tsp_reply_timeout`,
/// so it is matched as the literal the SDK documents as stable).
const TSP_REPLY_TIMEOUT_PREFIX: &str = "timed out waiting for the TSP reply";

/// The text of a DIDComm reply timeout, which `vta-sdk` keeps verbatim
/// ("Preserve the exact timeout message callers/tests match on today").
const DIDCOMM_REPLY_TIMEOUT: &str = "timeout waiting for DIDComm response";

/// Whether `e` is a reply timeout: sent, and no reply in time.
#[must_use]
pub fn is_reply_timeout(e: &VtaError) -> bool {
    match e {
        VtaError::TspTransport(msg) => msg.starts_with(TSP_REPLY_TIMEOUT_PREFIX),
        VtaError::DidcommTransport(msg) => msg.contains(DIDCOMM_REPLY_TIMEOUT),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_timeouts_are_recognised_on_both_transports() {
        assert!(is_reply_timeout(&VtaError::TspTransport(format!(
            "{TSP_REPLY_TIMEOUT_PREFIX} to request 'urn:uuid:1'"
        ))));
        assert!(is_reply_timeout(&VtaError::DidcommTransport(
            DIDCOMM_REPLY_TIMEOUT.into()
        )));
    }

    #[test]
    fn a_failure_to_send_is_not_a_reply_timeout() {
        for e in [
            VtaError::TspTransport("failed to seal frame".into()),
            VtaError::DidcommTransport("message pickup error: socket closed".into()),
            VtaError::Protocol("bad shape".into()),
            VtaError::NotFound("x".into()),
        ] {
            assert!(!is_reply_timeout(&e));
        }
    }

    #[test]
    fn the_breaker_is_two_timeouts_in_a_row() {
        assert_eq!(REPLY_TIMEOUT_BREAKER, 2);
        let mut h = ReceiveHealth::default();
        h.consecutive_reply_timeouts = 1;
        assert!(!h.replies_not_arriving());
        h.consecutive_reply_timeouts = 2;
        assert!(h.replies_not_arriving());
    }
}
