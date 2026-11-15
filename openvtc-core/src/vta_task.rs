//! One Trust Task at this account's VTA, sent with this crate's generated types
//! ([`crate::specs`]).
//!
//! The SDK's typed `VtaClient` methods take and return the specification versions the
//! SDK pins, as the SDK's own types. Where this crate speaks a task in a version of its
//! own choosing, it goes through [`call`] instead: the generic dispatch underneath those
//! methods, so the request is signed, sent and verified exactly as theirs are, and a
//! declared refusal still arrives as [`VtaError::Rejected`] with its code.

use serde::{Serialize, de::DeserializeOwned};
use trust_tasks_rs::Payload;
use vta_sdk::client::VtaClient;
use vta_sdk::error::VtaError;

/// Send `payload` (its Type URI is `P::TYPE_URI`) and read the answer as `R`, waiting at
/// most `timeout_secs` for it.
pub async fn call<P: Payload + Serialize, R: DeserializeOwned>(
    vta: &VtaClient,
    payload: &P,
    timeout_secs: u64,
) -> Result<R, VtaError> {
    let uri = P::TYPE_URI;
    let payload = serde_json::to_value(payload)
        .map_err(|e| VtaError::Validation(format!("{uri} request: {e}")))?;
    let answer = vta.dispatch_trust_task(uri, payload, timeout_secs).await?;
    serde_json::from_value(answer)
        .map_err(|e| VtaError::Protocol(format!("{uri} response does not match its schema: {e}")))
}

/// Whether `err` says the ACL entry being revoked is not there: `acl/revoke/0.2`
/// declares it as `subjectNotPresent`, where 0.1 answered not-found.
#[must_use]
pub fn acl_subject_absent(err: &VtaError) -> bool {
    matches!(err, VtaError::NotFound(_))
        || err.rejection_code() == Some("acl/revoke:subjectNotPresent")
}

/// Max attempts for a single VTA round-trip before giving up (1 try + 2 retries).
pub const MAX_ATTEMPTS: usize = 3;

/// Base back-off between retries; doubles each attempt (0.5s, then 1s, each
/// jittered down by up to half — see [`backoff_delay`]). Short, because the
/// dominant retryable fault is a stale DIDComm socket that ATM re-establishes
/// almost immediately — we just need a beat before re-sending.
const RETRY_BASE: std::time::Duration = std::time::Duration::from_millis(500);

/// The back-off before retry number `attempt` (1-based): "equal jitter" over the
/// exponential step `RETRY_BASE * 2^(attempt-1)` — half of the step is fixed, the
/// other half is scaled by `unit`, a sample in `[0, 1]`. The fixed half keeps the
/// beat a stale socket needs; the random half spreads clients that failed together
/// (a VTA or mediator restart) so their retries do not land in lockstep (R1.4).
/// `unit` is clamped, so the result is always within `[step/2, step]`.
#[must_use]
fn backoff_delay(attempt: usize, unit: f64) -> std::time::Duration {
    let step = RETRY_BASE * (1u32 << (attempt.saturating_sub(1)).min(16));
    let half = step / 2;
    half + half.mul_f64(unit.clamp(0.0, 1.0))
}

/// True for errors a retry might clear: transport/timeout faults where the
/// request most likely never reached the VTA (or its reply never came back).
///
/// The motivating case is a stale always-on DIDComm session — the mediator
/// dropped the idle WebSocket, the first `send_and_wait` packed into a dead
/// socket and timed out, but ATM auto-reconnects underneath, so the *next* send
/// lands on a live socket and succeeds. REST `Network` and 5xx `Server` errors
/// are transient the same way. Deterministic faults (validation, conflict,
/// not-found, auth, gone) are never retried — re-sending can't change them.
#[must_use]
pub fn retryable(e: &VtaError) -> bool {
    matches!(
        e,
        VtaError::DidcommTransport(_) | VtaError::Network(_) | VtaError::Server { .. }
    )
}

/// Run a single VTA round-trip with bounded retry on transient transport faults
/// (see [`retryable`]). `op` is re-invoked from scratch each attempt, so it
/// must rebuild any by-value request — and the caller must be content with a
/// possible duplicate on the rare "VTA processed it but the reply was lost"
/// timeout. That's a non-issue for reads (`get_key_secret`, `list_*`) and cheap
/// for `create_key` (at worst an orphan key); the join flow already rolls back a
/// half-minted persona. `label` names the op for the retry log line.
pub async fn retry<T, F, Fut>(label: &str, mut op: F) -> Result<T, VtaError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, VtaError>>,
{
    let mut attempt = 1;
    loop {
        match op().await {
            Ok(v) => return Ok(v),
            Err(e) if attempt < MAX_ATTEMPTS && retryable(&e) => {
                let backoff = backoff_delay(attempt, rand::random::<f64>());
                tracing::warn!(
                    "VTA '{label}' failed (attempt {attempt}/{MAX_ATTEMPTS}): {e} — \
                     retrying in {backoff:?}"
                );
                tokio::time::sleep(backoff).await;
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn retryable_covers_transport_and_5xx_only() {
        // Transient transport / server faults — retry may clear them.
        assert!(retryable(&VtaError::DidcommTransport("timeout".into())));
        assert!(retryable(&VtaError::Server {
            status: 503,
            body: String::new(),
        }));
        // Deterministic faults — re-sending can't change the outcome.
        assert!(!retryable(&VtaError::Validation("bad".into())));
        assert!(!retryable(&VtaError::Conflict("dup".into())));
        assert!(!retryable(&VtaError::NotFound("gone".into())));
        assert!(!retryable(&VtaError::Auth("expired".into())));
    }

    #[test]
    fn backoff_delay_stays_within_jitter_bounds() {
        for attempt in 1..MAX_ATTEMPTS {
            let step = RETRY_BASE * (1 << (attempt - 1));
            // The extremes of the sample, and out-of-range samples, are clamped.
            assert_eq!(backoff_delay(attempt, 0.0), step / 2);
            assert_eq!(backoff_delay(attempt, 1.0), step);
            assert_eq!(backoff_delay(attempt, -3.0), step / 2);
            assert_eq!(backoff_delay(attempt, 7.0), step);
            for _ in 0..200 {
                let d = backoff_delay(attempt, rand::random::<f64>());
                assert!(d >= step / 2 && d <= step, "attempt {attempt}: {d:?}");
            }
        }
        // A runaway attempt count cannot overflow the shift.
        assert!(backoff_delay(usize::MAX, 1.0) <= RETRY_BASE * (1 << 16));
    }

    #[tokio::test(start_paused = true)]
    async fn returns_immediately_on_success() {
        let calls = Cell::new(0u32);
        let out: Result<u8, VtaError> = retry("ok", || {
            calls.set(calls.get() + 1);
            async { Ok(7) }
        })
        .await;
        assert_eq!(out.unwrap(), 7);
        assert_eq!(calls.get(), 1, "no retry when the first attempt succeeds");
    }

    #[tokio::test(start_paused = true)]
    async fn retries_transient_then_succeeds() {
        // Models a stale socket: first send times out, ATM reconnects, second
        // send lands. The op should be retried and ultimately succeed.
        let calls = Cell::new(0u32);
        let out: Result<u8, VtaError> = retry("stale-then-ok", || {
            let n = calls.get() + 1;
            calls.set(n);
            async move {
                if n < 2 {
                    Err(VtaError::DidcommTransport("stale socket".into()))
                } else {
                    Ok(9)
                }
            }
        })
        .await;
        assert_eq!(out.unwrap(), 9);
        assert_eq!(calls.get(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn gives_up_after_max_attempts() {
        let calls = Cell::new(0u32);
        let out: Result<u8, VtaError> = retry("always-down", || {
            calls.set(calls.get() + 1);
            async { Err(VtaError::DidcommTransport("down".into())) }
        })
        .await;
        assert!(out.is_err());
        assert_eq!(calls.get(), MAX_ATTEMPTS as u32);
    }

    #[tokio::test(start_paused = true)]
    async fn does_not_retry_deterministic_error() {
        let calls = Cell::new(0u32);
        let out: Result<u8, VtaError> = retry("validation", || {
            calls.set(calls.get() + 1);
            async { Err(VtaError::Validation("nope".into())) }
        })
        .await;
        assert!(out.is_err());
        assert_eq!(calls.get(), 1, "deterministic faults are not retried");
    }
}
