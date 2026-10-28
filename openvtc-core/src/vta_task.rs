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
