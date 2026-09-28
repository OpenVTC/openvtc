//! Verifying a credential a community issues to us before it is stored.
//!
//! A VTC delivers the membership credential (VMC) and role credentials (VEC)
//! it issues as `credential-exchange/issue` messages. The transport says the
//! message came from the community; it says nothing about whether the
//! credential inside was signed by it, and the transport sender is a routing
//! hint rather than an identity in any case. Only a signature is what a stored
//! credential is later relied on for — it is shown as the member's standing
//! and presented to others. So every issued credential is verified here before
//! the caller may store it.
//!
//! # Rules
//!
//! - Every proof verifies against the issuer's DID document under
//!   `assertionMethod`, by the rules in [`crate::proof_check`]: at least one
//!   proof, none failing, each by a key of the issuer's own DID listed under
//!   `assertionMethod`.
//! - The credential is inside its validity window.
//! - If it names a `credentialStatus`, the issuer's status list is fetched and
//!   verified ([`crate::status_list`], which reads proof sets). A revoked or
//!   suspended credential is refused, and so is one whose status cannot be
//!   established — an unreachable or unverifiable list fails closed.
//!
//! Error text names what failed, never the credential or any DID: it reaches
//! the log and the user's activity feed.

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use chrono::{DateTime, Utc};
use serde_json::Value;
use tracing::debug;

use crate::proof_check::{self, ProofError, Purpose};

/// How far in the future a `validFrom` may sit, for clock skew between us and
/// the community.
pub const VALID_FROM_SKEW: chrono::TimeDelta = chrono::TimeDelta::minutes(5);

/// Why an issued credential was refused. Each message says what failed and
/// nothing about the credential's contents.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IssuedCredentialError {
    #[error("the credential was not checked")]
    NotChecked,
    #[error("the delivery is not a Trust Task document naming the community that sent it")]
    DeliveryIssuerNotSender,
    #[error("the delivery's proof: {0}")]
    DeliveryProof(ProofError),
    #[error("the delivery carries no credential")]
    NoCredential,
    #[error("its check did not finish (timed out or failed) — ask the community to send it again")]
    CheckUnfinished,
    #[error("the credential names no issuer")]
    NoIssuer,
    #[error("the credential's issuer is not the community that sent it")]
    IssuerNotSender,
    #[error("the credential's proof: {0}")]
    Proof(#[from] ProofError),
    #[error("the credential's {0} is not a valid timestamp")]
    BadTimestamp(&'static str),
    #[error("the credential is not valid yet")]
    NotYetValid,
    #[error("the credential has expired")]
    Expired,
    #[error("the community has revoked or suspended the credential")]
    Revoked,
    #[error(
        "the credential's revocation status could not be checked (the community's status \
         list was unreachable or did not verify); try again once the community is \
         reachable, or ask it to re-issue the credential"
    )]
    StatusUnknown,
}

/// A credential that passed [`verify_issued_credential`]. The only way to
/// obtain one outside tests, so a caller holding one cannot have skipped the
/// check.
#[derive(Debug, Clone)]
pub struct VerifiedIssuedCredential(Value);

impl VerifiedIssuedCredential {
    /// The credential, exactly as received.
    #[must_use]
    pub fn value(&self) -> &Value {
        &self.0
    }

    /// The credential, exactly as received, by value.
    #[must_use]
    pub fn into_value(self) -> Value {
        self.0
    }

    /// Wrap a credential without verifying it. Tests only: the storage logic
    /// downstream of verification is tested separately from it.
    #[cfg(test)]
    pub(crate) fn assume_verified(value: Value) -> Self {
        Self(value)
    }
}

/// The credential's issuer id (`issuer` as a string or `{ "id": … }`).
#[must_use]
pub fn issuer_of(credential: &Value) -> Option<&str> {
    match credential.get("issuer")? {
        Value::String(s) => Some(s.as_str()),
        Value::Object(o) => o.get("id").and_then(Value::as_str),
        _ => None,
    }
}

/// Verify a credential `sender` delivered as issued by itself: the issuer is
/// the sender, every proof verifies under the issuer's `assertionMethod` keys,
/// it is in its validity window and, where it names a status entry, not
/// revoked.
///
/// # Errors
///
/// The first check that failed, as an [`IssuedCredentialError`].
/// Verify a pushed `credential-exchange/issue` document and the credential it
/// delivers.
///
/// Two proofs, two questions. The **document** proof — by `sender`, the
/// community, under `authentication` — attributes the delivery: the community
/// handed this over, not whoever relayed it. The **credential** proof, checked
/// by [`verify_issued_credential`], is what the credential is trusted by. A VTC
/// signs every `issue` it pushes, so an unsigned one, or one signed by anyone
/// else, is refused before the credential is looked at.
///
/// # Errors
///
/// The first check that failed.
pub async fn verify_issued_delivery(
    document: &Value,
    sender: &str,
    resolver: &DIDCacheClient,
    now: DateTime<Utc>,
) -> Result<VerifiedIssuedCredential, IssuedCredentialError> {
    if document.get("issuer").and_then(Value::as_str) != Some(sender) {
        return Err(IssuedCredentialError::DeliveryIssuerNotSender);
    }
    proof_check::verify_signed(document, sender, resolver, &[Purpose::Authentication])
        .await
        .map_err(IssuedCredentialError::DeliveryProof)?;
    let credential = document
        .pointer("/payload/credential_response/credential")
        .cloned()
        .ok_or(IssuedCredentialError::NoCredential)?;
    verify_issued_credential(credential, sender, resolver, now).await
}

pub async fn verify_issued_credential(
    credential: Value,
    sender: &str,
    resolver: &DIDCacheClient,
    now: DateTime<Utc>,
) -> Result<VerifiedIssuedCredential, IssuedCredentialError> {
    let issuer = issuer_of(&credential).ok_or(IssuedCredentialError::NoIssuer)?;
    if issuer != sender {
        return Err(IssuedCredentialError::IssuerNotSender);
    }
    // Cheap, local checks first: nothing is resolved for a credential that is
    // out of date.
    check_validity_window(&credential, now)?;
    proof_check::verify_signed(&credential, issuer, resolver, &[Purpose::AssertionMethod]).await?;

    if let Some(status) = credential.get("credentialStatus") {
        check_status(status, issuer, resolver, now).await?;
    }
    Ok(VerifiedIssuedCredential(credential))
}

/// Read the credential's status list. Only an established "not revoked"
/// passes: revoked, suspended, and "could not be established" all refuse.
async fn check_status(
    status: &Value,
    issuer: &str,
    resolver: &DIDCacheClient,
    now: DateTime<Utc>,
) -> Result<(), IssuedCredentialError> {
    use crate::status_list::{StatusCheck, check_credential_status};
    use crate::vetting::status::{STATUS_FETCH_TIMEOUT, fetch_owned, status_client};

    let client = status_client(true, STATUS_FETCH_TIMEOUT).map_err(|e| {
        debug!(reason = %e, "issued credential: no HTTP client for the status list");
        IssuedCredentialError::StatusUnknown
    })?;
    match check_credential_status(
        status,
        issuer,
        // Owned arguments, so the future is `Send` for every lifetime the
        // fetch is called with (see `vetting::status::fetch_owned`).
        async move |url: &str| fetch_owned(client.clone(), url.to_string()).await,
        resolver,
        now,
    )
    .await
    {
        StatusCheck::Active => Ok(()),
        StatusCheck::Revoked => Err(IssuedCredentialError::Revoked),
        StatusCheck::Unknown(reason) => {
            debug!(%reason, "issued credential: status could not be established");
            Err(IssuedCredentialError::StatusUnknown)
        }
    }
}

/// `validFrom`/`validUntil` (VC 2.0), or `issuanceDate`/`expirationDate`
/// (VC 1.1). Absent bounds are open; a present bound that does not parse is a
/// refusal.
fn check_validity_window(
    credential: &Value,
    now: DateTime<Utc>,
) -> Result<(), IssuedCredentialError> {
    let read = |key: &'static str| -> Result<Option<DateTime<Utc>>, IssuedCredentialError> {
        match credential.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => DateTime::parse_from_rfc3339(s)
                .map(|t| Some(t.with_timezone(&Utc)))
                .map_err(|_| IssuedCredentialError::BadTimestamp(key)),
            Some(_) => Err(IssuedCredentialError::BadTimestamp(key)),
        }
    };
    let from = match read("validFrom")? {
        Some(t) => Some(t),
        None => read("issuanceDate")?,
    };
    let until = match read("validUntil")? {
        Some(t) => Some(t),
        None => read("expirationDate")?,
    };
    if from.is_some_and(|f| f > now + VALID_FROM_SKEW) {
        return Err(IssuedCredentialError::NotYetValid);
    }
    if until.is_some_and(|u| now >= u) {
        return Err(IssuedCredentialError::Expired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const VTC: &str = "did:webvh:QmScid:vtc.example.com";
    const PERSONA: &str = "did:webvh:QmP:example.com:alice";

    fn credential() -> Value {
        json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "MembershipCredential"],
            "issuer": VTC,
            "validFrom": "2026-01-01T00:00:00Z",
            "validUntil": "2099-01-01T00:00:00Z",
            "credentialSubject": { "id": PERSONA, "role": "member" },
        })
    }

    #[test]
    fn the_validity_window_is_enforced() {
        let now = Utc::now();
        let mut vc = credential();
        assert_eq!(check_validity_window(&vc, now), Ok(()));
        vc["validUntil"] = json!("2020-01-01T00:00:00Z");
        assert_eq!(
            check_validity_window(&vc, now),
            Err(IssuedCredentialError::Expired)
        );
        vc["validUntil"] = json!("2099-01-01T00:00:00Z");
        vc["validFrom"] = json!("2098-01-01T00:00:00Z");
        assert_eq!(
            check_validity_window(&vc, now),
            Err(IssuedCredentialError::NotYetValid)
        );
        vc["validFrom"] = json!("yesterday");
        assert_eq!(
            check_validity_window(&vc, now),
            Err(IssuedCredentialError::BadTimestamp("validFrom"))
        );
    }

    /// The issuer is checked before anything is resolved, and a credential with
    /// no proof is refused without a network call.
    #[tokio::test]
    async fn issuer_and_proof_presence_are_checked_locally() {
        let resolver = DIDCacheClient::new(
            affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
        )
        .await
        .expect("resolver");
        let now = Utc::now();
        assert_eq!(
            verify_issued_credential(
                credential(),
                "did:webvh:QmOther:evil.example.com",
                &resolver,
                now
            )
            .await
            .unwrap_err(),
            IssuedCredentialError::IssuerNotSender
        );
        assert_eq!(
            verify_issued_credential(credential(), VTC, &resolver, now)
                .await
                .unwrap_err(),
            IssuedCredentialError::Proof(ProofError::NoProof)
        );
    }

    /// Revocation fails closed: a validly signed credential whose status list
    /// cannot be reached is refused, with a message that says to retry.
    #[tokio::test]
    async fn an_unreachable_status_list_refuses_the_credential() {
        let resolver = DIDCacheClient::new(
            affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
        )
        .await
        .expect("resolver");
        let mut key =
            affinidi_tdk::secrets_resolver::secrets::Secret::generate_ed25519(None, Some(&[4; 32]));
        let mb = key.get_public_keymultibase().unwrap();
        let issuer = format!("did:key:{mb}");
        key.id = format!("{issuer}#{mb}");
        let mut vc = credential();
        vc["issuer"] = json!(issuer);
        vc["credentialStatus"] = json!({
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListIndex": "7",
            "statusListCredential": "https://127.0.0.1:1/status/revocation",
        });
        let vc = crate::proof_check::test_support::sign(vc, &[&key]).await;
        let err = verify_issued_credential(vc, &issuer, &resolver, Utc::now())
            .await
            .unwrap_err();
        assert_eq!(err, IssuedCredentialError::StatusUnknown);
        assert!(err.to_string().contains("try again"), "{err}");
    }
}
