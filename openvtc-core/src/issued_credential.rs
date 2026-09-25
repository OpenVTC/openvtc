//! Verifying a credential a community issues to us before it is stored.
//!
//! A VTC delivers the membership credential (VMC) and role credentials (VEC)
//! it issues as `credential-exchange/issue` messages. The DIDComm envelope says
//! the message came from the community; it says nothing about whether the
//! credential inside was signed by it. Those are different claims, and only the
//! second is what a stored credential is later relied on for — it is shown as
//! the member's standing and presented to others. So every issued credential is
//! verified here, against the issuer's DID document, before the caller may
//! store it.
//!
//! # Rules
//!
//! - The credential carries at least one Data Integrity proof (a single object
//!   or a proof set). A credential with no proof is refused.
//! - **Every** proof must verify. The VTC signs with Ed25519 and, when it holds
//!   a post-quantum key, adds an ML-DSA-44 proof; this build checks both
//!   suites, so a present-but-invalid proof is a refusal, never skipped.
//! - Each proof's `verificationMethod` belongs to the issuer: its DID (the part
//!   before `#`) equals the issuer exactly, and the issuer's DID document lists
//!   it under the relationship its `proofPurpose` names — `assertionMethod`,
//!   the only purpose accepted for a credential (W3C Data Integrity §4.2 step
//!   "verification method … associated with the proof purpose"). A key the
//!   issuer publishes only for `authentication` or `keyAgreement` does not
//!   sign credentials.
//! - The credential is inside its validity window.
//! - If it names a `credentialStatus`, the issuer's status list is read through
//!   the SDK's existing check. A revoked or suspended credential is refused. A
//!   list that cannot be read is refused under [`StatusPolicy::Required`] and
//!   logged under [`StatusPolicy::Advisory`], which every caller uses today
//!   (see the variants for why).
//!
//! The key is taken from the same document the relationship check read, so the
//! two can never disagree about which key is the issuer's.
//!
//! Error text names what failed, never the credential or any DID: it reaches
//! the log and the user's activity feed.

use std::time::Duration;

use affinidi_data_integrity::crypto_suites::CryptoSuite;
use affinidi_data_integrity::{DataIntegrityProof, VerifyOptions};
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_tdk::did_common::Document;
use affinidi_tdk::did_common::verification_method::{VerificationMethod, VerificationRelationship};
use affinidi_tdk::secrets_resolver::multicodec::{ED25519_PUB, ML_DSA_44_PUB};
use affinidi_tdk::secrets_resolver::secrets::KeyType;
use chrono::{DateTime, Utc};
use serde_json::Value;
use tracing::{debug, warn};

/// The only proof purpose a credential proof may carry.
pub const CREDENTIAL_PROOF_PURPOSE: &str = "assertionMethod";

/// How far in the future a `validFrom` may sit, for clock skew between us and
/// the community.
pub const VALID_FROM_SKEW: chrono::TimeDelta = chrono::TimeDelta::minutes(5);

/// Bound on resolving the issuer's DID document (R1.2).
pub const ISSUER_RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);

/// The suites the VTC signs credentials with, and so the ones checked here.
fn accepted_suites() -> Vec<CryptoSuite> {
    vec![CryptoSuite::EddsaJcs2022, CryptoSuite::MlDsa44Jcs2024]
}

/// Why an issued credential was refused. Each message says what failed and
/// nothing about the credential's contents.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IssuedCredentialError {
    #[error("the credential names no issuer")]
    NoIssuer,
    #[error("the credential's issuer is not the community that sent it")]
    IssuerNotSender,
    #[error("the credential carries no proof")]
    NoProof,
    #[error("proof {0} is not a well-formed Data Integrity proof")]
    MalformedProof(usize),
    #[error("proof {0} has purpose other than assertionMethod")]
    WrongPurpose(usize),
    #[error("proof {0} uses a cryptosuite this client does not accept for credentials")]
    UnsupportedSuite(usize),
    #[error("proof {0} is signed by a key that does not belong to the issuer")]
    ForeignVerificationMethod(usize),
    #[error("proof {0} is signed by a key the issuer does not list for issuing credentials")]
    NotAnAssertionMethod(usize),
    #[error("proof {0} names a key the issuer's DID document does not publish")]
    KeyNotPublished(usize),
    #[error("proof {0} names a key the issuer has revoked")]
    KeyRevoked(usize),
    #[error("proof {0} names a key of a type that does not match its cryptosuite")]
    KeyTypeMismatch(usize),
    #[error("proof {0} did not verify")]
    ProofInvalid(usize),
    #[error("the issuer's DID document could not be resolved")]
    IssuerUnresolved,
    #[error("the resolved DID document is not the issuer's")]
    DocumentMismatch,
    #[error("the credential's {0} is not a valid timestamp")]
    BadTimestamp(&'static str),
    #[error("the credential is not valid yet")]
    NotYetValid,
    #[error("the credential has expired")]
    Expired,
    #[error("the community has revoked or suspended the credential")]
    Revoked,
    #[error("the credential's revocation status could not be checked")]
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
pub async fn verify_issued_credential(
    credential: Value,
    sender: &str,
    resolver: &DIDCacheClient,
    now: DateTime<Utc>,
    status_policy: StatusPolicy,
) -> Result<VerifiedIssuedCredential, IssuedCredentialError> {
    let issuer = issuer_of(&credential).ok_or(IssuedCredentialError::NoIssuer)?;
    if issuer != sender {
        return Err(IssuedCredentialError::IssuerNotSender);
    }
    // Cheap, local checks first: nothing is resolved for a credential that is
    // unsigned or out of date.
    check_validity_window(&credential, now)?;
    if proof_values(&credential)?.is_empty() {
        return Err(IssuedCredentialError::NoProof);
    }

    let doc = match tokio::time::timeout(ISSUER_RESOLVE_TIMEOUT, resolver.resolve(issuer)).await {
        Ok(Ok(resolved)) => resolved.doc,
        Ok(Err(e)) => {
            debug!(error = %e, "issued credential: issuer DID did not resolve");
            return Err(IssuedCredentialError::IssuerUnresolved);
        }
        Err(_) => {
            debug!("issued credential: issuer DID resolution timed out");
            return Err(IssuedCredentialError::IssuerUnresolved);
        }
    };
    verify_proofs(&credential, issuer, &doc)?;

    if let Some(status) = credential.get("credentialStatus") {
        check_status(status, issuer, resolver, status_policy).await?;
    }
    Ok(VerifiedIssuedCredential(credential))
}

/// What to do when a credential names a status list that cannot be read.
///
/// A revoked or suspended credential is refused under either policy; the
/// policies differ only when revocation cannot be established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusPolicy {
    /// Accept, logging that status is unknown. For a credential the community
    /// has just delivered: it cannot have been revoked before it was issued,
    /// and refusing would lose the delivery (it is not re-sent) because the
    /// community's status host was briefly unreachable. Also, for now, for the
    /// vault sync and recovery (see [`StatusPolicy::Required`]).
    Advisory,
    /// Refuse. The right policy for a credential read back from storage
    /// (recovery), where it may be old and revocation is the question that
    /// matters. Not used there yet: `vta_sdk`'s status check cannot read a
    /// status list signed with a proof set, which a post-quantum VTC emits, so
    /// requiring it would refuse every such community's credentials.
    Required,
}

/// Read the status list through the SDK's check. A definite revocation always
/// refuses; an unreadable list refuses only under [`StatusPolicy::Required`].
async fn check_status(
    status: &Value,
    issuer: &str,
    resolver: &DIDCacheClient,
    policy: StatusPolicy,
) -> Result<(), IssuedCredentialError> {
    use crate::vetting::status::{STATUS_FETCH_TIMEOUT, fetch_status_list, status_client};
    use vta_sdk::vetting::status::{StatusCheck, check_credential_status};

    let unknown = |reason: &str| {
        debug!(%reason, "issued credential: status could not be established");
        match policy {
            StatusPolicy::Advisory => {
                warn!("issued credential: revocation status unknown — accepting the delivery");
                Ok(())
            }
            StatusPolicy::Required => Err(IssuedCredentialError::StatusUnknown),
        }
    };
    let client = match status_client(true, STATUS_FETCH_TIMEOUT) {
        Ok(c) => c,
        Err(e) => return unknown(&e),
    };
    let vm_resolver = vta_sdk::trust_task_proof::TrustTaskVmResolver::new(resolver.clone());
    match check_credential_status(
        status,
        issuer,
        async |url: &str| fetch_status_list(&client, url).await,
        &vm_resolver,
    )
    .await
    {
        StatusCheck::Active => Ok(()),
        StatusCheck::Revoked => Err(IssuedCredentialError::Revoked),
        StatusCheck::Unknown(reason) => unknown(&reason),
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

/// The raw proof entries: one object, or each member of a proof set.
fn proof_values(credential: &Value) -> Result<Vec<&Value>, IssuedCredentialError> {
    match credential.get("proof") {
        None | Some(Value::Null) => Err(IssuedCredentialError::NoProof),
        Some(Value::Array(items)) => Ok(items.iter().collect()),
        Some(single) => Ok(vec![single]),
    }
}

/// Verify every proof on `credential` against `issuer_doc`, the resolved DID
/// document of `issuer`. At least one proof must be present and none may fail.
///
/// # Errors
///
/// The first proof that fails, by index.
pub fn verify_proofs(
    credential: &Value,
    issuer: &str,
    issuer_doc: &Document,
) -> Result<(), IssuedCredentialError> {
    if issuer_doc.id.as_str() != issuer {
        return Err(IssuedCredentialError::DocumentMismatch);
    }
    let raw = proof_values(credential)?;
    if raw.is_empty() {
        return Err(IssuedCredentialError::NoProof);
    }

    // Every proof in a set is over the document without its proof block, which
    // is how the VTC's `sign_multi` produces them.
    let mut unsigned = credential.clone();
    if let Some(map) = unsigned.as_object_mut() {
        map.remove("proof");
    }

    for (i, value) in raw.into_iter().enumerate() {
        let proof: DataIntegrityProof = serde_json::from_value(value.clone())
            .map_err(|_| IssuedCredentialError::MalformedProof(i))?;
        verify_one(i, &proof, &unsigned, issuer, issuer_doc)?;
    }
    Ok(())
}

fn verify_one(
    i: usize,
    proof: &DataIntegrityProof,
    unsigned: &Value,
    issuer: &str,
    doc: &Document,
) -> Result<(), IssuedCredentialError> {
    if proof.proof_purpose != CREDENTIAL_PROOF_PURPOSE {
        return Err(IssuedCredentialError::WrongPurpose(i));
    }
    if !accepted_suites().contains(&proof.cryptosuite) {
        return Err(IssuedCredentialError::UnsupportedSuite(i));
    }

    // The method's DID must be the issuer's, exactly — `did:x:issuer-evil#k`
    // shares a prefix with `did:x:issuer` and is somebody else.
    let vm = proof.verification_method.as_str();
    let (vm_did, fragment) = vm
        .split_once('#')
        .ok_or(IssuedCredentialError::ForeignVerificationMethod(i))?;
    if vm_did != issuer || fragment.is_empty() {
        return Err(IssuedCredentialError::ForeignVerificationMethod(i));
    }
    let relative = format!("#{fragment}");

    // The relationship the purpose names must list the method. A document may
    // spell its ids absolutely or relatively; accept both spellings of this
    // exact method and nothing else.
    let listed = doc
        .assertion_method
        .iter()
        .find(|r| r.get_id() == vm || r.get_id() == relative)
        .ok_or(IssuedCredentialError::NotAnAssertionMethod(i))?;

    // The key comes from this same document: embedded in the relationship, or
    // referenced into `verificationMethod`.
    let method: &VerificationMethod = match listed {
        VerificationRelationship::VerificationMethod(m) => m,
        _ => doc
            .verification_method
            .iter()
            .find(|m| m.id.as_str() == vm || m.id.as_str() == relative)
            .ok_or(IssuedCredentialError::KeyNotPublished(i))?,
    };
    if method.revoked.is_some() {
        return Err(IssuedCredentialError::KeyRevoked(i));
    }
    let (codec, key) = method
        .decode_public_key()
        .map_err(|_| IssuedCredentialError::KeyNotPublished(i))?;
    let key_type = match codec {
        ED25519_PUB => KeyType::Ed25519,
        ML_DSA_44_PUB => KeyType::MlDsa44,
        _ => return Err(IssuedCredentialError::KeyTypeMismatch(i)),
    };
    proof
        .cryptosuite
        .validate_key_type(key_type)
        .map_err(|_| IssuedCredentialError::KeyTypeMismatch(i))?;

    proof
        .verify_with_public_key(
            unsigned,
            &key,
            VerifyOptions::new().with_allowed_suites(accepted_suites()),
        )
        .map_err(|e| {
            debug!(proof = i, error = %e, "issued credential proof did not verify");
            IssuedCredentialError::ProofInvalid(i)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_data_integrity::SignOptions;
    use affinidi_tdk::secrets_resolver::secrets::Secret;
    use serde_json::json;

    const VTC: &str = "did:webvh:QmScid:vtc.example.com";
    const OTHER: &str = "did:webvh:QmOther:evil.example.com";
    const PERSONA: &str = "did:webvh:QmP:example.com:alice";

    fn ed_key(did: &str, fragment: &str, seed: u8) -> Secret {
        Secret::generate_ed25519(Some(&format!("{did}#{fragment}")), Some(&[seed; 32]))
    }

    fn pq_key(did: &str, fragment: &str, seed: u8) -> Secret {
        Secret::generate_ml_dsa_44(Some(&format!("{did}#{fragment}")), Some(&[seed; 32]))
    }

    fn multikey(id: &str, controller: &str, secret: &Secret) -> Value {
        json!({
            "id": id,
            "type": "Multikey",
            "controller": controller,
            "publicKeyMultibase": secret.get_public_keymultibase().unwrap(),
        })
    }

    /// A DID document for `did`. `assertion` keys are listed under
    /// `assertionMethod` (relatively, as webvh documents often do); `auth_only`
    /// keys are published but listed only under `authentication` and
    /// `keyAgreement`.
    fn document(
        did: &str,
        assertion: &[(&str, &Secret)],
        auth_only: &[(&str, &Secret)],
    ) -> Document {
        let mut vms = Vec::new();
        for (frag, s) in assertion.iter().chain(auth_only) {
            vms.push(multikey(&format!("{did}#{frag}"), did, s));
        }
        let rel = |keys: &[(&str, &Secret)]| {
            keys.iter()
                .map(|(frag, _)| json!(format!("#{frag}")))
                .collect::<Vec<_>>()
        };
        serde_json::from_value(json!({
            "id": did,
            "verificationMethod": vms,
            "assertionMethod": rel(assertion),
            "authentication": rel(auth_only),
            "keyAgreement": rel(auth_only),
        }))
        .expect("a well-formed DID document")
    }

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

    /// Sign `vc` with each of `signers`, attaching a single proof object for
    /// one signer and a proof set for several — the VTC's shapes.
    async fn sign(mut vc: Value, signers: &[&Secret]) -> Value {
        let mut proofs = Vec::new();
        for s in signers {
            let p = DataIntegrityProof::sign(&vc, *s, SignOptions::new())
                .await
                .expect("sign");
            proofs.push(serde_json::to_value(p).unwrap());
        }
        vc["proof"] = if proofs.len() == 1 {
            proofs.remove(0)
        } else {
            Value::Array(proofs)
        };
        vc
    }

    #[tokio::test]
    async fn a_valid_credential_is_accepted() {
        let key = ed_key(VTC, "key-0", 1);
        let doc = document(VTC, &[("key-0", &key)], &[]);
        let vc = sign(credential(), &[&key]).await;
        assert_eq!(verify_proofs(&vc, VTC, &doc), Ok(()));
    }

    #[tokio::test]
    async fn a_valid_hybrid_proof_set_is_accepted() {
        let ed = ed_key(VTC, "key-0", 1);
        let pq = pq_key(VTC, "key-pq", 2);
        let doc = document(VTC, &[("key-0", &ed), ("key-pq", &pq)], &[]);
        let vc = sign(credential(), &[&ed, &pq]).await;
        assert!(vc["proof"].is_array());
        assert_eq!(verify_proofs(&vc, VTC, &doc), Ok(()));
    }

    #[tokio::test]
    async fn a_tampered_claim_is_refused() {
        let key = ed_key(VTC, "key-0", 1);
        let doc = document(VTC, &[("key-0", &key)], &[]);
        let mut vc = sign(credential(), &[&key]).await;
        vc["credentialSubject"]["role"] = json!("admin");
        assert_eq!(
            verify_proofs(&vc, VTC, &doc),
            Err(IssuedCredentialError::ProofInvalid(0))
        );
    }

    /// A key from another DID is refused even if it verifies its own signature
    /// — and even if the issuer's document were to list it.
    #[tokio::test]
    async fn a_proof_by_another_dids_key_is_refused() {
        let theirs = ed_key(OTHER, "key-0", 9);
        let doc = document(VTC, &[("key-0", &theirs)], &[]);
        let vc = sign(credential(), &[&theirs]).await;
        assert_eq!(
            verify_proofs(&vc, VTC, &doc),
            Err(IssuedCredentialError::ForeignVerificationMethod(0))
        );

        // A DID that merely starts with the issuer's is someone else too.
        let prefixed = format!("{VTC}x");
        let lookalike = ed_key(&prefixed, "key-0", 9);
        let vc = sign(credential(), &[&lookalike]).await;
        assert_eq!(
            verify_proofs(&vc, VTC, &doc),
            Err(IssuedCredentialError::ForeignVerificationMethod(0))
        );
    }

    #[tokio::test]
    async fn a_key_not_listed_as_an_assertion_method_is_refused() {
        let signing = ed_key(VTC, "key-0", 1);
        let auth = ed_key(VTC, "key-auth", 3);
        let doc = document(VTC, &[("key-0", &signing)], &[("key-auth", &auth)]);
        // Signed with a key the VTC publishes, but only for authentication and
        // key agreement.
        let vc = sign(credential(), &[&auth]).await;
        assert_eq!(
            verify_proofs(&vc, VTC, &doc),
            Err(IssuedCredentialError::NotAnAssertionMethod(0))
        );
    }

    /// One good proof does not carry a bad one beside it.
    #[tokio::test]
    async fn a_proof_set_with_one_bad_proof_is_refused() {
        let ed = ed_key(VTC, "key-0", 1);
        let pq = pq_key(VTC, "key-pq", 2);
        let doc = document(VTC, &[("key-0", &ed), ("key-pq", &pq)], &[]);
        let mut vc = sign(credential(), &[&ed, &pq]).await;
        // Corrupt the second (post-quantum) proof's signature.
        let bad = sign(json!({"something": "else"}), &[&pq]).await;
        vc["proof"][1]["proofValue"] = bad["proof"]["proofValue"].clone();
        assert_eq!(
            verify_proofs(&vc, VTC, &doc),
            Err(IssuedCredentialError::ProofInvalid(1))
        );

        // Nor does a set whose second member was signed by an outsider.
        let outsider = ed_key(OTHER, "key-0", 9);
        let mut vc = sign(credential(), &[&ed, &outsider]).await;
        assert!(vc["proof"].is_array());
        assert_eq!(
            verify_proofs(&vc, VTC, &doc),
            Err(IssuedCredentialError::ForeignVerificationMethod(1))
        );
        // And a malformed member is not ignored.
        vc["proof"][1] = json!({"type": "nope"});
        assert_eq!(
            verify_proofs(&vc, VTC, &doc),
            Err(IssuedCredentialError::MalformedProof(1))
        );
    }

    #[tokio::test]
    async fn a_missing_proof_is_refused() {
        let key = ed_key(VTC, "key-0", 1);
        let doc = document(VTC, &[("key-0", &key)], &[]);
        assert_eq!(
            verify_proofs(&credential(), VTC, &doc),
            Err(IssuedCredentialError::NoProof)
        );
        let mut empty = credential();
        empty["proof"] = json!([]);
        assert_eq!(
            verify_proofs(&empty, VTC, &doc),
            Err(IssuedCredentialError::NoProof)
        );
    }

    #[tokio::test]
    async fn a_proof_with_another_purpose_is_refused() {
        let key = ed_key(VTC, "key-0", 1);
        let doc = document(VTC, &[("key-0", &key)], &[]);
        let mut vc = credential();
        let p = DataIntegrityProof::sign(
            &vc,
            &key,
            SignOptions::new().with_proof_purpose("authentication"),
        )
        .await
        .unwrap();
        vc["proof"] = serde_json::to_value(p).unwrap();
        assert_eq!(
            verify_proofs(&vc, VTC, &doc),
            Err(IssuedCredentialError::WrongPurpose(0))
        );
    }

    #[tokio::test]
    async fn a_document_for_another_did_is_refused() {
        let key = ed_key(VTC, "key-0", 1);
        let doc = document(OTHER, &[("key-0", &key)], &[]);
        let vc = sign(credential(), &[&key]).await;
        assert_eq!(
            verify_proofs(&vc, VTC, &doc),
            Err(IssuedCredentialError::DocumentMismatch)
        );
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

    /// The refusal text is safe to show: it names no DID and quotes no claim.
    #[test]
    fn refusal_text_carries_no_identifiers() {
        for e in [
            IssuedCredentialError::ForeignVerificationMethod(0),
            IssuedCredentialError::NotAnAssertionMethod(1),
            IssuedCredentialError::ProofInvalid(0),
            IssuedCredentialError::NoProof,
        ] {
            assert!(!e.to_string().contains("did:"), "{e}");
        }
    }
}
