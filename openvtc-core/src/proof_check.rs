//! Checking a Data Integrity proof against the signer's DID document.
//!
//! The DIDComm (or TSP) transport tells this client which DID a message claims
//! to come from. That is a routing hint, not an identity: whenever a decision
//! turns on *who* said something — a credential stored, a membership ended, a
//! relationship bound to a DID — the claim must carry a proof by that party,
//! checked here.
//!
//! # Rules (W3C Data Integrity)
//!
//! - At least one proof is attached (a single object or a proof set), and
//!   **every** proof must verify. A present-but-invalid proof — bad signature,
//!   unsupported suite, malformed, foreign key — is a refusal, never skipped.
//! - Each proof's `verificationMethod` belongs to the signer: its DID (the part
//!   before `#`) equals the signer exactly — no prefix match.
//! - Its `proofPurpose` is one the caller accepts, and the signer's DID
//!   document lists the method under the relationship that purpose names
//!   (`assertionMethod`, `authentication`). A key published only for
//!   `keyAgreement`, or for another purpose, does not sign.
//! - Suites: `eddsa-jcs-2022`, and `mldsa44-jcs-2024` for a signer that also
//!   holds a post-quantum key. The proofs of a set are each over the document
//!   without its `proof` block, as `sign_multi` produces them.
//!
//! The key is taken from the same document the relationship check read, so the
//! two can never disagree about which key is the signer's.
//!
//! Signature arithmetic is `affinidi-data-integrity`'s; this module adds the
//! binding of a proof to a DID and a relationship, which the shared resolvers
//! do not check.
//!
//! Error text names what failed, never the document or a DID: it reaches the
//! log and the user's activity feed.

use std::time::Duration;

use affinidi_data_integrity::crypto_suites::CryptoSuite;
use affinidi_data_integrity::{DataIntegrityProof, VerifyOptions};
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_tdk::did_common::Document;
use affinidi_tdk::did_common::verification_method::{VerificationMethod, VerificationRelationship};
use affinidi_tdk::secrets_resolver::multicodec::{ED25519_PUB, ML_DSA_44_PUB};
use affinidi_tdk::secrets_resolver::secrets::KeyType;
use serde_json::Value;
use tracing::debug;

/// How far in the future a proof's `created` may be — the same allowance
/// operational documents get on `issuedAt`, so a slightly fast clock at the
/// signer is not a refusal.
pub const CREATED_SKEW: chrono::TimeDelta = chrono::TimeDelta::minutes(5);

/// Bound on resolving a signer's DID document (R1.2).
pub const SIGNER_RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);

/// A proof purpose, and the DID-document relationship that must list the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// `assertionMethod` — credentials and signed statements.
    AssertionMethod,
    /// `authentication` — proving control of a DID.
    Authentication,
}

impl Purpose {
    /// The `proofPurpose` value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Purpose::AssertionMethod => "assertionMethod",
            Purpose::Authentication => "authentication",
        }
    }

    fn relationship(self, doc: &Document) -> &[VerificationRelationship] {
        match self {
            Purpose::AssertionMethod => &doc.assertion_method,
            Purpose::Authentication => &doc.authentication,
        }
    }
}

/// The suites checked here.
fn accepted_suites() -> Vec<CryptoSuite> {
    vec![CryptoSuite::EddsaJcs2022, CryptoSuite::MlDsa44Jcs2024]
}

/// Why a proof was refused. Each message says what failed and nothing about
/// the document or its parties.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProofError {
    #[error("no proof is attached")]
    NoProof,
    #[error("proof {0} is not a well-formed Data Integrity proof")]
    MalformedProof(usize),
    #[error("proof {0} has a purpose this message does not accept")]
    WrongPurpose(usize),
    #[error("proof {0} uses a cryptosuite this client does not accept")]
    UnsupportedSuite(usize),
    #[error("proof {0} is signed by a key that does not belong to the signer")]
    ForeignVerificationMethod(usize),
    #[error("proof {0} is signed by a key the signer does not list for that purpose")]
    NotInRelationship(usize),
    #[error("proof {0} names a key the signer's DID document does not publish")]
    KeyNotPublished(usize),
    #[error("proof {0} names a key controlled by someone other than the signer")]
    ForeignController(usize),
    #[error("proof {0} names a key the signer has revoked")]
    KeyRevoked(usize),
    #[error("proof {0} names a key of a type that does not match its cryptosuite")]
    KeyTypeMismatch(usize),
    #[error("proof {0} did not verify")]
    Invalid(usize),
    #[error("the signer's DID document could not be resolved")]
    SignerUnresolved,
    #[error("the resolved DID document is not the signer's")]
    DocumentMismatch,
}

/// Whether `doc` carries anything in `proof` at all.
#[must_use]
pub fn has_proof(doc: &Value) -> bool {
    proof_values(doc).is_ok_and(|p| !p.is_empty())
}

/// Resolve `did`'s DID document, bounded by [`SIGNER_RESOLVE_TIMEOUT`].
///
/// # Errors
///
/// [`ProofError::SignerUnresolved`]; the resolver's own error is logged at
/// debug only (it can name the DID).
pub async fn resolve_document(
    did: &str,
    resolver: &DIDCacheClient,
) -> Result<Document, ProofError> {
    match tokio::time::timeout(SIGNER_RESOLVE_TIMEOUT, resolver.resolve(did)).await {
        Ok(Ok(resolved)) => Ok(resolved.doc),
        Ok(Err(e)) => {
            debug!(error = %e, "proof check: signer DID did not resolve");
            Err(ProofError::SignerUnresolved)
        }
        Err(_) => {
            debug!("proof check: signer DID resolution timed out");
            Err(ProofError::SignerUnresolved)
        }
    }
}

/// Resolve `signer` and verify every proof on `doc` against it.
///
/// # Errors
///
/// The first check that failed.
pub async fn verify_signed(
    doc: &Value,
    signer: &str,
    resolver: &DIDCacheClient,
    purposes: &[Purpose],
) -> Result<(), ProofError> {
    // Nothing is resolved for a document with no proof.
    if !has_proof(doc) {
        return Err(ProofError::NoProof);
    }
    let signer_doc = resolve_document(signer, resolver).await?;
    verify_proofs(doc, signer, &signer_doc, purposes)
}

/// The raw proof entries: one object, or each member of a proof set.
fn proof_values(doc: &Value) -> Result<Vec<&Value>, ProofError> {
    match doc.get("proof") {
        None | Some(Value::Null) => Err(ProofError::NoProof),
        Some(Value::Array(items)) => Ok(items.iter().collect()),
        Some(single) => Ok(vec![single]),
    }
}

/// Verify every proof on `doc` against `signer_doc`, the resolved DID document
/// of `signer`. At least one proof must be present and none may fail; each
/// must carry one of `purposes`.
///
/// # Errors
///
/// The first proof that fails, by index.
pub fn verify_proofs(
    doc: &Value,
    signer: &str,
    signer_doc: &Document,
    purposes: &[Purpose],
) -> Result<(), ProofError> {
    if signer_doc.id.as_str() != signer {
        return Err(ProofError::DocumentMismatch);
    }
    let raw = proof_values(doc)?;
    if raw.is_empty() {
        return Err(ProofError::NoProof);
    }

    let mut unsigned = doc.clone();
    if let Some(map) = unsigned.as_object_mut() {
        map.remove("proof");
    }

    for (i, value) in raw.into_iter().enumerate() {
        let proof: DataIntegrityProof =
            serde_json::from_value(value.clone()).map_err(|_| ProofError::MalformedProof(i))?;
        verify_one(i, &proof, &unsigned, signer, signer_doc, purposes)?;
    }
    Ok(())
}

fn verify_one(
    i: usize,
    proof: &DataIntegrityProof,
    unsigned: &Value,
    signer: &str,
    doc: &Document,
    purposes: &[Purpose],
) -> Result<(), ProofError> {
    let purpose = purposes
        .iter()
        .copied()
        .find(|p| p.as_str() == proof.proof_purpose)
        .ok_or(ProofError::WrongPurpose(i))?;
    if !accepted_suites().contains(&proof.cryptosuite) {
        return Err(ProofError::UnsupportedSuite(i));
    }

    // The method's DID must be the signer's, exactly — `did:x:signer-evil#k`
    // shares a prefix with `did:x:signer` and is somebody else.
    let vm = proof.verification_method.as_str();
    let (vm_did, fragment) = vm
        .split_once('#')
        .ok_or(ProofError::ForeignVerificationMethod(i))?;
    if vm_did != signer || fragment.is_empty() {
        return Err(ProofError::ForeignVerificationMethod(i));
    }
    let relative = format!("#{fragment}");

    // The relationship the purpose names must list the method. A document may
    // spell its ids absolutely or relatively; accept both spellings of this
    // exact method and nothing else.
    let listed = purpose
        .relationship(doc)
        .iter()
        .find(|r| r.get_id() == vm || r.get_id() == relative)
        .ok_or(ProofError::NotInRelationship(i))?;

    // The key comes from this same document: embedded in the relationship, or
    // referenced into `verificationMethod`.
    let method: &VerificationMethod = match listed {
        VerificationRelationship::VerificationMethod(m) => m,
        _ => doc
            .verification_method
            .iter()
            .find(|m| m.id.as_str() == vm || m.id.as_str() == relative)
            .ok_or(ProofError::KeyNotPublished(i))?,
    };
    // The method's controller is the signer: a document may embed or
    // reference a method some other DID controls, and that method does not
    // speak for the signer.
    if method.controller.as_str() != signer {
        return Err(ProofError::ForeignController(i));
    }
    if method.revoked.is_some() {
        return Err(ProofError::KeyRevoked(i));
    }
    let (codec, key) = method
        .decode_public_key()
        .map_err(|_| ProofError::KeyNotPublished(i))?;
    let key_type = match codec {
        ED25519_PUB => KeyType::Ed25519,
        ML_DSA_44_PUB => KeyType::MlDsa44,
        _ => return Err(ProofError::KeyTypeMismatch(i)),
    };
    proof
        .cryptosuite
        .validate_key_type(key_type)
        .map_err(|_| ProofError::KeyTypeMismatch(i))?;

    proof
        .verify_with_public_key(
            unsigned,
            &key,
            VerifyOptions::new()
                .with_allowed_suites(accepted_suites())
                .with_clock_skew(CREATED_SKEW),
        )
        .map_err(|e| {
            debug!(proof = i, error = %e, "proof did not verify");
            ProofError::Invalid(i)
        })
}

/// Fixtures for tests that need real proofs over real-shaped DID documents.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use affinidi_data_integrity::SignOptions;
    use affinidi_tdk::secrets_resolver::secrets::Secret;
    use serde_json::json;

    pub(crate) fn ed_key(did: &str, fragment: &str, seed: u8) -> Secret {
        Secret::generate_ed25519(Some(&format!("{did}#{fragment}")), Some(&[seed; 32]))
    }

    pub(crate) fn pq_key(did: &str, fragment: &str, seed: u8) -> Secret {
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
    pub(crate) fn document(
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

    /// Sign `doc` with each of `signers` for `purpose`, attaching a single
    /// proof object for one signer and a proof set for several — the VTC's
    /// shapes.
    pub(crate) async fn sign_for(mut doc: Value, signers: &[&Secret], purpose: Purpose) -> Value {
        if let Some(map) = doc.as_object_mut() {
            map.remove("proof");
        }
        let mut proofs = Vec::new();
        for s in signers {
            let p = DataIntegrityProof::sign(
                &doc,
                *s,
                SignOptions::new().with_proof_purpose(purpose.as_str()),
            )
            .await
            .expect("sign");
            proofs.push(serde_json::to_value(p).unwrap());
        }
        doc["proof"] = if proofs.len() == 1 {
            proofs.remove(0)
        } else {
            Value::Array(proofs)
        };
        doc
    }

    /// [`sign_for`] with `assertionMethod`.
    pub(crate) async fn sign(doc: Value, signers: &[&Secret]) -> Value {
        sign_for(doc, signers, Purpose::AssertionMethod).await
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use serde_json::json;

    const SIGNER: &str = "did:webvh:QmScid:vtc.example.com";
    const OTHER: &str = "did:webvh:QmOther:evil.example.com";
    const ASSERT: &[Purpose] = &[Purpose::AssertionMethod];

    fn statement() -> Value {
        json!({ "issuer": SIGNER, "claim": { "role": "member" } })
    }

    #[tokio::test]
    async fn a_valid_proof_is_accepted() {
        let key = ed_key(SIGNER, "key-0", 1);
        let doc = document(SIGNER, &[("key-0", &key)], &[]);
        let signed = sign(statement(), &[&key]).await;
        assert_eq!(verify_proofs(&signed, SIGNER, &doc, ASSERT), Ok(()));
    }

    #[tokio::test]
    async fn a_valid_hybrid_proof_set_is_accepted() {
        let ed = ed_key(SIGNER, "key-0", 1);
        let pq = pq_key(SIGNER, "key-pq", 2);
        let doc = document(SIGNER, &[("key-0", &ed), ("key-pq", &pq)], &[]);
        let signed = sign(statement(), &[&ed, &pq]).await;
        assert!(signed["proof"].is_array());
        assert_eq!(verify_proofs(&signed, SIGNER, &doc, ASSERT), Ok(()));
    }

    #[tokio::test]
    async fn a_tampered_claim_is_refused() {
        let key = ed_key(SIGNER, "key-0", 1);
        let doc = document(SIGNER, &[("key-0", &key)], &[]);
        let mut signed = sign(statement(), &[&key]).await;
        signed["claim"]["role"] = json!("admin");
        assert_eq!(
            verify_proofs(&signed, SIGNER, &doc, ASSERT),
            Err(ProofError::Invalid(0))
        );
    }

    /// A key from another DID is refused even if it verifies its own signature
    /// — and even if the signer's document were to list it.
    #[tokio::test]
    async fn a_proof_by_another_dids_key_is_refused() {
        let theirs = ed_key(OTHER, "key-0", 9);
        let doc = document(SIGNER, &[("key-0", &theirs)], &[]);
        let signed = sign(statement(), &[&theirs]).await;
        assert_eq!(
            verify_proofs(&signed, SIGNER, &doc, ASSERT),
            Err(ProofError::ForeignVerificationMethod(0))
        );

        // A DID that merely starts with the signer's is someone else too.
        let prefixed = format!("{SIGNER}x");
        let lookalike = ed_key(&prefixed, "key-0", 9);
        let signed = sign(statement(), &[&lookalike]).await;
        assert_eq!(
            verify_proofs(&signed, SIGNER, &doc, ASSERT),
            Err(ProofError::ForeignVerificationMethod(0))
        );
    }

    #[tokio::test]
    async fn a_key_not_listed_for_the_purpose_is_refused() {
        let signing = ed_key(SIGNER, "key-0", 1);
        let auth = ed_key(SIGNER, "key-auth", 3);
        let doc = document(SIGNER, &[("key-0", &signing)], &[("key-auth", &auth)]);
        // Signed with a key the signer publishes, but only for authentication
        // and key agreement.
        let signed = sign(statement(), &[&auth]).await;
        assert_eq!(
            verify_proofs(&signed, SIGNER, &doc, ASSERT),
            Err(ProofError::NotInRelationship(0))
        );
        // And the other way round: an assertion key does not authenticate.
        let signed = sign_for(statement(), &[&signing], Purpose::Authentication).await;
        assert_eq!(
            verify_proofs(&signed, SIGNER, &doc, &[Purpose::Authentication]),
            Err(ProofError::NotInRelationship(0))
        );
        // Where the caller accepts authentication, the authentication key does.
        let signed = sign_for(statement(), &[&auth], Purpose::Authentication).await;
        assert_eq!(
            verify_proofs(&signed, SIGNER, &doc, &[Purpose::Authentication]),
            Ok(())
        );
    }

    /// One good proof does not carry a bad one beside it.
    #[tokio::test]
    async fn a_proof_set_with_one_bad_proof_is_refused() {
        let ed = ed_key(SIGNER, "key-0", 1);
        let pq = pq_key(SIGNER, "key-pq", 2);
        let doc = document(SIGNER, &[("key-0", &ed), ("key-pq", &pq)], &[]);
        let mut signed = sign(statement(), &[&ed, &pq]).await;
        // Corrupt the second (post-quantum) proof's signature.
        let bad = sign(json!({"something": "else"}), &[&pq]).await;
        signed["proof"][1]["proofValue"] = bad["proof"]["proofValue"].clone();
        assert_eq!(
            verify_proofs(&signed, SIGNER, &doc, ASSERT),
            Err(ProofError::Invalid(1))
        );

        // Nor does a set whose second member was signed by an outsider.
        let outsider = ed_key(OTHER, "key-0", 9);
        let mut signed = sign(statement(), &[&ed, &outsider]).await;
        assert!(signed["proof"].is_array());
        assert_eq!(
            verify_proofs(&signed, SIGNER, &doc, ASSERT),
            Err(ProofError::ForeignVerificationMethod(1))
        );
        // And a malformed member is not ignored.
        signed["proof"][1] = json!({"type": "nope"});
        assert_eq!(
            verify_proofs(&signed, SIGNER, &doc, ASSERT),
            Err(ProofError::MalformedProof(1))
        );
    }

    #[tokio::test]
    async fn a_missing_proof_is_refused() {
        let key = ed_key(SIGNER, "key-0", 1);
        let doc = document(SIGNER, &[("key-0", &key)], &[]);
        assert_eq!(
            verify_proofs(&statement(), SIGNER, &doc, ASSERT),
            Err(ProofError::NoProof)
        );
        let mut empty = statement();
        empty["proof"] = json!([]);
        assert_eq!(
            verify_proofs(&empty, SIGNER, &doc, ASSERT),
            Err(ProofError::NoProof)
        );
        assert!(!has_proof(&empty));
    }

    #[tokio::test]
    async fn a_proof_with_another_purpose_is_refused() {
        let key = ed_key(SIGNER, "key-0", 1);
        let doc = document(SIGNER, &[("key-0", &key)], &[]);
        let signed = sign_for(statement(), &[&key], Purpose::Authentication).await;
        assert_eq!(
            verify_proofs(&signed, SIGNER, &doc, ASSERT),
            Err(ProofError::WrongPurpose(0))
        );
    }

    #[tokio::test]
    async fn a_document_for_another_did_is_refused() {
        let key = ed_key(SIGNER, "key-0", 1);
        let doc = document(OTHER, &[("key-0", &key)], &[]);
        let signed = sign(statement(), &[&key]).await;
        assert_eq!(
            verify_proofs(&signed, SIGNER, &doc, ASSERT),
            Err(ProofError::DocumentMismatch)
        );
    }

    /// A method the signer's document embeds but someone else controls does
    /// not speak for the signer.
    #[tokio::test]
    async fn a_method_controlled_by_another_did_is_refused() {
        let key = ed_key(SIGNER, "key-0", 1);
        let doc: Document = serde_json::from_value(json!({
            "id": SIGNER,
            "assertionMethod": [{
                "id": format!("{SIGNER}#key-0"),
                "type": "Multikey",
                "controller": OTHER,
                "publicKeyMultibase": key.get_public_keymultibase().unwrap(),
            }],
        }))
        .unwrap();
        let signed = sign(statement(), &[&key]).await;
        assert_eq!(
            verify_proofs(&signed, SIGNER, &doc, ASSERT),
            Err(ProofError::ForeignController(0))
        );
    }

    /// A proof `created` a little in the signer's future (its clock runs fast)
    /// still verifies; one far in the future does not.
    #[tokio::test]
    async fn a_slightly_fast_signer_clock_is_tolerated() {
        use affinidi_data_integrity::SignOptions;
        let key = ed_key(SIGNER, "key-0", 1);
        let doc = document(SIGNER, &[("key-0", &key)], &[]);
        for (ahead, ok) in [
            (chrono::TimeDelta::minutes(3), true),
            (chrono::TimeDelta::hours(1), false),
        ] {
            let mut st = statement();
            let p = DataIntegrityProof::sign(
                &st,
                &key,
                SignOptions::new().with_created(chrono::Utc::now() + ahead),
            )
            .await
            .unwrap();
            st["proof"] = serde_json::to_value(p).unwrap();
            assert_eq!(
                verify_proofs(&st, SIGNER, &doc, ASSERT).is_ok(),
                ok,
                "{ahead}"
            );
        }
    }

    /// The refusal text is safe to show: it names no DID and quotes no claim.
    #[test]
    fn refusal_text_carries_no_identifiers() {
        for e in [
            ProofError::ForeignVerificationMethod(0),
            ProofError::NotInRelationship(1),
            ProofError::Invalid(0),
            ProofError::NoProof,
            ProofError::SignerUnresolved,
        ] {
            assert!(!e.to_string().contains("did:"), "{e}");
        }
    }
}
