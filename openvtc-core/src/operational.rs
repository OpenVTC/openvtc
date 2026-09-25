//! Operational documents from a community: signed, addressed, fresh, once.
//!
//! A removal notice or a community's answer to a question of ours is an
//! *operational* message — the community acting, not attesting. Such a
//! document is acted on only when (VTI-KEY-106, VTI-KEY-107):
//!
//! - its `issuer` is the community it came from, and a proof by that DID
//!   verifies with `proofPurpose: authentication` under a key its DID document
//!   lists under `authentication` (the community's operational key). A proof
//!   under `assertionMethod` is refused here: that key issues credentials, and
//!   credentials are a different thing from acting;
//! - it names a `recipient`, which is the persona it is for;
//! - it carries an `issuedAt` inside the window its kind allows (not in the
//!   future beyond clock skew, not older than [`OperationalKind::max_age`]),
//!   and any `expiresAt` has not passed;
//! - its `id` has not been acted on before ([`SeenDocuments`], persisted, so a
//!   replay after a restart is caught too). The id is recorded only after the
//!   proof verifies, so an unsigned copy cannot burn a genuine document's id.
//!
//! Membership and role credentials, and vetter grants, are attestations and
//! stay under `assertionMethod` ([`crate::issued_credential`]).

use std::collections::BTreeMap;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::proof_check::{self, ProofError, Purpose};

/// Clock skew allowed on `issuedAt`.
pub const ISSUED_AT_SKEW: TimeDelta = TimeDelta::minutes(5);

/// How many document ids are remembered. Entries are dropped once their
/// window has passed (a replay is then refused as stale instead), so this
/// bounds only a burst.
pub const MAX_SEEN_DOCUMENTS: usize = 4096;

/// What an operational document is, for the freshness window it gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationalKind {
    /// A removal notice. Pushed to a member who may be offline, and delivered
    /// for up to thirty days, so its window matches.
    RemovalNotice,
    /// A community's answer to a question we asked.
    CommunityAnswer,
}

impl OperationalKind {
    /// The oldest an `issuedAt` may be.
    #[must_use]
    pub fn max_age(self) -> TimeDelta {
        match self {
            OperationalKind::RemovalNotice => TimeDelta::days(30) + TimeDelta::days(1),
            OperationalKind::CommunityAnswer => TimeDelta::days(1),
        }
    }
}

/// Why an operational document was not acted on. Names what failed, never the
/// document or a DID.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OperationalError {
    #[error("it is not a Trust Task document")]
    NotADocument,
    #[error("it has no id")]
    NoId,
    #[error("it is not issued by the community it came from")]
    IssuerNotSender,
    #[error("it names no recipient")]
    NoRecipient,
    #[error("it is addressed to someone else")]
    WrongRecipient,
    #[error("it has no valid issuedAt")]
    NoIssuedAt,
    #[error("it is dated in the future")]
    FromTheFuture,
    #[error("it is too old to act on")]
    TooOld,
    #[error("it has expired")]
    Expired,
    #[error("it was already acted on (replay)")]
    Replayed,
    #[error("its proof: {0}")]
    Proof(#[from] ProofError),
}

/// Document ids already acted on, each kept until its window has passed.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SeenDocuments {
    /// id → when it may be forgotten.
    #[serde(default)]
    entries: BTreeMap<String, DateTime<Utc>>,
}

impl SeenDocuments {
    /// Nothing remembered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether `id` was already acted on (and not yet forgotten).
    #[must_use]
    pub fn contains(&self, id: &str, now: DateTime<Utc>) -> bool {
        self.entries.get(id).is_some_and(|until| *until > now)
    }

    /// Remember `id` until `forget_after`. Returns `false` if it was already
    /// remembered — a replay.
    pub fn record(&mut self, id: &str, forget_after: DateTime<Utc>, now: DateTime<Utc>) -> bool {
        self.entries.retain(|_, until| *until > now);
        if self.contains(id, now) {
            return false;
        }
        while self.entries.len() >= MAX_SEEN_DOCUMENTS {
            // Drop the one closest to expiry.
            let Some(first) = self
                .entries
                .iter()
                .min_by_key(|(_, until)| **until)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            self.entries.remove(&first);
        }
        self.entries.insert(id.to_string(), forget_after);
        true
    }
}

/// Verify an operational `document` from `sender` addressed to one of
/// `our_dids`, and record its id. Returns the recipient it named.
///
/// # Errors
///
/// [`OperationalError`] naming the first check that failed. Nothing is
/// recorded on failure.
pub async fn verify_operational(
    document: &Value,
    sender: &str,
    our_dids: &[&str],
    kind: OperationalKind,
    resolver: &DIDCacheClient,
    seen: &mut SeenDocuments,
    now: DateTime<Utc>,
) -> Result<String, OperationalError> {
    let recipient = check_envelope(document, sender, our_dids, kind, seen, now)?;
    proof_check::verify_signed(document, sender, resolver, &[Purpose::Authentication]).await?;
    record(document, kind, seen, now)?;
    Ok(recipient)
}

/// [`verify_operational`] against an already-resolved sender document.
///
/// # Errors
///
/// As [`verify_operational`].
pub fn verify_operational_with(
    document: &Value,
    sender: &str,
    sender_doc: &affinidi_tdk::did_common::Document,
    our_dids: &[&str],
    kind: OperationalKind,
    seen: &mut SeenDocuments,
    now: DateTime<Utc>,
) -> Result<String, OperationalError> {
    let recipient = check_envelope(document, sender, our_dids, kind, seen, now)?;
    proof_check::verify_proofs(document, sender, sender_doc, &[Purpose::Authentication])?;
    record(document, kind, seen, now)?;
    Ok(recipient)
}

/// Everything but the proof: cheap, local, and done first.
fn check_envelope(
    document: &Value,
    sender: &str,
    our_dids: &[&str],
    kind: OperationalKind,
    seen: &SeenDocuments,
    now: DateTime<Utc>,
) -> Result<String, OperationalError> {
    let obj = document.as_object().ok_or(OperationalError::NotADocument)?;
    if !obj.contains_key("payload") {
        return Err(OperationalError::NotADocument);
    }
    let id = obj
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(OperationalError::NoId)?;
    if obj.get("issuer").and_then(Value::as_str) != Some(sender) {
        return Err(OperationalError::IssuerNotSender);
    }
    let recipient = obj
        .get("recipient")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(OperationalError::NoRecipient)?;
    if !our_dids.contains(&recipient) {
        return Err(OperationalError::WrongRecipient);
    }
    let issued_at = timestamp(obj.get("issuedAt")).ok_or(OperationalError::NoIssuedAt)?;
    if issued_at > now + ISSUED_AT_SKEW {
        return Err(OperationalError::FromTheFuture);
    }
    if issued_at + kind.max_age() < now {
        return Err(OperationalError::TooOld);
    }
    match obj.get("expiresAt") {
        None | Some(Value::Null) => {}
        Some(v) => {
            let expires = timestamp(Some(v)).ok_or(OperationalError::Expired)?;
            if expires <= now {
                return Err(OperationalError::Expired);
            }
        }
    }
    if seen.contains(id, now) {
        return Err(OperationalError::Replayed);
    }
    Ok(recipient.to_string())
}

fn record(
    document: &Value,
    kind: OperationalKind,
    seen: &mut SeenDocuments,
    now: DateTime<Utc>,
) -> Result<(), OperationalError> {
    let id = document
        .get("id")
        .and_then(Value::as_str)
        .ok_or(OperationalError::NoId)?;
    let issued_at = timestamp(document.get("issuedAt")).ok_or(OperationalError::NoIssuedAt)?;
    // Remembered until it would be refused as too old anyway.
    let forget_after = issued_at + kind.max_age() + ISSUED_AT_SKEW;
    if seen.record(id, forget_after, now) {
        Ok(())
    } else {
        Err(OperationalError::Replayed)
    }
}

fn timestamp(value: Option<&Value>) -> Option<DateTime<Utc>> {
    value
        .and_then(Value::as_str)
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.with_timezone(&Utc))
}

/// Test fixtures: an operational document signed as a community signs one.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use affinidi_tdk::secrets_resolver::secrets::Secret;
    use serde_json::json;

    /// A fresh operational document from `issuer` to `recipient`.
    pub(crate) fn document(issuer: &str, recipient: &str, payload: Value) -> Value {
        json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": "https://trusttasks.org/spec/vtc/test/0.1",
            "issuer": issuer,
            "recipient": recipient,
            "issuedAt": Utc::now().to_rfc3339(),
            "payload": payload,
        })
    }

    /// Sign `doc` with `signer` under `authentication`.
    pub(crate) async fn sign(doc: Value, signer: &Secret) -> Value {
        proof_check::test_support::sign_for(doc, &[signer], Purpose::Authentication).await
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{document, sign};
    use super::*;
    use crate::proof_check::test_support::{document as did_document, ed_key};
    use serde_json::json;

    const VTC: &str = "did:webvh:QmScid:vtc.example.com";
    const ME: &str = "did:webvh:QmP:example.com:alice";

    /// The VTC's DID document: `#key-0` issues credentials, `#key-op` is its
    /// operational (authentication) key.
    fn vtc() -> (
        affinidi_tdk::secrets_resolver::secrets::Secret,
        affinidi_tdk::secrets_resolver::secrets::Secret,
        affinidi_tdk::did_common::Document,
    ) {
        let assertion = ed_key(VTC, "key-0", 1);
        let op = ed_key(VTC, "key-op", 2);
        let doc = did_document(VTC, &[("key-0", &assertion)], &[("key-op", &op)]);
        (assertion, op, doc)
    }

    fn verify(
        d: &Value,
        doc: &affinidi_tdk::did_common::Document,
        seen: &mut SeenDocuments,
    ) -> Result<String, OperationalError> {
        verify_operational_with(
            d,
            VTC,
            doc,
            &[ME],
            OperationalKind::CommunityAnswer,
            seen,
            Utc::now(),
        )
    }

    #[tokio::test]
    async fn a_fresh_signed_addressed_document_is_accepted_once() {
        let (_, op, doc) = vtc();
        let mut seen = SeenDocuments::default();
        let d = sign(document(VTC, ME, json!({})), &op).await;
        assert_eq!(verify(&d, &doc, &mut seen), Ok(ME.to_string()));
        assert_eq!(verify(&d, &doc, &mut seen), Err(OperationalError::Replayed));
    }

    /// VTI-KEY-106: acting is the operational key's job, not the credential
    /// key's — even a valid assertionMethod proof is refused here.
    #[tokio::test]
    async fn an_assertion_method_proof_is_not_operational() {
        let (assertion, _, doc) = vtc();
        let mut seen = SeenDocuments::default();
        let d = proof_check::test_support::sign(document(VTC, ME, json!({})), &[&assertion]).await;
        assert!(matches!(
            verify(&d, &doc, &mut seen),
            Err(OperationalError::Proof(ProofError::WrongPurpose(0)))
        ));
        // An authentication-purpose proof by the assertion key: not listed.
        let d = sign(document(VTC, ME, json!({})), &assertion).await;
        assert!(matches!(
            verify(&d, &doc, &mut seen),
            Err(OperationalError::Proof(ProofError::NotInRelationship(0)))
        ));
        assert!(seen.is_empty(), "nothing recorded for a refused document");
    }

    #[tokio::test]
    async fn recipient_window_and_issuer_are_required() {
        let (_, op, doc) = vtc();
        let mut seen = SeenDocuments::default();

        let mut no_recipient = document(VTC, ME, json!({}));
        no_recipient.as_object_mut().unwrap().remove("recipient");
        let no_recipient = sign(no_recipient, &op).await;
        assert_eq!(
            verify(&no_recipient, &doc, &mut seen),
            Err(OperationalError::NoRecipient)
        );

        let other = sign(
            document(VTC, "did:webvh:QmP:example.com:bob", json!({})),
            &op,
        )
        .await;
        assert_eq!(
            verify(&other, &doc, &mut seen),
            Err(OperationalError::WrongRecipient)
        );

        let mut undated = document(VTC, ME, json!({}));
        undated.as_object_mut().unwrap().remove("issuedAt");
        let undated = sign(undated, &op).await;
        assert_eq!(
            verify(&undated, &doc, &mut seen),
            Err(OperationalError::NoIssuedAt)
        );

        let mut old = document(VTC, ME, json!({}));
        old["issuedAt"] = json!((Utc::now() - TimeDelta::days(2)).to_rfc3339());
        let old = sign(old, &op).await;
        assert_eq!(verify(&old, &doc, &mut seen), Err(OperationalError::TooOld));

        let mut future = document(VTC, ME, json!({}));
        future["issuedAt"] = json!((Utc::now() + TimeDelta::hours(1)).to_rfc3339());
        let future = sign(future, &op).await;
        assert_eq!(
            verify(&future, &doc, &mut seen),
            Err(OperationalError::FromTheFuture)
        );

        let mut expired = document(VTC, ME, json!({}));
        expired["expiresAt"] = json!((Utc::now() - TimeDelta::minutes(1)).to_rfc3339());
        let expired = sign(expired, &op).await;
        assert_eq!(
            verify(&expired, &doc, &mut seen),
            Err(OperationalError::Expired)
        );

        let mut foreign = document("did:webvh:QmOther:evil.example.com", ME, json!({}));
        foreign["issuer"] = json!("did:webvh:QmOther:evil.example.com");
        let foreign = sign(foreign, &op).await;
        assert_eq!(
            verify(&foreign, &doc, &mut seen),
            Err(OperationalError::IssuerNotSender)
        );

        // An unsigned copy of a genuine document does not burn its id.
        let genuine = sign(document(VTC, ME, json!({})), &op).await;
        let mut unsigned = genuine.clone();
        unsigned.as_object_mut().unwrap().remove("proof");
        assert!(verify(&unsigned, &doc, &mut seen).is_err());
        assert_eq!(verify(&genuine, &doc, &mut seen), Ok(ME.to_string()));
    }

    #[test]
    fn remembered_ids_are_forgotten_after_their_window() {
        let mut seen = SeenDocuments::default();
        let now = Utc::now();
        assert!(seen.record("a", now + TimeDelta::hours(1), now));
        assert!(!seen.record("a", now + TimeDelta::hours(1), now));
        let later = now + TimeDelta::hours(2);
        assert!(!seen.contains("a", later));
        assert!(seen.record("a", later + TimeDelta::hours(1), later));
    }
}
