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
//! - its signed `type` is the one the handler acting on it handles — a
//!   community's signed answer to one question cannot be replayed as a
//!   removal notice, or as its answer to another — and the freshness window
//!   comes from that type ([`OperationalKind::of`]);
//! - it names a `recipient`, which is the persona it is for;
//! - it carries an `issuedAt` inside the window its kind allows (not in the
//!   future beyond clock skew, not older than [`OperationalKind::max_age`]),
//!   and any `expiresAt` has not passed;
//! - its `id` (at most [`MAX_DOCUMENT_ID_CHARS`]) has not been acted on before
//!   by that issuer ([`SeenDocuments`], persisted, so a replay after a restart
//!   is caught too).
//!
//! # Recording, and why it is the caller's step
//!
//! [`verify_operational`] records nothing: it returns a
//! [`VerifiedOperational`] the caller [`commit`](VerifiedOperational::commit)s
//! only once the document has been *bound* — the sender is a community we
//! hold a membership with and the payload names what it should, or a reply has
//! matched a request we have outstanding. A party able to sign with its own
//! key, but with no standing, therefore cannot write to the replay set at all.
//!
//! The set is keyed by `(issuer, id)`, holds at most
//! [`MAX_SEEN_PER_ISSUER`] ids per issuer and [`MAX_SEEN_ISSUERS`] issuers,
//! and at the bound it **refuses** new documents rather than evicting: an
//! entry is never dropped before its window has passed, so a genuine
//! document's id cannot be pushed out and replayed.
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

/// The longest document id accepted.
pub const MAX_DOCUMENT_ID_CHARS: usize = 256;

/// Most ids remembered for one issuer. At the bound a new document from that
/// issuer is refused until earlier ids age out; nothing is evicted.
pub const MAX_SEEN_PER_ISSUER: usize = 1024;

/// Most issuers remembered. Only bound documents are recorded (communities we
/// belong to, replies we asked for), so this is a backstop.
pub const MAX_SEEN_ISSUERS: usize = 256;

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
    /// The kind a document of type `typ` is. Taken from the type the handler
    /// handles, which the document's own signed `type` must equal.
    #[must_use]
    pub fn of(typ: &str) -> Self {
        if typ == vta_sdk::protocols::members::MEMBER_REMOVAL_NOTICE_TYPE {
            OperationalKind::RemovalNotice
        } else {
            OperationalKind::CommunityAnswer
        }
    }

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
    #[error("its signed type is not the one this message was handled as")]
    WrongType,
    #[error("its id is too long")]
    IdTooLong,
    #[error("too many recent documents from this community to take another yet")]
    QuotaExceeded,
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

/// Document ids already acted on, per issuer, each kept until its window has
/// passed.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SeenDocuments {
    /// issuer → id → when it may be forgotten.
    #[serde(default)]
    entries: BTreeMap<String, BTreeMap<String, DateTime<Utc>>>,
    /// Bumped on every change, so a caller can tell the set needs saving.
    #[serde(skip)]
    revision: u64,
}

impl SeenDocuments {
    /// Nothing remembered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// A counter that changes whenever the set does — compare before and after
    /// to know whether it needs persisting.
    #[must_use]
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Whether `issuer` already sent a document `id` (not yet forgotten).
    #[must_use]
    pub fn contains(&self, issuer: &str, id: &str, now: DateTime<Utc>) -> bool {
        self.entries
            .get(issuer)
            .and_then(|ids| ids.get(id))
            .is_some_and(|until| *until > now)
    }

    /// Drop entries whose window has passed — and only those.
    fn prune(&mut self, now: DateTime<Utc>) {
        let before: usize = self.entries.values().map(BTreeMap::len).sum();
        for ids in self.entries.values_mut() {
            ids.retain(|_, until| *until > now);
        }
        self.entries.retain(|_, ids| !ids.is_empty());
        let after: usize = self.entries.values().map(BTreeMap::len).sum();
        if after != before {
            self.revision += 1;
        }
    }

    /// Whether `record(issuer, id, ..)` would succeed now.
    ///
    /// # Errors
    ///
    /// [`OperationalError::Replayed`] or [`OperationalError::QuotaExceeded`].
    pub fn check(
        &self,
        issuer: &str,
        id: &str,
        now: DateTime<Utc>,
    ) -> Result<(), OperationalError> {
        if self.contains(issuer, id, now) {
            return Err(OperationalError::Replayed);
        }
        let live =
            |ids: &BTreeMap<String, DateTime<Utc>>| ids.values().filter(|u| **u > now).count();
        match self.entries.get(issuer) {
            Some(ids) if live(ids) >= MAX_SEEN_PER_ISSUER => Err(OperationalError::QuotaExceeded),
            None if self.entries.values().filter(|ids| live(ids) > 0).count()
                >= MAX_SEEN_ISSUERS =>
            {
                Err(OperationalError::QuotaExceeded)
            }
            _ => Ok(()),
        }
    }

    /// Remember `(issuer, id)` until `forget_after`.
    ///
    /// # Errors
    ///
    /// [`OperationalError::Replayed`] if already remembered, or
    /// [`OperationalError::QuotaExceeded`] at a bound — nothing is evicted to
    /// make room.
    pub fn record(
        &mut self,
        issuer: &str,
        id: &str,
        forget_after: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<(), OperationalError> {
        self.prune(now);
        self.check(issuer, id, now)?;
        self.entries
            .entry(issuer.to_string())
            .or_default()
            .insert(id.to_string(), forget_after);
        self.revision += 1;
        Ok(())
    }
}

/// An operational document whose envelope and proof verified, not yet
/// recorded. [`commit`](Self::commit) it once the caller has bound it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "a verified document must be committed once bound, or it can be replayed"]
pub struct VerifiedOperational {
    issuer: String,
    id: String,
    recipient: String,
    forget_after: DateTime<Utc>,
}

impl VerifiedOperational {
    /// The recipient the document named (one of ours).
    #[must_use]
    pub fn recipient(&self) -> &str {
        &self.recipient
    }

    /// Whether committing would succeed (not a replay, under quota). Check this
    /// before acting, then [`commit`](Self::commit) after.
    ///
    /// # Errors
    ///
    /// As [`SeenDocuments::check`].
    pub fn check(&self, seen: &SeenDocuments, now: DateTime<Utc>) -> Result<(), OperationalError> {
        seen.check(&self.issuer, &self.id, now)
    }

    /// Record the document as acted on.
    ///
    /// # Errors
    ///
    /// As [`SeenDocuments::record`].
    pub fn commit(
        self,
        seen: &mut SeenDocuments,
        now: DateTime<Utc>,
    ) -> Result<(), OperationalError> {
        seen.record(&self.issuer, &self.id, self.forget_after, now)
    }
}

/// Verify an operational `document` from `sender` addressed to one of
/// `our_dids`, handled as type `typ` (which its signed `type` must be). Records nothing: the caller binds the result and then
/// [commits](VerifiedOperational::commit) it.
///
/// # Errors
///
/// [`OperationalError`] naming the first check that failed, including a
/// document already recorded as acted on.
pub async fn verify_operational(
    document: &Value,
    sender: &str,
    our_dids: &[&str],
    typ: &str,
    resolver: &DIDCacheClient,
    seen: &SeenDocuments,
    now: DateTime<Utc>,
) -> Result<VerifiedOperational, OperationalError> {
    let verified = check_envelope(document, sender, our_dids, typ, seen, now)?;
    proof_check::verify_signed(document, sender, resolver, &[Purpose::Authentication]).await?;
    Ok(verified)
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
    typ: &str,
    seen: &SeenDocuments,
    now: DateTime<Utc>,
) -> Result<VerifiedOperational, OperationalError> {
    let verified = check_envelope(document, sender, our_dids, typ, seen, now)?;
    proof_check::verify_proofs(document, sender, sender_doc, &[Purpose::Authentication])?;
    Ok(verified)
}

/// Everything but the proof: cheap, local, and done first.
fn check_envelope(
    document: &Value,
    sender: &str,
    our_dids: &[&str],
    typ: &str,
    seen: &SeenDocuments,
    now: DateTime<Utc>,
) -> Result<VerifiedOperational, OperationalError> {
    let obj = document.as_object().ok_or(OperationalError::NotADocument)?;
    if !obj.contains_key("payload") {
        return Err(OperationalError::NotADocument);
    }
    // The handler is chosen by the message's type, which is not signed; the
    // document's is. They must agree, or a signed document of one kind could
    // be acted on as another.
    if obj.get("type").and_then(Value::as_str) != Some(typ) {
        return Err(OperationalError::WrongType);
    }
    let kind = OperationalKind::of(typ);
    let id = obj
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(OperationalError::NoId)?;
    if id.chars().count() > MAX_DOCUMENT_ID_CHARS {
        return Err(OperationalError::IdTooLong);
    }
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
    if seen.contains(sender, id, now) {
        return Err(OperationalError::Replayed);
    }
    Ok(VerifiedOperational {
        issuer: sender.to_string(),
        id: id.to_string(),
        recipient: recipient.to_string(),
        // Remembered until it would be refused as too old anyway.
        forget_after: issued_at + kind.max_age() + ISSUED_AT_SKEW,
    })
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

    /// The type [`document`] gives its documents.
    pub(crate) const TEST_TYPE: &str = "https://trusttasks.org/spec/vtc/test/0.1";

    /// A fresh operational document from `issuer` to `recipient`.
    pub(crate) fn document(issuer: &str, recipient: &str, payload: Value) -> Value {
        json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": TEST_TYPE,
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
    use super::test_support::{TEST_TYPE, document, sign};
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
        seen: &SeenDocuments,
    ) -> Result<VerifiedOperational, OperationalError> {
        verify_operational_with(d, VTC, doc, &[ME], TEST_TYPE, seen, Utc::now())
    }

    #[tokio::test]
    async fn a_committed_document_is_not_taken_again() {
        let (_, op, doc) = vtc();
        let mut seen = SeenDocuments::default();
        let d = sign(document(VTC, ME, json!({})), &op).await;
        let v = verify(&d, &doc, &seen).unwrap();
        assert_eq!(v.recipient(), ME);
        // Verification alone records nothing.
        assert!(seen.is_empty());
        assert!(verify(&d, &doc, &seen).is_ok());
        let rev = seen.revision();
        v.commit(&mut seen, Utc::now()).unwrap();
        assert_ne!(seen.revision(), rev, "a commit is a change to persist");
        assert_eq!(verify(&d, &doc, &seen), Err(OperationalError::Replayed));
    }

    /// VTI-KEY-106: acting is the operational key's job, not the credential
    /// key's — even a valid assertionMethod proof is refused here.
    /// The document's signed `type` binds it to the handler: a community's
    /// signed answer cannot be acted on as a removal notice (or any other
    /// type), and the window is the handled type's.
    #[tokio::test]
    async fn a_document_is_taken_only_as_its_signed_type() {
        let (_, op, doc) = vtc();
        let seen = SeenDocuments::default();
        let d = sign(document(VTC, ME, json!({})), &op).await;
        assert!(verify(&d, &doc, &seen).is_ok());
        let as_notice = verify_operational_with(
            &d,
            VTC,
            &doc,
            &[ME],
            vta_sdk::protocols::members::MEMBER_REMOVAL_NOTICE_TYPE,
            &seen,
            Utc::now(),
        );
        assert_eq!(as_notice, Err(OperationalError::WrongType));

        // No signed type at all.
        let mut untyped = document(VTC, ME, json!({}));
        untyped.as_object_mut().unwrap().remove("type");
        let untyped = sign(untyped, &op).await;
        assert_eq!(
            verify(&untyped, &doc, &seen),
            Err(OperationalError::WrongType)
        );

        assert_eq!(
            OperationalKind::of(vta_sdk::protocols::members::MEMBER_REMOVAL_NOTICE_TYPE),
            OperationalKind::RemovalNotice
        );
        assert_eq!(
            OperationalKind::of(TEST_TYPE),
            OperationalKind::CommunityAnswer
        );
    }

    #[tokio::test]
    async fn an_assertion_method_proof_is_not_operational() {
        let (assertion, _, doc) = vtc();
        let seen = SeenDocuments::default();
        let d = proof_check::test_support::sign(document(VTC, ME, json!({})), &[&assertion]).await;
        assert!(matches!(
            verify(&d, &doc, &seen),
            Err(OperationalError::Proof(ProofError::WrongPurpose(0)))
        ));
        let d = sign(document(VTC, ME, json!({})), &assertion).await;
        assert!(matches!(
            verify(&d, &doc, &seen),
            Err(OperationalError::Proof(ProofError::NotInRelationship(0)))
        ));
    }

    #[tokio::test]
    async fn recipient_window_issuer_and_id_are_required() {
        let (_, op, doc) = vtc();
        let seen = SeenDocuments::default();

        let mut no_recipient = document(VTC, ME, json!({}));
        no_recipient.as_object_mut().unwrap().remove("recipient");
        let no_recipient = sign(no_recipient, &op).await;
        assert_eq!(
            verify(&no_recipient, &doc, &seen),
            Err(OperationalError::NoRecipient)
        );

        let other = sign(
            document(VTC, "did:webvh:QmP:example.com:bob", json!({})),
            &op,
        )
        .await;
        assert_eq!(
            verify(&other, &doc, &seen),
            Err(OperationalError::WrongRecipient)
        );

        let mut undated = document(VTC, ME, json!({}));
        undated.as_object_mut().unwrap().remove("issuedAt");
        let undated = sign(undated, &op).await;
        assert_eq!(
            verify(&undated, &doc, &seen),
            Err(OperationalError::NoIssuedAt)
        );

        let mut old = document(VTC, ME, json!({}));
        old["issuedAt"] = json!((Utc::now() - TimeDelta::days(2)).to_rfc3339());
        let old = sign(old, &op).await;
        assert_eq!(verify(&old, &doc, &seen), Err(OperationalError::TooOld));

        let mut future = document(VTC, ME, json!({}));
        future["issuedAt"] = json!((Utc::now() + TimeDelta::hours(1)).to_rfc3339());
        let future = sign(future, &op).await;
        assert_eq!(
            verify(&future, &doc, &seen),
            Err(OperationalError::FromTheFuture)
        );

        let mut expired = document(VTC, ME, json!({}));
        expired["expiresAt"] = json!((Utc::now() - TimeDelta::minutes(1)).to_rfc3339());
        let expired = sign(expired, &op).await;
        assert_eq!(
            verify(&expired, &doc, &seen),
            Err(OperationalError::Expired)
        );

        let mut foreign = document("did:webvh:QmOther:evil.example.com", ME, json!({}));
        foreign["issuer"] = json!("did:webvh:QmOther:evil.example.com");
        let foreign = sign(foreign, &op).await;
        assert_eq!(
            verify(&foreign, &doc, &seen),
            Err(OperationalError::IssuerNotSender)
        );

        let mut long = document(VTC, ME, json!({}));
        long["id"] = json!("x".repeat(MAX_DOCUMENT_ID_CHARS + 1));
        let long = sign(long, &op).await;
        assert_eq!(verify(&long, &doc, &seen), Err(OperationalError::IdTooLong));
    }

    /// The replay set is keyed by issuer: one community's id does not collide
    /// with another's, and a flood from one issuer cannot touch another's.
    #[test]
    fn ids_are_per_issuer_and_quotas_refuse_rather_than_evict() {
        let now = Utc::now();
        let later = now + TimeDelta::days(30);
        let mut seen = SeenDocuments::default();
        seen.record(VTC, "genuine", later, now).unwrap();
        assert!(seen.record("did:web:other", "genuine", later, now).is_ok());

        // Fill one issuer to its bound: the next is refused, nothing evicted.
        let flood = "did:web:flood.example";
        for i in 0..MAX_SEEN_PER_ISSUER {
            seen.record(flood, &format!("f{i}"), now + TimeDelta::minutes(1), now)
                .unwrap();
        }
        assert_eq!(
            seen.record(flood, "one-more", later, now),
            Err(OperationalError::QuotaExceeded)
        );
        assert!(
            seen.contains(VTC, "genuine", now),
            "another issuer is untouched"
        );
        assert!(seen.contains(flood, "f0", now), "nothing was evicted");
        assert_eq!(
            seen.record(VTC, "genuine", later, now),
            Err(OperationalError::Replayed)
        );

        // Once the flood's window passes, it ages out — and only then.
        let after = now + TimeDelta::minutes(2);
        assert!(seen.record(flood, "one-more", later, after).is_ok());
        assert!(seen.contains(VTC, "genuine", after));
    }

    #[test]
    fn remembered_ids_are_forgotten_after_their_window() {
        let mut seen = SeenDocuments::default();
        let now = Utc::now();
        seen.record(VTC, "a", now + TimeDelta::hours(1), now)
            .unwrap();
        assert_eq!(
            seen.record(VTC, "a", now + TimeDelta::hours(1), now),
            Err(OperationalError::Replayed)
        );
        let later = now + TimeDelta::hours(2);
        assert!(!seen.contains(VTC, "a", later));
        assert!(
            seen.record(VTC, "a", later + TimeDelta::hours(1), later)
                .is_ok()
        );
    }
}
