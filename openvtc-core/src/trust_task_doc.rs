//! Building a Trust Task document — once, for every verb that sends one.
//!
//! # Why this exists
//!
//! Three copies of this had accumulated: `join::build_trust_task_document`,
//! `personhood::build_document` and `vetting::wire::document`. They differed
//! only in whether they returned a `Value` or a `TrustTask<Value>`; the logic —
//! parse the type URI, set `issuer`, `recipient`, `issuedAt` — was identical in
//! all three.
//!
//! `join.rs`'s own comment named the hazard while the second copy was being
//! written: *"a second verb writing its own copy is how one of them ends up
//! subtly different."* By the time this module was added there were three, and
//! the difference they were guarding against is not theoretical — a document
//! missing `issuedAt` is refused by a peer enforcing framework §7.3 item 17, and
//! a document missing `recipient` is refused by one enforcing §7.2 item 5b.
//! Neither failure names the missing field on the sender's side.
//!
//! # What belongs here and what does not
//!
//! The *envelope*: the fields every Trust Task document carries regardless of
//! verb. Not the payload, not the proof, and not the carriage — a document is
//! addressed and dated here, signed by whoever owns the key, and wrapped by
//! whichever binding carries it.

use chrono::Utc;
use serde::Serialize;
use serde_json::Value;
use trust_tasks_rs::TrustTask;

use crate::errors::OpenVTCError;

/// Build an addressed, dated Trust Task document.
///
/// `document_id` is supplied rather than minted here because a caller often
/// needs it to correlate the reply — and on the DIDComm path the same id is used
/// as the message id, which is what makes the two transports' reply threading
/// agree (see `join::submit_join_request`).
///
/// The `issuedAt` is stamped at build time. That is deliberate: a document built
/// now and sent later is *stale*, and a peer enforcing a freshness window should
/// say so rather than accept it.
pub fn build<P: Serialize>(
    type_uri: &str,
    issuer_did: &str,
    recipient_did: &str,
    document_id: impl Into<String>,
    payload: P,
) -> Result<TrustTask<Value>, OpenVTCError> {
    let type_uri = type_uri
        .parse()
        .map_err(|e| OpenVTCError::Config(format!("trust task type URI parse: {e}")))?;
    let payload = serde_json::to_value(payload)
        .map_err(|e| OpenVTCError::Config(format!("trust task payload serialize: {e}")))?;
    let mut doc = TrustTask::new(document_id.into(), type_uri, payload);
    doc.issuer = Some(issuer_did.to_string());
    doc.recipient = Some(recipient_did.to_string());
    doc.issued_at = Some(Utc::now());
    Ok(doc)
}

/// [`build`], serialised — for the callers that hand a `Value` straight to a
/// DIDComm message body.
pub fn build_value<P: Serialize>(
    type_uri: &str,
    issuer_did: &str,
    recipient_did: &str,
    document_id: impl Into<String>,
    payload: P,
) -> Result<Value, OpenVTCError> {
    let doc = build(type_uri, issuer_did, recipient_did, document_id, payload)?;
    serde_json::to_value(&doc)
        .map_err(|e| OpenVTCError::Config(format!("trust task document serialize: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const TYPE_URI: &str = "https://trusttasks.org/spec/vtc/members/self-remove/0.1";

    /// Every field a peer's framework checks is present.
    ///
    /// Written as one assertion per field rather than a shape comparison,
    /// because each has a different consequence when absent and the message
    /// should say which: a missing `issuedAt` is refused under §7.3 item 17, a
    /// missing `recipient` under §7.2 item 5b, and neither refusal names the
    /// field on the sender's side.
    #[test]
    fn a_built_document_is_addressed_and_dated() {
        let doc = build(
            TYPE_URI,
            "did:key:zMember",
            "did:webvh:community",
            "urn:uuid:1",
            json!({}),
        )
        .expect("builds");

        assert_eq!(doc.id, "urn:uuid:1");
        assert_eq!(doc.type_uri.to_string(), TYPE_URI);
        assert_eq!(
            doc.issuer.as_deref(),
            Some("did:key:zMember"),
            "without `issuer` a peer cannot bind the document to its sender"
        );
        assert_eq!(
            doc.recipient.as_deref(),
            Some("did:webvh:community"),
            "without `recipient` the document is refused under §7.2 item 5b"
        );
        assert!(
            doc.issued_at.is_some(),
            "without `issuedAt` the document is refused under §7.3 item 17"
        );
    }

    /// The two entry points describe the same document.
    ///
    /// They exist because callers want different types, not different documents
    /// — which is exactly the difference the three copies this module replaced
    /// were free to develop.
    #[test]
    fn the_two_builders_agree() {
        let doc = build(
            TYPE_URI,
            "did:key:zM",
            "did:webvh:c",
            "urn:uuid:2",
            json!({"a": 1}),
        )
        .expect("builds");
        let value = build_value(
            TYPE_URI,
            "did:key:zM",
            "did:webvh:c",
            "urn:uuid:2",
            json!({"a": 1}),
        )
        .expect("builds");

        // `issuedAt` is stamped per call, so compare everything else.
        let mut from_doc = serde_json::to_value(&doc).expect("serialises");
        let mut from_value = value;
        for v in [&mut from_doc, &mut from_value] {
            v.as_object_mut().expect("an object").remove("issuedAt");
        }
        assert_eq!(from_doc, from_value);
    }

    /// A type URI that is not a type URI fails here, not on the wire.
    #[test]
    fn a_malformed_type_uri_is_refused_at_build_time() {
        let err = build(
            "not a uri",
            "did:key:zM",
            "did:webvh:c",
            "urn:uuid:3",
            json!({}),
        )
        .expect_err("a malformed type URI must not produce a document");
        assert!(
            err.to_string().contains("type URI"),
            "the error should name what was wrong: {err}"
        );
    }
}
