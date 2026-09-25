//! Is a credential revoked? Reading a `credentialStatus` against the issuer's
//! Bitstring Status List.
//!
//! The list is a credential too, and it is verified by the same rules as any
//! other the issuer signs ([`crate::proof_check`], `assertionMethod`): every
//! proof must verify, by a key of the issuer's own DID. That matters because a
//! community holding a post-quantum key signs its list with a proof **set**
//! (Ed25519 + ML-DSA-44); a reader that understands only a single proof object
//! can never establish the status of such a community's credentials.
//!
//! Beyond the proof, the list must name itself as the URL it was fetched from
//! (a list at one URL cannot stand in for another), be issued by the
//! credential's issuer, be inside its validity window, and carry the entry's
//! `statusPurpose`. The bitstring is GZIP + base64url (a multibase `u` prefix
//! is accepted), decoded with `affinidi-status-list` only as far as the
//! entry's bit, so a hostile list cannot cost more than its index allows.
//!
//! The caller supplies the fetch, and so owns transport, timeouts and SSRF
//! guards.
//!
//! [`StatusCheck::Unknown`] is "not established", never "not revoked": a
//! caller relying on a credential treats it as a refusal.

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_status_list::{BitstringStatusList, StatusPurpose};
use chrono::{DateTime, Utc};
use serde_json::Value;
pub use vta_sdk::vetting::status::StatusCheck;
use vta_sdk::vetting::status::{
    BITSTRING_STATUS_LIST_CREDENTIAL_TYPE, BITSTRING_STATUS_LIST_ENTRY_TYPE,
    MAX_ENCODED_LIST_CHARS, MAX_STATUS_ENTRIES, MAX_STATUS_LIST_BITS, MAX_STATUS_LIST_URL_CHARS,
};

use crate::proof_check::{self, Purpose};

/// Clock skew allowed on the list's validity window.
const CLOCK_SKEW: chrono::TimeDelta = chrono::TimeDelta::minutes(5);

/// base64url of the GZIP magic bytes: a multibase `u` followed by this is a
/// prefixed list, not a list whose first character happens to be `u`.
const GZIP_BASE64URL_PREFIX: &str = "H4sI";

/// Check `credential_status` (one entry or an array) of a credential issued by
/// `issuer`.
///
/// Entries whose `statusPurpose` is neither `revocation` nor `suspension` are
/// ignored; a credential with none of those is [`StatusCheck::Unknown`]. Each
/// list URL is fetched once.
pub async fn check_credential_status(
    credential_status: &Value,
    issuer: &str,
    fetch: impl AsyncFn(&str) -> Result<Value, String>,
    resolver: &DIDCacheClient,
    now: DateTime<Utc>,
) -> StatusCheck {
    let entries: Vec<&Value> = match credential_status {
        Value::Array(items) => items.iter().collect(),
        Value::Object(_) => vec![credential_status],
        _ => return unknown("credentialStatus is not an object or array"),
    };
    if entries.len() > MAX_STATUS_ENTRIES {
        return unknown("credentialStatus has too many entries");
    }
    let mut parsed = Vec::new();
    for entry in entries {
        match parse_entry(entry) {
            Ok(Some(e)) => parsed.push(e),
            Ok(None) => {}
            Err(reason) => return StatusCheck::Unknown(reason),
        }
    }
    if parsed.is_empty() {
        return unknown("no revocation or suspension status entry");
    }

    // The issuer's document is resolved once, when the first list arrives.
    let mut issuer_doc: Option<affinidi_tdk::did_common::Document> = None;
    let mut lists: Vec<(String, Result<Value, String>)> = Vec::new();
    let mut first_unknown = None;
    for entry in &parsed {
        if !lists.iter().any(|(url, _)| *url == entry.url) {
            let body = fetch(&entry.url).await;
            lists.push((entry.url.clone(), body));
        }
        let outcome = match lists.iter().find(|(url, _)| *url == entry.url) {
            Some((_, Ok(list))) => {
                if issuer_doc.is_none() {
                    match proof_check::resolve_document(issuer, resolver).await {
                        Ok(doc) => issuer_doc = Some(doc),
                        Err(e) => return StatusCheck::Unknown(e.to_string()),
                    }
                }
                match &issuer_doc {
                    Some(doc) => read_bit(list, entry, issuer, doc, now),
                    None => Err("the issuer's DID document was not resolved".to_string()),
                }
            }
            Some((_, Err(e))) => Err(format!("the status list could not be fetched: {e}")),
            None => Err("the status list was not fetched".to_string()),
        };
        match outcome {
            Ok(true) => return StatusCheck::Revoked,
            Ok(false) => {}
            Err(reason) => {
                first_unknown.get_or_insert(reason);
            }
        }
    }
    match first_unknown {
        Some(reason) => StatusCheck::Unknown(reason),
        None => StatusCheck::Active,
    }
}

fn unknown(reason: &str) -> StatusCheck {
    StatusCheck::Unknown(reason.to_string())
}

struct Entry {
    url: String,
    index: usize,
    purpose: StatusPurpose,
}

/// `Ok(None)` for an entry of a purpose this check does not read.
fn parse_entry(entry: &Value) -> Result<Option<Entry>, String> {
    let obj = entry
        .as_object()
        .ok_or_else(|| "a status entry is not an object".to_string())?;
    if !has_type(obj.get("type"), BITSTRING_STATUS_LIST_ENTRY_TYPE) {
        return Ok(None);
    }
    let purpose = match obj.get("statusPurpose").and_then(Value::as_str) {
        Some("revocation") => StatusPurpose::Revocation,
        Some("suspension") => StatusPurpose::Suspension,
        Some(_) => return Ok(None),
        None => return Err("a status entry has no statusPurpose".into()),
    };
    let url = obj
        .get("statusListCredential")
        .and_then(Value::as_str)
        .filter(|u| !u.is_empty() && u.chars().count() <= MAX_STATUS_LIST_URL_CHARS)
        .ok_or_else(|| "a status entry has no usable statusListCredential".to_string())?;
    let index = parse_index(obj.get("statusListIndex"))?;
    Ok(Some(Entry {
        url: url.to_string(),
        index,
        purpose,
    }))
}

/// A string of digits (W3C) or a JSON integer, bounded by
/// [`MAX_STATUS_LIST_BITS`].
fn parse_index(value: Option<&Value>) -> Result<usize, String> {
    let n = match value {
        Some(Value::String(s))
            if !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit()) =>
        {
            s.parse::<u64>().ok()
        }
        Some(Value::Number(n)) => n.as_u64(),
        _ => None,
    }
    .ok_or_else(|| "statusListIndex is not a non-negative integer".to_string())?;
    if n >= MAX_STATUS_LIST_BITS {
        return Err("statusListIndex is past the largest status list read".into());
    }
    usize::try_from(n).map_err(|_| "statusListIndex does not fit this platform".to_string())
}

fn has_type(value: Option<&Value>, wanted: &str) -> bool {
    match value {
        Some(Value::String(t)) => t == wanted,
        Some(Value::Array(types)) => types.iter().any(|t| t.as_str() == Some(wanted)),
        _ => false,
    }
}

/// `true` when the entry's bit is set in a list this issuer signed.
fn read_bit(
    list: &Value,
    entry: &Entry,
    issuer: &str,
    issuer_doc: &affinidi_tdk::did_common::Document,
    now: DateTime<Utc>,
) -> Result<bool, String> {
    let obj = list
        .as_object()
        .ok_or_else(|| "the status list is not a JSON object".to_string())?;
    if !has_type(obj.get("type"), BITSTRING_STATUS_LIST_CREDENTIAL_TYPE) {
        return Err("the fetched document is not a BitstringStatusListCredential".into());
    }
    if obj.get("id").and_then(Value::as_str) != Some(entry.url.as_str()) {
        return Err("the status list's id is not the URL it was fetched from".into());
    }
    let list_issuer = match obj.get("issuer") {
        Some(Value::String(s)) => Some(s.as_str()),
        Some(Value::Object(o)) => o.get("id").and_then(Value::as_str),
        _ => None,
    }
    .ok_or_else(|| "the status list has no issuer".to_string())?;
    if list_issuer != issuer {
        return Err("the status list's issuer is not the credential's issuer".into());
    }
    check_window(obj, now)?;
    proof_check::verify_proofs(list, issuer, issuer_doc, &[Purpose::AssertionMethod])
        .map_err(|e| format!("the status list's proof: {e}"))?;

    let subject = obj
        .get("credentialSubject")
        .and_then(Value::as_object)
        .ok_or_else(|| "the status list has no credentialSubject".to_string())?;
    if subject.get("statusPurpose").and_then(Value::as_str) != Some(purpose_str(entry.purpose)) {
        return Err("the status list's purpose is not the entry's".into());
    }
    let encoded = subject
        .get("encodedList")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= MAX_ENCODED_LIST_CHARS)
        .ok_or_else(|| "the status list has no usable encodedList".to_string())?;
    let encoded = match encoded.strip_prefix('u') {
        Some(rest) if rest.starts_with(GZIP_BASE64URL_PREFIX) => rest,
        _ => encoded,
    };
    let size = entry.index.saturating_add(1);
    let decoded = BitstringStatusList::decode(encoded, size, entry.purpose)
        .map_err(|e| format!("the status list does not decode as far as the entry: {e}"))?;
    decoded
        .get(entry.index)
        .map_err(|e| format!("statusListIndex is outside the status list: {e}"))
}

fn check_window(obj: &serde_json::Map<String, Value>, now: DateTime<Utc>) -> Result<(), String> {
    let read = |member: &str| -> Result<Option<DateTime<Utc>>, String> {
        match obj.get(member) {
            None => Ok(None),
            Some(Value::String(s)) => DateTime::parse_from_rfc3339(s)
                .map(|t| Some(t.with_timezone(&Utc)))
                .map_err(|_| format!("the status list's {member} is not a timestamp")),
            Some(_) => Err(format!("the status list's {member} is not a timestamp")),
        }
    };
    if read("validFrom")?.is_some_and(|from| from > now + CLOCK_SKEW) {
        return Err("the status list is not yet valid".into());
    }
    if read("validUntil")?.is_some_and(|until| until + CLOCK_SKEW < now) {
        return Err("the status list has expired".into());
    }
    Ok(())
}

fn purpose_str(purpose: StatusPurpose) -> &'static str {
    match purpose {
        StatusPurpose::Revocation => "revocation",
        StatusPurpose::Suspension => "suspension",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof_check::test_support::{document, ed_key, pq_key, sign};
    use serde_json::json;

    const ISSUER: &str = "did:webvh:QmScid:vtc.example.com";
    const URL: &str = "https://vtc.example.com/v1/status-lists/revocation";
    const SIZE: usize = 131_072;

    fn entry(index: &str) -> Value {
        json!({
            "id": format!("{URL}#{index}"),
            "type": BITSTRING_STATUS_LIST_ENTRY_TYPE,
            "statusPurpose": "revocation",
            "statusListIndex": index,
            "statusListCredential": URL,
        })
    }

    fn list(set: &[usize]) -> Value {
        let mut bits = BitstringStatusList::new(SIZE, StatusPurpose::Revocation);
        for &i in set {
            bits.set(i, true).unwrap();
        }
        json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "id": URL,
            "type": ["VerifiableCredential", BITSTRING_STATUS_LIST_CREDENTIAL_TYPE],
            "issuer": ISSUER,
            "validFrom": "2026-01-01T00:00:00Z",
            "credentialSubject": {
                "id": format!("{URL}#list"),
                "type": "BitstringStatusList",
                "statusPurpose": "revocation",
                "encodedList": bits.encode().unwrap(),
            },
        })
    }

    fn check(
        list_value: &Value,
        entry_value: &Value,
        doc: &affinidi_tdk::did_common::Document,
    ) -> Result<bool, String> {
        let e = parse_entry(entry_value).unwrap().unwrap();
        read_bit(list_value, &e, ISSUER, doc, Utc::now())
    }

    /// The case the SDK's reader could not handle: a list signed with a proof
    /// set is read, both ways.
    #[tokio::test]
    async fn a_list_signed_with_a_proof_set_is_read() {
        let ed = ed_key(ISSUER, "key-0", 1);
        let pq = pq_key(ISSUER, "key-pq", 2);
        let doc = document(ISSUER, &[("key-0", &ed), ("key-pq", &pq)], &[]);
        let signed = sign(list(&[7]), &[&ed, &pq]).await;
        assert!(signed["proof"].is_array());
        assert_eq!(check(&signed, &entry("7"), &doc), Ok(true));
        assert_eq!(check(&signed, &entry("8"), &doc), Ok(false));
    }

    #[tokio::test]
    async fn a_list_that_does_not_verify_is_not_read() {
        let key = ed_key(ISSUER, "key-0", 1);
        let doc = document(ISSUER, &[("key-0", &key)], &[]);
        // Unsigned.
        assert!(check(&list(&[]), &entry("7"), &doc).is_err());
        // Bit cleared after signing.
        let mut tampered = sign(list(&[7]), &[&key]).await;
        tampered["credentialSubject"]["encodedList"] =
            list(&[])["credentialSubject"]["encodedList"].clone();
        assert!(check(&tampered, &entry("7"), &doc).is_err());
        // Signed by another DID.
        let other = ed_key("did:webvh:QmOther:evil.example.com", "key-0", 9);
        let foreign = sign(list(&[]), &[&other]).await;
        assert!(check(&foreign, &entry("7"), &doc).is_err());
        // A list served for another URL.
        let mut elsewhere = list(&[]);
        elsewhere["id"] = json!("https://vtc.example.com/other");
        let elsewhere = sign(elsewhere, &[&key]).await;
        assert!(check(&elsewhere, &entry("7"), &doc).is_err());
    }

    #[tokio::test]
    async fn an_unreachable_list_is_unknown_never_active() {
        let resolver = DIDCacheClient::new(
            affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
        )
        .await
        .unwrap();
        let (did, _) = {
            let s = crate::proof_check::test_support::ed_key("did:key:x", "k", 1);
            let mb = s.get_public_keymultibase().unwrap();
            (format!("did:key:{mb}"), s)
        };
        let status = entry("7");
        let out = check_credential_status(
            &status,
            &did,
            async |_: &str| Err("connection refused".to_string()),
            &resolver,
            Utc::now(),
        )
        .await;
        assert!(matches!(out, StatusCheck::Unknown(_)), "{out:?}");
        assert!(matches!(
            check_credential_status(
                &json!("nope"),
                &did,
                async |_: &str| Ok(json!({})),
                &resolver,
                Utc::now()
            )
            .await,
            StatusCheck::Unknown(_)
        ));
    }
}
