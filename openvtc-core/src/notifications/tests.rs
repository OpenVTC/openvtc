#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use serde_json::json;

const COMMUNITY: &str = "did:key:z6MkCommunityHoldingTheElection";
const PARTY: &str = "did:key:z6MkPartyThatIsAMember";

fn notification(audience: &str, status: &str) -> Value {
    json!({
        "notificationId": "urn:uuid:7f7d1b9e-1c1e-4c1a-9d1e-0b0b0b0b0b0b",
        "revision": 2,
        "kind": "election",
        "subject": {
            "heldBy": COMMUNITY,
            "id": "agm-2027",
            "openWith": "https://trusttasks.org/spec/vtc/elections/show/0.6"
        },
        "audience": audience,
        "status": status,
        "relayable": true,
        "validFrom": "2027-01-01T00:00:00.000Z",
        "validUntil": "2027-01-08T00:00:00.000Z"
    })
}

fn held(record: &str, n: Value) -> Value {
    json!({
        "recordId": record,
        "contextId": "personal",
        "addressee": "did:key:z6MkMe",
        "originator": COMMUNITY,
        "relayedBy": [PARTY],
        "notification": n,
        "state": "active",
        "receivedAt": "2026-12-01T00:00:00Z"
    })
}

#[test]
fn only_notify_and_relay_requests_are_notifications() {
    assert!(is_notification_type(
        "https://trusttasks.org/spec/notifications/notify/0.1"
    ));
    assert!(is_notification_type(
        "https://trusttasks.org/spec/notifications/relay/0.1"
    ));
    assert!(!is_notification_type(
        "https://trusttasks.org/spec/notifications/notify/0.1#response"
    ));
    assert!(!is_notification_type(
        "https://trusttasks.org/spec/vta/notifications/deposit/0.1"
    ));
}

/// VTI-NTF-054: the deposit carries the document as received — its timestamps in the form
/// they were written, its proof untouched, nothing added.
#[test]
fn vti_ntf_054_the_deposit_carries_the_document_exactly_as_received() {
    let received = json!({
        "id": "urn:uuid:00000000-0000-4000-8000-000000000001",
        "type": NOTIFY_TYPE,
        "issuer": COMMUNITY,
        "recipient": "did:key:z6MkMe",
        "issuedAt": "2026-12-01T00:00:00.000000Z",
        "payload": { "notification": notification(PARTY, "available") },
        "proof": { "type": "DataIntegrityProof", "proofValue": "z5opaque" }
    });
    let p = deposit_payload("personal", &received);
    assert_eq!(p["contextId"], "personal");
    assert_eq!(p["document"], received);
    assert_eq!(
        serde_json::to_string(&p["document"]).unwrap(),
        serde_json::to_string(&received).unwrap()
    );
    assert_eq!(addressee_of(&received), Some("did:key:z6MkMe"));
    assert_eq!(
        addressee_of(&json!({ "type": "x", "recipient": "y" })),
        None
    );
}

/// The receipt answers the document it received, from the addressee to the sender, and says
/// only the notification and its revision (VTI-NTF-023).
#[test]
fn vti_ntf_023_the_receipt_threads_on_the_document_and_says_nothing_else() {
    let received = Received {
        document: json!({ "id": "urn:uuid:00000000-0000-4000-8000-000000000009", "type": RELAY_TYPE }),
        sender: PARTY.into(),
        addressee: "did:key:z6MkMe".into(),
        over_tsp: false,
    };
    let doc =
        receipt_document(&received, json!({ "notificationId": "n-1", "revision": 3 })).unwrap();
    assert_eq!(doc.type_uri.to_string(), format!("{RELAY_TYPE}#response"));
    assert_eq!(
        doc.thread_id.as_deref(),
        Some("urn:uuid:00000000-0000-4000-8000-000000000009")
    );
    assert_eq!(doc.issuer.as_deref(), Some("did:key:z6MkMe"));
    assert_eq!(doc.recipient.as_deref(), Some(PARTY));
    assert_eq!(
        doc.payload,
        json!({ "notificationId": "n-1", "revision": 3 })
    );
    let no_id = Received {
        document: json!({ "type": RELAY_TYPE }),
        ..received
    };
    assert!(receipt_document(&no_id, json!({})).is_err());
}

/// VTI-NTF-063: a held election notification is shown as notified — who holds it, its id,
/// audience and period. Withdrawn ones, and other kinds, are not listed.
#[test]
fn vti_ntf_063_held_election_notifications_are_read_as_notified() {
    let mut other_kind = notification(PARTY, "available");
    other_kind["kind"] = json!("room");
    let page = json!({
        "items": [
            held("hn-00000000000000001", notification(PARTY, "available")),
            held("hn-00000000000000002", notification(PARTY, "withdrawn")),
            held("hn-00000000000000003", other_kind),
        ],
        "nextCursor": "page-2"
    });
    let (items, next) = notified_elections(&page).unwrap();
    assert_eq!(next.as_deref(), Some("page-2"));
    assert_eq!(items.len(), 1);
    let e = &items[0];
    assert_eq!(e.record_id, "hn-00000000000000001");
    assert_eq!(e.held_by, COMMUNITY);
    assert_eq!(e.election_id, "agm-2027");
    assert_eq!(e.audience, PARTY);
    assert_eq!(e.relayed_by, vec![PARTY.to_string()]);
    assert!(
        e.valid_until
            .as_deref()
            .is_some_and(|t| t.starts_with("2027-01-08"))
    );
    assert!(e.opens_with_a_served_version());
    // Put to a party's members: opening it takes presenting that membership.
    assert!(e.audience_is_another_party());
    // Shown in the view of the community holding it, and of the party it is put to.
    assert!(e.concerns(COMMUNITY));
    assert!(e.concerns(PARTY));
    assert!(!e.concerns("did:key:z6MkSomeoneElse"));
}

#[test]
fn a_page_the_schema_refuses_is_an_error_not_an_empty_list() {
    assert!(notified_elections(&json!({ "items": [{ "recordId": "x" }] })).is_err());
}

/// VTI-NTF-054 / VTI-NTF-055: the sender's receipt is the VTA's answer to the deposit, taken
/// as the deposit's response schema reads it — whatever the VTA did with the document, and with
/// no verification of this client's own to turn it on.
#[test]
fn the_receipt_is_the_vtas_answer_to_the_deposit() {
    let answer =
        json!({ "notificationId": "urn:uuid:7f7d1b9e-1c1e-4c1a-9d1e-0b0b0b0b0b0b", "revision": 2 });
    assert_eq!(receipt_from_deposit(answer.clone()).unwrap(), answer);
    // Anything more than the receipt, or less, is not one: no receipt is sent.
    assert!(
        receipt_from_deposit(json!({ "notificationId": "n-1", "revision": 1, "held": true }))
            .is_err()
    );
    assert!(receipt_from_deposit(json!({ "notificationId": "n-1" })).is_err());
    assert!(receipt_from_deposit(json!({})).is_err());
}
