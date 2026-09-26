//! End-to-end DIDComm exchange over a real in-process mediator.
//!
//! Uses the [`MockMediator`] harness to spin up the real
//! `affinidi-messaging-mediator` server, registers two DIDComm
//! profiles (Alice + Bob) through `DIDCommService`, and verifies
//! that messages Alice sends through the mediator are delivered to
//! Bob's handler. Two scenarios:
//!
//!   * `alice_sends_to_bob_via_mediator` — generic test-protocol
//!     payload, asserts the message lands at Bob's router.
//!   * `relationship_request_round_trip` — sends a real openvtc-core
//!     `RelationshipRequestBody` and asserts Bob can deserialise it,
//!     proving the harness drives the actual production protocol
//!     types and not just opaque JSON.
//!   * `vrc_request_and_reject_round_trip` — Alice sends a
//!     `VRC_REQUEST` to Bob, Bob's "issuer" side responds with
//!     `VRCRequestReject` (the protocol's request/reject pair). Both
//!     bodies use the openvtc-core types so a serde regression on
//!     either field name trips this test.
//!
//! All `#[ignore]`'d because the mediator boot + auth handshake +
//! WS connect adds ~1s. CI's coverage job runs them via
//! `cargo llvm-cov ... -- --include-ignored`.

mod common;

use std::time::Duration;

use affinidi_tdk::didcomm::Message;
use openvtc_core::protocol_urls::{RELATIONSHIP_REQUEST, VRC_REJECTED, VRC_REQUEST};
use openvtc_core::relationships::RelationshipRequestBody;
use openvtc_core::vrc::{VRCRequestReject, VrcRequest};
use tokio::sync::mpsc;

use common::{MockMediator, ProfileMessaging, init_test_tracing, start_profile_messaging};

const TEST_MESSAGE_TYPE: &str = "https://example.com/openvtc-test/1.0/echo";

/// Connect both profiles to the mediator and wait for them to settle.
/// Bob's listener comes up first so his pickup queue is ready when
/// Alice pushes; both routers register handlers for `routes`.
async fn connect_alice_and_bob(
    mediator: &MockMediator,
    routes: &[&'static str],
) -> (
    ProfileMessaging,
    ProfileMessaging,
    String,
    String,
    mpsc::UnboundedReceiver<Message>,
) {
    let alice = mediator.profile("alice").expect("alice profile");
    let bob = mediator.profile("bob").expect("bob profile");
    let alice_did = alice.did.clone();
    let bob_did = bob.did.clone();

    let (bob_inbound_tx, bob_inbound_rx) = mpsc::unbounded_channel::<Message>();
    let bob_service = start_profile_messaging(bob, routes, bob_inbound_tx)
        .await
        .expect("bob service");

    let (alice_inbound_tx, _alice_inbound_rx) = mpsc::unbounded_channel::<Message>();
    let alice_service = start_profile_messaging(alice, routes, alice_inbound_tx)
        .await
        .expect("alice service");

    bob_service
        .wait_connected(Duration::from_secs(15))
        .await
        .expect("bob connect");
    alice_service
        .wait_connected(Duration::from_secs(15))
        .await
        .expect("alice connect");

    (
        alice_service,
        bob_service,
        alice_did,
        bob_did,
        bob_inbound_rx,
    )
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "slow: spawns mediator + two DIDCommService listeners (~1s)"]
async fn alice_sends_to_bob_via_mediator() {
    init_test_tracing();
    let mediator = MockMediator::start().await.expect("mediator start");
    let (alice_service, bob_service, alice_did, bob_did, mut bob_rx) =
        connect_alice_and_bob(&mediator, &[TEST_MESSAGE_TYPE]).await;

    let payload = serde_json::json!({"hello": "from-alice"});
    let msg = Message::build(
        uuid::Uuid::new_v4().to_string(),
        TEST_MESSAGE_TYPE.to_string(),
        payload,
    )
    .from(alice_did)
    .to(bob_did.clone())
    .finalize();

    alice_service
        .send(&msg, &bob_did)
        .await
        .expect("alice send");

    let received = tokio::time::timeout(Duration::from_secs(15), bob_rx.recv())
        .await
        .expect("bob received within 15s")
        .expect("inbound channel still open");

    assert_eq!(received.typ, TEST_MESSAGE_TYPE);
    assert_eq!(
        received.body.get("hello").and_then(|v| v.as_str()),
        Some("from-alice")
    );

    let _ = (alice_service, bob_service);
    drop(mediator);
}

/// Drives a real openvtc-core `RelationshipRequestBody` through the
/// mediator and asserts that Bob can deserialise the payload back into
/// the same protocol type. Same connect / wait / send / receive shape
/// as the basic round-trip, but the message body is the production
/// `relationships::RelationshipRequestBody` instead of opaque JSON —
/// so a future serde change on either side trips this test.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "slow: spawns mediator + two DIDCommService listeners (~1s)"]
async fn relationship_request_round_trip() {
    init_test_tracing();
    let mediator = MockMediator::start().await.expect("mediator start");
    let (alice_service, bob_service, alice_did, bob_did, mut bob_rx) =
        connect_alice_and_bob(&mediator, &[RELATIONSHIP_REQUEST]).await;

    // Use the openvtc-core protocol body shape so a serde regression on
    // either field name (`reason`, `did`, `name`) is caught here too.
    let body = RelationshipRequestBody {
        reason: Some("integration test".to_string()),
        did: alice_did.clone(),
        name: Some("Alice".to_string()),
        // The transport round trip is what this covers; the binding proofs
        // have their own tests in `relationships`.
        did_proof: None,
        persona_proof: None,
    };
    let msg = Message::build(
        uuid::Uuid::new_v4().to_string(),
        RELATIONSHIP_REQUEST.to_string(),
        serde_json::to_value(&body).expect("serialise body"),
    )
    .from(alice_did)
    .to(bob_did.clone())
    .finalize();

    alice_service
        .send(&msg, &bob_did)
        .await
        .expect("alice send");

    let received = tokio::time::timeout(Duration::from_secs(15), bob_rx.recv())
        .await
        .expect("bob received within 15s")
        .expect("inbound channel still open");

    assert_eq!(received.typ, RELATIONSHIP_REQUEST);
    let parsed: RelationshipRequestBody =
        serde_json::from_value(received.body.clone()).expect("deserialise body");
    assert_eq!(parsed.reason.as_deref(), Some("integration test"));
    assert_eq!(parsed.name.as_deref(), Some("Alice"));
    assert!(parsed.did.starts_with("did:peer:"));

    let _ = (alice_service, bob_service);
    drop(mediator);
}

/// Two-leg VRC protocol round-trip:
///   Alice -> Bob: `VrcRequest { reason: "..." }`        typed as VRC_REQUEST
///   Bob   -> Alice: `VRCRequestReject { reason: "..." }` typed as VRC_REJECTED
///
/// The mediator routes both legs. Each side deserialises the inbound
/// message body back into the openvtc-core protocol type. Catches
/// serde regressions on the VRC request/reject pair.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "slow: spawns mediator + two DIDCommService listeners (~1s)"]
async fn vrc_request_and_reject_round_trip() {
    init_test_tracing();
    let mediator = MockMediator::start().await.expect("mediator start");

    let alice = mediator.profile("alice").expect("alice");
    let bob = mediator.profile("bob").expect("bob");
    let alice_did = alice.did.clone();
    let bob_did = bob.did.clone();

    let routes: &[&'static str] = &[VRC_REQUEST, VRC_REJECTED];

    let (alice_inbound_tx, mut alice_inbound_rx) = mpsc::unbounded_channel::<Message>();
    let alice_service = start_profile_messaging(alice, routes, alice_inbound_tx)
        .await
        .expect("alice service");

    let (bob_inbound_tx, mut bob_inbound_rx) = mpsc::unbounded_channel::<Message>();
    let bob_service = start_profile_messaging(bob, routes, bob_inbound_tx)
        .await
        .expect("bob service");

    bob_service
        .wait_connected(Duration::from_secs(15))
        .await
        .expect("bob connect");
    alice_service
        .wait_connected(Duration::from_secs(15))
        .await
        .expect("alice connect");

    // Leg 1: Alice -> Bob (VRC_REQUEST).
    let request_body = VrcRequest {
        reason: Some("integration-test request".to_string()),
    };
    let request_id = uuid::Uuid::new_v4().to_string();
    let request_msg = Message::build(
        request_id.clone(),
        VRC_REQUEST.to_string(),
        serde_json::to_value(&request_body).expect("serialise request"),
    )
    .from(alice_did.clone())
    .to(bob_did.clone())
    .finalize();

    alice_service
        .send(&request_msg, &bob_did)
        .await
        .expect("alice -> bob send");

    let received_request = tokio::time::timeout(Duration::from_secs(15), bob_inbound_rx.recv())
        .await
        .expect("bob received within 15s")
        .expect("inbound channel still open");
    assert_eq!(received_request.typ, VRC_REQUEST);
    let parsed_request: VrcRequest =
        serde_json::from_value(received_request.body.clone()).expect("deserialise request");
    assert_eq!(
        parsed_request.reason.as_deref(),
        Some("integration-test request")
    );

    // Leg 2: Bob -> Alice (VRC_REJECTED). thid links back to the request.
    let reject_body = VRCRequestReject {
        reason: Some("integration-test reject".to_string()),
    };
    let reject_msg = Message::build(
        uuid::Uuid::new_v4().to_string(),
        VRC_REJECTED.to_string(),
        serde_json::to_value(&reject_body).expect("serialise reject"),
    )
    .from(bob_did.clone())
    .to(alice_did.clone())
    .thid(request_id)
    .finalize();

    bob_service
        .send(&reject_msg, &alice_did)
        .await
        .expect("bob -> alice send");

    let received_reject = tokio::time::timeout(Duration::from_secs(15), alice_inbound_rx.recv())
        .await
        .expect("alice received within 15s")
        .expect("inbound channel still open");
    assert_eq!(received_reject.typ, VRC_REJECTED);
    let parsed_reject: VRCRequestReject =
        serde_json::from_value(received_reject.body.clone()).expect("deserialise reject");
    assert_eq!(
        parsed_reject.reason.as_deref(),
        Some("integration-test reject")
    );

    let _ = (alice_service, bob_service);
    drop(mediator);
}
