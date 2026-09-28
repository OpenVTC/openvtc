//! Integration coverage for the production DIDComm transport module
//! ([`openvtc_core::didcomm`]) over a real mediator.
//!
//! **This test could not exist before the module moved into `openvtc-core`.** It
//! lived at `openvtc/src/state_handler/didcomm.rs`, and `openvtc` is a
//! binary-only crate (`[[bin]]`, no `src/lib.rs`), so nothing could import it.
//! That is why the module that owns every socket in the TUI had no coverage
//! beyond two pure unit groups — a regex and an id function — while its actual
//! failure mode is `duplicate-channel` and duelling reconnect loops, which
//! produce neither a compile error nor a failing unit test.
//!
//! So this asserts the three things the delivery-layer swap (#189) is about to
//! rewrite, against the real mediator rather than a mock:
//!
//! 1. `build_router` routes an OpenVTC protocol message to the event channel —
//!    the catch-all regex working on a real wire, not just against `Regex::new`.
//! 2. `send_message_via` actually delivers through the mediator.
//! 3. A listener built by `relationship_listener_config_from_secrets` connects.
//!
//! Deliberately uses the `..._from_secrets` constructor: it is the one listener
//! builder that takes no `Config`, so the transport path is exercised without
//! standing up an encrypted on-disk config. The `Config`-taking builders
//! (`build_listener_configs`, `persona_listener_config_for`) differ only in where
//! the DID, mediator and secrets come from.
//!
//! `#[ignore]` like its siblings — booting the mediator is slow. CI's coverage
//! job runs `--include-ignored`.

mod common;

use std::time::Duration;

use affinidi_tdk::didcomm::Message;
use common::{MockMediator, init_test_tracing};
use openvtc_core::didcomm::{
    DIDCommEvent, Messaging, add_listener, relationship_listener_config_from_secrets,
    send_message_via,
};
use tokio::sync::mpsc;
use uuid::Uuid;

/// An OpenVTC protocol type the production catch-all pattern must route.
const OPENVTC_TYPE: &str = "https://linuxfoundation.org/openvtc/test/1.0/ping";

/// Stand up one profile's production `Messaging` runtime and install its listener.
async fn start_production_service(
    profile: common::TestProfile,
    remote_did: &str,
    event_tx: mpsc::UnboundedSender<DIDCommEvent>,
) -> (Messaging, String) {
    let listener = relationship_listener_config_from_secrets(
        &profile.did,
        remote_did,
        &profile.mediator_did,
        profile.secrets.clone(),
    );
    let listener_id = listener.id.clone();
    let service = Messaging::start(event_tx);
    add_listener(&service, &listener)
        .await
        .expect("production listener spec installs");
    (service, listener_id)
}

/// The end-to-end path the swap will replace: production listener → production
/// send → mediator → production router → event channel.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "slow: spawns a real mediator (~1s)"]
async fn an_openvtc_message_routes_through_the_production_transport() {
    init_test_tracing();
    let mediator = MockMediator::start().await.expect("mediator start");
    let alice = mediator.profile("alice").expect("alice");
    let bob = mediator.profile("bob").expect("bob");
    let alice_did = alice.did.clone();
    let bob_did = bob.did.clone();

    // Receiver first: a listener that is not yet polling would miss the frame.
    let (bob_tx, mut bob_rx) = mpsc::unbounded_channel::<DIDCommEvent>();
    let (bob_service, bob_listener) = start_production_service(bob, &alice_did, bob_tx).await;
    bob_service
        .wait_connected(&bob_listener, Duration::from_secs(20))
        .await
        .expect("bob listener connects");

    let (alice_tx, _alice_rx) = mpsc::unbounded_channel::<DIDCommEvent>();
    let (alice_service, alice_listener) = start_production_service(alice, &bob_did, alice_tx).await;
    alice_service
        .wait_connected(&alice_listener, Duration::from_secs(20))
        .await
        .expect("alice listener connects");

    let message = Message::build(
        Uuid::new_v4().to_string(),
        OPENVTC_TYPE.to_string(),
        serde_json::json!({ "hello": "transport" }),
    )
    .from(alice_did.clone())
    .to(bob_did.clone())
    .finalize();

    send_message_via(&alice_service, &message, &alice_listener, &bob_did)
        .await
        .expect("production send delivers");

    let event = tokio::time::timeout(Duration::from_secs(20), bob_rx.recv())
        .await
        .expect("bob receives within 20s")
        .expect("event channel still open");

    match event {
        DIDCommEvent::InboundMessage {
            message,
            from,
            transport,
            ..
        } => {
            assert_eq!(
                message.typ, OPENVTC_TYPE,
                "the catch-all pattern routed this type"
            );
            // The reported transport is the one that actually carried the
            // frame, not a guess. This leg is DIDComm; the activity log used to
            // hardcode that label and so was wrong for every TSP frame.
            assert_eq!(
                transport,
                openvtc_core::didcomm::MessagingTransport::DidComm,
                "a DIDComm round trip reports DIDComm"
            );
            assert_eq!(
                from.as_deref(),
                Some(alice_did.as_str()),
                "the sender survives the round trip"
            );
            assert_eq!(
                message.body.get("hello").and_then(|v| v.as_str()),
                Some("transport"),
                "the body survives pack/unpack"
            );
        }
        other => panic!("expected InboundMessage, got {other:?}"),
    }
}

/// A type the catch-all must *not* route reaches no handler, so nothing lands on
/// the event channel. The unit test asserts this against the regex; this asserts
/// it against a real delivered message, which is the claim that actually matters
/// — a routing gate that leaks would hand unvetted traffic to dispatch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "slow: spawns a real mediator (~1s)"]
async fn an_unrelated_message_type_reaches_no_handler() {
    init_test_tracing();
    let mediator = MockMediator::start().await.expect("mediator start");
    let alice = mediator.profile("alice").expect("alice");
    let bob = mediator.profile("bob").expect("bob");
    let alice_did = alice.did.clone();
    let bob_did = bob.did.clone();

    let (bob_tx, mut bob_rx) = mpsc::unbounded_channel::<DIDCommEvent>();
    let (bob_service, bob_listener) = start_production_service(bob, &alice_did, bob_tx).await;
    bob_service
        .wait_connected(&bob_listener, Duration::from_secs(20))
        .await
        .expect("bob listener connects");

    let (alice_tx, _alice_rx) = mpsc::unbounded_channel::<DIDCommEvent>();
    let (alice_service, alice_listener) = start_production_service(alice, &bob_did, alice_tx).await;
    alice_service
        .wait_connected(&alice_listener, Duration::from_secs(20))
        .await
        .expect("alice listener connects");

    let message = Message::build(
        Uuid::new_v4().to_string(),
        "https://example.com/not-openvtc/1.0/whatever".to_string(),
        serde_json::json!({}),
    )
    .from(alice_did.clone())
    .to(bob_did.clone())
    .finalize();

    send_message_via(&alice_service, &message, &alice_listener, &bob_did)
        .await
        .expect("send delivers");

    assert!(
        tokio::time::timeout(Duration::from_millis(2500), bob_rx.recv())
            .await
            .is_err(),
        "an unrelated type must not reach the event channel"
    );
}

/// A message that arrived while its recipient had **no listener at all** is
/// collected when one comes up.
///
/// This is the join that sits `Pending` forever, reduced to its essentials. A
/// mediator live-streams only to a recipient connected at the instant the
/// message lands; everything else is stored, and a stored inbox is redelivered
/// *only* to a socket that displaces an existing one for the same DID. Bob here
/// has never connected, so there is nothing to displace: without
/// `pickup_stored`, this message is unreachable until some future process
/// happens to replace a socket, which is why relaunching the app "fixed" it.
///
/// Deliberately sends **before** bob has any transport — not merely before he is
/// connected — so no amount of live-stream timing luck can make it pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "slow: spawns a real mediator (~1s)"]
async fn a_message_stored_before_the_listener_existed_is_collected_on_connect() {
    init_test_tracing();
    let mediator = MockMediator::start().await.expect("mediator start");
    let alice = mediator.profile("alice").expect("alice");
    let bob = mediator.profile("bob").expect("bob");
    let alice_did = alice.did.clone();
    let bob_did = bob.did.clone();

    // Sender only. Bob has no service, no transport, no socket.
    let (alice_tx, _alice_rx) = mpsc::unbounded_channel::<DIDCommEvent>();
    let (alice_service, alice_listener) = start_production_service(alice, &bob_did, alice_tx).await;
    alice_service
        .wait_connected(&alice_listener, Duration::from_secs(20))
        .await
        .expect("alice listener connects");

    let message = Message::build(
        Uuid::new_v4().to_string(),
        OPENVTC_TYPE.to_string(),
        serde_json::json!({ "hello": "stored" }),
    )
    .from(alice_did.clone())
    .to(bob_did.clone())
    .finalize();

    send_message_via(&alice_service, &message, &alice_listener, &bob_did)
        .await
        .expect("production send delivers to the mediator");

    // Let the mediator finish storing it with no recipient attached. Without
    // this the send and the connect are milliseconds apart, and the frame is
    // simply live-delivered to a socket that came up while it was still in
    // flight — which passes whether or not anything collects stored mail.
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Now bring bob up. The connect transition is what triggers the pickup.
    let (bob_tx, mut bob_rx) = mpsc::unbounded_channel::<DIDCommEvent>();
    let (bob_service, bob_listener) = start_production_service(bob, &alice_did, bob_tx).await;
    bob_service
        .wait_connected(&bob_listener, Duration::from_secs(20))
        .await
        .expect("bob listener connects");

    let event = tokio::time::timeout(Duration::from_secs(20), bob_rx.recv())
        .await
        .expect("bob collects the stored message within 20s")
        .expect("event channel still open");

    match event {
        DIDCommEvent::InboundMessage {
            message,
            from,
            transport,
            ..
        } => {
            assert_eq!(message.typ, OPENVTC_TYPE);
            assert_eq!(
                transport,
                openvtc_core::didcomm::MessagingTransport::DidComm,
                "a collected DIDComm message still reports DIDComm"
            );
            // The anti-spoof binding survives the pickup path: `from` is the DID
            // that authcrypted the envelope, not the plaintext header. A
            // collected message carries membership decisions and credentials, so
            // this must not be the one path where that check is skipped.
            assert_eq!(
                from.as_deref(),
                Some(alice_did.as_str()),
                "the cryptographically-bound sender survives collection"
            );
            assert_eq!(
                message.body.get("hello").and_then(|v| v.as_str()),
                Some("stored"),
            );
        }
        other => panic!("expected InboundMessage, got {other:?}"),
    }

    // A collected message is acknowledged, so it is gone from the mailbox. Were
    // it not, every connect would re-deliver it — and the *next* connect is a
    // replacement, which is exactly when the mediator redelivers the whole
    // undelivered inbox. Replacing bob's transport and hearing nothing is the
    // assertion that the ack landed.
    //
    // The ack is issued after the handoff this test just observed, so tearing
    // the transport down the instant the event arrives would cancel the ack
    // in flight and assert a race rather than the behaviour. Give the round trip
    // room against an in-process mediator.
    tokio::time::sleep(Duration::from_secs(3)).await;
    bob_service.remove_listener(&bob_listener).await;
    let (bob_tx2, mut bob_rx2) = mpsc::unbounded_channel::<DIDCommEvent>();
    let (bob_service2, bob_listener2) =
        start_production_service(mediator.profile("bob").expect("bob"), &alice_did, bob_tx2).await;
    bob_service2
        .wait_connected(&bob_listener2, Duration::from_secs(20))
        .await
        .expect("bob reconnects");

    // Anything the *mediator* says about the swap is expected and irrelevant —
    // replacing a socket earns a `w.websocket.duplicate-channel` problem-report
    // addressed to the terminated one. The claim is only that the collected
    // message itself does not come back.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while let Ok(Some(event)) = tokio::time::timeout_at(deadline, bob_rx2.recv()).await {
        if let DIDCommEvent::InboundMessage { message, .. } = event {
            assert_ne!(
                message.typ, OPENVTC_TYPE,
                "an already-collected message must not be delivered a second time"
            );
        }
    }
}

/// The supervisor must leave a **healthy** transport alone.
///
/// A rebuild tears the websocket down and builds a new one, so a supervisor that
/// fired on a connected transport — or on every tick — would churn the socket and
/// race the mediator's one-per-DID rule, manufacturing the `duplicate-channel`
/// fault it exists to recover from (#132).
///
/// The unit tests in `supervisor_policy_tests` pin the timing thresholds. This
/// asserts the loop actually honours them against a real mediator: across several
/// supervisor ticks, a connected listener neither reports a disconnect transition
/// nor leaves `Connected`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "slow: spawns a real mediator and waits out several supervisor ticks"]
async fn the_supervisor_does_not_churn_a_healthy_transport() {
    init_test_tracing();
    let mediator = MockMediator::start().await.expect("mediator start");
    let alice = mediator.profile("alice").expect("alice");
    let bob_did = mediator.profile("bob").expect("bob").did;

    let (tx, _rx) = mpsc::unbounded_channel::<DIDCommEvent>();
    let (service, listener_id) = start_production_service(alice, &bob_did, tx).await;
    service
        .wait_connected(&listener_id, Duration::from_secs(20))
        .await
        .expect("listener connects");

    // Watch for transitions from here: a rebuild would surface as a disconnect.
    let mut status = service.subscribe();

    // Comfortably more than one supervisor tick (10s), so a loop that rebuilds
    // unconditionally is caught.
    tokio::time::sleep(Duration::from_secs(25)).await;

    while let Ok(event) = status.try_recv() {
        if let openvtc_core::didcomm::ListenerStatus::Disconnected { listener_id, .. } = event {
            panic!("a healthy transport was disconnected — the supervisor churned {listener_id}");
        }
    }
    assert_eq!(
        service.listener_state(&listener_id),
        Some(openvtc_core::didcomm::ConnState::Connected),
        "the listener is still connected after several supervisor ticks"
    );
}

/// Removing a listener must actually close its socket — not just forget it.
///
/// The regression: `remove_listener` dropped the `IdentityWire` and nothing else.
/// The SDK has no `Drop` for `ATM`, and the identity's outbox drain still held the
/// transport, so the websocket stayed up and kept reconnecting on its own timer.
/// Re-adding a listener for the same DID — a community going inactive and then
/// being re-joined, a mediator change, the supervisor's rebuild — then opened a
/// second socket, and the mediator's one-socket-per-DID rule made the two evict
/// each other indefinitely. It presented as a listener flapping every 30-60 s with
/// "no transport error reported".
///
/// This is deliberately behavioural: the wire is gone from the map either way, so
/// the only way to tell a closed socket from an orphaned one is to ask the
/// mediator, by re-adding the DID and seeing whether the new listener is left
/// alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "slow: spawns a real mediator and watches the re-added listener for 30s"]
async fn a_re_added_listener_does_not_duel_with_the_removed_one() {
    init_test_tracing();
    let mediator = MockMediator::start().await.expect("mediator start");
    let alice = mediator.profile("alice").expect("alice");
    let bob_did = mediator.profile("bob").expect("bob").did;

    // Built here rather than via `start_production_service`, because the same spec
    // has to be installed twice.
    let listener = relationship_listener_config_from_secrets(
        &alice.did,
        &bob_did,
        &alice.mediator_did,
        alice.secrets.clone(),
    );
    let listener_id = listener.id.clone();

    let (tx, _rx) = mpsc::unbounded_channel::<DIDCommEvent>();
    let service = Messaging::start(tx);
    add_listener(&service, &listener)
        .await
        .expect("the listener installs");
    service
        .wait_connected(&listener_id, Duration::from_secs(20))
        .await
        .expect("the listener connects");

    service.remove_listener(&listener_id).await;
    add_listener(&service, &listener)
        .await
        .expect("the listener re-installs");
    service
        .wait_connected(&listener_id, Duration::from_secs(20))
        .await
        .expect("the re-added listener connects");

    // Watch from here: an orphan is not idle, it reconnects on its own timer, so
    // the eviction shows up as a disconnect on the listener that is still wanted.
    let mut status = service.subscribe();
    tokio::time::sleep(Duration::from_secs(30)).await;

    while let Ok(event) = status.try_recv() {
        if let openvtc_core::didcomm::ListenerStatus::Disconnected { listener_id, .. } = event {
            panic!(
                "the re-added listener was evicted — the removed listener's socket is still \
                 open and contending for the DID ({listener_id})"
            );
        }
    }
    assert_eq!(
        service.listener_state(&listener_id),
        Some(openvtc_core::didcomm::ConnState::Connected),
        "the re-added listener is still connected"
    );
}
