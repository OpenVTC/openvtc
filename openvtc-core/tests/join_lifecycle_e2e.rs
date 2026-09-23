//! End-to-end join + lifecycle exchange over a real in-process mediator.
//!
//! Join-request submission and its lifecycle resolution are **pure
//! DIDComm** — the applicant talks to the VTC through a mediator and
//! never touches the VTA — so the existing [`MockMediator`] harness is
//! enough to drive the whole flow over the wire. (The VTA-side half of
//! State-A bootstrap / webvh mint needs a richer `MockVta`; that's
//! tracked in verifiable-trust-infrastructure#406 and deferred.)
//!
//! Two DIDComm profiles stand in for the two ends:
//!
//!   * **alice** — the joining persona (the applicant).
//!   * **bob** — the community VTC.
//!
//! Scenarios:
//!
//!   * `join_submit_and_approval_activates` — alice submits a real
//!     `JoinRequestSubmitBody` to bob; bob deserialises it, then replies
//!     with an `approved` `JoinRequestStatusResponseBody`. Feeding the
//!     wire-delivered response into the production
//!     [`handle_join_status_response`] reducer flips the persisted
//!     community `Pending → Active` and stamps `member_since` (R-B-8).
//!   * `join_submit_and_rejection_inactivates` — same first leg, but a
//!     `rejected` response drives `Pending → Rejected`, marks the
//!     session for deregistration, and raises the actions-required badge
//!     (R-B-8 / R-S-2 / R-S-3).
//!   * `member_self_remove_round_trip` — alice sends a real
//!     `SelfRemoveBody` (`MEMBER_SELF_REMOVE`) to bob, who deserialises
//!     it; the local membership then transitions to `Left` (R-L-1).
//!
//! All `#[ignore]`'d because the mediator boot + auth handshake + WS
//! connect adds ~1s. CI's coverage job runs them via
//! `cargo llvm-cov ... -- --include-ignored`.

mod common;

use std::time::Duration;

use affinidi_tdk::didcomm::Message;
use chrono::Utc;
use openvtc_core::config::account::{Account, CommunityRecord, CommunityStatus, PersonaId};
use openvtc_core::messaging::handle_join_status_response;
use tokio::sync::mpsc;
use uuid::Uuid;
use vta_sdk::protocols::join_requests::{
    JOIN_REQUEST_STATUS_RESPONSE_TYPE, JOIN_REQUEST_SUBMIT_TYPE, JoinRequestStatusResponseBody,
    JoinRequestSubmitBody, MEMBER_SELF_REMOVE_TYPE, SelfRemoveBody,
};

use common::{MockMediator, ProfileMessaging, init_test_tracing, start_profile_messaging};

/// Connect the persona (alice) and VTC (bob) profiles to the mediator,
/// each routing `routes` into its own inbound channel, and wait for both
/// to settle. Returns both services (kept alive by the caller) plus the
/// two DIDs and inbound receivers.
async fn connect_persona_and_vtc(
    mediator: &MockMediator,
    routes: &[&'static str],
) -> (
    ProfileMessaging,
    ProfileMessaging,
    String,
    String,
    mpsc::UnboundedReceiver<Message>,
    mpsc::UnboundedReceiver<Message>,
) {
    let persona = mediator.profile("alice").expect("persona profile");
    let vtc = mediator.profile("bob").expect("vtc profile");
    let persona_did = persona.did.clone();
    let vtc_did = vtc.did.clone();

    // VTC listener comes up first so its pickup queue is ready when the
    // persona pushes the join request.
    let (vtc_tx, vtc_rx) = mpsc::unbounded_channel::<Message>();
    let vtc_service = start_profile_messaging(vtc, routes, vtc_tx)
        .await
        .expect("vtc messaging");

    let (persona_tx, persona_rx) = mpsc::unbounded_channel::<Message>();
    let persona_service = start_profile_messaging(persona, routes, persona_tx)
        .await
        .expect("persona messaging");

    vtc_service
        .wait_connected(Duration::from_secs(15))
        .await
        .expect("vtc connect");
    persona_service
        .wait_connected(Duration::from_secs(15))
        .await
        .expect("persona connect");

    (
        persona_service,
        vtc_service,
        persona_did,
        vtc_did,
        persona_rx,
        vtc_rx,
    )
}

/// A persona-side account with a single `Pending` community keyed by
/// `vtc_did`, awaiting the VTC's decision on `request_id`.
fn pending_account(vtc_did: &str, request_id: Uuid) -> Account {
    let mut account = Account::default();
    account.add_membership(CommunityRecord::new_pending(
        vtc_did.to_string(),
        Some("Integration Test Community".to_string()),
        "openvtc/integration-test".to_string(),
        PersonaId::new(),
        request_id,
        Utc::now(),
    ));
    account
}

/// Send the persona's join request to the VTC and assert the VTC
/// deserialises the production `JoinRequestSubmitBody` off the wire.
async fn submit_and_assert(
    persona_service: &ProfileMessaging,
    persona_did: &str,
    vtc_did: &str,
    vtc_rx: &mut mpsc::UnboundedReceiver<Message>,
) {
    let vp = serde_json::json!({
        "type": "VerifiablePresentation",
        "holder": persona_did,
    });
    let body = JoinRequestSubmitBody {
        vp: vp.clone(),
        registry_consent: false,
        extensions: serde_json::Value::Null,
        attributes: Vec::new(),
    };
    let submit = Message::build(
        Uuid::new_v4().to_string(),
        JOIN_REQUEST_SUBMIT_TYPE.to_string(),
        serde_json::to_value(&body).expect("serialise submit body"),
    )
    .from(persona_did.to_string())
    .to(vtc_did.to_string())
    .finalize();

    persona_service
        .send(&submit, vtc_did)
        .await
        .expect("persona -> vtc submit");

    let received = tokio::time::timeout(Duration::from_secs(15), vtc_rx.recv())
        .await
        .expect("vtc received within 15s")
        .expect("inbound channel still open");
    assert_eq!(received.typ, JOIN_REQUEST_SUBMIT_TYPE);
    let parsed: JoinRequestSubmitBody =
        serde_json::from_value(received.body.clone()).expect("deserialise submit body");
    assert_eq!(
        parsed.vp.get("holder").and_then(|v| v.as_str()),
        Some(persona_did),
        "the VTC sees the applicant persona as the VP holder"
    );
    assert!(!parsed.registry_consent);
}

/// The VTC sends a `join-requests/status-response` carrying `status`
/// (correlated to `request_id`) back to the persona, who receives it off
/// the wire. Returns the delivered message for the reducer to consume.
async fn respond_status(
    vtc_service: &ProfileMessaging,
    vtc_did: &str,
    persona_did: &str,
    request_id: Uuid,
    status: &str,
    persona_rx: &mut mpsc::UnboundedReceiver<Message>,
) -> Message {
    let body = JoinRequestStatusResponseBody {
        request_id,
        status: status.to_string(),
        needs: Vec::new(),
        presentation_definition: None,
        // Refusal detail (vta-sdk 0.31): carried only on a `rejected`
        // status, which this helper does not exercise.
        code: None,
        reason: None,
        decided_at: None,
    };
    let response = Message::build(
        Uuid::new_v4().to_string(),
        JOIN_REQUEST_STATUS_RESPONSE_TYPE.to_string(),
        serde_json::to_value(&body).expect("serialise status response"),
    )
    .from(vtc_did.to_string())
    .to(persona_did.to_string())
    .finalize();

    vtc_service
        .send(&response, persona_did)
        .await
        .expect("vtc -> persona status response");

    tokio::time::timeout(Duration::from_secs(15), persona_rx.recv())
        .await
        .expect("persona received within 15s")
        .expect("inbound channel still open")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "slow: spawns mediator + two DIDCommService listeners (~1s)"]
async fn join_submit_and_approval_activates() {
    init_test_tracing();
    let mediator = MockMediator::start().await.expect("mediator start");
    let routes: &[&'static str] = &[JOIN_REQUEST_SUBMIT_TYPE, JOIN_REQUEST_STATUS_RESPONSE_TYPE];
    let (persona_service, vtc_service, persona_did, vtc_did, mut persona_rx, mut vtc_rx) =
        connect_persona_and_vtc(&mediator, routes).await;

    let request_id = Uuid::new_v4();
    let mut account = pending_account(&vtc_did, request_id);

    // Leg 1: persona submits the join request; the VTC receives it.
    submit_and_assert(&persona_service, &persona_did, &vtc_did, &mut vtc_rx).await;

    // Leg 2: the VTC approves; the wire-delivered response drives the
    // production lifecycle reducer.
    let delivered = respond_status(
        &vtc_service,
        &vtc_did,
        &persona_did,
        request_id,
        "approved",
        &mut persona_rx,
    )
    .await;

    let outcome = handle_join_status_response(&mut account, &delivered, &vtc_did);
    assert!(outcome.changed, "approval transitions the record");
    assert!(
        outcome.inactivated.is_none(),
        "approval keeps the live session"
    );

    let record = account.memberships().next().expect("community");
    assert!(record.status.is_active(), "Pending -> Active on approval");
    assert!(
        record.member_since.is_some(),
        "member_since stamped on activation"
    );

    let _ = (persona_service, vtc_service);
    drop(mediator);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "slow: spawns mediator + two DIDCommService listeners (~1s)"]
async fn join_submit_and_rejection_inactivates() {
    init_test_tracing();
    let mediator = MockMediator::start().await.expect("mediator start");
    let routes: &[&'static str] = &[JOIN_REQUEST_SUBMIT_TYPE, JOIN_REQUEST_STATUS_RESPONSE_TYPE];
    let (persona_service, vtc_service, persona_did, vtc_did, mut persona_rx, mut vtc_rx) =
        connect_persona_and_vtc(&mediator, routes).await;

    let request_id = Uuid::new_v4();
    let mut account = pending_account(&vtc_did, request_id);

    submit_and_assert(&persona_service, &persona_did, &vtc_did, &mut vtc_rx).await;

    let delivered = respond_status(
        &vtc_service,
        &vtc_did,
        &persona_did,
        request_id,
        "rejected",
        &mut persona_rx,
    )
    .await;

    let outcome = handle_join_status_response(&mut account, &delivered, &vtc_did);
    assert!(outcome.changed, "rejection transitions the record");
    assert!(
        outcome.inactivated.is_some(),
        "rejection must deregister the live session (R-S-3)"
    );

    let record = account.memberships().next().expect("community");
    assert!(matches!(record.status, CommunityStatus::Rejected));
    assert!(
        record.needs_attention(),
        "an unacknowledged rejection raises the actions-required badge (R-S-2)"
    );

    let _ = (persona_service, vtc_service);
    drop(mediator);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "slow: spawns mediator + two DIDCommService listeners (~1s)"]
async fn member_self_remove_round_trip() {
    init_test_tracing();
    let mediator = MockMediator::start().await.expect("mediator start");
    let routes: &[&'static str] = &[MEMBER_SELF_REMOVE_TYPE];
    let (persona_service, vtc_service, persona_did, vtc_did, _persona_rx, mut vtc_rx) =
        connect_persona_and_vtc(&mediator, routes).await;

    // An already-Active membership the persona now leaves.
    let mut account = pending_account(&vtc_did, Uuid::new_v4());
    account
        .memberships_mut()
        .next()
        .expect("community")
        .activate(Utc::now());

    // Persona -> VTC: a real self-remove body, deserialised by the VTC.
    let body = SelfRemoveBody {
        disposition: Some("tombstone".to_string()),
    };
    let leave = Message::build(
        Uuid::new_v4().to_string(),
        MEMBER_SELF_REMOVE_TYPE.to_string(),
        serde_json::to_value(&body).expect("serialise self-remove body"),
    )
    .from(persona_did.clone())
    .to(vtc_did.clone())
    .finalize();

    persona_service
        .send(&leave, &vtc_did)
        .await
        .expect("persona -> vtc self-remove");

    let received = tokio::time::timeout(Duration::from_secs(15), vtc_rx.recv())
        .await
        .expect("vtc received within 15s")
        .expect("inbound channel still open");
    assert_eq!(received.typ, MEMBER_SELF_REMOVE_TYPE);
    let parsed: SelfRemoveBody =
        serde_json::from_value(received.body.clone()).expect("deserialise self-remove body");
    assert_eq!(parsed.disposition.as_deref(), Some("tombstone"));

    // On send success the local membership becomes read-only `Left` (R-L-1).
    let record = account.memberships_mut().next().expect("community");
    record.leave();
    assert!(matches!(record.status, CommunityStatus::Left));
    assert!(
        !record.needs_attention(),
        "a voluntary leave never raises the badge"
    );

    let _ = (persona_service, vtc_service);
    drop(mediator);
}
