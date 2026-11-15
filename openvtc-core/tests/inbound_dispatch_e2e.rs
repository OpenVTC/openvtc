//! Inbound dispatch, end to end: a peer sends over a real in-process mediator,
//! this client's transport unpacks and authenticates the message, and it goes
//! through the inbound gate and `process_inbound_message` exactly as the
//! runtime loop puts it — including a deferred proof check run off the loop and
//! handed back.
//!
//! Alice plays the other party (a peer, or a community); Bob is this client's
//! persona, with a `Config` built for each scenario. One test per family:
//!
//! * a trust-pong closing our ping, and a trust-ping recorded as a task;
//! * a relationship request, with its DID-binding proof checked against
//!   Alice's resolved `did:peer`, queued in the inbox;
//! * a VRC issued in an established relationship, its proof checked, queued;
//! * a community's signed refusal of our pending join, which rejects it;
//! * a type no handler claims, refused by the gate and ignored by dispatch.
//!
//! `#[ignore]`d like the rest of the mediator suite (the boot costs ~1s); CI's
//! coverage job runs them with `--include-ignored`, and locally:
//!
//!     cargo test -p openvtc-core --test inbound_dispatch_e2e -- --ignored

mod common;

use std::sync::Arc;
use std::time::Duration;

use affinidi_tdk::TDK;
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::profiles::{ATMProfile, ATMProfileInner};
use affinidi_tdk::secrets_resolver::secrets::Secret;
use openvtc_core::config::account::{CommunityRecord, CommunityStatus, PersonaId, PersonaRecord};
use openvtc_core::config::{
    Config, KeyBackend, account::Account, protected_config::ProtectedConfig,
    public_config::PublicConfig, secured_config::ProtectionMethod,
};
use openvtc_core::didcomm::{Messaging, routes_inbound_type};
use openvtc_core::inbound::{Arrival, InboundEffects, process_inbound_message};
use openvtc_core::messaging::SeenMessages;
use openvtc_core::pending_replies::PendingReplies;
use openvtc_core::protocol_urls;
use openvtc_core::relationships::{
    BindingRole, Relationship, RelationshipRequestBody, RelationshipState, did_binding_proofs,
};
use openvtc_core::tasks::TaskType;
use tokio::sync::mpsc;

use common::{MockMediator, ProfileMessaging, Received, init_test_tracing, start_profile_inbound};

/// Alice (sending) and Bob (receiving, every type), connected.
struct Pair {
    alice: ProfileMessaging,
    _bob: ProfileMessaging,
    alice_did: String,
    bob_did: String,
    /// Alice's Ed25519 key: signs her proofs and documents.
    alice_key: Secret,
    bob_rx: mpsc::UnboundedReceiver<Received>,
    _mediator: MockMediator,
}

async fn connect() -> Pair {
    init_test_tracing();
    let mediator = MockMediator::start().await.expect("mediator start");
    let alice = mediator.profile("alice").expect("alice");
    let bob = mediator.profile("bob").expect("bob");
    let (alice_did, bob_did) = (alice.did.clone(), bob.did.clone());
    let alice_key = alice
        .secrets
        .iter()
        .find(|s| {
            s.get_public_keymultibase()
                .is_ok_and(|mb| mb.starts_with("z6Mk"))
        })
        .cloned()
        .expect("alice has an Ed25519 key");

    let (bob_tx, bob_rx) = mpsc::unbounded_channel();
    let bob = start_profile_inbound(bob, bob_tx).await.expect("bob up");
    let (alice_tx, _alice_rx) = mpsc::unbounded_channel();
    let alice = start_profile_inbound(alice, alice_tx)
        .await
        .expect("alice up");
    bob.wait_connected(Duration::from_secs(15))
        .await
        .expect("bob connected");
    alice
        .wait_connected(Duration::from_secs(15))
        .await
        .expect("alice connected");
    Pair {
        alice,
        _bob: bob,
        alice_did,
        bob_did,
        alice_key,
        bob_rx,
        _mediator: mediator,
    }
}

impl Pair {
    /// Alice sends `message` to Bob; Bob's transport hands it over.
    async fn deliver(&mut self, message: &Message) -> Received {
        self.alice
            .send(message, &self.bob_did)
            .await
            .expect("alice sends");
        // Bob's mailbox also carries the mediator's own traffic (pickup
        // status); the gate drops that, and it is not what this test sent.
        loop {
            let received = tokio::time::timeout(Duration::from_secs(15), self.bob_rx.recv())
                .await
                .expect("bob receives within 15s")
                .expect("inbound channel open");
            if received.message.id == message.id {
                return received;
            }
            assert!(
                !routes_inbound_type(&received.message.typ),
                "only mediator housekeeping arrives besides what Alice sent: {}",
                received.message.typ
            );
        }
    }

    fn message(&self, typ: &str, body: serde_json::Value) -> Message {
        Message::build(uuid::Uuid::new_v4().to_string(), typ.to_string(), body)
            .from(self.alice_did.clone())
            .to(self.bob_did.clone())
            .created_time(chrono::Utc::now().timestamp() as u64)
            .finalize()
    }
}

async fn offline_tdk() -> TDK {
    TDK::new(
        affinidi_tdk::common::config::TDKConfig::builder()
            .with_load_environment(false)
            .build()
            .expect("TDK config"),
        None,
    )
    .await
    .expect("TDK builds offline")
}

/// Bob's account: one persona, `bob_did`, with its runtime identity.
fn bob_config(bob_did: &str) -> (Config, PersonaId) {
    let mut config = Config {
        protected_key: None,
        integrity: Default::default(),
        public: PublicConfig::default(),
        private: ProtectedConfig::default(),
        key_backend: KeyBackend::Bip32 {
            root: ed25519_dalek_bip32::ExtendedSigningKey::from_seed(&[7u8; 32]).unwrap(),
            seed: secrecy::SecretString::new("seed".into()),
        },
        key_info: std::collections::HashMap::new(),
        protection_method: ProtectionMethod::default(),
        #[cfg(feature = "openpgp-card")]
        token_admin_pin: None,
        #[cfg(feature = "openpgp-card")]
        token_user_pin: secrecy::SecretString::new("".into()),
        unlock_code: None,
        account: Account::default(),
        identities: std::collections::BTreeMap::new(),
        active_persona: None,
        runtime_trust_overrides: None,
    };
    let pid = PersonaId::new();
    config.account.personas.insert(
        pid,
        PersonaRecord {
            extra: serde_json::Map::new(),
            persona_id: pid,
            did: bob_did.into(),
            did_document: None,
            did_locator: None,
            key_refs: vec![],
            mediator_did: None,
            origin_context_id: "openvtc".into(),
            created_at: chrono::Utc::now(),
            label: None,
        },
    );
    config.identities.insert(
        pid,
        openvtc_core::identity::IdentityContext {
            persona_id: pid,
            did: bob_did.to_string(),
            document: serde_json::from_value(serde_json::json!({ "id": bob_did }))
                .expect("minimal DID document"),
            profile: Arc::new(ATMProfile {
                inner: Arc::new(ATMProfileInner {
                    did: bob_did.to_string(),
                    alias: bob_did.to_string(),
                    mediator: Arc::new(None),
                }),
            }),
            mediator_did: None,
        },
    );
    (config, pid)
}

/// An established relationship between Bob and Alice, both on their personas.
fn with_relationship(config: &mut Config, alice: &str, bob: &str) {
    let alice = Arc::new(alice.to_string());
    config.private.relationships.relationships.insert(
        Arc::clone(&alice),
        Relationship {
            task_id: Arc::new(uuid::Uuid::new_v4().to_string()),
            our_did: Arc::new(bob.to_string()),
            remote_did: Arc::clone(&alice),
            remote_p_did: alice,
            created: chrono::Utc::now(),
            state: RelationshipState::Established,
            our_persona: None,
            needs_reestablishment: false,
        },
    );
}

/// What the runtime loop does with one arrival: the gate, then dispatch; a
/// message set aside for a proof check has the check run and is dispatched
/// again with its result. Returns whether the config changed and the effects of
/// the last pass. Panics if the gate refuses it — use [`gate_refuses`] for that.
async fn dispatch(config: &mut Config, tdk: &TDK, received: &Received) -> (bool, InboundEffects) {
    assert!(
        routes_inbound_type(&received.message.typ),
        "the gate admits {}",
        received.message.typ
    );
    let (tx, _rx) = mpsc::unbounded_channel();
    let service: Messaging =
        openvtc_core::didcomm::start_empty_service(tx, tokio_util::sync::CancellationToken::new());
    let mut seen = SeenMessages::new();
    let mut pending = PendingReplies::default();
    let nobody = |_: &str| false;
    let mut arrival = Arrival::New { waiting: &nobody };
    let mut message = received.message.clone();
    let mut changed = false;
    for _ in 0..3 {
        let mut effects = InboundEffects::default();
        changed |= process_inbound_message(
            config,
            tdk,
            &service,
            &mut seen,
            &mut pending,
            &message,
            received.authenticated.as_deref(),
            &mut effects,
            arrival,
        )
        .await
        .expect("dispatch");
        let Some(deferred) = effects.deferred.take() else {
            return (changed, effects);
        };
        arrival = Arrival::Returning(deferred.job.run(tdk.clone()).await);
        message = deferred.message;
    }
    panic!("a returning message is handled, not set aside again");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "slow: spawns the in-process mediator (~1s)"]
async fn a_trust_pong_closes_our_ping_and_a_ping_is_recorded() {
    let mut pair = connect().await;
    let tdk = offline_tdk().await;
    let (mut config, _) = bob_config(&pair.bob_did);
    with_relationship(&mut config, &pair.alice_did, &pair.bob_did);
    let alice = Arc::new(pair.alice_did.clone());

    // Our ping to Alice, waiting on its pong.
    let ping_id = Arc::new(uuid::Uuid::new_v4().to_string());
    config.private.tasks.new_task(
        &ping_id,
        TaskType::TrustPing {
            from: Arc::new(pair.bob_did.clone()),
            to: Arc::clone(&alice),
            remote_p_did: Arc::clone(&alice),
        },
    );
    let mut pong = pair.message(protocol_urls::TRUST_PONG, serde_json::json!({}));
    pong.thid = Some(ping_id.to_string());
    let received = pair.deliver(&pong).await;
    let (changed, _) = dispatch(&mut config, &tdk, &received).await;
    assert!(changed);
    assert!(
        config.private.tasks.get_by_id(&ping_id).is_none(),
        "the pong closed our ping"
    );

    // Alice pings us: recorded for the member to see.
    let ping = pair.message(
        protocol_urls::TRUST_PING,
        serde_json::json!({ "response_requested": true }),
    );
    let ping_task = Arc::new(ping.id.clone());
    let received = pair.deliver(&ping).await;
    let (changed, _) = dispatch(&mut config, &tdk, &received).await;
    assert!(changed);
    assert!(matches!(
        config.private.tasks.get_by_id(&ping_task).map(|t| &t.type_),
        Some(TaskType::TrustPing { .. })
    ));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "slow: spawns the in-process mediator (~1s)"]
async fn a_relationship_request_is_proven_then_queued() {
    let mut pair = connect().await;
    let tdk = offline_tdk().await;
    let (mut config, _) = bob_config(&pair.bob_did);

    let id = uuid::Uuid::new_v4().to_string();
    let (did_proof, persona_proof) = did_binding_proofs(
        &pair.alice_did,
        &pair.alice_did,
        &pair.bob_did,
        &id,
        BindingRole::Request,
        &pair.alice_key,
        &pair.alice_key,
    )
    .await
    .expect("Alice proves her DID for this request");
    let body = RelationshipRequestBody {
        reason: Some("e2e".into()),
        did: pair.alice_did.clone(),
        name: Some("Alice".into()),
        did_proof: Some(did_proof),
        persona_proof,
    };
    let mut request = pair.message(
        protocol_urls::RELATIONSHIP_REQUEST,
        serde_json::to_value(&body).unwrap(),
    );
    request.id = id.clone();
    let received = pair.deliver(&request).await;
    let (changed, _) = dispatch(&mut config, &tdk, &received).await;
    assert!(changed, "the request was queued");
    match config
        .private
        .tasks
        .get_by_id(&Arc::new(id))
        .map(|t| &t.type_)
    {
        Some(TaskType::RelationshipRequestInbound { from, .. }) => {
            assert_eq!(from.as_str(), pair.alice_did)
        }
        other => panic!("expected an inbound relationship request, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "slow: spawns the in-process mediator (~1s)"]
async fn a_vrc_in_an_established_relationship_is_proven_then_queued() {
    let mut pair = connect().await;
    let tdk = offline_tdk().await;
    let (mut config, _) = bob_config(&pair.bob_did);
    with_relationship(&mut config, &pair.alice_did, &pair.bob_did);

    let mut vrc = dtg_credentials::DTGCredential::new_vrc(
        pair.alice_did.clone(),
        dtg_credentials::IssuerScope::Pairwise,
        pair.bob_did.clone(),
        chrono::Utc::now(),
        None,
    );
    vrc.sign(&pair.alice_key, None).await.expect("Alice signs");
    let issued = pair.message(
        protocol_urls::VRC_ISSUED,
        serde_json::to_value(&vrc).unwrap(),
    );
    let task = Arc::new(issued.id.clone());
    let received = pair.deliver(&issued).await;
    let (changed, _) = dispatch(&mut config, &tdk, &received).await;
    assert!(changed, "the VRC was queued");
    assert!(matches!(
        config.private.tasks.get_by_id(&task).map(|t| &t.type_),
        Some(TaskType::VRCIssued { .. })
    ));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "slow: spawns the in-process mediator (~1s)"]
async fn a_communitys_signed_refusal_rejects_our_pending_join() {
    let mut pair = connect().await;
    let tdk = offline_tdk().await;
    let (mut config, pid) = bob_config(&pair.bob_did);
    // Alice is the community; our join to it is pending.
    let request_id = uuid::Uuid::new_v4();
    config.account.add_membership(CommunityRecord::new_pending(
        pair.alice_did.clone(),
        None,
        "openvtc/alice".into(),
        pid,
        request_id,
        chrono::Utc::now(),
    ));

    let mut document = serde_json::from_value(serde_json::json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": "https://trusttasks.org/spec/trust-task-error/0.1",
        "issuer": pair.alice_did,
        "recipient": pair.bob_did,
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "threadId": request_id.to_string(),
        "payload": {
            "code": "permissionDenied",
            "message": "not admitted",
            "retryable": false,
        },
    }))
    .expect("a refusal document");
    openvtc_core::capabilities::sign_document(&mut document, &pair.alice_key)
        .await
        .expect("the community signs its refusal");
    let mut refusal = pair.message(
        openvtc_core::capabilities::TRUST_TASK_ENVELOPE_TYPE,
        serde_json::to_value(&document).unwrap(),
    );
    refusal.thid = Some(request_id.to_string());
    let received = pair.deliver(&refusal).await;
    let (changed, effects) = dispatch(&mut config, &tdk, &received).await;
    assert!(changed);
    assert_eq!(
        config
            .account
            .membership(&pair.alice_did, pid)
            .map(|m| m.status.clone()),
        Some(CommunityStatus::Rejected),
        "the signed refusal rejected the join"
    );
    assert_eq!(effects.inactivated.len(), 1, "its session is torn down");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "slow: spawns the in-process mediator (~1s)"]
async fn a_type_no_handler_claims_is_refused_by_the_gate() {
    let mut pair = connect().await;
    let tdk = offline_tdk().await;
    let (mut config, _) = bob_config(&pair.bob_did);
    with_relationship(&mut config, &pair.alice_did, &pair.bob_did);

    let unknown = pair.message(
        "https://example.com/not-a-verb-we-speak/1.0",
        serde_json::json!({}),
    );
    let received = pair.deliver(&unknown).await;
    assert!(
        !routes_inbound_type(&received.message.typ),
        "the gate drops a type no handler claims"
    );
    // And were it put to the dispatcher anyway, nothing changes.
    let (tx, _rx) = mpsc::unbounded_channel();
    let service =
        openvtc_core::didcomm::start_empty_service(tx, tokio_util::sync::CancellationToken::new());
    let mut effects = InboundEffects::default();
    let nobody = |_: &str| false;
    let changed = process_inbound_message(
        &mut config,
        &tdk,
        &service,
        &mut SeenMessages::new(),
        &mut PendingReplies::default(),
        &received.message,
        received.authenticated.as_deref(),
        &mut effects,
        Arrival::New { waiting: &nobody },
    )
    .await
    .expect("dispatch");
    assert!(!changed);
    assert!(effects.deferred.is_none());
    assert!(config.private.tasks.tasks.is_empty());
}
