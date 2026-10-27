//! Witnessing a relationship through the member's VTA, end to end (`openvtc_core::witness`).
//!
//! The VTA is a real one, in process (`MockVta`, the `vta/witness/*/0.2` tasks behind the production
//! spine), driven through this client's own round (`witness::run`) exactly as the TUI drives it.
//! The relationship is the shape this client mints: a `did:peer:2` over keys created at the VTA
//! with no context named — so they land in the account's one context — and a VRC signed locally
//! with the exported key, then stored in the vault by this client's own sync.
//!
//! The witness is a minimal one held by the test: it answers `witness/session` with a challenge
//! and `witness/session/submit` with a VWC built by `dtg-credentials` over the presented
//! relationship credential, signed with its own `did:key` — what the VTA verifies before storing
//! it. Its answers reach the round through the same `ReplyRouter` the inbound dispatcher feeds.
//!
//! `#[ignore]`'d like the other MockVta suites: spinning up the VTA is slow. CI's coverage job
//! runs them via `--include-ignored`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use affinidi_tdk::dids::{DID, PeerKeyRole};
use async_trait::async_trait;
use chrono::{TimeDelta, Utc};
use dtg_credentials::{DTGCredential, IssuerScope};
use openvtc_core::specs::witness::session;
use openvtc_core::witness::{
    self, Carrier, MembershipEvidence, ReplyRouter, Round, WitnessError, WitnessRefusal,
    WitnessRequest,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use trust_tasks_rs::{ErrorPayload, TrustTask};
use vta_sdk::client::{ClientIdentity, CreateContextRequest, CreateKeyRequest, VtaClient};
use vta_sdk::keys::KeyType;
use vta_sdk::provision_client::EphemeralSetupKey;
use vta_sdk::trust_task_proof::TrustTaskVmResolver;
use vta_sdk::trust_task_sign::{HolderKey, sign_in_place_with, sign_object_for_assertion};
use vta_service::test_support::MockVta;

const CTX: &str = "personal";

fn urn() -> String {
    format!("urn:uuid:{}", uuid::Uuid::new_v4())
}

fn holder(key: &EphemeralSetupKey) -> HolderKey {
    HolderKey::from_did_key(&key.did, key.private_key_multibase()).expect("holder key")
}

/// What the witness does with a document, for one test.
#[derive(Clone, Copy, PartialEq)]
enum Behaviour {
    Witness,
    RefuseSession,
}

/// A witness, in process. Answers are signed for `authentication` by its `did:key`.
struct TestWitness {
    key: EphemeralSetupKey,
    behaviour: Behaviour,
    /// Session id → (challenge, the session document as received).
    sessions: Mutex<HashMap<String, (String, Value)>>,
}

impl TestWitness {
    fn did(&self) -> &str {
        &self.key.did
    }

    async fn answer(&self, sender: &str, document: &Value) -> Value {
        let doc: TrustTask<Value> = serde_json::from_value(document.clone()).expect("a document");
        let type_uri = doc.type_uri.to_string();
        let payload = if type_uri == witness::session_type() {
            if self.behaviour == Behaviour::RefuseSession {
                return self
                    .refuse(&doc, sender, session::v0_2::error_codes::REFUSED.into())
                    .await;
            }
            assert_eq!(doc.thread_id.as_deref(), Some(doc.id.as_str()));
            let challenge = hex::encode(Sha256::digest(urn().as_bytes()));
            self.sessions
                .lock()
                .unwrap()
                .insert(doc.id.clone(), (challenge.clone(), document.clone()));
            json!({ "challenge": challenge, "domain": self.did() })
        } else {
            assert_eq!(type_uri, witness::submit_type());
            let thread = doc.thread_id.clone().expect("threaded to its session");
            let (challenge, session_document) = self
                .sessions
                .lock()
                .unwrap()
                .remove(&thread)
                .expect("a session this witness opened");
            let vp = &doc.payload["vp"];
            assert_eq!(vp["nonce"], challenge, "bound to the session's challenge");
            assert_eq!(vp["domain"], self.did(), "bound to the session's domain");
            let vrc = vp["verifiableCredential"]
                .as_array()
                .unwrap()
                .iter()
                .find(|vc| {
                    vc["type"]
                        .as_array()
                        .is_some_and(|t| t.iter().any(|t| t == "RelationshipCredential"))
                })
                .expect("the relationship credential is presented")
                .clone();
            let vwc = DTGCredential::new_witnessed_vsc(
                self.did().to_string(),
                IssuerScope::Public,
                &vrc,
                &session_document,
                Utc::now(),
                None,
                None,
            )
            .expect("a VWC over the session")
            .with_id(urn());
            let mut vwc = serde_json::to_value(vwc).unwrap();
            sign_object_for_assertion(&mut vwc, &holder(&self.key))
                .await
                .expect("sign the VWC");
            let mut multihash = vec![0x12, 0x20];
            multihash.extend_from_slice(&Sha256::digest(
                serde_json_canonicalizer::to_vec(&vwc).unwrap(),
            ));
            json!({
                "vwc": vwc,
                "vwcDigestMultibase": multibase::encode(multibase::Base::Base58Btc, multihash),
            })
        };
        let mut reply = doc.respond_with(urn(), payload);
        reply.issuer = Some(self.did().to_string());
        reply.recipient = Some(sender.to_string());
        reply.issued_at = Some(Utc::now());
        sign_in_place_with(&mut reply, &holder(&self.key))
            .await
            .expect("sign the answer");
        serde_json::to_value(reply).unwrap()
    }

    async fn refuse(&self, doc: &TrustTask<Value>, sender: &str, error: ErrorPayload) -> Value {
        let reply = doc.reject_with_recipient(urn(), error, Some(sender.to_string()));
        let mut reply: TrustTask<Value> =
            serde_json::from_value(serde_json::to_value(reply).unwrap()).unwrap();
        reply.issuer = Some(self.did().to_string());
        reply.issued_at = Some(Utc::now());
        sign_in_place_with(&mut reply, &holder(&self.key))
            .await
            .expect("sign the refusal");
        serde_json::to_value(reply).unwrap()
    }
}

/// Carries a document to the witness from the relationship DID, and delivers the answer the way
/// the inbound dispatcher does: to the router, under the transport-proven sender.
struct InProcess {
    witness: Arc<TestWitness>,
    router: ReplyRouter,
    from: String,
    /// What was carried, in order — to check what the client sent in the relationship's name.
    carried: Mutex<Vec<Value>>,
}

#[async_trait]
impl Carrier for InProcess {
    async fn send(&self, document: &Value) -> Result<(), String> {
        self.carried.lock().unwrap().push(document.clone());
        let answer = self.witness.answer(&self.from, document).await;
        assert!(self.router.deliver(self.witness.did(), answer));
        Ok(())
    }
}

/// A member's VTA holding a relationship minted the way this client mints one, and the
/// credentials it presents.
struct World {
    _mock: MockVta,
    client: VtaClient,
    relationship: String,
    counterparty: String,
    vrc: Value,
    community: EphemeralSetupKey,
}

/// Which of our DIDs the relationship uses.
#[derive(Clone, Copy, PartialEq)]
enum OurSide {
    /// A pairwise `did:peer:2`, as this client mints one by default.
    PairwiseDid,
    /// The persona DID itself — a `did:key` over a key the VTA holds, in the account's context.
    PersonaDid,
}

impl World {
    async fn new() -> Self {
        Self::with(OurSide::PairwiseDid).await
    }

    async fn with(our_side: OurSide) -> Self {
        let mock = MockVta::start_provisionable().await;
        let admin = EphemeralSetupKey::generate().expect("admin key");
        let super_token = mock.ctx.mint_token(&admin.did, "admin", vec![]).await;
        let setup = VtaClient::authenticated(
            mock.base_url(),
            ClientIdentity::did_key(
                admin.did.clone(),
                admin.private_key_multibase(),
                mock.vta_did(),
            ),
            super_token,
        )
        .await;
        setup
            .create_context(CreateContextRequest {
                id: CTX.into(),
                name: CTX.into(),
                description: None,
                parent: None,
            })
            .await
            .expect("create the context");

        // The account's own credential: an admin of its one context, as onboarding grants.
        let member = EphemeralSetupKey::generate().expect("member key");
        let token = mock
            .ctx
            .mint_token(&member.did, "admin", vec![CTX.into()])
            .await;
        let client = VtaClient::authenticated(
            mock.base_url(),
            ClientIdentity::did_key(
                member.did.clone(),
                member.private_key_multibase(),
                mock.vta_did(),
            ),
            token,
        )
        .await;

        // The relationship keys, as `relationship_actions::create_relationship_keys` creates
        // them: no context named, then exported. The export is the VTA's own operation, called
        // as the account over an end-to-end channel: the client exports over DIDComm, and the
        // VTA refuses an export over this test's REST client.
        let secret = |key_type| {
            let client = &client;
            let state = &mock.ctx.state;
            async move {
                let created = client
                    .create_key(CreateKeyRequest {
                        internal: None,
                        key_type,
                        derivation_path: None,
                        key_id: None,
                        mnemonic: None,
                        label: Some("relationship".into()),
                        context_id: None,
                    })
                    .await
                    .expect("create a relationship key");
                let response = vta_service::operations::keys::get_key_secret(
                    &state.keys_ks,
                    &state.imported_ks,
                    &state.contexts_ks,
                    &state.acl_ks,
                    &state.seed_store,
                    &state.audit_sink,
                    &vta_service::test_support::admin_claims_for_context(CTX),
                    &created.key_id,
                    vta_service::operations::keys::ExportChannel::EndToEnd("didcomm"),
                )
                .await
                .expect("export it");
                vta_sdk::did_key::secret_from_key_response(&response).expect("a secret")
            }
        };
        let mut v_secret = secret(KeyType::Ed25519).await;
        let relationship = match our_side {
            OurSide::PairwiseDid => {
                let mut e_secret = secret(KeyType::X25519).await;
                let mediator = EphemeralSetupKey::generate().unwrap().did;
                DID::generate_did_peer_from_secrets(
                    &mut [
                        (PeerKeyRole::Verification, &mut v_secret),
                        (PeerKeyRole::Encryption, &mut e_secret),
                    ],
                    Some(mediator),
                )
                .expect("the relationship DID")
            }
            OurSide::PersonaDid => {
                let public = v_secret.get_public_keymultibase().expect("a public key");
                let did = format!("did:key:{public}");
                v_secret.id = format!("{did}#{public}");
                did
            }
        };

        // Our VRC to the counterparty, as `prepare_accept_vrc_request` issues it.
        let counterparty = EphemeralSetupKey::generate().unwrap().did;
        let mut vrc = openvtc_core::vrc::new_identified_vrc(
            &relationship,
            openvtc_core::dtg::relationship_issuer_scope(false),
            &counterparty,
            Utc::now() - TimeDelta::minutes(5),
            None,
        );
        vrc.sign(&v_secret, None).await.expect("sign the VRC");
        let vrc = serde_json::to_value(&vrc).unwrap();

        Self {
            _mock: mock,
            client,
            relationship,
            counterparty,
            vrc,
            community: EphemeralSetupKey::generate().unwrap(),
        }
    }

    /// The community's membership credential naming `member`.
    async fn vmc(&self, member: &str) -> Value {
        let vc = DTGCredential::new_vmc(
            self.community.did.clone(),
            member.to_string(),
            Utc::now() - TimeDelta::days(1),
            None,
            false,
        )
        .with_id(urn());
        let mut v = serde_json::to_value(vc).unwrap();
        sign_object_for_assertion(&mut v, &holder(&self.community))
            .await
            .unwrap();
        v
    }

    fn request(&self, witness: &str, membership: Option<MembershipEvidence>) -> WitnessRequest {
        WitnessRequest {
            witness_did: witness.to_string(),
            relationship_did: self.relationship.clone(),
            counterparty_did: self.counterparty.clone(),
            relationship_thread_id: urn(),
            relationship_credential: self.vrc.clone(),
            membership,
        }
    }

    async fn run(
        &self,
        witness: Arc<TestWitness>,
        membership: Option<MembershipEvidence>,
    ) -> (Result<witness::Witnessed, WitnessError>, Vec<Value>) {
        let router = ReplyRouter::default();
        let carrier = InProcess {
            witness: witness.clone(),
            router: router.clone(),
            from: self.relationship.clone(),
            carried: Mutex::new(Vec::new()),
        };
        let resolver = TrustTaskVmResolver::did_key_only();
        let round = Round {
            vta: &self.client,
            carrier: &carrier,
            router: &router,
            resolver: &resolver,
            answer_timeout: Duration::from_secs(10),
        };
        let steps = Mutex::new(Vec::new());
        let result = witness::run(&round, &self.request(witness.did(), membership), &|step| {
            steps.lock().unwrap().push(step)
        })
        .await;
        (result, carrier.carried.into_inner().unwrap())
    }
}

fn witness(behaviour: Behaviour) -> Arc<TestWitness> {
    Arc::new(TestWitness {
        key: EphemeralSetupKey::generate().unwrap(),
        behaviour,
        sessions: Mutex::new(HashMap::new()),
    })
}

/// open → carry → present → carry → accept: the VTA stores the VWC, and the client keeps the
/// session's outcome evidence a community needs beside it. The relationship key was created with
/// no context named — the account's one context — and the VRC reached the vault through this
/// client's own sync.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "slow: spins up a VTA"]
async fn a_relationship_is_witnessed_through_the_vta() {
    let w = World::new().await;

    let stored = openvtc_core::credential_sync::store_relationship_credentials(
        &w.client,
        vec![w.vrc.clone()],
    )
    .await;
    assert_eq!(stored.stored, 1, "{stored:?}");
    let again = openvtc_core::credential_sync::store_relationship_credentials(
        &w.client,
        vec![w.vrc.clone()],
    )
    .await;
    assert_eq!(
        (again.stored, again.already_held),
        (0, 1),
        "a VRC the vault holds is not stored again — that would change the bytes a session is \
         bound to"
    );

    let vmc = w.vmc(&w.relationship).await;
    let witness = witness(Behaviour::Witness);
    let (result, carried) = w
        .run(
            witness.clone(),
            Some(MembershipEvidence {
                credential: vmc,
                member_did: None,
            }),
        )
        .await;
    let witnessed = result.expect("witnessed");

    assert_eq!(witnessed.witness, witness.did());
    assert_eq!(
        carried.len(),
        2,
        "the session document, then the submission"
    );
    assert_eq!(witnessed.evidence["session"], carried[0]);
    assert_eq!(
        witnessed.evidence["outcome"]["type"],
        format!("{}#response", witness::submit_type())
    );
    let vwc = witnessed.vwc().expect("the VWC is in the evidence");
    assert_eq!(vwc["issuer"], witness.did());
    assert!(
        carried
            .iter()
            .all(|d| d["issuer"] == w.relationship.as_str() && d["recipient"] == witness.did()),
        "everything carried is the relationship DID's, to the witness"
    );

    assert!(
        carried[1]["payload"].get("memberPresentation").is_none(),
        "a VMC naming the relationship DID needs no member link"
    );

    // The VWC is in the vault under the handle the VTA reported.
    let held = w
        .client
        .cred_vault_get(&witnessed.credential_id)
        .await
        .expect("the VWC is stored at the VTA");
    assert_eq!(held["credential"], *vwc);

    // And it rides a personhood assertion with its evidence.
    let record = witness::WitnessRecord {
        remote_p_did: w.counterparty.clone(),
        relationship_did: w.relationship.clone(),
        witnessed_at: Utc::now(),
        witnessed: witnessed.clone(),
    };
    let (none, no_evidence) = witness::personhood_evidence([&record], &[]);
    assert!(
        none.is_empty() && no_evidence.is_empty(),
        "nothing unless selected"
    );
    let (vwcs, evidence) =
        witness::personhood_evidence([&record], std::slice::from_ref(&witnessed.session_id));
    assert_eq!(vwcs, vec![vwc.clone()]);
    assert_eq!(evidence, vec![witnessed.evidence.clone()]);
}

/// A refusal from the witness ends the session at the client, classified, and is never handed
/// back to the VTA.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "slow: spins up a VTA"]
async fn a_witness_refusal_ends_the_session_with_a_reason() {
    let w = World::new().await;
    let (result, carried) = w.run(witness(Behaviour::RefuseSession), None).await;
    match result {
        Err(WitnessError::Refused { refusal, code, .. }) => {
            assert_eq!(refusal, WitnessRefusal::SessionRefused);
            assert_eq!(code, "witness/session:refused");
        }
        other => panic!("expected the witness's refusal, got {other:?}"),
    }
    assert_eq!(carried.len(), 1, "nothing is presented after a refusal");
}

/// When the member explicitly opts in for this witnessing (`membership` with `memberDid`), a
/// membership credential naming the persona rather than the relationship DID is linked to it by a
/// second presentation by the persona, which the VTA carries in the submission's own
/// `memberPresentation` (`witness/session/submit/0.2`) — never in a vendor `ext`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "slow: spins up a VTA"]
async fn the_member_link_rides_the_submissions_member_presentation() {
    let w = World::new().await;
    // A persona DID the VTA holds a key of, in the account's context.
    let persona_key = w
        .client
        .create_key(CreateKeyRequest {
            internal: None,
            key_type: KeyType::Ed25519,
            derivation_path: None,
            key_id: None,
            mnemonic: None,
            label: Some("persona".into()),
            context_id: None,
        })
        .await
        .expect("a persona key");
    let raw = vta_sdk::did_key::decode_ed25519_public_key_multibase(&persona_key.public_key)
        .expect("an Ed25519 key");
    let persona = affinidi_tdk::affinidi_crypto::did_key::ed25519_pub_to_did_key(&raw);
    let vmc = w.vmc(&persona).await;

    // The explicit opt-in: the member chose to let this witness learn who they are.
    let opted_in = Some(MembershipEvidence {
        credential: vmc,
        member_did: Some(persona.clone()),
    });
    let (result, carried) = w.run(witness(Behaviour::Witness), opted_in).await;
    result.expect("witnessed with the member link");
    let submit = &carried[1];
    assert_eq!(submit["type"], witness::submit_type());
    let member = &submit["payload"]["memberPresentation"];
    assert_eq!(member["holder"], persona.as_str(), "{submit}");
    assert!(
        submit.get("ext").is_none() && submit["payload"].get("ext").is_none(),
        "no vendor carriage: {submit}"
    );
}

/// By default — the member chose nothing — no membership is named on `vta/witness/open`, so
/// the witness learns nothing of the member: the submission carries only the relationship
/// credential, and no member presentation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "slow: spins up a VTA"]
async fn by_default_no_membership_and_no_member_presentation_is_sent() {
    let w = World::new().await;
    let (result, carried) = w.run(witness(Behaviour::Witness), None).await;
    result.expect("witnessed without any membership");
    let submit = &carried[1];
    assert_eq!(submit["type"], witness::submit_type());
    assert!(
        submit["payload"].get("memberPresentation").is_none(),
        "no member presentation: {submit}"
    );
    let presented = submit["payload"]["vp"]["verifiableCredential"]
        .as_array()
        .expect("the presentation's credentials");
    assert_eq!(presented.len(), 1, "only the relationship credential");
    assert!(
        presented[0]["type"]
            .as_array()
            .is_some_and(|t| t.iter().any(|t| t == "RelationshipCredential")),
        "{presented:?}"
    );
}

/// A witnessing whose record this client lost — `accept` answered, then the process died before
/// the record was kept anywhere — is rebuilt from `vta/witness/list`, byte for byte what `accept`
/// returned, and only once. Rebuilding it presents nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "slow: spins up a VTA"]
async fn a_lost_witnessing_is_rebuilt_from_the_vtas_list() {
    let w = World::new().await;
    let (result, _) = w.run(witness(Behaviour::Witness), None).await;
    let witnessed = result.expect("witnessed");

    let ours = |relationship_did: &str, parties: &[String]| {
        (relationship_did == w.relationship && parties.contains(&w.counterparty))
            .then(|| "did:webvh:bob".to_string())
    };

    // The crash: nothing kept locally.
    let mut local = witness::Witnessings::default();
    let rebuilt = witness::reconcile(&w.client, &mut local, ours)
        .await
        .expect("listed");
    assert_eq!(rebuilt, 1);
    let record = &local.0[0];
    assert_eq!(record.remote_p_did, "did:webvh:bob");
    assert_eq!(record.relationship_did, w.relationship);
    assert_eq!(
        record.witnessed, witnessed,
        "the record is what `accept` answered: handle, witness, digest and evidence"
    );
    assert!(record.witnessed.vwc().is_some());

    // Once: what is kept is not rebuilt again.
    assert_eq!(
        witness::reconcile(&w.client, &mut local, ours)
            .await
            .unwrap(),
        0
    );
    assert_eq!(local.0.len(), 1);

    // A rebuilt record is a choice the picker offers, never a disclosure on its own.
    let (vwcs, evidence) = witness::personhood_evidence(&local.0, &[]);
    assert!(vwcs.is_empty() && evidence.is_empty());

    // A relationship this account no longer holds is not brought back.
    let mut fresh = witness::Witnessings::default();
    assert_eq!(
        witness::reconcile(&w.client, &mut fresh, |_, _| None)
            .await
            .unwrap(),
        0
    );
    assert!(fresh.is_empty());
}

/// A relationship that uses the persona DID itself (not a pairwise DID) is witnessed the same
/// way: the VTA signs as the persona, and the membership credential, which names the persona,
/// needs no member link.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "slow: spins up a VTA"]
async fn a_persona_did_relationship_is_witnessed_through_the_vta() {
    let w = World::with(OurSide::PersonaDid).await;
    assert!(w.relationship.starts_with("did:key:"), "{}", w.relationship);
    let vmc = w.vmc(&w.relationship).await;
    let witness = witness(Behaviour::Witness);
    let (result, carried) = w
        .run(
            witness.clone(),
            Some(MembershipEvidence {
                credential: vmc,
                member_did: None,
            }),
        )
        .await;
    let witnessed = result.expect("witnessed as the persona");
    assert_eq!(witnessed.witness, witness.did());
    assert_eq!(carried.len(), 2);
    assert!(
        carried
            .iter()
            .all(|d| d["issuer"] == w.relationship.as_str() && d["recipient"] == witness.did()),
        "everything carried is the persona's, to the witness"
    );
    assert_eq!(
        witnessed.vwc().expect("a VWC")["credentialSubject"]["id"],
        w.relationship.as_str()
    );
}
