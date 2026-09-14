//! The vetting ceremony end to end, over a real in-process mediator.
//!
//! `openvtc-core/src/vetting/tests.rs` already walks this sequence — it hands
//! each message straight to [`handle`]. This does the same walk over DIDComm:
//! every document is packed, sent through the mediator, and unpacked on the
//! other side before the production handler sees it. What that adds is the leg
//! the unit tests cannot cover:
//!
//! * **These are the largest payloads OpenVTC sends peer to peer.** A signed
//!   Vetting Card carries the applicant's released claims and a proof; a signed
//!   Vetting Statement carries an endorsement credential. A size limit silently
//!   dropping a join submission has happened here before (#137), and nothing
//!   in-process would have caught it.
//! * **The envelope and the document must agree.** `wire::open` refuses a
//!   document whose issuer is not the DIDComm sender, and refuses a proof
//!   signed by anyone else. In-process that pairing is asserted by the test
//!   itself; over the wire the transport decides who the sender is.
//! * **The thread has to survive the round trip**, because a session's reply
//!   and the statement that follows it are correlated by it.
//!
//! Alice is the applicant and Bob the vetter, and they are the mediator's two
//! profiles: the DID that signs a vetting document is the DID that sends it, as
//! production requires. Both are `did:peer`, which
//! `TrustTaskVmResolver::did_key_only` resolves with no I/O, so the proofs
//! verify without a network. The community is a `did:key` — it never joins the
//! mediator, because nothing it sends here is peer-to-peer: its manifest and
//! the vetter's role credential are replies authenticated by their transport,
//! and they are handed in directly, as setup rather than as the thing under
//! test.
//!
//! `#[ignore]`d with the rest of the integration suite: the mediator boot and
//! websocket connect cost about a second. CI's coverage job runs them with
//! `--include-ignored`.

mod common;

use std::time::Duration;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use chrono::Utc;
use dtg_credentials::DTGCredential;
use openvtc_core::config::account::{Account, CommunityRecord, PersonaId};
use openvtc_core::vetting::applicant::{Application, RequestDraft};
use openvtc_core::vetting::book::VettingBook;
use openvtc_core::vetting::inbound::{Context, Handled, Notice, handle};
use openvtc_core::vetting::tickets::{DEFAULT_VALIDITY, Ticket};
use openvtc_core::vetting::vetter::Attestation;
use openvtc_core::vetting::wire;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use uuid::Uuid;
use vta_sdk::protocols::join_requests::{
    JOIN_REQUEST_MANIFEST_0_2_RESPONSE_TYPE, JOIN_REQUEST_MANIFEST_0_2_TYPE, manifest,
};
use vta_sdk::protocols::vetting::{
    COMMUNITY_ROLE_ENDORSEMENT_TYPE, IDENTITY_VETTING_ENDORSEMENT_TYPE, VETTER_ROLE,
    VETTING_REQUEST_RESPONSE_TYPE, VETTING_REQUEST_TYPE, VETTING_SESSION_RESPONSE_TYPE,
    VETTING_SESSION_TYPE, VettingMethod, VettingRelationship, VettingRequirements, session,
};
use vta_sdk::trust_task_proof::TrustTaskVmResolver;
use vta_sdk::vetting::card::sign_card;
use vta_sdk::vetting::statement::sign_statement;

use common::{MockMediator, ProfileMessaging, init_test_tracing, start_profile_messaging};

/// Every type either side listens for. The credential delivery carrying the
/// statement rides `credential-exchange/issue`, so the applicant subscribes to
/// that too.
const ROUTES: &[&str] = &[
    VETTING_REQUEST_TYPE,
    VETTING_REQUEST_RESPONSE_TYPE,
    VETTING_SESSION_TYPE,
    VETTING_SESSION_RESPONSE_TYPE,
    vta_sdk::protocols::credential_exchange::ISSUE,
];

const DIGEST: &str = "zQmVettingRequirementsDigest";

/// How long to wait for a message to cross the mediator before failing. Long
/// enough for a loaded CI box, short enough that a lost message is a failure
/// rather than a hang (R1.2).
const HOP: Duration = Duration::from_secs(10);

// ── identities ──────────────────────────────────────────────────────────

/// A `did:key` Ed25519 secret from a fixed seed, for the community.
fn key_secret(seed: u8) -> Secret {
    let mut secret = Secret::generate_ed25519(None, Some(&[seed; 32]));
    let public = secret.get_public_keymultibase().expect("multibase");
    secret.id = format!("did:key:{public}#{public}");
    secret
}

fn did_of(secret: &Secret) -> String {
    secret.id.split('#').next().expect("a did").to_string()
}

/// The profile's signing key.
///
/// A `did:peer` carries both an Ed25519 verification key and an X25519 key
/// agreement key; a data-integrity proof needs the former, and `z6Mk` is its
/// multicodec prefix. Picking by prefix rather than by position because the
/// order the mediator returns them in is not part of its contract.
fn signing_secret(secrets: &[Secret]) -> Secret {
    secrets
        .iter()
        .find(|s| {
            s.get_public_keymultibase()
                .is_ok_and(|mb| mb.starts_with("z6Mk"))
        })
        .cloned()
        .expect("the profile has an Ed25519 key")
}

// ── the two parties ─────────────────────────────────────────────────────

/// One side of the ceremony: its identity, its book, and the memberships the
/// handler reads to decide what it is entitled to do.
struct Party {
    did: String,
    secret: Secret,
    persona: PersonaId,
    book: VettingBook,
    account: Account,
}

impl Party {
    fn new(did: String, secret: Secret) -> Self {
        Self {
            did,
            secret,
            persona: PersonaId::new(),
            book: VettingBook::default(),
            account: Account::default(),
        }
    }

    fn member_of(mut self, community: &str) -> Self {
        let mut record = CommunityRecord::new_pending(
            community.to_string(),
            None,
            "openvtc/test".to_string(),
            self.persona,
            Uuid::new_v4(),
            Utc::now(),
        );
        record.activate(Utc::now());
        self.account.add_membership(record);
        self
    }

    /// Feed a message to the production handler as this party.
    async fn receive(&mut self, message: &Message, sender: &str) -> Handled {
        let resolver = TrustTaskVmResolver::did_key_only();
        let ctx = Context {
            account: &self.account,
            resolver: &resolver,
            recipient: Some((self.persona, &self.did)),
            now: Utc::now(),
        };
        handle(&mut self.book, &ctx, message, sender)
            .await
            .expect("a vetting message is claimed")
    }

    fn application(&mut self, community: &str) -> &mut Application {
        self.book
            .application_mut(community, self.persona)
            .expect("application started")
    }
}

// ── what the community says, handed in rather than sent ─────────────────

fn requirements() -> VettingRequirements {
    serde_json::from_value(json!({
        "version": "0.1",
        "statementType": IDENTITY_VETTING_ENDORSEMENT_TYPE,
        "minStatements": 1,
        "minByMethod": { "inPerson": 1 },
        "acceptedMethods": ["inPerson", "video"],
        "requiredClaims": ["name.legal"],
        "eligibleVetters": { "role": "vetter" }
    }))
    .expect("requirements")
}

fn manifest_reply(community: &str) -> Message {
    let criterion = manifest::v0_2::Criterion::try_from(
        manifest::v0_2::Criterion::builder()
            .id("vetted")
            .presentation_definition(serde_json::Map::new())
            .vetting(Some(requirements()))
            .requirements_digest(Some(
                manifest::v0_2::DigestMultibase::try_from(DIGEST).expect("digest"),
            )),
    )
    .expect("criterion");
    let body = manifest::v0_2::Response::try_from(
        manifest::v0_2::Response::builder()
            .community_did(community)
            .criteria(vec![criterion])
            .branding(None),
    )
    .expect("manifest");
    Message::build(
        wire::new_id(),
        JOIN_REQUEST_MANIFEST_0_2_RESPONSE_TYPE.to_string(),
        json!({ "type": JOIN_REQUEST_MANIFEST_0_2_TYPE, "payload": body }),
    )
    .from(community.to_string())
    .thid(wire::new_id())
    .finalize()
}

/// The community's `vetter` role credential for `subject`.
async fn role_credential(issuer: &Secret, community: &str, subject: &str) -> Value {
    let now = Utc::now();
    let mut credential = DTGCredential::new_vec(
        did_of(issuer),
        subject.to_string(),
        now - chrono::Duration::minutes(1),
        Some(now + chrono::Duration::days(365)),
        json!({
            "type": COMMUNITY_ROLE_ENDORSEMENT_TYPE,
            "role": VETTER_ROLE,
            "communityDid": community,
        }),
    )
    .with_id(wire::new_id());
    credential.sign(issuer, None).await.expect("sign the grant");
    serde_json::to_value(&credential).expect("credential json")
}

/// `credential-exchange/issue`, as a community's dispatcher delivers one.
fn delivery(credential: &Value, from: &str) -> Message {
    Message::build(
        wire::new_id(),
        vta_sdk::protocols::credential_exchange::ISSUE.to_string(),
        json!({ "credential_response": { "credential": credential } }),
    )
    .from(from.to_string())
    .finalize()
}

// ── the wire ────────────────────────────────────────────────────────────

/// Send a signed document and return it as the other side received it.
async fn hop(
    from: &ProfileMessaging,
    to_did: &str,
    inbox: &mut mpsc::UnboundedReceiver<Message>,
    message: &Message,
) -> Message {
    from.send(message, to_did).await.expect("send");
    tokio::time::timeout(HOP, inbox.recv())
        .await
        .expect("a vetting message crosses the mediator")
        .expect("the inbound channel is open")
}

#[tokio::test]
#[ignore = "boots a mediator (~1s); CI's coverage job runs it with --include-ignored"]
async fn the_vetting_ceremony_completes_over_the_wire() {
    init_test_tracing();
    let mediator = MockMediator::start().await.expect("mediator");
    let resolver = TrustTaskVmResolver::did_key_only();

    let community_secret = key_secret(9);
    let community = did_of(&community_secret);

    let alice_profile = mediator.profile("alice").expect("alice");
    let bob_profile = mediator.profile("bob").expect("bob");
    let alice_did = alice_profile.did.clone();
    let bob_did = bob_profile.did.clone();
    let alice_secret = signing_secret(&alice_profile.secrets);
    let bob_secret = signing_secret(&bob_profile.secrets);

    let (alice_tx, mut alice_inbox) = mpsc::unbounded_channel();
    let (bob_tx, mut bob_inbox) = mpsc::unbounded_channel();
    let alice_msg = start_profile_messaging(alice_profile, ROUTES, alice_tx)
        .await
        .expect("alice messaging");
    let bob_msg = start_profile_messaging(bob_profile, ROUTES, bob_tx)
        .await
        .expect("bob messaging");
    alice_msg.wait_connected(HOP).await.expect("alice connects");
    bob_msg.wait_connected(HOP).await.expect("bob connects");

    let mut alice = Party::new(alice_did.clone(), alice_secret);
    let mut bob = Party::new(bob_did.clone(), bob_secret).member_of(&community);

    // ── setup: what the community told each of them ────────────────────
    let grant = role_credential(&community_secret, &community, &bob_did).await;
    let handled = bob.receive(&delivery(&grant, &community), &community).await;
    assert!(
        matches!(handled.notice, Some(Notice::VetterGranted { .. })),
        "bob holds the community's vetter grant"
    );

    alice
        .book
        .start_application(&community, alice.persona, &alice_did, Utc::now())
        .expect("application starts");
    let handled = alice.receive(&manifest_reply(&community), &community).await;
    assert!(matches!(
        handled.notice,
        Some(Notice::RequirementsUpdated { .. })
    ));

    // ── 1. bob cuts a ticket; alice asks with it ───────────────────────
    let ticket = Ticket::issue(
        &community,
        bob.persona,
        vec![],
        1,
        DEFAULT_VALIDITY,
        Utc::now(),
    );
    let presented = ticket.code_presentation().expect("a code to read out");
    bob.book.tickets.push(ticket);

    let request_doc_id = wire::new_id();
    let body = alice
        .application(&community)
        .prepare_request(
            &request_doc_id,
            &bob_did,
            presented,
            RequestDraft::default(),
            Utc::now(),
        )
        .expect("a request");
    let mut document = wire::document(
        VETTING_REQUEST_TYPE,
        &alice_did,
        &bob_did,
        request_doc_id,
        &body,
    )
    .expect("request document");
    wire::sign(&mut document, &alice.secret)
        .await
        .expect("alice signs as herself");
    let request = wire::to_message(&document).expect("request message");

    let arrived = hop(&alice_msg, &bob_did, &mut bob_inbox, &request).await;
    // The envelope survived: same document, same thread, same issuer.
    assert_eq!(arrived.typ, VETTING_REQUEST_TYPE);
    assert_eq!(arrived.body, request.body, "the document crossed intact");

    let handled = bob.receive(&arrived, &alice_did).await;
    let Some(Notice::RequestAccepted { request_id, .. }) = handled.notice.clone() else {
        panic!("a ticketed request is accepted, got {:?}", handled.notice);
    };

    // ── 2. bob answers, presenting the grant ───────────────────────────
    let reply = handled.reply.expect("an accepted request is answered");
    assert!(
        reply.eligibility.is_some(),
        "a named vetter presents the grant"
    );
    let mut response = reply.document;
    wire::attach_eligibility(
        &mut response,
        &bob.secret,
        reply.eligibility.expect("eligibility"),
    )
    .await
    .expect("attach the eligibility presentation");
    wire::sign(&mut response, &bob.secret)
        .await
        .expect("bob signs the answer");
    let response = wire::to_message(&response).expect("response message");

    let arrived = hop(&bob_msg, &alice_did, &mut alice_inbox, &response).await;
    let handled = alice.receive(&arrived, &bob_did).await;
    assert!(
        matches!(
            handled.notice,
            Some(Notice::VetterAccepted {
                shown_eligible: true,
                ..
            })
        ),
        "the grant verified after crossing the wire, got {:?}",
        handled.notice
    );

    // ── 3. the session, and the match code both screens show ───────────
    let session_id = wire::new_id();
    let body = bob
        .book
        .open_session(
            &request_id,
            VettingMethod::InPerson,
            vec!["name.legal".into()],
            vec![],
            &session_id,
            Utc::now(),
        )
        .expect("a session");
    let mut document = wire::document(
        VETTING_SESSION_TYPE,
        &bob_did,
        &alice_did,
        session_id.clone(),
        &body,
    )
    .expect("session document");
    wire::sign(&mut document, &bob.secret).await.expect("sign");
    let session_doc = document.clone();
    let session_msg = wire::to_message(&document).expect("session message");

    let arrived = hop(&bob_msg, &alice_did, &mut alice_inbox, &session_msg).await;
    let handled = alice.receive(&arrived, &bob_did).await;
    let Some(Notice::SessionOpened {
        session_id: opened,
        match_code,
        ..
    }) = handled.notice.clone()
    else {
        panic!("the session opens, got {:?}", handled.notice);
    };
    assert_eq!(
        Some(match_code.as_str()),
        bob.book.desk_entry(&request_id).expect("desk").match_code(),
        "both sides derive the same code from the session that crossed"
    );

    // ── 4. alice signs a card and sends it back ────────────────────────
    let draft = alice
        .application(&community)
        .card_draft(
            &opened,
            vec![
                session::v0_1::VettingCardClaim::try_from(
                    session::v0_1::VettingCardClaim::builder()
                        .type_("name.legal")
                        .value(json!("Alice Example"))
                        .provenance("selfAsserted"),
                )
                .expect("claim"),
            ],
            Utc::now(),
        )
        .expect("a card draft");
    let card = sign_card(draft, &alice.secret)
        .await
        .expect("sign the card");
    alice
        .application(&community)
        .record_card(&opened, &card, &resolver, Utc::now())
        .await
        .expect("record the card");
    let mut document =
        wire::response(&session_doc, &json!({ "card": card })).expect("card response");
    wire::sign(&mut document, &alice.secret)
        .await
        .expect("sign the response");
    let card_msg = wire::to_message(&document).expect("card message");

    let arrived = hop(&alice_msg, &bob_did, &mut bob_inbox, &card_msg).await;
    assert_eq!(
        arrived.body, card_msg.body,
        "the signed card crossed intact — its digest is what the statement names"
    );
    let handled = bob.receive(&arrived, &alice_did).await;
    assert!(
        matches!(handled.notice, Some(Notice::CardReceived { .. })),
        "the card verified against the session it answers, got {:?}",
        handled.notice
    );

    // ── 5. bob attests, and the statement travels ──────────────────────
    let draft = bob
        .book
        .statement_draft(
            &request_id,
            &bob_did,
            Attestation {
                method: VettingMethod::InPerson,
                document_classes: vec!["passport".into()],
                claims_verified: vec!["name.legal".into()],
                liveness_confirmed: true,
                declared_relationship: VettingRelationship::None,
                attestation_text_digest: None,
            },
            Utc::now(),
        )
        .expect("a statement draft");
    let statement = sign_statement(draft, &bob.secret)
        .await
        .expect("sign the statement");
    bob.book
        .record_statement(&request_id, &statement, &resolver, Utc::now())
        .await
        .expect("record the statement");
    let statement_msg = wire::credential_delivery(&bob_did, &alice_did, &statement, &opened)
        .expect("credential delivery");

    let arrived = hop(&bob_msg, &alice_did, &mut alice_inbox, &statement_msg).await;
    let handled = alice.receive(&arrived, &bob_did).await;
    assert!(
        matches!(handled.notice, Some(Notice::StatementReceived { .. })),
        "the statement verified against alice's own card, got {:?}",
        handled.notice
    );

    // ── the point of all of it ─────────────────────────────────────────
    let application = alice.application(&community);
    assert!(
        application
            .checklist(Utc::now())
            .expect("a checklist")
            .satisfied(),
        "one statement from one vetter meets requirements that ask for one"
    );
    assert_eq!(application.presentable_statements(Utc::now()).len(), 1);
    assert_eq!(application.join_extensions()["requirementsDigest"], DIGEST);
}

#[tokio::test]
#[ignore = "boots a mediator (~1s); CI's coverage job runs it with --include-ignored"]
async fn a_request_without_a_ticket_is_refused_at_the_desk() {
    init_test_tracing();
    let mediator = MockMediator::start().await.expect("mediator");
    let community = did_of(&key_secret(9));

    let alice_profile = mediator.profile("alice").expect("alice");
    let bob_profile = mediator.profile("bob").expect("bob");
    let alice_did = alice_profile.did.clone();
    let bob_did = bob_profile.did.clone();
    let alice_secret = signing_secret(&alice_profile.secrets);
    let bob_secret = signing_secret(&bob_profile.secrets);

    let (alice_tx, _alice_inbox) = mpsc::unbounded_channel();
    let (bob_tx, mut bob_inbox) = mpsc::unbounded_channel();
    let alice_msg = start_profile_messaging(alice_profile, ROUTES, alice_tx)
        .await
        .expect("alice messaging");
    let bob_msg = start_profile_messaging(bob_profile, ROUTES, bob_tx)
        .await
        .expect("bob messaging");
    alice_msg.wait_connected(HOP).await.expect("alice connects");
    bob_msg.wait_connected(HOP).await.expect("bob connects");

    let mut alice = Party::new(alice_did.clone(), alice_secret);
    let mut bob = Party::new(bob_did.clone(), bob_secret).member_of(&community);

    alice
        .book
        .start_application(&community, alice.persona, &alice_did, Utc::now())
        .expect("application starts");
    alice.receive(&manifest_reply(&community), &community).await;

    // A ticket bob never issued: the code is well-formed and worthless.
    let stranger = Ticket::issue(
        &community,
        PersonaId::new(),
        vec![],
        1,
        DEFAULT_VALIDITY,
        Utc::now(),
    );
    let presented = stranger.code_presentation().expect("a code");

    let id = wire::new_id();
    let body = alice
        .application(&community)
        .prepare_request(
            &id,
            &bob_did,
            presented,
            RequestDraft::default(),
            Utc::now(),
        )
        .expect("a request");
    let mut document =
        wire::document(VETTING_REQUEST_TYPE, &alice_did, &bob_did, id, &body).expect("document");
    wire::sign(&mut document, &alice.secret)
        .await
        .expect("sign");
    let request = wire::to_message(&document).expect("message");

    let arrived = hop(&alice_msg, &bob_did, &mut bob_inbox, &request).await;
    let handled = bob.receive(&arrived, &alice_did).await;
    assert!(
        !matches!(handled.notice, Some(Notice::RequestAccepted { .. })),
        "a ticket bob did not issue does not open his desk, got {:?}",
        handled.notice
    );
    assert!(
        bob.book.desk.is_empty(),
        "nothing is recorded for a request that was never consented to"
    );
}
