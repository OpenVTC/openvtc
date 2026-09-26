//! The whole exchange between an applicant and a vetter, message by message,
//! through the same [`super::inbound::handle`] the TUI's dispatch calls.
//!
//! Each party keeps its own book and account; the only thing that passes
//! between them is a DIDComm `Message`, built and signed the way the client
//! sends it. Nothing here touches a network: every DID is a `did:key`.

use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use chrono::{Duration, Utc};
use dtg_credentials::DTGCredential;
use serde_json::{Value, json};
use trust_tasks_rs::TrustTask;
use uuid::Uuid;
use vta_sdk::protocols::join_requests::{JOIN_REQUEST_MANIFEST_0_2_RESPONSE_TYPE, manifest};
use vta_sdk::protocols::vetting::{
    COMMUNITY_ROLE_ENDORSEMENT_TYPE, IDENTITY_VETTING_ENDORSEMENT_TYPE, VETTER_ROLE,
    VETTING_DECLINE_TYPE, VETTING_REQUEST_ERR_INVALID_TICKET, VETTING_REQUEST_ERR_NOT_ELIGIBLE,
    VETTING_REQUEST_TYPE, VETTING_SESSION_TYPE, VETTING_VETTER_PROFILE_ERR_NOT_ELIGIBLE,
    VETTING_VETTER_RESEND_ERR_NOT_GRANTED, VettingMethod, VettingRelationship, VettingRequirements,
    decline, request, revoke_statement, session, vetters,
};
use vta_sdk::trust_task_proof::TrustTaskVmResolver;
use vta_sdk::vetting::card::sign_card;
use vta_sdk::vetting::statement::sign_statement;
use vta_sdk::vetting::status::StatusCheck;

use super::VettingBook;
use super::applicant::{
    ApplicantError, Application, ChosenFace, GrantStatus, NextStep, RequestDraft, RequestState,
    TicketUriError, VetterEligibility,
};
use super::book::{Knowledge, VetterPolicy};
use super::inbound::{Context, Handled, Notice, Reply, handle};
use super::queries::{CommunityAnswer, CommunityQuery, QueryKind};
use super::registry::{ProfileDraft, ProfileState};
use super::tickets::{DEFAULT_VALIDITY, Ticket};
use super::vetter::{Attestation, DeskState};
use super::wire::{
    self,
    tests::{did, secret},
};
use crate::config::account::{Account, CommunityRecord, PersonaId};
use crate::persona::disclosure::ReleasedClaim;

/// The community is a `did:key` too, so the role credentials it signs verify
/// offline. [`the_community_is_its_key`] holds the two together.
const COMMUNITY: &str = "did:key:z6MkkckEJvRiDoUSv2KFGPFuUoNjJbWTZUvWThqshF7g1u4p";
const COMMUNITY_SEED: u8 = 0xC0;
/// A `requirementsDigest` the published criterion accepts: base58btc, at least
/// 16 characters.
const DIGEST: &str = "zQmbWqxBEKC3P8tqsKc98xmWNzrzDtRLMiMPL8wBuTGsMnR";

/// A listing request with no filters at all.
fn unfiltered_list() -> vetters::list::v0_1::Payload {
    vetters::list::v0_1::Payload::try_from(vetters::list::v0_1::Payload::builder()).unwrap()
}

/// A spoken ticket in the published form — upper-case Crockford base32.
fn code_ticket(code: &str) -> request::v0_1::Ticket {
    request::v0_1::Ticket::ShortCodeTicket(
        request::v0_1::ShortCodeTicket::try_from(
            request::v0_1::ShortCodeTicket::builder().code(code),
        )
        .expect("a Crockford code"),
    )
}

/// A credential-issue's credential, verified as the dispatcher's off-loop job
/// verifies it; `None` for any other message.
async fn verified_delivery(
    message: &Message,
    sender: &str,
    resolver: &affinidi_did_resolver_cache_sdk::DIDCacheClient,
) -> Option<
    Result<
        crate::issued_credential::VerifiedIssuedCredential,
        crate::issued_credential::IssuedCredentialError,
    >,
> {
    if message.typ != vta_sdk::protocols::credential_exchange::ISSUE {
        return None;
    }
    crate::messaging::credential_in_issue(message)?;
    Some(
        crate::issued_credential::verify_issued_delivery(
            &message.body,
            sender,
            resolver,
            Utc::now(),
        )
        .await,
    )
}

/// A DID resolver. Every DID here is a `did:key`, which resolves locally.
async fn did_resolver() -> affinidi_did_resolver_cache_sdk::DIDCacheClient {
    affinidi_did_resolver_cache_sdk::DIDCacheClient::new(
        affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
    )
    .await
    .expect("a DID resolver")
}

#[test]
fn the_community_is_its_key() {
    assert_eq!(did(&secret(COMMUNITY_SEED)), COMMUNITY);
}

/// A community role credential, signed by `issuer`.
async fn role_credential(issuer: &Secret, community: &str, subject: &str, role: &str) -> Value {
    let now = Utc::now();
    let mut credential = DTGCredential::new_vec(
        did(issuer),
        subject.to_string(),
        now - chrono::Duration::minutes(1),
        Some(now + chrono::Duration::days(365)),
        json!({
            "type": COMMUNITY_ROLE_ENDORSEMENT_TYPE,
            "role": role,
            "communityDid": community,
        }),
    )
    .with_id(wire::new_id());
    credential.sign(issuer, None).await.unwrap();
    serde_json::to_value(&credential).unwrap()
}

/// `credential-exchange/issue` from `from`, as a community delivers.
/// `credential-exchange/issue` as a community pushes it: a Trust Task document
/// signed by `issuer` under `authentication`.
async fn delivery(credential: &Value, issuer: &Secret) -> Message {
    let document: TrustTask<Value> = serde_json::from_value(json!({
        "id": format!("urn:uuid:{}", wire::new_id()),
        "type": vta_sdk::protocols::credential_exchange::ISSUE,
        "issuer": did(issuer),
        "recipient": "did:key:zTheMember",
        "issuedAt": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": { "credential_response": { "credential": credential } },
    }))
    .expect("an issue document");
    signed(document, issuer).await
}

/// Sign a reply the way `wire::send_reply` does: presentation first.
async fn signed_reply(reply: Reply, signer: &Secret) -> Message {
    let mut document = reply.document;
    if let Some(eligibility) = reply.eligibility {
        wire::attach_eligibility(&mut document, signer, eligibility)
            .await
            .unwrap();
    }
    signed(document, signer).await
}

struct Party {
    secret: Secret,
    did: String,
    persona: PersonaId,
    book: VettingBook,
    account: Account,
    seen: crate::operational::SeenDocuments,
}

impl Party {
    fn new(seed: u8) -> Self {
        let secret = secret(seed);
        Self {
            did: did(&secret),
            secret,
            persona: PersonaId::new(),
            book: VettingBook::default(),
            account: Account::default(),
            seen: crate::operational::SeenDocuments::default(),
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

    /// The community names this party a vetter, and delivers the credential.
    async fn named_vetter(&mut self) {
        let credential = role_credential(
            &secret(COMMUNITY_SEED),
            COMMUNITY,
            &self.did.clone(),
            VETTER_ROLE,
        )
        .await;
        let handled = self
            .receive(
                &delivery(&credential, &secret(COMMUNITY_SEED)).await,
                COMMUNITY,
            )
            .await;
        assert!(matches!(handled.notice, Some(Notice::VetterGranted { .. })));
    }

    async fn receive(&mut self, message: &Message, sender: &str) -> Handled {
        let resolver = TrustTaskVmResolver::did_key_only();
        let did_resolver = did_resolver().await;
        // As the dispatcher does off the loop: a delivered credential is
        // verified before the handler sees it.
        let issued = verified_delivery(message, sender, &did_resolver).await;
        let ctx = Context {
            account: &self.account,
            resolver: &resolver,
            did_resolver: &did_resolver,
            issued_credential: issued.as_ref(),
            community_answer: None,
            recipient: Some((self.persona, &self.did)),
            now: Utc::now(),
        };
        handle(&mut self.book, &ctx, &mut self.seen, message, sender)
            .await
            .expect("a vetting message is claimed")
    }

    /// [`Self::receive`], with the community answer already checked off the
    /// loop, as the dispatcher passes it.
    async fn receive_checked(
        &mut self,
        message: &Message,
        sender: &str,
        answer: &Result<
            crate::operational::VerifiedOperational,
            crate::operational::OperationalError,
        >,
    ) -> Handled {
        let resolver = TrustTaskVmResolver::did_key_only();
        let did_resolver = did_resolver().await;
        let ctx = Context {
            account: &self.account,
            resolver: &resolver,
            did_resolver: &did_resolver,
            issued_credential: None,
            community_answer: Some(answer),
            recipient: Some((self.persona, &self.did)),
            now: Utc::now(),
        };
        handle(&mut self.book, &ctx, &mut self.seen, message, sender)
            .await
            .expect("a vetting message is claimed")
    }

    fn application(&mut self) -> &mut super::applicant::Application {
        self.book
            .application_mut(COMMUNITY, self.persona)
            .expect("application started")
    }
}

async fn signed(mut document: TrustTask<Value>, signer: &Secret) -> Message {
    wire::sign(&mut document, signer).await.unwrap();
    wire::to_message(&document).unwrap()
}

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
    .unwrap()
}

/// The community's manifest 0.2 body.
fn manifest_body() -> manifest::v0_2::Response {
    manifest_with(Some(requirements()), None)
}

/// A manifest 0.2 body carrying `vetting` and `branding`.
fn manifest_with(
    vetting: Option<VettingRequirements>,
    branding: Option<manifest::v0_2::CommunityBranding>,
) -> manifest::v0_2::Response {
    let criterion = manifest::v0_2::Criterion::try_from(
        manifest::v0_2::Criterion::builder()
            .id("vetted")
            .presentation_definition(serde_json::Map::new())
            .vetting(vetting)
            .requirements_digest(Some(
                manifest::v0_2::DigestMultibase::try_from(DIGEST).unwrap(),
            )),
    )
    .unwrap();
    manifest::v0_2::Response::try_from(
        manifest::v0_2::Response::builder()
            .community_did(COMMUNITY)
            .criteria(vec![criterion])
            .branding(branding),
    )
    .unwrap()
}

/// The community's manifest answer to `to`, as a VTC sends an operational
/// document: signed with its authentication key, addressed, dated.
async fn manifest_reply(to: &str) -> Message {
    signed_manifest(to, manifest_body()).await
}

/// `body` as the community's signed manifest answer to `to`.
async fn signed_manifest(to: &str, body: impl serde::Serialize) -> Message {
    let document = crate::operational::test_support::sign(
        json!({
            "id": wire::new_id(),
            "type": JOIN_REQUEST_MANIFEST_0_2_RESPONSE_TYPE,
            "issuer": COMMUNITY,
            "recipient": to,
            "issuedAt": Utc::now().to_rfc3339(),
            "payload": body,
        }),
        &secret(COMMUNITY_SEED),
    )
    .await;
    Message::build(
        wire::new_id(),
        JOIN_REQUEST_MANIFEST_0_2_RESPONSE_TYPE.to_string(),
        document,
    )
    .from(COMMUNITY.to_string())
    .thid(wire::new_id())
    .finalize()
}

/// An applicant with requirements in hand, and a vetter with a ticket for them.
async fn ready() -> (Party, Party, request::v0_1::Ticket) {
    let mut applicant = Party::new(1);
    let mut vetter = Party::new(2).member_of(COMMUNITY);
    vetter.named_vetter().await;
    let now = Utc::now();
    applicant
        .book
        .start_application(COMMUNITY, applicant.persona, &applicant.did, now)
        .unwrap();
    let handled = applicant
        .receive(&manifest_reply(&applicant.did.clone()).await, COMMUNITY)
        .await;
    assert!(matches!(
        handled.notice,
        Some(Notice::RequirementsUpdated { .. })
    ));
    let ticket = Ticket::issue(COMMUNITY, vetter.persona, vec![], 1, DEFAULT_VALIDITY, now);
    let presented = ticket.code_presentation().unwrap();
    vetter.book.tickets.push(ticket);
    (applicant, vetter, presented)
}

async fn request(applicant: &mut Party, vetter: &Party, ticket: request::v0_1::Ticket) -> Message {
    let id = wire::new_id();
    let vetter_did = vetter.did.clone();
    let body = applicant
        .application()
        .prepare_request(
            &id,
            &vetter_did,
            ticket,
            RequestDraft::default(),
            Utc::now(),
        )
        .unwrap();
    let doc = wire::document(VETTING_REQUEST_TYPE, &applicant.did, &vetter.did, id, &body).unwrap();
    signed(doc, &applicant.secret).await
}

/// Request, accept and open a session. Returns the vetter's request id and the
/// session document.
async fn in_session(applicant: &mut Party, vetter: &mut Party) -> (String, TrustTask<Value>) {
    let ticket = vetter.book.tickets[0].code_presentation().unwrap();
    let message = request(applicant, vetter, ticket).await;
    let handled = vetter.receive(&message, &applicant.did).await;
    let Some(Notice::RequestAccepted { request_id, .. }) = handled.notice.clone() else {
        panic!("the request is accepted");
    };
    let reply = handled.reply.expect("an accepted request is answered");
    assert!(
        reply.eligibility.is_some(),
        "a named vetter presents the grant"
    );
    let message = signed_reply(reply, &vetter.secret).await;
    let handled = applicant.receive(&message, &vetter.did).await;
    assert!(matches!(
        handled.notice,
        Some(Notice::VetterAccepted {
            shown_eligible: true,
            ..
        })
    ));
    let accepted = applicant.application().requests.last().unwrap().clone();
    assert!(matches!(
        accepted.eligibility,
        Some(VetterEligibility::Shown { .. })
    ));

    let session_id = wire::new_id();
    let body = vetter
        .book
        .open_session(
            &request_id,
            VettingMethod::InPerson,
            vec!["name.legal".into()],
            vec![],
            &session_id,
            Utc::now(),
        )
        .unwrap();
    let doc = wire::document(
        VETTING_SESSION_TYPE,
        &vetter.did,
        &applicant.did,
        session_id,
        &body,
    )
    .unwrap();
    (request_id, doc)
}

#[tokio::test]
async fn an_applicant_is_vetted_end_to_end() {
    let (mut applicant, mut vetter, _) = ready().await;
    let resolver = TrustTaskVmResolver::did_key_only();
    let (request_id, session_doc) = in_session(&mut applicant, &mut vetter).await;

    // The session reaches the applicant; both screens show the same code.
    let message = signed(session_doc.clone(), &vetter.secret).await;
    let handled = applicant.receive(&message, &vetter.did).await;
    let Some(Notice::SessionOpened {
        session_id,
        match_code,
        ..
    }) = handled.notice.clone()
    else {
        panic!("the session opens");
    };
    assert_eq!(
        Some(match_code.as_str()),
        vetter.book.desk_entry(&request_id).unwrap().match_code()
    );
    assert!(
        handled.notice.unwrap().task().is_some(),
        "the applicant must act"
    );

    // The applicant signs a card and sends it back.
    let draft = applicant
        .application()
        .card_draft(
            &session_id,
            vec![
                session::v0_1::VettingCardClaim::try_from(
                    session::v0_1::VettingCardClaim::builder()
                        .type_("name.legal")
                        .value(json!("Alice Example"))
                        .provenance("selfAsserted"),
                )
                .unwrap(),
            ],
            Utc::now(),
        )
        .unwrap();
    let card = sign_card(draft, &applicant.secret).await.unwrap();
    applicant
        .application()
        .record_card(&session_id, &card, &resolver, Utc::now())
        .await
        .unwrap();
    // The card travels as it was signed: its digest is what the statement names.
    let doc = wire::response(&session_doc, &json!({ "card": card })).unwrap();
    let message = signed(doc, &applicant.secret).await;
    let handled = vetter.receive(&message, &applicant.did).await;
    assert!(matches!(handled.notice, Some(Notice::CardReceived { .. })));

    // The vetter checks the person and attests.
    let draft = vetter
        .book
        .statement_draft(
            &request_id,
            &vetter.did,
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
        .unwrap();
    let statement = sign_statement(draft, &vetter.secret).await.unwrap();
    let issued = vetter
        .book
        .record_statement(&request_id, &statement, &resolver, Utc::now())
        .await
        .unwrap();
    assert!(matches!(
        vetter.book.desk_entry(&request_id).unwrap().state,
        DeskState::Attested { .. }
    ));

    // The statement reaches the applicant, who now meets the requirements.
    let message = wire::credential_delivery(
        &vetter.did,
        &applicant.did,
        &statement,
        &session_id,
        &vetter.secret,
    )
    .await
    .unwrap();
    let handled = applicant.receive(&message, &vetter.did).await;
    assert!(matches!(
        handled.notice,
        Some(Notice::StatementReceived { .. })
    ));
    let application = applicant.application();
    assert!(application.checklist(Utc::now()).unwrap().satisfied());
    assert_eq!(application.presentable_statements(Utc::now()).len(), 1);
    assert_eq!(application.join_extensions()["requirementsDigest"], DIGEST);

    // Later, the vetter withdraws it.
    let notice_id = wire::new_id();
    let (body, _) = vetter
        .book
        .withdrawal(
            &issued.id,
            Some(revoke_statement::v0_1::PayloadReason::Mistake),
            &notice_id,
            Utc::now(),
        )
        .unwrap();
    assert_eq!(
        body.statement_digest_multibase.as_str(),
        issued.digest_multibase
    );
    assert!(
        vetter
            .book
            .on_withdrawal_recorded(COMMUNITY, &notice_id, Utc::now())
            .is_some()
    );
}

/// What the face released, as the disclosure reports it.
fn released(name: Option<&str>) -> Vec<ReleasedClaim> {
    vec![
        ReleasedClaim {
            claim_type: "name.legal".into(),
            value: name.map(|n| json!(n)),
            provenance: Some("selfAsserted".into()),
            stale: false,
        },
        ReleasedClaim {
            claim_type: "email.work".into(),
            value: Some(json!("alice@example.com")),
            provenance: Some("selfAsserted".into()),
            stale: false,
        },
    ]
}

/// A card's identity comes from the persona's face, and every later card has
/// to show what the first one did.
#[tokio::test]
async fn cards_come_from_the_face_and_keep_showing_the_same_identity() {
    let (mut applicant, mut vetter, _) = ready().await;
    let resolver = TrustTaskVmResolver::did_key_only();
    let (_, session_doc) = in_session(&mut applicant, &mut vetter).await;
    let message = signed(session_doc, &vetter.secret).await;
    let handled = applicant.receive(&message, &vetter.did).await;
    let Some(Notice::SessionOpened { session_id, .. }) = handled.notice else {
        panic!("the session opens");
    };
    let signer = applicant.secret.clone();
    let app = applicant.application();
    assert_eq!(app.requested_claims(&session_id), vec!["name.legal"]);

    // Only the session's claim types go on the card, and each needs a value a
    // vetter can read.
    let claims = app
        .card_claims(&session_id, &released(Some("Alice Example")))
        .unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].value, json!("Alice Example"));
    assert!(matches!(
        app.card_claims(&session_id, &released(None)),
        Err(ApplicantError::ValueWithheld(t)) if t == "name.legal"
    ));
    assert!(matches!(
        app.card_claims(&session_id, &[]),
        Err(ApplicantError::MissingClaim(_))
    ));

    let draft = app
        .card_draft(&session_id, claims.clone(), Utc::now())
        .unwrap();
    let card = sign_card(draft, &signer).await.unwrap();
    let sent = app
        .record_card(&session_id, &card, &resolver, Utc::now())
        .await
        .unwrap();
    app.record_sent_card(&session_id, sent, &claims, Utc::now())
        .unwrap();
    // The generated card claim has no `PartialEq`; what was kept is compared as
    // what it serialises to.
    assert_eq!(
        serde_json::to_value(&app.identity_claims).unwrap(),
        serde_json::to_value(&claims).unwrap()
    );

    // The face has changed since: the next card is refused before it is signed.
    assert!(matches!(
        app.card_claims(&session_id, &released(Some("Alicia Example"))),
        Err(ApplicantError::IdentityChanged(t)) if t == "name.legal"
    ));
}

#[tokio::test]
async fn without_a_ticket_there_is_no_answer_at_all() {
    let (mut applicant, mut vetter, _) = ready().await;
    let message = request(&mut applicant, &vetter, code_ticket("0000-0000")).await;
    let handled = vetter.receive(&message, &applicant.did).await;
    assert!(handled.reply.is_none() && handled.notice.is_none());
    assert!(vetter.book.desk.is_empty());
}

#[tokio::test]
async fn a_bad_scanned_ticket_is_refused_and_the_applicant_hears_why() {
    let (mut applicant, mut vetter, _) = ready().await;
    let ticket_id = vetter.book.tickets[0].id.clone();
    let scanned = request::v0_1::Ticket::QrTicket(
        request::v0_1::QrTicket::try_from(
            request::v0_1::QrTicket::builder()
                .ticket_id(ticket_id)
                .secret("A".repeat(43)),
        )
        .unwrap(),
    );
    let message = request(&mut applicant, &vetter, scanned).await;
    let handled = vetter.receive(&message, &applicant.did).await;
    let reply = handled.reply.expect("a scanned ticket is answered");
    assert_eq!(
        reply.document.payload["code"],
        VETTING_REQUEST_ERR_INVALID_TICKET
    );
    // The vetter hears about it too. A refusal used to leave nothing at all on
    // their side, so the one person who can issue a fresh ticket saw an empty
    // desk and no way to find out that anybody had tried.
    let Some(Notice::RequestRefused {
        applicant: who,
        code,
    }) = handled.notice
    else {
        panic!("the vetter is told a request was turned away");
    };
    assert_eq!(who, applicant.did);
    assert_eq!(code, VETTING_REQUEST_ERR_INVALID_TICKET);

    let message = signed(reply.document, &vetter.secret).await;
    let handled = applicant.receive(&message, &vetter.did).await;
    let refused = handled.notice.expect("the applicant is told");
    assert!(matches!(refused, Notice::VetterRefused { .. }));
    // In words, not just the wire code: "vetting/request:invalidTicket" under
    // a vetter's name reads as a fault in the software rather than as a ticket
    // that needs replacing.
    let said = refused.describe();
    assert!(said.contains(VETTING_REQUEST_ERR_INVALID_TICKET), "{said}");
    assert!(said.contains("Ask them for a fresh one"), "{said}");
    assert!(matches!(
        applicant.application().requests[0].state,
        RequestState::Refused { .. }
    ));
}

#[tokio::test]
async fn someone_who_is_not_a_member_cannot_vet() {
    let (mut applicant, _, _) = ready().await;
    let mut outsider = Party::new(3);
    let ticket = Ticket::issue(
        COMMUNITY,
        outsider.persona,
        vec![],
        1,
        DEFAULT_VALIDITY,
        Utc::now(),
    );
    let presented = ticket.code_presentation().unwrap();
    outsider.book.tickets.push(ticket);
    let message = request(&mut applicant, &outsider, presented).await;
    let handled = outsider.receive(&message, &applicant.did).await;
    assert_eq!(
        handled.reply.unwrap().document.payload["code"],
        VETTING_REQUEST_ERR_NOT_ELIGIBLE
    );
}

/// A vetter grant is taken only from the community's signed delivery. The
/// same grant, correctly signed by the community, in a bare `issue` body —
/// the shape a VTC sent before every `issue` was a document — makes nobody a
/// vetter.
#[tokio::test]
async fn a_bare_vetter_grant_delivery_is_refused() {
    let mut member = Party::new(6).member_of(COMMUNITY);
    let credential = role_credential(
        &secret(COMMUNITY_SEED),
        COMMUNITY,
        &member.did.clone(),
        VETTER_ROLE,
    )
    .await;
    let bare = Message::build(
        wire::new_id(),
        vta_sdk::protocols::credential_exchange::ISSUE.to_string(),
        json!({ "credential_response": { "credential": credential } }),
    )
    .from(COMMUNITY.to_string())
    .finalize();
    let resolver = TrustTaskVmResolver::did_key_only();
    let did_resolver = did_resolver().await;
    let ctx = Context {
        account: &member.account,
        resolver: &resolver,
        did_resolver: &did_resolver,
        issued_credential: None,
        community_answer: None,
        recipient: Some((member.persona, &member.did)),
        now: Utc::now(),
    };
    let handled = handle(
        &mut member.book,
        &ctx,
        &mut crate::operational::SeenDocuments::default(),
        &bare,
        COMMUNITY,
    )
    .await;
    assert!(
        handled.is_none_or(|h| h.notice.is_none()),
        "a bare delivery grants nothing"
    );
    assert!(member.book.vetter_grants.is_empty());
}

/// And a signed delivery by anyone but the community is refused before the
/// grant inside is looked at, even when the grant itself is the community's.
#[tokio::test]
async fn a_vetter_grant_relayed_by_another_party_is_refused() {
    let mut member = Party::new(7).member_of(COMMUNITY);
    let credential = role_credential(
        &secret(COMMUNITY_SEED),
        COMMUNITY,
        &member.did.clone(),
        VETTER_ROLE,
    )
    .await;
    let relay = secret(0xD7);
    let handled = member
        .receive(&delivery(&credential, &relay).await, &did(&relay))
        .await;
    assert!(handled.notice.is_none() && member.book.vetter_grants.is_empty());
}

/// Membership is not enough: the community has to have named the member a
/// vetter, or requests are refused before anything is recorded.
#[tokio::test]
async fn a_member_the_community_has_not_named_cannot_vet() {
    let (mut applicant, _, _) = ready().await;
    let mut member = Party::new(4).member_of(COMMUNITY);
    let ticket = Ticket::issue(
        COMMUNITY,
        member.persona,
        vec![],
        1,
        DEFAULT_VALIDITY,
        Utc::now(),
    );
    let presented = ticket.code_presentation().unwrap();
    member.book.tickets.push(ticket);
    let message = request(&mut applicant, &member, presented).await;
    let handled = member.receive(&message, &applicant.did).await;
    assert_eq!(
        handled.reply.unwrap().document.payload["code"],
        VETTING_REQUEST_ERR_NOT_ELIGIBLE
    );
    assert!(member.book.desk.is_empty());
}

/// Only the community a grant names can deliver it, and only to the persona
/// it names. A member's ordinary role credential is left for the join handler,
/// so it keeps its place.
#[tokio::test]
async fn a_vetter_grant_is_kept_only_from_its_community() {
    let mut member = Party::new(5).member_of(COMMUNITY);
    let impostor = secret(0xC1);
    let forged = role_credential(&impostor, COMMUNITY, &member.did.clone(), VETTER_ROLE).await;
    let handled = member
        .receive(&delivery(&forged, &impostor).await, &did(&impostor))
        .await;
    assert!(handled.notice.is_none() && member.book.vetter_grants.is_empty());

    let for_someone_else = role_credential(
        &secret(COMMUNITY_SEED),
        COMMUNITY,
        "did:key:zSomeoneElse",
        VETTER_ROLE,
    )
    .await;
    let handled = member
        .receive(
            &delivery(&for_someone_else, &secret(COMMUNITY_SEED)).await,
            COMMUNITY,
        )
        .await;
    assert!(handled.notice.is_none() && member.book.vetter_grants.is_empty());

    let ordinary = role_credential(
        &secret(COMMUNITY_SEED),
        COMMUNITY,
        &member.did.clone(),
        "member",
    )
    .await;
    let resolver = TrustTaskVmResolver::did_key_only();
    let did_resolver = did_resolver().await;
    let issued: Option<
        Result<
            crate::issued_credential::VerifiedIssuedCredential,
            crate::issued_credential::IssuedCredentialError,
        >,
    > = None;
    let ctx = Context {
        account: &member.account,
        resolver: &resolver,
        did_resolver: &did_resolver,
        issued_credential: issued.as_ref(),
        community_answer: None,
        recipient: Some((member.persona, &member.did)),
        now: Utc::now(),
    };
    assert!(
        handle(
            &mut member.book,
            &ctx,
            &mut crate::operational::SeenDocuments::default(),
            &delivery(&ordinary, &secret(COMMUNITY_SEED)).await,
            COMMUNITY
        )
        .await
        .is_none(),
        "an ordinary role credential is not vetting's"
    );

    member.named_vetter().await;
    assert!(
        member
            .book
            .vetter_grant(COMMUNITY, member.persona, Utc::now())
            .is_some()
    );
}

/// An acceptance that shows nothing is still an acceptance — the check is
/// advisory — but the applicant is told.
#[tokio::test]
async fn an_acceptance_without_a_grant_shown_is_recorded_as_such() {
    let (mut applicant, mut vetter, ticket) = ready().await;
    let message = request(&mut applicant, &vetter, ticket).await;
    let handled = vetter.receive(&message, &applicant.did).await;
    let mut reply = handled.reply.unwrap();
    reply.eligibility = None;
    let message = signed_reply(reply, &vetter.secret).await;
    let handled = applicant.receive(&message, &vetter.did).await;
    assert!(matches!(
        handled.notice,
        Some(Notice::VetterAccepted {
            shown_eligible: false,
            ..
        })
    ));
    assert_eq!(
        applicant.application().requests[0].eligibility,
        Some(VetterEligibility::NotShown)
    );
}

#[tokio::test]
async fn a_vetter_can_decline_without_a_reason() {
    let (mut applicant, mut vetter, _) = ready().await;
    let (request_id, _) = in_session(&mut applicant, &mut vetter).await;
    let body = vetter
        .book
        .decline(
            &request_id,
            Some(decline::v0_1::PayloadCode::NotComfortable),
            None,
            Utc::now(),
        )
        .unwrap();
    let doc = wire::document(
        VETTING_DECLINE_TYPE,
        &vetter.did,
        &applicant.did,
        wire::new_id(),
        &body,
    )
    .unwrap();
    let message = signed(doc, &vetter.secret).await;
    let handled = applicant.receive(&message, &vetter.did).await;
    assert!(matches!(handled.notice, Some(Notice::Declined { .. })));
    assert!(applicant.application().checklist(Utc::now()).is_some());
}

#[tokio::test]
async fn a_membership_credential_is_left_for_the_join_handler() {
    let mut applicant = Party::new(1);
    let vmc = json!({ "credential_response": { "credential": {
        "type": ["VerifiableCredential", "MembershipCredential"],
        "issuer": COMMUNITY
    } } });
    let message = Message::build(
        wire::new_id(),
        vta_sdk::protocols::credential_exchange::ISSUE.to_string(),
        vmc,
    )
    .from(COMMUNITY.to_string())
    .finalize();
    let resolver = TrustTaskVmResolver::did_key_only();
    let did_resolver = did_resolver().await;
    let issued: Option<
        Result<
            crate::issued_credential::VerifiedIssuedCredential,
            crate::issued_credential::IssuedCredentialError,
        >,
    > = None;
    let ctx = Context {
        account: &applicant.account,
        resolver: &resolver,
        did_resolver: &did_resolver,
        issued_credential: issued.as_ref(),
        community_answer: None,
        recipient: Some((applicant.persona, &applicant.did)),
        now: Utc::now(),
    };
    assert!(
        handle(
            &mut applicant.book,
            &ctx,
            &mut crate::operational::SeenDocuments::default(),
            &message,
            COMMUNITY
        )
        .await
        .is_none()
    );
}

#[tokio::test]
async fn a_vetter_asks_for_the_claims_the_community_requires() {
    let mut vetter = Party::new(2).member_of(COMMUNITY);
    assert_eq!(
        vetter.book.required_claims_for(COMMUNITY, None),
        (vec!["name.legal".to_string()], false),
        "without the manifest, the fallback — and it says so"
    );
    let handled = vetter
        .receive(&manifest_reply(&vetter.did.clone()).await, COMMUNITY)
        .await;
    assert!(handled.changed, "the criteria are remembered");
    let (claims, known) = vetter.book.required_claims_for(COMMUNITY, Some(DIGEST));
    assert!(known);
    assert_eq!(
        claims,
        requirements()
            .required_claims
            .iter()
            .flatten()
            .map(|c| c.as_str().to_string())
            .collect::<Vec<_>>()
    );
    assert!(
        !vetter
            .receive(&manifest_reply(&vetter.did.clone()).await, COMMUNITY)
            .await
            .changed,
        "the same manifest again changes nothing"
    );
}

#[tokio::test]
async fn the_communitys_decision_sla_is_known_once_its_manifest_is() {
    let (applicant, _, _) = ready().await;
    let persona = applicant.persona;
    assert_eq!(applicant.book.decision_sla(COMMUNITY, persona), None);

    let mut with_sla = Party::new(4);
    with_sla
        .book
        .start_application(COMMUNITY, with_sla.persona, &with_sla.did, Utc::now())
        .unwrap();
    let mut requirements = requirements();
    requirements.decision_sla = Some("P21D".try_into().unwrap());
    let body = manifest_with(Some(requirements), None);
    let reply = signed_manifest(&with_sla.did.clone(), body).await;
    with_sla.receive(&reply, COMMUNITY).await;
    assert_eq!(
        with_sla.book.decision_sla(COMMUNITY, with_sla.persona),
        chrono::Duration::try_days(21)
    );
}

// ----------------------------------------------------------------------------
// Questions put to the community: the vetter registry, resends, the manifest
// ----------------------------------------------------------------------------

/// The community's answer to `request`, as its dispatcher sends it: unsigned
/// (transport authenticates it) and threaded on the request.
/// The community answering `request`, signed as a VTC signs its success
/// responses.
async fn community_answer<P: serde::Serialize>(request: &TrustTask<Value>, payload: &P) -> Message {
    let document = wire::response(request, payload).unwrap();
    let mut message = wire::to_message(&document).unwrap();
    message.body = crate::operational::test_support::sign(
        serde_json::to_value(&document).unwrap(),
        &secret(COMMUNITY_SEED),
    )
    .await;
    message
}

/// The community refusing `request` with `code`.
fn community_refusal(request: &TrustTask<Value>, code: &str) -> Message {
    wire::to_message(&wire::refusal(request, code, Some("because")).unwrap()).unwrap()
}

fn asked(request: &TrustTask<Value>, persona: PersonaId, kind: QueryKind) -> CommunityQuery {
    CommunityQuery {
        document_id: request.id.clone(),
        community: COMMUNITY.into(),
        persona,
        kind,
        sent_at: Utc::now(),
    }
}

fn listed_vetter() -> vetters::list::v0_1::ListedVetter {
    serde_json::from_value(json!({
        "vetterDid": "did:key:zCarol",
        "displayName": "Carol",
        "languages": ["en", "cs"],
        "location": { "country": "CZ", "city": "Prague" },
        "methods": ["inPerson", "video"],
        "acceptsDocumentation": ["passport"],
        "contactHint": "find me at the LPC vetting desk",
        "events": [{ "name": "LPC", "startDate": "2026-10-05", "endDate": "2026-10-07" }],
        "grantValidUntil": "2027-09-01T00:00:00Z",
        "updatedAt": "2026-09-01T00:00:00Z"
    }))
    .unwrap()
}

#[tokio::test]
async fn a_vetter_publishes_a_profile_and_hears_the_communitys_answer() {
    let mut vetter = Party::new(2).member_of(COMMUNITY);
    vetter.named_vetter().await;
    let now = Utc::now();
    let mut draft = ProfileDraft::new(&VetterPolicy::default());
    draft.listed = true;
    draft.languages = "en, cs".into();
    let body = draft.to_body().unwrap();

    // What the community receives is signed by the vetter, with the
    // authentication key and proofPurpose (trust-tasks 0.23: `proof`
    // REQUIRED, and this is the vetter acting on their own standing, not a
    // claim to be held to later — the same purpose a personhood challenge or
    // assertion is signed with), and opens as a profile.
    let mut request = wire::vetter_profile_request(&vetter.did, COMMUNITY, &body).unwrap();
    wire::sign(&mut request, &vetter.secret).await.unwrap();
    assert_eq!(
        request.proof.as_ref().unwrap().proof_purpose,
        "authentication"
    );
    // It travels in the binding envelope; the community takes that off first.
    let sent = wire::to_message(&request).unwrap();
    assert_eq!(sent.typ, crate::capabilities::TRUST_TASK_ENVELOPE_TYPE);
    let opened: wire::Opened<vetters::profile::v0_1::Payload> = wire::open(
        &crate::didcomm::open_didcomm_envelope(&sent).unwrap(),
        &vetter.did,
        &TrustTaskVmResolver::did_key_only(),
    )
    .await
    .unwrap();
    // The generated payload has no `PartialEq`; what was sent is compared as
    // what it serialises to.
    assert_eq!(
        serde_json::to_value(&opened.payload).unwrap(),
        serde_json::to_value(&body).unwrap()
    );

    vetter
        .book
        .record_profile_sent(COMMUNITY, vetter.persona, &body, now);
    vetter
        .book
        .ask(asked(&request, vetter.persona, QueryKind::VetterProfile));
    let stored = vetters::profile::v0_1::Response::try_from(
        vetters::profile::v0_1::Response::builder()
            .listed(true)
            .updated_at(now),
    )
    .unwrap();
    let handled = vetter
        .receive(&community_answer(&request, &stored).await, COMMUNITY)
        .await;
    assert!(handled.changed, "the stored state is kept");
    assert!(matches!(
        handled.notice,
        Some(Notice::ProfilePublished { listed: true, .. })
    ));
    assert!(matches!(
        handled.answer,
        Some(CommunityAnswer::ProfileStored { listed: true, .. })
    ));
    assert!(matches!(
        vetter
            .book
            .vetter_profile(COMMUNITY, vetter.persona)
            .unwrap()
            .state,
        ProfileState::Stored { listed: true, .. }
    ));

    // Published again, and refused: the community no longer counts the grant.
    let request = wire::vetter_profile_request(&vetter.did, COMMUNITY, &body).unwrap();
    vetter
        .book
        .record_profile_sent(COMMUNITY, vetter.persona, &body, now);
    vetter
        .book
        .ask(asked(&request, vetter.persona, QueryKind::VetterProfile));
    let handled = vetter
        .receive(
            &community_refusal(&request, VETTING_VETTER_PROFILE_ERR_NOT_ELIGIBLE),
            COMMUNITY,
        )
        .await;
    assert!(matches!(
        &handled.answer,
        Some(CommunityAnswer::Refused { kind: QueryKind::VetterProfile, code, .. })
            if code == VETTING_VETTER_PROFILE_ERR_NOT_ELIGIBLE
    ));
    let notice = handled.notice.expect("a refusal is explained");
    assert!(notice.describe().contains("live vetter credential"));
    assert!(matches!(
        vetter
            .book
            .vetter_profile(COMMUNITY, vetter.persona)
            .unwrap()
            .state,
        ProfileState::Refused { .. }
    ));
}

#[tokio::test]
async fn the_directory_answers_only_what_was_asked() {
    let mut applicant = Party::new(1);
    let page = vetters::list::v0_1::Response::try_from(
        vetters::list::v0_1::Response::builder()
            .vetters(vec![listed_vetter()])
            .next_cursor(Some(
                vetters::list::v0_1::ResponseNextCursor::try_from("page-2").unwrap(),
            )),
    )
    .unwrap();
    let request = wire::vetter_list_request(&applicant.did, COMMUNITY, &unfiltered_list()).unwrap();

    // Nobody asked: the page answers nothing.
    let handled = applicant
        .receive(&community_answer(&request, &page).await, COMMUNITY)
        .await;
    assert!(handled.answer.is_none());

    applicant
        .book
        .ask(asked(&request, applicant.persona, QueryKind::VetterList));
    // Another community cannot answer our question.
    let handled = applicant
        .receive(
            &community_answer(&request, &page).await,
            "did:key:zElsewhere",
        )
        .await;
    assert!(handled.answer.is_none());

    let handled = applicant
        .receive(&community_answer(&request, &page).await, COMMUNITY)
        .await;
    let Some(CommunityAnswer::Vetters {
        query, page: got, ..
    }) = handled.answer
    else {
        panic!("the page is handed to whoever asked");
    };
    assert_eq!(query, request.id);
    assert_eq!(
        serde_json::to_value(&got).unwrap(),
        serde_json::to_value(&page).unwrap()
    );
    assert!(!handled.changed, "a directory page is never saved");

    // Refused: the community would not answer this caller.
    let request = wire::vetter_list_request(&applicant.did, COMMUNITY, &unfiltered_list()).unwrap();
    applicant
        .book
        .ask(asked(&request, applicant.persona, QueryKind::VetterList));
    let handled = applicant
        .receive(&community_refusal(&request, "permissionDenied"), COMMUNITY)
        .await;
    assert!(matches!(
        &handled.answer,
        Some(CommunityAnswer::Refused { kind: QueryKind::VetterList, code, .. })
            if code == "permissionDenied"
    ));

    // An error that answers nothing we asked is left for the join handler.
    let stray = wire::vetter_list_request(&applicant.did, COMMUNITY, &unfiltered_list()).unwrap();
    let resolver = TrustTaskVmResolver::did_key_only();
    let did_resolver = did_resolver().await;
    let issued: Option<
        Result<
            crate::issued_credential::VerifiedIssuedCredential,
            crate::issued_credential::IssuedCredentialError,
        >,
    > = None;
    let ctx = Context {
        account: &applicant.account,
        resolver: &resolver,
        did_resolver: &did_resolver,
        issued_credential: issued.as_ref(),
        community_answer: None,
        recipient: Some((applicant.persona, &applicant.did)),
        now: Utc::now(),
    };
    assert!(
        handle(
            &mut applicant.book,
            &ctx,
            &mut crate::operational::SeenDocuments::default(),
            &community_refusal(&stray, "permissionDenied"),
            COMMUNITY
        )
        .await
        .is_none()
    );

    // An answer this client cannot read says so, rather than timing out.
    let request = wire::vetter_list_request(&applicant.did, COMMUNITY, &unfiltered_list()).unwrap();
    applicant
        .book
        .ask(asked(&request, applicant.persona, QueryKind::VetterList));
    let handled = applicant
        .receive(
            &community_answer(&request, &json!({ "vetters": "not a list" })).await,
            COMMUNITY,
        )
        .await;
    assert!(matches!(
        handled.answer,
        Some(CommunityAnswer::Unreadable {
            kind: QueryKind::VetterList,
            ..
        })
    ));
    assert!(applicant.book.queries.is_empty());
}

/// `message` as a community that follows the DIDComm binding (§5) sends it:
/// typed as the envelope, with the same document as the body.
fn enveloped(message: &Message) -> Message {
    let mut enveloped = message.clone();
    enveloped.typ = crate::capabilities::TRUST_TASK_ENVELOPE_TYPE.to_string();
    enveloped
}

/// A community answers in the response document's own type today and in the
/// binding envelope once it follows §5 fully (the follow-up to VTI #1687). Both
/// must reach the same handler, or the switch silently drops every answer.
#[tokio::test]
async fn a_community_answer_is_read_in_either_carriage() {
    let mut applicant = Party::new(1);
    let page = vetters::list::v0_1::Response::try_from(
        vetters::list::v0_1::Response::builder().vetters(vec![listed_vetter()]),
    )
    .unwrap();
    for in_envelope in [false, true] {
        let request =
            wire::vetter_list_request(&applicant.did, COMMUNITY, &unfiltered_list()).unwrap();
        applicant
            .book
            .ask(asked(&request, applicant.persona, QueryKind::VetterList));
        let reply = community_answer(&request, &page).await;
        let reply = if in_envelope {
            crate::didcomm::open_didcomm_envelope(&enveloped(&reply))
                .expect("an enveloped document opens")
        } else {
            assert!(
                crate::didcomm::open_didcomm_envelope(&reply).is_none(),
                "a document-typed reply needs no opening"
            );
            reply
        };
        let handled = applicant.receive(&reply, COMMUNITY).await;
        assert!(
            matches!(&handled.answer, Some(CommunityAnswer::Vetters { query, .. }) if *query == request.id),
            "answered in the envelope: {in_envelope}"
        );

        // And a refusal, in the same carriage.
        let request =
            wire::vetter_list_request(&applicant.did, COMMUNITY, &unfiltered_list()).unwrap();
        applicant
            .book
            .ask(asked(&request, applicant.persona, QueryKind::VetterList));
        let refusal = community_refusal(&request, "permissionDenied");
        let refusal = if in_envelope {
            crate::didcomm::open_didcomm_envelope(&enveloped(&refusal)).unwrap()
        } else {
            refusal
        };
        let handled = applicant.receive(&refusal, COMMUNITY).await;
        assert!(matches!(
            &handled.answer,
            Some(CommunityAnswer::Refused { kind: QueryKind::VetterList, code, .. })
                if code == "permissionDenied"
        ));
    }
    assert!(applicant.book.queries.is_empty());
}

/// A community refusing at the DIDComm layer — a problem-report, as a VTC sends
/// for a Trust Task typed as its task URI (VTI #1687) — refuses the question it
/// threads on at once, instead of leaving it to time out.
#[tokio::test]
async fn a_problem_report_refuses_the_question_it_threads_on() {
    let mut applicant = Party::new(1);
    let request = wire::vetter_list_request(&applicant.did, COMMUNITY, &unfiltered_list()).unwrap();
    applicant
        .book
        .ask(asked(&request, applicant.persona, QueryKind::VetterList));
    let report = |thid: &str| {
        Message::build(
            wire::new_id(),
            vta_sdk::protocols::PROBLEM_REPORT_TYPE.to_string(),
            json!({
                "code": "e.p.msg.bad-request",
                "comment": "unsupported message type: … — Trust Tasks must be carried in the \
                            DIDComm binding envelope",
            }),
        )
        .from(COMMUNITY.to_string())
        .thid(thid.to_string())
        .finalize()
    };

    let handled = applicant.receive(&report(&request.id), COMMUNITY).await;
    let Some(CommunityAnswer::Refused {
        query,
        kind: QueryKind::VetterList,
        code,
        message,
        ..
    }) = handled.answer
    else {
        panic!("the question is refused");
    };
    assert_eq!(query, request.id);
    assert_eq!(code, "e.p.msg.bad-request");
    assert!(message.unwrap().contains("binding envelope"));
    assert!(applicant.book.queries.is_empty());

    // One threading on nothing of vetting's is left for the join handler.
    let resolver = TrustTaskVmResolver::did_key_only();
    let did_resolver = did_resolver().await;
    let issued: Option<
        Result<
            crate::issued_credential::VerifiedIssuedCredential,
            crate::issued_credential::IssuedCredentialError,
        >,
    > = None;
    let ctx = Context {
        account: &applicant.account,
        resolver: &resolver,
        did_resolver: &did_resolver,
        issued_credential: issued.as_ref(),
        community_answer: None,
        recipient: Some((applicant.persona, &applicant.did)),
        now: Utc::now(),
    };
    assert!(
        handle(
            &mut applicant.book,
            &ctx,
            &mut crate::operational::SeenDocuments::default(),
            &report("urn:uuid:not-ours"),
            COMMUNITY
        )
        .await
        .is_none()
    );
}

#[tokio::test]
async fn a_resend_is_answered_or_refused_in_plain_words() {
    let mut member = Party::new(5).member_of(COMMUNITY);
    let request = wire::vetter_resend_request(&member.did, COMMUNITY).unwrap();
    member
        .book
        .ask(asked(&request, member.persona, QueryKind::VetterResend));
    let resent = vetters::resend::v0_1::Response::try_from(
        vetters::resend::v0_1::Response::builder()
            .credential_id("urn:uuid:grant")
            .valid_until(Utc::now() + Duration::days(300)),
    )
    .unwrap();
    let handled = member
        .receive(&community_answer(&request, &resent).await, COMMUNITY)
        .await;
    assert!(matches!(
        handled.answer,
        Some(CommunityAnswer::Resent { .. })
    ));
    assert!(matches!(handled.notice, Some(Notice::GrantResent { .. })));

    let request = wire::vetter_resend_request(&member.did, COMMUNITY).unwrap();
    member
        .book
        .ask(asked(&request, member.persona, QueryKind::VetterResend));
    let handled = member
        .receive(
            &community_refusal(&request, VETTING_VETTER_RESEND_ERR_NOT_GRANTED),
            COMMUNITY,
        )
        .await;
    assert!(matches!(
        handled.answer,
        Some(CommunityAnswer::Refused {
            kind: QueryKind::VetterResend,
            ..
        })
    ));
    let notice = handled.notice.expect("a refusal is explained");
    assert!(notice.describe().contains("has not named you a vetter"));
}

#[tokio::test]
async fn a_manifest_answers_whoever_asked_and_brings_the_communitys_branding() {
    let mut applicant = Party::new(1);
    let request = wire::manifest_request(&applicant.did, COMMUNITY).unwrap();
    applicant
        .book
        .ask(asked(&request, applicant.persona, QueryKind::Manifest));
    let branding = manifest::v0_2::CommunityBranding::try_from(
        manifest::v0_2::CommunityBranding::builder()
            .display_name(Some(
                manifest::v0_2::CommunityBrandingDisplayName::try_from("Kernel Developers")
                    .unwrap(),
            ))
            .accent_color(Some(
                manifest::v0_2::CommunityBrandingAccentColor::try_from("#336699").unwrap(),
            )),
    )
    .unwrap();
    let body = manifest_with(Some(requirements()), Some(branding));
    let handled = applicant
        .receive(&community_answer(&request, &body).await, COMMUNITY)
        .await;
    assert!(matches!(
        handled.answer,
        Some(CommunityAnswer::Manifest { .. })
    ));
    assert!(matches!(
        applicant.book.knowledge(COMMUNITY),
        Knowledge::Vetting(_)
    ));
    let branding = applicant.book.branding(COMMUNITY).unwrap();
    assert_eq!(branding.display_name.as_deref(), Some("Kernel Developers"));
    assert_eq!(branding.accent_rgb(), Some((0x33, 0x66, 0x99)));
    assert!(applicant.book.queries.is_empty());
}

/// A community role credential carrying a status list entry, signed by
/// `issuer`. `DTGCredential` does not model `credentialStatus`, so the
/// credential is signed as JSON.
async fn role_credential_with_status(issuer: &Secret, subject: &str) -> Value {
    let now = Utc::now();
    let credential = DTGCredential::new_vec(
        did(issuer),
        subject.to_string(),
        now - Duration::minutes(1),
        Some(now + Duration::days(365)),
        json!({
            "type": COMMUNITY_ROLE_ENDORSEMENT_TYPE,
            "role": VETTER_ROLE,
            "communityDid": COMMUNITY,
        }),
    )
    .with_id(wire::new_id());
    let mut value = serde_json::to_value(&credential).unwrap();
    value.as_object_mut().unwrap().remove("proof");
    value["credentialStatus"] = json!({
        "id": "https://vtc.example.com/v1/status-lists/revocation#7",
        "type": "BitstringStatusListEntry",
        "statusPurpose": "revocation",
        "statusListIndex": "7",
        "statusListCredential": "https://vtc.example.com/v1/status-lists/revocation"
    });
    let proof = DataIntegrityProof::sign(
        &value,
        issuer,
        SignOptions::new().with_proof_purpose("assertionMethod"),
    )
    .await
    .unwrap();
    value["proof"] = serde_json::to_value(proof).unwrap();
    value
}

#[tokio::test]
async fn a_verified_grant_is_handed_on_for_a_revocation_check() {
    let (mut applicant, mut vetter, ticket) = ready().await;
    let credential =
        role_credential_with_status(&secret(COMMUNITY_SEED), &vetter.did.clone()).await;
    // Receiving this grant would read its status list, which fails closed
    // with no list to fetch (see `a_grant_whose_status_cannot_be_read_is_not_kept`);
    // this test is about the applicant's side, so the vetter is handed the grant.
    vetter.book.keep_vetter_grant(super::book::VetterGrant {
        community: COMMUNITY.to_string(),
        persona: vetter.persona,
        credential_id: credential["id"].as_str().map(str::to_string),
        valid_until: credential["validUntil"]
            .as_str()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&Utc)),
        received_at: Utc::now(),
        credential: credential.clone(),
    });

    let message = request(&mut applicant, &vetter, ticket).await;
    let reply = vetter
        .receive(&message, &applicant.did)
        .await
        .reply
        .expect("accepted");
    let handled = applicant
        .receive(&signed_reply(reply, &vetter.secret).await, &vetter.did)
        .await;
    let check = handled
        .grant_check
        .expect("a verified grant with a status entry is checked");
    assert_eq!(check.issuer, COMMUNITY);
    assert_eq!(check.vetter, vetter.did);
    assert_eq!(check.credential_status["statusListIndex"], "7");
    let app = applicant.application();
    assert!(matches!(
        app.requests[0].grant_status,
        Some(GrantStatus::Checking { .. })
    ));

    app.record_grant_status(
        &check.request_document_id,
        &check.vetter,
        GrantStatus::from_check(StatusCheck::Revoked, Utc::now()),
    )
    .unwrap();
    assert!(matches!(
        app.requests[0].grant_status,
        Some(GrantStatus::Revoked { .. })
    ));
}

#[tokio::test]
async fn a_grant_that_names_no_status_list_is_not_called_unrevoked() {
    let (mut applicant, mut vetter, ticket) = ready().await;
    let message = request(&mut applicant, &vetter, ticket).await;
    let reply = vetter
        .receive(&message, &applicant.did)
        .await
        .reply
        .unwrap();
    let handled = applicant
        .receive(&signed_reply(reply, &vetter.secret).await, &vetter.did)
        .await;
    assert!(handled.grant_check.is_none());
    assert!(matches!(
        applicant.application().requests[0].grant_status,
        Some(GrantStatus::Unknown { .. })
    ));
}

#[tokio::test]
async fn a_scanned_ticket_link_is_enough_to_ask_and_another_communitys_is_refused() {
    let (mut applicant, mut vetter, _) = ready().await;
    let link = vetter.book.tickets[0].uri(&vetter.did).unwrap();
    let ticket = applicant.application().ticket_from_uri(&link).unwrap();
    assert_eq!(ticket.vetter, vetter.did);
    let message = request(&mut applicant, &vetter, ticket.presentation).await;
    let handled = vetter.receive(&message, &applicant.did).await;
    assert!(matches!(
        handled.notice,
        Some(Notice::RequestAccepted { .. })
    ));

    let elsewhere = Ticket::issue(
        "did:key:zOtherCommunity",
        vetter.persona,
        vec![],
        1,
        DEFAULT_VALIDITY,
        Utc::now(),
    );
    assert!(matches!(
        applicant
            .application()
            .ticket_from_uri(&elsewhere.uri(&vetter.did).unwrap()),
        Err(TicketUriError::OtherCommunity(c)) if c == "did:key:zOtherCommunity"
    ));
    assert!(matches!(
        applicant.application().ticket_from_uri("K7QF-2M9X"),
        Err(TicketUriError::Unreadable(_))
    ));
}

#[tokio::test]
async fn the_next_step_follows_the_application() {
    let fresh = Application::new(COMMUNITY, PersonaId::new(), "did:key:zA", Utc::now()).unwrap();
    assert_eq!(fresh.next_step(Utc::now()), NextStep::LearnRequirements);

    let (mut applicant, mut vetter, _) = ready().await;
    assert_eq!(
        applicant.application().next_step(Utc::now()),
        NextStep::ChooseFace
    );
    // Choosing one advances the step. The claims are only read from the face
    // when the first card goes out, so without `face` being recorded in its own
    // right the step still said "choose a face" right after one was chosen —
    // the screen told you to do the thing you had just done.
    applicant.application().face = Some(ChosenFace {
        profile_id: "p1".into(),
        name: "Work".into(),
    });
    assert_eq!(
        applicant.application().next_step(Utc::now()),
        NextStep::AskVetter
    );
    let (_, session_doc) = in_session(&mut applicant, &mut vetter).await;
    assert_eq!(
        applicant.application().next_step(Utc::now()),
        NextStep::WaitForVetters
    );
    let message = signed(session_doc.clone(), &vetter.secret).await;
    applicant.receive(&message, &vetter.did).await;
    assert_eq!(
        applicant.application().next_step(Utc::now()),
        NextStep::SendCard {
            session_id: session_doc.id.clone()
        }
    );
}

/// A community's answer is acted on only when the community signed it: an
/// unsigned manifest, or one whose content was changed after signing, is not
/// adopted — whoever the transport says sent it.
#[tokio::test]
async fn an_unsigned_or_altered_community_answer_is_not_acted_on() {
    let mut applicant = Party::new(1);
    applicant
        .book
        .start_application(COMMUNITY, applicant.persona, &applicant.did, Utc::now())
        .unwrap();

    let unsigned = Message::build(
        wire::new_id(),
        JOIN_REQUEST_MANIFEST_0_2_RESPONSE_TYPE.to_string(),
        json!({
            "type": JOIN_REQUEST_MANIFEST_0_2_RESPONSE_TYPE,
            "issuer": COMMUNITY,
            "payload": manifest_body(),
        }),
    )
    .from(COMMUNITY.to_string())
    .finalize();
    let handled = applicant.receive(&unsigned, COMMUNITY).await;
    assert!(!handled.changed && handled.notice.is_none());

    let mut altered = manifest_reply(&applicant.did.clone()).await;
    altered.body["payload"]["tampered"] = json!(true);
    let handled = applicant.receive(&altered, COMMUNITY).await;
    assert!(!handled.changed && handled.notice.is_none());

    // Signed by the community, but arriving as another sender's answer.
    let handled = applicant
        .receive(
            &manifest_reply(&applicant.did.clone()).await,
            "did:key:zElsewhere",
        )
        .await;
    assert!(!handled.changed && handled.notice.is_none());

    // The genuine answer is adopted.
    let handled = applicant
        .receive(&manifest_reply(&applicant.did.clone()).await, COMMUNITY)
        .await;
    assert!(matches!(
        handled.notice,
        Some(Notice::RequirementsUpdated { .. })
    ));
}

/// A community answer checked off the loop is taken from that check — not
/// resolved again — and one whose check failed or never ran is refused.
#[tokio::test]
async fn a_community_answer_is_taken_from_its_off_loop_check() {
    let mut applicant = Party::new(1);
    applicant
        .book
        .start_application(COMMUNITY, applicant.persona, &applicant.did, Utc::now())
        .unwrap();
    let reply = manifest_reply(&applicant.did.clone()).await;

    let refused = Err(crate::operational::OperationalError::NotChecked);
    let handled = applicant.receive_checked(&reply, COMMUNITY, &refused).await;
    assert!(!handled.changed && handled.notice.is_none());

    let checked = crate::operational::verify_operational(
        &reply.body,
        COMMUNITY,
        &[applicant.did.as_str()],
        &reply.typ,
        &did_resolver().await,
        &applicant.seen,
        Utc::now(),
    )
    .await;
    let handled = applicant.receive_checked(&reply, COMMUNITY, &checked).await;
    assert!(matches!(
        handled.notice,
        Some(Notice::RequirementsUpdated { .. })
    ));
}

/// A vetter role credential whose proof does not verify is not kept — here, a
/// genuine grant with its role claim changed after the community signed it.
#[tokio::test]
async fn a_tampered_vetter_grant_is_not_kept() {
    let mut member = Party::new(2).member_of(COMMUNITY);
    let mut credential = role_credential(
        &secret(COMMUNITY_SEED),
        COMMUNITY,
        &member.did.clone(),
        VETTER_ROLE,
    )
    .await;
    credential["validUntil"] = json!("2999-01-01T00:00:00Z");
    let handled = member
        .receive(
            &delivery(&credential, &secret(COMMUNITY_SEED)).await,
            COMMUNITY,
        )
        .await;
    assert!(handled.notice.is_none() && member.book.vetter_grants.is_empty());
}

/// A vetter grant naming a status list that cannot be read is not kept:
/// revocation fails closed.
#[tokio::test]
async fn a_grant_whose_status_cannot_be_read_is_not_kept() {
    let mut vetter = Party::new(2).member_of(COMMUNITY);
    let credential =
        role_credential_with_status(&secret(COMMUNITY_SEED), &vetter.did.clone()).await;
    let handled = vetter
        .receive(
            &delivery(&credential, &secret(COMMUNITY_SEED)).await,
            COMMUNITY,
        )
        .await;
    assert!(handled.notice.is_none() && vetter.book.vetter_grants.is_empty());
}

/// A community answer is operational: signed with the community's
/// authentication key, not its credential key, and taken once.
#[tokio::test]
async fn a_community_answer_is_taken_once_and_only_from_the_operational_key() {
    let mut applicant = Party::new(1);
    applicant
        .book
        .start_application(COMMUNITY, applicant.persona, &applicant.did, Utc::now())
        .unwrap();
    // `did:key` lists its one key under both relationships, so an
    // assertionMethod proof is refused for its purpose.
    let asserted = crate::proof_check::test_support::sign(
        json!({
            "id": wire::new_id(),
            "type": JOIN_REQUEST_MANIFEST_0_2_RESPONSE_TYPE,
            "issuer": COMMUNITY,
            "recipient": applicant.did,
            "issuedAt": Utc::now().to_rfc3339(),
            "payload": manifest_body(),
        }),
        &[&secret(COMMUNITY_SEED)],
    )
    .await;
    let message = Message::build(
        wire::new_id(),
        JOIN_REQUEST_MANIFEST_0_2_RESPONSE_TYPE.to_string(),
        asserted,
    )
    .from(COMMUNITY.to_string())
    .finalize();
    let handled = applicant.receive(&message, COMMUNITY).await;
    assert!(handled.notice.is_none());

    let reply = manifest_reply(&applicant.did.clone()).await;
    let handled = applicant.receive(&reply, COMMUNITY).await;
    assert!(matches!(
        handled.notice,
        Some(Notice::RequirementsUpdated { .. })
    ));
    let mut again = reply.clone();
    again.id = wire::new_id();
    let handled = applicant.receive(&again, COMMUNITY).await;
    assert!(
        !handled.changed && handled.notice.is_none(),
        "a replayed answer is refused"
    );

    // Addressed to somebody else.
    let other = manifest_reply("did:key:zSomeoneElse").await;
    let handled = applicant.receive(&other, COMMUNITY).await;
    assert!(!handled.changed && handled.notice.is_none());
}

/// A signed manifest nobody asked for — no query, no application, no
/// membership — is not learned, and nothing is written to the replay set.
#[tokio::test]
async fn an_unsolicited_manifest_writes_nothing() {
    let mut stranger = Party::new(7);
    let reply = manifest_reply(&stranger.did.clone()).await;
    let handled = stranger.receive(&reply, COMMUNITY).await;
    assert!(!handled.changed && handled.notice.is_none() && handled.answer.is_none());
    assert!(stranger.seen.is_empty(), "the replay set is untouched");
    assert!(matches!(
        stranger.book.knowledge(COMMUNITY),
        Knowledge::Unknown
    ));
}
