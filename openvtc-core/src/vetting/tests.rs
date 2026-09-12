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
use vta_sdk::protocols::join_requests::{
    CommunityBranding, JOIN_REQUEST_MANIFEST_0_2_RESPONSE_TYPE, JoinRequestManifestResponseBody,
    ManifestCriterion,
};
use vta_sdk::protocols::vetting::{
    COMMUNITY_ROLE_ENDORSEMENT_TYPE, CardClaim, DeclaredRelationship, DeclineCode,
    IDENTITY_VETTING_ENDORSEMENT_TYPE, ListedVetter, RevocationReason, TicketPresentation,
    VETTER_ROLE, VETTING_DECLINE_TYPE, VETTING_REQUEST_ERR_INVALID_TICKET,
    VETTING_REQUEST_ERR_NOT_ELIGIBLE, VETTING_REQUEST_TYPE, VETTING_SESSION_TYPE,
    VETTING_VETTER_PROFILE_ERR_NOT_ELIGIBLE, VETTING_VETTER_RESEND_ERR_NOT_GRANTED, VetterListBody,
    VetterListResponseBody, VetterProfileBody, VetterProfileResponseBody, VetterResendResponseBody,
    VettingMethod, VettingRequirements, VettingSessionResponseBody,
};
use vta_sdk::trust_task_proof::TrustTaskVmResolver;
use vta_sdk::vetting::card::sign_card;
use vta_sdk::vetting::statement::sign_statement;
use vta_sdk::vetting::status::StatusCheck;

use super::VettingBook;
use super::applicant::{
    ApplicantError, Application, GrantStatus, NextStep, RequestDraft, RequestState, TicketUriError,
    VetterEligibility,
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
fn delivery(credential: &Value, from: &str) -> Message {
    Message::build(
        wire::new_id(),
        vta_sdk::protocols::credential_exchange::ISSUE.to_string(),
        json!({ "credential_response": { "credential": credential } }),
    )
    .from(from.to_string())
    .finalize()
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
            .receive(&delivery(&credential, COMMUNITY), COMMUNITY)
            .await;
        assert!(matches!(handled.notice, Some(Notice::VetterGranted { .. })));
    }

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
fn manifest_body() -> JoinRequestManifestResponseBody {
    JoinRequestManifestResponseBody {
        community_did: COMMUNITY.into(),
        criteria: vec![ManifestCriterion {
            id: "vetted".into(),
            description: None,
            presentation_definition: json!({}),
            vetting: Some(requirements()),
            requirements_digest: Some("zRequirementsDigest".into()),
        }],
        branding: None,
    }
}

/// The community's manifest 0.2 reply, as its dispatcher sends it.
fn manifest_reply() -> Message {
    let body = manifest_body();
    Message::build(
        wire::new_id(),
        JOIN_REQUEST_MANIFEST_0_2_RESPONSE_TYPE.to_string(),
        json!({ "type": JOIN_REQUEST_MANIFEST_0_2_RESPONSE_TYPE, "payload": body }),
    )
    .from(COMMUNITY.to_string())
    .thid(wire::new_id())
    .finalize()
}

/// An applicant with requirements in hand, and a vetter with a ticket for them.
async fn ready() -> (Party, Party, TicketPresentation) {
    let mut applicant = Party::new(1);
    let mut vetter = Party::new(2).member_of(COMMUNITY);
    vetter.named_vetter().await;
    let now = Utc::now();
    applicant
        .book
        .start_application(COMMUNITY, applicant.persona, &applicant.did, now)
        .unwrap();
    let handled = applicant.receive(&manifest_reply(), COMMUNITY).await;
    assert!(matches!(
        handled.notice,
        Some(Notice::RequirementsUpdated { .. })
    ));
    let ticket = Ticket::issue(COMMUNITY, vetter.persona, vec![], 1, DEFAULT_VALIDITY, now);
    let presented = ticket.code_presentation();
    vetter.book.tickets.push(ticket);
    (applicant, vetter, presented)
}

async fn request(applicant: &mut Party, vetter: &Party, ticket: TicketPresentation) -> Message {
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
    let ticket = vetter.book.tickets[0].code_presentation();
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
            vec![CardClaim {
                claim_type: "name.legal".into(),
                value: json!("Alice Example"),
                provenance: "selfAsserted".into(),
            }],
            Utc::now(),
        )
        .unwrap();
    let card = sign_card(draft, &applicant.secret).await.unwrap();
    applicant
        .application()
        .record_card(&session_id, &card, &resolver, Utc::now())
        .await
        .unwrap();
    let doc = wire::response(
        &session_doc,
        &VettingSessionResponseBody { card, ext: None },
    )
    .unwrap();
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
                declared_relationship: DeclaredRelationship::None,
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
    let message =
        wire::credential_delivery(&vetter.did, &applicant.did, &statement, &session_id).unwrap();
    let handled = applicant.receive(&message, &vetter.did).await;
    assert!(matches!(
        handled.notice,
        Some(Notice::StatementReceived { .. })
    ));
    let application = applicant.application();
    assert!(application.checklist(Utc::now()).unwrap().satisfied());
    assert_eq!(application.presentable_statements(Utc::now()).len(), 1);
    assert_eq!(
        application.join_extensions()["requirementsDigest"],
        "zRequirementsDigest"
    );

    // Later, the vetter withdraws it.
    let notice_id = wire::new_id();
    let (body, _) = vetter
        .book
        .withdrawal(
            &issued.id,
            Some(RevocationReason::Mistake),
            &notice_id,
            Utc::now(),
        )
        .unwrap();
    assert_eq!(body.statement_digest_multibase, issued.digest_multibase);
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
    assert_eq!(app.identity_claims, claims);

    // The face has changed since: the next card is refused before it is signed.
    assert!(matches!(
        app.card_claims(&session_id, &released(Some("Alicia Example"))),
        Err(ApplicantError::IdentityChanged(t)) if t == "name.legal"
    ));
}

#[tokio::test]
async fn without_a_ticket_there_is_no_answer_at_all() {
    let (mut applicant, mut vetter, _) = ready().await;
    let message = request(
        &mut applicant,
        &vetter,
        TicketPresentation::Code {
            code: "0000-0000".into(),
        },
    )
    .await;
    let handled = vetter.receive(&message, &applicant.did).await;
    assert!(handled.reply.is_none() && handled.notice.is_none());
    assert!(vetter.book.desk.is_empty());
}

#[tokio::test]
async fn a_bad_scanned_ticket_is_refused_and_the_applicant_hears_why() {
    let (mut applicant, mut vetter, _) = ready().await;
    let ticket_id = vetter.book.tickets[0].id.clone();
    let message = request(
        &mut applicant,
        &vetter,
        TicketPresentation::Scanned {
            ticket_id,
            secret: "A".repeat(43),
        },
    )
    .await;
    let handled = vetter.receive(&message, &applicant.did).await;
    let reply = handled.reply.expect("a scanned ticket is answered");
    assert_eq!(
        reply.document.payload["code"],
        VETTING_REQUEST_ERR_INVALID_TICKET
    );
    let message = signed(reply.document, &vetter.secret).await;
    let handled = applicant.receive(&message, &vetter.did).await;
    assert!(matches!(handled.notice, Some(Notice::VetterRefused { .. })));
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
    let presented = ticket.code_presentation();
    outsider.book.tickets.push(ticket);
    let message = request(&mut applicant, &outsider, presented).await;
    let handled = outsider.receive(&message, &applicant.did).await;
    assert_eq!(
        handled.reply.unwrap().document.payload["code"],
        VETTING_REQUEST_ERR_NOT_ELIGIBLE
    );
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
    let presented = ticket.code_presentation();
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
        .receive(&delivery(&forged, &did(&impostor)), &did(&impostor))
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
        .receive(&delivery(&for_someone_else, COMMUNITY), COMMUNITY)
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
    let ctx = Context {
        account: &member.account,
        resolver: &resolver,
        recipient: Some((member.persona, &member.did)),
        now: Utc::now(),
    };
    assert!(
        handle(
            &mut member.book,
            &ctx,
            &delivery(&ordinary, COMMUNITY),
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
            Some(DeclineCode::NotComfortable),
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
    let ctx = Context {
        account: &applicant.account,
        resolver: &resolver,
        recipient: Some((applicant.persona, &applicant.did)),
        now: Utc::now(),
    };
    assert!(
        handle(&mut applicant.book, &ctx, &message, COMMUNITY)
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
    let handled = vetter.receive(&manifest_reply(), COMMUNITY).await;
    assert!(handled.changed, "the criteria are remembered");
    let (claims, known) = vetter
        .book
        .required_claims_for(COMMUNITY, Some("zRequirementsDigest"));
    assert!(known);
    assert_eq!(claims, requirements().required_claims);
    assert!(
        !vetter.receive(&manifest_reply(), COMMUNITY).await.changed,
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
    requirements.decision_sla = Some("P21D".into());
    let body = JoinRequestManifestResponseBody {
        community_did: COMMUNITY.into(),
        criteria: vec![ManifestCriterion {
            id: "vetted".into(),
            description: None,
            presentation_definition: json!({}),
            vetting: Some(requirements),
            requirements_digest: Some("zOther".into()),
        }],
        branding: None,
    };
    let reply = Message::build(
        wire::new_id(),
        JOIN_REQUEST_MANIFEST_0_2_RESPONSE_TYPE.to_string(),
        json!({ "type": JOIN_REQUEST_MANIFEST_0_2_RESPONSE_TYPE, "payload": body }),
    )
    .from(COMMUNITY.to_string())
    .finalize();
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
fn community_answer<P: serde::Serialize>(request: &TrustTask<Value>, payload: &P) -> Message {
    wire::to_message(&wire::response(request, payload).unwrap()).unwrap()
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

fn listed_vetter() -> ListedVetter {
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

    // What the community receives is signed by the vetter and opens as a profile.
    let mut request = wire::vetter_profile_request(&vetter.did, COMMUNITY, &body).unwrap();
    wire::sign(&mut request, &vetter.secret).await.unwrap();
    let opened: wire::Opened<VetterProfileBody> = wire::open(
        &wire::to_message(&request).unwrap(),
        &vetter.did,
        &TrustTaskVmResolver::did_key_only(),
    )
    .await
    .unwrap();
    assert_eq!(opened.payload, body);

    vetter
        .book
        .record_profile_sent(COMMUNITY, vetter.persona, &body, now);
    vetter
        .book
        .ask(asked(&request, vetter.persona, QueryKind::VetterProfile));
    let stored = VetterProfileResponseBody {
        listed: true,
        updated_at: now,
    };
    let handled = vetter
        .receive(&community_answer(&request, &stored), COMMUNITY)
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
    let page = VetterListResponseBody {
        vetters: vec![listed_vetter()],
        next_cursor: Some("page-2".into()),
    };
    let request =
        wire::vetter_list_request(&applicant.did, COMMUNITY, &VetterListBody::default()).unwrap();

    // Nobody asked: the page answers nothing.
    let handled = applicant
        .receive(&community_answer(&request, &page), COMMUNITY)
        .await;
    assert!(handled.answer.is_none());

    applicant
        .book
        .ask(asked(&request, applicant.persona, QueryKind::VetterList));
    // Another community cannot answer our question.
    let handled = applicant
        .receive(&community_answer(&request, &page), "did:key:zElsewhere")
        .await;
    assert!(handled.answer.is_none());

    let handled = applicant
        .receive(&community_answer(&request, &page), COMMUNITY)
        .await;
    let Some(CommunityAnswer::Vetters {
        query, page: got, ..
    }) = handled.answer
    else {
        panic!("the page is handed to whoever asked");
    };
    assert_eq!(query, request.id);
    assert_eq!(got, page);
    assert!(!handled.changed, "a directory page is never saved");

    // Refused: the community would not answer this caller.
    let request =
        wire::vetter_list_request(&applicant.did, COMMUNITY, &VetterListBody::default()).unwrap();
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
    let stray =
        wire::vetter_list_request(&applicant.did, COMMUNITY, &VetterListBody::default()).unwrap();
    let resolver = TrustTaskVmResolver::did_key_only();
    let ctx = Context {
        account: &applicant.account,
        resolver: &resolver,
        recipient: Some((applicant.persona, &applicant.did)),
        now: Utc::now(),
    };
    assert!(
        handle(
            &mut applicant.book,
            &ctx,
            &community_refusal(&stray, "permissionDenied"),
            COMMUNITY
        )
        .await
        .is_none()
    );

    // An answer this client cannot read says so, rather than timing out.
    let request =
        wire::vetter_list_request(&applicant.did, COMMUNITY, &VetterListBody::default()).unwrap();
    applicant
        .book
        .ask(asked(&request, applicant.persona, QueryKind::VetterList));
    let handled = applicant
        .receive(
            &community_answer(&request, &json!({ "vetters": "not a list" })),
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

#[tokio::test]
async fn a_resend_is_answered_or_refused_in_plain_words() {
    let mut member = Party::new(5).member_of(COMMUNITY);
    let request = wire::vetter_resend_request(&member.did, COMMUNITY).unwrap();
    member
        .book
        .ask(asked(&request, member.persona, QueryKind::VetterResend));
    let resent = VetterResendResponseBody {
        credential_id: "urn:uuid:grant".into(),
        valid_until: Utc::now() + Duration::days(300),
    };
    let handled = member
        .receive(&community_answer(&request, &resent), COMMUNITY)
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
    let mut body = manifest_body();
    body.branding = Some(CommunityBranding {
        display_name: Some("Kernel Developers".into()),
        accent_color: Some("#336699".into()),
        ..CommunityBranding::default()
    });
    let handled = applicant
        .receive(&community_answer(&request, &body), COMMUNITY)
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
    let handled = vetter
        .receive(&delivery(&credential, COMMUNITY), COMMUNITY)
        .await;
    assert!(matches!(handled.notice, Some(Notice::VetterGranted { .. })));

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
    let link = vetter.book.tickets[0].uri(&vetter.did);
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
        applicant.application().ticket_from_uri(&elsewhere.uri(&vetter.did)),
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
