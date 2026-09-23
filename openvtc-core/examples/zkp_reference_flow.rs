//! A reference run of hidden-vetter admission, through the real vetting ceremony.
//!
//! Ten members hold a real community-issued vetter role credential. Three of them run real
//! vetting sessions with one applicant — ticket, session, a Vetting Card the applicant signs
//! with its own key and the vetter verifies against the resolver — and attest. The applicant
//! proves, and the community admits.
//!
//! Nothing here is a stand-in: every identity is a `did:key` with a real Ed25519 key, the role
//! credentials and the Vetting Cards carry real Data Integrity proofs, and the identity
//! commitment and card digest bound into each attestation are the ones the ceremony computed.
//!
//! ```sh
//! cargo run -p openvtc-core --example zkp_reference_flow > /tmp/zkp-reference.json
//! ```

use affinidi_tdk::secrets_resolver::secrets::Secret;
use chrono::{Duration, Utc};
use dtg_credentials::DTGCredential;
use openvtc_core::config::account::PersonaId;
use openvtc_core::vetting::{
    VettingBook,
    applicant::{RequestDraft, VetterEligibility},
    hidden::{self, HiddenParams},
    tickets::Ticket,
    vetter::{Attestation, IncomingRequest, Intake},
};
use openvtc_vetting_pcs::{
    meta::StatementMeta, scheme::key_text, snapshot::VetterSnapshot, vetter::VetterEngine,
    vtc::Vtc, wire::SubmissionWire,
};
use rand::{SeedableRng, rngs::StdRng};
use serde_json::{Value, json};
use vta_sdk::protocols::vetting::{
    COMMUNITY_ROLE_ENDORSEMENT_TYPE, IDENTITY_VETTING_ENDORSEMENT_TYPE, VETTER_ROLE, VettingMethod,
    VettingRelationship, request, session,
};
use vta_sdk::trust_task_proof::TrustTaskVmResolver;
use vta_sdk::vetting::card::sign_card;

const PERIOD: &str = "2026-09";
const VETTERS: usize = 10;
/// Which of the ten vet. The other seven never hear of the application.
const VETTING: [usize; 3] = [2, 5, 7];

/// A `did:key` Ed25519 identity from a fixed seed, so the run is reproducible.
fn identity(seed: u8) -> (Secret, String) {
    let mut secret = Secret::generate_ed25519(None, Some(&[seed; 32]));
    let public = secret.get_public_keymultibase().unwrap();
    secret.id = format!("did:key:{public}#{public}");
    let did = secret.id.split('#').next().unwrap().to_string();
    (secret, did)
}

fn requirements() -> Value {
    json!({
        "version": "0.1",
        "statementType": IDENTITY_VETTING_ENDORSEMENT_TYPE,
        "minStatements": 3,
        "minByMethod": { "inPerson": 1 },
        "acceptedMethods": ["inPerson", "video", "priorAcquaintance"],
        "requiredClaims": ["name.legal"],
        "maxStatementAge": "P120D",
        "eligibleVetters": { "role": "vetter" },
        "independence": {
            "maxByDeclaredRelationship": { "family": 0, "sameEmployer": 1 },
            "requireConsistentIdentityCommitment": true
        }
    })
}

/// A real community role credential: a DTG endorsement credential, signed by the community.
async fn role_credential(issuer: &Secret, community: &str, subject: &str) -> Value {
    let now = Utc::now();
    let mut credential = DTGCredential::new_vec(
        community.to_string(),
        subject.to_string(),
        now - Duration::minutes(1),
        Some(now + Duration::days(365)),
        json!({
            "type": COMMUNITY_ROLE_ENDORSEMENT_TYPE,
            "role": VETTER_ROLE,
            "communityDid": community,
        }),
    )
    .with_id(format!("urn:uuid:{}", uuid::Uuid::new_v4()));
    credential.sign(issuer, None).await.unwrap();
    serde_json::to_value(&credential).unwrap()
}

fn size_of(v: &Value) -> usize {
    serde_json::to_vec(v).map(|b| b.len()).unwrap_or(0)
}

#[tokio::main]
async fn main() {
    let mut rng = StdRng::seed_from_u64(0x2026_0923);
    let resolver = TrustTaskVmResolver::did_key_only();
    let mut report = serde_json::Map::new();

    // --- 1. Real identities -----------------------------------------------------------------
    let (community_secret, community) = identity(0xC0);
    let (applicant_secret, applicant_did) = identity(0xB0);
    let vetter_ids: Vec<(Secret, String)> = (0..VETTERS).map(|i| identity(i as u8 + 1)).collect();

    // --- 2. The community stands up its hidden-vetting deployment ---------------------------
    let mut vtc = Vtc::new(&community, PERIOD, requirements(), &mut rng).expect("vtc");
    let token_label = vtc.current_token_label().to_string();
    let digest = vtc.requirements_digest().to_string();
    report.insert(
        "step1_identities_and_deployment".into(),
        json!({
            "communityDid": community,
            "applicantJoinDid": applicant_did,
            "vetterDids": vetter_ids.iter().map(|(_, d)| d).collect::<Vec<_>>(),
            "helperKeyHvk": key_text(vtc.hvk()).unwrap(),
            "tokenKeyTvk": key_text(vtc.tvk()).unwrap(),
            "vetterLabel": format!("vetter/{PERIOD}"),
            "tokenLabel": token_label,
            "requirements": requirements(),
            "requirementsDigest": digest,
        }),
    );

    // --- 3. Ten real role credentials, then ten PCS enrolments ------------------------------
    let mut engines: Vec<VetterSnapshot> = Vec::new();
    for (i, (_, did)) in vetter_ids.iter().enumerate() {
        let credential = role_credential(&community_secret, &community, did).await;
        if i == VETTING[0] {
            report.insert("step2_vetter_role_credential".into(), credential);
        }
        vtc.grant(did);
        let mut engine = VetterEngine::new(did, &vtc, &mut rng).expect("engine");
        engine.enroll(&mut vtc, &mut rng).expect("root credential");
        engine
            .drip(&mut vtc, 1, &token_label, 3, &mut rng)
            .expect("tokens");
        engines.push(engine.snapshot().expect("snapshot"));
    }
    let one = &engines[VETTING[0]];
    report.insert(
        "step3_pcs_enrolment".into(),
        json!({
            "enrolled": VETTERS,
            "label": format!("vetter/{PERIOD}"),
            "exampleVetterDid": vetter_ids[VETTING[0]].1,
            "examplePcsIdentifier": one.id,
            "exampleRootCredential": one.credentials.get(PERIOD),
            "exampleTokenSerial": one.tokens[0].serial,
            "exampleTokenSignature": one.tokens[0].credential,
            "tokensMintedThisTick": VETTERS * 3,
        }),
    );

    // --- 4. The published criterion ----------------------------------------------------------
    let mut vetting = requirements();
    vetting["ext"] = json!({
        hidden::HIDDEN_VETTING_NS: {
            "suite": hidden::SUITE,
            "helperKey": key_text(vtc.hvk()).unwrap(),
            "tokenKey": key_text(vtc.tvk()).unwrap(),
            "vetterLabels": [format!("vetter/{PERIOD}")],
            "tokenLabels": [token_label],
        }
    });
    vetting["extCritical"] = json!([hidden::HIDDEN_VETTING_NS]);
    let criterion = json!({
        "id": "kernel-developer-private",
        "description": "Three kernel vetters must confirm who you are. At least one must meet you in person.",
        "presentationDefinition": { "credentials": [] },
        "vetting": vetting,
        "requirementsDigest": digest,
    });
    let manifest_payload = json!({ "communityDid": community, "criteria": [criterion.clone()] });
    report.insert("step4_manifest_criterion".into(), criterion);

    // --- 5. The applicant adopts it ----------------------------------------------------------
    let mut book = VettingBook::default();
    let persona = PersonaId::new();
    book.start_application(&community, persona, &applicant_did, Utc::now())
        .expect("application");
    let parsed = serde_json::from_value(manifest_payload.clone()).expect("manifest parses");
    let application = book.application_mut(&community, persona).unwrap();
    application
        .adopt_manifest(&parsed, &manifest_payload)
        .expect("a criterion this build implements");
    let params: HiddenParams = application
        .hidden
        .clone()
        .expect("hidden-vetting criterion");
    let applicant_pcs_id = application
        .hidden_id()
        .expect("a key of its own")
        .to_string();
    report.insert(
        "step5_application".into(),
        json!({
            "joinDid": applicant_did,
            "pcsIdentifier": applicant_pcs_id,
            "note": "The commitment salt stays local; the identity commitment below is computed over it.",
        }),
    );

    // --- 6. Three real vetting sessions -------------------------------------------------------
    let methods = [
        (VettingMethod::InPerson, vec!["passport".to_string()]),
        (VettingMethod::Video, vec!["nationalId".to_string()]),
        (VettingMethod::InPerson, vec!["passport".to_string()]),
    ];
    let mut sessions = Vec::new();
    for (n, &index) in VETTING.iter().enumerate() {
        let (vetter_secret, vetter_did) = &vetter_ids[index];
        let _ = vetter_secret;
        let (method, documents) = &methods[n];

        let mut desk = VettingBook::default();
        let ticket = Ticket::issue(
            community.clone(),
            persona,
            vec![VettingMethod::InPerson, VettingMethod::Video],
            3,
            Duration::days(7),
            Utc::now(),
        );
        let code = ticket.code.clone();
        desk.tickets.push(ticket);

        let request_document_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
        let request = book
            .application_mut(&community, persona)
            .unwrap()
            .prepare_request(
                &request_document_id,
                vetter_did,
                request::v0_1::Ticket::ShortCodeTicket(
                    request::v0_1::ShortCodeTicket::try_from(
                        request::v0_1::ShortCodeTicket::builder().code(code),
                    )
                    .expect("a Crockford code"),
                ),
                RequestDraft {
                    preferred_method: Some(*method),
                    languages: vec!["en".into()],
                    message: Some("Kernel maintainer application".into()),
                    availability: None,
                },
                Utc::now(),
            )
            .expect("a well-formed request");

        let accepted = desk.take_request(
            IncomingRequest {
                document_id: &request_document_id,
                sender: &applicant_did,
                persona,
                body: request,
                eligible: true,
            },
            Utc::now(),
        );
        let Intake::Accepted(response) = accepted else {
            panic!("the desk accepts the request");
        };
        // The acceptance reaches the applicant, carrying the vetter's own handle for it and
        // the eligibility the vetter showed — the role credential issued in step 2.
        book.application_mut(&community, persona)
            .unwrap()
            .on_accepted(
                &request_document_id,
                vetter_did,
                *response,
                VetterEligibility::Shown {
                    credential_id: None,
                    valid_until: Utc::now() + Duration::days(365),
                },
                Utc::now(),
            )
            .expect("the applicant records the acceptance");
        // The desk's own handle for this request, which it sent back to the applicant.
        let request_id = desk
            .desk
            .iter()
            .find(|e| e.request_document_id == request_document_id)
            .map(|e| e.request_id.clone())
            .expect("the desk took it");

        let session_document_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
        let session_payload = desk
            .open_session(
                &request_id,
                *method,
                vec!["name.legal".into()],
                vec![],
                &session_document_id,
                Utc::now(),
            )
            .expect("a session opens");
        let open = book
            .application_mut(&community, persona)
            .unwrap()
            .on_session(
                &session_document_id,
                vetter_did,
                session_payload,
                Utc::now(),
            )
            .expect("the applicant accepts the session");

        // A real Vetting Card, signed by the applicant's own key.
        let draft = book
            .application_mut(&community, persona)
            .unwrap()
            .card_draft(
                &open.id,
                vec![
                    session::v0_1::VettingCardClaim::try_from(
                        session::v0_1::VettingCardClaim::builder()
                            .type_("name.legal")
                            .value(json!("Bob Example"))
                            .provenance("selfAsserted"),
                    )
                    .unwrap(),
                ],
                Utc::now(),
            )
            .expect("a card draft");
        let card = sign_card(draft, &applicant_secret)
            .await
            .expect("a signed card");
        book.application_mut(&community, persona)
            .unwrap()
            .record_card(&open.id, &card, &resolver, Utc::now())
            .await
            .expect("the applicant re-verifies what it signed");

        // The vetter verifies the card against the resolver, then checks the human.
        desk.receive_card(
            vetter_did,
            &applicant_did,
            &open.id,
            &card,
            &resolver,
            Utc::now(),
        )
        .await
        .expect("the card verifies");

        // The statement the vetter would sign on the named path. Here it is the source of the
        // facts the attestation carries: the commitment and card digest are the ceremony's.
        let statement_draft = desk
            .statement_draft(
                &request_id,
                vetter_did,
                Attestation {
                    method: *method,
                    document_classes: documents.clone(),
                    claims_verified: vec!["name.legal".into()],
                    liveness_confirmed: true,
                    declared_relationship: VettingRelationship::None,
                    attestation_text_digest: None,
                },
                Utc::now(),
            )
            .expect("a statement draft");
        let endorsement = serde_json::to_value(&statement_draft.endorsement).unwrap();

        let meta = StatementMeta {
            community: community.clone(),
            requirements_digest: digest.clone(),
            method: *method,
            claims_verified: statement_draft
                .endorsement
                .claims_verified
                .iter()
                .map(|c| c.to_string())
                .collect(),
            liveness_confirmed: statement_draft.endorsement.liveness_confirmed,
            declared_relationship: statement_draft.endorsement.declared_relationship,
            identity_commitment: statement_draft.endorsement.identity_commitment.clone(),
            card_digest_multibase: statement_draft.endorsement.card_digest_multibase.clone(),
            valid_from: statement_draft.valid_from.date_naive(),
            valid_until: statement_draft.valid_until.date_naive(),
            token_label: String::new(),
            token_serial: String::new(),
        };
        let attestation = hidden::attest(
            &community,
            &params,
            &mut engines[index],
            &applicant_pcs_id,
            meta,
            &mut rng,
        )
        .expect("the vetter holds a live credential and a free token");
        book.application_mut(&community, persona)
            .unwrap()
            .receive_hidden_attestation(&attestation)
            .expect("the applicant verifies it at the session");

        sessions.push(json!({
            "vetterDid": vetter_did,
            "matchCode": open.match_code,
            "vettingCard": if n == 0 { card } else { json!("one per session; the first is shown in full") },
            "namedPathStatementEndorsement": endorsement,
            "hiddenAttestation": attestation.clone(),
            "hiddenAttestationBytes": size_of(&attestation),
        }));
    }
    report.insert(
        "step6_sessions".into(),
        json!({ "vetted": VETTING.len(), "ofEligible": VETTERS, "sessions": sessions }),
    );

    // --- 7. The applicant proves and submits ---------------------------------------------------
    let challenge = vtc.challenge(&mut rng);
    let application = book.application_mut(&community, persona).unwrap();
    application
        .prepare_hidden_submission(&challenge)
        .expect("a proof over what it holds");
    let extensions = application.join_extensions();
    report.insert(
        "step7_submission".into(),
        json!({
            "extensions": extensions.clone(),
            "extensionsBytes": size_of(&extensions),
            "capBytes": 16 * 1024,
            "namedStatementsPresented": application.presentable_statements(Utc::now()).len(),
        }),
    );

    // --- 8. The community decides ---------------------------------------------------------------
    let carried = extensions[hidden::EXTENSIONS_MEMBER].clone();
    let wire: SubmissionWire = serde_json::from_value(carried).expect("wire");
    let decision = vtc
        .submit(&wire.to_submission().expect("decode"), Utc::now())
        .expect("the proof verifies");
    let tags: Vec<String> = decision
        .statements
        .iter()
        .map(|s| s.issuer.clone())
        .collect();
    let pcs_ids: Vec<String> = engines.iter().map(|e| e.id.clone()).collect();
    let submitted = serde_json::to_string(&extensions).unwrap();
    report.insert(
        "step8_decision".into(),
        json!({
            "facts": serde_json::to_value(&decision.statements).unwrap(),
            "distinctVetters": decision.evaluation.distinct_vetters(),
            "satisfied": decision.evaluation.satisfied(),
            "byMethod": decision
                .evaluation
                .by_method
                .iter()
                .map(|(m, n)| (m.to_string(), json!(n)))
                .collect::<serde_json::Map<String, Value>>(),
            "commitmentsConsistent": decision.evaluation.commitments_consistent,
        }),
    );
    report.insert(
        "step9_what_the_community_learns".into(),
        json!({
            "tags": tags,
            "enrolledPcsIdentifiers": pcs_ids,
            "enrolledVetterDids": vetter_ids.iter().map(|(_, d)| d).collect::<Vec<_>>(),
            "anyTagEqualsAnEnrolledIdentifier": tags.iter().any(|t| pcs_ids.contains(t)),
            "anyVetterDidAppearsInTheSubmission": vetter_ids
                .iter()
                .any(|(_, d)| submitted.contains(d)),
            "whoActuallyVetted": VETTING
                .iter()
                .map(|i| vetter_ids[*i].1.clone())
                .collect::<Vec<_>>(),
        }),
    );

    println!(
        "{}",
        serde_json::to_string_pretty(&Value::Object(report)).unwrap()
    );
}
