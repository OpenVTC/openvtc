//! Onboarding under a hidden-vetting criterion, end to end, through the client's own API.
//!
//! The community here is the same verifier `vtc-service` runs on the VTI `zkp-pcs` branch, so
//! what this test exercises is the real decision path: what the client builds is what the
//! service checks. The cross-repo fixture test on the VTI side proves the wire format agrees.
//!
//! What it demonstrates, in the order an applicant lives it:
//!
//! 1. The community publishes its parameters in the manifest, under a namespace it controls,
//!    marked critical.
//! 2. The applicant adopts the criterion and starts an application with a key of its own.
//! 3. Two vetters run ordinary vetting sessions and attest — without learning each other, and
//!    without the community learning either of them.
//! 4. The applicant proves, and the proof rides in the join submission's `extensions`.
//! 5. The community counts it with the same rule it counts named statements with, and admits.

use chrono::{NaiveDate, TimeZone, Utc};
use openvtc_core::vetting::hidden::{self, HiddenParams};
use openvtc_vetting_pcs::{
    meta::StatementMeta, snapshot::VetterSnapshot, vetter::VetterEngine, vtc::Vtc,
    wire::SubmissionWire,
};
use rand::{SeedableRng, rngs::StdRng};
use serde_json::{Value, json};
use vta_sdk::protocols::vetting::{
    IDENTITY_VETTING_ENDORSEMENT_TYPE, VettingMethod, VettingRelationship,
};

const COMMUNITY: &str = "did:webvh:QmVtcScid:kernel-vtc.example";
const PERIOD: &str = "2026-09";
const JOIN_DID: &str = "did:webvh:QmVtcScid:bob-kernel";

fn requirements() -> Value {
    json!({
        "version": "0.1",
        "statementType": IDENTITY_VETTING_ENDORSEMENT_TYPE,
        "minStatements": 2,
        "minByMethod": { "inPerson": 1 },
        "acceptedMethods": ["inPerson", "video"],
        "requiredClaims": ["name.legal"],
        "maxStatementAge": "P120D",
        "eligibleVetters": { "role": "vetter" }
    })
}

/// The criterion as the community publishes it: the named members, plus its parameters under
/// `vetting.ext`, marked critical so no client applies the wrong way.
fn published_criterion(vtc: &Vtc) -> Value {
    let params = vtc.params().unwrap();
    let mut vetting = requirements();
    vetting["ext"] = json!({
        hidden::HIDDEN_VETTING_NS: {
            "suite": hidden::SUITE,
            "helperKey": openvtc_vetting_pcs::scheme::key_text(vtc.hvk()).unwrap(),
            "tokenKey": openvtc_vetting_pcs::scheme::key_text(vtc.tvk()).unwrap(),
            "vetterLabels": params.vetter_labels(),
            "tokenLabels": params.tokens().live_labels().iter().collect::<Vec<_>>(),
        }
    });
    vetting["extCritical"] = json!([hidden::HIDDEN_VETTING_NS]);
    json!({
        "id": "kernel-developer",
        "description": "Two kernel vetters, one in person. The community is told how many, never who.",
        "presentationDefinition": { "credentials": [] },
        "vetting": vetting,
        "requirementsDigest": vtc.requirements_digest(),
    })
}

fn statement_meta(method: VettingMethod, digest: &str) -> StatementMeta {
    StatementMeta {
        community: COMMUNITY.into(),
        requirements_digest: digest.into(),
        method,
        claims_verified: vec!["name.legal".into()],
        liveness_confirmed: true,
        declared_relationship: VettingRelationship::None,
        identity_commitment: "zCommitmentOfThisApplication".into(),
        card_digest_multibase: "zCardDigest".into(),
        valid_from: NaiveDate::from_ymd_opt(2026, 9, 20).unwrap(),
        valid_until: NaiveDate::from_ymd_opt(2027, 1, 18).unwrap(),
        token_label: String::new(),
        token_serial: String::new(),
    }
}

#[test]
fn an_applicant_is_admitted_without_the_community_learning_who_vetted_them() {
    let mut rng = StdRng::seed_from_u64(0x2026_0922);
    // --- the community ------------------------------------------------------------------
    let mut vtc = Vtc::new(COMMUNITY, PERIOD, requirements(), &mut rng).unwrap();
    let token_label = vtc.current_token_label().to_string();
    let mut vetters: Vec<VetterSnapshot> = Vec::new();
    for i in 0..2 {
        let member = format!("member-{i}");
        vtc.grant(&member);
        let mut engine = VetterEngine::new(&member, &vtc, &mut rng).unwrap();
        engine.enroll(&mut vtc, &mut rng).unwrap();
        engine.drip(&mut vtc, 1, &token_label, 2, &mut rng).unwrap();
        vetters.push(engine.snapshot().unwrap());
    }
    let criterion = published_criterion(&vtc);
    let digest = vtc.requirements_digest().to_string();

    // --- the applicant reads the manifest -----------------------------------------------
    let mode = hidden::read_mode(&criterion).expect("this client implements the namespace");
    let params: HiddenParams = match mode {
        hidden::Mode::Hidden(p) => *p,
        hidden::Mode::Named => panic!("the criterion publishes hidden-vetting parameters"),
    };
    let mut application = hidden::start(COMMUNITY, &params, JOIN_DID, &mut rng).unwrap();
    let applicant_id = application.id.clone();

    // --- two vetting sessions ------------------------------------------------------------
    for (i, method) in [(0usize, VettingMethod::InPerson), (1, VettingMethod::Video)] {
        let attestation = hidden::attest(
            COMMUNITY,
            &params,
            &mut vetters[i],
            &applicant_id,
            statement_meta(method, &digest),
            &mut rng,
        )
        .expect("the vetter holds a live credential and a token");
        hidden::receive(COMMUNITY, &params, &mut application, &attestation)
            .expect("the applicant checks it at the session, not at submit");
    }

    // --- submit ---------------------------------------------------------------------------
    let challenge = vtc.challenge(&mut rng);
    let submission = hidden::prove(
        COMMUNITY,
        &params,
        &digest,
        &application,
        &challenge,
        &mut rng,
    )
    .unwrap();

    // What rides in `extensions`, and nothing in it names a vetter.
    let json = serde_json::to_string(&submission).unwrap();
    assert!(!json.contains("member-0") && !json.contains("member-1"));
    assert!(!json.contains("did:webvh:QmVtcScid:kernel-vtc.example:member"));

    // --- the community decides --------------------------------------------------------------
    let wire: SubmissionWire = serde_json::from_value(submission).unwrap();
    let decision = vtc
        .submit(
            &wire.to_submission().unwrap(),
            Utc.with_ymd_and_hms(2026, 9, 22, 12, 0, 0).unwrap(),
        )
        .expect("the proof verifies under the published parameters");
    assert!(decision.evaluation.satisfied(), "{:?}", decision.evaluation);
    assert_eq!(decision.evaluation.distinct_vetters(), 2);

    // The facts the policy sees carry tags, not vetters.
    for statement in &decision.statements {
        assert!(statement.counted);
        assert!(statement.issuer.starts_with('z'));
        for v in &vetters {
            assert_ne!(statement.issuer, v.id);
            assert_ne!(statement.issuer, v.member);
        }
    }
}

/// The same flow again, but driven through `Application` — the type the join flow actually
/// holds — so what lands in the submission's `extensions` is what a real submit would carry.
#[test]
fn the_join_submission_carries_the_proof_in_its_extensions() {
    use openvtc_core::config::account::PersonaId;
    use openvtc_core::vetting::book::VettingBook;
    use openvtc_core::vetting::hidden::EXTENSIONS_MEMBER;

    let mut rng = StdRng::seed_from_u64(0x2026_0923);
    let mut vtc = Vtc::new(COMMUNITY, PERIOD, requirements(), &mut rng).unwrap();
    let token_label = vtc.current_token_label().to_string();
    let mut vetters: Vec<VetterSnapshot> = Vec::new();
    for i in 0..2 {
        let member = format!("member-{i}");
        vtc.grant(&member);
        let mut engine = VetterEngine::new(&member, &vtc, &mut rng).unwrap();
        engine.enroll(&mut vtc, &mut rng).unwrap();
        engine.drip(&mut vtc, 1, &token_label, 2, &mut rng).unwrap();
        vetters.push(engine.snapshot().unwrap());
    }
    let digest = vtc.requirements_digest().to_string();

    // The applicant adopts the criterion. Adopting it mints this application's own key.
    let mut book = VettingBook::default();
    let persona = PersonaId::new();
    book.start_application(COMMUNITY, persona, JOIN_DID, Utc::now())
        .unwrap();
    let manifest_payload = json!({
        "communityDid": COMMUNITY,
        "criteria": [published_criterion(&vtc)],
    });
    let parsed = serde_json::from_value(manifest_payload.clone()).unwrap();
    let application = book.application_mut(COMMUNITY, persona).unwrap();
    application
        .adopt_manifest(&parsed, &manifest_payload)
        .unwrap();
    assert!(
        application.hidden.is_some(),
        "the criterion is hidden-vetting"
    );
    let applicant_id = application
        .hidden_id()
        .expect("adopting a hidden criterion mints a key")
        .to_string();

    // Two sessions, and the attestations land on the application itself.
    let params = application.hidden.clone().unwrap();
    for (i, method) in [(0usize, VettingMethod::InPerson), (1, VettingMethod::Video)] {
        let attestation = hidden::attest(
            COMMUNITY,
            &params,
            &mut vetters[i],
            &applicant_id,
            statement_meta(method, &digest),
            &mut rng,
        )
        .unwrap();
        book.application_mut(COMMUNITY, persona)
            .unwrap()
            .receive_hidden_attestation(&attestation)
            .expect("the applicant verifies it on receipt");
    }

    // Submit: the proof is built and carried in `extensions`, beside the requirements digest.
    let application = book.application_mut(COMMUNITY, persona).unwrap();
    let challenge = vtc.challenge(&mut rng);
    assert!(application.prepare_hidden_submission(&challenge).unwrap());
    let extensions = application.join_extensions();
    assert_eq!(
        extensions["requirementsDigest"].as_str(),
        Some(digest.as_str())
    );
    let carried = extensions
        .get(EXTENSIONS_MEMBER)
        .expect("the proof rides in extensions");

    // And the community admits on it.
    let wire: SubmissionWire = serde_json::from_value(carried.clone()).unwrap();
    let decision = vtc
        .submit(
            &wire.to_submission().unwrap(),
            Utc.with_ymd_and_hms(2026, 9, 22, 12, 0, 0).unwrap(),
        )
        .unwrap();
    assert!(decision.evaluation.satisfied(), "{:?}", decision.evaluation);
    assert_eq!(decision.evaluation.distinct_vetters(), 2);

    // The submission is inside the VTC's 16 KiB `extensions` cap, with room over.
    let bytes = serde_json::to_vec(&extensions).unwrap().len();
    assert!(bytes < 16 * 1024, "extensions is {bytes} bytes");
}
