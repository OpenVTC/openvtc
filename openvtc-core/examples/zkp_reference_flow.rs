//! A reference run of hidden-vetter admission: ten eligible vetters, three of whom vet one
//! applicant, who is then admitted by the community.
//!
//! Every artifact the flow produces is printed as JSON, with its byte size, so the output is a
//! reference set rather than a description of one. Run:
//!
//! ```sh
//! cargo run -p openvtc-core --example zkp_reference_flow > /tmp/zkp-reference.json
//! ```

use chrono::{NaiveDate, TimeZone, Utc};
use openvtc_core::vetting::hidden::{self, HiddenParams};
use openvtc_vetting_pcs::{
    meta::StatementMeta, scheme::key_text, snapshot::VetterSnapshot, vetter::VetterEngine,
    vtc::Vtc, wire::SubmissionWire,
};
use rand::{SeedableRng, rngs::StdRng};
use serde_json::{Value, json};
use vta_sdk::protocols::vetting::{
    IDENTITY_VETTING_ENDORSEMENT_TYPE, VettingMethod, VettingRelationship,
};

const COMMUNITY: &str = "did:webvh:QmKernelVtcScid:kernel-vtc.example";
const PERIOD: &str = "2026-09";
const JOIN_DID: &str = "did:webvh:QmBobScid:bob-kernel";
const VETTERS: usize = 10;
/// Which of the ten actually vet. The other seven never learn of the application.
const VETTING: [usize; 3] = [2, 5, 7];

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

/// Shorten a long multibase value for display, keeping both ends so it stays recognisable.
fn brief(s: &str) -> String {
    if s.chars().count() <= 24 {
        return s.to_string();
    }
    let head: String = s.chars().take(14).collect();
    let tail: String = s
        .chars()
        .rev()
        .take(6)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{head}…{tail}")
}

fn size_of(v: &Value) -> usize {
    serde_json::to_vec(v).map(|b| b.len()).unwrap_or(0)
}

fn statement_meta(method: VettingMethod, digest: &str, day: u32) -> StatementMeta {
    StatementMeta {
        community: COMMUNITY.into(),
        requirements_digest: digest.into(),
        method,
        claims_verified: vec!["name.legal".into()],
        liveness_confirmed: true,
        declared_relationship: VettingRelationship::None,
        identity_commitment: "zHbFqTnG8sPz3VtKmXwRc4dYjLnQ2pAe7BvNsKdRxMwT".into(),
        card_digest_multibase: "zQmCardDigestOfBobsVettingCardAsTransmitted".into(),
        // Day granularity only: an exact time would let the community line a statement up with
        // a vetter's activity.
        valid_from: NaiveDate::from_ymd_opt(2026, 9, day).unwrap(),
        valid_until: NaiveDate::from_ymd_opt(2027, 1, 18).unwrap(),
        token_label: String::new(),
        token_serial: String::new(),
    }
}

fn main() {
    let mut rng = StdRng::seed_from_u64(0x2026_0923);
    let mut report = serde_json::Map::new();

    // --- 1. The community stands up its deployment --------------------------------------
    let mut vtc = Vtc::new(COMMUNITY, PERIOD, requirements(), &mut rng).expect("community");
    let token_label = vtc.current_token_label().to_string();
    let digest = vtc.requirements_digest().to_string();
    report.insert(
        "step1_community".into(),
        json!({
            "communityDid": COMMUNITY,
            "vetterLabel": format!("vetter/{PERIOD}"),
            "tokenLabel": token_label,
            "helperKeyHvk": key_text(vtc.hvk()).unwrap(),
            "tokenKeyTvk": key_text(vtc.tvk()).unwrap(),
            "requirements": requirements(),
            "requirementsDigest": digest,
        }),
    );

    // --- 2. Ten members are granted the vetter role and enrol ----------------------------
    let mut vetters: Vec<VetterSnapshot> = Vec::new();
    let mut enrolled = Vec::new();
    for i in 0..VETTERS {
        let member = format!("did:webvh:QmKernelVtcScid:vetter-{i:02}");
        vtc.grant(&member);
        let mut engine = VetterEngine::new(&member, &vtc, &mut rng).expect("engine");
        engine.enroll(&mut vtc, &mut rng).expect("root credential");
        // One tick of the drip: the community mints tokens for every vetter, whether or not
        // they ever vet. That is what makes a fetch say nothing about activity.
        engine
            .drip(&mut vtc, 1, &token_label, 3, &mut rng)
            .expect("tokens");
        let snap = engine.snapshot().expect("snapshot");
        enrolled.push(json!({
            "memberDid": snap.member,
            "pcsIdentifier": snap.id,
            "rootCredential": snap.credentials.get(PERIOD),
            "tokensHeld": snap.tokens.len(),
        }));
        vetters.push(snap);
    }
    let one = &vetters[VETTING[0]];
    report.insert(
        "step2_vetters".into(),
        json!({
            "count": VETTERS,
            "credentialLabel": format!("vetter/{PERIOD}"),
            "enrolled": enrolled,
            "exampleCredentialBytes": one.credentials.get(PERIOD).map(|c| c.len()),
            "exampleToken": {
                "label": one.tokens[0].label,
                "serial": one.tokens[0].serial,
                "signatureBytes": one.tokens[0].credential.len(),
            },
        }),
    );

    // --- 3. The community publishes the criterion ----------------------------------------
    let params_json = json!({
        "suite": hidden::SUITE,
        "helperKey": key_text(vtc.hvk()).unwrap(),
        "tokenKey": key_text(vtc.tvk()).unwrap(),
        "vetterLabels": [format!("vetter/{PERIOD}")],
        "tokenLabels": [token_label],
    });
    let mut vetting = requirements();
    vetting["ext"] = json!({ hidden::HIDDEN_VETTING_NS: params_json });
    vetting["extCritical"] = json!([hidden::HIDDEN_VETTING_NS]);
    let criterion = json!({
        "id": "kernel-developer-private",
        "description": "Three kernel vetters must confirm who you are. At least one must meet you in person.",
        "presentationDefinition": { "credentials": [] },
        "vetting": vetting,
        "requirementsDigest": digest,
    });
    report.insert("step3_manifest_criterion".into(), criterion.clone());

    // --- 4. The applicant adopts it and mints a key of this application's own -------------
    let params: HiddenParams =
        match hidden::read_mode(&criterion).expect("a mode this build implements") {
            hidden::Mode::Hidden(p) => *p,
            hidden::Mode::Named => unreachable!("the criterion publishes parameters"),
        };
    let mut application = hidden::start(COMMUNITY, &params, JOIN_DID, &mut rng).expect("start");
    let applicant_id = application.id.clone();
    report.insert(
        "step4_applicant".into(),
        json!({
            "joinDid": JOIN_DID,
            "pcsIdentifier": applicant_id,
            "note": "Minted for this application and no other. A vetter attests this identifier; \
                     the community later binds it to the join DID.",
        }),
    );

    // --- 5. Three of the ten vet ----------------------------------------------------------
    let methods = [
        (VettingMethod::InPerson, 20u32),
        (VettingMethod::Video, 21),
        (VettingMethod::InPerson, 22),
    ];
    let mut sessions = Vec::new();
    for (n, &index) in VETTING.iter().enumerate() {
        let (method, day) = methods[n];
        let meta = statement_meta(method, &digest, day);
        let attestation = hidden::attest(
            COMMUNITY,
            &params,
            &mut vetters[index],
            &applicant_id,
            meta.clone(),
            &mut rng,
        )
        .expect("attestation");
        hidden::receive(COMMUNITY, &params, &mut application, &attestation)
            .expect("the applicant verifies it at the session");
        sessions.push(json!({
            "vetterMemberDid": vetters[index].member,
            "vetterPcsIdentifier": vetters[index].id,
            "statementMetadata": serde_json::to_value(&meta).unwrap(),
            "attestation": attestation,
            "attestationBytes": size_of(&attestation),
        }));
    }
    report.insert(
        "step5_sessions".into(),
        json!({
            "vetted": VETTING.len(),
            "ofEligible": VETTERS,
            "sessions": sessions,
        }),
    );

    // --- 6. The applicant proves ----------------------------------------------------------
    let challenge = vtc.challenge(&mut rng);
    let submission = hidden::prove(
        COMMUNITY,
        &params,
        &digest,
        &application,
        &challenge,
        &mut rng,
    )
    .expect("proof");
    let extensions =
        json!({ "requirementsDigest": digest, hidden::EXTENSIONS_MEMBER: submission.clone() });
    report.insert(
        "step6_submission".into(),
        json!({
            "extensions": extensions,
            "extensionsBytes": size_of(&extensions),
            "capBytes": 16 * 1024,
            "proofBytes": submission["proof"].as_str().map(str::len),
            "statementsCarried": submission["statements"].as_array().map(Vec::len),
        }),
    );

    // --- 7. The community decides ----------------------------------------------------------
    let wire: SubmissionWire = serde_json::from_value(submission.clone()).expect("wire");
    let decision = vtc
        .submit(
            &wire.to_submission().expect("decode"),
            Utc.with_ymd_and_hms(2026, 9, 23, 9, 30, 0).unwrap(),
        )
        .expect("the proof verifies");
    let tags: Vec<String> = decision
        .statements
        .iter()
        .map(|s| s.issuer.clone())
        .collect();
    report.insert(
        "step7_decision".into(),
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
            "needs": decision.evaluation.needs.iter().map(|n| n.to_wire()).collect::<Vec<_>>(),
        }),
    );

    // --- 8. What the community can and cannot tell -------------------------------------------
    let all_ids: Vec<String> = vetters.iter().map(|v| v.id.clone()).collect();
    let any_tag_is_an_identifier = tags.iter().any(|t| all_ids.contains(t));
    report.insert(
        "step8_what_the_community_learns".into(),
        json!({
            "tagsOnTheFacts": tags.iter().map(|t| brief(t)).collect::<Vec<_>>(),
            "eligibleVetterIdentifiers": all_ids.iter().map(|i| brief(i)).collect::<Vec<_>>(),
            "anyTagEqualsAnEnrolledIdentifier": any_tag_is_an_identifier,
            "anonymitySet": VETTERS,
            "learns": [
                "three distinct eligible vetters attested, and none of them is the applicant",
                "each statement's method, claims verified and day-granular validity",
                "that all three carry the same identity commitment",
                "which token label each spent, and that no serial was spent twice"
            ],
            "doesNotLearn": [
                "which three of the ten vetted",
                "whether the same vetter has vetted anyone else",
                "any vetter's member DID or PCS identifier"
            ],
        }),
    );

    println!(
        "{}",
        serde_json::to_string_pretty(&Value::Object(report)).unwrap()
    );
}
