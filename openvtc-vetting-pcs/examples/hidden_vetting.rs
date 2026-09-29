//! Hidden vetting, end to end, with nothing around it.
//!
//! Ten members of a community are named vetters. Three of them vet one applicant. The applicant
//! proves that three distinct vetters did so, the community counts it — and cannot tell which
//! three, even though it issued all ten of their credentials itself.
//!
//! ```sh
//! cargo run --example hidden_vetting
//! ```
//!
//! What this is *not*: the ceremony. A real deployment wraps every step here in something —
//! a ticket, a session, a signed Vetting Card, a Trust Task, a membership credential — and none
//! of it changes what happens below. This is the protocol on its own, so that what it does and
//! does not reveal can be read in one file.

use chrono::{NaiveDate, TimeZone, Utc};
use openvtc_vetting_pcs::{
    applicant::ApplicantEngine, meta::StatementMeta, scheme::key_text, vetter::VetterEngine,
    vtc::Vtc,
};
use rand::{SeedableRng, rngs::StdRng};
use serde_json::json;
use vta_sdk::protocols::vetting::{
    IDENTITY_VETTING_ENDORSEMENT_TYPE, VettingMethod, VettingRelationship,
};

const COMMUNITY: &str = "did:example:kernel-vtc";
const APPLICANT: &str = "did:example:bob";
const PERIOD: &str = "2026-09";
const VETTERS: usize = 10;
/// Which of the ten vet. The other seven never hear of the application.
const VETTING: [usize; 3] = [2, 5, 7];

/// What this community asks of an applicant: three vetters, one of them in person.
fn requirements() -> serde_json::Value {
    json!({
        "version": "0.1",
        "statementType": IDENTITY_VETTING_ENDORSEMENT_TYPE,
        "minStatements": 3,
        "minByMethod": { "inPerson": 1 },
        "acceptedMethods": ["inPerson", "video"],
        "requiredClaims": ["name.legal"],
        "maxStatementAge": "P120D",
        "eligibleVetters": { "role": "vetter" },
        "independence": {
            "maxByDeclaredRelationship": { "family": 0 },
            "requireConsistentIdentityCommitment": true
        }
    })
}

/// What a vetter attests to, after meeting the applicant.
///
/// Dates, never timestamps: an exact time would let the community line an attestation up with a
/// vetter's activity, which undoes the proof without touching it.
fn what_the_vetter_saw(digest: &str, method: VettingMethod) -> StatementMeta {
    StatementMeta {
        community: COMMUNITY.into(),
        requirements_digest: digest.into(),
        method,
        claims_verified: vec!["name.legal".into()],
        liveness_confirmed: true,
        declared_relationship: VettingRelationship::None,
        // In a deployment these come from the Vetting Card the applicant signed and showed.
        identity_commitment: "zCommitmentOfThisApplication".into(),
        card_digest_multibase: "zDigestOfTheCardTheyShowed".into(),
        valid_from: NaiveDate::from_ymd_opt(2026, 9, 20).unwrap(),
        valid_until: NaiveDate::from_ymd_opt(2027, 1, 18).unwrap(),
        token_label: String::new(),
        token_serial: String::new(),
    }
}

fn main() {
    let mut rng = StdRng::seed_from_u64(0x2026_0927);
    let rule = |label: &str| println!("\n\x1b[1m{label}\x1b[0m");

    // --- the community ------------------------------------------------------------------------
    rule("1. A community stands up a hidden-vetting deployment");
    let mut vtc = Vtc::new(COMMUNITY, PERIOD, requirements(), &mut rng).expect("deployment");
    let token_label = vtc.current_token_label().to_string();
    let drip = vtc.drip_rate();
    let digest = vtc.requirements_digest().to_string();
    println!("   helper key   {}…", &key_text(vtc.hvk()).unwrap()[..46]);
    println!("   token key    {}…", &key_text(vtc.tvk()).unwrap()[..46]);
    println!("   class label  vetter/{PERIOD}");
    println!("   token label  {token_label}");
    println!("   drip         {} tokens per vetter per tick", drip);
    println!(
        "\n   Two keys, never one: a token signed under the helper key would *be* a vetter\n   \
         credential whose secret the vetter knows. The period lives in the label rather than\n   \
         in the key, so one proof can carry attestations made either side of a rotation."
    );

    // --- the vetters --------------------------------------------------------------------------
    rule("2. Ten members are named vetters, enrol, and draw tokens");
    let mut vetters: Vec<VetterEngine> = Vec::new();
    for i in 0..VETTERS {
        let member = format!("member-{i}");
        vtc.grant(&member);
        let mut engine = VetterEngine::new(&member, &vtc, &mut rng).expect("engine");
        engine.enroll(&mut vtc, &mut rng).expect("class credential");
        engine
            .drip(&mut vtc, 1, &token_label, drip, &mut rng)
            .expect("tokens");
        vetters.push(engine);
    }
    println!(
        "   {VETTERS} enrolled, {} tokens minted this tick, 0 spent.",
        VETTERS * drip
    );
    println!(
        "\n   The class credential is blind: the community signed a commitment it cannot open,\n   \
         so it cannot recognise the credential it just made. The drip is unconditional — every\n   \
         vetter draws on a schedule whether or not it has vetted anyone, because a fetch that\n   \
         happened only when someone was busy would announce that they were busy."
    );

    // The community caps the draw. A vetter asking for more is refused the batch.
    let greedy = vetters[0]
        .drip(&mut vtc, 2, &token_label, drip + 5, &mut rng)
        .expect_err("more than the published rate");
    println!("\n   Asking for more: {greedy}");

    // --- the applicant ------------------------------------------------------------------------
    rule("3. An applicant starts an application");
    let params = vtc.params().expect("published parameters");
    let mut bob = ApplicantEngine::new(&params, APPLICANT, &mut rng).expect("application");
    println!("   join did   {APPLICANT}");
    println!(
        "   pcs id     {}…",
        &openvtc_vetting_pcs::scheme::point_text(bob.id()).expect("id")[..46]
    );
    println!(
        "\n   A key for this application and no other. That identifier is what a vetter attests;\n   \
         the community binds it to the join DID at submit, and a vetter never needs the DID."
    );

    // --- three sessions -----------------------------------------------------------------------
    rule("4. Three of the ten vet him");
    for (n, &index) in VETTING.iter().enumerate() {
        let method = if n == 1 {
            VettingMethod::Video
        } else {
            VettingMethod::InPerson
        };
        // A vetter reserves a token when it accepts, and spends it when it attests. Out of
        // tokens is `atCapacity` — a decline, not a failure.
        let reservation = vetters[index].accept(None, 2).expect("a free token");
        let attestation = vetters[index]
            .attest(
                &params,
                &reservation,
                bob.id(),
                what_the_vetter_saw(&digest, method),
                &mut rng,
            )
            .expect("attestation");
        bob.receive(&params, attestation)
            .expect("the applicant verifies it on receipt, not at submit");
        println!(
            "   member-{index} attested ({}); tokens left: {}",
            match method {
                VettingMethod::InPerson => "in person",
                _ => "video",
            },
            vetters[index].tokens_free()
        );
    }

    // --- the proof ----------------------------------------------------------------------------
    rule("5. He proves it, once, over all three");
    let challenge = vtc.challenge(&mut rng);
    println!("   challenge   {challenge}  (minted by the community, spent once)");
    let submission = bob
        .submit(&params, &digest, &challenge, &mut rng)
        .expect("a proof over what he holds");
    let wire = serde_json::to_value(
        openvtc_vetting_pcs::wire::SubmissionWire::from_submission(&submission).expect("wire"),
    )
    .unwrap();
    println!(
        "   submission  {} bytes of JSON, {} of proof",
        serde_json::to_vec(&wire).unwrap().len(),
        wire["proof"].as_str().map(str::len).unwrap_or(0)
    );

    // --- the community counts it ----------------------------------------------------------------
    rule("6. The community counts it with the rule it already had");
    let now = Utc.with_ymd_and_hms(2026, 9, 22, 12, 0, 0).unwrap();
    let decision = vtc.submit(&submission, now).expect("the proof verifies");
    println!(
        "   satisfied: {}   distinct vetters: {}   by method: {:?}",
        decision.evaluation.satisfied(),
        decision.evaluation.distinct_vetters(),
        decision
            .evaluation
            .by_method
            .iter()
            .map(|(m, n)| format!("{m} {n}"))
            .collect::<Vec<_>>()
    );
    for statement in &decision.statements {
        println!("   counted: tag {}…", &statement.issuer[..32]);
    }

    // --- what it learned ------------------------------------------------------------------------
    rule("7. What the community can and cannot tell");
    let tags: Vec<&str> = decision
        .statements
        .iter()
        .map(|s| s.issuer.as_str())
        .collect();
    let enrolled: Vec<String> = vetters.iter().map(|v| v.snapshot().unwrap().id).collect();
    let overlap = tags
        .iter()
        .filter(|t| enrolled.iter().any(|e| e == *t))
        .count();
    println!(
        "   It holds {} enrolled identifiers and {} tags. Identifiers matching a tag: {overlap}.",
        enrolled.len(),
        tags.len()
    );
    println!(
        "   It knows: three distinct eligible vetters attested, none of them the applicant;\n   \
         each one's method, claims and window; that all three saw one identity commitment;\n   \
         and that no token serial was spent twice."
    );
    println!(
        "   It does not know: which three of the ten vetted, whether any of them has vetted\n   \
         anyone else, or any vetter's identifier."
    );
    println!("\n   (For the record, and only because this file kept score: {VETTING:?}.)");

    // --- replay -----------------------------------------------------------------------------------
    rule("8. The same proof again");
    let replayed = vtc
        .submit(&submission, now)
        .expect_err("the challenge was spent by the first one");
    println!("   {replayed}");
    println!(
        "\n   A proof verifies as often as it is submitted. What makes a submission unrepeatable\n   \
         is the challenge being the community's, and spent."
    );
}
