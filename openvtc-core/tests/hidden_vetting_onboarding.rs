//! Onboarding under a hidden-vetting criterion, end to end, with every PCS key held by the VTA.
//!
//! The VTA is a real one, in process (`MockVta`), driven through this client's own calls
//! (`openvtc_core::vetting::pcs_vta`) exactly as the TUI drives them. The community is the one
//! `vtc-service` runs (`vti_vetting_pcs::vtc::Vtc`), so what is checked is the real decision
//! path: what the VTA builds is what the community counts.
//!
//! In the order the people involved live it:
//!
//! 1. The community publishes its parameters in the manifest, under a namespace it controls,
//!    marked critical; the client reads them out of the criterion.
//! 2. Two vetters enrol and draw a tick of tokens — their VTA builds every request, the client
//!    carries it to the community and the answer back.
//! 3. The applicant's VTA creates the application; each vetter's VTA attests to its PCS
//!    identifier, and the applicant's VTA takes each attestation in.
//! 4. The applicant's VTA proves, bound to the community's challenge, and the community admits —
//!    without learning who vetted.
//!
//! `#[ignore]`'d like the other MockVta suites: spinning up the VTA is slow. CI's coverage job
//! runs them via `--include-ignored`.

use openvtc_core::vetting::hidden::{self, HiddenParams, Mode};
use openvtc_core::vetting::pcs_vta;
use openvtc_core::vetting::wire::pcs::{RootResponse, TokensResponse};
use serde_json::{Value, json};
use vta_sdk::client::{ClientIdentity, CreateContextRequest, VtaClient};
use vta_sdk::protocols::vetting::VETTED_PREDICATE;
use vta_sdk::provision_client::EphemeralSetupKey;
use vta_service::test_support::MockVta;
use vti_vetting_pcs::{
    issuer::{RootRequestWire, TokenRequestWire},
    rand::{SeedableRng, rngs::StdRng},
    scheme::{enc, key_text, point_from_text},
    vtc::Vtc,
    wire::SubmissionWire,
};

const COMMUNITY: &str = "did:webvh:QmVtcScid:kernel-vtc.example";
const PERIOD: &str = "2026-10";

fn requirements() -> Value {
    json!({
        "version": "0.1",
        "statementType": VETTED_PREDICATE,
        "minStatements": 2,
        "acceptedMethods": ["inPerson", "video"],
        "requiredClaims": ["name.legal"],
        "eligibleVetters": { "role": "vetter" }
    })
}

/// The criterion as the community publishes it: the named members, plus its parameters under
/// `vetting.ext`, marked critical so no client applies the wrong way.
fn published_criterion(vtc: &Vtc) -> Value {
    let mut vetting = requirements();
    vetting["ext"] = json!({
        hidden::HIDDEN_VETTING_NS: {
            "suite": hidden::SUITE,
            "helperKey": key_text(vtc.hvk()).unwrap(),
            "tokenKey": key_text(vtc.tvk()).unwrap(),
            "vetterLabels": vtc.live_periods().iter().map(|p| format!("vetter/{p}")).collect::<Vec<_>>(),
            "tokenLabels": [vtc.current_token_label()],
            "dripPerTick": vtc.drip_rate(),
            "tickLength": "P3D",
        }
    });
    vetting["extCritical"] = json!([hidden::HIDDEN_VETTING_NS]);
    json!({
        "id": "kernel-developer",
        "vetting": vetting,
        "requirementsDigest": vtc.requirements_digest(),
    })
}

/// What a vetter's statement says, as the desk builds it (`hidden::statement_meta`).
fn statement_meta(vtc: &Vtc, card: &str) -> Value {
    let today = chrono::Utc::now().date_naive();
    json!({
        "community": COMMUNITY,
        "requirementsDigest": vtc.requirements_digest(),
        "method": "inPerson",
        "claimsVerified": ["name.legal"],
        "livenessConfirmed": true,
        "declaredRelationship": "none",
        "identityCommitment": "z3Commitment",
        "cardDigestMultibase": card,
        "validFrom": today.to_string(),
        "validUntil": (today + chrono::Duration::days(90)).to_string(),
    })
}

async fn admin_client(mock: &MockVta) -> VtaClient {
    let admin = EphemeralSetupKey::generate().expect("generate admin key");
    let token = mock.ctx.mint_token(&admin.did, "admin", vec![]).await;
    VtaClient::authenticated(
        mock.base_url(),
        ClientIdentity::did_key(
            admin.did.clone(),
            admin.private_key_multibase(),
            mock.vta_did(),
        ),
        token,
    )
    .await
}

async fn context(client: &VtaClient, id: &str) {
    client
        .create_context(CreateContextRequest {
            id: id.to_string(),
            name: id.to_string(),
            description: None,
            parent: None,
        })
        .await
        .unwrap_or_else(|e| panic!("create context {id}: {e}"));
}

/// A vetter, enrolled with the community through its VTA and holding one tick of tokens. The
/// client's part is only carrying: each request the VTA builds goes to the community as the
/// wire carries it, and each answer comes back the same way.
async fn enrolled_vetter(
    client: &VtaClient,
    vtc: &mut Vtc,
    params: &HiddenParams,
    rng: &mut StdRng,
    ctx: &str,
    member: &str,
) {
    context(client, ctx).await;
    vtc.grant(member);
    let label = format!("vetter/{}", vtc.current_period());

    let request = pcs_vta::root_request(client, ctx, COMMUNITY, member, params, &label)
        .await
        .expect("the VTA builds the enrolment request");
    // On the wire to the community (`vtc/vetting/vetters/pcs-root`), as `wire::pcs_root_request`
    // carries it.
    let carried: RootRequestWire = serde_json::from_value(serde_json::to_value(&request).unwrap())
        .expect("the community reads what the client sends");
    let pre = vtc
        .issue_vetter_root(
            member,
            &point_from_text(&carried.id).unwrap(),
            &serde_json::from_value(carried.request).unwrap(),
            rng,
        )
        .expect("the community signs the blinded request");
    let view = pcs_vta::root_accept(
        client,
        ctx,
        COMMUNITY,
        params,
        &RootResponse {
            label: label.clone(),
            pre_credential: enc(&pre).unwrap(),
            ext: None,
        },
    )
    .await
    .expect("the VTA opens the community's answer");
    assert!(view.enrolled_for(vtc.current_period()), "{view:?}");

    let token_label = vtc.current_token_label().to_string();
    let draw = pcs_vta::tokens_request(
        client,
        ctx,
        COMMUNITY,
        params,
        &token_label,
        1,
        vtc.drip_rate(),
    )
    .await
    .expect("the VTA builds a draw");
    let requests: Vec<_> = draw
        .requests
        .iter()
        .map(|r| {
            TokenRequestWire {
                commitment: r.commitment.clone(),
                opening_proof: r.opening_proof.clone(),
            }
            .to_request()
            .unwrap()
        })
        .collect();
    let served = vtc
        .drip(member, 1, &token_label, &requests, rng)
        .expect("the community serves the draw");
    let (received, view) = pcs_vta::tokens_accept(
        client,
        ctx,
        COMMUNITY,
        params,
        &TokensResponse {
            label: token_label,
            tick: 1,
            pre_credentials: served.iter().map(|p| enc(p).unwrap()).collect(),
            ext: None,
        },
    )
    .await
    .expect("the VTA takes the tokens in");
    assert_eq!(usize::try_from(received).unwrap(), vtc.drip_rate());
    assert!(view.draws_in_flight.is_empty(), "{view:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "slow: spins up a VTA"]
async fn an_applicant_is_admitted_with_every_pcs_key_in_the_vta() {
    let mock = MockVta::start_provisionable().await;
    let client = admin_client(&mock).await;
    let mut rng = StdRng::seed_from_u64(0x2026_1013);
    let mut vtc = Vtc::new(COMMUNITY, PERIOD, requirements(), &mut rng).unwrap();

    // 1. What the community publishes, read the way the client reads a manifest's criterion.
    let params = match hidden::read_mode(&published_criterion(&vtc)).expect("readable") {
        Mode::Hidden(params) => *params,
        Mode::Named => panic!("the criterion publishes hidden-vetting parameters"),
    };

    // 2. Two vetters, each in a context of its own.
    for (ctx, member) in [
        ("vetter-a", "did:key:z6MkVetterA"),
        ("vetter-b", "did:key:z6MkVetterB"),
    ] {
        enrolled_vetter(&client, &mut vtc, &params, &mut rng, ctx, member).await;
    }

    // 3. The application, its identifier in each vetting request, an attestation from each.
    context(&client, "applicant").await;
    let application = pcs_vta::create_application(
        &client,
        "applicant",
        COMMUNITY,
        "did:key:z6MkApplicantJoin",
        &params,
    )
    .await
    .expect("the VTA creates the application");
    let ext = hidden::request_ext(hidden::SUITE, &application.id);
    let applicant_id = hidden::read_request_ext(Some(&ext))
        .unwrap()
        .expect("the vetter reads the identifier off the request");
    for (ctx, card) in [("vetter-a", "z3CardA"), ("vetter-b", "z3CardB")] {
        let attestation = pcs_vta::attest(
            &client,
            ctx,
            COMMUNITY,
            &params,
            &applicant_id,
            statement_meta(&vtc, card),
            None,
        )
        .await
        .expect("the vetter's VTA spends a token and attests");
        assert!(
            attestation.get("tokenSerial").is_none() && attestation.get("token").is_some(),
            "the `vetting/attestation/0.1` shape: {attestation}"
        );
        pcs_vta::verify_attestation(&client, &application.application_id, &params, &attestation)
            .await
            .expect("the applicant's VTA takes the attestation in");
    }
    let held = pcs_vta::show_application(&client, &application.application_id)
        .await
        .unwrap()
        .expect("the application is there");
    assert_eq!(held.attestations.len(), 2);
    assert!(
        held.attestations
            .iter()
            .all(|a| a.token_label == vtc.current_token_label()),
        "{held:?}"
    );

    // 4. The proof, bound to the community's challenge — and the community admits.
    let challenge = vtc.challenge(&mut rng);
    let proof = pcs_vta::prove(
        &client,
        &application.application_id,
        &params,
        vtc.requirements_digest(),
        &challenge,
    )
    .await
    .expect("the VTA proves");
    let submission: SubmissionWire = serde_json::from_value(proof).unwrap();
    let decision = vtc
        .submit(&submission.to_submission().unwrap(), chrono::Utc::now())
        .expect("the community verifies the proof");
    assert!(
        decision.evaluation.satisfied(),
        "two distinct hidden vetters satisfy the criterion: {:?}",
        decision.evaluation.needs
    );

    // A vetter that has attested sees it, and has spent the token.
    let vetter = pcs_vta::vetter_show(&client, "vetter-a", COMMUNITY)
        .await
        .unwrap()
        .expect("the engine is there");
    assert_eq!(vetter.attested, 1);
    assert_eq!(
        usize::try_from(vetter.tokens_held).unwrap(),
        vtc.drip_rate() - 1
    );

    // Done with: the application's key and attestations go.
    pcs_vta::delete_application(&client, &application.application_id)
        .await
        .unwrap();
    assert!(
        pcs_vta::show_application(&client, &application.application_id)
            .await
            .unwrap()
            .is_none()
    );
}

/// A refusal reaches the client as the code its specification declares, so the desk can say
/// "no token yet" rather than a failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "slow: spins up a VTA"]
async fn attesting_with_no_engine_is_refused_with_its_declared_code() {
    let mock = MockVta::start_provisionable().await;
    let client = admin_client(&mock).await;
    let mut rng = StdRng::seed_from_u64(7);
    let vtc = Vtc::new(COMMUNITY, PERIOD, requirements(), &mut rng).unwrap();
    let Mode::Hidden(params) = hidden::read_mode(&published_criterion(&vtc)).unwrap() else {
        panic!("hidden");
    };
    context(&client, "vetter").await;
    context(&client, "applicant").await;
    assert!(
        pcs_vta::vetter_show(&client, "vetter", COMMUNITY)
            .await
            .unwrap()
            .is_none(),
        "no engine before the first enrolment"
    );
    // Somebody real to attest to: the identifier is checked before the engine is looked up.
    let applicant = pcs_vta::create_application(
        &client,
        "applicant",
        COMMUNITY,
        "did:key:z6MkApplicantJoin",
        &params,
    )
    .await
    .unwrap();
    let refused = pcs_vta::attest(
        &client,
        "vetter",
        COMMUNITY,
        &params,
        &applicant.id,
        statement_meta(&vtc, "z3Card"),
        None,
    )
    .await
    .unwrap_err();
    assert!(refused.is_not_found(), "{refused}");
    // And a malformed identifier is said as such, by its own code.
    let refused = pcs_vta::attest(
        &client,
        "vetter",
        COMMUNITY,
        &params,
        "z3Nobody",
        statement_meta(&vtc, "z3Card"),
        None,
    )
    .await
    .unwrap_err();
    assert!(
        refused.is(pcs_vta::tasks::attest::v0_1::error_codes::APPLICANT_INVALID),
        "{refused}"
    );
}
