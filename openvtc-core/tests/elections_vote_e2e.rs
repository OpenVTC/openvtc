//! A member votes in a community election, end to end, with every voter key held by the VTA.
//!
//! The VTA is a real one, in process (`MockVta`), driven through this client's own calls
//! (`openvtc_core::elections`) exactly as the TUI drives them. The community's registrar and the
//! ballot box are VTI's own (`vti_voting::registrar::Registrar`, `vti_voting::service::BallotBox`),
//! so what is checked is that what the VTA builds is what they accept:
//!
//! 1. the VTA builds the blinded ticket request (no `member`: the client signs the
//!    `vtc/elections/tickets/issue` document as the persona); the registrar signs it blind;
//! 2. the VTA takes the ticket, and refuses a second register as `ticketHeld`;
//! 3. the VTA builds the cast under a one-time key; the ballot box counts it;
//! 4. the ballot box's signed receipt is checked here (signer, thread, recipient) and kept by
//!    the VTA — and a receipt signed by anyone else is refused before it reaches the VTA.
//!
//! The HTTPS post to the ballot box is not exercised (the hardened client refuses loopback);
//! the receipt it would carry is built here as the ballot box answers it.
//!
//! `#[ignore]`'d like the other MockVta suites: spinning up the VTA is slow. CI's coverage job
//! runs them via `--include-ignored`.

use openvtc_core::elections::{
    self, AnswerDraft, BallotDraft, Cast, CastError, Kept, ReceiptOutcome, Registered, Request,
    ShownElection, Voter,
};
use serde_json::{Value, json};
use trust_tasks_rs::TrustTask;
use vta_sdk::client::{ClientIdentity, CreateContextRequest, VtaClient};
use vta_sdk::provision_client::EphemeralSetupKey;
use vta_sdk::trust_task_proof::TrustTaskVmResolver;
use vta_sdk::trust_task_sign::{HolderKey, sign_in_place_with};
use vta_service::test_support::MockVta;
use vti_vetting_pcs::scheme::{enc, point_from_text};
use vti_voting::{
    election::{Election, ElectionId},
    rand::{SeedableRng, rngs::StdRng},
    registrar::Registrar,
    rules::{digest_multibase, manifest_digest},
    service::BallotBox,
};

const COMMUNITY: &str = "did:webvh:QmVtcScid:elections-vtc.example";
const CONTEXT: &str = "voter";

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

/// The election releases written answers after 3 ballots: below the 10 VTI-VOT-065 advises and
/// above the 1 it allows, so the whole flow runs on the voting/_shared/0.3 manifest, which a 0.2
/// task would refuse.
fn manifest(ballot_box: &str) -> Value {
    let now = chrono::Utc::now();
    let t = |d: chrono::DateTime<chrono::Utc>| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    json!({
        "electionId": "agm-2027", "community": COMMUNITY, "title": "Annual general meeting",
        "questions": [
            { "key": "budget", "type": "choice", "text": "Approve the budget?",
              "options": [{ "key": "yes" }, { "key": "no" }],
              "minSelections": 1, "maxSelections": 1, "optional": false }
        ],
        "secrecy": "open", "roll": { "rule": "members" },
        "registrationOpensAt": t(now - chrono::Duration::days(2)),
        "votingOpensAt": t(now - chrono::Duration::hours(1)),
        "votingClosesAt": t(now + chrono::Duration::days(1)),
        "revote": "replace",
        "board": { "visibility": "public", "auditors": [] }, "ballotBox": ballot_box,
        "binding": false, "allowEarlyClose": false, "resultsBeforeClose": false,
        "textReleaseThreshold": 3
    })
}

/// The ballot box's signed answer to `cast`, as it answers over HTTPS.
async fn receipt(signer_did: &str, key: &HolderKey, cast: &Cast, payload: Value) -> Value {
    let mut doc: TrustTask<Value> = serde_json::from_value(json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": "https://trusttasks.org/spec/voting/ballot/cast/0.1#response",
        "issuer": signer_did,
        "recipient": cast.issuer(),
        "threadId": cast.id(),
        "issuedAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "payload": payload,
    }))
    .unwrap();
    sign_in_place_with(&mut doc, key).await.unwrap();
    serde_json::to_value(&doc).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "slow: spins up a VTA"]
async fn a_member_takes_a_ticket_then_votes_and_keeps_the_receipt() {
    let mock = MockVta::start_provisionable().await;
    let client = admin_client(&mock).await;
    client
        .create_context(CreateContextRequest {
            id: CONTEXT.into(),
            name: CONTEXT.into(),
            description: None,
            parent: None,
        })
        .await
        .expect("create the persona's context");

    // The community and its ballot box.
    let mut rng = StdRng::seed_from_u64(0xE1);
    let registrar = Registrar::generate(COMMUNITY, &mut rng).unwrap();
    let parameters =
        json!({ "suite": "ps-ddh-bls12381", "votingKey": registrar.public_text().unwrap() });
    let box_key = EphemeralSetupKey::generate().unwrap();
    let box_signer =
        HolderKey::from_did_key(&box_key.did, box_key.private_key_multibase()).unwrap();
    let m = manifest(&box_key.did);
    let digest = manifest_digest(&m).unwrap();
    let digest_text = digest_multibase(&digest);
    let shown = ShownElection::from_payload(json!({
        "manifest": m, "manifestDigest": digest_text, "state": "voting",
        "parameters": parameters,
        "disclosure": {
            "ballotBox": box_key.did, "ballotBoxOperator": "Example Ballots",
            "sameOperator": false, "boardVisibility": "public", "auditors": [],
            "revote": "replace", "coercionResistance": false
        },
        "checkpoints": []
    }))
    .expect("the community's show answer");
    assert!(
        shown.text_release_warning().is_some(),
        "VTI-VOT-090: the member is warned before taking the ticket"
    );
    let voter = Voter {
        vta: &client,
        context_id: CONTEXT,
        community: COMMUNITY,
    };

    // 1. The ticket request, built by the VTA, carried to the community as the persona.
    let Registered::Request(ticket) = elections::register(&voter, &shown).await.unwrap() else {
        panic!("no ticket held yet")
    };
    let sent = elections::build(
        &Request::IssueTicket(ticket.clone()),
        "did:key:z6MkPersona",
        COMMUNITY,
    )
    .unwrap();
    assert_eq!(sent.payload["manifestDigest"], json!(digest_text));
    let election = Election::new(COMMUNITY, ElectionId::new("agm-2027").unwrap(), digest).unwrap();
    let id = point_from_text(sent.payload["request"]["id"].as_str().unwrap()).unwrap();
    let blinded = serde_json::from_value(sent.payload["request"]["request"].clone()).unwrap();
    let pre = registrar
        .issue_ticket(&election, &id, &blinded, &mut rng)
        .expect("the registrar signs the ticket blind");
    let issued = json!({
        "electionId": "agm-2027",
        "label": sent.payload["request"]["label"],
        "preCredential": enc(&pre).unwrap(),
        "ext": { "org.example": {} }
    });

    // 2. The VTA takes the ticket; a second register is "already held".
    elections::accept(&voter, &shown, &issued)
        .await
        .expect("the VTA takes the ticket");
    assert_eq!(
        elections::register(&voter, &shown).await.unwrap(),
        Registered::AlreadyHeld
    );

    // 3. The ballot, built as the TUI builds it, cast under a one-time key.
    let mut draft = BallotDraft::new(shown.manifest());
    draft.answers[0].1 = AnswerDraft::Choice(vec!["yes".into()]);
    let ballot = draft.to_ballot(shown.election_id(), shown.manifest_digest());
    let cast = elections::vote(&voter, &shown, &ballot)
        .await
        .expect("the VTA builds the cast");
    assert_eq!(cast.document["recipient"], json!(box_key.did));
    assert!(
        cast.issuer().starts_with("did:key:") && cast.issuer() != "did:key:z6MkPersona",
        "VTI-VOT-003: the cast is not signed as the member"
    );

    let mut bb = BallotBox::new(&box_key.did);
    let now = chrono::Utc::now();
    bb.register(
        COMMUNITY,
        &json!({ "community": COMMUNITY, "manifest": m, "manifestDigest": digest_text,
                 "parameters": parameters }),
        now,
    )
    .expect("the ballot box registers the election");
    let counted = bb
        .cast(&cast.document["payload"], now)
        .expect("the ballot box counts the cast");

    // 4. The receipt: checked here, kept by the VTA.
    let answer = receipt(&box_key.did, &box_signer, &cast, counted.clone()).await;
    let resolver = TrustTaskVmResolver::default();
    let verified = elections::check_receipt(answer, &cast, &box_key.did, &resolver)
        .await
        .expect("the ballot box's receipt for this cast");
    assert_eq!(verified.outcome, ReceiptOutcome::Counted);
    assert_eq!(
        elections::keep_receipt(&voter, "agm-2027", &verified)
            .await
            .expect("the VTA keeps the receipt"),
        Kept::Kept
    );

    // A receipt signed by anyone else proves nothing, and never reaches the VTA.
    let other = EphemeralSetupKey::generate().unwrap();
    let other_signer = HolderKey::from_did_key(&other.did, other.private_key_multibase()).unwrap();
    let forged = receipt(&other.did, &other_signer, &cast, counted).await;
    assert!(matches!(
        elections::check_receipt(forged, &cast, &box_key.did, &resolver).await,
        Err(CastError::WrongSigner { .. })
    ));
}
