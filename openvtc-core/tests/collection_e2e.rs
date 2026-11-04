//! A persona's collection claim, made at a real VTA (`MockVta`) through this client's own calls
//! (`openvtc_core::collection`), as a persona listener makes it before it connects
//! (VTI-NTF-080 – 084, `vta/collection/{claim,release}/0.1`).
//!
//! 1. A persona DID the VTA mints in a context, advertising a mediator, is claimed: the VTA
//!    grants a claim of the twenty-four hours asked, so the socket may connect.
//! 2. Claimed again by the same client, it is a renewal.
//! 3. Released (the socket closed first), it ends at once and can be claimed afresh.
//! 4. A DID the VTA holds no keys of is `notCollectable`: the VTA never collects for it, so
//!    connecting it evicts nobody.
//!
//! `#[ignore]`'d like the other MockVta suites: spinning up the VTA is slow. CI's coverage job
//! runs them via `--include-ignored`.

use affinidi_tdk::dids::{DID, KeyType};
use openvtc_core::collection::{self, ASKED_CLAIM_SECS, ClaimAnswer, CollectionTarget};
use serde_json::json;
use vta_sdk::client::{ClientIdentity, CreateContextRequest, CreateDidWebvhRequest, VtaClient};
use vta_sdk::protocols::did_management::create::WebvhPathMode;
use vta_sdk::provision_client::EphemeralSetupKey;
use vta_service::test_support::MockVta;

const CONTEXT: &str = "persona";

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "slow: spins up a provisionable VTA + an in-process stub webvh host"]
async fn a_persona_is_claimed_before_it_connects_renewed_and_released() {
    let mock = MockVta::start_with_webvh_host().await;
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

    // The persona, minted by the VTA and advertising a mediator: one the VTA collects for
    // unless a client claims it (VTI-NTF-080).
    let minted = client
        .create_did_webvh(CreateDidWebvhRequest {
            context_id: CONTEXT.to_string(),
            server_id: Some(MockVta::WEBVH_SERVER_ID.to_string()),
            url: None,
            path: None,
            path_mode: Some(WebvhPathMode::AutoAssign),
            domain: None,
            label: None,
            portable: false,
            add_mediator_service: false,
            add_tsp_service: false,
            additional_services: Some(vec![json!({
                "id": "#didcomm",
                "type": "DIDCommMessaging",
                "serviceEndpoint": [{ "uri": "did:web:mediator.example", "accept": ["didcomm/v2"] }]
            })]),
            pre_rotation_count: 0,
            did_document: None,
            did_log: None,
            set_primary: false,
            signing_key_id: None,
            ka_key_id: None,
            template: None,
            template_context: None,
            template_vars: Default::default(),
        })
        .await
        .expect("mint the persona DID");
    let persona = CollectionTarget {
        context_id: CONTEXT.into(),
        identifier: minted.did.clone(),
    };

    let before = chrono::Utc::now();
    let granted = collection::claim(&client, &persona, ASKED_CLAIM_SECS).await;
    let ClaimAnswer::Granted { ends_at, renewed } = granted else {
        panic!("the VTA grants a claim for its persona: {granted:?}");
    };
    assert!(!renewed, "a first claim is not a renewal");
    assert!(granted.may_connect());
    let lasts = ends_at - before;
    assert!(
        lasts <= chrono::Duration::seconds(ASKED_CLAIM_SECS + 5)
            && lasts >= chrono::Duration::seconds(ASKED_CLAIM_SECS - 60),
        "the twenty-four hours asked: {lasts}"
    );

    match collection::claim(&client, &persona, ASKED_CLAIM_SECS).await {
        ClaimAnswer::Granted { renewed: true, .. } => {}
        other => panic!("claimed again by its claimant, it is a renewal: {other:?}"),
    }

    collection::release(&client, &persona)
        .await
        .expect("the claimant releases its claim");
    match collection::claim(&client, &persona, ASKED_CLAIM_SECS).await {
        ClaimAnswer::Granted { renewed: false, .. } => {}
        other => panic!("released, the next claim is a fresh one: {other:?}"),
    }

    // A DID the VTA holds no keys of: it never collects for it.
    let (stranger, _) = DID::generate_did_key(KeyType::Ed25519).unwrap();
    let answer = collection::claim(
        &client,
        &CollectionTarget {
            context_id: CONTEXT.into(),
            identifier: stranger,
        },
        ASKED_CLAIM_SECS,
    )
    .await;
    assert_eq!(answer, ClaimAnswer::NotCollectable);

    mock.shutdown().await;
}
