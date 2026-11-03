//! A persona's received notification, handed to a real VTA (`MockVta`) through this client's
//! own calls (`openvtc_core::notifications`), as the TUI hands it over (VTI-NTF-054).
//!
//! 1. A community's signed `notifications/notify/0.1` goes to the VTA's
//!    `vta/notifications/deposit/0.1` as received. Addressed to a DID the VTA holds no keys of
//!    in the context, it is refused `notAddressedHere` — the VTA answered, so the deposit is
//!    [`Deposited::Refused`], never an unreachable VTA (which would leave the sender unanswered
//!    for its retry).
//! 2. The VTA's held election notifications are listed (`vta/notifications/list/0.1`), and a
//!    context holding none answers an empty list rather than an error.
//!
//! `#[ignore]`'d like the other MockVta suites: spinning up the VTA is slow. CI's coverage job
//! runs them via `--include-ignored`.

use affinidi_tdk::dids::{DID, KeyType};
use openvtc_core::notifications::{self, Deposited, NOTIFY_TYPE};
use serde_json::json;
use vta_sdk::client::{ClientIdentity, CreateContextRequest, VtaClient};
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
#[ignore = "slow: spins up a VTA"]
async fn a_received_notification_is_deposited_and_the_held_elections_listed() {
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

    // A community's notification of an election, addressed to a DID this VTA holds no keys
    // of: the VTA reads it and refuses it as not addressed here.
    let (community, key) = DID::generate_did_key(KeyType::Ed25519).unwrap();
    let (stranger, _) = DID::generate_did_key(KeyType::Ed25519).unwrap();
    let now = chrono::Utc::now();
    let t = |d: chrono::DateTime<chrono::Utc>| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let document = openvtc_core::trust_task_doc::build_signed_value(
        NOTIFY_TYPE,
        &community,
        &stranger,
        format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        json!({ "notification": {
            "notificationId": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "revision": 1,
            "kind": "election",
            "subject": {
                "heldBy": community,
                "id": "agm-2027",
                "openWith": "https://trusttasks.org/spec/vtc/elections/show/0.6"
            },
            "audience": community,
            "status": "available",
            "relayable": true,
            "validFrom": t(now + chrono::Duration::days(1)),
            "validUntil": t(now + chrono::Duration::days(8))
        }}),
        &key,
    )
    .await
    .unwrap();

    match notifications::deposit(&client, CONTEXT, &document).await {
        Ok(Deposited::Refused(code)) => assert!(
            code.contains("notAddressedHere"),
            "refused as not addressed here, not {code}"
        ),
        other => panic!("the VTA answers a deposit for a DID it does not hold: {other:?}"),
    }

    // Nothing is held in the context: an empty list, not an error.
    let held = notifications::list_elections(&client, CONTEXT)
        .await
        .expect("the VTA lists the context's held election notifications");
    assert!(held.is_empty());
}
