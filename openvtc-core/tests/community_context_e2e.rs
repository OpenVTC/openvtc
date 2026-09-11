//! A community's context against a real in-process VTA: device access granted,
//! listed and revoked, and the context previewed and deleted with its subtree.
//!
//! These are the calls OpenVTC makes from the communities panel, checked
//! against the VTA's current contract rather than assumed (dev-guide R3.6):
//! `acl/grant` with a context scope and an expiry, `acl/list` read in the
//! subtree direction, `acl/show` + `acl/revoke`, `contexts/list`,
//! `contexts/preview-delete`, and `contexts/delete` with the cascade.
//!
//! `#[ignore]`'d like the other MockVta suites: spinning up the VTA is slow.
//! CI's coverage job runs them via `--include-ignored`.

use chrono::{Duration, Utc};
use openvtc_core::community_access::{
    Revoked, grant_device, list_device_grants, revoke_device_grant,
};
use openvtc_core::config::community_context::{
    delete_context, ensure_context, preview_context_deletion,
};
use vta_sdk::client::{ClientIdentity, CreateContextRequest, VtaClient};
use vta_sdk::provision_client::EphemeralSetupKey;
use vta_service::test_support::MockVta;

const TOP: &str = "openvtc-acct";
const ACME: &str = "openvtc-acct/acme";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "slow: spins up a provisionable VTA"]
async fn a_community_context_grants_devices_and_is_deleted_with_its_subtree() {
    let mock = MockVta::start_provisionable().await;
    // An authenticated admin client, exactly as the bootstrap suite builds one:
    // a self-resolving did:key holding its own key, with a token minted for it.
    let admin = EphemeralSetupKey::generate().expect("generate admin key");
    let token = mock.ctx.mint_token(&admin.did, "admin", vec![]).await;
    let client = VtaClient::authenticated(
        mock.base_url(),
        ClientIdentity::did_key(
            admin.did.clone(),
            admin.private_key_multibase(),
            mock.vta_did(),
        ),
        token,
    )
    .await;
    client
        .create_context(CreateContextRequest {
            id: TOP.to_string(),
            name: "OpenVTC Account".to_string(),
            description: None,
            parent: None,
        })
        .await
        .expect("create the account's top context");

    // A community context with a sub-context beneath it, and a sibling.
    assert!(
        ensure_context(&client, TOP, &format!("{ACME}/ci"), "ci")
            .await
            .expect("create the community context and its sub-context")
    );
    ensure_context(&client, TOP, "openvtc-acct/other", "other")
        .await
        .expect("create a sibling community context");

    // A device is granted `application` in the community's context, with an expiry.
    let device = EphemeralSetupKey::generate().expect("generate device key");
    let expires = Utc::now() + Duration::days(7);
    let grant = grant_device(
        &client,
        TOP,
        ACME,
        &device.did,
        "laptop — Acme (OpenVTC)",
        expires,
    )
    .await
    .expect("grant device access");
    assert_eq!(grant.role, "application");
    assert_eq!(grant.contexts, [ACME]);
    assert!(grant.elsewhere.is_empty());
    assert_eq!(
        grant.expires_at.map(|at| at.timestamp()),
        Some(expires.timestamp()),
        "the expiry the VTA recorded is the one asked for"
    );

    // One entry per DID: a second grant is refused, not widened.
    let again = grant_device(
        &client,
        TOP,
        "openvtc-acct/other",
        &device.did,
        "laptop",
        expires,
    )
    .await
    .expect_err("a DID already granted is not widened into another community");
    assert!(again.to_string().contains("already has access"), "{again}");

    // The subtree listing finds the grant in its community and not in the sibling.
    let listed = list_device_grants(&client, ACME)
        .await
        .expect("list device access in the community");
    assert_eq!(
        listed.iter().map(|g| g.did.as_str()).collect::<Vec<_>>(),
        [device.did.as_str()]
    );
    assert!(
        list_device_grants(&client, "openvtc-acct/other")
            .await
            .expect("list device access in the sibling")
            .is_empty()
    );

    // The preview names the sub-context the delete cascades to and the device's
    // entry it removes.
    let preview = preview_context_deletion(&client, TOP, ACME)
        .await
        .expect("preview deleting the community context");
    assert_eq!(
        preview.sub_contexts().collect::<Vec<_>>(),
        [format!("{ACME}/ci")]
    );
    assert!(
        preview.contexts[0]
            .acl_entries_removed
            .contains(&device.did),
        "the device's entry is in the preview: {:?}",
        preview.contexts[0]
    );

    // Revoked, it is gone from the listing.
    assert_eq!(
        revoke_device_grant(&client, ACME, &device.did)
            .await
            .expect("revoke device access"),
        Revoked::Deleted
    );
    assert!(
        list_device_grants(&client, ACME)
            .await
            .expect("list after revoking")
            .is_empty()
    );

    // The delete takes the sub-context with it and leaves the sibling alone.
    delete_context(&client, TOP, ACME)
        .await
        .expect("delete the community context");
    assert!(client.get_context(ACME).await.is_err());
    assert!(client.get_context(&format!("{ACME}/ci")).await.is_err());
    assert!(client.get_context("openvtc-acct/other").await.is_ok());

    // The top context is refused before the VTA is asked.
    assert!(delete_context(&client, TOP, TOP).await.is_err());
    assert!(client.get_context(TOP).await.is_ok());

    mock.shutdown().await;
}
