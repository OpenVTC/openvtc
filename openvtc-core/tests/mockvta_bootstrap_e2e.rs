//! End-to-end State-A bootstrap exchange against a real in-process VTA.
//!
//! Drives the VTA-side of OpenVTC bootstrap against `vta_service`'s
//! `MockVta::start_provisionable()` — a real, listening VTA on a loopback
//! port with a self-resolving `did:key` identity (VTI#406/#427). Because the
//! mock can't be resolved *back* to its loopback URL, provisioning is driven
//! **URL-direct** (the seam OpenVTC's own bootstrap takes when `OPENVTC_VTA_URL`
//! is set): `provision_admin_rotated_via_rest` talks REST to `base_url()` with
//! the configured `vta_did()`, never re-resolving the DID.
//!
//! Scenarios:
//!
//!   * `admin_rotation_provisions_against_mock_vta` — the State-A admin
//!     rotation: an ephemeral setup `did:key` (authorized in the ACL via
//!     `grant_super_admin`, the `pnm acl create` step) drives
//!     `provision_admin_rotated_via_rest`, which returns a freshly-minted
//!     long-term admin DID + key (not the setup pair).
//!   * `bootstrap_creates_top_context_and_lists_webvh_server` — the rest of the
//!     State-A VTA surface: an authenticated client creates the account's
//!     top-level context and sees a seeded webvh hosting server in the catalogue.
//!   * `persona_did_webvh_mint_round_trips` — the State-B persona mint: against a
//!     `MockVta::start_with_webvh_host` (an in-process stub webvh host + a
//!     resolvable server DID), `create_did_webvh` mints a server-managed
//!     `did:webvh` persona.
//!
//! The DIDComm join-request submission + lifecycle resolution that follow
//! bootstrap are pure-mediator and covered in `join_lifecycle_e2e.rs`.
//!
//! All `#[ignore]`'d: spinning up the provisionable VTA + the provision
//! round-trip is slow. CI's coverage job runs them via `--include-ignored`.
//!
//! NOTE: depends on the `vta-service` git dev-dependency (the VTA server crate
//! is not on crates.io); its git source is allow-listed in `deny.toml`.

use vta_sdk::client::{ClientIdentity, CreateContextRequest, CreateDidWebvhRequest, VtaClient};
use vta_sdk::protocols::did_management::create::WebvhPathMode;
use vta_sdk::provision_client::{
    EphemeralSetupKey, ProvisionAsk, provision_admin_rotated_via_rest,
};
use vta_test_support::MockVta;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "slow: spins up a provisionable VTA + URL-direct admin-rotation round-trip"]
async fn admin_rotation_provisions_against_mock_vta() {
    let mock = MockVta::start_provisionable().await;
    assert!(
        mock.vta_did().starts_with("did:key:z6Mk"),
        "provisionable mock must expose a real, self-resolving did:key"
    );

    let setup = EphemeralSetupKey::generate().expect("generate setup key");
    // Authorize the ephemeral setup did:key as super-admin (the `pnm acl create`
    // step) so the provision gate accepts it — VTI#429's ergonomic seam.
    mock.grant_super_admin(&setup.did).await;

    // URL-direct: REST to base_url() with the configured vta_did, no DID→URL
    // resolution — the seam OpenVTC's bootstrap takes when OPENVTC_VTA_URL is set.
    let reply = provision_admin_rotated_via_rest(
        mock.base_url(),
        mock.vta_did(),
        setup.did.clone(),
        setup.private_key_multibase().to_string(),
        ProvisionAsk::vta_admin_rotated("ctx1"),
    )
    .await
    .expect("URL-direct admin rotation round-trips against MockVta");

    assert!(
        reply.admin_did.starts_with("did:key:"),
        "rotated admin must be a did:key, got {}",
        reply.admin_did
    );
    assert_ne!(
        reply.admin_did, setup.did,
        "rotation must mint a fresh admin DID, not echo the ephemeral setup DID"
    );
    assert!(
        !reply.admin_private_key_mb.is_empty(),
        "the rotated admin must carry its private key"
    );

    mock.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "slow: spins up a provisionable VTA"]
async fn bootstrap_creates_top_context_and_lists_webvh_server() {
    let mock = MockVta::start_provisionable().await;

    // Authenticated client. `mint_token` with an empty contexts vec is
    // super-admin (top-level context creation is super-admin only); it bypasses
    // the DIDComm-packed live handshake the REST-only mock can't unpack.
    //
    // The token authenticates the *connection*; from vta-sdk 0.31 a dispatched
    // Trust-Task document also needs an in-band `recipient` and a `proof` (SPEC
    // §7.2 items 5b/7a), which the client can only produce from a
    // `ClientIdentity`. So the admin is a real, self-resolving `did:key` whose
    // private key the client holds, and the token is minted for *that* DID —
    // item 6 rejects a document whose in-band issuer disagrees with the
    // identity the transport authenticated as.
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

    // State-A: create the account's top-level context.
    let ctx = client
        .create_context(CreateContextRequest {
            id: "openvtc-acct".to_string(),
            name: "OpenVTC Account".to_string(),
            description: None,
            parent: None,
        })
        .await
        .expect("create top-level context");
    assert_eq!(ctx.id, "openvtc-acct");

    // A webvh hosting server must be in the catalogue for a later persona
    // did:webvh mint to find one to publish to.
    mock.seed_webvh_server("prod", "did:webvh:host.example.com")
        .await;
    let servers = client
        .list_webvh_servers()
        .await
        .expect("list webvh servers");
    assert!(
        servers
            .servers
            .iter()
            .any(|s| s.id == "prod" && s.did == "did:webvh:host.example.com"),
        "seeded webvh server must appear in the catalogue, got {:?}",
        servers.servers
    );

    mock.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "slow: spins up a provisionable VTA + an in-process stub webvh host"]
async fn persona_did_webvh_mint_round_trips() {
    // `start_with_webvh_host` stands up an in-process stub webvh host and
    // registers a resolvable server DID under `WEBVH_SERVER_ID`, so a
    // server-managed mint publishes and resolves entirely in-process (VTI#431).
    let mock = MockVta::start_with_webvh_host().await;

    // Signed-document identity as above: a real `did:key` the client can sign
    // as, and a token minted for the same DID.
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

    // State-B: mint the persona did:webvh against the hosting server.
    let minted = client
        .create_did_webvh(CreateDidWebvhRequest {
            context_id: "ctx1".to_string(),
            server_id: Some(MockVta::WEBVH_SERVER_ID.to_string()),
            url: None,
            path: None,
            path_mode: Some(WebvhPathMode::AutoAssign),
            domain: None,
            label: None,
            portable: false,
            add_mediator_service: false,
            // This harness asserts the bootstrap round-trip, not document
            // shape; no mediator service is requested, so no TSP entry either.
            add_tsp_service: false,
            additional_services: None,
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
        .expect("create_did_webvh round-trips against the stub host");

    assert!(
        minted.did.starts_with("did:webvh:"),
        "expected a minted did:webvh, got {}",
        minted.did
    );
    assert_eq!(
        minted.server_id.as_deref(),
        Some(MockVta::WEBVH_SERVER_ID),
        "result records the server the persona was minted against"
    );
    assert!(!minted.scid.is_empty(), "minted DID must carry an SCID");

    mock.shutdown().await;
}
