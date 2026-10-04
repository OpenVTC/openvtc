//! did-git-sign's credential against a real in-process VTA: granted for one
//! persona's context narrowed to `key-export`, proven by fetching the key, and
//! revoked — the calls the Repos panel makes when a member sets up signing
//! (dev-guide R3.6: checked against the VTA's current contract, not assumed).
//!
//! `#[ignore]`'d like the other MockVta suites: spinning up the VTA is slow.
//! CI's coverage job runs them via `--include-ignored`.

use openvtc_core::config::community_context::ensure_context;
use openvtc_core::git_signing::{
    PersonaSigner, SignerCredential, VtaEndpoint, grant_signer, revoke_signer, verify_signer,
};
use vta_sdk::client::{ClientIdentity, CreateContextRequest, CreateKeyRequest, VtaClient};
use vta_sdk::error::VtaError;
use vta_sdk::keys::KeyType;
use vta_sdk::provision_client::EphemeralSetupKey;
use vta_service::test_support::MockVta;

const TOP: &str = "openvtc-acct";
const ALICE: &str = "openvtc-acct/alice";
const BOB: &str = "openvtc-acct/bob";

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

/// An Ed25519 key in `ctx`, with its public half.
async fn key_in(client: &VtaClient, ctx: &str) -> (String, [u8; 32]) {
    let mut req = CreateKeyRequest::new(KeyType::Ed25519);
    req.context_id = Some(ctx.to_string());
    let key = client.create_key(req).await.expect("create key");
    let public = vta_sdk::did_key::decode_ed25519_public_key_multibase(&key.public_key)
        .expect("decode the key's public half");
    (key.key_id, public)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "slow: spins up a VTA and its mediator"]
async fn a_signer_is_granted_one_persona_proven_and_revoked() {
    // With its mediator: the VTA releases a private key only over a channel
    // confidential end to end, never REST — so the signer is proven over DIDComm,
    // as did-git-sign signs.
    let mock = MockVta::start_with_transports().await;
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
    context(&client, TOP).await;
    for (ctx, name) in [(ALICE, "alice"), (BOB, "bob")] {
        ensure_context(&client, TOP, ctx, name)
            .await
            .unwrap_or_else(|e| panic!("create {ctx}: {e}"));
    }
    let (alice_key, alice_pub) = key_in(&client, ALICE).await;
    let (bob_key, bob_pub) = key_in(&client, BOB).await;

    let endpoint = VtaEndpoint {
        vta_did: mock.vta_did().to_string(),
        vta_url: mock.base_url().to_string(),
        mediator_did: Some(mock.mediator_did().to_string()),
    };
    let alice = PersonaSigner {
        did_key_id: "did:webvh:alice#key-0".into(),
        vta_key_id: alice_key,
        verifying_key: alice_pub,
        context: ALICE.into(),
        label: "Alice".into(),
    };

    // Granted and proven: the new credential exports Alice's key.
    // The fixture's mediator admits only accounts registered with it.
    let cred = SignerCredential::generate().expect("mint");
    mock.register_mediator_account(&cred.did).await;
    grant_signer(&client, &cred, &alice, &endpoint, TOP)
        .await
        .expect("grant the signer Alice's context");
    let entry = client.get_acl(&cred.did).await.expect("the entry exists");
    assert_eq!(entry.allowed_contexts, vec![ALICE.to_string()]);
    assert_eq!(entry.capabilities(), vec!["key-export".to_string()]);

    // Narrowed to Alice: the same credential cannot take Bob's key.
    let as_bob = PersonaSigner {
        did_key_id: "did:webvh:bob#key-0".into(),
        vta_key_id: bob_key,
        verifying_key: bob_pub,
        context: BOB.into(),
        label: "Bob".into(),
    };
    assert!(
        verify_signer(&cred, &as_bob, &endpoint).await.is_err(),
        "a signer for Alice must not export Bob's key"
    );

    // openvtc's own credential is never revoked, whatever it is asked.
    assert!(
        !revoke_signer(&client, &admin.did, &admin.did)
            .await
            .unwrap()
    );

    // Revoked: gone, and it can no longer export.
    assert!(revoke_signer(&client, &cred.did, &admin.did).await.unwrap());
    assert!(matches!(
        client.get_acl(&cred.did).await,
        Err(VtaError::NotFound(_))
    ));
    assert!(verify_signer(&cred, &alice, &endpoint).await.is_err());
    // Revoking twice is not an error.
    assert!(!revoke_signer(&client, &cred.did, &admin.did).await.unwrap());

    // A key that is not the one the persona publishes is refused, and the
    // grant made for it is taken back.
    let impostor = PersonaSigner {
        verifying_key: bob_pub,
        ..alice.clone()
    };
    let other = SignerCredential::generate().expect("mint");
    mock.register_mediator_account(&other.did).await;
    let err = grant_signer(&client, &other, &impostor, &endpoint, TOP)
        .await
        .expect_err("a mismatched key is refused");
    assert!(err.to_string().contains("not the key"), "{err}");
    let left = client.list_acl(None).await.expect("list");
    assert!(
        left.entries.iter().all(|e| !e
            .label
            .as_deref()
            .unwrap_or_default()
            .contains("did-git-sign")),
        "a refused setup leaves no grant behind"
    );

    // The account context is never granted.
    let legacy = PersonaSigner {
        context: TOP.into(),
        ..alice
    };
    assert!(
        grant_signer(&client, &other, &legacy, &endpoint, TOP)
            .await
            .is_err()
    );
}
