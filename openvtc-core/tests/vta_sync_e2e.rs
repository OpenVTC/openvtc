//! Account-state sync against a real in-process VTA.
//!
//! The unit tests in `vta_sync` run against an in-memory store written to the
//! app-state specification. This runs the same sync against `vta_service`'s
//! `MockVta`, so the wire contract — task URIs, payload shapes, the
//! `versionConflict` outcome, the change feed — is checked against the service
//! itself rather than our reading of it (R3.6).
//!
//! The scenario is the one users hit: archive a community on one machine,
//! open the same account on another, and find it archived there too.
//!
//! `#[ignore]`'d like the other MockVta tests: spinning up a VTA is slow.
//! CI's coverage job runs them via `--include-ignored`.

use std::collections::HashMap;

use chrono::Utc;
use openvtc_core::config::KeyTypes;
use openvtc_core::config::account::{
    Account, CommunityRecord, DecisionEvidence, KeyRef, PersonaId, PersonaRecord,
};
use openvtc_core::config::protected_config::ProtectedConfig;
use openvtc_core::config::secured_config::KeyInfoConfig;
use openvtc_core::vta_sync::{SyncParts, SyncReport, SyncState, sync_at_load};
use uuid::Uuid;
use vta_sdk::client::{ClientIdentity, CreateContextRequest, VtaClient};
use vta_sdk::provision_client::EphemeralSetupKey;
use vta_service::test_support::MockVta;

const CTX: &str = "openvtc-acct";
const VTC: &str = "did:webvh:scid:vtc.example.com";

#[derive(Default)]
struct Device {
    account: Account,
    private: ProtectedConfig,
    key_info: HashMap<String, KeyInfoConfig>,
    state: SyncState,
}

impl Device {
    async fn open(&mut self, client: &VtaClient) -> SyncReport {
        let mut parts = SyncParts {
            account: &mut self.account,
            private: &mut self.private,
            key_info: &mut self.key_info,
        };
        sync_at_load(client, &mut parts, &mut self.state, CTX).await
    }

    fn membership(&self) -> &CommunityRecord {
        self.account.memberships().next().expect("a membership")
    }
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "slow: spins up a provisionable VTA"]
async fn an_archive_on_one_device_is_there_when_another_opens() {
    let mock = MockVta::start_provisionable().await;
    let client = admin_client(&mock).await;
    client
        .create_context(CreateContextRequest {
            id: CTX.to_string(),
            name: "OpenVTC Account".to_string(),
            description: None,
            parent: None,
        })
        .await
        .expect("create top-level context");

    // Work around a VTA defect, not part of the scenario: on a namespace that
    // has never been written, `list` answers `highWatermark: 0`, which the
    // published schema forbids (`Version` has `minimum: 1`). A production VTA
    // sends it anyway and the sync reads it fine; MockVta's response
    // conformance check turns it into a 500. One write under a key no build
    // interprets moves the counter off zero. Drop this once VTI #2029 is fixed (it either omits
    // the member at zero or the schema admits it).
    client
        .app_state_put(
            CTX,
            openvtc_core::vta_sync::NAMESPACE,
            "e2e/seed",
            serde_json::json!({}),
            None,
        )
        .await
        .expect("seed the namespace");

    // Device A holds a persona and a membership the community declined.
    let mut a = Device::default();
    a.account.top_context_id = CTX.to_string();
    let persona = PersonaRecord {
        extra: serde_json::Map::new(),
        persona_id: PersonaId::new(),
        did: "did:webvh:scid:example.com:alice".to_string(),
        did_document: None,
        key_refs: vec![KeyRef {
            key_id: "key-alice".to_string(),
            purpose: KeyTypes::PersonaSigning,
            created_at: Utc::now(),
        }],
        mediator_did: None,
        origin_context_id: CTX.to_string(),
        created_at: Utc::now(),
        label: Some("alice".to_string()),
    };
    let mut membership = CommunityRecord::new_pending(
        VTC.to_string(),
        Some("Example".to_string()),
        format!("{CTX}/example"),
        persona.persona_id,
        Uuid::new_v4(),
        Utc::now(),
    );
    membership.reject(DecisionEvidence::default());
    let persona_id = persona.persona_id;
    a.account.personas.insert(persona_id, persona);
    a.account.add_membership(membership);

    let report = a.open(&client).await;
    assert!(report.error.is_none(), "first sync: {:?}", report.error);
    assert_eq!(report.pushed, 2, "persona and membership go up");

    // Device B opens the same account and gets both.
    let mut b = Device::default();
    let report = b.open(&client).await;
    assert!(report.error.is_none(), "{:?}", report.error);
    assert_eq!(report.pulled, 2);
    assert!(!b.membership().archived);

    // A archives the community, and B — opened again — sees it.
    a.account
        .archive_membership(VTC, persona_id)
        .expect("a declined membership may be archived");
    let report = a.open(&client).await;
    assert!(report.error.is_none(), "{:?}", report.error);
    assert_eq!(report.pushed, 1);

    let report = b.open(&client).await;
    assert!(report.error.is_none(), "{:?}", report.error);
    assert!(
        b.membership().archived,
        "the archive reached the other device"
    );

    // Concurrent edits to different fields: B stars it while A renames it.
    // B's push races A's, comes back with A's value, merges, and goes up.
    a.account.memberships_mut().next().unwrap().display_name = Some("Renamed".to_string());
    b.account.memberships_mut().next().unwrap().favourite = true;
    assert!(a.open(&client).await.error.is_none());
    let report = b.open(&client).await;
    assert!(report.error.is_none(), "{:?}", report.error);
    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    let m = b.membership();
    assert!(m.favourite && m.archived);
    assert_eq!(m.display_name.as_deref(), Some("Renamed"));

    assert!(a.open(&client).await.error.is_none());
    assert!(a.membership().favourite, "and the star reached A");

    mock.shutdown().await;
}
