//! Fixtures the feature tests share: a persona whose signing key resolves, so a
//! handler gets past its key lookup and signing and reaches its claim.
//!
//! The persona has no messaging listener and the TDK no mediator, so a send it
//! makes fails off the loop — which is the send-failure path the feature tests
//! pin.

use std::sync::Arc;

use affinidi_tdk::messaging::profiles::{ATMProfile, ATMProfileInner};
use affinidi_tdk::secrets_resolver::SecretsResolver;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use openvtc_core::config::KeyTypes;
use openvtc_core::config::account::{CommunityRecord, PersonaId, PersonaRecord};
use openvtc_core::config::secured_config::{KeyInfoConfig, KeySourceMaterial};

use super::super::Runtime;

/// Give the runtime a persona `did` whose authentication, assertion and
/// key-agreement keys all resolve to one Ed25519 key held by the TDK. Returns
/// its id.
pub(crate) async fn persona_with_keys(rt: &mut Runtime, did: &str) -> PersonaId {
    let persona = PersonaId::new();
    let kid = format!("{did}#key-1");
    let secret = Secret::generate_ed25519(Some(&kid), Some(&[9u8; 32]));
    rt.tdk
        .get_shared_state()
        .secrets_resolver()
        .insert(secret)
        .await;
    rt.config.key_info.insert(
        kid.clone(),
        KeyInfoConfig {
            path: KeySourceMaterial::Derived {
                path: "m/0'/0'/0'".into(),
            },
            create_time: chrono::Utc::now(),
            purpose: KeyTypes::PersonaAuthentication,
        },
    );
    rt.config.account.personas.insert(
        persona,
        PersonaRecord {
            extra: serde_json::Map::new(),
            persona_id: persona,
            did: did.into(),
            did_document: None,
            did_locator: None,
            key_refs: vec![],
            mediator_did: None,
            origin_context_id: "openvtc".into(),
            created_at: chrono::Utc::now(),
            label: None,
        },
    );
    let document = serde_json::from_value(serde_json::json!({
        "id": did,
        "authentication": [kid],
        "assertionMethod": [kid],
        "keyAgreement": [kid],
    }))
    .expect("a DID document naming the key");
    rt.config.identities.insert(
        persona,
        openvtc_core::identity::IdentityContext {
            persona_id: persona,
            did: did.to_string(),
            document,
            profile: Arc::new(ATMProfile {
                inner: Arc::new(ATMProfileInner {
                    did: did.to_string(),
                    alias: did.to_string(),
                    mediator: Arc::new(None),
                }),
            }),
            mediator_did: None,
        },
    );
    persona
}

/// Record `persona` as an Active member of `vtc`.
pub(crate) fn active_membership(rt: &mut Runtime, vtc: &str, persona: PersonaId) {
    let mut record = CommunityRecord::new_pending(
        vtc.into(),
        None,
        format!("openvtc/{}", uuid::Uuid::new_v4()),
        persona,
        uuid::Uuid::new_v4(),
        chrono::Utc::now(),
    );
    record.activate(chrono::Utc::now());
    rt.config.account.add_membership(record);
}

/// The persona's keys resolve: the fixture is what the feature tests rely on.
#[tokio::test]
async fn the_fixture_personas_keys_resolve() {
    let (mut rt, _h) = super::runtime().await;
    let persona = persona_with_keys(&mut rt, "did:key:zFixturePersona").await;
    let keys = rt
        .config
        .get_persona_keys_for(persona, &rt.tdk)
        .await
        .expect("keys resolve");
    assert_eq!(
        keys.authentication.secret.id,
        "did:key:zFixturePersona#key-1"
    );
    active_membership(&mut rt, "did:key:zFixtureVtc", persona);
    assert!(
        rt.config
            .account
            .membership("did:key:zFixtureVtc", persona)
            .is_some_and(|c| c.status.is_active())
    );
}

/// Give the runtime a persona whose DID is a freshly generated `did:key`,
/// held by the TDK: like [`persona_with_keys`], but what it signs also
/// verifies, because its DID resolves offline to the key that signed. Returns
/// its id and its DID.
pub(crate) async fn persona_with_did_key(rt: &mut Runtime) -> (PersonaId, String) {
    let (did, secret) =
        affinidi_tdk::dids::DID::generate_did_key(affinidi_tdk::dids::KeyType::Ed25519)
            .expect("did:key generates");
    let kid = secret.id.clone();
    rt.tdk
        .get_shared_state()
        .secrets_resolver()
        .insert(secret)
        .await;
    rt.config.key_info.insert(
        kid.clone(),
        KeyInfoConfig {
            path: KeySourceMaterial::Derived {
                path: "m/0'/0'/1'".into(),
            },
            create_time: chrono::Utc::now(),
            purpose: KeyTypes::PersonaAuthentication,
        },
    );
    let persona = PersonaId::new();
    let document = serde_json::from_value(serde_json::json!({
        "id": did,
        "authentication": [kid],
        "assertionMethod": [kid],
        "keyAgreement": [kid],
    }))
    .expect("a DID document naming the key");
    rt.config.identities.insert(
        persona,
        openvtc_core::identity::IdentityContext {
            persona_id: persona,
            did: did.clone(),
            document,
            profile: Arc::new(ATMProfile {
                inner: Arc::new(ATMProfileInner {
                    did: did.clone(),
                    alias: did.clone(),
                    mediator: Arc::new(None),
                }),
            }),
            mediator_did: None,
        },
    );
    (persona, did)
}
