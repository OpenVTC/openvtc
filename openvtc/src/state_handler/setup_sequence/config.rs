/*! Contains specific Config extensions for the CLI Application. */

use affinidi_tdk::{TDK, messaging::profiles::ATMProfile, secrets_resolver::SecretsResolver};
use anyhow::{Result, bail};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek_bip32::ExtendedSigningKey;
use openvtc_core::{
    LF_ORG_DID, LF_PUBLIC_MEDIATOR_DID,
    config::{
        Config, ConfigProtectionType, ExportedConfig, KeyBackend, KeyTypes,
        account::{Account, KeyRef, PersonaId, PersonaRecord},
        derive_passphrase_key,
        protected_config::ProtectedConfig,
        public_config::PublicConfig,
        secured_config::{KeyInfoConfig, ProtectionMethod, passphrase_decrypt},
    },
    identity::IdentityContext,
    logs::{LogFamily, LogMessage, Logs},
};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    fs,
};
use tokio::sync::watch;

use crate::state_handler::{
    setup_sequence::{ConfigProtection, MessageType, SetupState},
    state::State,
};

pub trait ConfigExtension {
    /// Imports a backup of openvtc configuration settings from an encrypted file
    /// state: OpenVTC backend state
    /// state_tx: State update channel transmitter
    /// import_unlock_passphrase: Passphrase used to decrypt the imported configuration
    /// new_unlock_passphrase: New passphrase to protect the imported configuration
    /// file: Path to the file containing the exported configuration
    /// profile: Profile name to import the configuration into
    fn import(
        state: &mut State,
        state_tx: &watch::Sender<State>,
        import_unlock_passphrase: &SecretString,
        new_unlock_passphrase: &SecretString,
        file: &str,
        profile: &str,
    ) -> Result<()>;

    /// State A (R-A-5): build and persist an **account-only** Config from the VTA
    /// bootstrap state — no persona, no community, no `did:webvh`, no mediator.
    /// The runtime loads this to a "no active community" state until a join.
    async fn create_account(state: &SetupState, profile: &str) -> Result<Config>;

    /// State B: mint a persona (`did:webvh` + keys + mediator + runtime identity)
    /// into an existing account `config`, persist, and return its id. Used by the
    /// join flow (Stage 4) once a community has been chosen.
    ///
    /// The persona label/username is read from `state.username` — a name the
    /// *operator* chose (the setup wizard via `Action::SetUsername`, or the
    /// create-persona overlay). This replaces the previous
    /// `setup_flow.username.username` read so the join flow needn't construct a
    /// full `SetupFlow` UI component just to carry one string.
    ///
    /// An **empty** `username` mints the persona unlabelled and leaves
    /// `public.friendly_name` alone: the join flow has no operator-chosen name
    /// to offer, and the community name it used to pass here is not a name for
    /// the persona.
    async fn mint_persona_into(
        config: &mut Config,
        state: &SetupState,
        tdk: &TDK,
        profile: &str,
    ) -> Result<PersonaId>;
}

/// The operator-chosen name in `SetupState::username`, or `None` when there
/// isn't one.
///
/// Gates both the persona's `label` and the account's `public.friendly_name`.
/// The join flow used to pass the *community's* name here (falling back to a
/// rendering of the community's VTC DID when it had no verified name), which
/// labelled the persona with a community identifier and made the account's
/// self-display name the community it had just joined — the top bar then named
/// that community twice. A join now passes nothing and both fields are left
/// alone; only a name the operator actually typed sets them.
fn operator_chosen_name(username: &str) -> Option<&str> {
    let name = username.trim();
    (!name.is_empty()).then_some(name)
}

impl ConfigExtension for Config {
    /// Import previously exported configuration settings from an encrypted file
    fn import(
        state: &mut State,
        state_tx: &watch::Sender<State>,
        import_unlock_passphrase: &SecretString,
        new_unlock_passphrase: &SecretString,
        file: &str,
        profile: &str,
    ) -> Result<()> {
        let content = match fs::read_to_string(file) {
            Ok(content) => content,
            Err(e) => {
                state
                    .setup
                    .config_import
                    .messages
                    .push(MessageType::Error(format!(
                        "Couldn't read from file ({file}). Reason: {e}"
                    )));
                let _ = state_tx.send(state.clone());
                bail!("File read error");
            }
        };

        let decoded = match BASE64_URL_SAFE_NO_PAD.decode(content) {
            Ok(decoded) => decoded,
            Err(e) => {
                state
                    .setup
                    .config_import
                    .messages
                    .push(MessageType::Error(format!(
                        "Couldn't base64 decode file content. Reason: {e}"
                    )));
                let _ = state_tx.send(state.clone());
                bail!("base64 decoding error");
            }
        };

        // Exports are written by `passphrase_encrypt_v2` (v2: OPV2 magic +
        // random Argon2 salt embedded in the blob). `passphrase_decrypt`
        // auto-detects the format and falls back to the legacy v1
        // deterministic-salt KDF for pre-v2 export files.
        let decoded = passphrase_decrypt(
            import_unlock_passphrase.expose_secret().as_bytes(),
            b"openvtc-export-v1",
            &decoded,
        )?;

        let config: ExportedConfig = match serde_json::from_slice(&decoded) {
            Ok(config) => config,
            Err(e) => {
                state
                    .setup
                    .config_import
                    .messages
                    .push(MessageType::Error(format!(
                        "Couldn't deserialize configuration settings. Reason: {e}"
                    )));
                let _ = state_tx.send(state.clone());
                bail!("deserialization error");
            }
        };

        let bip32_seed = config
            .sc
            .bip32_seed
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Imported config missing BIP32 seed"))?;
        let bip32_root = ExtendedSigningKey::from_seed(
            BASE64_URL_SAFE_NO_PAD
                .decode(bip32_seed.expose_secret())
                .map_err(|e| anyhow::anyhow!("Couldn't base64 decode BIP32 seed: {e}"))?
                .as_slice(),
        )?;
        let private_seed = ProtectedConfig::get_seed(&bip32_root, "m/0'/0'/0'")?;

        let private = if let Some(private) = &config.pc.private {
            ProtectedConfig::load(&private_seed, private)?
        } else {
            ProtectedConfig::default()
        };

        config
            .pc
            .save(profile, &private, &private_seed)
            .map_err(|e| anyhow::anyhow!("Couldn't save Public Config: {e}"))?;

        #[cfg(feature = "openpgp-card")]
        {
            let state_clone = state.clone();
            let state_tx_clone = state_tx.clone();
            config
                .sc
                .save(
                    profile,
                    if let ConfigProtectionType::Token(token) = &config.pc.protection {
                        Some(token)
                    } else {
                        None
                    },
                    Some(
                        &derive_passphrase_key(
                            new_unlock_passphrase.expose_secret().as_bytes(),
                            b"openvtc-unlock-code-v1",
                        )?
                        .to_vec(),
                    ),
                    &move || {
                        let mut state_mut = state_clone.clone();
                        state_mut
                            .setup
                            .config_import
                            .messages
                            .push(MessageType::Info(
                                "Please touch token hardware to unlock keys".to_string(),
                            ));
                        let _ = state_tx_clone.send(state_mut);
                    },
                )
                .map_err(|e| anyhow::anyhow!("Couldn't save Secured Config: {e}"))?;
        }

        #[cfg(not(feature = "openpgp-card"))]
        config
            .sc
            .save(
                profile,
                if let ConfigProtectionType::Token(token) = &config.pc.protection {
                    Some(token)
                } else {
                    None
                },
                Some(
                    &derive_passphrase_key(
                        new_unlock_passphrase.expose_secret().as_bytes(),
                        b"openvtc-unlock-code-v1",
                    )?
                    .to_vec(),
                ),
            )
            .map_err(|e| anyhow::anyhow!("Couldn't save Secured Config: {e}"))?;

        Ok(())
    }

    async fn create_account(state: &SetupState, profile: &str) -> Result<Config> {
        let config = build_state_a_config(state)?;
        config.save(
            profile,
            #[cfg(feature = "openpgp-card")]
            &|| {
                eprintln!("Touch confirmation needed for decryption");
            },
        )?;
        Ok(config)
    }

    async fn mint_persona_into(
        config: &mut Config,
        state: &SetupState,
        tdk: &TDK,
        profile: &str,
    ) -> Result<PersonaId> {
        let mediator_did = if let Some(mediator) = &state.custom_mediator {
            mediator.to_string()
        } else {
            LF_PUBLIC_MEDIATOR_DID.to_string()
        };

        // Build key info from the persona keys created during this mint.
        let mut key_info = HashMap::new();
        let persona_keys = state
            .did_keys
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Persona DID keys not set during setup"))?;
        key_info.insert(
            persona_keys.signing.secret.id.clone(),
            KeyInfoConfig {
                path: persona_keys.signing.source.clone(),
                create_time: persona_keys.signing.created,
                purpose: KeyTypes::PersonaSigning,
            },
        );
        key_info.insert(
            persona_keys.authentication.secret.id.clone(),
            KeyInfoConfig {
                path: persona_keys.authentication.source.clone(),
                create_time: persona_keys.authentication.created,
                purpose: KeyTypes::PersonaAuthentication,
            },
        );
        key_info.insert(
            persona_keys.decryption.secret.id.clone(),
            KeyInfoConfig {
                path: persona_keys.decryption.source.clone(),
                create_time: persona_keys.decryption.created,
                purpose: KeyTypes::PersonaEncryption,
            },
        );

        // Build the runtime identity, mirroring `load_step2` so
        // `active_identity()` is consistent whether the Config came from setup
        // or from a load.
        let persona_did_str = state.webvh_address.did.to_string();
        let document = state.webvh_address.document.clone();
        let atm = tdk
            .atm
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("TDK ATM not initialized"))?;
        let persona_profile = ATMProfile::new(
            atm,
            Some("Persona DID".to_string()),
            persona_did_str.clone(),
            Some(mediator_did.clone()),
        )
        .await?;
        // Register the profile with the ATM (no socket) and load the persona's
        // secrets into the live secrets resolver, mirroring the config-load path
        // (`regenerate_persona_keys`). Without this a just-minted persona cannot
        // pack/unpack DIDComm in THIS session — packing authcrypt fails with
        // "sender has no usable key agreement key" because its X25519
        // key-agreement secret isn't in the resolver yet.
        let persona_profile = atm.profile_add(&persona_profile, false).await?;
        tdk.get_shared_state()
            .secrets_resolver()
            .insert(persona_keys.signing.secret.clone())
            .await;
        tdk.get_shared_state()
            .secrets_resolver()
            .insert(persona_keys.authentication.secret.clone())
            .await;
        tdk.get_shared_state()
            .secrets_resolver()
            .insert(persona_keys.decryption.secret.clone())
            .await;
        let persona_id = PersonaId::new();
        let persona_record = PersonaRecord {
            extra: serde_json::Map::new(),
            persona_id,
            did: persona_did_str.clone(),
            // Cache the minted document so the next startup skips the resolve.
            did_document: Some(document.clone()),
            key_refs: key_info
                .iter()
                .map(|(id, info)| KeyRef {
                    key_id: id.clone(),
                    purpose: info.purpose.clone(),
                    created_at: info.create_time,
                })
                .collect(),
            mediator_did: Some(mediator_did.clone()),
            origin_context_id: String::new(),
            created_at: Utc::now(),
            label: operator_chosen_name(&state.username).map(str::to_owned),
        };

        config.account.personas.insert(persona_id, persona_record);
        config.identities.insert(
            persona_id,
            IdentityContext {
                persona_id,
                did: persona_did_str,
                document,
                profile: persona_profile,
                mediator_did: Some(mediator_did),
            },
        );
        config.key_info.extend(key_info);
        // Only an operator-chosen name may become the account's self-display
        // name. The join flow passes nothing, so a join no longer overwrites
        // `friendly_name` with the community it was joining.
        if let Some(name) = operator_chosen_name(&state.username) {
            config.public.friendly_name = name.to_string();
        }

        config.save(
            profile,
            #[cfg(feature = "openpgp-card")]
            &|| {
                eprintln!("Touch confirmation needed for decryption");
            },
        )?;

        Ok(persona_id)
    }
}

/// Build the State-A account-only [`Config`] from the VTA bootstrap state
/// **without persisting it** (R-A-3/4/5). Pure — no disk or keyring I/O — so the
/// bootstrap shape (top context set; no persona, community, `did:webvh`,
/// mediator, or runtime identity) is unit-testable. `create_account` wraps this
/// with a `save`.
fn build_state_a_config(state: &SetupState) -> Result<Config> {
    let mut unlock_code = None;
    let protection = match &state.protection {
        ConfigProtection::PlainText => ConfigProtectionType::Plaintext,
        #[cfg(feature = "openpgp-card")]
        ConfigProtection::Token(token) => ConfigProtectionType::Token(token.to_string()),
        ConfigProtection::Passcode(unlock) => {
            unlock_code = Some(SecretBox::new(Box::new(unlock.expose_secret().to_vec())));
            ConfigProtectionType::Encrypted
        }
    };

    // Build VTA key backend from the admin credential issued during online
    // provisioning. The on-disk `credential_bundle` is the JSON form
    // (post-vta-sdk-0.5); confidentiality at rest is provided by the OS keyring /
    // secured config wrapper.
    let admin = state
        .vta
        .admin_credential
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("VTA admin credential not issued"))?;
    let bundle = vta_sdk::credentials::CredentialBundle::new(
        admin.admin_did.clone(),
        admin.admin_private_key_mb.clone(),
        state.vta.vta_did.clone(),
    )
    .vta_url(state.vta.vta_url.clone());
    let credential_raw = serde_json::to_string(&bundle)
        .map_err(|e| anyhow::anyhow!("Failed to serialise VTA credential bundle: {e}"))?;
    let encryption_seed = ProtectedConfig::get_seed_from_credential(&admin.admin_private_key_mb)?;
    let key_backend = KeyBackend::Vta {
        credential_bundle: SecretString::new(credential_raw.into()),
        credential_did: admin.admin_did.clone(),
        credential_private_key: SecretString::new(admin.admin_private_key_mb.clone().into()),
        vta_did: state.vta.vta_did.clone(),
        vta_url: state.vta.vta_url.clone(),
        mediator_did: state.vta.mediator_did.clone(),
        encryption_seed,
    };

    // Normally the account owns only the VTA relationship + top-level context:
    // no persona, no community, no runtime identity yet (R-A-5).
    //
    // A confirmed recovery replaces that with the account rebuilt from the
    // context — its personas and their verified memberships — while the VTA
    // relationship and protection choice still come from this run. The
    // credential is new (this install was authorised separately), and the
    // protection is whatever the operator picked here, so a recovered profile
    // is protected on THIS machine rather than inheriting anything.
    let recovered = state
        .vta
        .rebuild
        .as_ref()
        .and_then(|r| r.as_ref().ok())
        .filter(|o| !o.account.account.personas.is_empty());

    let mut key_info = HashMap::new();
    let account = match recovered {
        Some(outcome) => {
            key_info = outcome.account.key_info.clone();
            let mut account = outcome.account.account.clone();
            account.vta_did = state.vta.vta_did.clone();
            account.vta_url = state.vta.vta_url.clone();
            account.org_did = LF_ORG_DID.to_string();
            account
        }
        None => Account {
            vta_did: state.vta.vta_did.clone(),
            vta_url: state.vta.vta_url.clone(),
            top_context_id: state.vta.context_id.clone().unwrap_or_default(),
            org_did: LF_ORG_DID.to_string(),
            ..Account::default()
        },
    };

    Ok(Config {
        protected_key: None,
        integrity: Default::default(),
        account,
        identities: BTreeMap::new(),
        active_persona: None,
        runtime_trust_overrides: None,
        key_backend,
        public: PublicConfig {
            config_version: openvtc_core::config::public_config::CONFIG_VERSION,
            protection,
            private: None,
            logs: Logs {
                messages: VecDeque::from([LogMessage {
                    created: Utc::now(),
                    type_: LogFamily::Config,
                    message: "Account bootstrap completed".to_string(),
                }]),
                ..Default::default()
            },
            friendly_name: String::new(),
        },
        private: ProtectedConfig::default(),
        // Empty for a fresh account; for a recovery, the verification-method
        // → VTA-key mapping without which a rebuilt persona cannot sign.
        key_info,
        #[cfg(feature = "openpgp-card")]
        token_admin_pin: None,
        #[cfg(feature = "openpgp-card")]
        token_user_pin: SecretString::new(String::new().into()),
        protection_method: ProtectionMethod::default(),
        unlock_code,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::setup_sequence::VtaSetupState;
    use vta_sdk::provision_client::AdminCredentialReply;

    // --- operator-chosen name gate ---

    /// A name the operator typed labels the persona and becomes the account's
    /// self-display name.
    #[test]
    fn an_operator_chosen_name_is_used() {
        assert_eq!(operator_chosen_name("Glenn"), Some("Glenn"));
        assert_eq!(operator_chosen_name("  Glenn  "), Some("Glenn"));
    }

    /// The join flow passes nothing, so the persona is minted unlabelled and
    /// `friendly_name` is left alone — it must not inherit the community.
    #[test]
    fn no_name_leaves_both_fields_alone() {
        assert_eq!(operator_chosen_name(""), None);
        assert_eq!(operator_chosen_name("   "), None);
    }

    /// A `SetupState` carrying just the VTA bootstrap output an account needs:
    /// the admin credential, top context, and (plaintext) protection.
    fn bootstrap_state() -> SetupState {
        SetupState {
            protection: ConfigProtection::PlainText,
            vta: VtaSetupState {
                vta_did: "did:webvh:zVTASCID:vta.example.com".to_string(),
                vta_url: "https://vta.example.com".to_string(),
                context_id: Some("openvtc".to_string()),
                mediator_did: None,
                admin_credential: Some(AdminCredentialReply {
                    admin_did: "did:key:zAdmin".to_string(),
                    admin_private_key_mb: "zAdminPrivKeyMultibase".to_string(),
                }),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// A confirmed recovery must actually reach the written config — the
    /// rebuilt personas AND the key mapping, without which they cannot sign.
    #[test]
    fn a_confirmed_recovery_replaces_the_empty_account() {
        use openvtc_core::{
            rebuild::{RebuildPlan, RebuiltMembership, RebuiltPersona},
            rebuild_apply::{self, KeyCandidate, KeyPurposeHint},
        };

        const ALICE: &str = "did:webvh:QmA:example.com:alice";
        const VTC: &str = "did:webvh:QmV:vtc.example.com:acme";

        let plan = RebuildPlan {
            top_context_id: "openvtc".to_string(),
            personas: vec![RebuiltPersona {
                did: ALICE.to_string(),
                context_id: "openvtc".to_string(),
                mediator_did: Some("did:webvh:QmM:mediator.example.com".to_string()),
            }],
            memberships: vec![RebuiltMembership {
                vtc_did: VTC.to_string(),
                persona_did: ALICE.to_string(),
                credential: serde_json::json!({ "id": "vmc-1" }),
            }],
            rejected: Vec::new(),
            other_credential_count: 0,
        };
        let keys = vec![
            KeyCandidate {
                key_id: format!("{ALICE}#key-0"),
                label: None,
                key_type: KeyPurposeHint::Signing,
                created_at: chrono::Utc::now(),
            },
            KeyCandidate {
                key_id: format!("{ALICE}#key-1"),
                label: None,
                key_type: KeyPurposeHint::Encryption,
                created_at: chrono::Utc::now(),
            },
        ];
        let rebuilt = rebuild_apply::apply(&plan, &keys, chrono::Utc::now());

        let mut state = bootstrap_state();
        state.vta.rebuild = Some(Ok(crate::state_handler::setup_sequence::RebuildOutcome {
            plan,
            account: rebuilt,
        }));

        let cfg = build_state_a_config(&state).expect("build should succeed");

        assert_eq!(
            cfg.account.personas.len(),
            1,
            "the persona must be restored"
        );
        assert_eq!(
            cfg.account.memberships().count(),
            1,
            "the membership must be restored"
        );
        assert_eq!(
            cfg.key_info.len(),
            2,
            "without key_info a rebuilt persona cannot sign or receive"
        );

        // The VTA relationship still comes from THIS run — the recovering
        // install was authorised separately and holds its own credential.
        assert_eq!(cfg.account.vta_did, "did:webvh:zVTASCID:vta.example.com");
    }

    /// A plan that produced nothing usable must not hijack the fresh path —
    /// otherwise a failed recovery would silently write an empty account.
    #[test]
    fn an_unusable_recovery_falls_back_to_a_fresh_account() {
        use openvtc_core::{rebuild::RebuildPlan, rebuild_apply::RebuiltAccount};

        let mut state = bootstrap_state();
        state.vta.rebuild = Some(Ok(crate::state_handler::setup_sequence::RebuildOutcome {
            plan: RebuildPlan::default(),
            account: RebuiltAccount::default(),
        }));

        let cfg = build_state_a_config(&state).expect("build should succeed");
        assert!(cfg.account.personas.is_empty());
        assert_eq!(cfg.account.top_context_id, "openvtc");
    }

    /// A failed plan must leave the fresh path completely alone.
    #[test]
    fn a_failed_recovery_falls_back_to_a_fresh_account() {
        let mut state = bootstrap_state();
        state.vta.rebuild = Some(Err("access denied".to_string()));

        let cfg = build_state_a_config(&state).expect("build should succeed");
        assert!(cfg.account.personas.is_empty());
        assert_eq!(cfg.account.top_context_id, "openvtc");
    }

    // R-A-3/4/5: bootstrap yields an account-only v2 config — top context set, no
    // persona / community / runtime identity / did:webvh.
    #[test]
    fn state_a_config_is_account_only() {
        let cfg = build_state_a_config(&bootstrap_state()).expect("build should succeed");

        assert_eq!(
            cfg.public.config_version,
            openvtc_core::config::public_config::CONFIG_VERSION
        );
        assert_eq!(cfg.account.top_context_id, "openvtc");
        assert_eq!(cfg.account.vta_did, "did:webvh:zVTASCID:vta.example.com");

        // R-A-5: no persona, community, runtime identity, or persona key material.
        assert!(cfg.account.personas.is_empty(), "no persona at bootstrap");
        assert!(
            cfg.account.communities.is_empty(),
            "no community at bootstrap"
        );
        assert!(
            cfg.active_persona.is_none(),
            "no active persona at bootstrap"
        );
        assert!(
            cfg.identities.is_empty(),
            "no runtime identity at bootstrap"
        );
        assert!(
            cfg.key_info.is_empty(),
            "no persona key material at bootstrap"
        );

        // The only local secret is the account admin credential (D12).
        assert!(matches!(cfg.key_backend, KeyBackend::Vta { .. }));
    }

    // Plaintext protection stores no unlock code.
    #[test]
    fn state_a_plaintext_protection_has_no_unlock_code() {
        let cfg = build_state_a_config(&bootstrap_state()).unwrap();
        assert!(cfg.unlock_code.is_none());
        assert!(matches!(
            cfg.public.protection,
            ConfigProtectionType::Plaintext
        ));
    }

    // Bootstrap cannot proceed without the VTA-issued admin credential.
    #[test]
    fn state_a_requires_admin_credential() {
        let mut state = bootstrap_state();
        state.vta.admin_credential = None;
        assert!(build_state_a_config(&state).is_err());
    }
}
