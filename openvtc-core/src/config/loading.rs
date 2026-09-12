//! Configuration loading logic (step 1 and step 2).

use crate::{
    config::{
        Config, ConfigProtectionType, KeyBackend, UnlockCode,
        account::{Account, PersonaId},
        integrity::{DegradedPersona, DegradedReason, LoadIntegrity, StrandedMembership},
        protected_config::ProtectedConfig,
        public_config::PublicConfig,
        secured_config::SecuredConfig,
    },
    errors::OpenVTCError,
};
use affinidi_tdk::{TDK, messaging::profiles::ATMProfile};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use ed25519_dalek_bip32::ExtendedSigningKey;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use std::collections::BTreeMap;
use tracing::{debug, info, warn};
use vta_sdk::credentials::CredentialBundle;

#[cfg(feature = "openpgp-card")]
use super::TokenInteractions;

/// Hierarchical startup-progress callback: invoked as `(major, sub)` when a new
/// sub-step of a major task begins, so the UI can build a two-level loading view
/// with per-step and per-major timing.
pub type ProgressFn<'a> = &'a (dyn Fn(&str, &str) + Send + Sync);

/// Decrypt the protected blob, trying each key a profile could legitimately be
/// sitting under, newest first. Returns the config and whether it needs re-keying.
///
/// Three keys, because all three are reachable in practice:
///
/// 1. **`stored`** — the profile's own D12 key. The normal case once migrated.
/// 2. **`legacy`** — the pre-D12 seed derived from the admin credential (or the
///    BIP32 root). Reached by a config written before D12, *and* by one whose
///    re-key was interrupted: `Config::save` writes the secured blob before the
///    public one, so a crash between them leaves the new key stored and the old
///    blob on disk. Trying `legacy` after `stored` is precisely what makes that
///    survivable rather than a lockout (R7).
/// 3. **`oldest`** — pre-0.1.4 BIP32 configs, which derived from the verifying
///    key. `None` for VTA-backed profiles, which never had that form.
///
/// Anything but (1) sets the re-key flag, and the next save rewrites the blob
/// under the stored key.
///
/// Extracted from `load_step2` so this decision is testable without a TDK, a
/// keyring, or a network — it is the one place a wrong answer locks a user out
/// of their own profile.
fn decrypt_protected_with_fallback(
    stored: Option<&SecretBox<Vec<u8>>>,
    legacy: &SecretBox<Vec<u8>>,
    oldest: Option<&SecretBox<Vec<u8>>>,
    blob: &str,
) -> Result<(ProtectedConfig, bool), OpenVTCError> {
    if let Some(seed) = stored {
        match ProtectedConfig::load(seed, blob) {
            Ok(cfg) => return Ok((cfg, false)),
            Err(e) => {
                debug!("stored config key did not decrypt ({e}); trying older seeds");
            }
        }
    }

    match ProtectedConfig::load(legacy, blob) {
        Ok(cfg) => {
            if stored.is_none() {
                info!("config predates its own encryption key; re-keying on next save (D12)");
            } else {
                warn!(
                    "config decrypted with the pre-D12 seed despite a stored key — a previous \
                     re-key was interrupted; completing it on next save"
                );
            }
            Ok((cfg, true))
        }
        Err(legacy_err) => {
            let Some(oldest) = oldest else {
                return Err(legacy_err);
            };
            match ProtectedConfig::load(oldest, blob) {
                Ok(cfg) => {
                    warn!(
                        "config was encrypted with the pre-0.1.4 seed — re-encrypting on next save"
                    );
                    Ok((cfg, true))
                }
                Err(e) => Err(e),
            }
        }
    }
}

/// Record a persona that could not be brought up, pulling its label and
/// creation time from the account so the report can name it the way the user
/// does rather than by DID alone.
///
/// Deliberately does **not** touch the account: the persona's record stays
/// exactly as it was. See `config::integrity` for why removing it would be the
/// wrong thing to do on the one path taken by an already-damaged profile.
fn record_degraded(
    integrity: &mut LoadIntegrity,
    account: &Account,
    persona_id: PersonaId,
    persona_did: &str,
    reason: DegradedReason,
) {
    let record = account.personas.get(&persona_id);
    warn!(
        persona = %persona_did,
        "persona unavailable this session: {}", reason.summary()
    );
    integrity.degraded_personas.push(DegradedPersona {
        persona_id,
        did: persona_did.to_string(),
        label: record.and_then(|p| p.label.clone()),
        created_at: record.map_or_else(chrono::Utc::now, |p| p.created_at),
        reason,
    });
}

/// Cross-check the account against what actually loaded.
///
/// Two mismatches matter, and both are the same interrupted write seen from
/// opposite sides: a membership whose persona did not load (so the community is
/// inert), and `key_info` entries for a DID no persona claims (so keys were
/// written and the account was not).
fn cross_check(integrity: &mut LoadIntegrity, account: &Account, key_ids: &[String]) {
    let unusable: std::collections::HashSet<PersonaId> = integrity
        .degraded_personas
        .iter()
        .map(|p| p.persona_id)
        .collect();

    for community in account.memberships() {
        if unusable.contains(&community.persona_ref) {
            integrity.stranded_memberships.push(StrandedMembership {
                vtc_did: community.vtc_did.to_string(),
                persona_id: community.persona_ref,
                label: community.display_name.clone(),
            });
        }
    }

    // A key id is `{did}#key-N`; it is ours if some persona owns that DID.
    // Relationship (R-DID) keys are `did:peer:...` and are not persona keys, so
    // they are excluded rather than reported as orphans.
    let persona_dids: std::collections::HashSet<&str> =
        account.personas.values().map(|p| p.did.as_str()).collect();
    for key_id in key_ids {
        let did = key_id.split('#').next().unwrap_or(key_id);
        if did.starts_with("did:webvh:") && !persona_dids.contains(did) {
            integrity.orphaned_key_ids.push(key_id.clone());
        }
    }
    integrity.orphaned_key_ids.sort();
}

impl Config {
    /// Step 1 of loading the configuration: reads the public config from disk.
    ///
    /// Use this to inspect [`PublicConfig::protection`] and determine what additional
    /// credentials (passphrase, OpenPGP card PIN, etc.) are needed for step 2.
    ///
    /// # Errors
    ///
    /// Returns an error if the public config file cannot be read or deserialized.
    pub fn load_step1(profile: &str) -> Result<PublicConfig, OpenVTCError> {
        PublicConfig::load(profile)
    }

    /// Step 2 of loading the configuration: decrypts secrets, resolves the DID,
    /// regenerates keys, and builds the full [`Config`].
    ///
    /// Requires the [`PublicConfig`] from [`Config::load_step1`] plus any unlock
    /// credentials determined by the protection type.
    ///
    /// On success returns the loaded [`Config`] **and** the still-open admin VTA
    /// session (PERF #1) so the caller can reuse the single mediator connection
    /// for the context-name fetch, relationship/community operations, and joins,
    /// instead of opening a second session. The session is `None` for non-VTA
    /// backends or a no-persona (State-A) account, where none was opened. The
    /// caller is then responsible for shutting it down on every exit path.
    ///
    /// Progress is reported hierarchically via `on_progress(major, sub)`: each
    /// call names the major task and the sub-step now starting, letting the UI
    /// build a two-level loading view with per-step and per-major timing.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption fails, the BIP32 seed or VTA credential
    /// bundle is invalid, DID resolution fails, key regeneration fails, or
    /// ATM profile creation fails.
    pub async fn load_step2(
        tdk: &mut TDK,
        profile: &str,
        public_config: PublicConfig,
        unlock_passphrase: Option<&UnlockCode>,
        #[cfg(feature = "openpgp-card")] token_user_pin: &SecretString,
        #[cfg(feature = "openpgp-card")] touch_prompt: &impl TokenInteractions,
        on_progress: Option<ProgressFn<'_>>,
    ) -> Result<(Self, Option<vta_sdk::client::VtaClient>), OpenVTCError> {
        use tracing::debug;

        fn report_progress(on_progress: &Option<ProgressFn<'_>>, major: &str, sub: &str) {
            if let Some(f) = on_progress {
                f(major, sub);
            }
        }

        report_progress(&on_progress, "Local configuration", "Decrypting secrets");

        let mut sc = SecuredConfig::load(
            profile,
            #[cfg(feature = "openpgp-card")]
            token_user_pin,
            if let ConfigProtectionType::Token(token) = &public_config.protection {
                Some(token)
            } else {
                None
            },
            unlock_passphrase,
            #[cfg(feature = "openpgp-card")]
            touch_prompt,
        )?;

        debug!(
            "Secured Config loaded (key_info entries: {})",
            sc.key_info.len()
        );

        // Determine key backend from secured config
        let key_backend = if let Some(ref bip32_seed) = sc.bip32_seed {
            // Legacy BIP32 config — call .expose_secret() to get the inner &str.
            let bip32_root = ExtendedSigningKey::from_seed(
                BASE64_URL_SAFE_NO_PAD
                    .decode(bip32_seed.expose_secret())?
                    .as_slice(),
            )
            .map_err(|e| {
                OpenVTCError::BIP32(format!(
                    "Couldn't get bip32 root from the secret seed material: {}",
                    e
                ))
            })?;
            KeyBackend::Bip32 {
                root: bip32_root,
                seed: bip32_seed.clone(),
            }
        } else if let Some(ref credential_bundle) = sc.credential_bundle {
            // VTA-managed config — expose only at the point of decoding.
            let bundle: CredentialBundle = serde_json::from_str(credential_bundle.expose_secret())
                .map_err(|e| {
                    OpenVTCError::Config(format!("Couldn't decode VTA credential bundle: {e}"))
                })?;
            let encryption_seed =
                ProtectedConfig::get_seed_from_credential(&bundle.private_key_multibase)?;
            KeyBackend::Vta {
                credential_bundle: credential_bundle.clone(),
                credential_did: bundle.did.clone(),
                credential_private_key: SecretString::new(
                    bundle.private_key_multibase.clone().into(),
                ),
                vta_did: sc.vta_did.clone().unwrap_or_default(),
                vta_url: sc.vta_url.clone().unwrap_or_default(),
                mediator_did: sc.mediator_did.clone(),
                encryption_seed,
            }
        } else {
            return Err(OpenVTCError::Config(
                "SecuredConfig has neither bip32_seed nor credential_bundle".to_string(),
            ));
        };

        // D12: the profile's own key encrypts `ProtectedConfig`, so the admin
        // credential is free to rotate and be re-issued to a recovering
        // install. `legacy_seed` is the pre-D12 derivation, kept as a
        // *decryption* fallback only.
        let legacy_seed = match &key_backend {
            KeyBackend::Bip32 { root, .. } => ProtectedConfig::get_seed(root, "m/0'/0'/0'")?,
            KeyBackend::Vta {
                encryption_seed, ..
            } => SecretBox::new(Box::new(encryption_seed.expose_secret().to_vec())),
        };
        let stored_key = sc.protected_key.clone();

        // Unencrypt the private config data, with migration from legacy seed
        //
        // Three keys are tried, newest first, because a profile can legitimately
        // be sitting under any of them:
        //   1. the stored D12 key — the normal case once migrated;
        //   2. the pre-D12 credential/BIP32-derived seed — a config written
        //      before D12, or one whose re-key was interrupted between the two
        //      writes `Config::save` makes (R7);
        //   3. the pre-0.1.4 BIP32 seed, which used the verifying key.
        // Succeeding on anything but (1) sets `needs_rekey`, and the next save
        // writes the blob back under the stored key.
        let (mut private_cfg, needs_rekey) = match &public_config.private {
            Some(blob) => {
                let stored_seed = stored_key
                    .as_ref()
                    .map(crate::config::decode_protected_key)
                    .transpose()?;
                let oldest_seed = match &key_backend {
                    KeyBackend::Bip32 { root, .. } => {
                        Some(ProtectedConfig::get_seed_legacy(root, "m/0'/0'/0'")?)
                    }
                    KeyBackend::Vta { .. } => None,
                };
                decrypt_protected_with_fallback(
                    stored_seed.as_ref(),
                    &legacy_seed,
                    oldest_seed.as_ref(),
                    blob,
                )?
            }
            // A profile with no protected blob yet still gets a key, so its
            // first write is already under the D12 scheme.
            None => (ProtectedConfig::default(), stored_key.is_none()),
        };

        // Mint the profile's own key now if it has none (or if a previous
        // re-key was interrupted); the next save persists it and rewrites the
        // protected blob under it.
        let protected_key = if needs_rekey || stored_key.is_none() {
            Some(crate::config::secured_config::new_protected_key())
        } else {
            stored_key
        };

        // Cached "this DID has no verifiable name" results do not survive a
        // restart — see `prune_agent_name_negatives`. The first refresh sweep
        // fires immediately after launch, so these re-resolve straight away.
        let pruned = private_cfg.prune_agent_name_negatives();
        if pruned > 0 {
            debug!("Discarded {pruned} cached agent-name negative(s); will re-resolve on launch");
        }

        log_private_config_shape(&private_cfg);

        // The v2 `account` persisted in the protected tier is the source of
        // truth. v1 (singleton) configs are reset before reaching here
        // (D13/R-RST), so a loadable config always carries an account.
        let account = private_cfg.account.clone();

        // Resolve runtime identities from the account's personas.
        //
        // A State-A (account-bootstrap, R-A-5) account persists with NO persona:
        // the app loads to a "no active community" state and a persona is minted
        // later in a State-B join. Such an account has no DID to resolve and no
        // persona/relationship messaging profiles to register, so the whole
        // resolve/keygen/profile block is skipped and `identities` stays empty.
        // A State-B account currently carries a single persona, resolved here.
        // The account's VTA mediator (captured at provisioning). Used as the
        // fallback below for any persona stored without one.
        let account_mediator = match &key_backend {
            KeyBackend::Vta { mediator_did, .. } => mediator_did.clone().unwrap_or_default(),
            KeyBackend::Bip32 { .. } => String::new(),
        };
        // Resolve a runtime identity for EVERY persona in the account, not just
        // the first: each persona gets its own DIDComm listener at runtime, so
        // all of them must be hydrated here (keys regenerated + an ATM messaging
        // profile registered). A State-A account has zero personas, so the loop
        // below never runs and `identities` stays empty.
        type PersonaSeed = (
            crate::config::account::PersonaId,
            std::sync::Arc<String>,
            String,
            Option<affinidi_tdk::did_common::Document>,
        );
        let personas: Vec<PersonaSeed> = account
            .personas
            .values()
            .map(|p| {
                // A persona minted before the mediator fix was stored with an
                // empty mediator, which leaves its DIDComm listener failing with
                // "No Mediator is configured" in an endless reconnect loop.
                // Repair it at load by falling back to the account's VTA mediator
                // — the persona DID was minted with the VTA's mediator service,
                // so they match — so an already-broken persona comes good on the
                // next launch with no re-join. (Runtime-only; the record is
                // rewritten on the next save.)
                let mediator = {
                    let stored = p.mediator_did.clone().unwrap_or_default();
                    if stored.is_empty() {
                        if account_mediator.is_empty() {
                            warn!(
                                persona = %p.did,
                                "persona has no mediator and the account has none either — \
                                 the persona listener will not connect"
                            );
                        } else {
                            warn!(
                                persona = %p.did,
                                "persona stored without a mediator — falling back to the \
                                 account VTA mediator"
                            );
                        }
                        account_mediator.clone()
                    } else {
                        stored
                    }
                };
                (
                    p.persona_id,
                    std::sync::Arc::new(p.did.clone()),
                    mediator,
                    // PERF #3: the cached DID document, used instead of a network
                    // resolve when present.
                    p.did_document.clone(),
                )
            })
            .collect();

        // Open the admin VTA session ONLY when there's a persona to rehydrate
        // (regenerate its keys + register messaging profiles). A State-A account
        // has none, so opening one here is useless — and opening it then shutting
        // it down right before `main_loop` opens its own admin session leaves the
        // shut-down session's auto-reconnect briefly dueling the live one on the
        // mediator (WebSocket churn → a dropped response on the first burst of
        // requests, e.g. the join's key creation). Skipping it leaves a single
        // admin session for the whole runtime.
        let vta_client = if matches!(&key_backend, KeyBackend::Vta { .. }) && !personas.is_empty() {
            report_progress(&on_progress, "VTA establishment", "Connecting to VTA");
            Some(super::build_runtime_vta_client(&key_backend).await?)
        } else {
            None
        };

        let mut identities = BTreeMap::new();

        // Hydrate every persona, then register relationship profiles once. The
        // whole block is wrapped in an inner future so that on ANY `?` error the
        // admin VTA session is shut down before the error propagates (a leaked
        // session trips the SDK `LeakGuard` and duels other sessions on the
        // mediator). On SUCCESS the session is returned to the caller alive
        // (PERF #1) — it is NOT shut down here.
        // Gathered rather than thrown: see `config::integrity`.
        let mut integrity = LoadIntegrity::default();

        let hydrate: Result<(), OpenVTCError> = async {
            for (persona_id, persona_did, persona_mediator, cached_document) in &personas {
                // Name the persona's messaging profile after its community AND
                // its own DID, so two personas in one community are still
                // distinguishable. Shares one helper
                // with the runtime label (`Config::persona_profile_label`) —
                // this used to be a second copy of the expression, which is how
                // the two could drift.
                //
                // No `Config` exists yet here, so the verified-name lookup goes
                // through `private_cfg` directly.
                let profile_label = crate::config::membership_profile_label(
                    account.memberships().find(|c| c.persona_ref == *persona_id),
                    persona_did,
                    |did| private_cfg.cached_agent_name(did).map(ToString::to_string),
                );

                // PERF #3: prefer the persisted persona DID document over a fresh
                // network resolve (~1s). did:webvh docs change rarely between
                // launches; a stale doc only matters if the persona rotated keys
                // out-of-band — rare, and recoverable on the next mint/resolve.
                let document = if let Some(doc) = cached_document.clone() {
                    report_progress(&on_progress, "Identity", "Loading DID document (cached)");
                    doc
                } else {
                    report_progress(&on_progress, "Identity", "Resolving DID document");
                    match tdk.did_resolver().resolve(persona_did).await {
                        Ok(resolved) => resolved.doc,
                        Err(e) => {
                            // Isolated, not fatal: this persona has no usable
                            // document, but the others may.
                            record_degraded(
                                &mut integrity,
                                &account,
                                *persona_id,
                                persona_did,
                                DegradedReason::DocumentUnresolvable {
                                    detail: e.to_string(),
                                },
                            );
                            continue;
                        }
                    }
                };

                // Final mediator resolution. If neither the persona record nor
                // the account carried a mediator, recover it from the DID
                // document itself — the persona DID was minted with a
                // DIDCommMessaging service whose endpoint IS the mediator, so it
                // is always authoritative. Without this the persona listener
                // fails with "No Mediator is configured" and reconnect-loops.
                let persona_mediator = if persona_mediator.is_empty() {
                    match super::did::mediator_from_document(&document) {
                        Some(m) => {
                            warn!(
                                persona = %persona_did,
                                mediator = %m,
                                "recovered persona mediator from its DID document"
                            );
                            m
                        }
                        None => {
                            warn!(
                                persona = %persona_did,
                                "persona has no mediator anywhere (record, account, \
                                 or DID document) — its listener will not connect"
                            );
                            persona_mediator.clone()
                        }
                    }
                } else {
                    persona_mediator.clone()
                };

                report_progress(&on_progress, "Identity", "Fetching persona keys");
                // THE isolation point. A persona recorded in the account with no
                // `key_info` — the signature of a save that wrote the config file
                // and then died before the credential store — used to return here
                // and fail the ENTIRE profile: every other persona, every
                // community, every relationship. Now it costs exactly the persona
                // that has the fault.
                if let Err(reason) = Config::regenerate_persona_keys(
                    tdk,
                    &sc,
                    &key_backend,
                    &document,
                    vta_client.as_ref(),
                )
                .await
                {
                    record_degraded(&mut integrity, &account, *persona_id, persona_did, reason);
                    continue;
                }

                report_progress(&on_progress, "Identity", "Building messaging profiles");
                // The ATM service itself is account-wide, not per persona: if it
                // is missing, no persona can work and degrading each in turn
                // would report the same fault N times as though N things broke.
                let atm = tdk.atm.clone().ok_or_else(|| {
                    OpenVTCError::Config("TDK ATM service not initialized".to_string())
                })?;
                let persona_profile = match ATMProfile::new(
                    &atm,
                    Some(profile_label.clone()),
                    persona_did.to_string(),
                    Some(persona_mediator.clone()),
                )
                .await
                {
                    Ok(profile) => profile,
                    Err(e) => {
                        record_degraded(
                            &mut integrity,
                            &account,
                            *persona_id,
                            persona_did,
                            DegradedReason::MessagingUnavailable {
                                detail: e.to_string(),
                            },
                        );
                        continue;
                    }
                };

                // Register the persona profile with the TDK ATM Service but do
                // NOT open a WebSocket — the DIDComm service owns connections.
                let persona_profile = match atm.profile_add(&persona_profile, false).await {
                    Ok(profile) => profile,
                    Err(e) => {
                        record_degraded(
                            &mut integrity,
                            &account,
                            *persona_id,
                            persona_did,
                            DegradedReason::MessagingUnavailable {
                                detail: e.to_string(),
                            },
                        );
                        continue;
                    }
                };

                identities.insert(
                    *persona_id,
                    crate::identity::IdentityContext {
                        persona_id: *persona_id,
                        did: persona_did.to_string(),
                        document,
                        profile: persona_profile,
                        mediator_did: Some(persona_mediator.clone()),
                    },
                );
            }

            // Register relationship (R-DID) profiles ONCE, excluding ALL persona
            // DIDs — including degraded ones, which are still ours and whose
            // relationships must not be re-registered under an R-DID profile.
            // Personas share the account VTA mediator, so any persona's mediator
            // works; take it from one that actually loaded, since a degraded
            // persona's mediator may be exactly what was wrong with it.
            // Registers each profile with the ATM service as a side-effect; the
            // returned map is no longer stored on `Config`.
            let relationship_mediator = identities
                .values()
                .find_map(|i| i.mediator_did.clone())
                .or_else(|| personas.first().map(|(_, _, m, _)| m.clone()));
            if let Some(first_mediator) = relationship_mediator.as_ref() {
                report_progress(&on_progress, "Identity", "Loading relationships");
                let our_p_dids: std::collections::HashSet<String> = personas
                    .iter()
                    .map(|(_, did, _, _)| did.to_string())
                    .collect();

                // Repair relationship (R-DID) `key_info` entries that older
                // builds persisted under pre-`did:peer`-mint placeholder ids,
                // BEFORE registering profiles below (which key off the canonical
                // `{r_did}#key-N` ids). Offline + idempotent; like the
                // seed-derivation migration above, the rewritten `key_info` is
                // persisted on the next save rather than forced here.
                let repair = private_cfg
                    .relationships
                    .repair_key_info_ids(tdk, &our_p_dids, &mut sc.key_info, &key_backend)
                    .await;
                if repair.changed() {
                    info!(
                        repaired = repair.repaired,
                        unrecoverable = repair.unrecoverable.len(),
                        "repaired relationship key ids; config will be rewritten on next save"
                    );
                    for r_did in &repair.unrecoverable {
                        warn!(r_did = %r_did,
                            "relationship has unrecoverable keys and must be re-established");
                    }
                }

                private_cfg
                    .relationships
                    .generate_profiles(
                        tdk,
                        &our_p_dids,
                        first_mediator,
                        &key_backend,
                        &sc.key_info,
                        vta_client.as_ref(),
                    )
                    .await?;
            }
            Ok(())
        }
        .await;

        // On ERROR, close the admin session before propagating (a leaked session
        // would duel others on the mediator). On SUCCESS, the session is returned
        // to the caller alive (PERF #1) and is NOT shut down here.
        if let Err(e) = hydrate {
            if let Some(client) = &vta_client {
                client.shutdown().await;
            }
            return Err(e);
        }

        // Cross-check what the account claims against what came up. Runs after
        // hydration because it needs the degraded set, and before `Config` is
        // built so the report travels with the config it describes.
        let key_ids: Vec<String> = sc.key_info.keys().cloned().collect();
        cross_check(&mut integrity, &account, &key_ids);
        if !integrity.is_clean() {
            warn!(
                degraded = integrity.degraded_personas.len(),
                stranded = integrity.stranded_memberships.len(),
                orphaned = integrity.orphaned_key_ids.len(),
                "profile loaded with problems; the user is asked to acknowledge them"
            );
        }

        Ok((
            Config {
                account,
                identities,
                integrity,
                protected_key,
                active_persona: None,
                runtime_trust_overrides: None,
                key_backend,
                public: public_config,
                private: private_cfg,
                key_info: sc.key_info.clone(),
                #[cfg(feature = "openpgp-card")]
                token_admin_pin: None,
                #[cfg(feature = "openpgp-card")]
                token_user_pin: token_user_pin.clone(),
                protection_method: sc.protection_method.clone(),
                unlock_code: unlock_passphrase
                    .map(|uc| SecretBox::new(Box::new(uc.0.expose_secret().to_owned()))),
            },
            // PERF #1: hand the still-open admin session back to the caller for
            // reuse (context-name fetch, relationships, joins). `vta_client` is
            // `Some` only for a VTA backend with an active persona.
            vta_client,
        ))
    }
}

/// Log the *shape* (collection sizes only) of the decrypted private config.
///
/// Deliberately never logs the contents: the protected tier holds contacts
/// (DIDs + aliases), the full relationship graph, tasks, and credential
/// claims, and the tracing sink can be a plaintext file on disk
/// (`OPENVTC_DEBUG_LOG`). Counts are enough for debugging load issues.
fn log_private_config_shape(private_cfg: &ProtectedConfig) {
    tracing::debug!(
        contacts = private_cfg.contacts.contacts.len(),
        relationships = private_cfg.relationships.relationships.len(),
        tasks = private_cfg.tasks.tasks.len(),
        vrcs_issued = private_cfg.vrcs_issued.keys().len(),
        vrcs_received = private_cfg.vrcs_received.keys().len(),
        "private config loaded"
    );
}

#[cfg(test)]
mod protected_key_fallback_tests {
    //! D12/R7 — the key-fallback decision. A wrong answer here locks a user out
    //! of their own profile, so every reachable combination is pinned.
    use super::*;
    use crate::config::secured_config::new_protected_key;

    fn seed(byte: u8) -> SecretBox<Vec<u8>> {
        SecretBox::new(Box::new(vec![byte; 32]))
    }

    fn blob_under(seed: &SecretBox<Vec<u8>>) -> String {
        let mut cfg = ProtectedConfig::default();
        cfg.account.top_context_id = "marker".to_string();
        cfg.save(seed).expect("encrypt")
    }

    /// The normal, migrated case: stored key decrypts, nothing to re-key.
    #[test]
    fn a_stored_key_decrypts_and_needs_no_rekey() {
        let stored = seed(1);
        let blob = blob_under(&stored);
        let (cfg, rekey) =
            decrypt_protected_with_fallback(Some(&stored), &seed(2), None, &blob).expect("decrypt");
        assert_eq!(cfg.account.top_context_id, "marker");
        assert!(!rekey);
    }

    /// A config written before D12: no stored key, legacy seed decrypts, and it
    /// must be flagged for re-keying.
    #[test]
    fn a_pre_d12_config_falls_back_and_is_flagged() {
        let legacy = seed(2);
        let blob = blob_under(&legacy);
        let (cfg, rekey) =
            decrypt_protected_with_fallback(None, &legacy, None, &blob).expect("decrypt");
        assert_eq!(cfg.account.top_context_id, "marker");
        assert!(rekey, "a pre-D12 config must be re-keyed");
    }

    /// **R7.** `Config::save` writes the secured blob before the public one, so
    /// a crash between them leaves the NEW key stored and the OLD blob on disk.
    /// The user must still get in.
    #[test]
    fn an_interrupted_rekey_still_opens_the_profile() {
        let legacy = seed(2);
        let blob = blob_under(&legacy);
        // The new key was persisted; the blob was not rewritten.
        let stored = crate::config::decode_protected_key(&new_protected_key()).expect("decode");

        let (cfg, rekey) = decrypt_protected_with_fallback(Some(&stored), &legacy, None, &blob)
            .expect("an interrupted re-key must not lock the user out");
        assert_eq!(cfg.account.top_context_id, "marker");
        assert!(
            rekey,
            "the interrupted re-key must be completed on next save"
        );
    }

    /// Pre-0.1.4 BIP32 configs used the verifying key. Still reachable.
    #[test]
    fn the_oldest_bip32_seed_is_still_tried() {
        let oldest = seed(3);
        let blob = blob_under(&oldest);
        let (cfg, rekey) =
            decrypt_protected_with_fallback(Some(&seed(1)), &seed(2), Some(&oldest), &blob)
                .expect("decrypt");
        assert_eq!(cfg.account.top_context_id, "marker");
        assert!(rekey);
    }

    /// A blob under none of the keys is an error, not a silent empty config —
    /// returning a default would present an account with no personas as though
    /// that were the truth.
    #[test]
    fn an_undecryptable_blob_is_an_error_not_an_empty_config() {
        let blob = blob_under(&seed(9));
        let err = decrypt_protected_with_fallback(Some(&seed(1)), &seed(2), Some(&seed(3)), &blob);
        assert!(err.is_err(), "must not fabricate an empty account");
    }

    /// A VTA-backed profile has no pre-0.1.4 form, so the legacy failure is
    /// what surfaces — not a confusing error about a seed that never applied.
    #[test]
    fn a_vta_profile_reports_the_legacy_failure() {
        let blob = blob_under(&seed(9));
        let err =
            decrypt_protected_with_fallback(None, &seed(2), None, &blob).expect_err("should fail");
        assert!(
            matches!(err, OpenVTCError::Decrypt(_)),
            "unexpected error: {err}"
        );
    }
}

#[cfg(test)]
mod integrity_tests {
    //! The cross-check that turns a half-written save into a report instead of
    //! a fatal load. The hydration path itself needs a live TDK and a VTA, so
    //! what is pinned here is the consistency logic that decides what the user
    //! is told.
    use super::*;
    use crate::config::account::{CommunityRecord, CommunityStatus, PersonaRecord, VtcDid};
    use uuid::Uuid;

    const ALICE: &str = "did:webvh:QmAlice:example.com:alice";
    const BOB: &str = "did:webvh:QmBob:example.com:bob";
    const GHOST: &str = "did:webvh:QmGhost:example.com:ghost";

    fn persona(did: &str) -> (PersonaId, PersonaRecord) {
        let persona_id = PersonaId(Uuid::new_v4());
        (
            persona_id,
            PersonaRecord {
                extra: serde_json::Map::new(),
                persona_id,
                did: did.to_string(),
                did_document: None,
                key_refs: Vec::new(),
                mediator_did: None,
                origin_context_id: "top".to_string(),
                created_at: chrono::Utc::now(),
                label: None,
            },
        )
    }

    fn account_with(personas: Vec<(PersonaId, PersonaRecord)>) -> Account {
        let mut account = Account::default();
        for (id, record) in personas {
            account.personas.insert(id, record);
        }
        account
    }

    fn active_membership(account: &mut Account, vtc: &str, persona_ref: PersonaId, name: &str) {
        let vtc_did = VtcDid::from(vtc.to_string());
        let mut record = CommunityRecord::new_pending(
            vtc_did.clone(),
            Some(name.to_string()),
            "top/sub".to_string(),
            persona_ref,
            Uuid::new_v4(),
            chrono::Utc::now(),
        );
        record.status = CommunityStatus::Active;
        account.communities.insert(vtc_did, vec![record]);
    }

    fn degraded(persona_id: PersonaId, did: &str) -> DegradedPersona {
        DegradedPersona {
            persona_id,
            did: did.to_string(),
            label: None,
            created_at: chrono::Utc::now(),
            reason: DegradedReason::MissingKeyInfo {
                key_id: format!("{did}#key-1"),
            },
        }
    }

    #[test]
    fn a_healthy_account_cross_checks_clean() {
        let (alice_id, alice) = persona(ALICE);
        let mut account = account_with(vec![(alice_id, alice)]);
        active_membership(
            &mut account,
            "did:webvh:QmV:vtc.example.com:c",
            alice_id,
            "C",
        );

        let mut integrity = LoadIntegrity::default();
        cross_check(
            &mut integrity,
            &account,
            &[format!("{ALICE}#key-1"), format!("{ALICE}#key-2")],
        );
        assert!(integrity.is_clean(), "{integrity:?}");
    }

    /// The point of the whole change: one degraded persona strands only its own
    /// membership. Bob and his community must be untouched.
    #[test]
    fn a_degraded_persona_strands_only_its_own_membership() {
        let (alice_id, alice) = persona(ALICE);
        let (bob_id, bob) = persona(BOB);
        let mut account = account_with(vec![(alice_id, alice), (bob_id, bob)]);
        active_membership(
            &mut account,
            "did:webvh:QmV:vtc.example.com:a",
            alice_id,
            "A",
        );
        active_membership(&mut account, "did:webvh:QmV:vtc.example.com:b", bob_id, "B");

        let mut integrity = LoadIntegrity {
            degraded_personas: vec![degraded(alice_id, ALICE)],
            ..Default::default()
        };
        cross_check(
            &mut integrity,
            &account,
            &[format!("{ALICE}#key-1"), format!("{BOB}#key-1")],
        );

        assert_eq!(integrity.stranded_memberships.len(), 1);
        assert_eq!(integrity.stranded_memberships[0].persona_id, alice_id);
        assert_eq!(
            integrity.stranded_memberships[0].label.as_deref(),
            Some("A")
        );
        assert!(integrity.orphaned_key_ids.is_empty());
    }

    /// The mirror image of the interrupted write: keys landed, the account did
    /// not. The keys belong to a persona the account has never heard of.
    #[test]
    fn keys_for_an_unknown_persona_are_reported_as_orphans() {
        let (alice_id, alice) = persona(ALICE);
        let account = account_with(vec![(alice_id, alice)]);

        let mut integrity = LoadIntegrity::default();
        cross_check(
            &mut integrity,
            &account,
            &[
                format!("{ALICE}#key-1"),
                format!("{GHOST}#key-1"),
                format!("{GHOST}#key-2"),
            ],
        );

        assert_eq!(integrity.orphaned_key_ids.len(), 2);
        assert!(integrity.orphaned_key_ids[0].starts_with(GHOST));
        assert!(integrity.has_incomplete_write());
    }

    /// Relationship keys are `did:peer:` and belong to no persona by design.
    /// Reporting them as orphans would cry wolf on every healthy profile that
    /// has ever formed a relationship.
    #[test]
    fn relationship_keys_are_not_mistaken_for_orphans() {
        let (alice_id, alice) = persona(ALICE);
        let account = account_with(vec![(alice_id, alice)]);

        let mut integrity = LoadIntegrity::default();
        cross_check(
            &mut integrity,
            &account,
            &[
                format!("{ALICE}#key-1"),
                "did:peer:2.Ez6LS.Vz6Mk#key-1".to_string(),
                "did:peer:2.Ez6LS.Vz6Mk#key-2".to_string(),
            ],
        );
        assert!(integrity.is_clean(), "{integrity:?}");
    }

    /// A membership whose persona loaded fine is never stranded, even when some
    /// *other* persona is degraded.
    #[test]
    fn a_healthy_persona_keeps_its_membership_when_another_is_degraded() {
        let (alice_id, alice) = persona(ALICE);
        let (bob_id, bob) = persona(BOB);
        let mut account = account_with(vec![(alice_id, alice), (bob_id, bob)]);
        active_membership(&mut account, "did:webvh:QmV:vtc.example.com:b", bob_id, "B");

        let mut integrity = LoadIntegrity {
            degraded_personas: vec![degraded(alice_id, ALICE)],
            ..Default::default()
        };
        cross_check(&mut integrity, &account, &[]);
        assert!(integrity.stranded_memberships.is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::protected_config::Contact,
        relationships::{Relationship, RelationshipState},
    };
    use std::{
        io::Write,
        sync::{Arc, Mutex},
    };

    /// `MakeWriter` that appends all output to a shared buffer so the test
    /// can inspect exactly what the tracing layer emitted.
    #[derive(Clone, Default)]
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedWriter {
        type Writer = SharedWriter;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Regression test for the privacy finding where the entire decrypted
    /// `ProtectedConfig` (contacts, relationships, tasks, credentials) was
    /// pretty-printed to the debug log. The load-path log statement must emit
    /// shape information only — none of the sensitive field values may leak.
    #[test]
    fn private_config_shape_log_does_not_leak_contents() {
        const MARKER: &str = "MARKER_MUST_NOT_LEAK";

        let mut private_cfg = ProtectedConfig::default();

        // Contact whose DID and alias both carry the marker.
        let did = Arc::new(format!("did:web:{MARKER}.example.com"));
        private_cfg.contacts.contacts.insert(
            did.clone(),
            Arc::new(Contact {
                did: did.clone(),
                alias: Some(MARKER.to_string()),
            }),
        );

        // Relationship whose DIDs all carry the marker.
        private_cfg.relationships.relationships.insert(
            did.clone(),
            Relationship {
                task_id: Arc::new(MARKER.to_string()),
                our_did: did.clone(),
                remote_did: did.clone(),
                remote_p_did: did.clone(),
                created: chrono::Utc::now(),
                state: RelationshipState::Established,
                our_persona: None,
                needs_reestablishment: false,
            },
        );

        let writer = SharedWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(writer.clone())
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            log_private_config_shape(&private_cfg);
        });

        let output = String::from_utf8(writer.0.lock().unwrap().clone()).unwrap();
        assert!(
            output.contains("private config loaded"),
            "shape log line was not captured; got: {output}"
        );
        assert!(
            output.contains("contacts=1") && output.contains("relationships=1"),
            "expected collection counts in the log line; got: {output}"
        );
        assert!(
            !output.contains(MARKER),
            "decrypted private-config contents leaked into log output: {output}"
        );
    }
}
