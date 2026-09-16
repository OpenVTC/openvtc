//! Key resolution and regeneration logic for persona and relationship DIDs.

use secrecy::ExposeSecret;

use crate::{
    KeyPurpose,
    bip32::Bip32Extension,
    config::{
        Config, KeyBackend, KeyInfo, KeyTypes, PersonaDIDKeys,
        integrity::DegradedReason,
        secured_config::{KeyInfoConfig, KeySourceMaterial, SecuredConfig},
    },
    errors::OpenVTCError,
};
use affinidi_tdk::{
    TDK,
    did_common::{Document, document::DocumentExt, verification_method::VerificationRelationship},
    secrets_resolver::{SecretsResolver, secrets::Secret},
};
use std::collections::HashMap;
use tracing::warn;

/// Resolves a single key from a DID document verification relationship field.
async fn resolve_key_from_document(
    doc_field: &[VerificationRelationship],
    field_name: &str,
    tdk: &TDK,
    key_info: &HashMap<String, KeyInfoConfig>,
) -> Result<KeyInfo, OpenVTCError> {
    let vm = doc_field.first().ok_or_else(|| {
        OpenVTCError::Config(format!("DID Document does not contain any {field_name}!"))
    })?;
    let secret = tdk
        .get_shared_state()
        .secrets_resolver()
        .get_secret(vm.get_id())
        .await
        .ok_or_else(|| {
            OpenVTCError::Config(format!("Couldn't find secret in TDK for ({})", vm.get_id()))
        })?;
    let ki = key_info.get(vm.get_id()).ok_or_else(|| {
        OpenVTCError::Config(format!(
            "Couldn't find key info in openvtc Config for ({})",
            vm.get_id()
        ))
    })?;
    Ok(KeyInfo {
        secret,
        source: ki.path.clone(),
        created: ki.create_time,
        expiry: None,
    })
}

impl Config {
    /// Returns the first matching set of keys for the persona DID.
    ///
    /// Resolves one key of each type from the DID document:
    /// - Signing (assertion method)
    /// - Authentication
    /// - Encryption (key agreement)
    ///
    /// # Errors
    ///
    /// Returns an error if the DID document is missing any required verification
    /// method, or if the corresponding secret or key info cannot be found.
    pub async fn get_persona_keys(&self, tdk: &TDK) -> Result<PersonaDIDKeys, OpenVTCError> {
        let doc = self
            .active_identity()
            .ok_or_else(|| OpenVTCError::Config("No active persona identity".to_string()))?
            .document();
        let signing = resolve_key_from_document(
            &doc.assertion_method,
            "assertion methods",
            tdk,
            &self.key_info,
        )
        .await?;
        let authentication = resolve_key_from_document(
            &doc.authentication,
            "authentication methods",
            tdk,
            &self.key_info,
        )
        .await?;
        let decryption =
            resolve_key_from_document(&doc.key_agreement, "key agreements", tdk, &self.key_info)
                .await?;
        Ok(PersonaDIDKeys {
            signing,
            authentication,
            decryption,
        })
    }

    /// Like [`Self::get_persona_keys`] but for a *specific* persona, not the active
    /// one — needed when an action targets a membership whose persona is not the
    /// current working identity (e.g. issuing a member VMC from a community row).
    pub async fn get_persona_keys_for(
        &self,
        persona_id: crate::config::account::PersonaId,
        tdk: &TDK,
    ) -> Result<PersonaDIDKeys, OpenVTCError> {
        let doc = self
            .identities
            .get(&persona_id)
            .ok_or_else(|| OpenVTCError::Config("Unknown persona identity".to_string()))?
            .document();
        let signing = resolve_key_from_document(
            &doc.assertion_method,
            "assertion methods",
            tdk,
            &self.key_info,
        )
        .await?;
        let authentication = resolve_key_from_document(
            &doc.authentication,
            "authentication methods",
            tdk,
            &self.key_info,
        )
        .await?;
        let decryption =
            resolve_key_from_document(&doc.key_agreement, "key agreements", tdk, &self.key_info)
                .await?;
        Ok(PersonaDIDKeys {
            signing,
            authentication,
            decryption,
        })
    }

    /// Build a subject-linkage proof (#1b) authorizing `presenter_did` to redeem
    /// the invitation `vic_id` that is bound to `subject_did` — one of *our*
    /// personas. Signs `TAG‖vic_id‖presenter` with that persona's signing key
    /// (via the TDK Ed25519 routine), under its assertionMethod verification
    /// method. Used when joining under a different/fresh DID than the invited one.
    ///
    /// Errors if `subject_did` is not one of our personas (we can't prove
    /// control of a key we don't hold).
    pub async fn build_subject_linkage(
        &self,
        subject_did: &str,
        vta_client: Option<&vta_sdk::client::VtaClient>,
        vic_id: &str,
        presenter_did: &str,
    ) -> Result<crate::join::SubjectLinkage, OpenVTCError> {
        // The subject persona's assertionMethod VM id (the VTC resolves it to
        // verify the signature).
        let persona = self
            .account
            .personas
            .values()
            .find(|p| p.did == subject_did)
            .ok_or_else(|| {
                OpenVTCError::Config(format!(
                    "invitation subject {subject_did} is not one of your personas"
                ))
            })?;
        let doc = persona.did_document.as_ref().ok_or_else(|| {
            OpenVTCError::Config("subject persona has no cached DID document".to_string())
        })?;
        let vm = doc
            .find_assertion_method(None)
            .first()
            .copied()
            .ok_or_else(|| {
                OpenVTCError::Config("subject persona has no assertionMethod".to_string())
            })?
            .to_string();

        let seed = self.persona_signing_seed(subject_did, vta_client).await?;
        crate::join::sign_subject_linkage(&seed, vm, vic_id, presenter_did)
    }

    /// Resolve a persona's Ed25519 signing-key seed (32 bytes) by DID, from
    /// whichever backing the key uses (BIP32-derived / imported / VTA-managed).
    /// Mirrors the per-key resolution in [`Self::load_persona_secrets`].
    async fn persona_signing_seed(
        &self,
        persona_did: &str,
        vta_client: Option<&vta_sdk::client::VtaClient>,
    ) -> Result<[u8; 32], OpenVTCError> {
        for (key_id, ki) in &self.key_info {
            if !key_id.starts_with(persona_did) || !matches!(ki.purpose, KeyTypes::PersonaSigning) {
                continue;
            }
            let secret = match &ki.path {
                KeySourceMaterial::Derived { path } => {
                    let KeyBackend::Bip32 { root, .. } = &self.key_backend else {
                        return Err(OpenVTCError::Config(
                            "Derived key requires a BIP32 backend".to_string(),
                        ));
                    };
                    root.get_secret_from_path(path, KeyPurpose::Signing)
                        .map_err(|e| {
                            OpenVTCError::Secret(format!("derive subject signing key: {e}"))
                        })?
                }
                KeySourceMaterial::Imported { seed } => {
                    Secret::from_multibase(seed.expose_secret(), None)
                        .map_err(|e| OpenVTCError::Secret(format!("imported signing key: {e}")))?
                }
                KeySourceMaterial::VtaManaged { key_id: vta_key_id } => {
                    let client = vta_client.ok_or_else(|| {
                        OpenVTCError::Config(
                            "VTA-managed signing key requires a VTA client".to_string(),
                        )
                    })?;
                    let resp = client.get_key_secret(vta_key_id).await.map_err(|e| {
                        OpenVTCError::Config(format!("fetch subject signing key: {e}"))
                    })?;
                    secret_from_vta_response(&resp, KeyPurpose::Signing)?
                }
            };
            return secret.get_private_bytes().try_into().map_err(|_| {
                OpenVTCError::Secret("signing key is not a 32-byte Ed25519 seed".to_string())
            });
        }
        Err(OpenVTCError::Config(format!(
            "no signing key found for persona {persona_did}"
        )))
    }

    /// Load persona DID key secrets into the TDK resolver from this Config.
    ///
    /// Call this after creating a new config (e.g., after setup wizard) so the
    /// DIDComm service can authenticate with the mediator. On normal startup
    /// this is done by `load_step2`.
    pub async fn load_persona_secrets(&self, tdk: &TDK) -> Result<(), OpenVTCError> {
        // Open ONE VTA admin session up front and reuse it for every VtaManaged
        // key below, instead of connecting (and tearing down) a fresh mediator
        // session per key.
        let vta_client = if matches!(&self.key_backend, KeyBackend::Vta { .. }) {
            super::build_runtime_vta_client(&self.key_backend)
                .await
                .ok()
        } else {
            None
        };

        // PERF: VtaManaged `get_key_secret` calls stay sequential — see the note
        // in `regenerate_persona_keys`: concurrent fetches on a single
        // DIDComm-backed session race on the shared live-stream cursor and can
        // drop each other's responses.
        for (key_id, key_info) in &self.key_info {
            if !key_id.starts_with(self.persona_did()) {
                continue;
            }
            let kp = match key_info.purpose {
                KeyTypes::PersonaSigning | KeyTypes::PersonaAuthentication => KeyPurpose::Signing,
                KeyTypes::PersonaEncryption => KeyPurpose::Encryption,
                _ => continue,
            };
            let secret = match &key_info.path {
                KeySourceMaterial::Derived { path } => {
                    let KeyBackend::Bip32 { root, .. } = &self.key_backend else {
                        continue;
                    };
                    root.get_secret_from_path(path, kp)
                        .map(|mut s| {
                            s.id = key_id.clone();
                            s
                        })
                        .ok()
                }
                KeySourceMaterial::Imported { seed } => {
                    use secrecy::ExposeSecret;
                    Secret::from_multibase(seed.expose_secret(), None)
                        .map(|mut s| {
                            s.id = key_id.clone();
                            s
                        })
                        .ok()
                }
                KeySourceMaterial::VtaManaged { key_id: vta_key_id } => {
                    if let Some(client) = vta_client.as_ref() {
                        client
                            .get_key_secret(vta_key_id)
                            .await
                            .ok()
                            .and_then(|resp| {
                                secret_from_vta_response(&resp, kp)
                                    .map(|mut s| {
                                        s.id = key_id.clone();
                                        s
                                    })
                                    .ok()
                            })
                    } else {
                        None
                    }
                }
            };
            if let Some(s) = secret {
                tdk.get_shared_state().secrets_resolver().insert(s).await;
            }
        }

        // Close the single shared session now that all keys are loaded.
        if let Some(client) = vta_client {
            client.shutdown().await;
        }
        Ok(())
    }

    /// Regenerates the persona DID keys from secured config and loads them into the TDK.
    ///
    /// # Errors
    ///
    /// Returns an error if a verification method key path is missing from config,
    /// key derivation or import fails, or VTA secret retrieval fails.
    /// Rehydrate one persona's private keys into the TDK secrets resolver.
    ///
    /// Returns a [`DegradedReason`] rather than an `OpenVTCError` because the
    /// caller isolates the fault to this persona: the two ways this fails —
    /// `key_info` has no entry for a verification method (an interrupted save)
    /// and the VTA will not hand the key back (a transient fault) — need
    /// different words in front of the user, and a formatted string cannot tell
    /// them apart. Previously both were `OpenVTCError::Config` and either one
    /// failed the entire profile load.
    pub(crate) async fn regenerate_persona_keys(
        tdk: &mut TDK,
        sc: &SecuredConfig,
        key_backend: &KeyBackend,
        doc: &Document,
        vta_client: Option<&vta_sdk::client::VtaClient>,
    ) -> Result<(), DegradedReason> {
        // Rehydrate DID keys referenced by Verification Methods in the DID
        // Document.
        //
        // PERF: the VtaManaged `get_key_secret` round-trips below are kept
        // SEQUENTIAL on purpose. When `vta_client` is DIDComm-backed (the
        // default for a VTA backend), all cloned `VtaClient`s share ONE
        // `Arc<ATM>`/`Arc<ATMProfile>` and therefore ONE WebSocket live-stream
        // cursor. `vta_sdk`'s `send_and_wait` reads that cursor with
        // `live_stream_next` and DROPS (`continue`) any message whose `thid`
        // doesn't match the request it is waiting on — so two concurrent
        // fetches on the same session race: one can consume and discard the
        // other's response, making that fetch time out. Parallelising here
        // would risk dropped persona keys at startup. (REST-backed sessions
        // would be safe, but the transport isn't known here.) See
        // `vta-sdk/src/didcomm_session.rs::send_and_wait`.
        for vm in &doc.verification_method {
            let Some(kp) = sc.key_info.get(vm.id.as_str()) else {
                // The account knows about this persona but the secured config
                // has no key for it: the two halves of a save disagree.
                warn!(
                    key_id = %vm.id,
                    "no key material recorded for this verification method"
                );
                return Err(DegradedReason::MissingKeyInfo {
                    key_id: vm.id.to_string(),
                });
            };

            // need to match this to VM purpose
            let k_purpose = if doc.contains_key_agreement(vm.id.as_str()) {
                KeyPurpose::Encryption
            } else if doc.contains_authentication(vm.id.as_str()) {
                KeyPurpose::Authentication
            } else if doc.contains_assertion_method(vm.id.as_str()) {
                KeyPurpose::Signing
            } else {
                warn!("Unknown DID VM ({}) found", vm.id);
                continue;
            };

            let mut secret = match &kp.path {
                KeySourceMaterial::Derived { path } => {
                    let KeyBackend::Bip32 { root, .. } = key_backend else {
                        return Err(DegradedReason::KeyUnavailable {
                            detail: "a derived key needs the BIP32 backend, but this account \
                                     uses VTA-managed keys"
                                .to_string(),
                        });
                    };
                    root.get_secret_from_path(path, k_purpose).map_err(|e| {
                        DegradedReason::KeyUnavailable {
                            detail: format!("could not derive {path}: {e}"),
                        }
                    })?
                }
                KeySourceMaterial::Imported { seed } => {
                    Secret::from_multibase(seed.expose_secret(), None).map_err(|e| {
                        DegradedReason::KeyUnavailable {
                            detail: format!("stored key material is not valid multibase: {e}"),
                        }
                    })?
                }
                KeySourceMaterial::VtaManaged { key_id } => {
                    // Use pre-authenticated VTA client
                    let client = vta_client.ok_or_else(|| DegradedReason::KeyUnavailable {
                        detail: "this persona's keys are held by the VTA, and no VTA session \
                                 is open"
                            .to_string(),
                    })?;

                    let key_secret = client.get_key_secret(key_id).await.map_err(|e| {
                        DegradedReason::KeyUnavailable {
                            detail: format!("the VTA would not return key {key_id}: {e}"),
                        }
                    })?;

                    secret_from_vta_response(&key_secret, k_purpose).map_err(|e| {
                        DegradedReason::KeyUnavailable {
                            detail: format!("the VTA returned an unusable key {key_id}: {e}"),
                        }
                    })?
                }
            };

            // Set the Secret key ID correctly
            secret.id = vm.id.to_string();

            // Load the secret into the TDK Secrets resolver
            tdk.get_shared_state()
                .secrets_resolver()
                .insert(secret)
                .await;
        }
        Ok(())
    }
}

/// Converts a VTA `GetKeySecretResponse` into a TDK `Secret`.
///
/// Supports Ed25519 (signing/authentication) and X25519 (encryption) key types.
///
/// # Errors
///
/// Returns [`OpenVTCError::Secret`] if the private key multibase cannot be decoded
/// or the secret cannot be constructed from the decoded material.
pub(crate) fn secret_from_vta_response(
    resp: &vta_sdk::client::GetKeySecretResponse,
    _purpose: KeyPurpose,
) -> Result<Secret, OpenVTCError> {
    match &resp.key_type {
        vta_sdk::keys::KeyType::Ed25519 => {
            let seed = vta_sdk::did_key::decode_private_key_multibase(&resp.private_key_multibase)
                .map_err(|e| {
                    OpenVTCError::Secret(format!(
                        "Failed to decode Ed25519 private key multibase: {:?}",
                        e
                    ))
                })?;
            Ok(Secret::generate_ed25519(None, Some(&seed)))
        }
        vta_sdk::keys::KeyType::X25519 => Secret::from_multibase(&resp.private_key_multibase, None)
            .map_err(|e| {
                OpenVTCError::Secret(format!(
                    "Failed to create X25519 secret from multibase: {e}"
                ))
            }),
        // Everything else, including the ML-DSA variants vta-sdk 0.39 added
        // (VTI #1502). A catch-all rather than an arm per variant: this function
        // converts a VTA key into a TDK `Secret`, and a key type TDK has no
        // `Secret` for is unsupported here whatever it is called. `KeyType` is
        // `#[non_exhaustive]`, so enumerating would mean editing this every time
        // the SDK learns a key type, in order to keep saying the same thing.
        //
        // The message names the type it refused, so an operator who hits it
        // learns which key they asked for rather than that "a" key failed.
        other => Err(OpenVTCError::Secret(format!(
            "{other:?} key type is not supported for OpenVTC secrets"
        ))),
    }
}
