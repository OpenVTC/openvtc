//! Relationship DIDs (R-DIDs): minting their keys and the did:peer they make.
//!
//! An R-DID's two keys (Ed25519 verification, X25519 key agreement) come from
//! the account's BIP32 seed or from its VTA, depending on the key backend.
//! [`plan_relationship_did`] is the only step that touches [`Config`] (it
//! reserves BIP32 paths), so it runs where `Config` lives;
//! [`RDidPlan::create_io`] does the I/O and returns the `key_info` entries for
//! the caller to record.

use affinidi_tdk::{
    TDK,
    affinidi_crypto::ed25519::ed25519_private_to_x25519,
    dids::{DID, PeerKeyRole},
    secrets_resolver::{SecretsResolver, secrets::Secret},
};
use base64::Engine;
use chrono::Utc;
use ed25519_dalek_bip32::DerivationPath;
use tracing::info;

use crate::config::{
    Config, KeyBackend, KeyTypes,
    secured_config::{KeyInfoConfig, KeySourceMaterial},
};
use crate::didcomm::Messaging;
use crate::errors::OpenVTCError;

/// Derive the BIP32 child at `path` from `root`.
fn derive(
    root: &ed25519_dalek_bip32::ExtendedSigningKey,
    path: &str,
) -> Result<ed25519_dalek_bip32::ExtendedSigningKey, OpenVTCError> {
    let path = path
        .parse::<DerivationPath>()
        .map_err(|e| OpenVTCError::BIP32(format!("bad derivation path {path}: {e}")))?;
    root.derive(&path)
        .map_err(|e| OpenVTCError::BIP32(format!("couldn't derive a relationship key: {e}")))
}

/// Loop-thread plan for creating a relationship DID, plus everything the
/// *I/O-only* [`RDidPlan::create_io`] needs to run off the loop without touching
/// `Config`. Building this is the only step that reads/mutates `Config` (the
/// BIP32 path-pointer reservation); the actual key creation (VTA round-trip or
/// BIP32 derivation), did:peer build, and resolver insert all run in the task.
pub enum RDidPlan {
    /// BIP32: paths reserved on the loop thread (pointer already advanced); the
    /// task derives the keys from a clone of the root. The root is boxed to keep
    /// the enum compact (it is the largest field by far).
    Bip32 {
        /// The BIP32 root the keys derive from.
        root: Box<ed25519_dalek_bip32::ExtendedSigningKey>,
        /// Reserved derivation path for the verification (signing) key.
        v_path: String,
        /// Reserved derivation path for the encryption (key-agreement) key.
        e_path: String,
        /// The mediator DID the relationship DID routes through.
        mediator: String,
    },
    /// VTA: the task creates the keys on the always-on admin session (cloned —
    /// cheap, shares the connection pool).
    Vta {
        /// The admin VTA session the keys are created on.
        admin_vta: vta_sdk::client::VtaClient,
        /// The mediator DID the relationship DID routes through.
        mediator: String,
    },
}

/// The created relationship DID plus the `key_info` entries to record in
/// `Config` on the loop thread. The secrets themselves were already inserted into
/// the (shared, `Arc`-based) TDK resolver inside the task, so they are visible to
/// the loop's TDK; only the `Config` bookkeeping is left for `apply`.
pub struct CreatedRDid {
    /// The new relationship DID (a did:peer).
    pub r_did: String,
    /// `key_info` entries keyed by the did:peer verification-method secret id.
    pub key_info: Vec<(String, KeyInfoConfig)>,
}

/// Build the [`RDidPlan`] on the loop thread. For BIP32 this reserves two unique
/// derivation paths and advances `path_pointer` (the only `Config` mutation the
/// pre-send step makes); for VTA it just snapshots the owned client/backend.
pub fn plan_relationship_did(
    config: &mut Config,
    mediator: &str,
    admin_vta: Option<&vta_sdk::client::VtaClient>,
) -> Result<RDidPlan, OpenVTCError> {
    match &config.key_backend {
        KeyBackend::Bip32 { seed, .. } => {
            // `ExtendedSigningKey` (ed25519-dalek-bip32 0.3) is not `Clone`, so
            // reconstruct an owned root from the persisted seed — the same
            // derivation the load path uses, and a pure function of the seed, so
            // the rebuilt root is identical to the live one.
            let root = Box::new(
                ed25519_dalek_bip32::ExtendedSigningKey::from_seed(
                    &base64::prelude::BASE64_URL_SAFE_NO_PAD
                        .decode(secrecy::ExposeSecret::expose_secret(seed))
                        .map_err(|e| {
                            OpenVTCError::BIP32(format!("couldn't decode BIP32 seed: {e}"))
                        })?,
                )
                .map_err(|e| OpenVTCError::BIP32(format!("couldn't rebuild BIP32 root: {e}")))?,
            );
            let v_path = format!("m/3'/1'/1'/{}'", config.private.relationships.path_pointer);
            config.private.relationships.path_pointer += 1;
            let e_path = format!("m/3'/1'/1'/{}'", config.private.relationships.path_pointer);
            config.private.relationships.path_pointer += 1;
            Ok(RDidPlan::Bip32 {
                root,
                v_path,
                e_path,
                mediator: mediator.to_string(),
            })
        }
        KeyBackend::Vta { .. } => {
            // The runtime always holds an admin VTA session for a VTA backend
            // (built at startup). If it doesn't, R-DID creation can't proceed —
            // surface that up front rather than parking the loop to open one.
            let admin_vta = admin_vta.cloned().ok_or_else(|| {
                OpenVTCError::Vta(
                    "no VTA session available to create a relationship DID".to_string(),
                )
            })?;
            Ok(RDidPlan::Vta {
                admin_vta,
                mediator: mediator.to_string(),
            })
        }
    }
}

impl RDidPlan {
    fn mediator(&self) -> &str {
        match self {
            RDidPlan::Bip32 { mediator, .. } | RDidPlan::Vta { mediator, .. } => mediator,
        }
    }

    /// I/O-only relationship-DID creation, run inside the spawned task. Creates
    /// the keys (BIP32 derivation or VTA round-trip), builds the did:peer,
    /// registers the secrets in the shared TDK resolver, **and registers the new
    /// R-DID listener** (built from the just-minted secrets — no resolver lookup,
    /// no `Config`). Returns the `Config` `key_info` entries for the loop thread
    /// to record. Never touches `Config`.
    ///
    /// `service` + `remote_p_did` are only used to register the post-establishment
    /// R-DID listener, right after key creation.
    pub async fn create_io(
        self,
        tdk: &TDK,
        service: &Messaging,
        remote_p_did: &str,
    ) -> Result<CreatedRDid, OpenVTCError> {
        let mediator = self.mediator().to_string();
        // Mint the keys and capture each one's *source material* (BIP32 path or
        // VTA key id) in verification-then-encryption order. Note we do NOT record
        // the secret ids yet: a freshly generated `Secret` carries a placeholder id
        // (`generate_ed25519` → a random base64 string, `generate_x25519` →
        // `"x25519"`), and `generate_did_peer_from_secrets` below rewrites those
        // ids to the did:peer verification-method ids. `key_info` must be built
        // from the *rewritten* ids — see the comment on that step.
        let (mut v_secret, mut e_secret, v_source, e_source) = match self {
            RDidPlan::Bip32 {
                root,
                v_path,
                e_path,
                ..
            } => {
                let v_key = derive(&root, &v_path)?;
                let e_key = derive(&root, &e_path)?;
                let v_secret = Secret::generate_ed25519(None, Some(v_key.signing_key.as_bytes()));
                let e_secret = Secret::generate_x25519(
                    None,
                    Some(&ed25519_private_to_x25519(e_key.signing_key.as_bytes())),
                )
                .map_err(|e| {
                    OpenVTCError::Secret(format!("couldn't build the encryption key: {e}"))
                })?;
                // NOTE: v_key/e_key hold BIP32-derived signing-key bytes on the
                // stack; ed25519-dalek-bip32 does not Zeroize, a known limitation.
                drop(v_key);
                drop(e_key);
                (
                    v_secret,
                    e_secret,
                    KeySourceMaterial::Derived { path: v_path },
                    KeySourceMaterial::Derived { path: e_path },
                )
            }
            RDidPlan::Vta { admin_vta, .. } => {
                let (v_secret, e_secret, sign_key_id, enc_key_id) =
                    create_relationship_keys(&admin_vta).await?;
                (
                    v_secret,
                    e_secret,
                    KeySourceMaterial::VtaManaged {
                        key_id: sign_key_id,
                    },
                    KeySourceMaterial::VtaManaged { key_id: enc_key_id },
                )
            }
        };

        // Build the did:peer from the secrets. This REWRITES each secret's `id` to
        // the did:peer verification-method id (`{did}#key-1` for verification,
        // `{did}#key-2` for the key-agreement key).
        let mut keys = vec![
            (PeerKeyRole::Verification, &mut v_secret),
            (PeerKeyRole::Encryption, &mut e_secret),
        ];
        let r_did = DID::generate_did_peer_from_secrets(&mut keys, Some(mediator.clone()))
            .map_err(|e| OpenVTCError::Secret(format!("Failed to create relationship DID: {e}")))?;
        drop(keys);

        // Record `key_info` under the FINAL did:peer-relative secret ids (set by
        // the call above), pairing each with its source material. This MUST run
        // after the did:peer mint: the reload path (`Relationships::
        // generate_profiles`) only re-registers a stored secret when its id
        // `starts_with` the R-DID, and packs DIDComm as the R-DID using the
        // `#key-1`/`#key-2` verification-method ids. Persisting the pre-mint
        // placeholder ids (the historical bug) left the reloaded R-DID with no
        // usable key-agreement secret, so mediator authentication looped forever
        // ("sender has no usable key agreement key").
        let key_info: Vec<(String, KeyInfoConfig)> = vec![
            (
                v_secret.id.clone(),
                KeyInfoConfig {
                    path: v_source,
                    create_time: Utc::now(),
                    purpose: KeyTypes::RelationshipVerification,
                },
            ),
            (
                e_secret.id.clone(),
                KeyInfoConfig {
                    path: e_source,
                    create_time: Utc::now(),
                    purpose: KeyTypes::RelationshipEncryption,
                },
            ),
        ];

        // Register the new R-DID listener from the just-minted secrets (the old
        // inline path did this right after key creation; failure is non-fatal).
        let listener_config = crate::didcomm::relationship_listener_config_from_secrets(
            &r_did,
            remote_p_did,
            &mediator,
            vec![v_secret.clone(), e_secret.clone()],
        );
        if let Err(e) = crate::didcomm::add_listener(service, &listener_config).await {
            tracing::warn!(did = %r_did, error = %e, "failed to add R-DID listener");
        }

        // Register the secrets in the shared TDK resolver (visible to the loop's
        // TDK — same `Arc`-backed resolver).
        tdk.get_shared_state()
            .secrets_resolver()
            .insert(v_secret)
            .await;
        tdk.get_shared_state()
            .secrets_resolver()
            .insert(e_secret)
            .await;

        Ok(CreatedRDid { r_did, key_info })
    }
}

/// Create a relationship's signing (Ed25519) + encryption (X25519) keys via the
/// VTA and fetch their secrets, on the given (admin) session. Returns
/// `(v_secret, e_secret, signing_key_id, encryption_key_id)`.
async fn create_relationship_keys(
    client: &vta_sdk::client::VtaClient,
) -> Result<(Secret, Secret, String, String), OpenVTCError> {
    use vta_sdk::client::CreateKeyRequest;
    use vta_sdk::keys::KeyType;

    info!("creating Ed25519 signing key via VTA...");
    let sign_resp = crate::vta_task::retry("create relationship signing key", || {
        client.create_key(CreateKeyRequest {
            // Absent is today's behaviour. `Some(true)` mints a
            // non-extractable key that cannot be recovered from
            // the mnemonic or any backup — never a default.
            internal: None,
            key_type: KeyType::Ed25519,
            derivation_path: None,
            key_id: None,
            mnemonic: None,
            label: Some("relationship-signing".to_string()),
            context_id: None,
        })
    })
    .await
    .map_err(|e| OpenVTCError::vta("Failed to create signing key", &e))?;
    let sign_secret_resp = crate::vta_task::retry("get relationship signing key secret", || {
        client.get_key_secret(&sign_resp.key_id)
    })
    .await
    .map_err(|e| OpenVTCError::vta("Failed to get signing key secret", &e))?;
    let mut v_secret = vta_sdk::did_key::secret_from_key_response(&sign_secret_resp)
        .map_err(|e| OpenVTCError::Secret(format!("{e:?}")))?;
    v_secret.id = v_secret
        .get_public_keymultibase()
        .map_err(|e| OpenVTCError::Secret(e.to_string()))?;

    info!("creating X25519 encryption key via VTA...");
    let enc_resp = crate::vta_task::retry("create relationship encryption key", || {
        client.create_key(CreateKeyRequest {
            // Absent is today's behaviour. `Some(true)` mints a
            // non-extractable key that cannot be recovered from
            // the mnemonic or any backup — never a default.
            internal: None,
            key_type: KeyType::X25519,
            derivation_path: None,
            key_id: None,
            mnemonic: None,
            label: Some("relationship-encryption".to_string()),
            context_id: None,
        })
    })
    .await
    .map_err(|e| OpenVTCError::vta("Failed to create encryption key", &e))?;
    let enc_secret_resp = crate::vta_task::retry("get relationship encryption key secret", || {
        client.get_key_secret(&enc_resp.key_id)
    })
    .await
    .map_err(|e| OpenVTCError::vta("Failed to get encryption key secret", &e))?;
    let mut e_secret = vta_sdk::did_key::secret_from_key_response(&enc_secret_resp)
        .map_err(|e| OpenVTCError::Secret(format!("{e:?}")))?;
    e_secret.id = e_secret
        .get_public_keymultibase()
        .map_err(|e| OpenVTCError::Secret(e.to_string()))?;

    Ok((v_secret, e_secret, sign_resp.key_id, enc_resp.key_id))
}

/// The key that proves control of `our_did` for a handshake: the persona's own
/// authentication key when `our_did` is the persona, else the R-DID's signing
/// key from the TDK's resolver.
pub async fn relationship_did_signer(
    tdk: &TDK,
    our_did: &str,
    persona_did: &str,
    persona_auth: &Secret,
) -> Result<Secret, OpenVTCError> {
    if our_did == persona_did {
        return Ok(persona_auth.clone());
    }
    crate::relationships::relationship_signing_secret(tdk, our_did)
        .await
        .ok_or_else(|| {
            OpenVTCError::MissingSecretKeyMaterial(format!(
                "the relationship DID's signing key is not loaded ({our_did})"
            ))
        })
}
