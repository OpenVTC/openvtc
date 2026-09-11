/*! Contains the OpenVTC CLI Tool Configuration
*
* Configuration is spread across four different contexts:
* 1. [Config]: Represents the active in-memory application config
* 2. [secured_config::SecuredConfig]: Represents [Config] info that is stored securely (key info)
* 3. [public_config::PublicConfig]: Represents [Config] info that is stored in plaintext on disk
* 4. [protected_config::ProtectedConfig]: Represents [Config] info that is encryoted and stored on disk
*
* NOTE: Secure Config information is saved item by item as needed to the secure storage
*/

use crate::{
    config::{
        protected_config::ProtectedConfig,
        secured_config::{KeyInfoConfig, KeySourceMaterial, ProtectionMethod},
    },
    errors::OpenVTCError,
};
use affinidi_tdk::secrets_resolver::secrets::Secret;
use argon2::{Algorithm, Argon2, Params, Version};
use chrono::{DateTime, TimeDelta, Utc};
use ed25519_dalek_bip32::ExtendedSigningKey;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    fmt::Display,
};

pub mod account;
pub mod community_context;
pub mod context_path;
pub mod did;
pub mod integrity;
pub mod keys;
pub mod loading;
pub mod protected_config;
pub mod public_config;
pub mod saving;
pub mod secured_config;

// Convenience re-export so the plaintext config model is reachable as
// `openvtc_core::config::PublicConfig` (it derives `Deserialize`; a clean
// parse surface for fuzzing / external consumers).
pub use public_config::PublicConfig;

/// Derives a 32-byte key from a user-provided passphrase using Argon2id.
///
/// Uses Argon2id (RFC 9106) with a domain-specific salt derived from `info`.
/// This provides strong resistance against brute-force and GPU-based attacks
/// on user-chosen passphrases.
///
/// # Parameters
///
/// - `passphrase`: The user-provided passphrase bytes.
/// - `info`: A domain-separation label (e.g., `b"openvtc-unlock-code-v1"`).
///   Different labels produce different keys from the same passphrase.
///
/// # Errors
///
/// Returns an error if Argon2 key derivation fails (e.g., memory allocation).
///
/// # Examples
///
/// ```
/// use openvtc_core::config::derive_passphrase_key;
///
/// let key1 = derive_passphrase_key(b"my-passphrase", b"context-a").unwrap();
/// let key2 = derive_passphrase_key(b"my-passphrase", b"context-b").unwrap();
///
/// // Same passphrase with different context produces different keys
/// assert_ne!(key1, key2);
///
/// // Deterministic for the same inputs
/// let key3 = derive_passphrase_key(b"my-passphrase", b"context-a").unwrap();
/// assert_eq!(key1, key3);
/// ```
pub fn derive_passphrase_key(passphrase: &[u8], info: &[u8]) -> Result<[u8; 32], OpenVTCError> {
    // Legacy v1 KDF: deterministic salt derived from the info label.
    //
    // This is kept for backwards-compatible decryption of v1 ciphertext
    // (data written before the per-entry random salt migration). The
    // deterministic salt means two users with the same passphrase produce
    // the same key, and rainbow-table attacks parallelise across all
    // OpenVTC users — which is the H2 finding from the v0.2.0 review.
    //
    // New ciphertext is always written via `derive_passphrase_key_v2`
    // (random per-entry salt) and the v2 magic-prefix format. The
    // unlock-code path auto-detects the format and reaches for this
    // legacy KDF only when consuming pre-migration data.
    let salt = Sha256::digest(info);
    derive_argon2_key(passphrase, &salt)
}

/// Derive a 32-byte AEAD key from `passphrase` using a per-entry random
/// `salt`. Pair with the v2 ciphertext format so the salt stored
/// alongside the ciphertext is what gets fed back here at decrypt time.
pub fn derive_passphrase_key_v2(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32], OpenVTCError> {
    derive_argon2_key(passphrase, salt)
}

/// Async wrapper for [`derive_passphrase_key`] that runs the (CPU-bound,
/// ~0.5–1 s) Argon2id derivation on `tokio::task::spawn_blocking` instead of
/// inline on the async runtime (R12).
///
/// The synchronous [`derive_passphrase_key`] pegs a tokio worker for the full
/// derive; at the user-initiated set/change-passphrase site that worker is the
/// event-loop thread, freezing the UI for ~1 s. This helper owns its inputs (so
/// the closure is `Send + 'static`) and moves the blocking crypto onto the
/// blocking pool, keeping the runtime / render task live. The KDF, salt
/// handling (the legacy v1 deterministic info-salt), and result are identical
/// to the sync path — only *where* the CPU work runs changes.
///
/// `passphrase` is taken by value so the secret bytes are moved into the
/// closure and dropped there; callers should pass an owned copy of the exposed
/// secret rather than logging or widening its exposure.
///
/// # Errors
///
/// Returns [`OpenVTCError::Config`] if Argon2 derivation fails, or if the
/// blocking task panics. The `JoinError` carries only the thread/panic
/// location — never the passphrase or the derived key — so the secret cannot
/// leak through the error path.
pub async fn derive_passphrase_key_blocking(
    passphrase: Vec<u8>,
    info: Vec<u8>,
) -> Result<[u8; 32], OpenVTCError> {
    // Wrap the moved passphrase copy in `Zeroizing` so the transient plaintext
    // is wiped when the closure scope ends, preserving the zeroization the
    // borrowed `SecretString`/`SecretBox` would otherwise give.
    let passphrase = zeroize::Zeroizing::new(passphrase);
    tokio::task::spawn_blocking(move || derive_passphrase_key(&passphrase, &info))
        .await
        .map_err(|e| OpenVTCError::Config(format!("Argon2 derivation task panicked: {e}")))?
}

/// Shared Argon2id derivation. OWASP "high-value KEK" profile:
///   m = 128 MiB (GPU-resistant; fits comfortably on 4 GiB devices)
///   t = 4 iterations
///   p = 1 lane (parallelism helps attackers more than users at this cost)
fn derive_argon2_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32], OpenVTCError> {
    let mut key = [0u8; 32];
    let params = Params::new(128 * 1024, 4, 1, Some(32))
        .map_err(|e| OpenVTCError::Config(format!("Invalid Argon2 parameters: {e}")))?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| OpenVTCError::Config(format!("Argon2 key derivation failed: {e}")))?;
    Ok(key)
}

/// Minimum passphrase length for unlock codes and export passphrases.
pub const MIN_PASSPHRASE_LENGTH: usize = 8;

/// Validates that a passphrase meets minimum strength requirements.
///
/// Returns `Ok(())` if the passphrase is at least [`MIN_PASSPHRASE_LENGTH`] characters.
pub fn validate_passphrase(passphrase: &str) -> Result<(), OpenVTCError> {
    if passphrase.len() < MIN_PASSPHRASE_LENGTH {
        return Err(OpenVTCError::Config(format!(
            "Passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters (got {})",
            passphrase.len()
        )));
    }
    Ok(())
}

/// A 32-byte symmetric key derived from a user-provided passphrase via Argon2id.
/// Used to encrypt/decrypt the secured configuration on disk.
pub struct UnlockCode(pub(crate) SecretBox<Vec<u8>>);

impl UnlockCode {
    /// Derives an unlock code from a plaintext passphrase string using Argon2id.
    ///
    /// # Errors
    ///
    /// Returns an error if the passphrase is shorter than [`MIN_PASSPHRASE_LENGTH`].
    pub fn from_string(s: &str) -> Result<Self, OpenVTCError> {
        validate_passphrase(s)?;
        let key = derive_passphrase_key(s.as_bytes(), b"openvtc-unlock-code-v1")?;
        Ok(UnlockCode(SecretBox::new(Box::new(key.to_vec()))))
    }
}

/// Describes how the configuration secrets are protected at rest.
#[derive(Clone, Serialize, Deserialize, Debug, Default)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum ConfigProtectionType {
    /// Requires a hardware token with the Token ID to unlock config
    /// Will need to provide the USER PIN to the token
    Token(String),

    /// Requires an unlock passphrase to unlock config
    /// Will need to provide the unlock passphrase
    #[default]
    Encrypted,

    /// Is not encrypted in any way
    Plaintext,
}

#[cfg(feature = "openpgp-card")]
/// Callback trait for hardware token (e.g. YubiKey) user interaction.
///
/// Implementors receive notifications before and after the token may require
/// a physical touch, allowing the UI to prompt the user accordingly.
pub trait TokenInteractions: Send + Sync {
    /// Called before the token may require a physical touch from the user.
    fn touch_notify(&self);

    /// Called after the token operation has completed.
    fn touch_completed(&self);
}

/// The key backend determines how cryptographic keys are stored and managed.
///
/// Either keys are derived locally from a BIP32 seed, or they are managed
/// remotely by a Verifiable Trust Authority (VTA) service.
pub enum KeyBackend {
    /// Legacy BIP32 hierarchical-deterministic key derivation from a local seed.
    Bip32 {
        /// The BIP32 extended signing key root, derived from the seed.
        root: ExtendedSigningKey,
        /// The base64url-encoded seed material (kept in secret memory).
        seed: SecretString,
    },
    /// Keys are managed remotely by a VTA service and fetched on demand.
    Vta {
        /// Encoded VTA credential bundle for authentication.
        credential_bundle: SecretString,
        /// DID associated with the VTA credential.
        credential_did: String,
        /// Private key multibase string for signing VTA challenge-response.
        credential_private_key: SecretString,
        /// DID of the VTA service itself.
        vta_did: String,
        /// Base URL of the VTA service. Empty for DIDComm-only VTAs.
        vta_url: String,
        /// DIDComm mediator DID advertised by the VTA's DID document. Set
        /// during setup when the bootstrap was reached over DIDComm; lets
        /// runtime open new DIDComm sessions instead of falling back to
        /// REST. `None` for REST-only VTAs.
        mediator_did: Option<String>,
        /// SHA-256 hash of the private key multibase, used as the encryption seed
        /// for `ProtectedConfig` (replaces BIP32 `m/0'/0'/0'` in the VTA flow).
        encryption_seed: SecretBox<Vec<u8>>,
    },
}

impl std::fmt::Debug for KeyBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyBackend::Bip32 { .. } => f.debug_struct("KeyBackend::Bip32").finish_non_exhaustive(),
            KeyBackend::Vta {
                credential_did,
                vta_did,
                vta_url,
                ..
            } => f
                .debug_struct("KeyBackend::Vta")
                .field("credential_did", credential_did)
                .field("vta_did", vta_did)
                .field("vta_url", vta_url)
                .finish_non_exhaustive(),
        }
    }
}

/// Configuration information for openvtc tool
/// This is the active configuration used by the application itself
/// When you want to load/save this configuration, it will become:
/// 1. [public_config::PublicConfig]: Configuration information that is saved to disk
/// 2. [secured_config::SecuredConfig]: Configuration information that is encrypted and saved to secure storage
#[derive(Debug)]
pub struct Config {
    /// Public readable config items when saved to disk
    pub public: public_config::PublicConfig,

    /// Private sensitive config items which are encrypted on disk
    pub private: ProtectedConfig,

    /// Key backend - either local BIP32 or VTA-managed
    pub key_backend: KeyBackend,

    /// Where did the key values come from? Derived or Imported?
    pub key_info: HashMap<String, KeyInfoConfig>,

    // *********************************************
    // Temporary Config values
    /// What protection method is being used for the secured config.
    pub protection_method: ProtectionMethod,

    /// Hardware token Admin PIN
    #[cfg(feature = "openpgp-card")]
    pub token_admin_pin: Option<SecretString>,

    /// Hardware token User PIN
    #[cfg(feature = "openpgp-card")]
    pub token_user_pin: SecretString,

    /// Argon2id-derived 32-byte symmetric key used to encrypt/decrypt `SecuredConfig`.
    ///
    /// Wrapped in `SecretBox` to ensure the key material is zeroed on drop and
    /// never accidentally logged or compared in constant time.  Set when the
    /// user provides an unlock passphrase; `None` for plaintext or token flows.
    pub unlock_code: Option<SecretBox<Vec<u8>>>,

    /// Config v2 multi-community account model (personas + communities).
    ///
    /// The persisted source of truth for the account's personas and community
    /// memberships (stored encrypted in [`ProtectedConfig`]). The persona DID,
    /// mediator DID, and org DID that used to live as `public.*` singletons are
    /// now read from here via [`Config::persona_did`], [`Config::mediator_did`],
    /// and `account.org_did`.
    pub account: account::Account,

    /// Random key that encrypts [`ProtectedConfig`], carried from
    /// [`secured_config::SecuredConfig`] and written straight back on save.
    ///
    /// `None` only between loading a pre-D12 config and its first save: the
    /// load falls back to the legacy credential-derived seed and mints a real
    /// key here, which the next save persists. See
    /// [`Self::get_encryption_seed`].
    pub protected_key: Option<SecretString>,

    /// What this load could not bring up. Runtime-only, like `identities`,
    /// and empty on a healthy profile.
    ///
    /// Lives on `Config` rather than being returned separately so it cannot be
    /// dropped on the floor by a caller that only wanted the config: the whole
    /// point is that a degraded load is still a load, and something has to
    /// carry the evidence that it was one.
    pub integrity: integrity::LoadIntegrity,

    /// Runtime-resolved identities (resolved DID document + ATM profile),
    /// keyed by persona id. Not persisted — rebuilt at load from `account`.
    ///
    /// Holds one entry per persona — load resolves an `IdentityContext` for
    /// every persona in the account, and a DIDComm listener is started for each.
    /// [`Config::active_identity`] still surfaces the first as the "active" one
    /// for user-initiated outbound actions; explicit persona *selection* lands in
    /// a later slice.
    ///
    /// A `BTreeMap` (ordered by [`account::PersonaId`]) so that iteration — and
    /// therefore [`Config::active_identity`] — is deterministic across process
    /// runs and insertion orders.
    pub identities: BTreeMap<account::PersonaId, crate::identity::IdentityContext>,

    /// The persona the user's selected working community resolves to (D10) — the
    /// runtime "active identity". Set by the StateHandler loop from
    /// `State.selected_community`; `None` falls back to the first persona so
    /// startup/setup (which run before any selection) behave exactly as before.
    /// Not persisted — a pure runtime selection pointer over `identities`.
    pub active_persona: Option<account::PersonaId>,
}

/// Serializable bundle of public and secured config, used for import/export.
#[derive(Deserialize, Serialize)]
pub struct ExportedConfig {
    /// The public (plaintext) portion of the configuration.
    pub pc: public_config::PublicConfig,
    /// The secured (secret key material) portion of the configuration.
    pub sc: secured_config::SecuredConfig,
}

/// How much of the persona DID a messaging-profile label carries. Matches the
/// width the R-DID labels use for their remote DID, so the two read alike in a
/// log line; the head of a DID is where the method and the SCID live, which is
/// the part that differs between two personas.
const PROFILE_LABEL_DID_WIDTH: usize = 32;

/// The messaging-profile label for one persona listener: which community it
/// speaks for, and **which identity is speaking**.
///
/// The community half is its display name, else its **verified** agent name,
/// else the VTC DID. The identity half is the persona's own DID, truncated the
/// same way the R-DID labels truncate theirs.
///
/// The identity half is not decoration. This label names the messaging profile,
/// so it is what the transport puts in every `websocket_run{profile=…}` span and
/// what a mediator-side log has to be correlated against — and naming only the
/// community made it many-to-one: two personas in the same community produced
/// byte-identical labels, a persona in several communities took whichever
/// membership `find` happened to return first, and a persona with no community
/// at all was labelled the literal string `"Persona"`. All three were observed
/// in live logs, where one listener reconnecting and several reconnecting
/// independently were impossible to tell apart. Same defect the activity log
/// had, one layer down — and this is the layer you drop to when the activity log
/// is not enough.
///
/// Shared by [`Config::persona_profile_label_for`] and the hydration path in
/// `loading.rs`, which built this label with its own copy of the same
/// expression. The two must agree — otherwise a persona's messaging profile is
/// named one thing at startup and another at runtime — and holding one copy
/// makes that structural instead of a comment asking the next editor to
/// remember.
///
/// The middle arm used to be `context_path::render_for_display(&c.vtc_did)`.
/// That is a **sub-context** helper: it splits on the last `/` and returns the
/// tail, which is right for `openvtc-glenn/qmxi1pzd4nev` and a no-op on a DID,
/// since a DID contains no `/`. So the "slug" fallback was the whole
/// `did:webvh:Qm…` string. A verified agent name is the readable label that arm
/// was reaching for.
///
/// `agent_name` must yield **only verified** names. [`Config::agent_name_for`]
/// and [`ProtectedConfig::cached_agent_name`] both read the cache of completed
/// round-trips and collapse a cached negative to `None`, which is what callers
/// should pass. Rendering a name straight from a document's `alsoKnownAs` would
/// make this a phishing surface — anyone can claim `bigbank.com/@support` in
/// their own document. See [`crate::agent_name`].
///
/// The closure returns an owned `String` rather than a borrow: the two callers
/// hold the cache behind different owners (a `&Config` and, during loading, a
/// `ProtectedConfig` that is later moved into one), and a borrowed return has no
/// lifetime to tie itself to that satisfies both. The allocation happens only on
/// the fallback path, where a label is being built anyway.
pub(crate) fn membership_profile_label(
    membership: Option<&account::CommunityRecord>,
    persona_did: &str,
    agent_name: impl FnOnce(&str) -> Option<String>,
) -> String {
    let who = crate::display::truncate_did(persona_did, PROFILE_LABEL_DID_WIDTH);
    let Some(c) = membership else {
        // No community yet (State A). The DID is then the only thing that
        // distinguishes this listener, so it carries the label alone rather
        // than hiding behind a bare "Persona".
        return format!("Persona ({who})");
    };
    let community = c
        .display_name
        .clone()
        .or_else(|| agent_name(&c.vtc_did))
        .unwrap_or_else(|| c.vtc_did.clone());
    format!("{community} ({who})")
}

/// Decode a stored base64url `ProtectedConfig` key into raw bytes.
pub(crate) fn decode_protected_key(key: &SecretString) -> Result<SecretBox<Vec<u8>>, OpenVTCError> {
    use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
    let bytes = BASE64_URL_SAFE_NO_PAD
        .decode(key.expose_secret())
        .map_err(|e| OpenVTCError::Decrypt(format!("stored config key is not base64url: {e}")))?;
    if bytes.len() < 32 {
        return Err(OpenVTCError::Decrypt(
            "stored config key is shorter than 32 bytes".to_string(),
        ));
    }
    Ok(SecretBox::new(Box::new(bytes)))
}

impl Config {
    /// Returns the 32-byte encryption seed used to encrypt/decrypt `ProtectedConfig`.
    ///
    /// For `Bip32` backends, this derives the seed from path `m/0'/0'/0'`.
    /// For `Vta` backends, this returns the pre-computed SHA-256 hash of the private key.
    pub fn get_encryption_seed(&self) -> Result<SecretBox<Vec<u8>>, OpenVTCError> {
        // D12: the profile's own key wins whenever it exists. Only a config
        // written before that field existed falls through to the legacy
        // derivation, and only until its next save.
        if let Some(key) = &self.protected_key {
            return decode_protected_key(key);
        }
        self.legacy_encryption_seed()
    }

    /// The pre-D12 seed: derived from the key backend rather than stored.
    ///
    /// Retained as a *decryption* fallback, never as the preferred key. A
    /// profile mid-migration may still have its `ProtectedConfig` under this
    /// seed — `Config::save` writes the secured blob before the public one, so
    /// a crash between the two leaves the new key stored and the old blob on
    /// disk. Keeping both readable is what makes that survivable (R7).
    pub(crate) fn legacy_encryption_seed(&self) -> Result<SecretBox<Vec<u8>>, OpenVTCError> {
        match &self.key_backend {
            KeyBackend::Bip32 { root, .. } => ProtectedConfig::get_seed(root, "m/0'/0'/0'"),
            KeyBackend::Vta {
                encryption_seed, ..
            } => Ok(SecretBox::new(Box::new(
                encryption_seed.expose_secret().to_vec(),
            ))),
        }
    }

    /// The currently-active runtime identity — the persona the selected working
    /// community resolves to (D10 / R-C-6/7).
    ///
    /// Honours [`Config::active_persona`] (set by the loop from the selected
    /// community) so all identity-derived reads — [`Config::persona_did`],
    /// [`Config::mediator_did`], the main-page identity chrome, outbound actions —
    /// scope to the working community without threading a selection through every
    /// call site. Falls back to the first persona (lowest [`account::PersonaId`],
    /// deterministic because `identities` is a `BTreeMap`) when no selection is
    /// set — i.e. during startup/setup, or single-persona accounts — preserving
    /// the prior behaviour.
    pub fn active_identity(&self) -> Option<&crate::identity::IdentityContext> {
        self.active_persona
            .and_then(|id| self.identities.get(&id))
            .or_else(|| self.identities.values().next())
    }

    /// Point the runtime active identity at `persona` (the selected working
    /// community's persona, D10), or clear it back to the first-persona default.
    /// A no-op-safe setter the loop calls each iteration from the selection.
    pub fn set_active_persona(&mut self, persona: Option<account::PersonaId>) {
        self.active_persona = persona;
    }

    /// The active persona's `did:webvh` as a string slice.
    ///
    /// Replaces the removed `public.persona_did` singleton. Returns `""` when no
    /// identity is resolved — which should not occur after a successful load or
    /// setup, where exactly one persona is always active.
    pub fn persona_did(&self) -> &str {
        self.active_identity().map(|i| i.did.as_str()).unwrap_or("")
    }

    /// The active persona's `did:webvh` as an owned `Arc<String>`.
    ///
    /// For the call sites that previously cloned the `Arc<String>` singleton
    /// (e.g. to stash the DID on a message or relationship). The returned `Arc`
    /// is freshly allocated; equality is by value, so sharing is not required.
    pub fn persona_did_arc(&self) -> std::sync::Arc<String> {
        std::sync::Arc::new(self.persona_did().to_string())
    }

    /// The active persona's mediator DID as a string slice (`""` if unset).
    ///
    /// Replaces the removed `public.mediator_did` singleton.
    pub fn mediator_did(&self) -> &str {
        self.active_identity()
            .and_then(|i| i.mediator_did.as_deref())
            .unwrap_or("")
    }

    /// Human label for the active persona's messaging profile: the community it
    /// belongs to (its display name, else its verified agent name, else the VTC
    /// DID), so each community's profile is identifiable rather than a generic
    /// "Persona". Falls back to "Persona" when the persona has no community yet.
    pub fn persona_profile_label(&self) -> String {
        match self.active_identity().map(|i| i.persona_id) {
            Some(pid) => self.persona_profile_label_for(pid),
            None => "Persona".to_string(),
        }
    }

    /// Human label for a *specific* persona's messaging profile (see
    /// [`Config::persona_profile_label`]). Used when building one DIDComm
    /// listener per persona so each is named after its community.
    pub fn persona_profile_label_for(&self, persona_id: account::PersonaId) -> String {
        membership_profile_label(
            self.account
                .memberships()
                .find(|c| c.persona_ref == persona_id),
            self.identities
                .get(&persona_id)
                .map_or("", |identity| identity.did.as_str()),
            |did| self.agent_name_for(did).map(ToString::to_string),
        )
    }

    /// The verified agent name cached for `did`, if one is known.
    ///
    /// Returns `Some` only for a positive lookup; a cached *negative* result
    /// (the DID has no verifiable name) reads as `None`, same as an uncached
    /// DID. Callers that need to distinguish the two consult
    /// [`ProtectedConfig::agent_names`](crate::config::protected_config::ProtectedConfig)
    /// directly.
    #[must_use]
    pub fn agent_name_for(&self, did: &str) -> Option<&str> {
        self.private.cached_agent_name(did)
    }

    /// Record a verified agent-name lookup (positive or negative) for `did`,
    /// stamped `now`. Overwrites any prior entry.
    pub fn set_cached_agent_name(
        &mut self,
        did: &str,
        name: Option<String>,
        now: chrono::DateTime<chrono::Utc>,
    ) {
        self.private.agent_names.insert(
            did.to_string(),
            crate::agent_name::CachedAgentName {
                name,
                checked_at: now,
            },
        );
    }

    /// Every DID the UI displays that needs an agent-name lookup — those with no
    /// cache entry or a stale one (`now` past [`AGENT_NAME_TTL`]).
    ///
    /// Covers persona DIDs, community VTC DIDs, relationship remote-persona DIDs,
    /// contact DIDs, and the two infrastructure DIDs the VTA panel displays (the
    /// VTA's own DID and the active persona's mediator). De-duplicated; the same
    /// DID appearing in several places is resolved once. Fed to the background
    /// batch refresh.
    ///
    /// The infrastructure DIDs are included because the VTA panel renders them
    /// to the operator: a `did:webvh` VTA or mediator can publish a verifiable
    /// name like any other party, and leaving them out of the sweep was the only
    /// reason those two rows always showed a raw DID. A DID with no verifiable
    /// name simply caches a negative and keeps rendering as a DID.
    ///
    /// [`AGENT_NAME_TTL`]: crate::agent_name::AGENT_NAME_TTL
    #[must_use]
    pub fn agent_name_refresh_targets(&self, now: chrono::DateTime<chrono::Utc>) -> Vec<String> {
        let mut dids: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for persona in self.account.personas.values() {
            dids.insert(persona.did.clone());
        }
        for community in self.account.memberships() {
            dids.insert(community.vtc_did.clone());
        }
        for rel in self.private.relationships.relationships.values() {
            dids.insert(rel.remote_p_did.to_string());
        }
        for contact in self.private.contacts.contacts.keys() {
            dids.insert(contact.to_string());
        }
        // Every persona's mediator, plus the VTA's DID. Only `did:*` values —
        // a mediator field left empty must not become a lookup for "".
        for persona in self.account.personas.values() {
            if let Some(mediator) = persona.mediator_did.as_deref()
                && mediator.starts_with("did:")
            {
                dids.insert(mediator.to_string());
            }
        }
        if let KeyBackend::Vta { vta_did, .. } = &self.key_backend
            && vta_did.starts_with("did:")
        {
            dids.insert(vta_did.clone());
        }
        dids.into_iter()
            .filter(|did| {
                self.private
                    .agent_names
                    .get(did)
                    .is_none_or(|cached| cached.is_stale(now))
            })
            .collect()
    }

    /// Set the active persona's mediator DID, updating both the persisted
    /// `account` record and the runtime `IdentityContext` so subsequent reads
    /// (and the next save) see the new value.
    ///
    /// Returns `false` when there is no active identity to set it on — a
    /// State-A config carries an account but no persona (see
    /// [`Config::mediator_did`], which reads back `""` there), and a mediator
    /// DID is a *per-persona* field with nowhere to live until one exists.
    ///
    /// The caller must not report success on `false`. Swallowing it is what
    /// made this look like a working setting that "did not take": the write
    /// vanished, the field read back empty, and the UI still said "Setting
    /// saved".
    #[must_use = "a false return means the mediator DID was NOT set; do not report success"]
    pub fn set_active_mediator_did(&mut self, did: &str) -> bool {
        let Some(id) = self.active_identity().map(|i| i.persona_id) else {
            return false;
        };
        // The account record is the half that survives a restart, so it decides
        // the answer: updating only the runtime context would report a success
        // the operator loses on next launch. Load builds `identities` by walking
        // `account.personas`, so a missing record here is not reachable — this
        // is what keeps the `true` honest rather than assumed.
        let Some(persona) = self.account.personas.get_mut(&id) else {
            return false;
        };
        persona.mediator_did = Some(did.to_string());
        if let Some(ctx) = self.identities.get_mut(&id) {
            ctx.mediator_did = Some(did.to_string());
        }
        true
    }

    /// Whether `did` is one of our resolved persona DIDs (vs. a relationship
    /// R-DID or a remote party's DID). Used to route inbound replies out of the
    /// addressed persona and to map a persona DID to its DIDComm listener.
    pub fn is_persona_did(&self, did: &str) -> bool {
        self.identities.values().any(|i| i.did == did)
    }
}

/// Build an authenticated [`vta_sdk::client::VtaClient`] from a `KeyBackend::Vta`,
/// preserving whichever transport (REST or DIDComm) was selected at setup.
///
/// - **DIDComm** — `mediator_did` is `Some`: opens a fresh DIDComm session
///   as the credential DID against the advertised mediator. The session
///   itself is the authenticator; no separate token round-trip happens.
/// - **REST** — `mediator_did` is `None`: runs a challenge-response auth
///   against `vta_url`, then attaches the bearer token to a REST client.
///
/// Returns an error for non-VTA backends (callers should branch on the
/// backend variant before calling).
pub async fn build_runtime_vta_client(
    backend: &KeyBackend,
) -> Result<vta_sdk::client::VtaClient, OpenVTCError> {
    let KeyBackend::Vta {
        vta_url,
        vta_did,
        credential_did,
        credential_private_key,
        mediator_did,
        ..
    } = backend
    else {
        return Err(OpenVTCError::Config(
            "build_runtime_vta_client called on a non-VTA key backend".to_string(),
        ));
    };

    // The transport choice (DIDComm vs REST), the `rest_fallback` derivation,
    // and the empty-URL rule are SDK-level knowledge — `connect_auto`
    // encapsulates them so this no longer hand-rolls the branch (R22). The
    // issued REST token is dropped: runtime clients re-auth per process and
    // never cached it here.
    let mut client = vta_sdk::client::VtaClient::connect_auto(vta_sdk::client::AutoConnect {
        vta_url,
        vta_did,
        credential_did,
        private_key_multibase: credential_private_key.expose_secret(),
        mediator_did: mediator_did.as_deref(),
    })
    .await
    .map(|connected| connected.client)
    .map_err(map_connect_error)?;

    enable_tsp_if_advertised(&mut client, vta_did).await;
    Ok(client)
}

/// Ceiling on the `#tsp` discovery resolve.
///
/// TSP is an upgrade, not a requirement, so this must never be able to delay
/// startup by more than a beat (R1.2). A resolver that hangs leaves the client on
/// DIDComm, which is exactly where it was before.
const TSP_DISCOVERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Move the Trust-Task surface onto TSP when the VTA advertises `#tsp`.
///
/// Only the **trust-task** surface moves. `rpc`/`rpc_void` — key management,
/// `create_did_webvh`, `list_contexts` — stay on DIDComm unconditionally, because
/// the VTA has no TSP dispatcher behind them. That per-surface split is the whole
/// reason this is a call on an existing client rather than a transport choice at
/// connect time (VTI #803 / #810).
///
/// No second socket: `enable_tsp_trust_tasks` rides the DIDComm session's own
/// mediator connection. The mediator permits one websocket per DID, and opening a
/// second is what made the previous `connect_tsp` route unusable for a consumer
/// that already held a session.
///
/// **Best-effort by construction.** Every failure path leaves the client exactly as
/// `connect_auto` returned it — on DIDComm, fully working. A VTA that advertises no
/// `#tsp`, a resolve that times out, or a split-mediator topology (which needs its
/// own session and key material a `DIDCommSession` deliberately does not keep) all
/// degrade silently to the previous behaviour rather than failing a startup that
/// would otherwise have succeeded.
async fn enable_tsp_if_advertised(client: &mut vta_sdk::client::VtaClient, vta_did: &str) {
    let resolver = match affinidi_did_resolver_cache_sdk::DIDCacheClient::new(
        affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
    )
    .await
    {
        Ok(resolver) => resolver,
        Err(e) => {
            tracing::debug!("TSP discovery resolver init failed ({e}); staying on DIDComm");
            return;
        }
    };
    enable_tsp_with_resolver(client, vta_did, &resolver).await;
}

/// The TSP mediator `peer_did` advertises, if any — for a **VTC**, not the VTA.
///
// Not an intra-doc link: `discover_tsp_mediator` is private, and a public item
// linking to it fails `rustdoc -D warnings`.
/// Same `#tsp` / `TSPTransport` lookup `discover_tsp_mediator` does for a VTA:
/// the service entry is generic, so what changes is only whose document is read.
/// Exposed publicly because the ceremony call sites live in the binary crate.
///
/// `None` on every non-answer — not advertised, unresolvable, or the bounded wait
/// elapsed — because all three mean the same thing to a caller: **use DIDComm**.
/// The distinction is kept in the log rather than the return type (R6.4), since
/// unlike the VTA panel there is nothing here to render it into.
///
/// Discovery is deliberately per-send rather than cached on the community: the
/// resolver caches the document, so a repeat is cheap, and a VTC that gains or
/// loses `#tsp` is picked up without a restart or a migration.
pub async fn peer_tsp_mediator(peer_did: &str) -> Option<String> {
    let resolver = match affinidi_did_resolver_cache_sdk::DIDCacheClient::new(
        affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
    )
    .await
    {
        Ok(resolver) => resolver,
        Err(e) => {
            tracing::debug!(
                peer = %peer_did,
                "TSP discovery resolver init failed ({e}); using DIDComm"
            );
            return None;
        }
    };
    match discover_tsp_mediator(peer_did, &resolver).await {
        TspDiscovery::Advertised(mediator) => {
            tracing::info!(
                peer = %peer_did,
                mediator = %mediator,
                "peer advertises #tsp — sending trust tasks over TSP"
            );
            Some(mediator)
        }
        TspDiscovery::NotAdvertised => {
            tracing::debug!(peer = %peer_did, "peer advertises no #tsp — using DIDComm");
            None
        }
        TspDiscovery::Unavailable(reason) => {
            tracing::warn!(
                peer = %peer_did,
                reason = %reason,
                "could not determine whether the peer offers TSP — using DIDComm"
            );
            None
        }
    }
}

/// The messaging transports a peer's DID document actually offers us.
///
/// Both halves come from **one** resolve — `resolve_vta_with_resolver` returns
/// the TSP mediator and the DIDComm mediator together — so asking about both
/// costs no more than asking about TSP alone.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PeerTransports {
    /// Mediator DID from a `#tsp` / `TSPTransport` service, if advertised.
    pub tsp_mediator: Option<String>,
    /// Mediator DID from a `DIDCommMessaging` service, if advertised.
    pub didcomm_mediator: Option<String>,
}

impl PeerTransports {
    /// Whether the peer offers any transport we can send a join over.
    ///
    /// A peer advertising neither cannot be joined at all, and finding that out
    /// *before* minting a persona is the difference between a clear refusal and
    /// an orphaned identity attached to a request nobody received.
    #[must_use]
    pub fn any(&self) -> bool {
        self.tsp_mediator.is_some() || self.didcomm_mediator.is_some()
    }

    /// Which transport a send would actually choose, mirroring the stack's
    /// prefer-TSP-then-DIDComm order.
    #[must_use]
    pub fn preferred(&self) -> Option<crate::didcomm::MessagingTransport> {
        if self.tsp_mediator.is_some() {
            Some(crate::didcomm::MessagingTransport::Tsp)
        } else if self.didcomm_mediator.is_some() {
            Some(crate::didcomm::MessagingTransport::DidComm)
        } else {
            None
        }
    }
}

/// Ask a peer's DID document which messaging transports it offers.
///
/// Deliberately *not* a reachability check. It reports what the document
/// advertises, which is all a client can know before sending — a peer that
/// advertises a transport its binary cannot decode looks identical from here,
/// and is the peer's defect to fix, not ours to work around. What this buys is
/// refusing the genuinely impossible case (a peer advertising nothing) early.
pub async fn peer_messaging_transports(peer_did: &str) -> PeerTransports {
    let Ok(resolver) = affinidi_did_resolver_cache_sdk::DIDCacheClient::new(
        affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
    )
    .await
    else {
        // Resolver init failure is not "the peer offers nothing" — say nothing
        // rather than block a join on a local fault.
        tracing::debug!(peer = %peer_did, "transport discovery resolver init failed");
        return PeerTransports {
            tsp_mediator: None,
            didcomm_mediator: None,
        };
    };

    match tokio::time::timeout(
        TSP_DISCOVERY_TIMEOUT,
        vta_sdk::provision_client::resolve_vta_with_resolver(peer_did, &resolver),
    )
    .await
    {
        Ok(Ok(resolved)) => PeerTransports {
            tsp_mediator: resolved.tsp_mediator_did,
            didcomm_mediator: resolved.mediator_did,
        },
        Ok(Err(e)) => {
            tracing::debug!(peer = %peer_did, error = %e, "transport discovery failed");
            PeerTransports::default()
        }
        Err(_) => {
            tracing::debug!(peer = %peer_did, "transport discovery timed out");
            PeerTransports::default()
        }
    }
}

/// Whether **our own** mediator can carry a TSP frame at all.
///
/// The other half of the transport decision, and the half a peer's document
/// cannot answer. A TSP send is an HTTP POST of raw CESR bytes to *our*
/// mediator's `/inbound` (`affinidi_messaging_sdk::protocols::TspOps::send_raw`)
/// — the peer's advertised mediator is only the hop the routing layer is sealed
/// to, and never sees the request. A mediator built without its `tsp` cargo
/// feature has no protocol sniff compiled in, so it hands the frame to the
/// DIDComm JSON parser and answers `400 w.m.message.deserialize`, before the
/// community is reached and with the peer's mediator named in the error.
///
/// [`TspCarriage::Unknown`] is kept distinct from [`TspCarriage::Absent`] for
/// the same reason [`TspDiscovery`] keeps them apart (R6.4): "your mediator does
/// not do TSP" is worth acting on, "we could not ask" is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TspCarriage {
    /// The mediator's own document advertises `TSPTransport` — it speaks TSP.
    Serves,
    /// Resolved fine; the mediator advertises no TSP transport. Not a fault of
    /// ours, and the reason to stay on DIDComm.
    Absent,
    /// Could not determine (resolve error, or the bounded wait elapsed).
    Unknown(String),
}

/// Ask a mediator's own DID document whether it carries TSP.
///
/// Split from applying the result so it is testable against a seeded resolver,
/// exactly as [`discover_tsp_mediator`] is.
///
/// Deliberately **not** `resolve_vta_with_resolver`: that helper keeps a `#tsp`
/// endpoint only when it is a DID, because a *peer's* `#tsp` advertises its
/// mediator by DID. A mediator's own `#tsp` carries the transport URL instead
/// (`https://mediator.example/mediator/v1`), so the VTA-shaped helper drops it
/// and would report every mediator as TSP-less. `ServiceCapabilities` is the
/// workspace's one service-type matcher and reads either shape — and matches on
/// the service `type`, never the `#id` fragment.
pub(crate) async fn mediator_tsp_carriage(
    mediator_did: &str,
    resolver: &affinidi_did_resolver_cache_sdk::DIDCacheClient,
) -> TspCarriage {
    let resolved =
        match tokio::time::timeout(TSP_DISCOVERY_TIMEOUT, resolver.resolve(mediator_did)).await {
            Ok(Ok(resolved)) => resolved,
            Ok(Err(e)) => return TspCarriage::Unknown(e.to_string()),
            Err(_) => {
                return TspCarriage::Unknown(format!(
                    "timed out after {}s",
                    TSP_DISCOVERY_TIMEOUT.as_secs()
                ));
            }
        };

    let doc = match serde_json::to_value(&resolved.doc) {
        Ok(doc) => doc,
        Err(e) => return TspCarriage::Unknown(format!("could not re-serialize document: {e}")),
    };

    if vta_sdk::protocol::matching::ServiceCapabilities::from_did_document(&doc)
        .tsp
        .is_some()
    {
        TspCarriage::Serves
    } else {
        TspCarriage::Absent
    }
}

/// Whether the mediator we would post through carries TSP.
///
/// `Some(true)` / `Some(false)` are answers; `None` means we could not ask, and
/// a caller must not read it as either.
///
// Not an intra-doc link: `TspCarriage` is private, and a public item linking to
// it fails `rustdoc -D warnings` — the same trap `peer_tsp_mediator` above
// carries this note for.
/// The three-way distinction it collapses lives on `TspCarriage`. Exposed
/// publicly because the ceremony call sites live in the binary crate, matching
/// [`peer_tsp_mediator`] beside it.
pub async fn our_mediator_carries_tsp(mediator_did: &str) -> Option<bool> {
    if mediator_did.is_empty() {
        return None;
    }
    let resolver = match affinidi_did_resolver_cache_sdk::DIDCacheClient::new(
        affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
    )
    .await
    {
        Ok(resolver) => resolver,
        Err(e) => {
            tracing::debug!(
                mediator = %mediator_did,
                "TSP carriage resolver init failed ({e})"
            );
            return None;
        }
    };
    match mediator_tsp_carriage(mediator_did, &resolver).await {
        TspCarriage::Serves => Some(true),
        TspCarriage::Absent => {
            tracing::debug!(
                mediator = %mediator_did,
                "our mediator advertises no TSPTransport — TSP sends would be rejected"
            );
            Some(false)
        }
        TspCarriage::Unknown(reason) => {
            tracing::warn!(
                mediator = %mediator_did,
                reason = %reason,
                "could not determine whether our mediator carries TSP"
            );
            None
        }
    }
}

/// What transport discovery decided about the TSP leg.
///
/// Returned rather than logged-and-dropped so the decision is assertable. The
/// caller turns it into a log line; a test turns it into an assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TspDiscovery {
    /// The VTA advertises `#tsp` at this mediator — enable the leg.
    Advertised(String),
    /// Resolved fine; the VTA simply offers no `#tsp` service. Not a fault.
    NotAdvertised,
    /// Discovery could not complete (resolve error, or the bounded wait elapsed).
    /// Also not a fault: TSP is an upgrade, so this degrades to DIDComm.
    Unavailable(String),
}

/// Ask the VTA's DID document whether it advertises a TSP mediator.
///
/// Split from applying the result purely so it is testable. `resolve_vta` builds
/// its resolver from the environment, so a test could not point discovery at a
/// fixture — which is why #196 shipped with this path verified by construction
/// rather than execution. vta-sdk 0.20.3 added the seam upstream (VTI #813); this
/// is that seam one layer down, so a test can seed a `#tsp`-advertising document
/// and assert what OpenVTC makes of it.
///
/// Bounded at [`TSP_DISCOVERY_TIMEOUT`] (R1.2): TSP is an upgrade, so discovery
/// must never delay startup by more than a beat.
pub(crate) async fn discover_tsp_mediator(
    vta_did: &str,
    resolver: &affinidi_did_resolver_cache_sdk::DIDCacheClient,
) -> TspDiscovery {
    let resolved = match tokio::time::timeout(
        TSP_DISCOVERY_TIMEOUT,
        vta_sdk::provision_client::resolve_vta_with_resolver(vta_did, resolver),
    )
    .await
    {
        Ok(Ok(resolved)) => resolved,
        Ok(Err(e)) => return TspDiscovery::Unavailable(e.to_string()),
        Err(_) => {
            return TspDiscovery::Unavailable(format!(
                "timed out after {}s",
                TSP_DISCOVERY_TIMEOUT.as_secs()
            ));
        }
    };

    match resolved.tsp_mediator_did {
        Some(mediator) => TspDiscovery::Advertised(mediator),
        None => TspDiscovery::NotAdvertised,
    }
}

/// [`enable_tsp_if_advertised`] over a caller-supplied resolver.
async fn enable_tsp_with_resolver(
    client: &mut vta_sdk::client::VtaClient,
    vta_did: &str,
    resolver: &affinidi_did_resolver_cache_sdk::DIDCacheClient,
) {
    match discover_tsp_mediator(vta_did, resolver).await {
        TspDiscovery::Advertised(mediator) => match client.enable_tsp_trust_tasks(&mediator) {
            Ok(()) => tracing::info!("trust tasks routed over TSP (mediator {mediator})"),
            Err(e) => {
                tracing::debug!("could not enable the TSP leg ({e}); trust tasks stay on DIDComm")
            }
        },
        TspDiscovery::NotAdvertised => {
            tracing::debug!("{vta_did} advertises no #tsp service; trust tasks stay on DIDComm")
        }
        TspDiscovery::Unavailable(reason) => {
            tracing::debug!("TSP discovery for {vta_did} failed ({reason}); staying on DIDComm")
        }
    }
}

/// Map a `vta_sdk` connect error onto the typed [`OpenVTCError`] taxonomy so
/// callers can keep distinguishing retryable transport/auth failures from
/// genuine config corruption (R18). An empty `vta_url` on the REST path comes
/// back as [`vta_sdk::error::VtaError::Validation`] — that is a bad on-disk
/// config, so it maps to [`OpenVTCError::Config`]; auth rejection maps to
/// [`OpenVTCError::Auth`]; everything else (network, DIDComm session open) is a
/// live-VTA reachability problem, [`OpenVTCError::Vta`].
fn map_connect_error(e: vta_sdk::error::VtaError) -> OpenVTCError {
    use vta_sdk::error::VtaError;
    match e {
        VtaError::Validation(msg) => OpenVTCError::Config(msg),
        VtaError::Auth(msg) => OpenVTCError::Auth(format!("VTA authentication failed: {msg}")),
        other => OpenVTCError::Vta(format!("VTA connection failed: {other}")),
    }
}

/// Run `f` with a runtime VTA client built from `backend`, guaranteeing the
/// (DIDComm) session is shut down whether `f` returns `Ok` **or** `Err`.
///
/// Mirrors [`vta_sdk::client::VtaClient::with_didcomm`] but threads the caller's
/// own error type — any `E: From<OpenVTCError>` (e.g. [`OpenVTCError`] or
/// `anyhow::Error`). `shutdown` is a no-op for the REST transport. Prefer this
/// over [`build_runtime_vta_client`] + a manual `shutdown()`: an early `?` in the
/// body can otherwise drop the session without closing it, leaking a live
/// session (and tripping the SDK's `LeakGuard`).
pub async fn with_runtime_vta_client<F, Fut, T, E>(backend: &KeyBackend, f: F) -> Result<T, E>
where
    F: FnOnce(vta_sdk::client::VtaClient) -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: From<OpenVTCError>,
{
    // Hand the body an owned clone (a `VtaClient` shares its session across
    // clones, and `shutdown` is idempotent) — passing by value sidesteps the
    // async-closure-borrowed-argument lifetime limitation.
    let client = build_runtime_vta_client(backend).await?;
    let result = f(client.clone()).await;
    client.shutdown().await;
    result
}

// ****************************************************************************
// Key Types
// ****************************************************************************

/// Classifies how a cryptographic key is used within the OpenVTC system.
#[derive(Clone, Serialize, Default, Deserialize, Debug)]
pub enum KeyTypes {
    /// Ed25519 key used for signing assertions on the persona DID.
    PersonaSigning,
    /// Ed25519 key used for authenticating the persona DID.
    PersonaAuthentication,
    /// X25519 key used for encryption on the persona DID.
    PersonaEncryption,
    /// Other persona-level key not fitting the above categories.
    PersonaOther,
    /// Ed25519 verification key bound to a specific relationship DID.
    RelationshipVerification,
    /// X25519 encryption key bound to a specific relationship DID.
    RelationshipEncryption,
    /// Key used for managing (updating) a `did:webvh` DID log.
    WebVHManagement,
    /// Key purpose has not been determined.
    #[default]
    Unknown,
}

impl Display for KeyTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            KeyTypes::PersonaSigning => "Persona Signing Key",
            KeyTypes::PersonaAuthentication => "Persona Authentication Key",
            KeyTypes::PersonaEncryption => "Persona Encryption Key",
            KeyTypes::PersonaOther => "Persona Other Key",
            KeyTypes::RelationshipVerification => "Relationship Verification Key",
            KeyTypes::RelationshipEncryption => "Relationship Encryption Key",
            KeyTypes::WebVHManagement => "Web VH Management Key",
            KeyTypes::Unknown => "Unknown Key Type",
        };
        write!(f, "{}", s)
    }
}

/// Secrets for the Persona DID.
///
/// Implements [`Drop`] to zeroize contained key material when the struct goes out of scope.
#[derive(Clone)]
pub struct PersonaDIDKeys {
    pub signing: KeyInfo,
    pub authentication: KeyInfo,
    pub decryption: KeyInfo,
}

impl std::fmt::Debug for PersonaDIDKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PersonaDIDKeys")
            .field("signing", &"[REDACTED]")
            .field("authentication", &"[REDACTED]")
            .field("decryption", &"[REDACTED]")
            .finish()
    }
}

/// Contains relevant key information required for setting up, configuring and managing keys.
///
/// Implements [`Drop`] to zeroize contained key material when the struct goes out of scope.
#[derive(Clone)]
pub struct KeyInfo {
    /// Secret Key Material that can be used within the TDK environment
    pub secret: Secret,
    /// Where did this key come from? Derived from BIP32 or Imported?
    pub source: KeySourceMaterial,

    /// Section 5.5.2 of RFC 4880 - Expiry time if set is # of days since creation
    pub expiry: Option<TimeDelta>,
    pub created: DateTime<Utc>,
}

impl std::fmt::Debug for KeyInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyInfo")
            .field("secret", &"[REDACTED]")
            .field("source", &self.source)
            .field("expiry", &self.expiry)
            .field("created", &self.created)
            .finish()
    }
}

/// TSP discovery against a **seeded** resolver.
///
/// These are the assertions #196 could not make. Its enablement path was verified
/// by construction, because `resolve_vta` built its resolver from the environment
/// and no fixture could reach it. vta-sdk 0.20.3 (VTI #813) added the seam; this
/// exercises it, in-process with no network and no live VTA.
#[cfg(test)]
mod tsp_discovery_tests {
    use super::{TspDiscovery, discover_tsp_mediator};
    use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
    use serde_json::json;

    const VTA: &str = "did:web:vta.example";
    const MEDIATOR: &str = "did:web:mediator.example";

    async fn resolver_serving(services: serde_json::Value) -> DIDCacheClient {
        let mut client = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .expect("local DID cache");
        let doc = json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": VTA,
            "service": services,
        });
        client
            .add_did_document(VTA, serde_json::from_value(doc).expect("fixture document"))
            .await;
        client
    }

    /// The reference deployment's shape: `#tsp` and `#vta-didcomm` at the **same**
    /// mediator. This is the case #196 wires up and could not previously assert.
    #[tokio::test]
    async fn a_tsp_advertising_vta_yields_its_mediator() {
        let resolver = resolver_serving(json!([
            { "id": format!("{VTA}#tsp"), "type": "TSPTransport", "serviceEndpoint": MEDIATOR },
            { "id": format!("{VTA}#vta-didcomm"), "type": "DIDCommMessaging", "serviceEndpoint": MEDIATOR },
        ]))
        .await;

        assert_eq!(
            discover_tsp_mediator(VTA, &resolver).await,
            TspDiscovery::Advertised(MEDIATOR.to_string()),
        );
    }

    /// A VTA offering no `#tsp` must report exactly that — distinct from a
    /// discovery failure, because only one of the two is worth an operator's
    /// attention (R6.4). Both still degrade to DIDComm.
    #[tokio::test]
    async fn a_didcomm_only_vta_is_not_advertised_rather_than_failed() {
        let resolver = resolver_serving(json!([
            { "id": format!("{VTA}#vta-didcomm"), "type": "DIDCommMessaging", "serviceEndpoint": MEDIATOR },
        ]))
        .await;

        assert_eq!(
            discover_tsp_mediator(VTA, &resolver).await,
            TspDiscovery::NotAdvertised,
        );
    }

    /// A DID that resolves to nothing **and** yields no URL is `Unavailable`,
    /// not `NotAdvertised`. Conflating them would report "this VTA offers no TSP"
    /// about one we simply failed to ask — the false-certainty #187 fixed in the
    /// panel.
    #[tokio::test]
    async fn an_unresolvable_vta_is_unavailable_not_unadvertised() {
        let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .expect("local DID cache");

        assert!(matches!(
            discover_tsp_mediator("did:example:nothing-seeded", &resolver).await,
            TspDiscovery::Unavailable(_)
        ));
    }

    /// **An unresolvable `did:web` reports `NotAdvertised`, not `Unavailable`** —
    /// surprising, and worth pinning rather than discovering again.
    ///
    /// `resolve_vta_endpoint` falls back to synthesizing `https://<domain>` from
    /// the DID itself when resolution fails, and returns that as a REST endpoint.
    /// So discovery succeeds, reports no `#tsp`, and we degrade to DIDComm — the
    /// right outcome, reached by a route that hides the resolution failure.
    ///
    /// Only `did:web` and `did:webvh` have a domain to synthesize from, which is
    /// why the test above needs a method that does not.
    ///
    /// **The address is loopback with a closed port on purpose, and must stay
    /// that way.** This asserts what the fallback does when resolution fails,
    /// so it needs resolution to fail *quickly*: the call is wrapped in
    /// [`TSP_DISCOVERY_TIMEOUT`], and a timeout reports `Unavailable` — the
    /// other outcome, which flips the assertion.
    ///
    /// It named `nothing-seeded.example` until this bump, which made a real DNS
    /// query. A resolver that answers NXDOMAIN instantly gives `NotAdvertised`;
    /// one that hangs on an unknown TLD gives a 5s timeout and `Unavailable`.
    /// So the test asserted a property of the environment's DNS as much as of
    /// this code, and duly failed on a macOS runner while passing everywhere
    /// else. Port 1 on 127.0.0.1 is refused by the kernel, with no name to look
    /// up, so every machine reaches the same branch the same way.
    #[tokio::test]
    async fn an_unresolvable_did_web_falls_back_rather_than_failing() {
        let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .expect("local DID cache");

        assert_eq!(
            discover_tsp_mediator("did:web:127.0.0.1%3A1", &resolver).await,
            TspDiscovery::NotAdvertised,
            "the URL fallback makes this look resolved"
        );
    }

    /// A `#tsp` entry carrying a URL rather than a mediator DID is a
    /// misconfiguration, not a routable endpoint. Enabling the leg against it
    /// would point trust tasks at something that cannot carry them.
    #[tokio::test]
    async fn a_non_did_tsp_endpoint_is_not_advertised() {
        let resolver = resolver_serving(json!([
            { "id": format!("{VTA}#tsp"), "type": "TSPTransport", "serviceEndpoint": "https://not-a-did.example" },
            { "id": format!("{VTA}#vta-didcomm"), "type": "DIDCommMessaging", "serviceEndpoint": MEDIATOR },
        ]))
        .await;

        assert_eq!(
            discover_tsp_mediator(VTA, &resolver).await,
            TspDiscovery::NotAdvertised,
        );
    }
}

/// Whether *our own* mediator carries TSP — the leg a peer's document cannot
/// answer, and the one that actually refused a live join.
///
/// The failure these pin: a community advertising `#tsp` at a TSP-capable
/// mediator, joined from a persona whose own mediator was built without the
/// feature. The send posts to *our* mediator, which fed the CESR frame to its
/// DIDComm JSON parser and answered `400 w.m.message.deserialize` — while the
/// error named the community's mediator, which never saw the request.
#[cfg(test)]
mod mediator_tsp_carriage_tests {
    use super::{TspCarriage, mediator_tsp_carriage};
    use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
    use serde_json::json;

    const MEDIATOR: &str = "did:web:mediator.example";

    async fn resolver_serving(services: serde_json::Value) -> DIDCacheClient {
        let mut client = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .expect("local DID cache");
        let doc = json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": MEDIATOR,
            "service": services,
        });
        client
            .add_did_document(
                MEDIATOR,
                serde_json::from_value(doc).expect("fixture document"),
            )
            .await;
        client
    }

    /// A mediator's own `#tsp` carries a transport **URL**, not a mediator DID —
    /// the shape `resolve_vta_with_resolver` discards, and the reason this check
    /// reads the document through `ServiceCapabilities` instead.
    #[tokio::test]
    async fn a_tsp_mediator_serves() {
        let resolver = resolver_serving(json!([
            { "id": format!("{MEDIATOR}#tsp"), "type": "TSPTransport", "serviceEndpoint": "https://mediator.example/mediator/v1" },
            { "id": format!("{MEDIATOR}#service"), "type": ["DIDCommMessaging"], "serviceEndpoint": [{ "uri": "https://mediator.example/mediator/v1", "accept": ["didcomm/v2"] }] },
        ]))
        .await;

        assert_eq!(
            mediator_tsp_carriage(MEDIATOR, &resolver).await,
            TspCarriage::Serves,
        );
    }

    /// The live shape that broke the join: DIDComm and Authentication, no TSP.
    /// `Absent` rather than `Unknown`, because the document answered — which is
    /// what lets the caller downgrade to DIDComm instead of guessing.
    #[tokio::test]
    async fn a_didcomm_only_mediator_is_absent_not_unknown() {
        let resolver = resolver_serving(json!([
            { "id": format!("{MEDIATOR}#service"), "type": ["DIDCommMessaging"], "serviceEndpoint": [{ "uri": "https://mediator.example/mediator/v1", "accept": ["didcomm/v2"] }] },
            { "id": format!("{MEDIATOR}#auth"), "type": ["Authentication"], "serviceEndpoint": "https://mediator.example/mediator/v1/authenticate" },
        ]))
        .await;

        assert_eq!(
            mediator_tsp_carriage(MEDIATOR, &resolver).await,
            TspCarriage::Absent,
        );
    }

    /// Matching is on the service `type`, never the `#id` fragment — the OWF
    /// reference implementation names it `#tsp-transport` where ours says `#tsp`.
    #[tokio::test]
    async fn carriage_is_matched_on_type_not_id_fragment() {
        let resolver = resolver_serving(json!([
            { "id": format!("{MEDIATOR}#tsp-transport"), "type": "TSPTransport", "serviceEndpoint": "https://mediator.example/mediator/v1" },
        ]))
        .await;

        assert_eq!(
            mediator_tsp_carriage(MEDIATOR, &resolver).await,
            TspCarriage::Serves,
        );
    }

    /// A mediator we could not ask is `Unknown` — never `Absent`. Conflating
    /// them would report "your mediator does not do TSP" about one we simply
    /// failed to resolve, and silently downgrade a healthy TSP deployment.
    #[tokio::test]
    async fn an_unresolvable_mediator_is_unknown() {
        let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .expect("local DID cache");

        assert!(matches!(
            mediator_tsp_carriage("did:example:nothing-seeded", &resolver).await,
            TspCarriage::Unknown(_)
        ));
    }
}

#[cfg(test)]
mod membership_profile_label_tests {
    use super::membership_profile_label;
    use crate::config::account::{CommunityRecord, PersonaId};

    const VTC_DID: &str = "did:webvh:QmScidCommunityCCCCCCCCCCCC:vtc.example:acme";
    const PERSONA_DID: &str = "did:webvh:QmScidPersonaAAAAAAAAAAAAAA:vtc.example:alice";
    /// What `PERSONA_DID` renders as inside a label.
    const PERSONA_SHORT: &str = "did:webvh:QmScidPersonaAAAAAA...";

    fn membership(display_name: Option<&str>) -> CommunityRecord {
        CommunityRecord::new_pending(
            VTC_DID.to_string(),
            display_name.map(ToString::to_string),
            "openvtc-glenn/qmxi1pzd4nev".to_string(),
            PersonaId::default(),
            uuid::Uuid::nil(),
            chrono::Utc::now(),
        )
    }

    /// A display name resolved from the VTC document wins outright — it is the
    /// community's own name for itself.
    #[test]
    fn a_display_name_is_preferred() {
        let c = membership(Some("Acme Corp"));
        let label = membership_profile_label(Some(&c), PERSONA_DID, |_| {
            Some("vtc.example/@acme".to_string())
        });
        assert_eq!(label, format!("Acme Corp ({PERSONA_SHORT})"));
    }

    /// The arm this change fixes. It used to run the DID through
    /// `context_path::render_for_display` — a no-op on a DID — so the label was
    /// the whole `did:webvh:…` string.
    #[test]
    fn a_verified_agent_name_is_used_when_there_is_no_display_name() {
        let c = membership(None);
        let label = membership_profile_label(Some(&c), PERSONA_DID, |did| {
            assert_eq!(did, VTC_DID, "the VTC DID is what gets looked up");
            Some("vtc.example/@acme".to_string())
        });
        assert_eq!(label, format!("vtc.example/@acme ({PERSONA_SHORT})"));
    }

    /// No display name and no *verified* name leaves the DID. Unpretty, but it
    /// is the only thing left that is true — a name that did not verify must
    /// never be shown (see `crate::agent_name`).
    #[test]
    fn an_unverified_community_falls_back_to_the_did() {
        let c = membership(None);
        assert_eq!(
            membership_profile_label(Some(&c), PERSONA_DID, |_| None),
            format!("{VTC_DID} ({PERSONA_SHORT})")
        );
    }

    /// A persona with no community yet (State A) is named by its DID rather
    /// than the bare word "Persona" — which is what several State-A listeners
    /// used to share, in the logs and in the mediator's view alike.
    #[test]
    fn no_membership_is_still_identified_by_its_did() {
        assert_eq!(
            membership_profile_label(None, PERSONA_DID, |_| None),
            format!("Persona ({PERSONA_SHORT})")
        );
    }

    /// The property the whole change exists for: two personas in the SAME
    /// community must not produce the same label. Before this, both were named
    /// only after the community and were indistinguishable in every
    /// `websocket_run{profile=…}` span the transport emits.
    #[test]
    fn two_personas_in_one_community_are_distinguishable() {
        const OTHER_PERSONA: &str = "did:webvh:QmScidPersonaBBBBBBBBBBBBBB:vtc.example:bob";
        let c = membership(Some("Acme Corp"));

        let one = membership_profile_label(Some(&c), PERSONA_DID, |_| None);
        let two = membership_profile_label(Some(&c), OTHER_PERSONA, |_| None);

        assert_ne!(
            one, two,
            "same community, different identity: {one} / {two}"
        );
        assert!(one.starts_with("Acme Corp ("), "{one}");
        assert!(two.starts_with("Acme Corp ("), "{two}");
    }

    /// A DID short enough not to need truncating is carried whole, so the
    /// label never invents an ellipsis.
    #[test]
    fn a_short_did_is_not_truncated() {
        const SHORT: &str = "did:key:z6MkShort";
        assert_eq!(
            membership_profile_label(None, SHORT, |_| None),
            format!("Persona ({SHORT})")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn test_derive_passphrase_key_deterministic() {
        let key1 = derive_passphrase_key(b"my-passphrase", b"info-label").unwrap();
        let key2 = derive_passphrase_key(b"my-passphrase", b"info-label").unwrap();
        assert_eq!(key1, key2, "Same inputs must produce the same derived key");
    }

    #[test]
    fn test_derive_passphrase_key_different_info_differs() {
        let key_a = derive_passphrase_key(b"same-passphrase", b"info-a").unwrap();
        let key_b = derive_passphrase_key(b"same-passphrase", b"info-b").unwrap();
        assert_ne!(
            key_a, key_b,
            "Different info labels must produce different keys"
        );
    }

    #[test]
    fn test_derive_passphrase_key_different_passphrase_differs() {
        let key_a = derive_passphrase_key(b"passphrase-one", b"same-info").unwrap();
        let key_b = derive_passphrase_key(b"passphrase-two", b"same-info").unwrap();
        assert_ne!(
            key_a, key_b,
            "Different passphrases must produce different keys"
        );
    }

    #[test]
    fn test_unlock_code_from_string_deterministic() {
        let uc1 = UnlockCode::from_string("my-unlock-phrase").unwrap();
        let uc2 = UnlockCode::from_string("my-unlock-phrase").unwrap();
        assert_eq!(
            uc1.0.expose_secret(),
            uc2.0.expose_secret(),
            "Same input string must produce the same unlock code"
        );
    }

    #[test]
    fn test_unlock_code_from_string_different_inputs_differ() {
        let uc1 = UnlockCode::from_string("phrase-alpha-long").unwrap();
        let uc2 = UnlockCode::from_string("phrase-beta-long").unwrap();
        assert_ne!(
            uc1.0.expose_secret(),
            uc2.0.expose_secret(),
            "Different input strings must produce different unlock codes"
        );
    }

    #[test]
    fn test_unlock_code_rejects_short_passphrase() {
        assert!(
            UnlockCode::from_string("short").is_err(),
            "Passphrase shorter than MIN_PASSPHRASE_LENGTH should be rejected"
        );
    }

    #[test]
    fn test_validate_passphrase_minimum_length() {
        assert!(validate_passphrase("12345678").is_ok());
        assert!(validate_passphrase("1234567").is_err());
        assert!(validate_passphrase("").is_err());
    }

    /// Build a minimal [`Config`] carrying the given runtime identities.
    fn test_config(
        identities: BTreeMap<account::PersonaId, crate::identity::IdentityContext>,
    ) -> Config {
        Config {
            protected_key: None,
            integrity: Default::default(),
            public: public_config::PublicConfig::default(),
            private: ProtectedConfig::default(),
            key_backend: KeyBackend::Bip32 {
                root: ExtendedSigningKey::from_seed(&[7u8; 32]).unwrap(),
                seed: SecretString::new("seed".into()),
            },
            key_info: HashMap::new(),
            protection_method: ProtectionMethod::default(),
            #[cfg(feature = "openpgp-card")]
            token_admin_pin: None,
            #[cfg(feature = "openpgp-card")]
            token_user_pin: SecretString::new("".into()),
            unlock_code: None,
            account: account::Account::default(),
            identities,
            active_persona: None,
        }
    }

    /// Build a minimal [`crate::identity::IdentityContext`] for tests — no
    /// network, no ATM service; the profile and DID document are constructed
    /// directly from their (public) fields.
    fn test_identity(
        persona_id: account::PersonaId,
        did: &str,
    ) -> crate::identity::IdentityContext {
        use affinidi_tdk::messaging::profiles::{ATMProfile, ATMProfileInner};
        use std::sync::Arc;

        let document: affinidi_tdk::did_common::Document =
            serde_json::from_value(serde_json::json!({ "id": did }))
                .expect("minimal DID document deserializes");
        crate::identity::IdentityContext {
            persona_id,
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
        }
    }

    /// A persona DID with no cache entry is a refresh target; once a lookup is
    /// recorded it drops out until it goes stale, and a positive lookup reads
    /// back through `agent_name_for` while a negative one does not.
    #[test]
    fn agent_name_targets_and_cache_roundtrip() {
        use crate::config::account::{PersonaId, PersonaRecord};
        use chrono::Utc;

        let now = Utc::now();
        let mut config = test_config(BTreeMap::new());
        let pid = PersonaId::new();
        let did = "did:webvh:example.com:alice".to_string();
        config.account.personas.insert(
            pid,
            PersonaRecord {
                extra: serde_json::Map::new(),
                persona_id: pid,
                did: did.clone(),
                did_document: None,
                key_refs: vec![],
                mediator_did: None,
                origin_context_id: "openvtc/alice".into(),
                created_at: now,
                label: None,
            },
        );

        // Uncached → a target.
        assert_eq!(config.agent_name_refresh_targets(now), vec![did.clone()]);

        // A positive lookup: no longer a target, readable via `agent_name_for`.
        config.set_cached_agent_name(&did, Some("example.com/@alice".into()), now);
        assert!(config.agent_name_refresh_targets(now).is_empty());
        assert_eq!(config.agent_name_for(&did), Some("example.com/@alice"));

        // A negative lookup on a second DID: still not a target, but no name.
        let did2 = "did:webvh:example.com:bob".to_string();
        config.set_cached_agent_name(&did2, None, now);
        assert!(config.agent_name_for(&did2).is_none());
        assert!(!config.agent_name_refresh_targets(now).contains(&did2));

        // Once stale, the entry becomes a target again.
        let later = now + crate::agent_name::AGENT_NAME_TTL;
        assert!(config.agent_name_refresh_targets(later).contains(&did));
    }

    /// The VTA panel renders the VTA's DID and the persona's mediator DID, so
    /// both must be swept — leaving them out was the only reason those two rows
    /// always showed a raw DID even when the party published a verifiable name.
    #[test]
    fn agent_name_targets_include_the_vta_and_mediator_dids() {
        use crate::config::account::{PersonaId, PersonaRecord};
        use chrono::Utc;

        let now = Utc::now();
        let mut config = test_config(BTreeMap::new());
        let pid = PersonaId::new();
        let mediator = "did:webvh:example.com:mediator".to_string();
        config.account.personas.insert(
            pid,
            PersonaRecord {
                extra: serde_json::Map::new(),
                persona_id: pid,
                did: "did:webvh:example.com:alice".into(),
                did_document: None,
                key_refs: vec![],
                mediator_did: Some(mediator.clone()),
                origin_context_id: "openvtc/alice".into(),
                created_at: now,
                label: None,
            },
        );
        let vta_did = "did:webvh:example.com:vta".to_string();
        config.key_backend = KeyBackend::Vta {
            vta_url: "https://vta.example".into(),
            vta_did: vta_did.clone(),
            credential_did: "did:key:z6MkTest".into(),
            credential_private_key: SecretString::new("z6Mktest".into()),
            mediator_did: Some(mediator.clone()),
            credential_bundle: SecretString::new("bundle".into()),
            encryption_seed: SecretBox::new(Box::new(vec![0u8; 32])),
        };

        let targets = config.agent_name_refresh_targets(now);
        assert!(targets.contains(&mediator), "mediator swept: {targets:?}");
        assert!(targets.contains(&vta_did), "VTA DID swept: {targets:?}");
    }

    /// An unset mediator field must not become a lookup for the empty string.
    #[test]
    fn agent_name_targets_skip_non_did_infrastructure_values() {
        use crate::config::account::{PersonaId, PersonaRecord};
        use chrono::Utc;

        let now = Utc::now();
        let mut config = test_config(BTreeMap::new());
        let pid = PersonaId::new();
        config.account.personas.insert(
            pid,
            PersonaRecord {
                extra: serde_json::Map::new(),
                persona_id: pid,
                did: "did:webvh:example.com:alice".into(),
                did_document: None,
                key_refs: vec![],
                mediator_did: Some(String::new()),
                origin_context_id: "openvtc/alice".into(),
                created_at: now,
                label: None,
            },
        );
        config.key_backend = KeyBackend::Vta {
            vta_url: "https://vta.example".into(),
            vta_did: String::new(),
            credential_did: "did:key:z6MkTest".into(),
            credential_private_key: SecretString::new("z6Mktest".into()),
            mediator_did: None,
            credential_bundle: SecretString::new("bundle".into()),
            encryption_seed: SecretBox::new(Box::new(vec![0u8; 32])),
        };

        let targets = config.agent_name_refresh_targets(now);
        assert!(
            !targets.iter().any(|t| t.is_empty()),
            "no empty target: {targets:?}"
        );
    }

    /// A State-A (account-bootstrap, R-A-5) config carries an account but no
    /// persona, so it resolves no runtime identity. The accessors must degrade
    /// to the documented "no active community" sentinels rather than panic.
    #[test]
    fn zero_persona_config_has_no_active_identity() {
        let config = test_config(BTreeMap::new());

        assert!(config.active_identity().is_none());
        assert_eq!(config.persona_did(), "");
        assert_eq!(config.mediator_did(), "");
    }

    /// The *write* side of the State-A case. Reading back `""` was already
    /// pinned above; what was not was that the write reports having done
    /// nothing. It used to return `()`, so the settings panel said "Setting
    /// saved" over a value that had gone nowhere.
    #[test]
    fn setting_mediator_did_without_a_persona_reports_that_it_did_not_apply() {
        let mut config = test_config(BTreeMap::new());

        assert!(
            !config.set_active_mediator_did("did:webvh:example:mediator"),
            "no persona to set a mediator on, so the write must report failure"
        );
        assert_eq!(
            config.mediator_did(),
            "",
            "and must not have invented somewhere to store it"
        );
    }

    /// The same write with a persona resolved applies to *both* the runtime
    /// identity and the persisted account record — the next read and the next
    /// save have to agree, or the setting reverts on restart.
    #[test]
    fn setting_mediator_did_with_a_persona_applies_to_runtime_and_account() {
        let pid = account::PersonaId(uuid::Uuid::from_u128(1));
        let mut identities = BTreeMap::new();
        identities.insert(pid, test_identity(pid, "did:example:persona"));
        let mut config = test_config(identities);
        // Seed the account half too: load derives `identities` from
        // `account.personas`, so a real config always has both.
        config.account.personas.insert(
            pid,
            account::PersonaRecord {
                persona_id: pid,
                did: "did:example:persona".to_string(),
                did_document: None,
                key_refs: Vec::new(),
                mediator_did: None,
                origin_context_id: "openvtc/test".to_string(),
                created_at: chrono::Utc::now(),
                label: None,
                extra: serde_json::Map::new(),
            },
        );

        assert!(config.set_active_mediator_did("did:webvh:example:mediator"));
        assert_eq!(config.mediator_did(), "did:webvh:example:mediator");
        assert_eq!(
            config
                .account
                .personas
                .get(&pid)
                .and_then(|p| p.mediator_did.as_deref()),
            Some("did:webvh:example:mediator"),
            "the persisted record must move too, or the change is lost on restart"
        );
    }

    /// R7: with multiple personas resolved, `active_identity()` must be
    /// deterministic — the identity with the lowest `PersonaId` wins, and the
    /// result is independent of the order entries were inserted. Interim
    /// behaviour until explicit persona selection lands (T1 Stage 5).
    #[test]
    fn active_identity_is_deterministic_regardless_of_insertion_order() {
        let pid_low = account::PersonaId(uuid::Uuid::from_u128(1));
        let pid_high = account::PersonaId(uuid::Uuid::from_u128(2));
        assert!(pid_low < pid_high);

        // Insert low-id first…
        let mut forward = BTreeMap::new();
        forward.insert(pid_low, test_identity(pid_low, "did:example:low"));
        forward.insert(pid_high, test_identity(pid_high, "did:example:high"));
        let config_forward = test_config(forward);

        // …and high-id first.
        let mut reverse = BTreeMap::new();
        reverse.insert(pid_high, test_identity(pid_high, "did:example:high"));
        reverse.insert(pid_low, test_identity(pid_low, "did:example:low"));
        let config_reverse = test_config(reverse);

        // The lexicographically-first persona id is the active identity…
        let active_forward = config_forward.active_identity().expect("identity resolved");
        assert_eq!(active_forward.persona_id, pid_low);
        assert_eq!(active_forward.did, "did:example:low");

        // …regardless of insertion order.
        let active_reverse = config_reverse.active_identity().expect("identity resolved");
        assert_eq!(active_reverse.persona_id, active_forward.persona_id);
        assert_eq!(active_reverse.did, active_forward.did);
        assert_eq!(config_forward.persona_did(), config_reverse.persona_did());
    }
}

#[cfg(test)]
mod peer_transport_tests {
    use super::*;
    use crate::didcomm::MessagingTransport;

    /// Preference order mirrors the stack's: TSP first, then DIDComm.
    #[test]
    fn tsp_is_preferred_when_both_are_advertised() {
        let both = PeerTransports {
            tsp_mediator: Some("did:web:tsp-mediator".into()),
            didcomm_mediator: Some("did:web:didcomm-mediator".into()),
        };
        assert_eq!(both.preferred(), Some(MessagingTransport::Tsp));
        assert!(both.any());
    }

    #[test]
    fn didcomm_is_used_when_tsp_is_absent() {
        let didcomm_only = PeerTransports {
            tsp_mediator: None,
            didcomm_mediator: Some("did:web:didcomm-mediator".into()),
        };
        assert_eq!(didcomm_only.preferred(), Some(MessagingTransport::DidComm));
        assert!(didcomm_only.any());
    }

    /// The case the join preflight exists for: a document offering no messaging
    /// service at all cannot be joined, and saying so before the persona mint is
    /// the difference between a clear refusal and an orphaned identity.
    #[test]
    fn a_peer_advertising_nothing_is_not_joinable() {
        let none = PeerTransports::default();
        assert_eq!(none.preferred(), None);
        assert!(!none.any());
    }

    /// A peer advertising only TSP is still "joinable" from here — whether it
    /// can actually *decode* TSP is not knowable before sending, and is the
    /// peer's defect rather than something to route around. Pinned so nobody
    /// later turns this into a reachability probe.
    #[test]
    fn tsp_only_is_joinable_because_advertisement_is_all_we_can_see() {
        let tsp_only = PeerTransports {
            tsp_mediator: Some("did:web:tsp-mediator".into()),
            didcomm_mediator: None,
        };
        assert_eq!(tsp_only.preferred(), Some(MessagingTransport::Tsp));
        assert!(tsp_only.any());
    }
}
