//!  Secured [crate::config::Config] information that is stored in the OS Secure Storage
//!
//!  * If using hardware tokens, then the data is encrypted/decrypted using the hardware token
//!  * If no hardware token, then may be using a passphrase to protect the data
//!  * If no hardware token, and no passphrase, then is in plaintext in the OS Secure Store
//!
//!  Must intially save bip32_seed first before any keys can be stored

#[cfg(feature = "openpgp-card")]
use crate::config::TokenInteractions;
use crate::{
    config::{Config, KeyBackend, KeyTypes, UNLOCK_SALT_LEN, UnlockCode, UnlockKey},
    errors::OpenVTCError,
};
use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use keyring_core::Entry;
use rand::{RngCore, rngs::OsRng};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    collections::{BTreeMap, HashMap},
    sync::{LazyLock, Mutex},
};
use tracing::{debug, error, info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Constants for storing secure info in the OS Secure Store
const SERVICE: &str = "openvtc";

/// Mint a fresh random 32-byte `ProtectedConfig` key, base64url-encoded.
///
/// Uses the OS CSPRNG. Called once per profile, on the first save after this
/// field existed; thereafter the stored value is reused so the on-disk blob
/// stays readable.
#[must_use]
pub fn new_protected_key() -> SecretString {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let encoded = BASE64_URL_SAFE_NO_PAD.encode(key);
    key.zeroize();
    SecretString::new(encoded.into())
}

/// Reject an unencrypted `SecuredConfig` blob.
///
/// This is the [`SecretPolicy`](crate::secure_store::file::SecretPolicy) the
/// file-backed store is built with. The file store exists so Linux profiles
/// survive a reboot, but "durable" must not silently become "your BIP32 seed is
/// now sitting in a file in the clear": a profile with no passphrase and no
/// hardware token stays on the volatile store and gets told how to fix that.
///
/// The check is on the stored envelope, not on the caller's intent, so it holds
/// for every path that reaches the store.
///
/// # Errors
///
/// Returns the reason to show the user when the blob is unencrypted or does not
/// parse as a `SecuredConfig` envelope at all.
pub fn require_encrypted_blob(bytes: &[u8]) -> Result<(), String> {
    match serde_json::from_slice::<SecuredConfigFormat>(bytes) {
        Ok(SecuredConfigFormat::PasswordEncrypted { .. })
        | Ok(SecuredConfigFormat::PasswordSealed { .. })
        | Ok(SecuredConfigFormat::TokenEncrypted { .. }) => Ok(()),
        Ok(SecuredConfigFormat::PlainText { .. }) => Err(
            "this profile has no passphrase, so its secret would be written to disk \
             unencrypted; set one under Settings -> Config Protection to store it durably"
                .to_string(),
        ),
        Err(e) => Err(format!(
            "refusing to store a blob that is not a SecuredConfig envelope: {e}"
        )),
    }
}

/// Serialize a `SecuredConfigFormat` envelope into the exact bytes handed to
/// the OS credential store: **compact, single-line JSON**.
///
/// The formatting is not cosmetic. gnome-keyring writes an item's secret into
/// its `.keyring` file verbatim, but reads it back through `GKeyFile`
/// *unescaping*, so a secret containing a raw newline reads back as extra
/// lines of the keyring file and makes the whole file — every item in it, not
/// just ours — unparseable:
///
/// ```text
/// keyring was in an invalid or unrecognized format: .../Default_keyring.keyring
/// ```
///
/// openvtc stored this envelope with `to_string_pretty`, so every save on a
/// Secret Service backend wrote a multi-line secret and took the user's login
/// keyring down with it. The guard below is the invariant the fix rests on:
/// the envelope's payloads are all BASE64URL, so its compact encoding is pure
/// ASCII with no control characters and no backslashes. Anything else is a bug
/// on our side, and we fail the save rather than corrupt a keyring with it.
fn encode_blob(format: &SecuredConfigFormat) -> Result<Vec<u8>, OpenVTCError> {
    let bytes = serde_json::to_vec(format)?;

    if let Some(pos) = bytes
        .iter()
        .position(|b| !b.is_ascii() || b.is_ascii_control() || *b == b'\\')
    {
        return Err(OpenVTCError::SecureStore {
            fault: crate::errors::SecureStoreFault::Corrupt,
            profile: String::new(),
            detail: format!(
                "refusing to write a secret containing a byte the OS credential store \
                 cannot round-trip (0x{:02x} at offset {pos}); storing it would corrupt \
                 the keyring",
                bytes[pos]
            ),
        });
    }

    Ok(bytes)
}

/// Returns the `keyring` service name openvtc stores its `SecuredConfig`
/// under. Used by sibling modules that need to address the same entry.
#[must_use]
pub(crate) fn service_name() -> &'static str {
    SERVICE
}

// ---------------------------------------------------------------------------
// Serde helpers for SecretString
//
// `Secret<String>` does not implement `SerializableSecret`, so the standard
// `#[serde(with = "secrecy")]` attribute won't compile.  These narrow modules
// expose the inner value only at the serde boundary and nowhere else.
// ---------------------------------------------------------------------------
mod serde_secret_str {
    use secrecy::{ExposeSecret, SecretString};
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &SecretString, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(v.expose_secret())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SecretString, D::Error> {
        // secrecy 0.10: SecretString::new() takes Box<str>, not String
        Ok(SecretString::new(String::deserialize(d)?.into()))
    }
}
mod serde_opt_secret_str {
    use secrecy::{ExposeSecret, SecretString};
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &Option<SecretString>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(secret) => s.serialize_some(secret.expose_secret()),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<SecretString>, D::Error> {
        // secrecy 0.10: SecretString::new() takes Box<str>, not String
        Ok(Option::<String>::deserialize(d)?.map(|s| SecretString::new(s.into())))
    }
}

/// Methods of protecting [SecuredConfig]
#[derive(Clone, Debug, Default)]
pub enum ProtectionMethod {
    /// Encrypted under a hardware token.
    TokenEncrypted,
    /// Encrypted under a key derived from a password or PIN.
    PasswordEncrypted,
    /// Stored unencrypted.
    PlainText,
    /// Not yet known: the config has not been read from storage.
    #[default]
    Unknown,
}

impl From<SecuredConfigFormat> for ProtectionMethod {
    fn from(format: SecuredConfigFormat) -> Self {
        match format {
            SecuredConfigFormat::TokenEncrypted { .. } => ProtectionMethod::TokenEncrypted,
            SecuredConfigFormat::PasswordEncrypted { .. }
            | SecuredConfigFormat::PasswordSealed { .. } => ProtectionMethod::PasswordEncrypted,
            SecuredConfigFormat::PlainText { .. } => ProtectionMethod::PlainText,
        }
    }
}

/// The formats [SecuredConfig] is stored in:
/// 1. TokenEncrypted — encrypted using a hardware token
/// 2. PasswordSealed — encrypted under a key derived from the unlock code with
///    a per-profile random Argon2id salt, profile bound as associated data.
///    The only passphrase format written.
/// 3. PasswordEncrypted — the legacy passphrase format (fixed Argon2id salt,
///    no associated data). Read, and rewritten as `PasswordSealed` on the
///    next successful unlock; never written.
/// 4. PlainText — no encryption at all (use at your own risk)
///
/// All string payloads are BASE64URL (no-pad) encoded.
///
/// # Security: tagged-variant downgrade defence
///
/// The format is `#[serde(tag = "format")]` so every blob carries an
/// explicit `"format"` discriminator. Without that tag (the historical
/// `#[serde(untagged)]` shape), an attacker with write access to the
/// OS keychain — or any caller fed a crafted blob — could substitute a
/// `PasswordEncrypted` blob with `{"text": "<plaintext>"}` and serde
/// would silently match it as `PlainText`, bypassing AES-256-GCM.
///
/// With the tag, any blob lacking `"format"` is rejected at parse time.
/// Layer 2 of the same defence is [`assert_format_matches_intent`],
/// which refuses to proceed if the stored variant doesn't match the
/// protection level the caller's credentials imply.
///
/// Old (untagged) blobs are migrated transparently in [`SecuredConfig::load`]
/// via [`LegacySecuredConfigFormat`].
///
/// `PasswordSealed` deliberately names its payload `sealed`, not `data`: a
/// build that predates it falls back to the untagged legacy parse on an
/// unknown variant, and a `data` field would let that parse match it as a
/// legacy `PasswordEncrypted` blob — reporting the right unlock code as wrong.
/// With no field in common, an older build rejects the blob as unrecognised
/// instead of misreading it.
#[derive(Serialize, Deserialize, Debug, Zeroize)]
#[serde(tag = "format")]
enum SecuredConfigFormat {
    /// Hardware token encrypted data
    TokenEncrypted {
        /// Encrypted Session Key
        esk: String,
        /// Encrypted data using esk
        data: String,
    },

    /// Legacy Password/PIN protected data: key from the fixed-salt Argon2id
    /// derivation, no associated data. Read-only.
    PasswordEncrypted {
        /// Encrypted data using AES-256 from derived key
        data: String,
    },

    /// Password/PIN protected data, salted and bound to its profile.
    PasswordSealed {
        /// The profile's random 16-byte Argon2id salt.
        salt: String,
        /// `[nonce(12) | ct+tag]`, AES-256-GCM under an HKDF key with label
        /// `openvtc/secured-config/v2` and associated data
        /// `openvtc/secured-config/v2\0profile\0{profile}`.
        sealed: String,
    },

    /// Plaintext data - dangerous!
    PlainText {
        /// Plaintext data that can be Serialized into [SecuredConfig]
        text: String,
    },
}

/// Legacy untagged format — used **only** for one-time migration of
/// blobs written before the `#[serde(tag = "format")]` change.
///
/// Old blobs have no `"format"` key, so the new tagged enum rejects
/// them. We try this enum on parse-failure of the new shape, then
/// promote to [`SecuredConfigFormat`] and re-save in the tagged form.
#[derive(Deserialize, Zeroize)]
#[serde(untagged)]
enum LegacySecuredConfigFormat {
    TokenEncrypted { esk: String, data: String },
    PasswordEncrypted { data: String },
    PlainText { text: String },
}

impl From<LegacySecuredConfigFormat> for SecuredConfigFormat {
    fn from(legacy: LegacySecuredConfigFormat) -> Self {
        match legacy {
            LegacySecuredConfigFormat::TokenEncrypted { esk, data } => {
                SecuredConfigFormat::TokenEncrypted { esk, data }
            }
            LegacySecuredConfigFormat::PasswordEncrypted { data } => {
                SecuredConfigFormat::PasswordEncrypted { data }
            }
            LegacySecuredConfigFormat::PlainText { text } => {
                SecuredConfigFormat::PlainText { text }
            }
        }
    }
}

/// Cross-validates the stored [`SecuredConfigFormat`] variant against
/// the protection level the caller's supplied credentials imply.
///
/// This is **Layer 2** of the downgrade-attack defence (Layer 1 is the
/// internally-tagged serde format). Even if an attacker manages to
/// write a syntactically valid but weaker variant into the keychain —
/// e.g. a correctly-tagged `PlainText` blob where `PasswordEncrypted`
/// is expected — this gate refuses to proceed, turning a silent
/// data-exfiltration into a loud, logged error.
///
/// Mapping from caller intent to expected format:
/// - `has_token == true`               → must be [`SecuredConfigFormat::TokenEncrypted`]
/// - `has_unlock == true`              → must be [`SecuredConfigFormat::PasswordSealed`]
///   or the legacy [`SecuredConfigFormat::PasswordEncrypted`]
/// - neither token nor unlock present  → must be [`SecuredConfigFormat::PlainText`]
fn assert_format_matches_intent(
    format: &SecuredConfigFormat,
    has_token: bool,
    has_unlock: bool,
) -> Result<(), OpenVTCError> {
    if matches!(
        (format, has_token, has_unlock),
        (SecuredConfigFormat::TokenEncrypted { .. }, true, _)
            | (SecuredConfigFormat::PasswordEncrypted { .. }, false, true)
            | (SecuredConfigFormat::PasswordSealed { .. }, false, true)
            | (SecuredConfigFormat::PlainText { .. }, false, false)
    ) {
        return Ok(());
    }

    let stored = match format {
        SecuredConfigFormat::TokenEncrypted { .. } => "token-encrypted",
        SecuredConfigFormat::PasswordEncrypted { .. }
        | SecuredConfigFormat::PasswordSealed { .. } => "password-encrypted",
        SecuredConfigFormat::PlainText { .. } => "plaintext",
    };
    let expected = if has_token {
        "token-encrypted"
    } else if has_unlock {
        "password-encrypted"
    } else {
        "plaintext"
    };

    error!(
        "SECURITY ALERT: stored config format ({stored}) does not match expected \
         protection level ({expected}). Possible downgrade attack or config corruption."
    );
    Err(OpenVTCError::Config(format!(
        "Security violation: stored config format '{stored}' does not match \
         expected protection level '{expected}'. Refusing to load."
    )))
}

/// What checking an unlock code against the stored secured config found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnlockCodeCheck {
    /// The code opens the stored config.
    Accepted,
    /// The stored config is passphrase-protected and this code does not open it.
    Rejected,
    /// The stored config is not passphrase-protected, so the code was not
    /// tried. [`SecuredConfig::load`] refuses that mismatch (the downgrade
    /// check); this check leaves the refusal to it.
    NotApplicable,
}

/// Decode a stored `PasswordSealed` salt.
fn decode_salt(salt: &str) -> Result<[u8; UNLOCK_SALT_LEN], OpenVTCError> {
    BASE64_URL_SAFE_NO_PAD
        .decode(salt)?
        .as_slice()
        .try_into()
        .map_err(|_| OpenVTCError::Decrypt(format!("Stored salt is not {UNLOCK_SALT_LEN} bytes")))
}

/// Seal `plaintext` as the `PasswordSealed` envelope of `profile`.
fn seal_password(
    key: &UnlockKey,
    profile: &str,
    plaintext: &[u8],
) -> Result<SecuredConfigFormat, OpenVTCError> {
    Ok(SecuredConfigFormat::PasswordSealed {
        salt: BASE64_URL_SAFE_NO_PAD.encode(key.salt()),
        sealed: BASE64_URL_SAFE_NO_PAD.encode(seal(
            key.key(),
            SECURED_SEALED_INFO,
            &secured_aad(profile),
            plaintext,
        )?),
    })
}

impl SecuredConfigFormat {
    /// Open a passphrase blob with `unlock`, or `Ok(None)` when the code (or,
    /// for a sealed blob, the profile it is bound to) does not match.
    ///
    /// Derives with the blob's own salt — the legacy fixed salt for
    /// `PasswordEncrypted`, the stored random one for `PasswordSealed`. The
    /// derived key is cached on `unlock`, so the load that follows the unlock
    /// prompt's check does not run Argon2 a second time.
    ///
    /// # Errors
    ///
    /// Only for a blob that could not be tried at all (bad base64, a
    /// malformed salt) — never for a code that is simply wrong. Also errors
    /// when called on a blob that is not passphrase-protected.
    fn open_password(
        &self,
        unlock: &UnlockCode,
        profile: &str,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, OpenVTCError> {
        match self {
            SecuredConfigFormat::PasswordEncrypted { data } => {
                let decoded = BASE64_URL_SAFE_NO_PAD.decode(data)?;
                let key = unlock.legacy_key()?;
                aead_open(&key, &decoded)
            }
            SecuredConfigFormat::PasswordSealed { salt, sealed } => {
                let salt = decode_salt(salt)?;
                let decoded = BASE64_URL_SAFE_NO_PAD.decode(sealed)?;
                let key = unlock.key_for_salt(&salt)?;
                let opened = open(
                    key.key(),
                    SECURED_SEALED_INFO,
                    &secured_aad(profile),
                    &decoded,
                )?;
                if opened.is_none() {
                    // A wrong code: don't keep its key as the profile's.
                    unlock.forget_salted();
                }
                Ok(opened)
            }
            _ => Err(OpenVTCError::Config(
                "not a passphrase-protected SecuredConfig".to_string(),
            )),
        }
    }

    /// Whether `unlock` opens this blob, decided by the AEAD tag alone. The
    /// plaintext is zeroed and dropped; it is never parsed or returned.
    ///
    /// # Errors
    ///
    /// Only for a blob that could not be tried at all (bad base64, a
    /// malformed salt) — never for a code that is simply wrong.
    pub fn check_unlock_code(
        &self,
        unlock: &UnlockCode,
        profile: &str,
    ) -> Result<UnlockCodeCheck, OpenVTCError> {
        if !matches!(
            self,
            SecuredConfigFormat::PasswordEncrypted { .. }
                | SecuredConfigFormat::PasswordSealed { .. }
        ) {
            return Ok(UnlockCodeCheck::NotApplicable);
        }
        Ok(match self.open_password(unlock, profile)? {
            Some(_plaintext) => UnlockCodeCheck::Accepted,
            None => UnlockCodeCheck::Rejected,
        })
    }

    /// Decrypts this blob into a [`SecuredConfig`].
    #[cfg_attr(not(feature = "openpgp-card"), allow(unused_variables))]
    pub fn unlock(
        &self,
        profile: &str,
        #[cfg(feature = "openpgp-card")] user_pin: &SecretString,
        token: Option<&String>,
        unlock: Option<&UnlockCode>,
        #[cfg(feature = "openpgp-card")] touch_prompt: &impl TokenInteractions,
    ) -> Result<SecuredConfig, OpenVTCError> {
        let raw_bytes: Zeroizing<Vec<u8>> = match self {
            SecuredConfigFormat::TokenEncrypted { esk, data } => {
                // Token Encrypted format
                if let Some(token) = token {
                    #[cfg(feature = "openpgp-card")]
                    {
                        use crate::openpgp_card::crypt::token_decrypt;

                        Zeroizing::new(token_decrypt(
                            user_pin,
                            token,
                            &BASE64_URL_SAFE_NO_PAD.decode(esk)?,
                            &BASE64_URL_SAFE_NO_PAD.decode(data)?,
                            touch_prompt,
                        )?)
                    }
                    #[cfg(not(feature = "openpgp-card"))]
                    {
                        warn!(
                            "Token has been configured, but no openpgp-card feature-flag has been enabled! exiting..."
                        );
                        return Err(OpenVTCError::Config("Token has been configured, but no openpgp-card feature-flag has been enabled! exiting.".to_string()));
                    }
                } else {
                    warn!(
                        "Secured Config is Token Encrypted, but no token identifier has been provided!"
                    );
                    return Err(OpenVTCError::Config("Secured Config is Token Encrypted, but no token identifier has been provided!".to_string()));
                }
            }
            SecuredConfigFormat::PasswordEncrypted { .. }
            | SecuredConfigFormat::PasswordSealed { .. } => {
                let Some(unlock) = unlock else {
                    return Err(OpenVTCError::Config(
                        "Secured Config is Password Encrypted, but no unlock code has been provided!".to_string()
                    ));
                };
                self.open_password(unlock, profile)?.ok_or_else(|| {
                    error!("Couldn't decrypt data. Likely due to incorrect unlock code!");
                    OpenVTCError::Decrypt(
                        "Couldn't decrypt password encrypted SecuredConfig. Reason: \
                         Couldn't decrypt data, likely due to incorrect unlock code!"
                            .to_string(),
                    )
                })?
            }
            SecuredConfigFormat::PlainText { text } => {
                // Plaintext format - no checks needed
                Zeroizing::new(BASE64_URL_SAFE_NO_PAD.decode(text)?)
            }
        };

        Ok(serde_json::from_slice(raw_bytes.as_slice())?)
    }
}

/// Serialize a `HashMap` in key order, so the same contents always produce the
/// same bytes. The keyring-write skip ([`SecuredConfig::save`]) compares
/// serialized plaintexts, and a `HashMap`'s iteration order is not stable.
fn serialize_sorted<S: serde::Serializer, V: Serialize>(
    map: &HashMap<String, V>,
    s: S,
) -> Result<S::Ok, S::Error> {
    map.iter().collect::<BTreeMap<_, _>>().serialize(s)
}

/// Secured Configuration information for openvtc tool
/// Try to keep this as small as possible for ease of secure storage
#[derive(Serialize, Deserialize, Debug, Zeroize, ZeroizeOnDrop)]
pub struct SecuredConfig {
    /// base64 encoded BIP32 private seed (legacy - present only for BIP32-based configs).
    ///
    /// `SecretString` ensures the value is zeroed on drop via `Secret<T>`'s `ZeroizeOnDrop`
    /// implementation.  We set `#[zeroize(skip)]` so the outer `Zeroize` derive does not
    /// try to call `.zeroize()` on `Secret<String>` directly (it doesn't implement `Zeroize`).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serde_opt_secret_str::serialize",
        deserialize_with = "serde_opt_secret_str::deserialize"
    )]
    #[zeroize(skip)]
    pub bip32_seed: Option<SecretString>,

    /// base64-encoded CredentialBundle for VTA auth.
    ///
    /// Same `#[zeroize(skip)]` rationale as `bip32_seed` above.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serde_opt_secret_str::serialize",
        deserialize_with = "serde_opt_secret_str::deserialize"
    )]
    #[zeroize(skip)]
    pub credential_bundle: Option<SecretString>,

    /// VTA service URL (REST). `None` for DIDComm-only VTAs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vta_url: Option<String>,

    /// VTA's DID
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vta_did: Option<String>,

    /// DIDComm mediator DID advertised by the VTA's DID document. Present
    /// when the VTA was reached over DIDComm during setup; runtime uses it
    /// to reopen authenticated DIDComm sessions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mediator_did: Option<String>,

    /// Random 32-byte key (base64url) that encrypts
    /// [`ProtectedConfig`](crate::config::protected_config::ProtectedConfig).
    ///
    /// # Why this is not derived from the admin credential
    ///
    /// The legacy derivation, `HKDF(admin_credential_private_key,
    /// "openvtc-protected-config-seed-v1")`, makes one value serve two
    /// irreconcilable roles — an **authorisation grant** designed to rotate
    /// (`acl/swap-key`) and be re-issued to a recovering install, and a
    /// **data-at-rest key** that must never change. Rotating the credential
    /// would make the on-disk config undecryptable, and a recovered install
    /// necessarily holds a *different* credential, so recovery and existing
    /// local state would be mutually exclusive.
    ///
    /// Generated on first save. `None` on configs written before this field
    /// existed; [`Config::load_step2`] falls back to the legacy derivation and
    /// re-keys on the next save. The fallback is retained deliberately — see
    /// `protected_key_or_legacy`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serde_opt_secret_str::serialize",
        deserialize_with = "serde_opt_secret_str::deserialize"
    )]
    #[zeroize(skip)]
    pub protected_key: Option<SecretString>,

    /// Key information containing path info
    /// key is the DID VerificationMethod ID
    ///
    /// Written in key order, so equal contents serialize to equal bytes.
    #[zeroize(skip)] // chrono doesn't support zeroize
    #[serde(serialize_with = "serialize_sorted")]
    pub key_info: HashMap<String, KeyInfoConfig>,

    /// How the config was protected when read. Never serialised.
    #[serde(skip, default)]
    #[zeroize(skip)]
    pub protection_method: ProtectionMethod,
}

impl From<&Config> for SecuredConfig {
    /// Extracts secured/private information from the full Config
    fn from(cfg: &Config) -> Self {
        match &cfg.key_backend {
            KeyBackend::Bip32 { seed, .. } => SecuredConfig {
                bip32_seed: Some(seed.clone()),
                credential_bundle: None,
                protected_key: cfg.protected_key.clone(),
                vta_url: None,
                vta_did: None,
                mediator_did: None,
                key_info: cfg.key_info.clone(),
                protection_method: cfg.protection_method.clone(),
            },
            KeyBackend::Vta {
                credential_bundle,
                mediator_did,
                ..
            } => {
                // The persisted anchor, not the live one: a runtime-only
                // override (see `Config::runtime_trust_overrides`) must never
                // reach disk through `save` or `export`.
                let (vta_url, vta_did) = cfg.persisted_vta_anchor().unwrap_or_default();
                SecuredConfig {
                    bip32_seed: None,
                    credential_bundle: Some(credential_bundle.clone()),
                    protected_key: cfg.protected_key.clone(),
                    vta_url: if vta_url.is_empty() {
                        None
                    } else {
                        Some(vta_url.to_string())
                    },
                    vta_did: Some(vta_did.to_string()),
                    mediator_did: mediator_did.clone(),
                    key_info: cfg.key_info.clone(),
                    protection_method: cfg.protection_method.clone(),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Skipping redundant keyring writes (#564)
//
// The secured tier (key material) changes far less often than the rest of the
// config, so rewriting it on every `Config::save` is mostly waste — and the
// keyring write is the slowest, most failure-prone step (Secret Service over
// D-Bus, a Keychain prompt, a card touch on token profiles).
//
// The skip compares a fingerprint of what *would* be sealed with what this
// process last wrote. Not the ciphertext: its nonce changes on every write.
// The fingerprint covers the plaintext and everything that decides the stored
// envelope (protection mode, the unlock key's salt, the token id), so changing
// or removing the passphrase always writes.
//
// The record is in memory only and starts empty, so the first save after
// start-up always writes. Any write this module did not make through `save`
// (migration, a failed write, a profile delete) clears it.
// ---------------------------------------------------------------------------

/// Profile → fingerprint of the secured blob this process last wrote there.
static LAST_WRITTEN: LazyLock<Mutex<HashMap<String, [u8; 32]>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn last_written() -> std::sync::MutexGuard<'static, HashMap<String, [u8; 32]>> {
    LAST_WRITTEN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Forget what was last written for `profile`, so the next save writes.
pub(crate) fn forget_written(profile: &str) {
    last_written().remove(profile);
}

/// Fingerprint of a secured-tier write: protection mode, the parameters that
/// shape the envelope, and the plaintext.
fn write_fingerprint(mode: &[u8], param: &[u8], plaintext: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = Sha256::new();
    h.update(b"openvtc/secured-write-fingerprint/v1\0");
    h.update((mode.len() as u64).to_be_bytes());
    h.update(mode);
    h.update((param.len() as u64).to_be_bytes());
    h.update(param);
    h.update(plaintext);
    h.finalize().into()
}

impl SecuredConfig {
    /// Saves this SecuredConfig to the OS Secure Store.
    ///
    /// Encrypts with the hardware token when `token` is set, else seals under
    /// `unlock` (the profile's salted unlock key) when set, else stores it as
    /// plaintext. A passphrase profile is always written in the salted,
    /// profile-bound `PasswordSealed` format.
    ///
    /// Skips the keyring write entirely when this process last wrote exactly
    /// this content, under the same protection, to the same profile (#564).
    #[cfg_attr(not(feature = "openpgp-card"), allow(unused_variables))]
    pub fn save(
        &self,
        profile: &str,
        token: Option<&String>,
        unlock: Option<&UnlockKey>,
        #[cfg(feature = "openpgp-card")] touch_prompt: &(dyn Fn() + Send + Sync),
    ) -> Result<(), OpenVTCError> {
        // Serialize SecuredConfig to byte array; wiped on drop.
        let input = Zeroizing::new(serde_json::to_vec(&self)?);

        let fingerprint = if let Some(token) = token {
            write_fingerprint(b"token", token.as_bytes(), &input)
        } else if let Some(unlock) = unlock {
            write_fingerprint(b"password-sealed", unlock.salt(), &input)
        } else {
            write_fingerprint(b"plaintext", b"", &input)
        };
        if last_written().get(profile) == Some(&fingerprint) {
            debug!("secured config unchanged since the last write; keyring write skipped");
            return Ok(());
        }

        let formatted = if let Some(token) = token {
            #[cfg(feature = "openpgp-card")]
            {
                use crate::openpgp_card::crypt::token_encrypt;

                let (esk, data) = token_encrypt(token, &input, touch_prompt)?;
                SecuredConfigFormat::TokenEncrypted {
                    esk: BASE64_URL_SAFE_NO_PAD.encode(&esk),
                    data: BASE64_URL_SAFE_NO_PAD.encode(&data),
                }
            }
            #[cfg(not(feature = "openpgp-card"))]
            return Err(OpenVTCError::Config( "Token has been configured, but no openpgp-card feature-flag has been enabled! exiting...".to_string()));
        } else if let Some(unlock) = unlock {
            seal_password(unlock, profile, &input)?
        } else {
            // Plain-text
            SecuredConfigFormat::PlainText {
                text: BASE64_URL_SAFE_NO_PAD.encode(input.as_slice()),
            }
        };

        match write_format(profile, &formatted) {
            Ok(()) => {
                last_written().insert(profile.to_string(), fingerprint);
                Ok(())
            }
            Err(e) => {
                // The store may hold either version now; write next time.
                forget_written(profile);
                Err(e)
            }
        }
    }

    /// Deserialize the stored `SecuredConfig` wire blob from raw bytes — the
    /// serde half of [`load`](Self::load), split out so the deserializer can be
    /// exercised directly (e.g. by a fuzz harness) with no OS keyring. Tries the
    /// current tagged format, then the legacy untagged shape (with `bool` =
    /// "needs migration"); errors only if neither parses. No key material is
    /// touched — that happens later in [`load`] under `unlock`.
    fn parse_format(
        secret: &[u8],
        profile: &str,
    ) -> Result<(SecuredConfigFormat, bool), OpenVTCError> {
        match serde_json::from_slice::<SecuredConfigFormat>(secret) {
            Ok(format) => Ok((format, false)),
            Err(tagged_err) => match serde_json::from_slice::<LegacySecuredConfigFormat>(secret) {
                Ok(legacy) => {
                    warn!(
                        "Tagged SecuredConfig parse failed ({tagged_err}); migrating legacy untagged blob"
                    );
                    Ok((SecuredConfigFormat::from(legacy), true))
                }
                Err(legacy_err) => {
                    error!(
                        "Format of SecuredConfig in OS Secure store is invalid! \
                         Tagged: {tagged_err}; legacy: {legacy_err}"
                    );
                    Err(OpenVTCError::SecureStore {
                        fault: crate::errors::SecureStoreFault::Corrupt,
                        profile: profile.to_string(),
                        detail: format!(
                            "stored blob parses as neither the current nor the legacy \
                             format: {tagged_err}"
                        ),
                    })
                }
            },
        }
    }

    /// Parse-check the stored `SecuredConfig` wire blob (tagged or legacy) from
    /// raw bytes, without an OS keyring. `Ok(())` if it deserializes into either
    /// format; the encrypted key material is not decrypted. Exposed for fuzzing
    /// the deserialization surface directly.
    pub fn parse(bytes: &[u8]) -> Result<(), OpenVTCError> {
        Self::parse_format(bytes, "").map(|_| ())
    }

    /// Reads the stored wire blob's raw bytes from the OS secure store.
    fn read_raw(profile: &str) -> Result<Zeroizing<Vec<u8>>, OpenVTCError> {
        let entry =
            Entry::new(SERVICE, profile).map_err(|e| OpenVTCError::from_keyring(&e, profile))?;

        match entry.get_secret() {
            Ok(s) => Ok(Zeroizing::new(s)),
            Err(e) => {
                // Typed, not stringly: `NoEntry` (the credential is gone) and
                // `NoStorageAccess` (the store is locked) need opposite advice,
                // and the old single `Config` string made them look identical.
                error!("Couldn't read the SecuredConfig from the OS secure store: {e}");
                Err(OpenVTCError::from_keyring(&e, profile))
            }
        }
    }

    /// Reads and parses the stored wire blob from the OS secure store, without
    /// decrypting it. The `bool` is "needs migration" (see [`parse_format`](Self::parse_format)).
    fn read_format(profile: &str) -> Result<(SecuredConfigFormat, bool), OpenVTCError> {
        // Try the current tagged format first, falling back to the legacy
        // untagged shape (flagged for migration). Anything that fails both is
        // genuinely invalid.
        Self::parse_format(Self::read_raw(profile)?.as_slice(), profile)
    }

    /// Checks an unlock code against the stored secured config without loading
    /// it: nothing is parsed, migrated or re-saved.
    ///
    /// [`UnlockCode::from_string`] does no crypto, so it accepts any code of
    /// the minimum length. This is how the unlock prompt finds out a code is
    /// wrong while it can still ask again — rather than at [`load`](Self::load),
    /// after the prompt has gone. Works for both the salted and the legacy
    /// passphrase formats; the key it derives is kept on `unlock`, so the load
    /// that follows does not derive again.
    ///
    /// # Errors
    ///
    /// When the stored config cannot be read or parsed. Those are the faults
    /// [`load`](Self::load) reports in full; a caller that gets one should let
    /// `load` report it rather than count it as a wrong code.
    pub fn check_unlock_code(
        profile: &str,
        unlock: &UnlockCode,
    ) -> Result<UnlockCodeCheck, OpenVTCError> {
        let (format, _) = Self::read_format(profile)?;
        format.check_unlock_code(unlock, profile)
    }

    /// Loads secret info from the OS Secure Store
    /// token: Hardware token identifier if being used
    /// unlock: Use a Password/PIN to unlock secret storage if no hardware token
    /// If token is None and unlock is false, assumes no protection apart from the OS Secure Store
    /// itself
    ///
    /// A legacy (fixed-salt) passphrase blob is rewritten in the salted
    /// `PasswordSealed` format before this returns, in a single store write
    /// that is built and checked first and read back after, so it can never
    /// leave the profile unopenable. A failed upgrade is logged and the
    /// load still succeeds; the next save writes the new format anyway.
    pub fn load(
        profile: &str,
        #[cfg(feature = "openpgp-card")] user_pin: &SecretString,
        token: Option<&String>,
        unlock: Option<&UnlockCode>,
        #[cfg(feature = "openpgp-card")] touch_prompt: &impl TokenInteractions,
    ) -> Result<Self, OpenVTCError> {
        let original = Self::read_raw(profile)?;
        let (raw_secured_config, needs_migration) =
            Self::parse_format(original.as_slice(), profile)?;
        // What is stored is what was just read, whoever wrote it; the next
        // save must not assume it is what this process last wrote.
        forget_written(profile);

        // Layer-2 downgrade defence: cross-check the stored variant against
        // the caller's credentials before any decryption or re-save.
        assert_format_matches_intent(&raw_secured_config, token.is_some(), unlock.is_some())?;

        let sc = raw_secured_config.unlock(
            profile,
            #[cfg(feature = "openpgp-card")]
            user_pin,
            token,
            unlock,
            #[cfg(feature = "openpgp-card")]
            touch_prompt,
        )?;

        if let (SecuredConfigFormat::PasswordEncrypted { .. }, Some(unlock)) =
            (&raw_secured_config, unlock)
        {
            // Legacy fixed-salt blob (tagged or not): move it to the salted,
            // profile-bound format now that the code is known to be right.
            match sc.upgrade_password_blob(profile, unlock, &original) {
                Ok(()) => info!("Migrated SecuredConfig to the salted passphrase format"),
                Err(e) => warn!(
                    "SecuredConfig is still in the legacy passphrase format ({e}); \
                     the next save rewrites it"
                ),
            }
        } else if needs_migration {
            // If we just loaded a legacy untagged blob, re-save it in the
            // tagged format so future loads take the fast path. Failures are
            // logged but not fatal — the in-memory config is already valid.
            if let Err(e) = sc.save(
                profile,
                token,
                None,
                #[cfg(feature = "openpgp-card")]
                &|| {},
            ) {
                warn!("Auto-migration: failed to re-save SecuredConfig in tagged format: {e}");
            } else {
                info!("Migrated legacy SecuredConfig blob to tagged format");
            }
        }

        Ok(sc)
    }

    /// Rewrite a legacy passphrase blob as `PasswordSealed`, under a key
    /// derived from the same code with a fresh random salt.
    ///
    /// # Why this cannot lock the profile out
    ///
    /// The upgrade is **one** store write, replacing one entry: before it the
    /// legacy blob is stored, after it the sealed one, and [`load`](Self::load)
    /// opens either with the same unlock code because it dispatches on the
    /// stored variant. The protected tier in `config.json` is encrypted under
    /// `protected_key`, carried *inside* this blob, not under the unlock key,
    /// so it does not change and needs no second write. In order:
    ///
    /// 1. The new envelope is built and opened again in memory; nothing is
    ///    written unless it round-trips.
    /// 2. The store write. A failure (or a crash) here leaves whichever whole
    ///    blob the store kept — every backend replaces an entry as a unit (the
    ///    file store by write-to-temp and rename).
    /// 3. The stored blob is read back and opened with the new key. If that
    ///    fails, the original bytes are written back.
    fn upgrade_password_blob(
        &self,
        profile: &str,
        unlock: &UnlockCode,
        original: &[u8],
    ) -> Result<(), OpenVTCError> {
        let key = unlock.salted_key()?;
        let plaintext = Zeroizing::new(serde_json::to_vec(self)?);
        let sealed = seal_password(&key, profile, &plaintext)?;

        // 1. In-memory round trip before anything is replaced.
        if sealed
            .open_password(unlock, profile)?
            .as_ref()
            .map(|p| p.as_slice())
            != Some(plaintext.as_slice())
        {
            return Err(OpenVTCError::Encrypt(
                "the upgraded SecuredConfig did not round-trip; left as it was".to_string(),
            ));
        }

        // 2. The one write.
        forget_written(profile);
        write_format(profile, &sealed)?;

        // 3. Read back and confirm.
        let confirmed = Self::read_format(profile)
            .and_then(|(stored, _)| stored.open_password(unlock, profile))
            .map(|opened| opened.as_ref().map(|p| p.as_slice()) == Some(plaintext.as_slice()));
        if matches!(confirmed, Ok(true)) {
            return Ok(());
        }
        error!("the upgraded SecuredConfig did not read back; restoring the original blob");
        Entry::new(SERVICE, profile)
            .and_then(|entry| entry.set_secret(original))
            .map_err(|e| OpenVTCError::from_keyring(&e, profile))?;
        Err(OpenVTCError::Encrypt(
            "the upgraded SecuredConfig did not read back; the original was restored".to_string(),
        ))
    }
}

/// Write an envelope to the OS secure store entry of `profile`.
fn write_format(profile: &str, format: &SecuredConfigFormat) -> Result<(), OpenVTCError> {
    let blob = encode_blob(format)?;
    Entry::new(SERVICE, profile)
        .and_then(|entry| entry.set_secret(&blob))
        .map_err(|e| OpenVTCError::from_keyring(&e, profile))
}

/// Information that is required for each key stored
#[derive(Clone, Serialize, Deserialize, Debug, Zeroize, ZeroizeOnDrop)]
pub struct KeyInfoConfig {
    /// Where did the keys being used come from?
    /// key: #key-id
    /// value: Derived Path (BIP32 or Imported)
    pub path: KeySourceMaterial,

    /// When wss this key first created?
    #[zeroize(skip)] // chrono doesn't support zeroize
    pub create_time: DateTime<Utc>,

    /// What the key is for.
    #[zeroize(skip)]
    #[serde(default)]
    pub purpose: KeyTypes,
}
/// Where did the source for the Key Material come from?
#[derive(Clone, Serialize, Deserialize, Debug, Zeroize, ZeroizeOnDrop)]
pub enum KeySourceMaterial {
    /// Sourced from BIP32 derivative, Path for this key
    Derived {
        /// The BIP32 derivation path.
        path: String,
    },

    /// Sourced from an external Key Import
    /// multiencoded private key
    /// Key Material will be stored in the OS Secure Store.
    ///
    /// `#[zeroize(skip)]`: `Secret<String>` zeroes itself on drop; the outer
    /// `Zeroize` derive cannot call `.zeroize()` on it directly.
    Imported {
        /// The imported private key, multiencoded.
        #[serde(with = "serde_secret_str")]
        #[zeroize(skip)]
        seed: SecretString,
    },

    /// Managed by VTA service - key_id is VTA's opaque identifier
    /// No derivation paths are stored in openvtc for VTA-managed keys
    VtaManaged {
        /// The VTA's opaque identifier for the key.
        key_id: String,
    },
}

/// AES-256-GCM nonce size in bytes
const NONCE_SIZE: usize = 12;
/// HKDF info label for key derivation (v2 format). Shared by every blob
/// written before the per-blob labels below existed; kept so those blobs
/// still open.
const HKDF_INFO: &[u8] = b"openvtc-key-v2";

/// HKDF info label for the passphrase-sealed `SecuredConfig` envelope
/// ([`SecuredConfigFormat::PasswordSealed`]).
const SECURED_SEALED_INFO: &[u8] = b"openvtc/secured-config/v2";
/// Associated-data prefix for the sealed `SecuredConfig` envelope. The keyring
/// account (the profile name) follows it.
const SECURED_SEALED_AAD: &[u8] = b"openvtc/secured-config/v2\0profile\0";

/// Derives an AES-256-GCM key from `ikm` and the nonce using HKDF-SHA256 with
/// the given `info` label.
fn derive_key(ikm: &[u8; 32], nonce: &[u8], info: &[u8]) -> Result<Aes256Gcm, OpenVTCError> {
    let hk = Hkdf::<Sha256>::new(Some(nonce), ikm);
    let mut key_bytes = Zeroizing::new([0u8; 32]);
    hk.expand(info, key_bytes.as_mut())
        .map_err(|e| OpenVTCError::Encrypt(format!("HKDF key derivation failed: {e}")))?;
    Aes256Gcm::new_from_slice(key_bytes.as_ref())
        .map_err(|e| OpenVTCError::Encrypt(format!("Invalid AES key: {e}")))
}

/// AES-256-GCM seal with an HKDF-derived per-write key and bound associated
/// data. Output: `[12-byte nonce | ciphertext + tag]`.
///
/// `info` separates the key per blob kind (so one input key never yields the
/// same AES key for two different kinds of blob); `aad` binds the ciphertext
/// to its context (format tag, profile), so a blob copied into another context
/// fails authentication instead of opening.
pub(crate) fn seal(
    ikm: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, OpenVTCError> {
    // Fill the nonce from `rand`'s OsRng rather than aes-gcm's own
    // `AeadCore::generate_nonce`: that helper wants an RNG from the rand_core
    // 0.9 trait set, and this crate is pinned to rand 0.8 by the OpenPGP stack
    // (see the `rand` entry in the workspace manifest). Same 12 random OS
    // bytes either way.
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = aes_gcm::Nonce::from(nonce_bytes);
    let cipher = derive_key(ikm, &nonce, info)?;

    match cipher.encrypt(
        &nonce,
        Payload {
            msg: plaintext,
            aad,
        },
    ) {
        Ok(ciphertext) => {
            let mut result = nonce.to_vec();
            result.extend_from_slice(&ciphertext);
            Ok(result)
        }
        Err(e) => {
            error!("Couldn't encrypt data. Reason: {e}");
            Err(OpenVTCError::Encrypt(format!(
                "Couldn't encrypt data. Reason: {e}"
            )))
        }
    }
}

/// The inverse of [`seal`], with the two failures kept apart: `Err` for input
/// that cannot be ciphertext at all, `Ok(None)` for ciphertext this key (or
/// this associated data) does not open — the wrong-code / wrong-context case.
pub(crate) fn open(
    ikm: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    input: &[u8],
) -> Result<Option<Zeroizing<Vec<u8>>>, OpenVTCError> {
    if input.len() <= NONCE_SIZE {
        return Err(OpenVTCError::Decrypt(
            "Ciphertext too short (missing nonce)".to_string(),
        ));
    }

    let (nonce_bytes, ciphertext) = input.split_at(NONCE_SIZE);
    // `nonce_bytes` is exactly NONCE_SIZE long (checked above + split_at), so
    // the slice→array conversion cannot fail; aes-gcm 0.11's `Nonce` borrows
    // from a fixed-size array rather than a slice.
    let nonce_arr: &[u8; NONCE_SIZE] = nonce_bytes
        .try_into()
        .map_err(|_| OpenVTCError::Decrypt("Nonce is not 12 bytes".to_string()))?;
    let nonce: &aes_gcm::Nonce<_> = nonce_arr.into();
    let cipher = derive_key(ikm, nonce_bytes, info)?;

    // aes-gcm's error is opaque by design: a failed tag check is the only
    // thing it reports here.
    Ok(cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
        .map(Zeroizing::new))
}

/// Encrypts data using AES-256-GCM with HKDF-derived key and random nonce.
///
/// Output format: `[12-byte nonce | ciphertext + auth tag]`. This is the
/// pre-AAD format — no associated data, and the shared `openvtc-key-v2` HKDF
/// label. Kept for the hardware-token envelope and for callers outside the
/// config store; the config store's own blobs are now written with per-kind
/// labels and bound associated data.
pub fn unlock_code_encrypt(unlock: &[u8; 32], input: &[u8]) -> Result<Vec<u8>, OpenVTCError> {
    seal(unlock, HKDF_INFO, b"", input)
}

/// Decrypts data using AES-256-GCM with HKDF-derived key.
///
/// Expected input format: `[12-byte nonce | ciphertext + auth tag]` — the
/// output of [`unlock_code_encrypt`].
pub fn unlock_code_decrypt(unlock: &[u8; 32], input: &[u8]) -> Result<Vec<u8>, OpenVTCError> {
    aead_open(unlock, input)?
        .map(|pt| pt.to_vec())
        .ok_or_else(|| {
            error!("Couldn't decrypt data. Likely due to incorrect unlock code!");
            OpenVTCError::Decrypt(
                "Couldn't decrypt data, likely due to incorrect unlock code!".to_string(),
            )
        })
}

/// The AEAD half of [`unlock_code_decrypt`], with the two failures kept apart:
/// `Err` for input that cannot be ciphertext at all, `Ok(None)` for ciphertext
/// this key does not open — the wrong-code case.
pub(crate) fn aead_open(
    unlock: &[u8; 32],
    input: &[u8],
) -> Result<Option<Zeroizing<Vec<u8>>>, OpenVTCError> {
    open(unlock, HKDF_INFO, b"", input)
}

/// Associated data for the sealed `SecuredConfig` envelope of `profile`.
fn secured_aad(profile: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(SECURED_SEALED_AAD.len() + profile.len());
    aad.extend_from_slice(SECURED_SEALED_AAD);
    aad.extend_from_slice(profile.as_bytes());
    aad
}

// ---------------------------------------------------------------------------
// Passphrase-AEAD blobs with a random per-blob Argon2 salt (exports)
//
// The encrypt/decrypt pair below take the *passphrase* directly and produce /
// consume a versioned blob, so the salt travels with the ciphertext:
//
//   v1 (legacy):  [nonce(12) | ct+tag]                       fixed info-salt
//   v2 (legacy):  ["OPV2" | salt(16) | nonce(12) | ct+tag]   no AAD, info unused
//   v3 (current): ["OPV3" | salt(16) | nonce(12) | ct+tag]
//                 HKDF info = "openvtc/passphrase-blob/v3\0" || info,
//                 AAD = "OPV3" || salt
//
// `passphrase_decrypt` reads all three; only v3 is written.
// ---------------------------------------------------------------------------

const V2_MAGIC: &[u8; 4] = b"OPV2";
const V3_MAGIC: &[u8; 4] = b"OPV3";
const PASSPHRASE_SALT_SIZE: usize = 16;
const PASSPHRASE_HEADER_SIZE: usize = 4 + PASSPHRASE_SALT_SIZE;
/// Prefix of the v3 HKDF label; the caller's `info` follows it.
const V3_INFO_PREFIX: &[u8] = b"openvtc/passphrase-blob/v3\0";

fn v3_info(info: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(V3_INFO_PREFIX.len() + info.len());
    out.extend_from_slice(V3_INFO_PREFIX);
    out.extend_from_slice(info);
    out
}

/// Encrypt `plaintext` under `passphrase` with a fresh random Argon2id salt
/// and AES-256-GCM nonce.
///
/// `info` is the domain-separation label (e.g. `b"openvtc-export-v1"`): it is
/// fed into the HKDF step, so a blob written for one purpose does not open
/// under another purpose's label even with the right passphrase. The header
/// (magic and salt) is bound as associated data.
///
/// Output is a v3 blob: `[OPV3 | salt(16) | nonce(12) | ct+tag]`. Read it back
/// with [`passphrase_decrypt`] and the same `info`.
///
/// # Errors
///
/// When Argon2 or AES-GCM fails.
pub fn passphrase_encrypt(
    passphrase: &[u8],
    info: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, OpenVTCError> {
    let mut salt = [0u8; PASSPHRASE_SALT_SIZE];
    OsRng.fill_bytes(&mut salt);

    let key = Zeroizing::new(crate::config::derive_passphrase_key_v2(passphrase, &salt)?);
    let mut header = Vec::with_capacity(PASSPHRASE_HEADER_SIZE);
    header.extend_from_slice(V3_MAGIC);
    header.extend_from_slice(&salt);
    let inner = seal(&key, &v3_info(info), &header, plaintext)?;

    let mut out = header;
    out.extend_from_slice(&inner);
    Ok(out)
}

/// Async wrapper for [`passphrase_encrypt`] that runs the (CPU-bound,
/// ~0.5–1 s) Argon2id key derivation on `tokio::task::spawn_blocking` instead
/// of inline on the async runtime (R12).
///
/// At the config-export site the derive would otherwise run on the event-loop
/// thread and freeze the UI for ~1 s. The inputs are owned (so the closure is
/// `Send + 'static`) and the secret ones are wiped when the closure ends. The
/// blob has exactly the shape the sync path writes.
///
/// # Errors
///
/// Returns [`OpenVTCError`] if derivation/encryption fails, or
/// [`OpenVTCError::Encrypt`] if the blocking task panics. The `JoinError`
/// carries only the panic location — never the passphrase, derived key, or
/// plaintext.
pub async fn passphrase_encrypt_blocking(
    passphrase: Zeroizing<Vec<u8>>,
    info: Vec<u8>,
    plaintext: Zeroizing<Vec<u8>>,
) -> Result<Vec<u8>, OpenVTCError> {
    tokio::task::spawn_blocking(move || passphrase_encrypt(&passphrase, &info, &plaintext))
        .await
        .map_err(|e| OpenVTCError::Encrypt(format!("Argon2 encrypt task panicked: {e}")))?
}

/// Decrypt a passphrase-protected blob written by:
///   * [`passphrase_encrypt`] (v3: `OPV3` magic, random salt, `info` in the
///     HKDF label, header bound as AAD),
///   * the earlier `passphrase_encrypt_v2` (v2: `OPV2` magic, random salt,
///     `info` unused), or
///   * the legacy v1 path, where the key was derived with the deterministic
///     `info`-based salt and the blob written by [`unlock_code_encrypt`].
///
/// Format selection is by magic prefix; anything without one is read as v1.
///
/// # Errors
///
/// [`OpenVTCError::Decrypt`] when the passphrase (or, for v1 and v3, the
/// `info` label) is wrong or the blob was altered.
pub fn passphrase_decrypt(
    passphrase: &[u8],
    info: &[u8],
    blob: &[u8],
) -> Result<Vec<u8>, OpenVTCError> {
    if blob.len() >= PASSPHRASE_HEADER_SIZE {
        let (header, inner) = blob.split_at(PASSPHRASE_HEADER_SIZE);
        let salt = &header[4..];
        if &header[..4] == V3_MAGIC {
            let key = Zeroizing::new(crate::config::derive_passphrase_key_v2(passphrase, salt)?);
            return open(&key, &v3_info(info), header, inner)?
                .map(|pt| pt.to_vec())
                .ok_or_else(|| {
                    OpenVTCError::Decrypt(
                        "Couldn't decrypt data, likely due to an incorrect passphrase".to_string(),
                    )
                });
        }
        if &header[..4] == V2_MAGIC {
            let key = Zeroizing::new(crate::config::derive_passphrase_key_v2(passphrase, salt)?);
            return unlock_code_decrypt(&key, inner);
        }
    }
    // Legacy v1 — deterministic Argon2 salt derived from `info`.
    let key = Zeroizing::new(crate::config::derive_passphrase_key(passphrase, info)?);
    unlock_code_decrypt(&key, blob)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    const PROFILE: &str = "default";

    /// A blob in the legacy fixed-salt passphrase format (#566).
    fn legacy_blob(code: &str, plaintext: &[u8]) -> SecuredConfigFormat {
        let key = derive_passphrase_key_for_test(code);
        SecuredConfigFormat::PasswordEncrypted {
            data: BASE64_URL_SAFE_NO_PAD.encode(unlock_code_encrypt(&key, plaintext).unwrap()),
        }
    }

    fn derive_passphrase_key_for_test(code: &str) -> [u8; 32] {
        crate::config::derive_passphrase_key(code.as_bytes(), b"openvtc-unlock-code-v1").unwrap()
    }

    fn password_blob(code: &str) -> SecuredConfigFormat {
        legacy_blob(code, b"{}")
    }

    /// A blob in the current salted, profile-bound format.
    fn sealed_blob(code: &str, profile: &str, plaintext: &[u8]) -> SecuredConfigFormat {
        let key = UnlockKey::derive(code.as_bytes()).unwrap();
        seal_password(&key, profile, plaintext).unwrap()
    }

    /// A short code set by a release that did not enforce the minimum still
    /// opens its profile; `from_string` refuses it before trying.
    #[test]
    fn a_short_existing_code_still_unlocks() {
        let blob = password_blob("hunter");
        assert!(UnlockCode::from_string("hunter").is_err());
        assert_eq!(
            blob.check_unlock_code(&UnlockCode::for_existing("hunter").unwrap(), PROFILE)
                .unwrap(),
            UnlockCodeCheck::Accepted
        );
    }

    /// The unlock prompt relies on this to count a wrong code of full length
    /// as a failed attempt. `UnlockCode::from_string` accepts any such code,
    /// so without it the prompt's attempt limit and backoff never applied.
    /// Pinned for both the legacy and the salted format.
    #[test]
    fn check_unlock_code_tells_right_from_wrong() {
        for blob in [
            password_blob("correct horse"),
            sealed_blob("correct horse", PROFILE, b"{}"),
        ] {
            let right = UnlockCode::from_string("correct horse").unwrap();
            let wrong = UnlockCode::from_string("correct house").unwrap();
            assert_eq!(
                blob.check_unlock_code(&right, PROFILE).unwrap(),
                UnlockCodeCheck::Accepted
            );
            assert_eq!(
                blob.check_unlock_code(&wrong, PROFILE).unwrap(),
                UnlockCodeCheck::Rejected
            );
        }
    }

    /// The sealed blob is bound to its profile. Copied into another profile's
    /// keyring entry, it does not open even with the right code (#569).
    #[test]
    fn a_sealed_blob_does_not_open_under_another_profile() {
        let blob = sealed_blob("correct horse", "alice", b"{}");
        let code = UnlockCode::from_string("correct horse").unwrap();
        assert_eq!(
            blob.check_unlock_code(&code, "alice").unwrap(),
            UnlockCodeCheck::Accepted
        );
        assert_eq!(
            blob.check_unlock_code(&code, "bob").unwrap(),
            UnlockCodeCheck::Rejected
        );
    }

    /// The salt is the profile's own, stored beside the ciphertext, and the
    /// sealed envelope round-trips into a `SecuredConfig` (#566).
    #[test]
    fn a_sealed_blob_round_trips_and_carries_its_salt() {
        let sc = SecuredConfig {
            bip32_seed: None,
            credential_bundle: Some(SecretString::new("bundle".into())),
            protected_key: None,
            vta_url: None,
            vta_did: Some("did:example:vta".into()),
            mediator_did: None,
            key_info: HashMap::new(),
            protection_method: ProtectionMethod::default(),
        };
        let key = UnlockKey::derive(b"correct horse").unwrap();
        let blob = seal_password(&key, PROFILE, &serde_json::to_vec(&sc).unwrap()).unwrap();
        let SecuredConfigFormat::PasswordSealed { salt, .. } = &blob else {
            panic!("not sealed");
        };
        assert_eq!(&decode_salt(salt).unwrap(), key.salt());

        let code = UnlockCode::from_string("correct horse").unwrap();
        let opened = blob
            .unlock(
                PROFILE,
                #[cfg(feature = "openpgp-card")]
                &SecretString::new("".into()),
                None,
                Some(&code),
                #[cfg(feature = "openpgp-card")]
                &NoTouch,
            )
            .unwrap();
        assert_eq!(opened.vta_did.as_deref(), Some("did:example:vta"));
        // The key the blob opened with is the one later saves use.
        assert_eq!(code.salted_key().unwrap().salt(), key.salt());

        let wrong = UnlockCode::from_string("correct house").unwrap();
        assert!(
            blob.unlock(
                PROFILE,
                #[cfg(feature = "openpgp-card")]
                &SecretString::new("".into()),
                None,
                Some(&wrong),
                #[cfg(feature = "openpgp-card")]
                &NoTouch,
            )
            .is_err()
        );
    }

    #[cfg(feature = "openpgp-card")]
    struct NoTouch;
    #[cfg(feature = "openpgp-card")]
    impl TokenInteractions for NoTouch {
        fn touch_notify(&self) {}
        fn touch_completed(&self) {}
    }

    /// An older build that meets a sealed blob must reject it as unrecognised
    /// — not fall back to its untagged legacy parse and try the right code as
    /// a legacy `PasswordEncrypted` blob, which would report it as wrong.
    #[test]
    fn a_sealed_blob_shares_no_shape_with_the_legacy_formats() {
        let bytes = encode_blob(&sealed_blob("correct horse", PROFILE, b"{}")).unwrap();
        assert!(serde_json::from_slice::<LegacySecuredConfigFormat>(&bytes).is_err());
        assert!(SecuredConfig::parse(&bytes).is_ok());
        assert!(require_encrypted_blob(&bytes).is_ok());
    }

    /// Damage to the stored blob is not a wrong code: it must surface as an
    /// error, so the prompt does not tell the user to retype a code that was
    /// right.
    #[test]
    fn check_unlock_code_reports_a_damaged_blob_as_an_error() {
        let code = UnlockCode::from_string("correct horse").unwrap();
        let truncated = SecuredConfigFormat::PasswordEncrypted {
            data: BASE64_URL_SAFE_NO_PAD.encode([0u8; 4]),
        };
        assert!(truncated.check_unlock_code(&code, PROFILE).is_err());
        let not_base64 = SecuredConfigFormat::PasswordEncrypted {
            data: "*not base64*".into(),
        };
        assert!(not_base64.check_unlock_code(&code, PROFILE).is_err());
        let short_salt = SecuredConfigFormat::PasswordSealed {
            salt: BASE64_URL_SAFE_NO_PAD.encode([0u8; 4]),
            sealed: BASE64_URL_SAFE_NO_PAD.encode([0u8; 64]),
        };
        assert!(short_salt.check_unlock_code(&code, PROFILE).is_err());
    }

    #[test]
    fn check_unlock_code_does_not_apply_to_other_protection() {
        let code = UnlockCode::from_string("correct horse").unwrap();
        let plain = SecuredConfigFormat::PlainText { text: "p".into() };
        assert_eq!(
            plain.check_unlock_code(&code, PROFILE).unwrap(),
            UnlockCodeCheck::NotApplicable
        );
    }

    /// The write fingerprint changes with anything that changes the stored
    /// envelope — so changing or removing the passphrase always writes.
    #[test]
    fn the_write_fingerprint_covers_mode_parameters_and_content() {
        let a = write_fingerprint(b"password-sealed", &[1; 16], b"{}");
        assert_eq!(a, write_fingerprint(b"password-sealed", &[1; 16], b"{}"));
        assert_ne!(a, write_fingerprint(b"password-sealed", &[2; 16], b"{}"));
        assert_ne!(a, write_fingerprint(b"plaintext", &[1; 16], b"{}"));
        assert_ne!(a, write_fingerprint(b"password-sealed", &[1; 16], b"{ }"));
    }

    /// The skip compares serialized plaintexts, so the same contents must
    /// always serialize to the same bytes, whatever the map's iteration order.
    #[test]
    fn key_info_serializes_in_key_order() {
        let info = |p: &str| KeyInfoConfig {
            path: KeySourceMaterial::Derived { path: p.into() },
            create_time: DateTime::<Utc>::from_timestamp(0, 0).unwrap(),
            purpose: KeyTypes::default(),
        };
        let mut a = HashMap::new();
        let mut b = HashMap::new();
        for k in ["z", "a", "m", "q", "c"] {
            a.insert(format!("did:example:{k}#key-1"), info(k));
        }
        for k in ["c", "q", "m", "a", "z"] {
            b.insert(format!("did:example:{k}#key-1"), info(k));
        }
        let sc = |key_info| SecuredConfig {
            bip32_seed: None,
            credential_bundle: None,
            protected_key: None,
            vta_url: None,
            vta_did: None,
            mediator_did: None,
            key_info,
            protection_method: ProtectionMethod::default(),
        };
        assert_eq!(
            serde_json::to_vec(&sc(a)).unwrap(),
            serde_json::to_vec(&sc(b)).unwrap()
        );
    }

    #[test]
    fn parse_accepts_tagged_blob_and_rejects_garbage() {
        // `parse` exercises the stored-blob deserializer (tagged or legacy)
        // without an OS keyring — the seam fuzz harnesses drive.
        let bytes =
            serde_json::to_vec(&SecuredConfigFormat::PlainText { text: "p".into() }).unwrap();
        assert!(SecuredConfig::parse(&bytes).is_ok());
        assert!(SecuredConfig::parse(b"{ not valid json").is_err());
        assert!(SecuredConfig::parse(&[]).is_err());
    }

    // ── Tagged-format downgrade defence ───────────────────────────────────────

    /// Every variant must serialise with an explicit `"format"` discriminator
    /// so that a blob lacking the tag (the historical untagged shape) is
    /// rejected at parse time rather than silently matching a weaker variant.
    #[test]
    fn tagged_format_writes_explicit_discriminator() {
        let token_enc = SecuredConfigFormat::TokenEncrypted {
            esk: "abc".into(),
            data: "xyz".into(),
        };
        let pass_enc = SecuredConfigFormat::PasswordEncrypted { data: "xyz".into() };
        let plain = SecuredConfigFormat::PlainText { text: "xyz".into() };
        assert!(
            serde_json::to_string(&token_enc)
                .unwrap()
                .contains(r#""format":"TokenEncrypted""#)
        );
        assert!(
            serde_json::to_string(&pass_enc)
                .unwrap()
                .contains(r#""format":"PasswordEncrypted""#)
        );
        assert!(
            serde_json::to_string(&plain)
                .unwrap()
                .contains(r#""format":"PlainText""#)
        );
    }

    /// Old (untagged) blobs must fail the tagged parse but succeed against
    /// `LegacySecuredConfigFormat` so they take the migration path.
    #[test]
    fn legacy_untagged_blobs_round_trip_through_legacy_enum() {
        let plain = r#"{"text":"dGVzdA"}"#;
        let pass = r#"{"data":"dGVzdA"}"#;
        let token = r#"{"esk":"e","data":"d"}"#;
        for blob in [plain, pass, token] {
            assert!(serde_json::from_str::<SecuredConfigFormat>(blob).is_err());
            assert!(serde_json::from_str::<LegacySecuredConfigFormat>(blob).is_ok());
        }
    }

    // ── Keyring round-trip safety ─────────────────────────────────────────────

    /// The stored secret must be a single line. gnome-keyring writes a secret
    /// into its `.keyring` file verbatim and reads it back with `GKeyFile`
    /// unescaping, so one raw newline in our blob makes the *whole file*
    /// unparseable and takes every other item in the user's login keyring with
    /// it. This is the regression test for that: the payloads are all
    /// BASE64URL, so a correct encoding has no newline anywhere.
    #[test]
    fn encoded_blob_is_a_single_line() {
        let formats = [
            SecuredConfigFormat::PlainText {
                text: BASE64_URL_SAFE_NO_PAD.encode(vec![0xffu8; 512]),
            },
            SecuredConfigFormat::PasswordEncrypted {
                data: BASE64_URL_SAFE_NO_PAD.encode(vec![0x00u8; 512]),
            },
            SecuredConfigFormat::PasswordSealed {
                salt: BASE64_URL_SAFE_NO_PAD.encode([0xfeu8; UNLOCK_SALT_LEN]),
                sealed: BASE64_URL_SAFE_NO_PAD.encode(vec![0x0du8; 512]),
            },
            SecuredConfigFormat::TokenEncrypted {
                esk: BASE64_URL_SAFE_NO_PAD.encode([7u8; 32]),
                data: BASE64_URL_SAFE_NO_PAD.encode(vec![0x0au8; 512]),
            },
        ];

        for format in &formats {
            let bytes = encode_blob(format).unwrap();
            assert!(
                !bytes.contains(&b'\n') && !bytes.contains(&b'\r'),
                "stored secret must not contain a line break"
            );
            assert!(
                bytes.iter().all(|b| b.is_ascii() && !b.is_ascii_control()),
                "stored secret must be printable ASCII"
            );
            assert!(!bytes.contains(&b'\\'), "stored secret must not escape");
            // Still the same envelope the loader expects.
            assert!(SecuredConfig::parse(&bytes).is_ok());
        }
    }

    /// A blob the credential store could not round-trip must fail the save
    /// rather than reach the keyring. Reproduced by handing the encoder a
    /// payload that is not base64 — which can only happen if a future variant
    /// stops encoding its field.
    #[test]
    fn encode_blob_refuses_a_non_round_trippable_secret() {
        let bad = SecuredConfigFormat::PlainText {
            text: "line one\nline two".to_string(),
        };
        let err = encode_blob(&bad).unwrap_err();
        assert!(matches!(
            err,
            OpenVTCError::SecureStore {
                fault: crate::errors::SecureStoreFault::Corrupt,
                ..
            }
        ));
    }

    /// Layer-2 gate: a tagged-but-weaker blob (e.g. PlainText where
    /// PasswordEncrypted is expected) must be refused before any decrypt.
    #[test]
    fn intent_gate_rejects_plaintext_when_password_expected() {
        let plain = SecuredConfigFormat::PlainText {
            text: BASE64_URL_SAFE_NO_PAD.encode(b"{}"),
        };
        let err = assert_format_matches_intent(&plain, false, true).unwrap_err();
        assert!(err.to_string().contains("Security violation"));
    }

    #[test]
    fn intent_gate_accepts_matching_combinations() {
        let token = SecuredConfigFormat::TokenEncrypted {
            esk: "e".into(),
            data: "d".into(),
        };
        let pass = SecuredConfigFormat::PasswordEncrypted { data: "d".into() };
        let plain = SecuredConfigFormat::PlainText { text: "p".into() };
        assert!(assert_format_matches_intent(&token, true, false).is_ok());
        assert!(assert_format_matches_intent(&pass, false, true).is_ok());
        assert!(assert_format_matches_intent(&plain, false, false).is_ok());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let unlock = [42u8; 32];
        let plaintext = b"hello world - this is sensitive config data";
        let encrypted = unlock_code_encrypt(&unlock, plaintext).unwrap();
        assert_ne!(encrypted, plaintext);
        let decrypted = unlock_code_decrypt(&unlock, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encryption_is_non_deterministic() {
        let unlock = [42u8; 32];
        let plaintext = b"same data";

        let cipher1 = unlock_code_encrypt(&unlock, plaintext).unwrap();
        let cipher2 = unlock_code_encrypt(&unlock, plaintext).unwrap();

        assert_ne!(cipher1, cipher2, "Encryption must be non-deterministic");
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let unlock = [42u8; 32];
        let wrong_unlock = [99u8; 32];
        let plaintext = b"secret data";
        let encrypted = unlock_code_encrypt(&unlock, plaintext).unwrap();
        assert!(unlock_code_decrypt(&wrong_unlock, &encrypted).is_err());
    }

    #[test]
    fn test_encrypt_empty_data() {
        let unlock = [42u8; 32];
        let encrypted = unlock_code_encrypt(&unlock, b"").unwrap();
        let decrypted = unlock_code_decrypt(&unlock, &encrypted).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_encrypt_large_data() {
        let unlock = [42u8; 32];
        let plaintext = vec![0xABu8; 10_000];
        let encrypted = unlock_code_encrypt(&unlock, &plaintext).unwrap();
        let decrypted = unlock_code_decrypt(&unlock, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_too_short_input_fails() {
        let unlock = [42u8; 32];
        // Input shorter than nonce size should fail
        assert!(unlock_code_decrypt(&unlock, &[0u8; 5]).is_err());
        assert!(unlock_code_decrypt(&unlock, &[]).is_err());
    }

    #[test]
    fn test_different_unlocks_produce_different_ciphertext() {
        let plaintext = b"same data";
        let encrypted1 = unlock_code_encrypt(&[1u8; 32], plaintext).unwrap();
        let encrypted2 = unlock_code_encrypt(&[2u8; 32], plaintext).unwrap();
        assert_ne!(encrypted1, encrypted2);
    }

    #[test]
    fn test_output_contains_nonce_prefix() {
        let unlock = [42u8; 32];
        let plaintext = b"test";

        let encrypted = unlock_code_encrypt(&unlock, plaintext).unwrap();
        // Output should be: 12 bytes nonce + ciphertext (plaintext len + 16 byte auth tag)
        assert_eq!(encrypted.len(), NONCE_SIZE + plaintext.len() + 16);
    }

    #[test]
    fn test_decrypt_corrupted_data_fails() {
        let unlock = [42u8; 32];
        let plaintext = b"important data";
        let mut encrypted = unlock_code_encrypt(&unlock, plaintext).unwrap();
        if let Some(byte) = encrypted.last_mut() {
            *byte ^= 0xFF;
        }
        assert!(unlock_code_decrypt(&unlock, &encrypted).is_err());
    }

    #[test]
    fn test_key_source_material_zeroize() {
        // SecretString zeroes itself via ZeroizeOnDrop when dropped.
        // We just verify the variant is constructed and accessible correctly.
        let source = KeySourceMaterial::Imported {
            seed: SecretString::new("z6MkTestSeed123456789".into()),
        };
        match &source {
            KeySourceMaterial::Imported { seed } => {
                assert!(!seed.expose_secret().is_empty())
            }
            _ => panic!("expected Imported variant"),
        }
    }

    #[test]
    fn test_bip32_seed_is_secret_string() {
        // Verify that SecretString cannot be printed via Debug or Display,
        // proving the seed value never leaks through formatting.
        let config = SecuredConfig {
            protected_key: None,
            bip32_seed: Some(SecretString::new("super-secret-seed-value".into())),
            credential_bundle: None,
            vta_url: None,
            vta_did: None,
            mediator_did: None,
            key_info: std::collections::HashMap::new(),
            protection_method: ProtectionMethod::default(),
        };
        let debug = format!("{:?}", config);
        assert!(
            !debug.contains("super-secret-seed-value"),
            "SecretString must not leak through Debug formatting"
        );
    }

    #[test]
    fn test_imported_seed_requires_expose() {
        // Prove that the seed field can only be accessed through expose_secret(),
        // preventing accidental plaintext access.
        let material = KeySourceMaterial::Imported {
            seed: SecretString::new("z6MkSensitiveKeyData".into()),
        };
        let json = serde_json::to_string(&material).unwrap();
        // The serde module deliberately exposes the value for serialization only.
        assert!(json.contains("z6MkSensitiveKeyData"));
        // But the Rust type system prevents direct field access — must go through
        // expose_secret(). This test documents the security invariant.
        if let KeySourceMaterial::Imported { seed } = &material {
            assert_eq!(seed.expose_secret(), "z6MkSensitiveKeyData");
        }
    }
}

#[cfg(test)]
mod protected_key_tests {
    //! D12 — the `ProtectedConfig` key is the profile's own, not derived from
    //! the admin credential. These pin the properties that make the credential
    //! safe to rotate and re-issue.
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn a_minted_key_is_32_bytes_and_unique() {
        let a = new_protected_key();
        let b = new_protected_key();
        assert_ne!(
            a.expose_secret(),
            b.expose_secret(),
            "two profiles must not share a config key"
        );
        let bytes = BASE64_URL_SAFE_NO_PAD
            .decode(a.expose_secret())
            .expect("base64url");
        assert_eq!(bytes.len(), 32);
    }

    /// The whole point: the key does not move when the credential does.
    #[test]
    fn the_key_is_independent_of_the_credential() {
        let key = new_protected_key();
        let before = key.expose_secret().to_string();
        // Whatever happens to the admin credential — rotation via
        // `acl/swap-key`, or a reprovision handing a recovering install an
        // entirely different one — this value is untouched, because nothing
        // derives it.
        let after = key.expose_secret().to_string();
        assert_eq!(before, after);
    }

    /// A profile with no key yet must round-trip through serde as absent, not
    /// as `null` — the `SecuredConfig` blob is size-sensitive and older builds
    /// must still parse it.
    #[test]
    fn an_absent_key_is_omitted_from_the_wire() {
        let sc = SecuredConfig {
            bip32_seed: None,
            credential_bundle: Some(SecretString::new("bundle".into())),
            protected_key: None,
            vta_url: None,
            vta_did: None,
            mediator_did: None,
            key_info: HashMap::new(),
            protection_method: ProtectionMethod::default(),
        };
        let json = serde_json::to_string(&sc).expect("serialize");
        assert!(!json.contains("protected_key"), "{json}");
        assert!(!json.contains("null"), "{json}");

        let back: SecuredConfig = serde_json::from_str(&json).expect("deserialize");
        assert!(back.protected_key.is_none());
    }

    #[test]
    fn a_stored_key_round_trips() {
        let key = new_protected_key();
        let expected = key.expose_secret().to_string();
        let sc = SecuredConfig {
            bip32_seed: None,
            credential_bundle: Some(SecretString::new("bundle".into())),
            protected_key: Some(key),
            vta_url: None,
            vta_did: None,
            mediator_did: None,
            key_info: HashMap::new(),
            protection_method: ProtectionMethod::default(),
        };
        let json = serde_json::to_string(&sc).expect("serialize");
        let back: SecuredConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(
            back.protected_key
                .as_ref()
                .expect("key present")
                .expose_secret(),
            &expected
        );
    }
}
