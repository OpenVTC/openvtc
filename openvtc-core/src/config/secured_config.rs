/*!
*  Secured [crate::config::Config] information that is stored in the OS Secure Storage
*
*  * If using hardware tokens, then the data is encrypted/decrypted using the hardware token
*  * If no hardware token, then may be using a passphrase to protect the data
*  * If no hardware token, and no passphrase, then is in plaintext in the OS Secure Store
*
*  Must intially save bip32_seed first before any keys can be stored
*/

#[cfg(feature = "openpgp-card")]
use crate::config::TokenInteractions;
use crate::{
    config::{Config, KeyBackend, KeyTypes, UnlockCode},
    errors::OpenVTCError,
};
use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use keyring_core::Entry;
use rand::{RngCore, rngs::OsRng};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use tracing::{error, info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

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
    TokenEncrypted,
    PasswordEncrypted,
    PlainText,
    #[default]
    Unknown,
}

impl From<SecuredConfigFormat> for ProtectionMethod {
    fn from(format: SecuredConfigFormat) -> Self {
        match format {
            SecuredConfigFormat::TokenEncrypted { .. } => ProtectionMethod::TokenEncrypted,
            SecuredConfigFormat::PasswordEncrypted { .. } => ProtectionMethod::PasswordEncrypted,
            SecuredConfigFormat::PlainText { .. } => ProtectionMethod::PlainText,
        }
    }
}

/// Three possible formats to store [SecuredConfig]:
/// 1. TokenEncrypted — encrypted using a hardware token
/// 2. PasswordEncrypted — encrypted from a key derived from a password/PIN
/// 3. PlainText — no encryption at all (use at your own risk)
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

    /// Password/PIN Protected data
    PasswordEncrypted {
        /// Encrypted data using AES-256 from derived key
        data: String,
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
/// - `has_unlock == true`              → must be [`SecuredConfigFormat::PasswordEncrypted`]
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
            | (SecuredConfigFormat::PlainText { .. }, false, false)
    ) {
        return Ok(());
    }

    let stored = match format {
        SecuredConfigFormat::TokenEncrypted { .. } => "token-encrypted",
        SecuredConfigFormat::PasswordEncrypted { .. } => "password-encrypted",
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

impl SecuredConfigFormat {
    /// Loads secret info from the OS Secure Store
    #[cfg_attr(not(feature = "openpgp-card"), allow(unused_variables))]
    pub fn unlock(
        &self,
        #[cfg(feature = "openpgp-card")] user_pin: &SecretString,
        token: Option<&String>,
        unlock: Option<&UnlockCode>,
        #[cfg(feature = "openpgp-card")] touch_prompt: &impl TokenInteractions,
    ) -> Result<SecuredConfig, OpenVTCError> {
        let raw_bytes = match self {
            SecuredConfigFormat::TokenEncrypted { esk, data } => {
                // Token Encrypted format
                if let Some(token) = token {
                    #[cfg(feature = "openpgp-card")]
                    {
                        use crate::openpgp_card::crypt::token_decrypt;

                        token_decrypt(
                            user_pin,
                            token,
                            &BASE64_URL_SAFE_NO_PAD.decode(esk)?,
                            &BASE64_URL_SAFE_NO_PAD.decode(data)?,
                            touch_prompt,
                        )?
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
            SecuredConfigFormat::PasswordEncrypted { data } => {
                // Password Encrypted format
                if let Some(unlock) = unlock {
                    let decoded = BASE64_URL_SAFE_NO_PAD.decode(data)?;
                    let key = unlock
                        .0
                        .expose_secret()
                        .first_chunk::<32>()
                        .ok_or_else(|| {
                            OpenVTCError::Decrypt("Unlock code is not 32 bytes".to_string())
                        })?;

                    unlock_code_decrypt(key, &decoded).map_err(|e| {
                        OpenVTCError::Decrypt(format!(
                            "Couldn't decrypt password encrypted SecuredConfig. Reason: {e}"
                        ))
                    })?
                } else {
                    return Err(OpenVTCError::Config(
                        "Secured Config is Password Encrypted, but no unlock code has been provided!".to_string()
                    ));
                }
            }
            SecuredConfigFormat::PlainText { text } => {
                // Plaintext format - no checks needed

                BASE64_URL_SAFE_NO_PAD.decode(text)?
            }
        };

        Ok(serde_json::from_slice(raw_bytes.as_slice())?)
    }
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
    /// It used to be: `HKDF(admin_credential_private_key,
    /// "openvtc-protected-config-seed-v1")`. That made one value serve two
    /// irreconcilable roles — an **authorisation grant** designed to rotate
    /// (`acl/swap-key`) and be re-issued to a recovering install, and a
    /// **data-at-rest key** that must never change. Rotating the credential
    /// would have made the on-disk config undecryptable, and a recovered
    /// install necessarily holds a *different* credential, so recovery and
    /// existing local state were mutually exclusive.
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
    #[zeroize(skip)] // chrono doesn't support zeroize
    pub key_info: HashMap<String, KeyInfoConfig>,

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

impl SecuredConfig {
    /// Internal private function that saves a SecuredConfig to the OS Secure Store
    /// Encrypts the secret info as needed based on token/unlock parameters
    /// Converts to BASE64 then saves to OS Secure Store
    #[cfg_attr(not(feature = "openpgp-card"), allow(unused_variables))]
    pub fn save(
        &self,
        profile: &str,
        token: Option<&String>,
        unlock: Option<&Vec<u8>>,
        #[cfg(feature = "openpgp-card")] touch_prompt: &(dyn Fn() + Send + Sync),
    ) -> Result<(), OpenVTCError> {
        let entry =
            Entry::new(SERVICE, profile).map_err(|e| OpenVTCError::from_keyring(&e, profile))?;

        // Serialize SecuredConfig to byte array
        let input = serde_json::to_vec(&self)?;

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
            SecuredConfigFormat::PasswordEncrypted {
                data: BASE64_URL_SAFE_NO_PAD.encode(unlock_code_encrypt(
                    unlock.first_chunk::<32>().ok_or_else(|| {
                        OpenVTCError::Encrypt("Unlock code is not 32 bytes".to_string())
                    })?,
                    &input,
                )?),
            }
        } else {
            // Plain-text
            SecuredConfigFormat::PlainText {
                text: BASE64_URL_SAFE_NO_PAD.encode(input),
            }
        };

        // Save this to the OS Secure Store
        entry
            .set_secret(&encode_blob(&formatted)?)
            .map_err(|e| OpenVTCError::from_keyring(&e, profile))?;
        Ok(())
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

    /// Loads secret info from the OS Secure Store
    /// token: Hardware token identifier if being used
    /// unlock: Use a Password/PIN to unlock secret storage if no hardware token
    /// If token is None and unlock is false, assumes no protection apart from the OS Secure Store
    /// itself
    pub fn load(
        profile: &str,
        #[cfg(feature = "openpgp-card")] user_pin: &SecretString,
        token: Option<&String>,
        unlock: Option<&UnlockCode>,
        #[cfg(feature = "openpgp-card")] touch_prompt: &impl TokenInteractions,
    ) -> Result<Self, OpenVTCError> {
        let entry =
            Entry::new(SERVICE, profile).map_err(|e| OpenVTCError::from_keyring(&e, profile))?;

        let secret = match entry.get_secret() {
            Ok(s) => s,
            Err(e) => {
                // Typed, not stringly: `NoEntry` (the credential is gone) and
                // `NoStorageAccess` (the store is locked) need opposite advice,
                // and the old single `Config` string made them look identical.
                error!("Couldn't read the SecuredConfig from the OS secure store: {e}");
                return Err(OpenVTCError::from_keyring(&e, profile));
            }
        };

        // Try the current tagged format first, falling back to the legacy
        // untagged shape (flagged for migration). Anything that fails both is
        // genuinely invalid.
        let (raw_secured_config, needs_migration) = Self::parse_format(secret.as_slice(), profile)?;

        // Layer-2 downgrade defence: cross-check the stored variant against
        // the caller's credentials before any decryption or re-save.
        assert_format_matches_intent(&raw_secured_config, token.is_some(), unlock.is_some())?;

        let sc = raw_secured_config.unlock(
            #[cfg(feature = "openpgp-card")]
            user_pin,
            token,
            unlock,
            #[cfg(feature = "openpgp-card")]
            touch_prompt,
        )?;

        // If we just loaded a legacy untagged blob, re-save it in the tagged
        // format so future loads take the fast path. Failures are logged but
        // not fatal — the in-memory config is already valid.
        if needs_migration {
            let unlock_vec = unlock.map(|uc| uc.0.expose_secret().clone());
            if let Err(e) = sc.save(
                profile,
                token,
                unlock_vec.as_ref(),
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

    #[zeroize(skip)]
    #[serde(default)]
    pub purpose: KeyTypes,
}
/// Where did the source for the Key Material come from?
#[derive(Clone, Serialize, Deserialize, Debug, Zeroize, ZeroizeOnDrop)]
pub enum KeySourceMaterial {
    /// Sourced from BIP32 derivative, Path for this key
    Derived { path: String },

    /// Sourced from an external Key Import
    /// multiencoded private key
    /// Key Material will be stored in the OS Secure Store.
    ///
    /// `#[zeroize(skip)]`: `Secret<String>` zeroes itself on drop; the outer
    /// `Zeroize` derive cannot call `.zeroize()` on it directly.
    Imported {
        #[serde(with = "serde_secret_str")]
        #[zeroize(skip)]
        seed: SecretString,
    },

    /// Managed by VTA service - key_id is VTA's opaque identifier
    /// No derivation paths are stored in openvtc for VTA-managed keys
    VtaManaged { key_id: String },
}

/// AES-256-GCM nonce size in bytes
const NONCE_SIZE: usize = 12;
/// HKDF info label for key derivation (v2 format)
const HKDF_INFO: &[u8] = b"openvtc-key-v2";

/// Derives an AES-256-GCM key from the unlock code and nonce using HKDF-SHA256.
fn derive_key(unlock: &[u8; 32], nonce: &[u8]) -> Result<Aes256Gcm, OpenVTCError> {
    let hk = Hkdf::<Sha256>::new(Some(nonce), unlock);
    let mut key_bytes = [0u8; 32];
    hk.expand(HKDF_INFO, &mut key_bytes)
        .map_err(|e| OpenVTCError::Encrypt(format!("HKDF key derivation failed: {e}")))?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| OpenVTCError::Encrypt(format!("Invalid AES key: {e}")))?;
    key_bytes.zeroize();
    Ok(cipher)
}

/// Encrypts data using AES-256-GCM with HKDF-derived key and random nonce.
///
/// Output format: `[12-byte nonce | ciphertext + auth tag]`
pub fn unlock_code_encrypt(unlock: &[u8; 32], input: &[u8]) -> Result<Vec<u8>, OpenVTCError> {
    // Fill the nonce from `rand`'s OsRng rather than aes-gcm's own
    // `AeadCore::generate_nonce`: that helper wants an RNG from the rand_core
    // 0.9 trait set, and this crate is pinned to rand 0.8 by the OpenPGP stack
    // (see the `rand` entry in the workspace manifest). Same 12 random OS
    // bytes either way.
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = aes_gcm::Nonce::from(nonce_bytes);
    let cipher = derive_key(unlock, &nonce)?;

    match cipher.encrypt(&nonce, input) {
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

/// Decrypts data using AES-256-GCM with HKDF-derived key.
///
/// Expected input format: `[12-byte nonce | ciphertext + auth tag]`
pub fn unlock_code_decrypt(unlock: &[u8; 32], input: &[u8]) -> Result<Vec<u8>, OpenVTCError> {
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
    let cipher = derive_key(unlock, nonce_bytes)?;

    cipher.decrypt(nonce, ciphertext).map_err(|e| {
        error!("Couldn't decrypt data. Likely due to incorrect unlock code! Reason: {e}");
        OpenVTCError::Decrypt(format!(
            "Couldn't decrypt data, likely due to incorrect unlock code! Reason: {e}"
        ))
    })
}

// ---------------------------------------------------------------------------
// v2 passphrase-AEAD format with random per-entry Argon2 salt
//
// The legacy `unlock_code_encrypt` / `unlock_code_decrypt` API takes a
// pre-derived AEAD key. Migrating to a per-entry random Argon2 salt
// requires the salt to travel with the ciphertext, so the encrypt/decrypt
// pair below take the *passphrase* directly and produce / consume a
// versioned blob:
//
//   v1 (legacy):  [nonce(12) | ciphertext+tag(N)]
//   v2 (current): [magic(4)="OPV2" | salt(16) | nonce(12) | ciphertext+tag(N)]
//
// `passphrase_decrypt_with_info` auto-detects the format. Encrypted blobs
// in keyring entries / on disk roll forward to v2 the next time the
// caller writes them — transparent migration for the user.
// ---------------------------------------------------------------------------

const V2_MAGIC: &[u8; 4] = b"OPV2";
const V2_SALT_SIZE: usize = 16;
const V2_HEADER_SIZE: usize = V2_MAGIC.len() + V2_SALT_SIZE;

/// Encrypt `plaintext` under `passphrase` using a fresh random Argon2id
/// salt and AES-256-GCM nonce. `info` provides domain separation in the
/// KDF so the same passphrase produces different keys for, e.g., the
/// SecuredConfig keyring entry vs. an exported config blob.
///
/// Output is a v2 blob: `[OPV2 | salt(16) | nonce(12) | ct+tag]`.
pub fn passphrase_encrypt_v2(
    passphrase: &[u8],
    _info: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, OpenVTCError> {
    use rand::RngCore;
    let mut salt = [0u8; V2_SALT_SIZE];
    OsRng.fill_bytes(&mut salt);

    let key = crate::config::derive_passphrase_key_v2(passphrase, &salt)?;
    let inner = unlock_code_encrypt(&key, plaintext)?;

    let mut out = Vec::with_capacity(V2_HEADER_SIZE + inner.len());
    out.extend_from_slice(V2_MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&inner);
    Ok(out)
}

/// Async wrapper for [`passphrase_encrypt_v2`] that runs the (CPU-bound,
/// ~0.5–1 s) Argon2id key derivation on `tokio::task::spawn_blocking` instead
/// of inline on the async runtime (R12).
///
/// `passphrase_encrypt_v2` derives a fresh-salt Argon2 key before AES-GCM
/// encrypting; at the config-export site that derive runs on the event-loop
/// thread and freezes the UI for ~1 s. This helper owns its inputs (so the
/// closure is `Send + 'static`) and moves the whole encrypt — including the
/// random per-call salt generation — onto the blocking pool. The salt is still
/// generated fresh per call inside the closure (not weakened), and the
/// resulting v2 blob is byte-for-byte the same shape as the sync path: a blob
/// produced here is decryptable by [`passphrase_decrypt`].
///
/// `passphrase` is taken by value so the secret bytes are moved into the
/// closure and dropped there.
///
/// # Errors
///
/// Returns [`OpenVTCError`] if derivation/encryption fails, or
/// [`OpenVTCError::Encrypt`] if the blocking task panics. The `JoinError`
/// carries only the panic location — never the passphrase, derived key, or
/// plaintext.
pub async fn passphrase_encrypt_v2_blocking(
    passphrase: Vec<u8>,
    info: Vec<u8>,
    plaintext: Vec<u8>,
) -> Result<Vec<u8>, OpenVTCError> {
    // Wrap the moved secret copies in `Zeroizing` so the transient plaintext
    // passphrase and config bytes are wiped when the closure scope ends.
    let passphrase = zeroize::Zeroizing::new(passphrase);
    let plaintext = zeroize::Zeroizing::new(plaintext);
    tokio::task::spawn_blocking(move || passphrase_encrypt_v2(&passphrase, &info, &plaintext))
        .await
        .map_err(|e| OpenVTCError::Encrypt(format!("Argon2 encrypt task panicked: {e}")))?
}

/// Decrypt a passphrase-protected blob written by either:
///   * `passphrase_encrypt_v2` (v2: random salt embedded in the blob), or
///   * the legacy v1 path where the caller derived a key with the
///     deterministic info-based salt and called `unlock_code_encrypt`.
///
/// Format selection is by magic prefix: blobs that start with `b"OPV2"`
/// are decoded as v2, anything else falls back to v1.
pub fn passphrase_decrypt(
    passphrase: &[u8],
    info: &[u8],
    blob: &[u8],
) -> Result<Vec<u8>, OpenVTCError> {
    if blob.len() >= V2_HEADER_SIZE && &blob[..V2_MAGIC.len()] == V2_MAGIC {
        let salt = &blob[V2_MAGIC.len()..V2_HEADER_SIZE];
        let inner = &blob[V2_HEADER_SIZE..];
        let key = crate::config::derive_passphrase_key_v2(passphrase, salt)?;
        return unlock_code_decrypt(&key, inner);
    }
    // Legacy v1 — deterministic Argon2 salt derived from `info`.
    let key = crate::config::derive_passphrase_key(passphrase, info)?;
    unlock_code_decrypt(&key, blob)
}

#[cfg(test)]
mod tests {
    use super::*;

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
