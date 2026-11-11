//! Common error types for the OpenVTC library.
//!
//! All fallible operations in the crate return [`OpenVTCError`] so that callers
//! can match on specific failure categories.

use affinidi_data_integrity::DataIntegrityError;
use affinidi_tdk::{common::errors::TDKError, didcomm, messaging::errors::ATMError};
use didwebvh_rs::DIDWebVHError;
use thiserror::Error;

/// Unified error type for all OpenVTC operations.
#[derive(Error, Debug)]
pub enum OpenVTCError {
    /// An unrecognised DIDComm message type URL was encountered.
    #[error("Invalid Message Type: {0}")]
    InvalidMessage(String),

    /// A required secret key could not be found in the secrets resolver.
    #[error("Missing Secret Key Material. Key-ID: {0}")]
    MissingSecretKeyMaterial(String),

    /// JSON serialization or deserialization failed.
    #[error("Serialize/Deserialize Error: {0}")]
    Serde(#[from] serde_json::Error),

    /// A data-integrity proof operation failed.
    #[error("DataIntegrityProof Error: {0}")]
    DataIntegrityProof(#[from] DataIntegrityError),

    /// An error from the Affinidi Trusted Messaging (ATM) layer.
    #[error("ATM Error: {0}")]
    ATM(#[from] ATMError),

    /// A DIDComm protocol-level error.
    #[error("DIDComm Error: {0}")]
    DIDComm(#[from] didcomm::DIDCommError),

    /// A BIP32 key derivation error.
    #[error("BIP32 Error: {0}")]
    BIP32(String),

    /// An error related to secret key material (creation, decoding, etc.).
    #[error("Key Secret Error: {0}")]
    Secret(String),

    /// Base64 decoding failed.
    #[error("BASE64 Decode Error: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    /// DID resolution failed.
    #[error("DID Resolver Error: {0}")]
    Resolver(String),

    /// A general configuration error.
    #[error("Config Error: {0}")]
    Config(String),

    /// A VTA connection, session, or transport failure (e.g. a DIDComm session
    /// could not be opened against the mediator). Distinct from [`Self::Config`]:
    /// this is a retryable runtime fault — the on-disk config is not corrupt, so
    /// the caller should advise checking VTA reachability / retrying rather than
    /// resetting the configuration.
    #[error("VTA Error: {0}")]
    Vta(String),

    /// A VTA authentication failure (e.g. the challenge-response handshake was
    /// rejected). Distinct from [`Self::Config`]: the on-disk config is not
    /// corrupt, so the caller should advise re-authenticating rather than
    /// resetting the configuration.
    #[error("Auth Error: {0}")]
    Auth(String),

    /// The configuration file could not be found at the expected path.
    #[error("Config Not Found! path({0}): {1}")]
    ConfigNotFound(String, std::io::Error),

    /// An operation against the OS secure store (keychain / credential manager
    /// / Secret Service / kernel keyring) failed.
    ///
    /// Distinct from [`Self::Config`] because the remedies do not overlap: a
    /// missing credential needs a restore-or-reset, a locked store needs the
    /// user to unlock it, and a corrupt blob needs a reset. Collapsing all
    /// three into one `Config` string is what produced the "check your
    /// network" advice for a purely local failure (dev-guide R6.4).
    #[error("Secure store error ({fault}) for profile '{profile}': {detail}")]
    SecureStore {
        /// Which class of secure-store failure this is.
        fault: SecureStoreFault,
        /// The config profile whose credential was being addressed.
        profile: String,
        /// The underlying store's own message, kept verbatim for the log.
        detail: String,
    },

    /// The on-disk config predates the current [`crate::config::public_config::CONFIG_VERSION`]
    /// and cannot be migrated in place (T1 breaking reset, D13/R-RST). The caller
    /// must warn the user, delete the old config + keyring entries, and re-run setup.
    #[error("Config version {found} is incompatible with required version {expected}")]
    ConfigVersionUnsupported {
        /// The `config_version` read from disk.
        found: u32,
        /// The version this build requires.
        expected: u32,
    },

    /// An error from a hardware security token (e.g. OpenPGP card / YubiKey).
    #[cfg(feature = "openpgp-card")]
    #[error("Token Error: {0}")]
    Token(String),

    /// The PIN provided to the hardware token was incorrect.
    #[cfg(feature = "openpgp-card")]
    #[error("Token Bad Pin")]
    TokenBadPin,

    /// Symmetric encryption failed.
    #[error("Encrypt Error: {0}")]
    Encrypt(String),

    /// Symmetric decryption failed.
    #[error("Decrypt Error: {0}")]
    Decrypt(String),

    /// The unlock code does not open this profile's secured config.
    ///
    /// Distinct from [`Self::Decrypt`] so a caller can treat a mistyped code
    /// as the ordinary thing it is (ask again, point at recovery) rather than
    /// as a decryption fault in the stored data.
    #[error("That unlock code didn't work")]
    UnlockCodeRejected,

    /// A contacts/address-book operation failed.
    #[error("Contacts Error: {0}")]
    Contact(String),

    /// An error from the `did:webvh` DID method library.
    #[error("WebVH DID error: {0}")]
    WebVH(#[from] DIDWebVHError),

    /// An error from the TDK (Trust Development Kit) layer.
    #[error("TDK error: {0}")]
    TDK(#[from] TDKError),

    /// A `Mutex` was found in a poisoned state.
    #[error("Mutex poisoned: {0}")]
    MutexPoisoned(String),

    /// Another instance of openvtc is already running for this profile.
    #[error("Duplicate instance running for profile '{0}'")]
    DuplicateInstance(String),

    /// A process lock-file operation (create, read, or remove) failed.
    #[error("Lock file error: {0}")]
    LockFile(String),
}

/// Which class of OS-secure-store failure occurred.
///
/// The point of the split is triage: each variant maps to a different remedy,
/// and [`crate::diagnostics`] turns each into its own set of checks and fixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureStoreFault {
    /// The store is reachable but holds no credential for this profile.
    ///
    /// On a profile that previously worked this means the credential was
    /// deleted, expired (the Linux kernel keyring is RAM-only), or the config
    /// file was copied to a machine/user whose store never held it.
    Missing,
    /// The store itself could not be opened or read — a locked login keychain,
    /// no D-Bus session, no Secret Service daemon, a denied access prompt.
    Unavailable,
    /// More than one credential matched this service/user pair.
    Ambiguous,
    /// A credential exists but its contents are not a readable `SecuredConfig`.
    Corrupt,
    /// The store refused to hold this secret. Currently only the encrypted-file
    /// store does this, and only for an unencrypted blob.
    Rejected,
}

impl std::fmt::Display for SecureStoreFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SecureStoreFault::Missing => "no credential stored",
            SecureStoreFault::Unavailable => "store unavailable",
            SecureStoreFault::Ambiguous => "ambiguous credential",
            SecureStoreFault::Corrupt => "stored credential unreadable",
            SecureStoreFault::Rejected => "store refused the secret",
        };
        f.write_str(s)
    }
}

impl OpenVTCError {
    /// Classify a [`keyring_core::Error`] into a typed [`Self::SecureStore`].
    ///
    /// Kept here rather than at the call sites so every keyring touchpoint
    /// classifies identically — the previous `format!` at each site is exactly
    /// how `NoEntry` and "keychain is locked" ended up indistinguishable.
    #[must_use]
    pub fn from_keyring(err: &keyring_core::Error, profile: &str) -> Self {
        let fault = match err {
            keyring_core::Error::NoEntry => SecureStoreFault::Missing,
            keyring_core::Error::NoStorageAccess(_)
            | keyring_core::Error::PlatformFailure(_)
            | keyring_core::Error::NoDefaultStore
            | keyring_core::Error::NotSupportedByStore(_) => SecureStoreFault::Unavailable,
            keyring_core::Error::Ambiguous(_) => SecureStoreFault::Ambiguous,
            keyring_core::Error::BadEncoding(_)
            | keyring_core::Error::BadDataFormat(_, _)
            | keyring_core::Error::BadStoreFormat(_) => SecureStoreFault::Corrupt,
            // `Error` is `#[non_exhaustive]`: an unrecognised variant is more
            // likely a store-level problem than a missing credential, and
            // guessing `Missing` would advise a reset that destroys keys.
            _ => SecureStoreFault::Unavailable,
        };
        OpenVTCError::SecureStore {
            fault,
            profile: profile.to_string(),
            detail: err.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_messages_are_meaningful() {
        let cases: Vec<Box<dyn std::fmt::Display>> = vec![
            Box::new(OpenVTCError::InvalidMessage("bad msg".into())),
            Box::new(OpenVTCError::MissingSecretKeyMaterial("key-1".into())),
            Box::new(OpenVTCError::BIP32("derivation failed".into())),
            Box::new(OpenVTCError::Secret("missing seed".into())),
            Box::new(OpenVTCError::Resolver("timeout".into())),
            Box::new(OpenVTCError::Config("not found".into())),
            Box::new(OpenVTCError::Vta("session open failed".into())),
            Box::new(OpenVTCError::Auth("challenge rejected".into())),
            Box::new(OpenVTCError::ConfigNotFound(
                "/tmp/missing".into(),
                std::io::Error::new(std::io::ErrorKind::NotFound, "no file"),
            )),
            Box::new(OpenVTCError::Encrypt("aes failure".into())),
            Box::new(OpenVTCError::Decrypt("bad key".into())),
            Box::new(OpenVTCError::UnlockCodeRejected),
            Box::new(OpenVTCError::Contact("unknown".into())),
            Box::new(OpenVTCError::MutexPoisoned("lock failed".into())),
        ];

        for err in &cases {
            let msg = format!("{}", err);
            assert!(!msg.is_empty(), "Error display message should not be empty");
        }
    }

    #[test]
    fn test_error_display_contains_inner_message() {
        let err = OpenVTCError::Config("something went wrong".to_string());
        let msg = format!("{}", err);
        assert!(
            msg.contains("something went wrong"),
            "Display should include the inner message, got: {}",
            msg
        );
    }

    #[test]
    fn test_vta_and_auth_variants_render_their_messages() {
        let vta = OpenVTCError::Vta("DIDComm session open failed: timeout".to_string());
        let vta_msg = format!("{vta}");
        assert!(
            vta_msg.starts_with("VTA Error:"),
            "Vta should render its #[error(...)] prefix, got: {vta_msg}"
        );
        assert!(vta_msg.contains("DIDComm session open failed: timeout"));

        let auth = OpenVTCError::Auth("VTA authentication failed: 401".to_string());
        let auth_msg = format!("{auth}");
        assert!(
            auth_msg.starts_with("Auth Error:"),
            "Auth should render its #[error(...)] prefix, got: {auth_msg}"
        );
        assert!(auth_msg.contains("VTA authentication failed: 401"));
    }

    /// A retryable VTA/auth failure must NOT be classified as a `Config` error:
    /// `Config` triggers reset-style guidance in callers, whereas these are
    /// "check VTA / re-auth" runtime faults (R18).
    #[test]
    fn test_vta_and_auth_are_distinct_from_config() {
        assert!(matches!(
            OpenVTCError::Vta("x".into()),
            OpenVTCError::Vta(_)
        ));
        assert!(!matches!(
            OpenVTCError::Vta("x".into()),
            OpenVTCError::Config(_)
        ));
        assert!(!matches!(
            OpenVTCError::Auth("x".into()),
            OpenVTCError::Config(_)
        ));
    }

    #[test]
    fn test_error_debug_is_nonempty() {
        let err = OpenVTCError::BIP32("test".into());
        let dbg = format!("{:?}", err);
        assert!(!dbg.is_empty(), "Debug output should not be empty");
    }
}
