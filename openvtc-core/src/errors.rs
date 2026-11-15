//! Common error types for the OpenVTC library.
//!
//! All fallible operations in the crate return [`OpenVTCError`] so that callers
//! can match on specific failure categories.

use affinidi_data_integrity::DataIntegrityError;
use affinidi_tdk::{common::errors::TDKError, didcomm, messaging::errors::ATMError};
use didwebvh_rs::DIDWebVHError;
use thiserror::Error;

/// Unified error type for all OpenVTC operations.
///
/// `#[non_exhaustive]` so a new failure category is not a breaking change:
/// without it every added variant fails the patch-line semver check
/// (`cargo-semver-checks` `enum_variant_added`), and a fix that needs one
/// cannot be backported to a release branch as it stands. Matches outside
/// this crate need a wildcard arm.
#[derive(Error, Debug)]
#[non_exhaustive]
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

    /// A remote service failed, classified by what an operator does about it
    /// (dev-guide R6.4): network unreachable, timed out, credentials refused,
    /// a contract mismatch, not found, refused with a reason, or failed on its
    /// side. Prefer this over [`Self::Vta`] / [`Self::Config`] for any failure
    /// that came back from — or never reached — another service; build it from
    /// the SDK error with [`Self::vta`] or [`Self::remote`].
    #[error("{service} {kind}: {detail}")]
    Remote {
        /// Which service.
        service: RemoteService,
        /// What kind of failure, for the remedy.
        kind: RemoteKind,
        /// What was being done, and the service's own words.
        detail: String,
    },
}

/// The remote service a [`OpenVTCError::Remote`] came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RemoteService {
    /// The account's own VTA.
    Vta,
    /// A DIDComm / TSP mediator.
    Mediator,
    /// A community (VTC) or another member, over messaging.
    Peer,
    /// An HTTP endpoint another party publishes (a manifest, a status list, a
    /// DID document host).
    Http,
}

impl std::fmt::Display for RemoteService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            RemoteService::Vta => "VTA",
            RemoteService::Mediator => "mediator",
            RemoteService::Peer => "peer",
            RemoteService::Http => "remote endpoint",
        })
    }
}

/// What kind of remote failure — each a different remedy (R6.4).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RemoteKind {
    /// It could not be reached at all: DNS, connection refused, no route, a
    /// transport that would not come up. Check the network and that the
    /// service is up.
    Unreachable,
    /// The request went out and no answer came in time. The service may be
    /// slow, or a leg beyond it silent; retrying may clear it.
    Timeout,
    /// It answered and refused our credentials (401/403, a refused
    /// credential, an ACL denial). Re-authenticate or check the grant; the
    /// network is fine.
    AuthRejected,
    /// It answered something this client cannot read: an unexpected shape,
    /// an unknown type, a version it does not speak. Not retryable; one side
    /// needs upgrading.
    Contract,
    /// It answered that the thing asked about does not exist.
    NotFound,
    /// It understood the request and declined it, for a reason it gave.
    Refused {
        /// The refusal's machine-readable code, when it sent one.
        code: Option<String>,
    },
    /// It was reached and failed on its own side (a 5xx, an internal error):
    /// its log has the cause.
    Failed,
}

impl std::fmt::Display for RemoteKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RemoteKind::Unreachable => f.write_str("unreachable"),
            RemoteKind::Timeout => f.write_str("timed out"),
            RemoteKind::AuthRejected => f.write_str("rejected our credentials"),
            RemoteKind::Contract => f.write_str("contract mismatch"),
            RemoteKind::NotFound => f.write_str("not found"),
            RemoteKind::Refused { code: Some(code) } => write!(f, "refused [{code}]"),
            RemoteKind::Refused { code: None } => f.write_str("refused"),
            RemoteKind::Failed => f.write_str("failed"),
        }
    }
}

impl RemoteKind {
    /// Classify a VTA SDK error.
    #[must_use]
    pub fn from_vta(e: &vta_sdk::error::VtaError) -> Self {
        use vta_sdk::error::VtaError as E;
        if crate::vta_receive_leg::is_reply_timeout(e) {
            return RemoteKind::Timeout;
        }
        match e {
            E::Network(inner) if inner.is_timeout() => RemoteKind::Timeout,
            E::Network(inner) if inner.is_decode() => RemoteKind::Contract,
            E::Network(_)
            | E::DidcommTransport(_)
            | E::TspTransport(_)
            | E::MediatorHandshakeFailed { .. } => RemoteKind::Unreachable,
            E::RepliesNotArriving { .. } => RemoteKind::Timeout,
            E::Auth(_) | E::Forbidden(_) => RemoteKind::AuthRejected,
            E::NotFound(_) | E::Gone(_) => RemoteKind::NotFound,
            E::Server { .. } | E::Unavailable { .. } | E::Other(_) => RemoteKind::Failed,
            E::UnsupportedTransport(_)
            | E::NoMatchingProtocol { .. }
            | E::UnsupportedTaskType { .. }
            | E::Protocol(_)
            | E::Serialization(_) => RemoteKind::Contract,
            E::Rejected { code, .. } | E::DidcommRemote { code, .. } => {
                Self::from_refusal_code(code)
            }
            E::ConsentRequired { .. } => RemoteKind::Refused {
                code: Some("consentRequired".to_string()),
            },
            E::RateLimited { .. } => RemoteKind::Refused {
                code: Some("rateLimited".to_string()),
            },
            other => RemoteKind::Refused {
                code: other.rejection_code().map(str::to_string),
            },
        }
    }

    /// Classify a refusal by its code: a Trust Task error code (`notFound`,
    /// `permissionDenied`, `internalError`, …), possibly scoped
    /// (`persona/attribute/get:notFound`), or a problem-report code.
    #[must_use]
    pub fn from_refusal_code(code: &str) -> Self {
        let leaf = code.rsplit([':', '.']).next().unwrap_or(code);
        match leaf {
            "notFound" | "not-found" | "not_found" | "gone" => RemoteKind::NotFound,
            "permissionDenied" | "forbidden" | "unauthorized" | "unauthenticated"
            | "identityMismatch" | "untrusted" => RemoteKind::AuthRejected,
            "internalError"
            | "internal"
            | "unavailable"
            | "upstreamUnavailable"
            | "upstream_unavailable"
            | "taskFailed" => RemoteKind::Failed,
            "unsupportedType" | "unsupportedVersion" | "malformed" | "malformedRequest"
            | "schemaViolation" => RemoteKind::Contract,
            _ => RemoteKind::Refused {
                code: Some(code.to_string()),
            },
        }
    }

    /// Classify a messaging (ATM) error.
    #[must_use]
    pub fn from_atm(e: &ATMError) -> Self {
        if let Some(status) = e.http_status() {
            return Self::from_http_status(status.status);
        }
        match e {
            ATMError::TransportError(_)
            | ATMError::SSLError(_)
            | ATMError::Disconnected(_)
            | ATMError::MsgSendError(_)
            | ATMError::MsgReceiveError(_) => RemoteKind::Unreachable,
            ATMError::AuthenticationError(_) | ATMError::DIDAuth(_) | ATMError::ACLDenied(_) => {
                RemoteKind::AuthRejected
            }
            ATMError::UnexpectedEnvelope(_)
            | ATMError::AddressingMismatch(_)
            | ATMError::DidcommError(..) => RemoteKind::Contract,
            ATMError::ProblemReport(code, ..) | ATMError::MediatorError(code, _) => {
                Self::from_refusal_code(code)
            }
            _ => RemoteKind::Failed,
        }
    }

    /// Classify an HTTP status a remote answered with.
    #[must_use]
    pub fn from_http_status(status: u16) -> Self {
        match status {
            401 | 403 => RemoteKind::AuthRejected,
            404 | 410 => RemoteKind::NotFound,
            408 | 504 => RemoteKind::Timeout,
            415 | 422 => RemoteKind::Contract,
            429 => RemoteKind::Refused {
                code: Some("rateLimited".to_string()),
            },
            500..=599 => RemoteKind::Failed,
            other => RemoteKind::Refused {
                code: Some(other.to_string()),
            },
        }
    }
}

/// The class of an error, for a UI that has to say what kind of failure it is
/// and what to do (R6.4) without reading its text. [`OpenVTCError::class`]
/// gives it; [`class_of`] does the same through an `anyhow` chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorClass {
    /// A remote service could not be reached.
    Unreachable,
    /// A remote service did not answer in time.
    Timeout,
    /// A remote service refused our credentials.
    AuthRejected,
    /// A remote service answered something this client cannot read.
    Contract,
    /// A remote service says the thing does not exist.
    NotFound,
    /// A remote service declined, with a reason.
    Refused,
    /// A remote service failed on its own side.
    RemoteFailed,
    /// Nothing remote: local configuration, storage, keys, input.
    Local,
}

impl ErrorClass {
    /// Whether the failure is another service's (or the network's), as
    /// opposed to local.
    #[must_use]
    pub fn is_remote(self) -> bool {
        self != ErrorClass::Local
    }

    /// One sentence on what to do about it.
    #[must_use]
    pub fn remedy(self) -> &'static str {
        match self {
            ErrorClass::Unreachable => {
                "Check the network, and that the service is up and reachable from here."
            }
            ErrorClass::Timeout => {
                "The request went out but no answer came in time — retry; if it persists, \
                 check the service's log for the leg it was waiting on."
            }
            ErrorClass::AuthRejected => {
                "The service was reached and refused our credentials — re-authenticate or \
                 check the grant. The network is fine."
            }
            ErrorClass::Contract => {
                "The service answered in a shape this client does not understand — one side \
                 needs upgrading. Retrying will not help."
            }
            ErrorClass::NotFound => "The service does not know the thing asked about.",
            ErrorClass::Refused => "The service declined; its reason is in the message.",
            ErrorClass::RemoteFailed => {
                "The service failed on its own side — its log has the cause."
            }
            ErrorClass::Local => "Nothing remote failed; the cause is on this machine.",
        }
    }
}

impl From<&RemoteKind> for ErrorClass {
    fn from(kind: &RemoteKind) -> Self {
        match kind {
            RemoteKind::Unreachable => ErrorClass::Unreachable,
            RemoteKind::Timeout => ErrorClass::Timeout,
            RemoteKind::AuthRejected => ErrorClass::AuthRejected,
            RemoteKind::Contract => ErrorClass::Contract,
            RemoteKind::NotFound => ErrorClass::NotFound,
            RemoteKind::Refused { .. } => ErrorClass::Refused,
            RemoteKind::Failed => ErrorClass::RemoteFailed,
        }
    }
}

/// The class of an error that has been through `anyhow` or another wrapper:
/// the first [`OpenVTCError`], VTA or messaging error in its source chain
/// decides it; an error with none of them is [`ErrorClass::Local`].
#[must_use]
pub fn class_of(e: &(dyn std::error::Error + 'static)) -> ErrorClass {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = cur {
        if let Some(e) = err.downcast_ref::<OpenVTCError>() {
            return e.class();
        }
        if let Some(e) = err.downcast_ref::<vta_sdk::error::VtaError>() {
            return ErrorClass::from(&RemoteKind::from_vta(e));
        }
        if let Some(e) = err.downcast_ref::<ATMError>() {
            return ErrorClass::from(&RemoteKind::from_atm(e));
        }
        if let Some(e) = err.downcast_ref::<crate::didcomm::MessagingError>() {
            return e.class();
        }
        cur = err.source();
    }
    ErrorClass::Local
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
    /// A failure at the account's VTA, classified from the SDK's error.
    /// `context` says what was being done ("persona attribute list failed").
    #[must_use]
    pub fn vta(context: impl std::fmt::Display, e: &vta_sdk::error::VtaError) -> Self {
        OpenVTCError::Remote {
            service: RemoteService::Vta,
            kind: RemoteKind::from_vta(e),
            detail: format!("{context}: {e}"),
        }
    }

    /// A remote failure of a known kind.
    #[must_use]
    pub fn remote(service: RemoteService, kind: RemoteKind, detail: impl Into<String>) -> Self {
        OpenVTCError::Remote {
            service,
            kind,
            detail: detail.into(),
        }
    }

    /// The class of this error, for a status line or a connection indicator
    /// that has to say what kind of failure it is (R6.4).
    ///
    /// The older string-carrying variants are classified by what they are
    /// documented to mean: [`Self::Vta`] is a connection/session fault,
    /// [`Self::Auth`] a refused handshake, [`Self::Resolver`] a resolution that
    /// did not complete.
    #[must_use]
    pub fn class(&self) -> ErrorClass {
        match self {
            OpenVTCError::Remote { kind, .. } => ErrorClass::from(kind),
            OpenVTCError::ATM(e) => ErrorClass::from(&RemoteKind::from_atm(e)),
            OpenVTCError::Vta(_) | OpenVTCError::Resolver(_) => ErrorClass::Unreachable,
            OpenVTCError::Auth(_) => ErrorClass::AuthRejected,
            _ => ErrorClass::Local,
        }
    }

    /// The remote failure's kind, when this is a [`Self::Remote`].
    #[must_use]
    pub fn remote_kind(&self) -> Option<&RemoteKind> {
        match self {
            OpenVTCError::Remote { kind, .. } => Some(kind),
            _ => None,
        }
    }

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

    /// Each VTA failure lands in the class its remedy needs (R6.4).
    #[test]
    fn a_vta_error_is_classified_by_its_remedy() {
        use vta_sdk::error::VtaError;
        let cases = [
            (
                VtaError::DidcommTransport("connection refused".into()),
                ErrorClass::Unreachable,
            ),
            (
                VtaError::TspTransport(
                    "timed out waiting for the TSP reply to request 'urn:uuid:1'".into(),
                ),
                ErrorClass::Timeout,
            ),
            (
                VtaError::RepliesNotArriving {
                    consecutive_timeouts: 3,
                },
                ErrorClass::Timeout,
            ),
            (VtaError::Auth("expired".into()), ErrorClass::AuthRejected),
            (VtaError::Forbidden("no".into()), ErrorClass::AuthRejected),
            (VtaError::Protocol("bad shape".into()), ErrorClass::Contract),
            (VtaError::NotFound("gone".into()), ErrorClass::NotFound),
            (
                VtaError::Server {
                    status: 500,
                    body: String::new(),
                },
                ErrorClass::RemoteFailed,
            ),
            (VtaError::Conflict("dup".into()), ErrorClass::Refused),
        ];
        for (e, class) in cases {
            let err = OpenVTCError::vta("doing a thing", &e);
            assert_eq!(err.class(), class, "{e}");
            assert!(err.to_string().contains("doing a thing"), "{err}");
        }
    }

    /// A refusal's code decides its kind, scoped or not.
    #[test]
    fn a_refusal_code_is_classified() {
        assert_eq!(
            RemoteKind::from_refusal_code("persona/attribute/get:notFound"),
            RemoteKind::NotFound
        );
        assert_eq!(
            RemoteKind::from_refusal_code("permissionDenied"),
            RemoteKind::AuthRejected
        );
        assert_eq!(
            RemoteKind::from_refusal_code("internalError"),
            RemoteKind::Failed
        );
        assert_eq!(
            RemoteKind::from_refusal_code("vtc/members/renew:notMember"),
            RemoteKind::Refused {
                code: Some("vtc/members/renew:notMember".into())
            }
        );
    }

    /// The class survives `anyhow`, so a CLI status line can ask for it.
    #[test]
    fn the_class_survives_anyhow() {
        let err = anyhow::Error::new(OpenVTCError::remote(
            RemoteService::Vta,
            RemoteKind::Timeout,
            "x",
        ))
        .context("while joining");
        assert_eq!(class_of(err.as_ref()), ErrorClass::Timeout);
        let local = anyhow::anyhow!("a local failure");
        assert_eq!(class_of(local.as_ref()), ErrorClass::Local);
    }

    /// The legacy string variants classify as they are documented.
    #[test]
    fn legacy_variants_keep_their_documented_class() {
        assert_eq!(
            OpenVTCError::Vta("x".into()).class(),
            ErrorClass::Unreachable
        );
        assert_eq!(
            OpenVTCError::Auth("x".into()).class(),
            ErrorClass::AuthRejected
        );
        assert_eq!(OpenVTCError::Config("x".into()).class(), ErrorClass::Local);
        assert!(!ErrorClass::Local.is_remote());
    }

    #[test]
    fn test_error_debug_is_nonempty() {
        let err = OpenVTCError::BIP32("test".into());
        let dbg = format!("{:?}", err);
        assert!(!dbg.is_empty(), "Debug output should not be empty");
    }
}
