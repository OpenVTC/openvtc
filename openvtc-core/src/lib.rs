/*! Library interface for OpenVTC
 *! Allows for other applications to use the same data structures and routines
*/
#![deny(unsafe_code)]

use crate::errors::OpenVTCError;
#[cfg(feature = "openpgp-card")]
use ::openpgp_card::ocard::KeyType;
use affinidi_tdk::{
    didcomm::Message,
    messaging::{ATM, profiles::ATMProfile},
};
use serde::{Deserialize, Serialize};
use std::{fmt, sync::Arc};

pub mod agent_name;
pub mod bip32;
pub mod capabilities;
pub mod community_access;
pub mod community_send;
pub mod config;
// `didcomm` is DIDComm transport plumbing; `messaging` is the pure protocol
// logic. Both module docs state the split. Deliberately a `//` comment, not a
// `///` doc: an outer doc on a `pub mod` merges with that module's own `//!`
// docs and is resolved in *this* file's scope, so every intra-doc link the
// module writes about its own items breaks — which is what failed CI on #192
// and again here.
pub mod context_probe;
pub mod credential_sync;
pub mod devices;
pub mod diagnostics;
pub mod didcomm;
pub mod display;
pub mod dtg;
pub mod errors;
pub mod forge_credential;
pub mod git_ns;
pub mod git_signing;
pub mod git_workspace;
pub mod health;
pub mod identity;
pub mod issued_credential;
pub mod join;
pub mod logs;
pub mod members;
pub mod messaging;
// Crate-private stopgap: a copy of `affinidi-did-web`'s host classifier until
// that crate exports it (see the module header).
mod net_guard;
#[cfg(feature = "openpgp-card")]
pub mod openpgp_card;
pub mod operational;
pub mod persona;
pub mod personhood;
pub mod presentation;
pub mod process_lock;
pub mod proof_check;
pub mod rebuild;
pub mod rebuild_apply;
pub mod relationships;
pub mod renewal;
pub mod secure_store;
pub mod status_list;
pub mod tasks;
/// Building a Trust Task document — once, for every verb that sends one.
pub mod trust_task_doc;
pub mod tsp;
/// Durable backing for TSP Rev 3 relationship state (the SDK's
/// `PersistentRelationshipStore`, mirrored into `ProtectedConfig`).
pub mod tsp_store;
pub mod vetting;
pub mod vrc;
pub mod vta_receive;
pub mod vta_receive_leg;

/// Packs a DIDComm message with authenticated encryption and forwards it
/// through the mediator to the recipient.
///
/// This is a convenience helper that combines `ATM::pack_encrypted` and
/// `ATM::forward_and_send_message` — the two-step pattern used at every
/// DIDComm send site in the workspace.
///
/// # Errors
///
/// Returns an error if message packing or delivery fails.
pub async fn pack_and_send(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    msg: &Message,
    from: &str,
    to: &str,
    mediator: &str,
) -> Result<(), errors::OpenVTCError> {
    let (packed, _) = atm.pack_encrypted(msg, to, Some(from), None).await?;
    atm.forward_and_send_message(
        profile, false, &packed, None, mediator, to, None, None, false,
    )
    .await?;
    Ok(())
}

/// Extracts the `from` address from a DIDComm message, returning an error
/// if the field is absent.
///
/// # Errors
///
/// Returns [`OpenVTCError::Config`] if the message has no `from` address.
pub fn require_from(msg: &Message) -> Result<String, errors::OpenVTCError> {
    msg.from
        .as_deref()
        .map(String::from)
        .ok_or_else(|| errors::OpenVTCError::Config("Message has no 'from' address".to_string()))
}

/// Protocol URL constants for DIDComm message types used in OpenVTC messaging.
pub mod protocol_urls {
    /// URL for initiating a new relationship request.
    pub const RELATIONSHIP_REQUEST: &str =
        "https://linuxfoundation.org/openvtc/1.0/relationship-request";
    /// URL for rejecting a relationship request.
    pub const RELATIONSHIP_REQUEST_REJECT: &str =
        "https://linuxfoundation.org/openvtc/1.0/relationship-request-reject";
    /// URL for accepting a relationship request.
    pub const RELATIONSHIP_REQUEST_ACCEPT: &str =
        "https://linuxfoundation.org/openvtc/1.0/relationship-request-accept";
    /// URL for finalizing an accepted relationship request.
    pub const RELATIONSHIP_REQUEST_FINALIZE: &str =
        "https://linuxfoundation.org/openvtc/1.0/relationship-request-finalize";
    /// URL for sending a DIDComm trust ping.
    pub const TRUST_PING: &str = "https://didcomm.org/trust-ping/2.0/ping";
    /// URL for responding to a DIDComm trust ping.
    pub const TRUST_PONG: &str = "https://didcomm.org/trust-ping/2.0/ping-response";
    /// URL for requesting a Verified Relationship Credential.
    pub const VRC_REQUEST: &str = "https://firstperson.network/vrc/1.0/request";
    /// URL for rejecting a VRC request.
    pub const VRC_REJECTED: &str = "https://firstperson.network/vrc/1.0/rejected";
    /// URL for issuing a VRC.
    pub const VRC_ISSUED: &str = "https://firstperson.network/vrc/1.0/issued";
    /// URL for a DIDComm MessagePickup 3.0 status message.
    pub const MESSAGEPICKUP_STATUS: &str = "https://didcomm.org/messagepickup/3.0/status";
}

/// Defined Message Types for OpenVTC DIDComm messaging protocol.
///
/// Each variant maps to a protocol URL used in DIDComm message `type` fields.
///
/// # Examples
///
/// ```
/// use openvtc_core::MessageType;
///
/// // Parse a protocol URL into a MessageType
/// let mt = MessageType::try_from("https://didcomm.org/trust-ping/2.0/ping").unwrap();
/// assert_eq!(mt.friendly_name(), "Trust Ping (Send)");
///
/// // Convert back to URL
/// let url: String = mt.into();
/// assert_eq!(url, "https://didcomm.org/trust-ping/2.0/ping");
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[non_exhaustive]
pub enum MessageType {
    /// A request to establish a new relationship with a remote party.
    RelationshipRequest,
    /// Notification that a relationship request was rejected by the remote party.
    RelationshipRequestRejected,
    /// Notification that a relationship request was accepted by the remote party.
    RelationshipRequestAccepted,
    /// Finalizes an accepted relationship, completing the handshake.
    RelationshipRequestFinalize,
    /// Sends a DIDComm trust-ping to verify connectivity with a remote party.
    TrustPing,
    /// Response to a trust-ping, confirming the remote party is reachable.
    TrustPong,
    /// A request for a Verified Relationship Credential (VRC) from a remote party.
    VRCRequest,
    /// Notification that a VRC request was rejected.
    VRCRequestRejected,
    /// A VRC has been issued and delivered.
    VRCIssued,
}

impl MessageType {
    /// Returns a human-readable display name for this message type.
    pub fn friendly_name(&self) -> String {
        match self {
            MessageType::RelationshipRequest => "Relationship Request",
            MessageType::RelationshipRequestRejected => "Relationship Request Rejected",
            MessageType::RelationshipRequestAccepted => "Relationship Request Accepted",
            MessageType::RelationshipRequestFinalize => "Relationship Request Finalize",
            MessageType::TrustPing => "Trust Ping (Send)",
            MessageType::TrustPong => "Trust Pong (Receive)",
            MessageType::VRCRequest => "VRC Request",
            MessageType::VRCRequestRejected => "VRC Request Rejected",
            MessageType::VRCIssued => "VRC Issued",
        }
        .to_string()
    }
}

/// Convert MessageType to its protocol URL string.
impl From<MessageType> for String {
    fn from(value: MessageType) -> Self {
        use protocol_urls::*;
        match value {
            MessageType::RelationshipRequest => RELATIONSHIP_REQUEST,
            MessageType::RelationshipRequestRejected => RELATIONSHIP_REQUEST_REJECT,
            MessageType::RelationshipRequestAccepted => RELATIONSHIP_REQUEST_ACCEPT,
            MessageType::RelationshipRequestFinalize => RELATIONSHIP_REQUEST_FINALIZE,
            MessageType::TrustPing => TRUST_PING,
            MessageType::TrustPong => TRUST_PONG,
            MessageType::VRCRequest => VRC_REQUEST,
            MessageType::VRCRequestRejected => VRC_REJECTED,
            MessageType::VRCIssued => VRC_ISSUED,
        }
        .to_string()
    }
}

/// Convert a protocol URL string to a MessageType.
impl TryFrom<&str> for MessageType {
    type Error = OpenVTCError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        use protocol_urls::*;
        match value {
            RELATIONSHIP_REQUEST => Ok(MessageType::RelationshipRequest),
            RELATIONSHIP_REQUEST_REJECT => Ok(MessageType::RelationshipRequestRejected),
            RELATIONSHIP_REQUEST_ACCEPT => Ok(MessageType::RelationshipRequestAccepted),
            RELATIONSHIP_REQUEST_FINALIZE => Ok(MessageType::RelationshipRequestFinalize),
            TRUST_PING => Ok(MessageType::TrustPing),
            TRUST_PONG => Ok(MessageType::TrustPong),
            VRC_REQUEST => Ok(MessageType::VRCRequest),
            VRC_REJECTED => Ok(MessageType::VRCRequestRejected),
            VRC_ISSUED => Ok(MessageType::VRCIssued),
            _ => Err(OpenVTCError::InvalidMessage(value.to_string())),
        }
    }
}

/// Convert a DIDComm message to a MessageType
impl TryFrom<&Message> for MessageType {
    type Error = OpenVTCError;

    fn try_from(value: &Message) -> Result<Self, Self::Error> {
        value.typ.as_str().try_into()
    }
}

/// The kinds of verifiable credential a VTC issues to a member over the
/// `credential-exchange/issue` protocol.
///
/// This is the single registry that drives credential storage
/// ([`CommunityRecord::credentials`](crate::config::account::CommunityRecord::credentials)),
/// dispatch ([`messaging::handle_credential_issue`])
/// and the "My Credentials" UI. Adding a credential kind means adding a variant
/// here plus its match arms below — the dispatch and UI code iterate
/// [`ALL`](Self::ALL) and classify through [`from_credential`](Self::from_credential),
/// so they pick the new kind up without edits.
///
/// It is kept next to [`MessageType`] deliberately: a `MessageType` identifies
/// a DIDComm message, while a `CredentialKind` identifies a credential carried
/// *inside* a `credential-exchange/issue` message. Every kind shares that one
/// message type and one DIDComm route, so the router needs no per-kind
/// registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[non_exhaustive]
pub enum CredentialKind {
    /// The membership credential (VMC) proving admission to the community.
    /// Receiving it activates the membership.
    Membership,
    /// The community role credential issued alongside the VMC: a
    /// community-issued VAC (`AuthorityCredential`, `issuerScope` public) whose
    /// `authority` is `{ scope: <community DID>, actions: ["role:<name>"] }`
    /// ([`dtg::community_roles`]). It replaced the pre-v1 role endorsement
    /// credential, a type DTG Credentials no longer defines.
    Role,
    /// The community's own identity check of the member: a `vetted/1`
    /// statement (`StatementCredential`) the community issued for itself, with
    /// none of the vetter-only members ([`dtg::is_community_vetting`]). It
    /// replaced the community-issued `IdentityVerificationCredential`, and is
    /// what a personhood assertion offers as identity evidence. A vetter's
    /// `vetted/1` is not this kind: it answers a vetting request instead.
    CommunityVetting,
}

impl CredentialKind {
    /// Every known credential kind, in display order. The single list that
    /// dispatch, storage and UI iterate; adding a variant extends all three.
    pub const ALL: &'static [CredentialKind] = &[
        CredentialKind::Membership,
        CredentialKind::Role,
        CredentialKind::CommunityVetting,
    ];

    /// The DTG concrete `type` that identifies this kind in an issued credential.
    pub fn vc_type(self) -> &'static str {
        match self {
            CredentialKind::Membership => "MembershipCredential",
            CredentialKind::Role => "AuthorityCredential",
            CredentialKind::CommunityVetting => "StatementCredential",
        }
    }

    /// Stable key used to persist this kind (the JSON map key in
    /// [`CommunityRecord::credentials`](crate::config::account::CommunityRecord::credentials))
    /// and as the short "My Credentials" display label.
    ///
    /// `Role` keeps its key across the move from a role endorsement to a role
    /// VAC: what sits under it is held to the current specification on load
    /// instead ([`crate::config::account::RetiredCredential`]), so a pre-v1 role
    /// endorsement under this key is set aside with a reason rather than being
    /// read as a VAC.
    pub fn config_key(self) -> &'static str {
        match self {
            CredentialKind::Membership => "Membership",
            CredentialKind::Role => "Role",
            CredentialKind::CommunityVetting => "CommunityVetting",
        }
    }

    /// Whether receiving this credential activates the community membership.
    /// The VMC is admission proof; the role VAC is supplementary.
    pub fn activates_membership(self) -> bool {
        matches!(self, CredentialKind::Membership)
    }

    /// Parse a persisted [`config_key`](Self::config_key) back into a kind.
    /// `None` for an unrecognised key (e.g. one written by a newer version).
    pub fn from_config_key(key: &str) -> Option<CredentialKind> {
        CredentialKind::ALL
            .iter()
            .copied()
            .find(|k| k.config_key() == key)
    }

    /// Classify an issued credential. It must first be a conformant DTG
    /// credential ([`dtg::parse_conformant`]) — the v1 context, a declared
    /// `issuerScope`, exactly one concrete type — and then:
    ///
    /// - a `MembershipCredential` is [`Membership`](Self::Membership);
    /// - an `AuthorityCredential` is [`Role`](Self::Role) only when it is a
    ///   community role grant ([`dtg::community_roles`]); any other VAC is of
    ///   no known kind;
    /// - a `StatementCredential` is [`CommunityVetting`](Self::CommunityVetting)
    ///   only when it is the community's own `vetted/1` check
    ///   ([`dtg::is_community_vetting`]); any other statement is of no known
    ///   kind here (a vetter's `vetted/1` is the vetting flow's).
    ///
    /// `None` for anything else, including every credential in a pre-v1 shape.
    pub fn from_credential(credential: &serde_json::Value) -> Option<CredentialKind> {
        let parsed = dtg::parse_conformant(credential).ok()?;
        match parsed.type_() {
            dtg_credentials::DTGCredentialType::Membership => Some(CredentialKind::Membership),
            dtg_credentials::DTGCredentialType::Authority
                if dtg::community_roles(&parsed).is_some() =>
            {
                Some(CredentialKind::Role)
            }
            dtg_credentials::DTGCredentialType::Statement if dtg::is_community_vetting(&parsed) => {
                Some(CredentialKind::CommunityVetting)
            }
            _ => None,
        }
    }
}

/// Persisted as its stable [`config_key`](CredentialKind::config_key) string so
/// it can serve as a JSON object key in
/// [`CommunityRecord::credentials`](crate::config::account::CommunityRecord::credentials).
impl Serialize for CredentialKind {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.config_key())
    }
}

impl<'de> Deserialize<'de> for CredentialKind {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let key = String::deserialize(deserializer)?;
        CredentialKind::from_config_key(&key)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown credential kind {key:?}")))
    }
}

// ****************************************************************************
// Secret Key types and conversions
// ****************************************************************************

/// Tags what a cryptographic key is used for within a DID Document.
#[derive(Default, Debug, Clone, Copy, PartialEq)]
pub enum KeyPurpose {
    /// Key used for signing assertions (assertion method).
    Signing,
    /// Key used for authentication.
    Authentication,
    /// Key used for encryption / key agreement.
    Encryption,
    /// Purpose has not been determined.
    #[default]
    Unknown,
}

impl fmt::Display for KeyPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyPurpose::Signing => write!(f, "Signing"),
            KeyPurpose::Authentication => write!(f, "Authentication"),
            KeyPurpose::Encryption => write!(f, "Encryption"),
            KeyPurpose::Unknown => write!(f, "Unknown"),
        }
    }
}

#[cfg(feature = "openpgp-card")]
impl From<KeyType> for KeyPurpose {
    fn from(kt: KeyType) -> Self {
        match kt {
            KeyType::Signing => KeyPurpose::Signing,
            KeyType::Authentication => KeyPurpose::Authentication,
            KeyType::Decryption => KeyPurpose::Encryption,
            _ => KeyPurpose::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_message_types() -> [MessageType; 9] {
        [
            MessageType::RelationshipRequest,
            MessageType::RelationshipRequestRejected,
            MessageType::RelationshipRequestAccepted,
            MessageType::RelationshipRequestFinalize,
            MessageType::TrustPing,
            MessageType::TrustPong,
            MessageType::VRCRequest,
            MessageType::VRCRequestRejected,
            MessageType::VRCIssued,
        ]
    }

    #[test]
    fn test_message_type_try_from_valid() {
        use protocol_urls::*;
        let cases = vec![
            (RELATIONSHIP_REQUEST, "RelationshipRequest"),
            (RELATIONSHIP_REQUEST_REJECT, "RelationshipRequestRejected"),
            (RELATIONSHIP_REQUEST_ACCEPT, "RelationshipRequestAccepted"),
            (RELATIONSHIP_REQUEST_FINALIZE, "RelationshipRequestFinalize"),
            (TRUST_PING, "TrustPing"),
            (TRUST_PONG, "TrustPong"),
            (VRC_REQUEST, "VRCRequest"),
            (VRC_REJECTED, "VRCRequestRejected"),
            (VRC_ISSUED, "VRCIssued"),
        ];

        for (url, expected_debug_contains) in cases {
            let mt = MessageType::try_from(url);
            assert!(mt.is_ok(), "Should parse URL '{}' into a MessageType", url);
            let debug_str = format!("{:?}", mt.unwrap());
            assert_eq!(debug_str, expected_debug_contains);
        }
    }

    #[test]
    fn credential_kind_registry_is_self_consistent() {
        // Every registered kind is recognised from a credential carrying its
        // `vc_type`, and its `config_key` round-trips. This is the property the
        // dispatch / storage / UI rely on, so a newly added variant is picked
        // up everywhere by extending `ALL` + the match arms — and nowhere else.
        for kind in CredentialKind::ALL {
            let cred = match kind {
                CredentialKind::Membership => crate::dtg::fixtures::grant("did:ex:c", "did:ex:m"),
                CredentialKind::Role => {
                    crate::dtg::fixtures::role_vac("did:ex:c", "did:ex:m", "member")
                }
                CredentialKind::CommunityVetting => {
                    crate::dtg::fixtures::community_vetting("did:ex:c", "did:ex:m")
                }
            };
            assert_eq!(cred["type"][2], kind.vc_type());
            assert_eq!(
                CredentialKind::from_credential(&cred),
                Some(*kind),
                "{kind:?} must be classified from its vc_type",
            );
            assert_eq!(
                CredentialKind::from_config_key(kind.config_key()),
                Some(*kind),
                "{kind:?} config_key must round-trip",
            );
        }
        assert_eq!(
            CredentialKind::from_credential(&serde_json::json!({ "type": ["Other"] })),
            None,
        );
        // A bare `type` is not enough: the credential must conform to DTG v1.
        assert_eq!(
            CredentialKind::from_credential(
                &serde_json::json!({ "type": ["VerifiableCredential", "MembershipCredential"] })
            ),
            None,
        );
        // A vetter's `vetted/1` is the vetting flow's, not a stored kind.
        assert_eq!(
            CredentialKind::from_credential(&crate::dtg::fixtures::vetted_statement(
                "did:ex:v",
                dtg_credentials::IssuerScope::Directed,
                "did:ex:m",
                "did:ex:c",
                true,
            )),
            None,
        );
        // The retired role endorsement is of no known kind.
        assert_eq!(
            CredentialKind::from_credential(&crate::dtg::fixtures::retired_role_endorsement(
                "did:ex:c", "did:ex:m"
            )),
            None,
        );
        assert_eq!(CredentialKind::from_config_key("Nope"), None);
    }

    #[test]
    fn test_message_type_try_from_unknown_yields_invalid_message() {
        let unknown = "https://example.com/not-a-real-openvtc-type";
        let err = MessageType::try_from(unknown).unwrap_err();
        match err {
            errors::OpenVTCError::InvalidMessage(s) => assert_eq!(s, unknown),
            other => panic!("expected InvalidMessage, got {other:?}"),
        }
    }

    #[test]
    fn test_message_type_string_roundtrip_all_variants() {
        for ty in all_message_types() {
            let url: String = ty.clone().into();
            let parsed = MessageType::try_from(url.as_str()).unwrap_or_else(|e| {
                panic!("try_from failed for variant url {url:?}: {e:?}");
            });
            let again: String = parsed.into();
            assert_eq!(url, again, "From<MessageType> and TryFrom drift");
        }
    }

    #[test]
    fn test_message_type_try_from_message() {
        let msg = Message::build(
            "test-id".to_string(),
            String::from(MessageType::TrustPing),
            serde_json::json!({}),
        )
        .finalize();
        let parsed = MessageType::try_from(&msg).expect("valid message type");
        assert_eq!(String::from(parsed), String::from(MessageType::TrustPing));
    }

    #[test]
    fn test_message_type_friendly_names() {
        let cases = [
            (MessageType::RelationshipRequest, "Relationship Request"),
            (
                MessageType::RelationshipRequestRejected,
                "Relationship Request Rejected",
            ),
            (
                MessageType::RelationshipRequestAccepted,
                "Relationship Request Accepted",
            ),
            (
                MessageType::RelationshipRequestFinalize,
                "Relationship Request Finalize",
            ),
            (MessageType::TrustPing, "Trust Ping (Send)"),
            (MessageType::TrustPong, "Trust Pong (Receive)"),
            (MessageType::VRCRequest, "VRC Request"),
            (MessageType::VRCRequestRejected, "VRC Request Rejected"),
            (MessageType::VRCIssued, "VRC Issued"),
        ];
        for (ty, want) in cases {
            assert_eq!(ty.friendly_name(), want);
        }
    }

    #[test]
    fn test_key_purpose_display() {
        assert_eq!(format!("{}", KeyPurpose::Signing), "Signing");
        assert_eq!(format!("{}", KeyPurpose::Authentication), "Authentication");
        assert_eq!(format!("{}", KeyPurpose::Encryption), "Encryption");
        assert_eq!(format!("{}", KeyPurpose::Unknown), "Unknown");
    }

    #[test]
    fn test_key_purpose_default() {
        let kp = KeyPurpose::default();
        assert_eq!(kp, KeyPurpose::Unknown);
    }
}
