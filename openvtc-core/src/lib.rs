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
pub mod errors;
pub mod health;
pub mod identity;
pub mod join;
pub mod logs;
pub mod members;
pub mod messaging;
#[cfg(feature = "openpgp-card")]
pub mod openpgp_card;
pub mod persona;
pub mod personhood;
pub mod presentation;
pub mod process_lock;
pub mod rebuild;
pub mod rebuild_apply;
pub mod relationships;
pub mod secure_store;
pub mod tasks;
pub mod tsp;
pub mod vetting;
pub mod vrc;

/// Primary Linux Foundation Mediator DID.
/// Can be overridden via the `OPENVTC_MEDIATOR_DID` environment variable.
pub const LF_PUBLIC_MEDIATOR_DID: &str =
    "did:webvh:QmetnhxzJXTJ9pyXR1BbZ2h6DomY6SB1ZbzFPrjYyaEq9V:fpp.storm.ws:public-mediator";

/// Primary Linux Foundation Organisation DID.
/// Can be overridden via the `OPENVTC_ORG_DID` environment variable.
pub const LF_ORG_DID: &str =
    "did:webvh:QmXkYcFCbvFFcYZf2q5gNk8Vp4b4vMbVKWbbc7oivcdZHK:fpp.storm.ws";

/// Resolves the mediator DID from an optional caller-supplied override.
///
/// The binary is the single boundary that reads the `OPENVTC_MEDIATOR_DID`
/// environment variable and passes its value (if any) in here; core never
/// reads process env itself. If `override_did` is `Some` and starts with
/// `"did:"`, it is returned; otherwise a warning is logged and the default
/// [`LF_PUBLIC_MEDIATOR_DID`] is returned instead.
pub fn mediator_did(override_did: Option<&str>) -> String {
    if let Some(did) = override_did {
        if did.starts_with("did:") {
            return did.to_string();
        }
        tracing::warn!(
            "mediator DID override '{}' is not a valid DID (must start with 'did:'), using default",
            did
        );
    }
    LF_PUBLIC_MEDIATOR_DID.to_string()
}

/// Resolves the organisation DID from an optional caller-supplied override.
///
/// The binary is the single boundary that reads the `OPENVTC_ORG_DID`
/// environment variable and passes its value (if any) in here; core never
/// reads process env itself. If `override_did` is `Some` and starts with
/// `"did:"`, it is returned; otherwise a warning is logged and the default
/// [`LF_ORG_DID`] is returned instead.
pub fn org_did(override_did: Option<&str>) -> String {
    if let Some(did) = override_did {
        if did.starts_with("did:") {
            return did.to_string();
        }
        tracing::warn!(
            "org DID override '{}' is not a valid DID (must start with 'did:'), using default",
            did
        );
    }
    LF_ORG_DID.to_string()
}

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
/// [`ALL`](Self::ALL) and match on [`vc_type`](Self::vc_type), so they pick the
/// new kind up without edits.
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
    /// The role endorsement credential (VEC) issued alongside the VMC.
    Role,
}

impl CredentialKind {
    /// Every known credential kind, in display order. The single list that
    /// dispatch, storage and UI iterate; adding a variant extends all three.
    pub const ALL: &'static [CredentialKind] = &[CredentialKind::Membership, CredentialKind::Role];

    /// The W3C VC `type` value that identifies this kind in an issued credential.
    pub fn vc_type(self) -> &'static str {
        match self {
            CredentialKind::Membership => "MembershipCredential",
            CredentialKind::Role => "EndorsementCredential",
        }
    }

    /// Stable key used to persist this kind (the JSON map key in
    /// [`CommunityRecord::credentials`](crate::config::account::CommunityRecord::credentials))
    /// and as the short "My Credentials" display label.
    pub fn config_key(self) -> &'static str {
        match self {
            CredentialKind::Membership => "Membership",
            CredentialKind::Role => "Role",
        }
    }

    /// Whether receiving this credential activates the community membership.
    /// The VMC is admission proof; the VEC (role) is supplementary.
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

    /// Classify an issued W3C VC by matching its `type` array against the
    /// registry. Returns the first kind whose [`vc_type`](Self::vc_type)
    /// appears, or `None` if the credential is of no known kind.
    pub fn from_credential(credential: &serde_json::Value) -> Option<CredentialKind> {
        let types = credential
            .get("type")
            .and_then(serde_json::Value::as_array)?;
        CredentialKind::ALL.iter().copied().find(|k| {
            types
                .iter()
                .filter_map(serde_json::Value::as_str)
                .any(|t| t == k.vc_type())
        })
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
            let cred = serde_json::json!({ "type": ["VerifiableCredential", kind.vc_type()] });
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
    fn test_mediator_did_default() {
        let did = mediator_did(None);
        assert_eq!(did, LF_PUBLIC_MEDIATOR_DID);
        assert!(
            did.starts_with("did:webvh:"),
            "Mediator DID should start with did:webvh:"
        );
    }

    #[test]
    fn test_org_did_default() {
        let did = org_did(None);
        assert_eq!(did, LF_ORG_DID);
        assert!(
            did.starts_with("did:webvh:"),
            "Org DID should start with did:webvh:"
        );
    }

    #[test]
    fn test_mediator_did_valid_override() {
        let custom = "did:web:example.com:mediator";
        let did = mediator_did(Some(custom));
        assert_eq!(did, custom);
    }

    #[test]
    fn test_mediator_did_invalid_override_falls_back() {
        let did = mediator_did(Some("not-a-did"));
        assert_eq!(
            did, LF_PUBLIC_MEDIATOR_DID,
            "Invalid override value should fall back to default"
        );
    }

    #[test]
    fn test_org_did_valid_override() {
        let custom = "did:web:example.com:org";
        let did = org_did(Some(custom));
        assert_eq!(did, custom);
    }

    #[test]
    fn test_org_did_invalid_override_falls_back() {
        let did = org_did(Some("bogus-value"));
        assert_eq!(
            did, LF_ORG_DID,
            "Invalid override value should fall back to default"
        );
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
