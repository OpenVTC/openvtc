//! Capability Trust Task client for the TUI: query and manage a community's
//! pluggable capabilities.
//!
//! The wire layer — document builders, envelope parsing, and reply
//! classification — lives in the shared [`trust_tasks_capability_client`]
//! crate (re-exported below) so this client and the community service's hook
//! producer cannot drift on the contract. Only the two pieces that are
//! genuinely openvtc-specific stay here: signing with the persona key
//! ([`sign_document`]) and sending over the profile's mediator
//! ([`send_capability_document`]).

use std::sync::Arc;

use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use uuid::Uuid;

use crate::errors::OpenVTCError;
use crate::pack_and_send;

// The wire layer, shared with the community service (vtc-service hooks).
pub use trust_tasks_capability_client::{
    CAPABILITY_DISABLE_TYPE, CAPABILITY_ENABLE_TYPE, CAPABILITY_LIST_TYPE, CapabilityReply,
    CapabilitySummary, TRUST_TASK_ENVELOPE_TYPE, build_list_document, build_toggle_document,
    parse_capability_reply, parse_envelope_document, parse_envelope_reply,
};

/// Attach an `eddsa-jcs-2022` Data-Integrity proof over `doc` (minus the
/// `proof` member), with `proofPurpose: authentication`, signed by the
/// document `issuer`'s **authentication** key — the persona proving it is the
/// party making the request. Every Trust Task request this client sends is
/// signed this way (a community requires a document proof bound to the sender
/// on every request); `signing_secret` must therefore be a key the issuer's DID
/// document lists under `authentication`. Signing is kept local rather than in the shared crate:
/// each consumer signs with its own signer and its own error type, so the
/// wire crate stays crypto-free.
///
/// NOTE: v1 signs directly in the client; routing the approval through the
/// delegated-execution consent flow is the planned upgrade
/// (`trust-task-delegation-architecture.md`).
pub async fn sign_document(
    doc: &mut TrustTask<Value>,
    signing_secret: &Secret,
) -> Result<(), OpenVTCError> {
    let mut doc_value = serde_json::to_value(&*doc)
        .map_err(|e| OpenVTCError::Config(format!("serialise capability document: {e}")))?;
    if let Some(obj) = doc_value.as_object_mut() {
        obj.remove("proof");
    }
    let proof = DataIntegrityProof::sign(
        &doc_value,
        signing_secret,
        SignOptions::new().with_proof_purpose("authentication"),
    )
    .await
    .map_err(|e| OpenVTCError::Config(format!("sign capability document: {e}")))?;
    let proof_value = serde_json::to_value(&proof)
        .map_err(|e| OpenVTCError::Config(format!("serialise proof: {e}")))?;
    doc.proof = Some(
        serde_json::from_value(proof_value)
            .map_err(|e| OpenVTCError::Config(format!("convert proof: {e}")))?,
    );
    Ok(())
}

/// Pack `doc` in the DIDComm Trust Task envelope and send it to the VTC via
/// the mediator. Returns the document id — the `threadId` the reply carries.
/// Sending is fire-and-forget: `Ok` means handed to the transport, never that
/// the host received it; the caller owns a reply timeout.
pub async fn send_capability_document(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    persona_did: &str,
    vtc_did: &str,
    mediator: &str,
    doc: &TrustTask<Value>,
) -> Result<String, OpenVTCError> {
    let body = serde_json::to_value(doc)
        .map_err(|e| OpenVTCError::Config(format!("serialise capability document: {e}")))?;
    let message = Message::build(
        format!("urn:uuid:{}", Uuid::new_v4()),
        TRUST_TASK_ENVELOPE_TYPE.to_string(),
        body,
    )
    .from(persona_did.to_string())
    .to(vtc_did.to_string())
    .thid(doc.id.clone())
    .finalize();
    pack_and_send(atm, profile, &message, persona_did, vtc_did, mediator).await?;
    Ok(doc.id.clone())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn re_exported_builders_are_addressed() {
        let list = build_list_document("did:example:me", "did:example:vtc");
        assert_eq!(list.recipient.as_deref(), Some("did:example:vtc"));
        assert_eq!(list.type_uri.slug(), "governance/capability/list");

        let enable = build_toggle_document(
            "did:example:me",
            "did:example:vtc",
            "git-trust",
            "0.1",
            true,
        );
        assert_eq!(enable.payload["config"]["authority"], "did:example:vtc");
    }

    /// A capability list — a read — is signed like a write: issuer the
    /// persona, recipient the community, dated, a fresh id, and an
    /// `authentication` proof.
    #[tokio::test]
    async fn a_list_request_is_signed_for_authentication() {
        use affinidi_tdk::dids::{DID, KeyType};
        let (me, signer) = DID::generate_did_key(KeyType::Ed25519).unwrap();
        let mut a = build_list_document(&me, "did:example:vtc");
        let b = build_list_document(&me, "did:example:vtc");
        assert_ne!(a.id, b.id, "every request has its own id");
        sign_document(&mut a, &signer).await.unwrap();
        let v = serde_json::to_value(&a).unwrap();
        assert_eq!(v["issuer"], me.as_str());
        assert_eq!(v["recipient"], "did:example:vtc");
        assert!(v.get("issuedAt").is_some(), "{v}");
        assert_eq!(v["proof"]["proofPurpose"], "authentication");
    }
}
