//! Member → VTC reciprocal membership-credential (VMC) exchange (the `members`
//! protocol family).
//!
//! Membership between a persona and a VTC is a *pair* of VMCs: the VTC issues one
//! to the member at admission (community → member, stored on the membership via
//! [`handle_credential_issue`](crate::messaging::handle_credential_issue)), and
//! the member issues one back (member → community). This module sends the
//! member's half over DIDComm.
//!
//! The VMC is a Data-Integrity VC whose `issuer` is the member persona and whose
//! `credentialSubject.id` is the community VTC DID; the VTC verifies the proof +
//! binding and stores it (vta-sdk `protocols::members`, type `members/vmc/1.0`).
//!
//! ## It carries a digest of the grant
//!
//! DTG Core Credentials: "A member-issued VMC whose `digest` does not match a
//! valid community-issued VMC MUST NOT be treated as completing a membership
//! edge." The digest is over the grant **as the community sent it** — the JSON
//! stored on the membership record, not a re-serialisation of a parse of it,
//! which drops members the local model does not know (`credentialStatus`, which
//! every VMC issued against a status list carries).
//!
//! That binding is also what makes renewal safe: a re-issued grant has different
//! claims and therefore a different digest, so consent to one membership cannot
//! carry over to another.

use std::sync::Arc;

use affinidi_tdk::{
    didcomm::Message,
    messaging::{ATM, profiles::ATMProfile},
    secrets_resolver::secrets::Secret,
};
use chrono::Utc;
use dtg_credentials::DTGCredential;
use serde_json::Value;
use uuid::Uuid;
use vta_sdk::protocols::members::{MEMBER_VMC_TYPE, MemberVmcBody};

use crate::errors::OpenVTCError;

/// Build + sign the reciprocal member VMC and send it to the community's VTC
/// (`members/vmc/1.0`), end to end. The VMC's `issuer` is the member persona
/// (`member_did`) and its `credentialSubject.id` is the community (`vtc_did`) —
/// the direction the VTC verifies. `signing_secret` is the member persona's
/// signing key (its `id` is the persona's assertionMethod VM, which becomes the
/// proof's `verificationMethod`). Used by both the manual "issue VMC" action and
/// the auto-answer to a VTC `members/request-vmc/1.0`.
///
/// `grant` is the community-issued VMC as received, from the membership record.
///
/// Returns the DIDComm message id (the receipt's thread root) and the signed
/// credential. The credential comes back so the caller can keep a copy: a
/// member who cannot show what they sent cannot answer "did I acknowledge
/// this?", and cannot re-send it without minting a different one.
///
/// Two keys, for two different acts: `signing_secret` (assertionMethod) signs
/// the credential, and `document_signer` (authentication) signs the Trust Task
/// request that carries it.
pub async fn issue_and_send_member_vmc(
    route: &Delivery<'_>,
    signing_secret: &Secret,
    document_signer: &Secret,
    grant: &Value,
    closes_request: Option<Uuid>,
) -> Result<(Uuid, Value), OpenVTCError> {
    let vc = build_member_vmc(signing_secret, grant).await?;
    let msg_id = submit_member_vmc(route, document_signer, vc.clone(), closes_request).await?;
    Ok((msg_id, vc))
}

/// Where a member VMC is going and who is sending it — the triple every
/// `members` delivery needs, resolved by the caller.
///
/// Grouped rather than passed loose, matching [`crate::personhood::Route`]
/// beside it. No TSP field: the `members/vmc` exchange has one transport today,
/// and a field that is always `None` would suggest a choice the caller does not
/// have.
pub struct Delivery<'a> {
    pub atm: &'a ATM,
    pub profile: &'a Arc<ATMProfile>,
    /// The member acting — the authcrypt sender, and so the identity the
    /// community proves the delivery came from.
    pub member_did: &'a str,
    /// The community being addressed.
    pub vtc_did: &'a str,
    /// The member's own mediator, for the DIDComm leg.
    pub mediator_did: &'a str,
}

/// Build + sign the reciprocal member VMC, without sending it. The signing half of
/// [`issue_and_send_member_vmc`], split out so the credential's shape can be asserted
/// without a mediator.
///
/// `grant` is the community-issued VMC **as it arrived** — the JSON on the membership
/// record. The member and the community are read off it, so the two halves of the edge
/// cannot disagree about who they are between, and the digest covers the document the
/// community will recompute it over.
///
/// # The credential carries its own `id`
///
/// A community stores a member's VMC keyed by that `id`: it is what makes a re-sent
/// credential idempotent rather than a duplicate, and a *different* one a renewal rather
/// than a conflict. A VMC without one is refused, and the refusal comes back as a
/// problem-report threaded on the delivery — which is not a thread this client correlates,
/// so the rejection is invisible from here and the membership pair silently stays half
/// formed.
///
/// The id has to be set before signing: the Data Integrity proof covers the credential
/// minus its `proof`, so an id added afterwards leaves a document whose proof no longer
/// verifies. The same is true of the digest, which is why it is set at construction.
pub async fn build_member_vmc(
    signing_secret: &Secret,
    grant: &Value,
) -> Result<Value, OpenVTCError> {
    let mut vmc = DTGCredential::new_member_vmc(grant, Utc::now(), None)
        .map_err(|e| {
            OpenVTCError::Config(format!(
                "cannot acknowledge this community's membership credential: {e}"
            ))
        })?
        .with_id(format!("urn:uuid:{}", Uuid::new_v4()));
    vmc.sign(signing_secret, None)
        .await
        .map_err(|e| OpenVTCError::Config(format!("sign member VMC: {e}")))?;
    serde_json::to_value(&vmc)
        .map_err(|e| OpenVTCError::Config(format!("serialize member VMC: {e}")))
}

/// Send a member-issued VMC to the community's VTC over DIDComm
/// (`members/vmc/1.0`). `vc` is the **signed** membership credential — `issuer`
/// = the member persona (`member_did`), `credentialSubject.id` = the community
/// (`vtc_did`). The message is packed authcrypt and forwarded via the persona's
/// mediator; the VTC reads the member from the envelope and verifies the VC's own
/// issuer proof. Returns the DIDComm message id (the thread root the VTC's
/// `#response` receipt references).
pub async fn submit_member_vmc(
    route: &Delivery<'_>,
    signer: &Secret,
    vc: Value,
    closes_request: Option<Uuid>,
) -> Result<Uuid, OpenVTCError> {
    let Delivery {
        atm,
        profile,
        member_did,
        vtc_did,
        mediator_did,
    } = *route;
    // `closes_request` closes an *approved join request* as a side effect of
    // the delivery — `vtc/members/vmc/0.1`'s `requestId`, carrying the retired
    // `join-requests/accept` semantics.
    //
    // It is `Some` only on the join-time delivery, where the community is
    // still holding the request open waiting for our half. The manual "issue
    // VMC" action and the auto-answer to a `members/request-vmc` have no
    // request to close, and pass `None`.
    let body = serde_json::to_value(MemberVmcBody {
        vc,
        request_id: closes_request.map(|id| id.to_string()),
    })
    .map_err(|e| OpenVTCError::Config(format!("member vmc body serialize: {e}")))?;

    // A **document** in the binding envelope, not a bare payload typed with the
    // task URI. The bare form reached a VTC handler that bypasses its dispatch
    // spine — so the receipt was never signed, and a refusal came back as a
    // DIDComm problem-report rather than a framework error document.
    //
    // The reply type is unchanged either way: `MEMBER_VMC_RESPONSE_TYPE` is
    // exactly `MEMBER_VMC_TYPE#response`, which is what the spine's
    // `success_response` produces, so `message_dispatch`'s arm for it keeps
    // matching.
    let msg_id = Uuid::new_v4();
    let document_id = format!("urn:uuid:{msg_id}");
    // `vtc/members/vmc/0.1` declares `proof` REQUIRED: the member's half of the
    // membership pair is a document the community keeps, so who wrote it must
    // survive being relayed.
    let body = crate::trust_task_doc::build_signed_value(
        MEMBER_VMC_TYPE,
        member_did,
        vtc_did,
        &document_id,
        body,
        signer,
    )
    .await?;

    let now = Utc::now().timestamp().max(0) as u64;
    let msg = Message::build(
        document_id,
        crate::capabilities::TRUST_TASK_ENVELOPE_TYPE.to_string(),
        body,
    )
    .from(member_did.to_string())
    .to(vtc_did.to_string())
    .created_time(now)
    .finalize();

    crate::pack_and_send(atm, profile, &msg, member_did, vtc_did, mediator_did).await?;
    Ok(msg_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_tdk::secrets_resolver::secrets::Secret;

    const MEMBER: &str = "did:example:member";
    const COMMUNITY: &str = "did:example:community";

    /// A community-issued grant in the wire form a member receives — including
    /// `credentialStatus`, which every VMC issued against a status list carries and
    /// which `dtg-credentials` does not model. The fixture carries it deliberately:
    /// a grant built through the local model would not exercise the case the digest
    /// has to get right.
    fn grant() -> Value {
        serde_json::json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://firstperson.network/credentials/dtg/v1"
            ],
            "type": ["VerifiableCredential", "DTGCredential", "MembershipCredential"],
            "id": "urn:uuid:0d7f4d2c-1b8e-4a55-9e1f-7c4a2b9d3e60",
            "issuer": COMMUNITY,
            "validFrom": "2026-01-01T00:00:00Z",
            "credentialStatus": {
                "id": "https://community.example/status#7",
                "type": "BitstringStatusListEntry",
                "statusPurpose": "revocation",
                "statusListIndex": "7"
            },
            "credentialSubject": { "id": MEMBER },
            "proof": { "type": "DataIntegrityProof", "proofValue": "zCommunitySignature" }
        })
    }

    async fn signed_vmc() -> (Secret, Value) {
        let secret = Secret::generate_ed25519(None, None);
        let vc = build_member_vmc(&secret, &grant())
            .await
            .expect("build the member VMC");
        (secret, vc)
    }

    /// The acknowledgement binds to the grant by a digest over the grant **as it
    /// arrived**. Digesting a parse of it instead would drop `credentialStatus` — the
    /// model has no field for it — and the community would refuse a credential that
    /// otherwise verifies, on a thread this client does not correlate. That is the
    /// same silent failure the missing top-level `id` caused.
    #[tokio::test]
    async fn the_acknowledgement_digests_the_grant_as_received() {
        let (_secret, vc) = signed_vmc().await;

        assert_eq!(
            vc["credentialSubject"]["digestMultibase"],
            Value::String(dtg_credentials::digest_multibase_json(&grant()).expect("digest")),
            "the digest must cover the grant the community sent"
        );

        // Digesting a round trip through the local model now produces the *same*
        // value. This used to be the hazard the acknowledgement guarded against:
        // the model had no field for `credentialStatus`, so parsing dropped it and
        // a digest over the parse mismatched the one the community recomputes. As
        // of `dtg-credentials` 0.9.1 (Working Draft 02) the model carries
        // `credentialStatus`, so the round trip is lossless and either route
        // digests to the same bytes — the divergence is closed at the library
        // rather than worked around here. Parsed without the proof, which the
        // digest excludes anyway.
        let mut proofless = grant();
        proofless.as_object_mut().expect("object").remove("proof");
        let parsed: DTGCredential = serde_json::from_value(proofless).expect("parses");
        assert_eq!(
            vc["credentialSubject"]["digestMultibase"],
            Value::String(parsed.digest_multibase().expect("digest")),
            "0.9.1 models credentialStatus, so digesting the parsed grant matches the wire"
        );
    }

    /// The digest names one grant. A community that re-issues gets a different digest,
    /// so an old acknowledgement no longer completes the edge and the member owes a
    /// fresh one — which is what stops consent to one membership carrying over to
    /// another.
    #[tokio::test]
    async fn a_reissued_grant_needs_a_fresh_acknowledgement() {
        let (_secret, vc) = signed_vmc().await;

        let mut renewed = grant();
        renewed["id"] = Value::String("urn:uuid:renewed".into());
        renewed["validFrom"] = Value::String("2027-01-01T00:00:00Z".into());

        assert_ne!(
            vc["credentialSubject"]["digestMultibase"],
            Value::String(dtg_credentials::digest_multibase_json(&renewed).expect("digest"))
        );
    }

    /// There is nothing to acknowledge without a grant, and saying so at construction
    /// beats sending a credential the community will refuse.
    #[tokio::test]
    async fn a_non_grant_is_refused_before_it_is_sent() {
        let secret = Secret::generate_ed25519(None, None);
        let not_a_grant = serde_json::json!({
            "type": ["VerifiableCredential", "DTGCredential", "RelationshipCredential"],
            "issuer": COMMUNITY,
            "credentialSubject": { "id": MEMBER }
        });
        assert!(build_member_vmc(&secret, &not_a_grant).await.is_err());
    }

    /// The community keys a member's VMC by its top-level `id` and refuses one that has
    /// none. Every VMC this client ever issued lacked it, because `dtg-credentials` had no
    /// field for it — so every delivery was rejected, and the rejection arrived on a thread
    /// this client does not correlate.
    #[tokio::test]
    async fn a_member_vmc_carries_a_top_level_id() {
        let (_secret, vc) = signed_vmc().await;

        let id = vc
            .get("id")
            .and_then(Value::as_str)
            .expect("the VMC carries a top-level `id`");
        assert!(
            id.starts_with("urn:uuid:"),
            "the id should be a urn:uuid: URN, got {id}"
        );
        // `credentialSubject.id` names the *community*. It is a different property and does
        // not stand in for the credential's own identifier.
        assert_eq!(vc["credentialSubject"]["id"], COMMUNITY);
    }

    /// Two deliveries must not collide: the community treats a repeat of the same `id` as
    /// idempotent and a different one as a renewal, so a fixed id would make every
    /// re-issuance a no-op.
    #[tokio::test]
    async fn each_member_vmc_gets_a_fresh_id() {
        let (_, first) = signed_vmc().await;
        let (_, second) = signed_vmc().await;
        assert_ne!(first["id"], second["id"]);
    }

    /// The id is inside what the proof covers, which is why it has to be set before signing
    /// rather than spliced into the JSON on the way out. Parsing the delivered credential
    /// back and verifying it is what the community does; it must pass.
    #[tokio::test]
    async fn the_signed_vmc_verifies_with_its_id_in_place() {
        let (secret, vc) = signed_vmc().await;

        let parsed: DTGCredential = serde_json::from_value(vc.clone()).expect("parse back");
        parsed
            .verify_proof_with_public_key(secret.get_public_bytes())
            .expect("the delivered credential verifies as sent");

        // Tampering with the id — or adding one after the fact, the same operation — breaks
        // the proof, so there is no post-signing workaround for an issuer that omits it.
        let mut tampered = vc;
        tampered["id"] = Value::String("urn:uuid:00000000-0000-0000-0000-000000000000".into());
        let parsed: DTGCredential = serde_json::from_value(tampered).expect("parse back");
        assert!(
            parsed
                .verify_proof_with_public_key(secret.get_public_bytes())
                .is_err(),
            "a changed id must invalidate the proof"
        );
    }

    /// The issuer / subject direction is what the community verifies the pair by: the member
    /// issues, the community is the subject. Reversing it is a different credential.
    #[tokio::test]
    async fn the_member_issues_and_the_community_is_the_subject() {
        let (_secret, vc) = signed_vmc().await;
        assert_eq!(vc["issuer"], MEMBER);
        assert_eq!(vc["credentialSubject"]["id"], COMMUNITY);
        assert!(
            vc["type"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t == "MembershipCredential")
        );
    }
}
