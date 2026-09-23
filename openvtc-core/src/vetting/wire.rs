//! The peer path: Trust Task documents between applicant and vetter, and
//! between a vetter and their community (design §5).
//!
//! Every vetting task carries a Data Integrity proof by its issuer — the specs
//! make it REQUIRED — even though DIDComm authcrypt already authenticates the
//! sender. The proof is what survives the transport: a statement dispute or an
//! audit reads the document, not the envelope it arrived in. [`open`] therefore
//! checks both, and that they name the same party.
//!
//! The Vetting Statement itself travels as `credential-exchange/issue/0.1`,
//! the same message a community uses to deliver a membership credential
//! ([`credential_delivery`]).

use std::str::FromStr;

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use trust_tasks_rs::{ErrorPayload, TrustTask, TrustTaskCode};
use uuid::Uuid;
use vta_sdk::protocols::credential_exchange::ISSUE as CREDENTIAL_ISSUE_TYPE;
use vta_sdk::trust_task_proof::{TrustTaskVmResolver, verify_trust_task_proof_with};

use crate::errors::OpenVTCError;
use crate::messaging::{MESSAGE_EXPIRY_SECS, build_didcomm_message, unix_now};

/// Why an inbound vetting document was not accepted.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// Not a Trust Task document, or a payload of the wrong shape.
    #[error("malformed vetting document: {0}")]
    Malformed(String),
    /// The document's `type` differs from the message's.
    #[error("document type does not match the message type")]
    TypeMismatch,
    /// The in-band `issuer` is not the transport-authenticated sender.
    #[error("document issuer is not the authenticated sender")]
    IssuerNotSender,
    /// Missing or failing proof.
    #[error("document proof did not verify")]
    Proof(String),
    /// Signed, but by someone other than the issuer.
    #[error("document is not signed by its issuer")]
    WrongSigner,
}

/// A Trust Task document on the peer path. Named here so callers need not
/// depend on `trust-tasks-rs` to hold one.
pub type Document = TrustTask<Value>;

/// A fresh `urn:uuid:` document id.
#[must_use]
pub fn new_id() -> String {
    format!("urn:uuid:{}", Uuid::new_v4())
}

fn config_error(what: &str, e: impl std::fmt::Display) -> OpenVTCError {
    OpenVTCError::Config(format!("{what}: {e}"))
}

/// A new request document from `issuer` to `recipient`.
pub fn document<P: Serialize>(
    type_uri: &str,
    issuer: &str,
    recipient: &str,
    id: String,
    payload: &P,
) -> Result<TrustTask<Value>, OpenVTCError> {
    crate::trust_task_doc::build(type_uri, issuer, recipient, id, payload)
}

/// The `#response` to `request`, threaded on it.
pub fn response<P: Serialize>(
    request: &TrustTask<Value>,
    payload: &P,
) -> Result<TrustTask<Value>, OpenVTCError> {
    let payload = serde_json::to_value(payload).map_err(|e| config_error("vetting payload", e))?;
    Ok(request.respond_with(new_id(), payload))
}

/// The `trust-task-error` refusing `request` with `code`.
pub fn refusal(
    request: &TrustTask<Value>,
    code: &str,
    message: Option<&str>,
) -> Result<TrustTask<Value>, OpenVTCError> {
    let code = TrustTaskCode::from_str(code).map_err(|e| config_error("error code", e))?;
    let mut payload = ErrorPayload::new(code);
    if let Some(message) = message {
        payload = payload.with_message(message);
    }
    let error = request.reject_with(new_id(), payload);
    serde_json::to_value(&error)
        .and_then(serde_json::from_value)
        .map_err(|e| config_error("error document", e))
}

/// Sign `doc` as its issuer.
pub async fn sign(doc: &mut TrustTask<Value>, signer: &Secret) -> Result<(), OpenVTCError> {
    crate::capabilities::sign_document(doc, signer).await
}

/// Wrap `doc` for DIDComm. The message id is the document id, and the thread is
/// the document's, so a reply correlates the same way on DIDComm and TSP.
pub fn to_message(doc: &TrustTask<Value>) -> Result<Message, OpenVTCError> {
    let from = doc
        .issuer
        .clone()
        .ok_or_else(|| OpenVTCError::Config("vetting document has no issuer".into()))?;
    let to = doc
        .recipient
        .clone()
        .ok_or_else(|| OpenVTCError::Config("vetting document has no recipient".into()))?;
    let body = serde_json::to_value(doc).map_err(|e| config_error("vetting document", e))?;
    let now = unix_now();
    let mut builder = Message::build(doc.id.clone(), doc.type_uri.to_string(), body)
        .from(from)
        .to(to)
        .created_time(now)
        .expires_time(now + MESSAGE_EXPIRY_SECS);
    if let Some(thread) = &doc.thread_id {
        builder = builder.thid(thread.clone());
    }
    Ok(builder.finalize())
}

/// The DIDComm message delivering a signed Vetting Statement to the applicant,
/// threaded on the session it came out of.
pub fn credential_delivery(
    vetter_did: &str,
    applicant_did: &str,
    statement: &Value,
    session_id: &str,
) -> Result<Message, OpenVTCError> {
    build_didcomm_message(
        CREDENTIAL_ISSUE_TYPE,
        json!({ "credential_response": { "credential": statement } }),
        vetter_did,
        applicant_did,
        Some(session_id),
    )
    .map_err(|e| config_error("statement delivery", e))
}

/// `vetting/attestation/0.1` — a vetter gives an applicant an attestation that names nobody.
///
/// The hidden path's answer to [`credential_delivery`]. The document is signed like any other, so
/// the applicant knows the delivery came from the vetter it sat with; what is *inside* carries no
/// issuer, and it is the inside that reaches the community.
///
/// The type URI is the published task's. Until the pinned `trust-tasks-rs` carries its generated
/// module, the payload is assembled here and checked against the published schema by
/// `openvtc-core`'s own fixture test — see `docs/design/vetting-hidden-vetters-pcs.md` §19.
///
/// # Errors
///
/// [`OpenVTCError::Config`] if the message cannot be built.
pub fn hidden_attestation(
    vetter_did: &str,
    applicant_did: &str,
    attestation: &Value,
    session_id: &str,
) -> Result<Message, OpenVTCError> {
    build_didcomm_message(
        HIDDEN_ATTESTATION_TYPE,
        attestation.clone(),
        vetter_did,
        applicant_did,
        Some(session_id),
    )
    .map_err(|e| config_error("attestation delivery", e))
}

/// The published type URI of `vetting/attestation/0.1`.
///
/// Inside OpenVTC's inbound filter (`trusttasks.org/spec/vetting/*`), so it reaches
/// [`crate::vetting::inbound::handle`] without a filter change.
pub const HIDDEN_ATTESTATION_TYPE: &str = "https://trusttasks.org/spec/vetting/attestation/0.1";

/// A verified inbound document.
#[derive(Debug, Clone)]
pub struct Opened<P> {
    /// The document as received.
    pub document: TrustTask<Value>,
    /// Its payload, parsed.
    pub payload: P,
}

/// Read an inbound vetting document: parse it, bind its issuer to the
/// authenticated `sender`, verify its proof, and parse the payload.
pub async fn open<P: DeserializeOwned>(
    message: &Message,
    sender: &str,
    resolver: &TrustTaskVmResolver,
) -> Result<Opened<P>, WireError> {
    let document: TrustTask<Value> = serde_json::from_value(message.body.clone())
        .map_err(|e| WireError::Malformed(e.to_string()))?;
    if document.type_uri.to_string() != message.typ {
        return Err(WireError::TypeMismatch);
    }
    if document.issuer.as_deref() != Some(sender) {
        return Err(WireError::IssuerNotSender);
    }
    let signer = verify_trust_task_proof_with(&document, resolver)
        .await
        .map_err(|e| WireError::Proof(e.cause().unwrap_or("no detail").to_string()))?;
    if signer != sender {
        return Err(WireError::WrongSigner);
    }
    let payload = serde_json::from_value(document.payload.clone())
        .map_err(|e| WireError::Malformed(e.to_string()))?;
    Ok(Opened { document, payload })
}

/// The `join-requests/manifest/0.2` request an applicant sends a community to
/// learn what it requires. The payload is empty.
pub fn manifest_request(
    applicant_did: &str,
    community_did: &str,
) -> Result<TrustTask<Value>, OpenVTCError> {
    document(
        vta_sdk::protocols::join_requests::JOIN_REQUEST_MANIFEST_0_2_TYPE,
        applicant_did,
        community_did,
        new_id(),
        &json!({}),
    )
}

/// A `vtc/vetting/vetters/list/0.1` request for one page of `community_did`'s
/// vetter directory. The community refuses a caller it cannot identify, so this
/// is signed and sent as one of our personas like every other vetting task.
pub fn vetter_list_request(
    issuer: &str,
    community_did: &str,
    body: &vta_sdk::protocols::vetting::vetters::list::v0_1::Payload,
) -> Result<TrustTask<Value>, OpenVTCError> {
    document(
        vta_sdk::protocols::vetting::VETTING_VETTER_LIST_TYPE,
        issuer,
        community_did,
        new_id(),
        body,
    )
}

/// A `vtc/vetting/vetters/profile/0.1` request publishing (replacing) our
/// vetter profile at `community_did`.
pub fn vetter_profile_request(
    vetter_did: &str,
    community_did: &str,
    body: &vta_sdk::protocols::vetting::vetters::profile::v0_1::Payload,
) -> Result<TrustTask<Value>, OpenVTCError> {
    document(
        vta_sdk::protocols::vetting::VETTING_VETTER_PROFILE_TYPE,
        vetter_did,
        community_did,
        new_id(),
        body,
    )
}

/// The three Trust Tasks hidden vetting's community half serves.
///
/// Published specifications (`dtgwg-trust-tasks-tf`, branch `hidden-vetting-tasks`); the payload
/// types are written here rather than taken from `trust_tasks_rs::specs` because the generated
/// bindings are 0.22 and this workspace pins `^0.21`. `vetting::hidden::tests` validates each of
/// them against the published schema, which is the check the generated type would have carried.
pub mod pcs {
    use serde::{Deserialize, Serialize};
    use serde_json::Value;

    /// `vtc/vetting/vetters/pcs-root/0.1`.
    pub const ROOT_TYPE: &str = "https://trusttasks.org/spec/vtc/vetting/vetters/pcs-root/0.1";
    /// `vtc/vetting/vetters/pcs-tokens/0.1`.
    pub const TOKENS_TYPE: &str = "https://trusttasks.org/spec/vtc/vetting/vetters/pcs-tokens/0.1";
    /// `vtc/vetting/pcs-challenge/0.1`.
    pub const CHALLENGE_TYPE: &str = "https://trusttasks.org/spec/vtc/vetting/pcs-challenge/0.1";

    /// `#response` of each, which is what an inbound arm matches on.
    #[must_use]
    pub fn response_of(type_uri: &str) -> String {
        format!("{type_uri}#response")
    }

    /// What a vetter sends to enrol.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub struct RootRequest {
        pub label: String,
        pub id: String,
        pub request: Value,
    }

    /// What the community answers with.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub struct RootResponse {
        pub label: String,
        pub pre_credential: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ext: Option<Value>,
    }

    /// One tick of the drip, asked for.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub struct TokensRequest {
        pub label: String,
        pub tick: u32,
        pub requests: Vec<TokenRequest>,
    }

    /// One blinded serial with its opening proof.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub struct TokenRequest {
        pub commitment: String,
        pub opening_proof: String,
    }

    /// One tick of the drip, served.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub struct TokensResponse {
        pub label: String,
        pub tick: u32,
        pub pre_credentials: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ext: Option<Value>,
    }

    /// An applicant asking for the challenge its proof must bind. Every member is optional: the
    /// applicant is identified by `issuer`.
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub struct ChallengeRequest {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub criterion_id: Option<String>,
    }

    /// The challenge, and when it stops being accepted.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub struct ChallengeResponse {
        pub challenge: String,
        pub expires_at: chrono::DateTime<chrono::Utc>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ext: Option<Value>,
    }
}

/// A `vtc/vetting/vetters/pcs-root/0.1` request: enrol this persona for a class label.
///
/// # Errors
///
/// [`OpenVTCError::Config`] if the document cannot be built.
pub fn pcs_root_request(
    vetter_did: &str,
    community_did: &str,
    body: &pcs::RootRequest,
) -> Result<TrustTask<Value>, OpenVTCError> {
    document(pcs::ROOT_TYPE, vetter_did, community_did, new_id(), body)
}

/// A `vtc/vetting/vetters/pcs-tokens/0.1` request: draw one tick of the drip.
///
/// # Errors
///
/// [`OpenVTCError::Config`] if the document cannot be built.
pub fn pcs_tokens_request(
    vetter_did: &str,
    community_did: &str,
    body: &pcs::TokensRequest,
) -> Result<TrustTask<Value>, OpenVTCError> {
    document(pcs::TOKENS_TYPE, vetter_did, community_did, new_id(), body)
}

/// A `vtc/vetting/pcs-challenge/0.1` request: ask for the nonce this submission must bind.
///
/// # Errors
///
/// [`OpenVTCError::Config`] if the document cannot be built.
pub fn pcs_challenge_request(
    applicant_did: &str,
    community_did: &str,
    criterion_id: Option<&str>,
) -> Result<TrustTask<Value>, OpenVTCError> {
    document(
        pcs::CHALLENGE_TYPE,
        applicant_did,
        community_did,
        new_id(),
        &pcs::ChallengeRequest {
            criterion_id: criterion_id.map(ToString::to_string),
        },
    )
}

/// A `vtc/vetting/vetters/resend/0.1` request asking `community_did` to
/// deliver our live vetter grant credential again.
pub fn vetter_resend_request(
    vetter_did: &str,
    community_did: &str,
) -> Result<TrustTask<Value>, OpenVTCError> {
    document(
        vta_sdk::protocols::vetting::VETTING_VETTER_RESEND_TYPE,
        vetter_did,
        community_did,
        new_id(),
        &vta_sdk::protocols::vetting::vetters::resend::v0_1::Payload::default(),
    )
}

/// Sign `document` with `persona`'s key and send it over DIDComm to its
/// recipient. Returns the document id — what a reply threads on.
///
/// `Ok` means handed to the transport, not delivered (R1.1): every step that
/// waits on the other party is driven by their reply, never by this.
pub async fn sign_and_send(
    config: &crate::config::Config,
    tdk: &affinidi_tdk::TDK,
    service: &crate::didcomm::Messaging,
    persona: crate::config::account::PersonaId,
    document: TrustTask<Value>,
) -> Result<String, OpenVTCError> {
    send_reply(
        config,
        tdk,
        service,
        super::inbound::Reply {
            persona,
            document,
            eligibility: None,
        },
    )
    .await
}

/// Present the role credentials `eligibility` names as the acceptance's
/// `eligibilityVp`, signed by `holder` for `authentication`. Done before the
/// document itself is signed, so its proof covers the presentation.
///
/// # Errors
///
/// A payload that is not an object, or a presentation that cannot be signed.
pub async fn attach_eligibility(
    document: &mut TrustTask<Value>,
    holder: &Secret,
    eligibility: super::inbound::EligibilityPresentation,
) -> Result<(), OpenVTCError> {
    let vp = vta_sdk::vetting::eligibility::build_eligibility_vp(
        holder,
        eligibility.credentials,
        &eligibility.nonce,
        &eligibility.domain,
    )
    .await
    .map_err(|e| config_error("eligibility presentation", e))?;
    document
        .payload
        .as_object_mut()
        .ok_or_else(|| OpenVTCError::Config("vetting reply payload is not an object".into()))?
        .insert("eligibilityVp".into(), vp);
    Ok(())
}

/// Sign a reply from [`super::inbound::handle`] as its persona — presenting
/// the role credential it asks for with the persona's authentication key —
/// and send it over DIDComm. Returns the document id.
///
/// `Ok` means handed to the transport, not delivered (R1.1).
pub async fn send_reply(
    config: &crate::config::Config,
    tdk: &affinidi_tdk::TDK,
    service: &crate::didcomm::Messaging,
    reply: super::inbound::Reply,
) -> Result<String, OpenVTCError> {
    let keys = config.get_persona_keys_for(reply.persona, tdk).await?;
    let mut document = reply.document;
    if let Some(eligibility) = reply.eligibility {
        attach_eligibility(&mut document, &keys.authentication.secret, eligibility).await?;
    }
    sign(&mut document, &keys.signing.secret).await?;
    let message = to_message(&document)?;
    let (from, to) = (
        document.issuer.as_deref().unwrap_or_default(),
        document.recipient.as_deref().unwrap_or_default(),
    );
    crate::didcomm::send_message(service, config, &message, from, to)
        .await
        .map_err(|e| config_error("send vetting document", e))?;
    Ok(document.id)
}

/// Deliver a signed statement to the applicant.
pub async fn send_statement(
    config: &crate::config::Config,
    service: &crate::didcomm::Messaging,
    vetter_did: &str,
    applicant_did: &str,
    statement: &Value,
    session_id: &str,
) -> Result<(), OpenVTCError> {
    let message = credential_delivery(vetter_did, applicant_did, statement, session_id)?;
    crate::didcomm::send_message(service, config, &message, vetter_did, applicant_did)
        .await
        .map_err(|e| config_error("send vetting statement", e))
}

/// The statement a `credential-exchange/issue` message carries, if it is an
/// identity-vetting statement rather than a community-issued credential.
#[must_use]
pub fn delivered_statement(body: &Value) -> Option<&Value> {
    let credential = body.pointer("/credential_response/credential")?;
    (credential
        .pointer("/credentialSubject/endorsement/type")
        .and_then(Value::as_str)
        == Some(vta_sdk::protocols::vetting::IDENTITY_VETTING_ENDORSEMENT_TYPE))
    .then_some(credential)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use vta_sdk::protocols::vetting::{
        VETTING_DECLINE_TYPE, VETTING_REQUEST_ERR_CAPACITY, VETTING_REQUEST_TYPE, decline, session,
    };

    /// A `did:key` Ed25519 secret from a fixed seed, `id` = `<did>#<multibase>`.
    pub(crate) fn secret(seed_byte: u8) -> Secret {
        let mut secret = Secret::generate_ed25519(None, Some(&[seed_byte; 32]));
        let public = secret.get_public_keymultibase().unwrap();
        secret.id = format!("did:key:{public}#{public}");
        secret
    }

    pub(crate) fn did(secret: &Secret) -> String {
        secret.id.split('#').next().unwrap().to_string()
    }

    /// A persona's assertionMethod key as `Config::regenerate_persona_keys`
    /// loads it: the secret id is the did:webvh verification method.
    fn webvh_persona_secret() -> Secret {
        let mut secret = Secret::generate_ed25519(None, Some(&[7u8; 32]));
        secret.id = "did:webvh:QmScid:example.com:alice#key-0".to_string();
        secret
    }

    /// Vetting documents and cards are signed locally as the persona DID — the
    /// same path reciprocal VMCs and capabilities take — so the proof names
    /// the persona's own verification method, not a VTA key or a did:key.
    #[tokio::test]
    async fn a_persona_signs_as_its_webvh_verification_method() {
        let signer = webvh_persona_secret();
        let persona = "did:webvh:QmScid:example.com:alice";
        let mut doc = document(
            VETTING_DECLINE_TYPE,
            persona,
            "did:webvh:QmScid:example.com:bob",
            new_id(),
            &decline(),
        )
        .unwrap();
        sign(&mut doc, &signer).await.unwrap();
        let signed = serde_json::to_value(&doc).unwrap();
        assert_eq!(
            signed.pointer("/proof/verificationMethod"),
            Some(&json!("did:webvh:QmScid:example.com:alice#key-0"))
        );

        let draft = vta_sdk::vetting::card::CardDraft {
            id: new_id(),
            publisher: persona.to_string(),
            audience: "did:webvh:QmScid:example.com:bob".to_string(),
            community: "did:webvh:QmScid:example.com:vtc".to_string(),
            challenge: "c".repeat(43),
            domain: "did:webvh:QmScid:example.com:vtc".to_string(),
            issued_at: chrono::Utc::now(),
            validity: chrono::Duration::minutes(10),
            claims: vec![
                session::v0_1::VettingCardClaim::try_from(
                    session::v0_1::VettingCardClaim::builder()
                        .type_("name.legal")
                        .value(json!("Alice Example"))
                        .provenance("selfAsserted"),
                )
                .unwrap(),
            ],
            identity_types: vec!["name.legal".into()],
            salt: vta_sdk::vetting::card::new_commitment_salt().unwrap(),
        };
        let card = vta_sdk::vetting::card::sign_card(draft, &signer)
            .await
            .unwrap();
        assert_eq!(
            card.pointer("/proof/verificationMethod"),
            Some(&json!("did:webvh:QmScid:example.com:alice#key-0"))
        );
    }

    fn decline() -> decline::v0_1::Payload {
        decline::v0_1::Payload::try_from(decline::v0_1::Payload::builder().request_id("r1"))
            .unwrap()
    }

    #[tokio::test]
    async fn a_signed_document_opens_for_its_sender_only() {
        let (vetter, applicant, other) = (secret(1), secret(2), secret(3));
        let mut doc = document(
            VETTING_DECLINE_TYPE,
            &did(&vetter),
            &did(&applicant),
            new_id(),
            &decline(),
        )
        .unwrap();
        sign(&mut doc, &vetter).await.unwrap();
        let message = to_message(&doc).unwrap();
        assert_eq!(message.id, doc.id);

        let resolver = TrustTaskVmResolver::did_key_only();
        let opened: Opened<decline::v0_1::Payload> =
            open(&message, &did(&vetter), &resolver).await.unwrap();
        assert_eq!(opened.payload.request_id.as_str(), "r1");

        assert!(matches!(
            open::<decline::v0_1::Payload>(&message, &did(&other), &resolver).await,
            Err(WireError::IssuerNotSender)
        ));
    }

    #[tokio::test]
    async fn an_unsigned_document_does_not_open() {
        let (vetter, applicant) = (secret(1), secret(2));
        let doc = document(
            VETTING_DECLINE_TYPE,
            &did(&vetter),
            &did(&applicant),
            new_id(),
            &decline(),
        )
        .unwrap();
        let message = to_message(&doc).unwrap();
        assert!(matches!(
            open::<decline::v0_1::Payload>(
                &message,
                &did(&vetter),
                &TrustTaskVmResolver::did_key_only()
            )
            .await,
            Err(WireError::Proof(_))
        ));
    }

    #[test]
    fn responses_and_refusals_thread_on_the_request() {
        let request = document(
            VETTING_REQUEST_TYPE,
            "did:key:zApplicant",
            "did:key:zVetter",
            new_id(),
            &json!({}),
        )
        .unwrap();
        let reply = response(&request, &json!({ "requestId": "r1" })).unwrap();
        assert_eq!(reply.thread_id.as_deref(), Some(request.id.as_str()));
        assert_eq!(reply.issuer.as_deref(), Some("did:key:zVetter"));
        assert!(reply.type_uri.to_string().ends_with("#response"));

        let refused = refusal(&request, VETTING_REQUEST_ERR_CAPACITY, None).unwrap();
        assert_eq!(refused.thread_id.as_deref(), Some(request.id.as_str()));
        assert_eq!(refused.payload["code"], VETTING_REQUEST_ERR_CAPACITY);
        assert!(
            crate::messaging::is_trust_task_error_type(&refused.type_uri.to_string()),
            "the inbound router must recognise it"
        );
    }

    #[test]
    fn only_identity_vetting_statements_are_picked_out_of_an_issue() {
        let statement = json!({
            "credentialSubject": { "endorsement": {
                "type": vta_sdk::protocols::vetting::IDENTITY_VETTING_ENDORSEMENT_TYPE
            } }
        });
        let body = json!({ "credential_response": { "credential": statement } });
        assert!(delivered_statement(&body).is_some());
        let vmc = json!({ "credential_response": { "credential": {
            "type": ["VerifiableCredential", "MembershipCredential"]
        } } });
        assert!(delivered_statement(&vmc).is_none());
    }
}
