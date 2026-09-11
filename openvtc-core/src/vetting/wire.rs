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
use chrono::Utc;
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
    let type_uri = type_uri
        .parse()
        .map_err(|e| config_error("vetting type URI", e))?;
    let payload = serde_json::to_value(payload).map_err(|e| config_error("vetting payload", e))?;
    let mut doc = TrustTask::new(id, type_uri, payload);
    doc.issuer = Some(issuer.to_string());
    doc.recipient = Some(recipient.to_string());
    doc.issued_at = Some(Utc::now());
    Ok(doc)
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
    mut document: TrustTask<Value>,
) -> Result<String, OpenVTCError> {
    let keys = config.get_persona_keys_for(persona, tdk).await?;
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
        VETTING_DECLINE_TYPE, VETTING_REQUEST_ERR_CAPACITY, VETTING_REQUEST_TYPE,
        VettingDeclineBody,
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

    fn decline() -> VettingDeclineBody {
        VettingDeclineBody {
            request_id: "r1".into(),
            code: None,
            message: None,
            ext: None,
        }
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
        let opened: Opened<VettingDeclineBody> =
            open(&message, &did(&vetter), &resolver).await.unwrap();
        assert_eq!(opened.payload.request_id, "r1");

        assert!(matches!(
            open::<VettingDeclineBody>(&message, &did(&other), &resolver).await,
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
            open::<VettingDeclineBody>(
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
