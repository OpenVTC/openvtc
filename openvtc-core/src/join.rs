/*!
 * VTC join-ceremony client helpers.
 *
 * Sends the applicant side of the join ceremony to a VTC over DIDComm or,
 * when the community advertises `#tsp`, over TSP (#185 item 2f).
 *
 * The payload is the same either way: a Trust Task **document**, which is
 * what the VTC's `dispatch_trust_task_core` reads on every transport.
 * DIDComm wraps that document in an authcrypt envelope; TSP carries it bare
 * and seals it in the routing layer. So the transport choice changes the
 * wire, not the ceremony.
 *
 * Either way the sender is cryptographically proven — the authcrypt sender
 * over DIDComm, the sender VID over TSP — so no separate holder-binding
 * signature is needed. **REST remains unusable** for a `did:webvh` persona
 * regardless: the VTC's REST holder-binding verification accepts `did:key`
 * applicants only.
 */

use std::sync::Arc;

use affinidi_tdk::secrets_resolver::secrets::Secret;
use affinidi_tdk::{
    didcomm::Message,
    messaging::{ATM, profiles::ATMProfile},
};
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;
use vta_sdk::protocols::join_requests::{
    JOIN_REQUEST_STATUS_TYPE, JOIN_REQUEST_SUBMIT_TYPE, JoinRequestStatusBody,
    JoinRequestSubmitBody, MEMBER_SELF_REMOVE_TYPE, SelfRemoveBody,
};

use crate::capabilities::TRUST_TASK_ENVELOPE_TYPE;
use crate::errors::OpenVTCError;

/// Ceiling on a join submit's serialized body, guarded before it goes out.
///
/// Mirrors the inbound `MAX_MESSAGE_BODY_SIZE` (1 MiB): a submit larger than the
/// size we ourselves refuse to *receive* will not be handled by a conformant
/// peer either. A mediator/bridge forward limit silently dropped an oversized
/// submit once — the join sat `Pending` with no error anywhere (PR #137). Guard
/// it at the source so an oversized submit fails loudly and actionably instead
/// of vanishing.
pub const MAX_JOIN_SUBMIT_BYTES: usize = 1_048_576;

/// The `vtc/community/profile/show` request type, sourced from the spec crate so
/// it cannot drift from the schema OpenVTC is built against (issue #241).
pub const COMMUNITY_PROFILE_SHOW_TYPE: &str = <trust_tasks_rs::specs::vtc::community::profile::show::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// The correlated `#response` type the VTC replies with, carrying the
/// `CommunityProfileView` (and its `relationshipIdentifierDefault`).
pub const COMMUNITY_PROFILE_SHOW_RESPONSE_TYPE: &str = <trust_tasks_rs::specs::vtc::community::profile::show::v0_1::Response as trust_tasks_rs::Payload>::TYPE_URI;

/// Who is speaking to which community, and over what.
///
/// Grouped rather than passed loose, matching [`crate::personhood::Route`] and
/// [`crate::members::Delivery`]: the applicant verbs take the same six values,
/// and a sixth positional `&str` is how one call ends up with two of them
/// swapped.
pub struct Applicant<'a> {
    pub atm: &'a ATM,
    pub profile: &'a Arc<ATMProfile>,
    /// The persona applying — the authcrypt sender / TSP sender VID, and the
    /// `issuer` of every document sent through this route.
    pub persona_did: &'a str,
    /// The persona's signing key. Every task here declares `proof` REQUIRED,
    /// so the route carries the key rather than each verb asking for it.
    pub signer: &'a Secret,
    /// The community being addressed.
    pub vtc_did: &'a str,
    /// The persona's own mediator, for the DIDComm leg.
    pub mediator_did: &'a str,
    /// The community's advertised TSP mediator, when it advertises `#tsp`.
    /// `Some` sends the bare document over TSP; `None` wraps it in DIDComm.
    pub tsp_mediator_did: Option<&'a str>,
}

/// Submit a join request to a VTC (`vtc_did`) over DIDComm, presenting
/// `persona_did` as the applicant.
///
/// `presentation` is the holder presentation the VTC's `join.rego` decides
/// over, with any submission `extensions` (a plain `Value` VP converts, with
/// none).
/// The message is packed authcrypt and forwarded via the persona's
/// `mediator_did`; the VTC authenticates the applicant from the
/// envelope's `from`.
///
/// Returns the correlation handle the VTC's reply threads on. **The same value
/// on either transport**, which is what lets one handle correlate a reply that
/// may arrive over either.
///
/// That takes a deliberate step, because the two transports thread differently:
/// DIDComm threads the reply on the request *message* id (`vtc-service` sets
/// `thid = msg.id`), while TSP has no message and threads on the request
/// *document* id (`threadId`). Those are two different UUIDs unless something
/// makes them one — so the DIDComm message is built with `id` equal to the Trust
/// Task document's id. `Uuid::parse_str` accepts the `urn:uuid:` form, so the
/// existing correlation code reads either unchanged.
///
/// `tsp_mediator_did` selects the wire: `Some` sends the bare Trust Task
/// document over TSP through that (the VTC's **advertised**) mediator; `None`
/// wraps it in DIDComm as before. Discovery belongs to the caller so that a VTC
/// which does not advertise `#tsp` simply degrades to DIDComm rather than
/// failing.
pub async fn submit_join_request(
    route: &Applicant<'_>,
    presentation: impl Into<JoinPresentation>,
) -> Result<Uuid, OpenVTCError> {
    let Applicant {
        atm,
        profile,
        persona_did,
        signer,
        vtc_did,
        mediator_did,
        tsp_mediator_did,
    } = *route;
    // One id, used as both the document id and — on the DIDComm path — the
    // message id, so the two transports' threading conventions coincide.
    let request_id = Uuid::new_v4();
    let document_id = format!("urn:uuid:{request_id}");
    let body = build_join_submit_document(persona_did, signer, vtc_did, presentation, &document_id)
        .await?;

    // Fail loudly on an oversized submit rather than letting a mediator/bridge
    // drop it silently into a stuck `Pending` (PR #137). This is the largest
    // thing OpenVTC sends — it carries the presentation and any invitation
    // credential — so it is the one worth guarding.
    if let Some(body_size) = oversized_join_submit(&body) {
        return Err(OpenVTCError::InvalidMessage(format!(
            "join request is too large to send reliably ({body_size} bytes; limit \
             {MAX_JOIN_SUBMIT_BYTES}). A large presentation or invitation credential is the \
             usual cause — remove or shrink it and try again."
        )));
    }

    match tsp_mediator_did {
        // TSP carries the Trust Task document as-is: no DIDComm envelope, and
        // the VTC's dispatcher reads `type`/`threadId` out of the document.
        Some(tsp_mediator) => {
            crate::tsp::send_trust_task(atm, profile, &body, vtc_did, tsp_mediator).await?;
        }
        None => {
            let now = Utc::now().timestamp().max(0) as u64;
            let msg = Message::build(document_id, TRUST_TASK_ENVELOPE_TYPE.to_string(), body)
                .from(persona_did.to_string())
                .to(vtc_did.to_string())
                .created_time(now)
                .finalize();

            crate::pack_and_send(atm, profile, &msg, persona_did, vtc_did, mediator_did).await?;
        }
    }

    Ok(request_id)
}

/// The serialized size of a join submit `body` when it exceeds
/// [`MAX_JOIN_SUBMIT_BYTES`], else `None`. Split out so the guard in
/// [`submit_join_request`] is testable without a live transport.
fn oversized_join_submit(body: &Value) -> Option<usize> {
    let size = serde_json::to_string(body).map(|s| s.len()).unwrap_or(0);
    (size > MAX_JOIN_SUBMIT_BYTES).then_some(size)
}

/// Ask a VTC what became of a join request we already have its id for
/// (`join-requests/status/0.1`).
///
/// The applicant is proven the same way `submit` proves it — the authcrypt
/// sender over DIDComm, the sender VID over TSP — so no holder-binding
/// signature rides along (the VTC's `status_inner` takes `signature_hex = None`
/// on this path). The reply is a `#response` document threaded on this
/// message, handled asynchronously by
/// [`crate::messaging::handle_join_status_response`]; nothing is awaited here.
///
/// `request_id` is the community's own id when we hold it. Pass `None` when we
/// do not: that asks "what is my open request?", which the community answers
/// from the authenticated applicant, and the reply carries the id.
///
/// Never pass our submit-time placeholder — the VTC has never heard of it and
/// answers "not found". An unconfirmed record has nothing worth quoting, so it
/// asks id-less instead; see [`CommunityRecord::request_id_confirmed`].
///
/// [`CommunityRecord::request_id_confirmed`]: crate::config::account::CommunityRecord::request_id_confirmed
pub async fn poll_join_status(
    route: &Applicant<'_>,
    request_id: Option<Uuid>,
) -> Result<(), OpenVTCError> {
    let Applicant {
        atm,
        profile,
        persona_did,
        signer,
        vtc_did,
        mediator_did,
        tsp_mediator_did,
    } = *route;
    let document_id = format!("urn:uuid:{}", Uuid::new_v4());
    let payload = JoinRequestStatusBody { request_id };
    let body = crate::trust_task_doc::build_signed_value(
        JOIN_REQUEST_STATUS_TYPE,
        persona_did,
        vtc_did,
        &document_id,
        payload,
        signer,
    )
    .await?;

    match tsp_mediator_did {
        Some(tsp_mediator) => {
            crate::tsp::send_trust_task(atm, profile, &body, vtc_did, tsp_mediator).await?;
        }
        None => {
            let now = Utc::now().timestamp().max(0) as u64;
            let msg = Message::build(document_id, TRUST_TASK_ENVELOPE_TYPE.to_string(), body)
                .from(persona_did.to_string())
                .to(vtc_did.to_string())
                .created_time(now)
                .finalize();
            crate::pack_and_send(atm, profile, &msg, persona_did, vtc_did, mediator_did).await?;
        }
    }
    Ok(())
}

/// Profile questions we have outstanding: document id → (community, when).
/// In memory: a question is this process's, and its answer after a restart is
/// simply not taken (the next launch asks again).
static PROFILE_QUERIES: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, (String, std::time::Instant)>>,
> = std::sync::LazyLock::new(Default::default);

/// How long a profile question waits for its answer.
const PROFILE_QUERY_TTL: std::time::Duration = std::time::Duration::from_secs(600);
/// Most profile questions outstanding at once.
const MAX_PROFILE_QUERIES: usize = 256;

fn remember_profile_query(document_id: &str, vtc_did: &str) {
    if let Ok(mut q) = PROFILE_QUERIES.lock() {
        q.retain(|_, (_, at)| at.elapsed() < PROFILE_QUERY_TTL);
        if q.len() < MAX_PROFILE_QUERIES {
            q.insert(
                document_id.to_string(),
                (vtc_did.to_string(), std::time::Instant::now()),
            );
        }
    }
}

/// Whether `thid` answers a profile question we put to `vtc_did` (and is not
/// yet answered). Consumes it: a question is answered once.
#[must_use]
pub fn take_profile_query(vtc_did: &str, thid: &str) -> bool {
    let Ok(mut q) = PROFILE_QUERIES.lock() else {
        return false;
    };
    match q.get(thid) {
        Some((vtc, at)) if vtc == vtc_did && at.elapsed() < PROFILE_QUERY_TTL => {
            q.remove(thid);
            true
        }
        _ => false,
    }
}

/// Ask a community for its profile (`vtc/community/profile/show/0.1`) so we can
/// read its declared `relationshipIdentifierDefault` (issue #241).
///
/// The request payload is empty — the community answers about itself, and the
/// applicant is proven exactly as `poll_join_status` proves it (authcrypt sender
/// over DIDComm, sender VID over TSP; no holder signature). The reply is a
/// `#response` document threaded on this message, handled asynchronously by
/// [`crate::messaging::handle_community_profile_show_response`]; nothing is
/// awaited here. Background, best-effort — a send failure is the caller's to log,
/// not surface (the value only seeds a form default, and its absence is a valid,
/// pairwise-defaulting state).
pub async fn send_community_profile_show(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    persona_did: &str,
    signer: &Secret,
    vtc_did: &str,
    mediator_did: &str,
    tsp_mediator_did: Option<&str>,
) -> Result<(), OpenVTCError> {
    let document_id = format!("urn:uuid:{}", Uuid::new_v4());
    // Remembered before the send, so an answer racing it is still recognised.
    remember_profile_query(&document_id, vtc_did);
    // The show payload carries only an optional extension bag; an empty object is
    // the request. The VTC reads the body as a Trust Task document, so it must be
    // wrapped (a bare payload is rejected `malformedRequest`).
    // Signed like every request: a community requires a proof bound to the
    // sender on every Trust Task it is sent.
    let body = crate::trust_task_doc::build_signed_value(
        COMMUNITY_PROFILE_SHOW_TYPE,
        persona_did,
        vtc_did,
        &document_id,
        serde_json::json!({}),
        signer,
    )
    .await?;

    match tsp_mediator_did {
        Some(tsp_mediator) => {
            crate::tsp::send_trust_task(atm, profile, &body, vtc_did, tsp_mediator).await?;
        }
        None => {
            let now = Utc::now().timestamp().max(0) as u64;
            let msg = Message::build(document_id, TRUST_TASK_ENVELOPE_TYPE.to_string(), body)
                .from(persona_did.to_string())
                .to(vtc_did.to_string())
                .created_time(now)
                .finalize();
            crate::pack_and_send(atm, profile, &msg, persona_did, vtc_did, mediator_did).await?;
        }
    }
    Ok(())
}

/// Build the DIDComm body for a join-request submit: a Trust Task *document*
/// (`trust_tasks_rs::TrustTask`) wrapping the [`JoinRequestSubmitBody`] payload.
///
/// The VTC deserializes the message body as `TrustTask<Value>` and rejects a
/// `malformedRequest` ("missing field `id`") when handed the bare payload, so the
/// payload must ride as the document's `payload` field. The document carries the
/// required `id` (a fresh `urn:uuid`) and `type`, plus the audience-binding
/// `issuer` (the applicant persona) and `recipient` (the VTC), and it is
/// **signed** by the persona: `vtc/join-requests/submit/0.2` declares `proof`
/// REQUIRED, and the authcrypt sender or TSP sender VID attributes the carriage
/// rather than the document.
async fn build_join_submit_document(
    persona_did: &str,
    signer: &Secret,
    vtc_did: &str,
    presentation: impl Into<JoinPresentation>,
    document_id: &str,
) -> Result<Value, OpenVTCError> {
    let JoinPresentation {
        vp,
        extensions,
        attributes,
    } = presentation.into();
    let payload = JoinRequestSubmitBody {
        vp,
        registry_consent: false,
        extensions,
        attributes,
    };
    // `document_id` is supplied rather than minted here: on the DIDComm path this
    // same id is the message id, which is what makes the two transports' reply
    // threading agree (see [`submit_join_request`]).
    crate::trust_task_doc::build_signed_value(
        JOIN_REQUEST_SUBMIT_TYPE,
        persona_did,
        vtc_did,
        document_id,
        payload,
        signer,
    )
    .await
}

/// Send a member self-removal (`MEMBER_SELF_REMOVE`) to a VTC over DIDComm to
/// leave the community (R-L-1). `member_did` is the persona presented to the
/// community (the authcrypt sender authenticates it). `disposition` optionally
/// requests how the VTC should treat the departing member's record (purge /
/// tombstone / historical); `None` lets the VTC apply its default.
///
/// Returns the DIDComm message id — the thread root the VTC's
/// `members/self-remove-receipt/1.0` reply references. The local membership is
/// set to `Left` on send success; the receipt is advisory (logged if it
/// arrives), so callers don't block on it.
pub async fn submit_self_remove(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    member_did: &str,
    signer: &Secret,
    vtc_did: &str,
    mediator_did: &str,
    disposition: Option<String>,
) -> Result<Uuid, OpenVTCError> {
    // A **document**, not a bare payload. The bare form reached a VTC handler
    // that bypasses its dispatch spine, so the reply was never signed and a
    // refusal was never a framework error document. Nothing here reads that
    // reply — self-remove is fire-and-forget — but "the answer is
    // unattributable" is not a property to leave in place on purpose.
    let msg_id = Uuid::new_v4();
    let document_id = format!("urn:uuid:{msg_id}");
    let body = crate::trust_task_doc::build_signed_value(
        MEMBER_SELF_REMOVE_TYPE,
        member_did,
        vtc_did,
        &document_id,
        SelfRemoveBody { disposition },
        signer,
    )
    .await?;

    let now = Utc::now().timestamp().max(0) as u64;
    let msg = Message::build(document_id, TRUST_TASK_ENVELOPE_TYPE.to_string(), body)
        .from(member_did.to_string())
        .to(vtc_did.to_string())
        .created_time(now)
        .finalize();

    crate::pack_and_send(atm, profile, &msg, member_did, vtc_did, mediator_did).await?;
    Ok(msg_id)
}

/// Build the holder presentation (VP) for a join request.
///
/// The VTC's raw-VP submit path performs no VP-level proof check — the DIDComm
/// authcrypt sender authenticates the applicant — so the VP is a plain JSON
/// object naming the `holder`. When the applicant holds a Verifiable Invitation
/// Credential (VIC), it is embedded in the `verifiableCredential` array; the
/// VTC extracts it, verifies its issuer signature + holder-binding, and (per the
/// default `join.rego`) auto-admits on a valid, trusted, unconsumed invitation.
///
/// `invitation` is the signed VIC as received out-of-band (a Data-Integrity VC,
/// object form with its own `proof`). When `None`, the VP carries no
/// credentials and the join falls to the community's other evidence / review.
///
/// The envelope carries the W3C VC Data Model 2.0 base `@context` (required: the
/// first value MUST be `https://www.w3.org/ns/credentials/v2`) and the
/// `VerifiablePresentation` `type`, so the artifact is a well-formed VP. It is
/// *unsecured* by a VP-level proof on purpose — over DIDComm the authcrypt sender
/// is the holder authentication — so it is a "presentation" the transport makes
/// verifiable, not a self-secured one.
pub fn build_join_vp(
    holder_did: &str,
    invitation: Option<&Value>,
    linkage: Option<&SubjectLinkage>,
) -> Value {
    let mut vp = serde_json::json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": "VerifiablePresentation",
        "holder": holder_did,
    });
    if let Some(vic) = invitation {
        vp["verifiableCredential"] = Value::Array(vec![vic.clone()]);
    }
    // Subject-linkage proof (#1b): present a VIC bound to a *different* DID by
    // proving that DID authorized this holder. Omitted on the join-as-subject
    // path (holder == VIC subject).
    if let Some(l) = linkage {
        vp["subjectLinkage"] = serde_json::json!({
            "verificationMethod": l.verification_method,
            "signature": l.signature_hex,
        });
    }
    vp
}

/// What a join request presents: the VP, and the submission's `extensions`.
///
/// `extensions` is where an applicant names the `requirementsDigest` its
/// vetting statements were gathered against, so the community evaluates them
/// under the same criterion ([`crate::vetting::applicant::Application::join_extensions`]).
#[derive(Debug, Clone, PartialEq)]
pub struct JoinPresentation {
    /// The holder presentation.
    pub vp: Value,
    /// Submission extensions; `Null` for none.
    pub extensions: Value,
    /// Answers to the community's `requestedAttributes`, released through a
    /// disclosure ([`crate::persona::join_answers`]). Empty when it asks
    /// nothing.
    pub attributes: Vec<vta_sdk::protocols::join_requests::JoinRequestAttribute>,
}

impl From<Value> for JoinPresentation {
    fn from(vp: Value) -> Self {
        Self {
            vp,
            extensions: Value::Null,
            attributes: Vec::new(),
        }
    }
}

/// Add `credentials` to a VP's `verifiableCredential`, after anything already
/// there. Used for the vetting statements an application gathered.
pub fn attach_credentials(vp: &mut Value, credentials: impl IntoIterator<Item = Value>) {
    let mut credentials = credentials.into_iter().peekable();
    if credentials.peek().is_none() {
        return;
    }
    let list = vp
        .as_object_mut()
        .expect("a VP is an object")
        .entry("verifiableCredential")
        .or_insert_with(|| Value::Array(Vec::new()));
    if let Value::Array(list) = list {
        list.extend(credentials);
    }
}

/// Domain tag the VIC subject signs over for a subject-linkage proof. **Must
/// match `vtc-service`'s `SUBJECT_LINKAGE_DOMAIN_TAG`** byte-for-byte.
pub const SUBJECT_LINKAGE_DOMAIN_TAG: &[u8] = b"vtc-invitation-subject-linkage/v1\0";

/// A subject-linkage proof: the VIC subject's key signed
/// [`subject_linkage_signing_bytes`], authorizing a different presenter to
/// redeem the invitation.
#[derive(Debug, Clone)]
pub struct SubjectLinkage {
    /// The VIC subject's verification method (`<subjectDid>#<key>`).
    pub verification_method: String,
    /// Hex-encoded Ed25519 signature over [`subject_linkage_signing_bytes`].
    pub signature_hex: String,
}

/// The exact bytes a subject-linkage proof signs:
/// `SUBJECT_LINKAGE_DOMAIN_TAG || vic_id || NUL || presenter_did`. The VTC
/// rebuilds these identically when verifying, so both sides must agree.
pub fn subject_linkage_signing_bytes(vic_id: &str, presenter_did: &str) -> Vec<u8> {
    let mut bytes = SUBJECT_LINKAGE_DOMAIN_TAG.to_vec();
    bytes.extend_from_slice(vic_id.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(presenter_did.as_bytes());
    bytes
}

/// Produce a subject-linkage proof: sign [`subject_linkage_signing_bytes`] with
/// the VIC subject's Ed25519 private key (`private_seed`, 32 raw bytes — e.g.
/// `Secret::get_private_bytes`), authorizing `presenter_did` to redeem the
/// invitation `vic_id`. `verification_method` is the subject's assertionMethod
/// VM id the VTC resolves to verify the signature.
///
/// Signs via the TDK's Ed25519 routine
/// ([`affinidi_tdk::affinidi_crypto::jose::signing::sign`]) — the same
/// primitive the workspace uses elsewhere — not a hand-rolled signer.
pub fn sign_subject_linkage(
    private_seed: &[u8; 32],
    verification_method: impl Into<String>,
    vic_id: &str,
    presenter_did: &str,
) -> Result<SubjectLinkage, OpenVTCError> {
    let bytes = subject_linkage_signing_bytes(vic_id, presenter_did);
    let signature = affinidi_tdk::affinidi_crypto::jose::signing::sign(&bytes, private_seed)
        .map_err(|e| OpenVTCError::Config(format!("subject-linkage signing failed: {e}")))?;
    Ok(SubjectLinkage {
        verification_method: verification_method.into(),
        signature_hex: hex::encode(signature),
    })
}

/// The DID a VIC is bound to (`credentialSubject.id`).
pub fn invitation_subject(vic: &Value) -> Option<&str> {
    vic.pointer("/credentialSubject/id").and_then(Value::as_str)
}

/// A VIC's top-level `id` (its consumption / linkage handle).
pub fn invitation_id(vic: &Value) -> Option<&str> {
    vic.get("id").and_then(Value::as_str)
}

/// A VIC's validity-window start (`validFrom`), RFC 3339, if declared. Shown as
/// the "Issued" detail when the operator chooses an invitation to present.
pub fn invitation_valid_from(vic: &Value) -> Option<&str> {
    vic.get("validFrom").and_then(Value::as_str)
}

/// A VIC's validity-window end (`validUntil`), RFC 3339, if declared. Shown as
/// the "Expires" detail.
pub fn invitation_valid_until(vic: &Value) -> Option<&str> {
    vic.get("validUntil").and_then(Value::as_str)
}

/// The DID that issued a VIC. For an `InvitationCredential` the issuer **is** the
/// community's VTC DID (the VTC signs it with its own issuer key, so
/// `issuer = signer.issuer_did()`), which is what a presentable invitation must
/// match against the community being joined. Accepts both the string issuer form
/// and the object form (`{ "id": "did:…" }`).
pub fn invitation_issuer(vic: &Value) -> Option<&str> {
    match vic.get("issuer")? {
        Value::String(s) => Some(s.as_str()),
        Value::Object(_) => vic.pointer("/issuer/id").and_then(Value::as_str),
        _ => None,
    }
}

/// Whether a VIC is bound to the community identified by `vtc_did` — i.e. the VIC
/// was issued by that VTC. A held/loaded VIC issued by a *different* community
/// must not be presented: the VTC would reject the mismatched binding, so it is
/// no better than presenting nothing (and worse, it looks like a failed
/// invitation rather than an open request).
pub fn invitation_matches_community(vic: &Value, vtc_did: &str) -> bool {
    invitation_issuer(vic) == Some(vtc_did)
}

/// Whether a VIC's declared validity window has elapsed as of `now`. A VIC with
/// no `validUntil` is treated as non-expiring here (the VTC re-checks validity at
/// submit). A malformed `validUntil` is treated as expired (fail closed) so a
/// broken credential is never presented.
pub fn invitation_is_expired(vic: &Value, now: DateTime<Utc>) -> bool {
    match vic.get("validUntil").and_then(Value::as_str) {
        None => false,
        Some(s) => match DateTime::parse_from_rfc3339(s) {
            Ok(t) => t.with_timezone(&Utc) <= now,
            Err(_) => true,
        },
    }
}

/// The two `@context` entries DTG Credentials §Common Structure requires of
/// every DTG credential, and the base `type` every one of them carries.
///
/// `dtg-credentials` builds all three into the credentials it mints but does
/// not export them, so they are named here rather than spelled out inline.
/// Removing this duplication needs a public constant upstream —
/// OpenVTC/dtg-credentials#10.
pub const W3C_VC_V2_CONTEXT: &str = "https://www.w3.org/ns/credentials/v2";
pub const DTG_CONTEXT: &str = "https://firstperson.network/credentials/dtg/v1";
pub const DTG_BASE_TYPE: &str = "DTGCredential";

/// Whether a JSON value is an InvitationCredential (its `type` array carries
/// the `InvitationCredential` tag). Used to validate a pasted/loaded VIC
/// before stashing it (join flow) or storing it in the vault (VIC manager).
pub fn is_invitation_credential(value: &Value) -> bool {
    value
        .get("type")
        .and_then(|t| t.as_array())
        .is_some_and(|types| {
            types
                .iter()
                .any(|t| t.as_str() == Some("InvitationCredential"))
        })
}

/// Validate that `vic` is a **complete, presentable** Invitation Credential, not
/// a summary/display projection. Returns a human-readable error naming every
/// missing/malformed field so a holder who pasted the wrong artifact (e.g. the
/// operator-UI summary instead of the signed credential the VTC issued for
/// out-of-band delivery) finds out *at ingest*, rather than silently submitting
/// an open request the VTC refers to a moderator.
///
/// The required set is the intersection of:
/// - **W3C VC Data Model 2.0** mandatory properties: `@context` (ordered set
///   whose first value is `https://www.w3.org/ns/credentials/v2`), `type`
///   (here ⊇ `VerifiableCredential` + `InvitationCredential`), `issuer`,
///   `credentialSubject` (with an `id`), and a securing `proof`.
/// - the **VIC profile** the receiving VTC enforces: a top-level `id` (the
///   single-use consumption handle — W3C makes `id` optional, the VIC profile
///   does not), `validUntil` (the invite's expiry), and `credentialStatus`
///   (issuance burns a revocation slot, so a VIC always carries one).
///
/// This is a **shape** check only: `proof` / `credentialStatus` are required
/// to be present, not verified. Anything that uses an invitation — stores it,
/// shows it as usable, reads its issuer — calls
/// [`verify_invitation_credential`], which does verify them.
pub fn validate_invitation_credential(vic: &Value) -> Result<(), String> {
    let mut missing: Vec<&str> = Vec::new();

    // @context — an array whose first element is the W3C v2 base URL, and
    // which carries the DTG context. Both are REQUIRED of every DTG credential
    // by §Common Structure; only the W3C half was checked until now, so a
    // credential that was not a DTG credential at all could pass as a VIC.
    let ctx = vic.get("@context").and_then(Value::as_array);
    match ctx {
        Some(c) if c.first().and_then(Value::as_str) == Some(W3C_VC_V2_CONTEXT) => {}
        _ => missing.push(
            "@context (must be an array whose first item is \"https://www.w3.org/ns/credentials/v2\")",
        ),
    }
    if !ctx.is_some_and(|c| c.iter().any(|v| v.as_str() == Some(DTG_CONTEXT))) {
        missing.push("@context entry \"https://firstperson.network/credentials/dtg/v1\"");
    }
    if !is_invitation_credential(vic) {
        missing
            .push("type (array containing \"VerifiableCredential\" and \"InvitationCredential\")");
    } else if !vic
        .get("type")
        .and_then(Value::as_array)
        .is_some_and(|t| t.iter().any(|v| v.as_str() == Some("VerifiableCredential")))
    {
        missing.push("type entry \"VerifiableCredential\"");
    }
    if !vic
        .get("type")
        .and_then(Value::as_array)
        .is_some_and(|t| t.iter().any(|v| v.as_str() == Some(DTG_BASE_TYPE)))
    {
        missing.push("type entry \"DTGCredential\"");
    }
    if invitation_issuer(vic).is_none() {
        missing.push("issuer (a DID string or an object with an `id`)");
    }
    if invitation_subject(vic).is_none() {
        missing.push("credentialSubject.id");
    }
    if invitation_id(vic).is_none() {
        missing.push("id (top-level, the single-use consumption handle)");
    }
    if vic.get("validUntil").and_then(Value::as_str).is_none() {
        missing.push("validUntil (RFC3339 expiry)");
    }
    if vic.get("credentialStatus").is_none() {
        missing.push("credentialStatus (revocation handle)");
    }
    if vic.get("proof").is_none() {
        missing.push("proof (the issuer's Data-Integrity signature)");
    }

    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "not a complete Invitation Credential — missing or malformed: {}. \
             Paste the full signed credential the community issued (the copy/QR \
             payload), not a summary view.",
            missing.join("; ")
        ))
    }
}

/// Check an invitation credential is complete **and** genuinely the
/// community's: [`validate_invitation_credential`], then its proof verified
/// against its issuer's DID document (`assertionMethod`, every proof in a set),
/// its validity window, and its revocation status, which must be established
/// ([`crate::issued_credential`]).
///
/// Until this passes, nothing read from the invitation — above all its issuer —
/// may be shown as the community or used to prefill one: anyone can write an
/// invitation naming any community.
///
/// # Errors
///
/// A sentence for the user saying what failed.
pub async fn verify_invitation_credential(
    vic: &Value,
    resolver: &affinidi_did_resolver_cache_sdk::DIDCacheClient,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), String> {
    validate_invitation_credential(vic)?;
    let issuer = invitation_issuer(vic)
        .ok_or_else(|| "the invitation names no issuer".to_string())?
        .to_string();
    crate::issued_credential::verify_issued_credential(vic.clone(), &issuer, resolver, now)
        .await
        .map(|_| ())
        .map_err(|e| format!("the invitation did not verify: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The outbound size guard: an ordinary submit passes, an oversized one is
    /// reported (so `submit_join_request` fails loudly instead of the mediator
    /// dropping it into a stuck `Pending`).
    #[tokio::test]
    async fn oversized_join_submit_is_flagged() {
        // A real key, because the submit is signed: the guard measures what
        // goes on the wire, and the proof is part of it.
        let (applicant, signer) =
            affinidi_tdk::dids::DID::generate_did_key(affinidi_tdk::dids::KeyType::Ed25519)
                .expect("did:key generates");
        let ordinary = build_join_submit_document(
            &applicant,
            &signer,
            "did:webvh:example.com:vtc",
            json!({}),
            "urn:uuid:1",
        )
        .await
        .expect("builds");
        assert_eq!(oversized_join_submit(&ordinary), None);

        // A presentation larger than the ceiling.
        let huge = json!({ "vp": "x".repeat(MAX_JOIN_SUBMIT_BYTES + 1) });
        let body = build_join_submit_document(
            &applicant,
            &signer,
            "did:webvh:example.com:vtc",
            huge,
            "urn:uuid:2",
        )
        .await
        .expect("builds");
        assert!(
            oversized_join_submit(&body).is_some_and(|n| n > MAX_JOIN_SUBMIT_BYTES),
            "an oversized submit must be flagged"
        );
    }

    /// The document a status poll puts on the wire. The VTC dispatches on the
    /// document, not the payload — a bare payload is rejected as
    /// `malformedRequest` ("missing field `id`"), which is exactly how the join
    /// submit failed before #138 — so the envelope members are the contract:
    /// `id`, `type`, and the audience binding (`issuer` = us, `recipient` = the
    /// community). The `requestId` must be the community's, and must ride in
    /// `payload` where `parse_payload` reads it.
    #[test]
    fn a_status_poll_is_a_well_formed_trust_task_document() {
        let request_id = Uuid::new_v4();
        let doc = crate::trust_task_doc::build_value(
            JOIN_REQUEST_STATUS_TYPE,
            "did:webvh:example.com:alice",
            "did:webvh:example.com:community",
            "urn:uuid:doc-1",
            JoinRequestStatusBody {
                request_id: Some(request_id),
            },
        )
        .expect("the status document builds");

        assert_eq!(doc["id"], json!("urn:uuid:doc-1"));
        assert_eq!(doc["type"], json!(JOIN_REQUEST_STATUS_TYPE));
        assert_eq!(doc["issuer"], json!("did:webvh:example.com:alice"));
        assert_eq!(doc["recipient"], json!("did:webvh:example.com:community"));
        assert_eq!(
            doc["payload"]["requestId"],
            json!(request_id),
            "the community looks the join up by this id"
        );
    }

    /// The submit document is built through the same helper, so its shape must
    /// not have moved: the payload still nests under `payload`, and the supplied
    /// document id is used verbatim (it doubles as the DIDComm message id, which
    /// is what makes DIDComm and TSP reply threading agree).
    #[tokio::test]
    async fn the_submit_document_keeps_its_shape_through_the_shared_builder() {
        let (applicant, signer) =
            affinidi_tdk::dids::DID::generate_did_key(affinidi_tdk::dids::KeyType::Ed25519)
                .expect("did:key generates");
        let doc = build_join_submit_document(
            &applicant,
            &signer,
            "did:webvh:example.com:community",
            json!({ "type": ["VerifiablePresentation"] }),
            "urn:uuid:submit-1",
        )
        .await
        .expect("the submit document builds");

        assert_eq!(doc["id"], json!("urn:uuid:submit-1"));
        assert_eq!(doc["type"], json!(JOIN_REQUEST_SUBMIT_TYPE));
        assert_eq!(doc["issuer"], json!(applicant));
        assert_eq!(doc["recipient"], json!("did:webvh:example.com:community"));
        assert_eq!(
            doc["payload"]["vp"]["type"],
            json!(["VerifiablePresentation"])
        );
        // `join-requests/submit/0.2` declares `proof` REQUIRED, and this is the
        // one document in the join flow a community cannot refuse for anything
        // else first — so its proof is part of the shape.
        assert_eq!(
            doc["proof"]["cryptosuite"],
            json!("eddsa-jcs-2022"),
            "the submit must be signed: {doc}"
        );
    }

    fn sample_vic() -> Value {
        json!({
            "id": "urn:uuid:vic-1",
            "type": ["VerifiableCredential", "InvitationCredential"],
            "issuer": "did:webvh:example.com:community",
            "credentialSubject": { "id": "did:webvh:example.com:alice" },
            "proof": { "type": "DataIntegrityProof" }
        })
    }

    #[test]
    fn is_invitation_credential_checks_the_type_tag() {
        assert!(is_invitation_credential(&sample_vic()));
        // Missing `type`.
        assert!(!is_invitation_credential(&json!({ "id": "x" })));
        // Wrong tag.
        assert!(!is_invitation_credential(
            &json!({ "type": ["VerifiableCredential", "MembershipCredential"] })
        ));
        // `type` not an array.
        assert!(!is_invitation_credential(
            &json!({ "type": "InvitationCredential" })
        ));
    }

    #[test]
    fn vp_without_invitation_is_holder_only() {
        let vp = build_join_vp("did:webvh:example.com:alice", None, None);
        assert_eq!(vp["type"], "VerifiablePresentation");
        assert_eq!(vp["holder"], "did:webvh:example.com:alice");
        assert!(
            vp.get("verifiableCredential").is_none(),
            "no invitation → no credentials array"
        );
        assert!(vp.get("subjectLinkage").is_none());
    }

    #[test]
    fn vp_with_invitation_embeds_the_vic() {
        let vic = sample_vic();
        let vp = build_join_vp("did:webvh:example.com:alice", Some(&vic), None);
        let creds = vp["verifiableCredential"]
            .as_array()
            .expect("verifiableCredential is an array");
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0], vic, "the VIC is embedded verbatim");
        assert!(
            vp.get("subjectLinkage").is_none(),
            "no linkage on the join-as-subject path"
        );
    }

    #[test]
    fn vp_with_linkage_embeds_the_proof() {
        let vic = sample_vic();
        let linkage = SubjectLinkage {
            verification_method: "did:webvh:example.com:alice#key-0".into(),
            signature_hex: "deadbeef".into(),
        };
        let vp = build_join_vp("did:key:zFreshB", Some(&vic), Some(&linkage));
        assert_eq!(
            vp["subjectLinkage"]["verificationMethod"],
            "did:webvh:example.com:alice#key-0"
        );
        assert_eq!(vp["subjectLinkage"]["signature"], "deadbeef");
    }

    #[tokio::test]
    async fn vetting_statements_ride_beside_the_invitation_and_the_digest_in_extensions() {
        let vic = sample_vic();
        let mut vp = build_join_vp("did:webvh:example.com:alice", Some(&vic), None);
        attach_credentials(
            &mut vp,
            [
                json!({ "id": "urn:uuid:s1" }),
                json!({ "id": "urn:uuid:s2" }),
            ],
        );
        let creds = vp["verifiableCredential"].as_array().unwrap();
        assert_eq!(creds.len(), 3);
        assert_eq!(creds[0], vic, "the invitation stays first");

        let mut bare = build_join_vp("did:webvh:example.com:alice", None, None);
        attach_credentials(&mut bare, Vec::new());
        assert!(
            bare.get("verifiableCredential").is_none(),
            "nothing to attach adds nothing"
        );

        let (applicant, signer) =
            affinidi_tdk::dids::DID::generate_did_key(affinidi_tdk::dids::KeyType::Ed25519)
                .expect("did:key generates");
        let doc = build_join_submit_document(
            &applicant,
            &signer,
            "did:webvh:example.com:community",
            JoinPresentation {
                vp,
                extensions: json!({ "requirementsDigest": "zDigest" }),
                attributes: Vec::new(),
            },
            "urn:uuid:submit-2",
        )
        .await
        .unwrap();
        assert_eq!(
            doc["payload"]["extensions"]["requirementsDigest"],
            "zDigest"
        );
    }

    #[test]
    fn vp_carries_the_w3c_base_context() {
        // W3C VC Data Model 2.0: a VP MUST carry `@context` whose first value is
        // the v2 base URL.
        let vp = build_join_vp("did:webvh:example.com:alice", None, None);
        assert_eq!(
            vp["@context"][0], "https://www.w3.org/ns/credentials/v2",
            "VP @context must lead with the W3C v2 base context"
        );
    }

    /// A complete, presentable VIC — every field `validate_invitation_credential`
    /// requires. Distinct from [`sample_vic`], which is intentionally minimal.
    fn complete_vic() -> Value {
        json!({
            // The DTG wire form, as `dtg-credentials` mints it. This fixture
            // previously carried only the W3C half and still called itself
            // complete — the validator agreed, because it checked only the
            // same half.
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://firstperson.network/credentials/dtg/v1"
            ],
            "id": "urn:uuid:vic-1",
            "type": ["VerifiableCredential", "DTGCredential", "InvitationCredential"],
            "issuer": "did:webvh:example.com:community",
            "credentialSubject": { "id": "did:webvh:example.com:alice" },
            "validUntil": "2099-01-01T00:00:00Z",
            "credentialStatus": { "type": "BitstringStatusListEntry" },
            "proof": { "type": "DataIntegrityProof" }
        })
    }

    /// An invitation is used only once its proof verifies against the issuer
    /// it names: an unsigned one, one signed by somebody else, and a signed one
    /// whose revocation status cannot be established are all refused.
    #[tokio::test]
    async fn an_invitation_must_verify_against_its_issuer() {
        let resolver = affinidi_did_resolver_cache_sdk::DIDCacheClient::new(
            affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
        )
        .await
        .unwrap();
        let key = |seed: u8| {
            let mut s = affinidi_tdk::secrets_resolver::secrets::Secret::generate_ed25519(
                None,
                Some(&[seed; 32]),
            );
            let mb = s.get_public_keymultibase().unwrap();
            let did = format!("did:key:{mb}");
            s.id = format!("{did}#{mb}");
            (did, s)
        };
        let (community, community_key) = key(0x61);
        let (_, other_key) = key(0x62);
        let mut vic = complete_vic();
        vic["issuer"] = json!(community);
        vic["credentialStatus"] = json!({
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListIndex": "3",
            "statusListCredential": "https://127.0.0.1:1/status",
        });
        let now = chrono::Utc::now();

        // The fixture's placeholder proof is not a proof.
        let err = verify_invitation_credential(&vic, &resolver, now)
            .await
            .unwrap_err();
        assert!(err.contains("did not verify"), "{err}");

        let forged = crate::proof_check::test_support::sign(vic.clone(), &[&other_key]).await;
        let err = verify_invitation_credential(&forged, &resolver, now)
            .await
            .unwrap_err();
        assert!(err.contains("does not belong to the signer"), "{err}");

        let genuine = crate::proof_check::test_support::sign(vic.clone(), &[&community_key]).await;
        let err = verify_invitation_credential(&genuine, &resolver, now)
            .await
            .unwrap_err();
        assert!(err.contains("revocation status"), "{err}");
    }

    #[test]
    fn a_profile_answer_is_taken_once_and_only_from_the_community_asked() {
        remember_profile_query("urn:uuid:q1", "did:webvh:vtc");
        assert!(!take_profile_query("did:webvh:mallory", "urn:uuid:q1"));
        assert!(!take_profile_query("did:webvh:vtc", "urn:uuid:other"));
        assert!(take_profile_query("did:webvh:vtc", "urn:uuid:q1"));
        assert!(
            !take_profile_query("did:webvh:vtc", "urn:uuid:q1"),
            "answered once"
        );
    }

    #[test]
    fn validate_accepts_a_complete_vic() {
        assert!(validate_invitation_credential(&complete_vic()).is_ok());
        // Object-form issuer is accepted too.
        let mut v = complete_vic();
        v["issuer"] = json!({ "id": "did:webvh:example.com:community" });
        assert!(validate_invitation_credential(&v).is_ok());
    }

    /// DTG Credentials §Common Structure is normative for *every* DTG
    /// credential: `@context` MUST include the DTG context and `type` MUST
    /// include `DTGCredential`. A credential carrying neither is not a DTG
    /// credential at all, whatever its subtype claims.
    #[test]
    fn validate_rejects_a_vic_missing_the_dtg_common_structure() {
        let mut no_ctx = complete_vic();
        no_ctx["@context"] = json!(["https://www.w3.org/ns/credentials/v2"]);
        let err = validate_invitation_credential(&no_ctx).expect_err("missing DTG context");
        assert!(
            err.contains("firstperson.network/credentials/dtg/v1"),
            "error should name the missing context: {err}"
        );

        let mut no_base = complete_vic();
        no_base["type"] = json!(["VerifiableCredential", "InvitationCredential"]);
        let err = validate_invitation_credential(&no_base).expect_err("missing DTGCredential");
        assert!(
            err.contains("DTGCredential"),
            "error should name the missing base type: {err}"
        );
    }

    #[test]
    fn validate_names_every_missing_field_on_a_stripped_vic() {
        // The exact shape that silently fell through to moderator review: a
        // summary missing id / proof / validUntil / credentialStatus / @context.
        let stripped = json!({
            "type": ["VerifiableCredential", "DTGCredential", "InvitationCredential"],
            "issuer": "did:webvh:example.com:community",
            "credentialSubject": { "id": "did:webvh:example.com:alice" },
            "validFrom": "2026-06-20T23:11:53Z"
        });
        let err = validate_invitation_credential(&stripped).expect_err("incomplete");
        for needle in ["@context", "id", "validUntil", "credentialStatus", "proof"] {
            assert!(err.contains(needle), "error should name `{needle}`: {err}");
        }
    }

    #[test]
    fn subject_and_id_extractors() {
        let vic = sample_vic();
        assert_eq!(
            invitation_subject(&vic),
            Some("did:webvh:example.com:alice")
        );
        assert_eq!(invitation_id(&vic), Some("urn:uuid:vic-1"));
        assert_eq!(invitation_subject(&json!({})), None);
    }

    #[tokio::test]
    async fn join_submit_body_is_a_trust_task_document_the_vtc_can_parse() {
        use trust_tasks_rs::TrustTask;

        let (applicant, signer) =
            affinidi_tdk::dids::DID::generate_did_key(affinidi_tdk::dids::KeyType::Ed25519)
                .expect("did:key generates");
        let vp = build_join_vp(&applicant, Some(&sample_vic()), None);
        let body = build_join_submit_document(
            &applicant,
            &signer,
            "did:webvh:example.com:community",
            vp,
            &format!("urn:uuid:{}", Uuid::new_v4()),
        )
        .await
        .expect("build document");

        // The exact deserialization the VTC performs — this is what was failing
        // with "missing field `id`" when we sent the bare payload.
        let doc: TrustTask<serde_json::Value> =
            serde_json::from_value(body.clone()).expect("body parses as a TrustTask document");

        assert!(doc.id.starts_with("urn:uuid:"), "document carries an id");
        assert_eq!(
            doc.type_uri.to_string(),
            JOIN_REQUEST_SUBMIT_TYPE,
            "type URI is the submit type"
        );
        assert_eq!(doc.issuer.as_deref(), Some(applicant.as_str()));
        assert_eq!(
            doc.recipient.as_deref(),
            Some("did:webvh:example.com:community")
        );
        // The submit is signed. It used to be unsigned deliberately — the
        // authcrypt sender authenticated the applicant — and this assertion
        // said so. But `join-requests/submit/0.2` declares `proof` REQUIRED,
        // and transport attribution says who handed the document over, not who
        // wrote it: only one of the two survives being relayed, and `issuer` is
        // what a community reads downstream (VTI #1641).
        assert!(
            doc.proof.is_some(),
            "the submit carries the proof its specification declares REQUIRED"
        );
        // The submit body rides as the document payload, VIC and all.
        assert_eq!(doc.payload["vp"]["holder"], applicant);
        assert!(doc.payload["vp"]["verifiableCredential"].is_array());
    }

    #[test]
    fn issuer_extractor_handles_string_and_object_forms() {
        // String issuer (the form the VTC emits).
        assert_eq!(
            invitation_issuer(&sample_vic()),
            Some("did:webvh:example.com:community")
        );
        // Object issuer (`{ "id": … }`).
        let obj = json!({ "issuer": { "id": "did:webvh:example.com:community" } });
        assert_eq!(
            invitation_issuer(&obj),
            Some("did:webvh:example.com:community")
        );
        // Missing / wrong-typed issuer.
        assert_eq!(invitation_issuer(&json!({})), None);
        assert_eq!(invitation_issuer(&json!({ "issuer": 42 })), None);
    }

    #[test]
    fn community_match_keys_on_the_issuer() {
        let vic = sample_vic();
        assert!(invitation_matches_community(
            &vic,
            "did:webvh:example.com:community"
        ));
        assert!(!invitation_matches_community(
            &vic,
            "did:webvh:example.com:other-community"
        ));
    }

    #[test]
    fn expiry_uses_valid_until_and_fails_closed() {
        let now = "2026-06-21T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        // No validUntil → never expired.
        assert!(!invitation_is_expired(&sample_vic(), now));
        // Future window → not expired.
        let future = json!({ "validUntil": "2027-01-01T00:00:00Z" });
        assert!(!invitation_is_expired(&future, now));
        // Past window → expired.
        let past = json!({ "validUntil": "2025-01-01T00:00:00Z" });
        assert!(invitation_is_expired(&past, now));
        // Malformed → treated as expired (fail closed).
        let bad = json!({ "validUntil": "not-a-date" });
        assert!(invitation_is_expired(&bad, now));
    }

    #[test]
    fn sign_subject_linkage_verifies_with_the_tdk_routine() {
        use affinidi_tdk::affinidi_crypto::jose::signing;
        let seed = [7u8; 32];
        let pubkey = signing::public_key_from_private(&seed);
        let linkage = sign_subject_linkage(
            &seed,
            "did:webvh:example.com:alice#key-0",
            "urn:uuid:vic-1",
            "did:key:zFreshB",
        )
        .expect("sign");
        assert_eq!(
            linkage.verification_method,
            "did:webvh:example.com:alice#key-0"
        );
        // The signature verifies over the canonical bytes — the exact check the
        // VTC performs against the subject's resolved key.
        let sig: [u8; 64] = hex::decode(&linkage.signature_hex)
            .unwrap()
            .try_into()
            .unwrap();
        let bytes = subject_linkage_signing_bytes("urn:uuid:vic-1", "did:key:zFreshB");
        assert!(signing::verify(&bytes, &sig, &pubkey).is_ok());
        // A different presenter's bytes must NOT verify against this signature.
        let other = subject_linkage_signing_bytes("urn:uuid:vic-1", "did:key:zOther");
        assert!(signing::verify(&other, &sig, &pubkey).is_err());
    }

    #[test]
    fn linkage_signing_bytes_are_tag_id_nul_presenter() {
        let bytes = subject_linkage_signing_bytes("urn:uuid:vic-1", "did:key:zB");
        let mut expected = SUBJECT_LINKAGE_DOMAIN_TAG.to_vec();
        expected.extend_from_slice(b"urn:uuid:vic-1");
        expected.push(0);
        expected.extend_from_slice(b"did:key:zB");
        assert_eq!(bytes, expected);
    }
}
