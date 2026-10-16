//! Witnessing a relationship, with the member's VTA as the witnessed party.
//!
//! A **witness** observes one side of a relationship present its relationship credential and
//! attests to it in a Verifiable Witness Credential (VWC). The party opens a `witness/session`
//! under its relationship DID, presents its relationship credential bound to the session's
//! challenge (`witness/session/submit`), and receives the VWC.
//!
//! This client does not build or sign any of that. The VTA does — it is the witnessed party for
//! its principal (`vta/witness/{open,present,accept}/0.1`, VTI `docs/02-vta/witness-party.md`):
//! it signs every document **as the relationship DID**, reads the credentials from its vault, and
//! verifies and stores what the witness answers. This client **carries** the documents: it sends
//! each one to the witness from the relationship DID, on that DID's own mediator connection, and
//! hands each answer back unaltered. The VTA never contacts the witness, because the relationship
//! DID's one websocket belongs to this client, and the witness answers on it.
//!
//! The round ([`run`]):
//!
//! 1. Make sure the relationship credential (and the membership credential, when one is
//!    presented) is in the VTA's credential vault ([`ensure_in_vault`]) — the VTA names them by
//!    vault handle.
//! 2. `vta/witness/open` → the `witness/session` document. [`check_witness_document`], send it,
//!    wait for the witness's answer on the session's thread, [`verify_witness_reply`].
//! 3. `vta/witness/present` with that answer → the `witness/session/submit` document. Check it,
//!    send it, wait, verify — and **discard the submit document**: it carries the principal's
//!    presentations, and nothing after this reads it (CONVENTIONS §6).
//! 4. `vta/witness/accept` with the witness's answer → the stored VWC's handle and the session's
//!    **outcome evidence**, which a community needs beside the VWC to count it
//!    ([`personhood_ext`]).
//!
//! A refusal from the witness ends the session here and is **not** handed back to the VTA; the
//! VTA's record expires on its own. An answer that does not verify as the witness's is not an
//! answer at all — it is discarded unread and the wait goes on, so nobody on the path can end a
//! session by forging a refusal.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use trust_tasks_rs::specs::vta::witness as vta_witness;
use trust_tasks_rs::specs::witness::session;
use trust_tasks_rs::{ErrorPayload, Payload, TrustTask};
use vta_sdk::client::VtaClient;
use vta_sdk::error::VtaError;
use vta_sdk::inbound::{Inbound, classify};
use vta_sdk::protocol::matching::{Protocol, ServiceCapabilities, select_protocol};
use vta_sdk::trust_task_proof::{TrustTaskVmResolver, verify_trust_task_proof_value};

/// The proof purpose a witness signs its answers for (VTI-KEY-106).
const REPLY_PROOF_PURPOSE: &str = "authentication";

/// The `type` prefix of a framework error document.
const TRUST_TASK_ERROR_PREFIX: &str = "https://trusttasks.org/spec/trust-task-error/";

/// How long to wait for the witness to answer one document. A witness answers at once or not at
/// all, so a minute is generous; the VTA's session lives ten (its `session_ttl_secs` default).
pub const DEFAULT_ANSWER_TIMEOUT: Duration = Duration::from_secs(60);

/// The vendor namespace the personhood assertion carries outcome evidence in
/// (VTI `docs/03-vtc/trusted-witnesses.md`).
pub const WITNESS_EXT: &str = "org.openvtc.witness";

/// At most this many outcome-evidence entries ride a personhood assertion; a VTC refuses more,
/// so the selection a member makes is held to it ([`personhood_ext`] never trims one).
pub const MAX_OUTCOME_EVIDENCE: usize = 16;

/// `witness/session/0.1`.
pub fn session_type() -> &'static str {
    <session::v0_1::Payload as Payload>::TYPE_URI
}

/// `witness/session/submit/0.1`.
pub fn submit_type() -> &'static str {
    <session::submit::v0_1::Payload as Payload>::TYPE_URI
}

/// Whether `typ` is a witness's answer to a document this client carries: the session's or the
/// submission's `#response`. A refusal arrives as a `trust-task-error`, which the dispatcher
/// offers here as well as to every other waiting ask.
pub fn is_reply_type(typ: &str) -> bool {
    typ.strip_suffix("#response")
        .is_some_and(|t| t == session_type() || t == submit_type())
}

// ─── Errors ──────────────────────────────────────────────────────────────────

/// Why a witnessing did not complete — each case worded for the member, because each has a
/// different fix (R6.4).
#[derive(Debug, thiserror::Error)]
pub enum WitnessError {
    /// The member's VTA refused a step. `code` is the rejection's code as sent.
    #[error("{}", vta_refusal_text(.step, .code, .message))]
    VtaRefused {
        step: &'static str,
        code: String,
        message: String,
    },
    /// The VTA could not be reached, or answered with something that is not the task's answer.
    #[error("your VTA could not {step}: {source}")]
    Vta {
        step: &'static str,
        #[source]
        source: VtaError,
    },
    /// The witness answered with a declared refusal.
    #[error("{}", witness_refusal_text(.refusal, .code, .message))]
    Refused {
        refusal: WitnessRefusal,
        code: String,
        message: Option<String>,
    },
    /// The witness did not answer in time.
    #[error(
        "the witness did not answer the {document} within {}s — it may be offline, or not \
         reachable from this relationship's mediator. Try again later, or choose another witness",
        .waited.as_secs()
    )]
    NoAnswer {
        document: &'static str,
        waited: Duration,
    },
    /// The document could not be handed to the transport.
    #[error("could not send the {document} to the witness: {reason}")]
    Send {
        document: &'static str,
        reason: String,
    },
    /// The relationship DID and the witness share no transport a witness can answer on.
    #[error("{0}")]
    NoRoute(String),
    /// The VTA handed back a document this client will not send in the relationship's name.
    #[error("{0}")]
    Document(String),
    /// What this account holds cannot be witnessed (no credential to present, no VTA, …).
    #[error("{0}")]
    Unsupported(String),
}

fn local_code(code: &str) -> &str {
    code.rsplit_once(':').map_or(code, |(_, local)| local)
}

fn vta_refusal_text(step: &str, code: &str, message: &str) -> String {
    let advice = match local_code(code) {
        "memberLinkUnsupported" => {
            "your VTA does not present your membership to this witness. Your membership \
             credential names your persona DID, not this relationship's DID, so the VTA has to \
             link the two for the witness — and it does that only for witnesses its operator has \
             listed in `[witness] member_link_witnesses`. Ask your VTA's operator to list this \
             witness, or choose a witness they have listed"
        }
        "credentialMismatch" => {
            "a credential does not fit the session — the relationship credential must be issued \
             by this relationship's DID to the other party, and every credential must be within \
             its validity period"
        }
        "witnessUnresolvable" => {
            "your VTA could not resolve the witness's DID. Check the DID, or try again later"
        }
        "sessionUnknown" => {
            "your VTA no longer has this session (it expired, or another attempt moved it on). \
             Start the witnessing again"
        }
        "responseInvalid" => {
            "your VTA did not accept the witness's answer as the witness's own for this session"
        }
        "vwcInvalid" => {
            "the witness's credential did not verify against the session, so your VTA did not \
             store it"
        }
        _ => "",
    };
    if advice.is_empty() {
        format!("your VTA refused to {step} [{code}]: {message}")
    } else {
        format!("your VTA refused to {step}: {advice} [{code}]")
    }
}

fn witness_refusal_text(refusal: &WitnessRefusal, code: &str, message: &Option<String>) -> String {
    let said = message
        .as_deref()
        .map(|m| format!(" (the witness said: {m})"))
        .unwrap_or_default();
    match refusal {
        WitnessRefusal::SessionRefused => format!(
            "the witness will not witness this relationship — its policy, its capacity or the \
             parties rule it out. Another witness may{said}"
        ),
        WitnessRefusal::ChallengeMismatch => format!(
            "the witness no longer holds this session (it expired or was already used). Start \
             the witnessing again{said}"
        ),
        WitnessRefusal::PresentationInvalid => format!(
            "the witness did not accept your credentials — a proof, a validity period, or a \
             community it does not serve{said}"
        ),
        WitnessRefusal::Other => format!("the witness refused [{code}]{said}"),
    }
}

/// Map a VTA failure at `step` to a [`WitnessError`], keeping the rejection's code.
fn vta_failure(step: &'static str, e: VtaError) -> WitnessError {
    match e {
        VtaError::Rejected { code, message, .. } => WitnessError::VtaRefused {
            step,
            code,
            message,
        },
        // `permissionDenied` arrives typed: custody of a DID the session needs, or no
        // `witness-request` standing. The VTA answers the same whichever it is.
        VtaError::Forbidden(message) => WitnessError::VtaRefused {
            step,
            code: "permissionDenied".into(),
            message: format!(
                "{message} — your VTA holds no key of this relationship's DID that this \
                 account may use, or this account may not request witnessing. A relationship \
                 created before its keys were held at the VTA has to be re-established"
            ),
        },
        // `notFound` arrives typed too: a credential not in the vault in a context we act in.
        VtaError::NotFound(message) => WitnessError::VtaRefused {
            step,
            code: "notFound".into(),
            message,
        },
        VtaError::UnsupportedTaskType { type_uri, .. } => WitnessError::Unsupported(format!(
            "your VTA does not serve `{type_uri}`: it predates witnessing. Upgrade the VTA to a \
             release that serves `vta/witness/*`"
        )),
        other => WitnessError::Vta {
            step,
            source: other,
        },
    }
}

// ─── The documents carried ───────────────────────────────────────────────────

/// Which session document is about to be carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessDocument {
    /// `witness/session/0.1`, from `vta/witness/open`.
    Session,
    /// `witness/session/submit/0.1`, from `vta/witness/present`.
    Submit,
}

impl WitnessDocument {
    fn type_uri(self) -> &'static str {
        match self {
            Self::Session => session_type(),
            Self::Submit => submit_type(),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Session => "session request",
            Self::Submit => "submission",
        }
    }
}

/// Refuse to carry `document` unless it is the `kind` document of session `session_id`, issued
/// and signed by `relationship_did`, and addressed to `witness_did`.
///
/// The VTA builds these documents; this is the client's own check that what it is about to send
/// in the relationship DID's name is what it asked for, to the witness it named (CONVENTIONS §6:
/// send each document only to its `recipient`). A session document's `id` is the session id; a
/// submit document is threaded to it.
pub fn check_witness_document(
    document: &Value,
    kind: WitnessDocument,
    session_id: &str,
    relationship_did: &str,
    witness_did: &str,
) -> Result<(), WitnessError> {
    let refuse = |reason: String| {
        Err(WitnessError::Document(format!(
            "refusing to send the witness {} your VTA built: {reason}",
            kind.name()
        )))
    };
    let field = |name: &str| document.get(name).and_then(Value::as_str);

    match field("type") {
        Some(t) if t == kind.type_uri() => {}
        other => {
            return refuse(format!(
                "it is a `{}`, not a `{}`",
                other.unwrap_or("(no type)"),
                kind.type_uri()
            ));
        }
    }
    let (member, bound) = match kind {
        WitnessDocument::Session => ("id", field("id")),
        WitnessDocument::Submit => ("threadId", field("threadId")),
    };
    if bound != Some(session_id) {
        return refuse(format!(
            "its `{member}` is `{}`, not the session `{session_id}`",
            bound.unwrap_or("(none)")
        ));
    }
    if document.get("proof").is_none() {
        return refuse("it carries no proof".into());
    }
    if field("issuedAt").is_none() {
        return refuse("it has no `issuedAt`".into());
    }
    if field("issuer") != Some(relationship_did) {
        return refuse(format!(
            "it is issued by `{}`, not by the relationship DID `{relationship_did}`",
            field("issuer").unwrap_or("(nobody)")
        ));
    }
    if field("recipient") != Some(witness_did) {
        return refuse(format!(
            "it is addressed to `{}`, not to the witness `{witness_did}`",
            field("recipient").unwrap_or("(nobody)")
        ));
    }
    Ok(())
}

/// Which declared refusal a witness answered with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessRefusal {
    /// `witness/session:refused` — this witness will not witness this exchange. Another may.
    SessionRefused,
    /// `witness/session/submit:challengeMismatch` — the session is spent, gone or another's.
    ChallengeMismatch,
    /// `witness/session/submit:presentationInvalid` — the credentials were not accepted.
    PresentationInvalid,
    /// Any other code; the [`WitnessError::Refused`] carries it.
    Other,
}

fn refusal_for(code: &str) -> WitnessRefusal {
    use session::submit::v0_1::error_codes as submit;
    use session::v0_1::error_codes as open;
    if code == open::REFUSED.code {
        WitnessRefusal::SessionRefused
    } else if code == submit::CHALLENGE_MISMATCH.code {
        WitnessRefusal::ChallengeMismatch
    } else if code == submit::PRESENTATION_INVALID.code {
        WitnessRefusal::PresentationInvalid
    } else {
        WitnessRefusal::Other
    }
}

/// What a witness answered, once the answer is proven to be the witness's.
#[derive(Debug, Clone, PartialEq)]
pub enum WitnessReply {
    /// The witness's `#response`: hand it back to the VTA, unaltered.
    Answered(Value),
    /// A `trust-task-error`: the session ends here. Never handed to the VTA.
    Refused {
        refusal: WitnessRefusal,
        code: String,
        message: Option<String>,
    },
}

/// Verify `reply` as the witness's answer to `request` (the document this client carried), and
/// classify it.
///
/// Accepted only when all of these hold — a refusal is held to the same rule as a success, so a
/// forged refusal cannot make this client abandon a session:
///
/// 1. its `type` is the request's `type` plus `#response`, or a `trust-task-error`;
/// 2. its `threadId` is the request's thread (`threadId`, else `id`);
/// 3. its `issuer` is `witness_did` and its `recipient` the request's issuer;
/// 4. it carries a Data Integrity proof for `authentication` by a key `witness_did` lists under
///    `authentication`, which verifies over the reply **as received**.
pub async fn verify_witness_reply(
    request: &Value,
    reply: &Value,
    witness_did: &str,
    resolver: &TrustTaskVmResolver,
) -> Result<WitnessReply, String> {
    let field = |doc: &Value, name: &str| doc.get(name).and_then(Value::as_str).map(str::to_string);
    let request_type = field(request, "type").ok_or("the carried document has no `type`")?;
    let request_id = field(request, "id").ok_or("the carried document has no `id`")?;
    let our_did = field(request, "issuer").ok_or("the carried document names no issuer")?;
    let thread = field(request, "threadId").unwrap_or(request_id);

    let reply_type = field(reply, "type").unwrap_or_default();
    let is_error = reply_type.starts_with(TRUST_TASK_ERROR_PREFIX);
    if !is_error && reply_type != format!("{request_type}#response") {
        return Err(format!("`{reply_type}` does not answer a `{request_type}`"));
    }
    if field(reply, "threadId").as_deref() != Some(thread.as_str()) {
        return Err(format!("it is not threaded to the session `{thread}`"));
    }
    if field(reply, "issuer").as_deref() != Some(witness_did) {
        return Err(format!("it is not issued by the witness `{witness_did}`"));
    }
    if field(reply, "recipient").as_deref() != Some(our_did.as_str()) {
        return Err(format!("it is not addressed to `{our_did}`"));
    }
    let purpose = reply
        .get("proof")
        .and_then(|p| p.get("proofPurpose"))
        .and_then(Value::as_str)
        .ok_or("it carries no proof")?;
    if purpose != REPLY_PROOF_PURPOSE {
        return Err(format!(
            "its proof is for `{purpose}`, not `{REPLY_PROOF_PURPOSE}`"
        ));
    }
    let signer = verify_trust_task_proof_value(reply, resolver)
        .await
        .map_err(|e| format!("its proof does not verify: {e}"))?;
    if signer != witness_did {
        return Err(format!("its proof is by `{signer}`, not by the witness"));
    }

    match classify(reply) {
        Inbound::Error => {
            let error: TrustTask<ErrorPayload> = serde_json::from_value(reply.clone())
                .map_err(|e| format!("the witness's trust-task-error does not parse: {e}"))?;
            let code = error.payload.code.to_string();
            Ok(WitnessReply::Refused {
                refusal: refusal_for(&code),
                code,
                message: error.payload.message,
            })
        }
        Inbound::Response => Ok(WitnessReply::Answered(reply.clone())),
        Inbound::Request => Err("the witness sent a request, not an answer".into()),
    }
}

// ─── Waiting for the witness ─────────────────────────────────────────────────

/// A document that arrived for a witnessing in progress, as the inbound dispatcher saw it.
#[derive(Debug, Clone)]
pub struct InboundReply {
    /// The transport-proven sender (authcrypt `from`, or the TSP sender VID).
    pub sender: String,
    /// The Trust Task document, as received.
    pub document: Value,
}

/// Hands the witness's answers from the inbound dispatcher to the witnessing waiting on them,
/// keyed by session id — which both answers thread on.
///
/// Cheap to clone; one per process. A document on a thread nobody is waiting on is dropped by
/// [`ReplyRouter::deliver`], and nothing here reads it.
#[derive(Clone, Default)]
pub struct ReplyRouter {
    waiting: Arc<Mutex<HashMap<String, mpsc::UnboundedSender<InboundReply>>>>,
}

/// One witnessing's place in the [`ReplyRouter`]. Dropping it stops the routing.
pub struct Waiting {
    session_id: String,
    router: ReplyRouter,
    replies: mpsc::UnboundedReceiver<InboundReply>,
}

impl Drop for Waiting {
    fn drop(&mut self) {
        if let Ok(mut waiting) = self.router.waiting.lock() {
            waiting.remove(&self.session_id);
        }
    }
}

impl ReplyRouter {
    /// Start routing the answers threaded on `session_id` to the returned [`Waiting`].
    pub fn wait_for(&self, session_id: &str) -> Waiting {
        let (tx, rx) = mpsc::unbounded_channel();
        if let Ok(mut waiting) = self.waiting.lock() {
            waiting.insert(session_id.to_string(), tx);
        }
        Waiting {
            session_id: session_id.to_string(),
            router: self.clone(),
            replies: rx,
        }
    }

    /// Hand `document` to the witnessing waiting on its `threadId`. `false` when nobody is.
    pub fn deliver(&self, sender: &str, document: Value) -> bool {
        let Some(thread) = document
            .get("threadId")
            .and_then(Value::as_str)
            .map(str::to_string)
        else {
            return false;
        };
        let Ok(waiting) = self.waiting.lock() else {
            return false;
        };
        waiting.get(&thread).is_some_and(|tx| {
            tx.send(InboundReply {
                sender: sender.to_string(),
                document,
            })
            .is_ok()
        })
    }

    /// Whether a witnessing is waiting on `thread`.
    pub fn is_waiting(&self, thread: &str) -> bool {
        self.waiting
            .lock()
            .is_ok_and(|waiting| waiting.contains_key(thread))
    }
}

impl Waiting {
    /// The witness's verified answer to `request`, or [`WitnessError::NoAnswer`] after `timeout`.
    ///
    /// Anything else on the thread — from another sender, or not verifiable as the witness's —
    /// is logged and discarded, and the wait goes on.
    async fn answer(
        &mut self,
        request: &Value,
        kind: WitnessDocument,
        witness_did: &str,
        resolver: &TrustTaskVmResolver,
        timeout: Duration,
    ) -> Result<WitnessReply, WitnessError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let next = tokio::time::timeout_at(deadline, self.replies.recv()).await;
            let Ok(Some(inbound)) = next else {
                return Err(WitnessError::NoAnswer {
                    document: kind.name(),
                    waited: timeout,
                });
            };
            if inbound.sender != witness_did {
                tracing::warn!(
                    sender = %inbound.sender,
                    session = %self.session_id,
                    "a witnessing answer from someone other than the witness — discarded"
                );
                continue;
            }
            match verify_witness_reply(request, &inbound.document, witness_did, resolver).await {
                Ok(reply) => return Ok(reply),
                Err(reason) => tracing::warn!(
                    session = %self.session_id,
                    %reason,
                    "a witnessing answer that is not the witness's — discarded unread"
                ),
            }
        }
    }
}

// ─── Carrying ────────────────────────────────────────────────────────────────

/// Sends a session document to the witness from the relationship DID.
///
/// `Ok` means handed to the transport, never delivered (R1.1): the answer is what shows it
/// arrived, and [`run`] waits for that.
#[async_trait]
pub trait Carrier: Send + Sync {
    async fn send(&self, document: &Value) -> Result<(), String>;
}

/// The transport both DID documents advertise, best first (TSP, then DIDComm), matched on service
/// `type`. REST is never a candidate: a witness answers the transport-proven sender, which an
/// HTTPS POST does not prove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessRoute {
    /// TSP, through the witness's advertised mediator.
    Tsp { witness_mediator: String },
    /// DIDComm, in the Trust Task binding envelope.
    Didcomm,
}

/// Pick the route from the two resolved DID documents. Pure, for tests.
pub fn select_route(
    relationship_doc: &Value,
    witness_doc: &Value,
    witness_did: &str,
) -> Result<WitnessRoute, WitnessError> {
    let carriers = |doc: &Value| ServiceCapabilities {
        rest: None,
        ..ServiceCapabilities::from_did_document(doc)
    };
    let matched = select_protocol(
        &carriers(relationship_doc),
        &carriers(witness_doc),
        witness_did,
    )
    .map_err(|e| {
        WitnessError::NoRoute(format!(
            "this relationship's DID and the witness share no transport a witness can \
                 answer on (TSP or DIDComm): {e}"
        ))
    })?;
    Ok(match matched.protocol {
        Protocol::Tsp => WitnessRoute::Tsp {
            witness_mediator: matched.peer_endpoint,
        },
        Protocol::Didcomm => WitnessRoute::Didcomm,
        Protocol::Rest => unreachable!("REST was removed from both sides"),
    })
}

/// Resolve `did` to its document as JSON.
pub async fn resolve_document(
    resolver: &affinidi_did_resolver_cache_sdk::DIDCacheClient,
    did: &str,
) -> Result<Value, WitnessError> {
    let resolved = tokio::time::timeout(Duration::from_secs(20), resolver.resolve(did))
        .await
        .map_err(|_| WitnessError::NoRoute(format!("resolving {did} timed out")))?
        .map_err(|e| WitnessError::NoRoute(format!("could not resolve {did}: {e}")))?;
    serde_json::to_value(&resolved.doc)
        .map_err(|e| WitnessError::NoRoute(format!("the DID document of {did}: {e}")))
}

/// Carries documents over DIDComm on the relationship DID's own listener, in the Trust Task
/// binding envelope, through the durable outbox (`didcomm::send_message_via`).
pub struct DidcommCarrier {
    pub service: crate::didcomm::Messaging,
    /// The relationship DID's listener — the one websocket the mediator allows it.
    pub listener_id: String,
    pub relationship_did: String,
    pub witness_did: String,
}

#[async_trait]
impl Carrier for DidcommCarrier {
    async fn send(&self, document: &Value) -> Result<(), String> {
        let id = document
            .get("id")
            .and_then(Value::as_str)
            .ok_or("the document has no id")?
            .to_string();
        let message = crate::community_send::didcomm_request(
            id,
            document.clone(),
            &self.relationship_did,
            &self.witness_did,
        );
        crate::didcomm::send_message_via(
            &self.service,
            &message,
            &self.listener_id,
            &self.witness_did,
        )
        .await
        .map_err(|e| e.to_string())
    }
}

/// Carries documents over TSP from a persona DID, through the witness's advertised mediator.
pub struct TspCarrier {
    pub atm: affinidi_tdk::messaging::ATM,
    pub profile: Arc<affinidi_tdk::messaging::profiles::ATMProfile>,
    pub witness_did: String,
    pub witness_mediator: String,
}

#[async_trait]
impl Carrier for TspCarrier {
    async fn send(&self, document: &Value) -> Result<(), String> {
        crate::tsp::send_trust_task(
            &self.atm,
            &self.profile,
            document,
            &self.witness_did,
            &self.witness_mediator,
        )
        .await
        .map_err(|e| e.to_string())
    }
}

// ─── The credentials presented ───────────────────────────────────────────────

/// The vault handle of `credential` (its own `id`), storing it at the VTA first when the vault
/// does not hold it.
///
/// Only when it does not: `vault/credentials/receive` overwrites, and the VTA binds a session to
/// the stored bytes, so re-storing one a session already named would fail that session's
/// presentation as `credentialMismatch`. `filter` narrows the query (the vault refuses an
/// unfiltered one).
pub async fn ensure_in_vault(
    client: &VtaClient,
    credential: &Value,
    filter: Value,
) -> Result<String, WitnessError> {
    let id = credential
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            WitnessError::Unsupported(
                "the credential has no `id`, so your VTA cannot name it — ask for it to be \
                 issued again"
                    .into(),
            )
        })?
        .to_string();
    // A failed read is a failure, not an empty vault: storing regardless would overwrite.
    let held = client
        .cred_vault_query(filter)
        .await
        .map(|listing| crate::credential_sync::held_ids(&listing))
        .map_err(|e| vta_failure("read its credential vault", e))?;
    if held.iter().any(|h| h == &id) {
        return Ok(id);
    }
    client
        .cred_vault_receive(credential.clone(), None)
        .await
        .map_err(|e| vta_failure("store the credential in its vault", e))?;
    Ok(id)
}

/// The vault filter for relationship credentials.
pub fn relationship_credential_filter() -> Value {
    json!({ "type": "RelationshipCredential" })
}

/// The vault filter for membership credentials.
pub fn membership_credential_filter() -> Value {
    json!({ "purpose": "membership" })
}

/// The membership evidence presented beside the relationship credential.
#[derive(Debug, Clone)]
pub struct MembershipEvidence {
    /// The community's membership credential (VMC), as held.
    pub credential: Value,
    /// The DID the VMC names, when it is not the relationship DID: the VTA then presents a second
    /// presentation by it, linking the two for the witness (the member link, VTI
    /// `witness-host-service.md` §3.3a). `None` when the VMC names the relationship DID itself.
    pub member_did: Option<String>,
}

/// One relationship to have witnessed.
#[derive(Debug, Clone)]
pub struct WitnessRequest {
    pub witness_did: String,
    /// Our DID in the relationship — the party, and the sender of every document.
    pub relationship_did: String,
    /// The other party's DID in the relationship.
    pub counterparty_did: String,
    /// The relationship exchange's thread, set as `parentThreadId` on the session's documents.
    pub relationship_thread_id: String,
    /// Our relationship credential: issued by `relationship_did`, naming `counterparty_did`.
    pub relationship_credential: Value,
    pub membership: Option<MembershipEvidence>,
}

/// A step of the round, for a progress line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    StoringCredentials,
    Opening,
    AwaitingSession,
    Presenting,
    AwaitingOutcome,
    Accepting,
}

impl Step {
    pub fn describe(self) -> &'static str {
        match self {
            Step::StoringCredentials => "Making sure your VTA holds the credentials to present…",
            Step::Opening => "Asking your VTA to open a witnessed session…",
            Step::AwaitingSession => "Waiting for the witness to open the session…",
            Step::Presenting => "Asking your VTA to present your credentials…",
            Step::AwaitingOutcome => "Waiting for the witness's credential…",
            Step::Accepting => "Asking your VTA to verify and store the witness's credential…",
        }
    }
}

/// What a completed witnessing produced.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Witnessed {
    pub session_id: String,
    /// The VWC's handle in the VTA's credential vault.
    pub credential_id: String,
    pub witness: String,
    pub vwc_digest_multibase: String,
    /// `{ session, outcome }`: the session document and the witness's submit `#response`, which
    /// carries the VWC. What a community needs beside the VWC to count it.
    pub evidence: Value,
}

impl Witnessed {
    /// The VWC, as the witness delivered it (inside the outcome evidence).
    pub fn vwc(&self) -> Option<&Value> {
        self.evidence.pointer("/outcome/payload/vwc")
    }
}

/// Everything [`run`] needs that is not the request.
pub struct Round<'a> {
    pub vta: &'a VtaClient,
    pub carrier: &'a dyn Carrier,
    pub router: &'a ReplyRouter,
    pub resolver: &'a TrustTaskVmResolver,
    pub answer_timeout: Duration,
}

/// Run one witnessing: open → carry → present → carry → accept. See the module docs.
pub async fn run(
    round: &Round<'_>,
    request: &WitnessRequest,
    progress: &(dyn Fn(Step) + Send + Sync),
) -> Result<Witnessed, WitnessError> {
    progress(Step::StoringCredentials);
    let relationship_credential_id = ensure_in_vault(
        round.vta,
        &request.relationship_credential,
        relationship_credential_filter(),
    )
    .await?;
    let membership = match &request.membership {
        Some(m) => {
            let id =
                ensure_in_vault(round.vta, &m.credential, membership_credential_filter()).await?;
            let mut membership = json!({ "credentialId": id });
            if let Some(member) = &m.member_did {
                membership["memberDid"] = json!(member);
            }
            Some(membership)
        }
        None => None,
    };

    progress(Step::Opening);
    let mut open_payload = json!({
        "witness": request.witness_did,
        "relationshipDid": request.relationship_did,
        "counterpartyDid": request.counterparty_did,
        "relationshipThreadId": request.relationship_thread_id,
        "relationshipCredentialId": relationship_credential_id,
    });
    if let Some(membership) = membership {
        open_payload["membership"] = membership;
    }
    let open_payload: vta_witness::open::v0_1::Payload = serde_json::from_value(open_payload)
        .map_err(|e| WitnessError::Document(format!("the witnessing request is not valid: {e}")))?;
    let opened = round
        .vta
        .witness_open(&open_payload)
        .await
        .map_err(|e| vta_failure("open a witnessed session", e))?;
    let session_id = opened.session_id.to_string();
    let session_document = Value::Object(opened.document.0);
    check_witness_document(
        &session_document,
        WitnessDocument::Session,
        &session_id,
        &request.relationship_did,
        &request.witness_did,
    )?;

    // Waiting before sending: an answer can arrive before `send` returns.
    let mut waiting = round.router.wait_for(&session_id);

    progress(Step::AwaitingSession);
    let session_answer = carry(
        round,
        &mut waiting,
        &session_document,
        WitnessDocument::Session,
        &request.witness_did,
    )
    .await?;

    progress(Step::Presenting);
    let present_payload: vta_witness::present::v0_1::Payload =
        serde_json::from_value(json!({ "sessionId": session_id, "response": session_answer }))
            .map_err(|e| WitnessError::Document(format!("the witness's answer: {e}")))?;
    let presented = round
        .vta
        .witness_present(&present_payload)
        .await
        .map_err(|e| vta_failure("present your credentials", e))?;
    let submit_document = Value::Object(presented.document.0);
    check_witness_document(
        &submit_document,
        WitnessDocument::Submit,
        &session_id,
        &request.relationship_did,
        &request.witness_did,
    )?;
    progress(Step::AwaitingOutcome);
    let outcome = carry(
        round,
        &mut waiting,
        &submit_document,
        WitnessDocument::Submit,
        &request.witness_did,
    )
    .await;
    // The submit document carries the principal's presentations, and the witness has answered
    // it (or never will): nothing after this reads it (CONVENTIONS §6).
    drop(submit_document);
    drop(waiting);
    let outcome = outcome?;

    progress(Step::Accepting);
    let accept_payload: vta_witness::accept::v0_1::Payload =
        serde_json::from_value(json!({ "sessionId": session_id, "response": outcome }))
            .map_err(|e| WitnessError::Document(format!("the witness's answer: {e}")))?;
    let accepted = round
        .vta
        .witness_accept(&accept_payload)
        .await
        .map_err(|e| vta_failure("store the witness's credential", e))?;

    Ok(Witnessed {
        session_id,
        credential_id: accepted.credential_id.to_string(),
        witness: accepted.witness.to_string(),
        vwc_digest_multibase: accepted.vwc_digest_multibase.to_string(),
        evidence: serde_json::to_value(&accepted.evidence)
            .map_err(|e| WitnessError::Document(format!("the outcome evidence: {e}")))?,
    })
}

/// Send `document` and wait for the witness's verified answer; a refusal is the error.
async fn carry(
    round: &Round<'_>,
    waiting: &mut Waiting,
    document: &Value,
    kind: WitnessDocument,
    witness_did: &str,
) -> Result<Value, WitnessError> {
    round
        .carrier
        .send(document)
        .await
        .map_err(|reason| WitnessError::Send {
            document: kind.name(),
            reason,
        })?;
    match waiting
        .answer(
            document,
            kind,
            witness_did,
            round.resolver,
            round.answer_timeout,
        )
        .await?
    {
        WitnessReply::Answered(answer) => Ok(answer),
        WitnessReply::Refused {
            refusal,
            code,
            message,
        } => Err(WitnessError::Refused {
            refusal,
            code,
            message,
        }),
    }
}

// ─── What is kept ────────────────────────────────────────────────────────────

/// A completed witnessing, as this client keeps it.
///
/// The VWC and its evidence are also in the VTA's credential vault (the VTA stores them at
/// `accept`); this copy is what the relationships view shows and what a personhood assertion
/// presents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WitnessRecord {
    /// The relationship, by the other party's persona DID (the relationships map's key).
    pub remote_p_did: String,
    /// Our DID in the relationship.
    pub relationship_did: String,
    pub witnessed_at: DateTime<Utc>,
    #[serde(flatten)]
    pub witnessed: Witnessed,
}

/// Every witnessing this account completed. Skipped when empty, so a config that has never
/// witnessed round-trips byte-identically.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Witnessings(pub Vec<WitnessRecord>);

impl Witnessings {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn push(&mut self, record: WitnessRecord) {
        self.0.push(record);
    }

    /// The witnessings of one relationship, oldest first.
    pub fn for_relationship<'a>(
        &'a self,
        remote_p_did: &'a str,
    ) -> impl Iterator<Item = &'a WitnessRecord> + 'a {
        self.0
            .iter()
            .filter(move |r| r.remote_p_did == remote_p_did)
    }

    /// Forget a relationship's witnessings, when the relationship is removed.
    pub fn remove_relationship(&mut self, remote_p_did: &str) {
        self.0.retain(|r| r.remote_p_did != remote_p_did);
    }
}

/// The VWCs and the `ext` a personhood assertion carries for the witnessings the member
/// **selected**, by session id: each selected VWC goes in the presentation, and its session's
/// outcome evidence beside it, in `ext["org.openvtc.witness"].outcomeEvidence` — without which a
/// VTC counts no VWC (`noOutcomeEvidence`).
///
/// Exactly the selected ones, in the order selected, and nothing at all when nothing is: a VWC
/// tells the community that a relationship exists and which witness attested it, so none is
/// disclosed unless the member chose it for this assertion. A selected id with no record (or a
/// record with no VWC) is skipped. The caller keeps a selection within
/// [`MAX_OUTCOME_EVIDENCE`]; nothing here drops a selected entry to fit.
pub fn personhood_ext<'a>(
    records: impl IntoIterator<Item = &'a WitnessRecord>,
    selected: &[String],
) -> (Vec<Value>, Option<Value>) {
    let records: Vec<&WitnessRecord> = records.into_iter().collect();
    let chosen: Vec<&WitnessRecord> = selected
        .iter()
        .filter_map(|id| {
            records
                .iter()
                .find(|r| &r.witnessed.session_id == id && r.witnessed.vwc().is_some())
                .copied()
        })
        .collect();
    if chosen.is_empty() {
        return (Vec::new(), None);
    }
    let vwcs = chosen
        .iter()
        .filter_map(|r| r.witnessed.vwc().cloned())
        .collect();
    let evidence: Vec<Value> = chosen
        .iter()
        .map(|r| r.witnessed.evidence.clone())
        .collect();
    (
        vwcs,
        Some(json!({ WITNESS_EXT: { "outcomeEvidence": evidence } })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELATIONSHIP: &str = "did:peer:2.Vz6MkRelationship";
    const WITNESS: &str = "did:key:z6MkWitness";
    const SESSION: &str = "urn:uuid:9e8d7c6b-0000-4000-8000-0000000000aa";

    fn session_doc() -> Value {
        json!({
            "id": SESSION,
            "threadId": SESSION,
            "type": session_type(),
            "issuer": RELATIONSHIP,
            "recipient": WITNESS,
            "issuedAt": "2026-10-15T10:00:00Z",
            "payload": {},
            "proof": { "type": "DataIntegrityProof" }
        })
    }

    fn submit_doc() -> Value {
        json!({
            "id": "urn:uuid:submit-1",
            "threadId": SESSION,
            "type": submit_type(),
            "issuer": RELATIONSHIP,
            "recipient": WITNESS,
            "issuedAt": "2026-10-15T10:00:05Z",
            "payload": { "vp": {} },
            "proof": { "type": "DataIntegrityProof" }
        })
    }

    fn check(doc: &Value, kind: WitnessDocument) -> Result<(), WitnessError> {
        check_witness_document(doc, kind, SESSION, RELATIONSHIP, WITNESS)
    }

    fn refused(r: Result<(), WitnessError>, needle: &str) {
        match r {
            Err(WitnessError::Document(reason)) => {
                assert!(
                    reason.contains(needle),
                    "expected `{needle}`, got `{reason}`"
                )
            }
            other => panic!("expected a refusal mentioning `{needle}`, got {other:?}"),
        }
    }

    /// Only the session's own documents, issued by the relationship DID and addressed to the
    /// witness that was named, are sent in the relationship's name.
    #[test]
    fn only_the_sessions_own_documents_are_carried() {
        check(&session_doc(), WitnessDocument::Session).expect("the session document");
        check(&submit_doc(), WitnessDocument::Submit).expect("the submit document");

        refused(check(&session_doc(), WitnessDocument::Submit), "not a");
        refused(check(&submit_doc(), WitnessDocument::Session), "not a");

        let mut other_session = submit_doc();
        other_session["threadId"] = json!("urn:uuid:another-session");
        refused(check(&other_session, WitnessDocument::Submit), "threadId");

        let mut elsewhere = session_doc();
        elsewhere["recipient"] = json!("did:key:z6MkSomeoneElse");
        refused(check(&elsewhere, WitnessDocument::Session), "addressed to");

        let mut foreign = submit_doc();
        foreign["issuer"] = json!("did:key:z6MkSomeoneElse");
        refused(check(&foreign, WitnessDocument::Submit), "issued by");

        let mut unsigned = submit_doc();
        unsigned.as_object_mut().unwrap().remove("proof");
        refused(check(&unsigned, WitnessDocument::Submit), "no proof");
    }

    #[test]
    fn the_witness_answers_are_recognised_and_nothing_else() {
        assert!(is_reply_type(&format!("{}#response", session_type())));
        assert!(is_reply_type(&format!("{}#response", submit_type())));
        assert!(!is_reply_type(session_type()));
        assert!(!is_reply_type(
            "https://trusttasks.org/spec/vtc/members/personhood/assert/0.1#response"
        ));
    }

    #[test]
    fn declared_refusals_are_told_apart() {
        assert_eq!(
            refusal_for("witness/session:refused"),
            WitnessRefusal::SessionRefused
        );
        assert_eq!(
            refusal_for("witness/session/submit:challengeMismatch"),
            WitnessRefusal::ChallengeMismatch
        );
        assert_eq!(
            refusal_for("witness/session/submit:presentationInvalid"),
            WitnessRefusal::PresentationInvalid
        );
        assert_eq!(refusal_for("malformedRequest"), WitnessRefusal::Other);
    }

    /// Each refusal reads as what the member can do about it, not as a code.
    #[test]
    fn a_refusal_says_what_to_do() {
        let member_link = WitnessError::VtaRefused {
            step: "open a witnessed session",
            code: "vta/witness/open:memberLinkUnsupported".into(),
            message: "no".into(),
        }
        .to_string();
        assert!(
            member_link.contains("member_link_witnesses"),
            "{member_link}"
        );

        let refused = WitnessError::Refused {
            refusal: WitnessRefusal::SessionRefused,
            code: "witness/session:refused".into(),
            message: Some("capacity".into()),
        }
        .to_string();
        assert!(refused.contains("Another witness may"), "{refused}");
        assert!(refused.contains("capacity"), "{refused}");

        let custody = vta_failure(
            "open a witnessed session",
            VtaError::Forbidden("no key".into()),
        )
        .to_string();
        assert!(custody.contains("re-established"), "{custody}");
    }

    #[tokio::test]
    async fn answers_reach_only_the_witnessing_waiting_on_their_thread() {
        let router = ReplyRouter::default();
        let mut waiting = router.wait_for(SESSION);
        assert!(router.is_waiting(SESSION));

        assert!(!router.deliver(WITNESS, json!({ "threadId": "urn:uuid:other" })));
        assert!(!router.deliver(WITNESS, json!({ "no": "thread" })));
        assert!(router.deliver(WITNESS, json!({ "threadId": SESSION, "n": 1 })));
        let got = waiting.replies.recv().await.expect("routed");
        assert_eq!(got.document["n"], 1);
        assert_eq!(got.sender, WITNESS);

        drop(waiting);
        assert!(
            !router.is_waiting(SESSION),
            "a finished witnessing stops routing"
        );
        assert!(!router.deliver(WITNESS, json!({ "threadId": SESSION })));
    }

    /// An answer that is not provably the witness's is not one: the wait runs out rather than
    /// ending on a forgery.
    #[tokio::test]
    async fn an_unverifiable_answer_is_discarded_and_the_wait_goes_on() {
        let router = ReplyRouter::default();
        let mut waiting = router.wait_for(SESSION);
        // From the right sender but unsigned, and from the wrong sender.
        let forged = json!({
            "id": "urn:uuid:x",
            "type": "https://trusttasks.org/spec/trust-task-error/0.5",
            "threadId": SESSION,
            "issuer": WITNESS,
            "recipient": RELATIONSHIP,
            "payload": { "code": "witness/session:refused", "retryable": false }
        });
        router.deliver(WITNESS, forged.clone());
        router.deliver("did:key:z6MkMallory", forged);
        let err = waiting
            .answer(
                &session_doc(),
                WitnessDocument::Session,
                WITNESS,
                &TrustTaskVmResolver::did_key_only(),
                Duration::from_millis(200),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, WitnessError::NoAnswer { .. }), "{err:?}");
    }

    fn doc_with(services: Value) -> Value {
        json!({ "id": "did:example:x", "service": services })
    }

    fn tsp(m: &str) -> Value {
        json!({ "id": "#tsp", "type": "TSPTransport", "serviceEndpoint": m })
    }

    fn didcomm(m: &str) -> Value {
        json!({ "id": "#didcomm", "type": "DIDCommMessaging", "serviceEndpoint": { "uri": m } })
    }

    #[test]
    fn the_route_is_the_best_transport_both_sides_advertise() {
        let both = |m| doc_with(json!([didcomm(m), tsp(m)]));
        assert_eq!(
            select_route(&both("did:m:ours"), &both("did:m:theirs"), WITNESS).unwrap(),
            WitnessRoute::Tsp {
                witness_mediator: "did:m:theirs".into()
            }
        );
        // A relationship DID as openvtc mints it advertises DIDComm only.
        assert_eq!(
            select_route(
                &doc_with(json!([didcomm("did:m:ours")])),
                &both("did:m:theirs"),
                WITNESS
            )
            .unwrap(),
            WitnessRoute::Didcomm
        );
        // REST is never a carrier: a witness answers the transport-proven sender.
        let rest = doc_with(json!([{ "id": "#rest", "type": "VTARest",
                                     "serviceEndpoint": "https://w.example" }]));
        assert!(matches!(
            select_route(&rest, &rest, WITNESS),
            Err(WitnessError::NoRoute(_))
        ));
    }

    fn record(at: i64, vwc: bool) -> WitnessRecord {
        let outcome = if vwc {
            json!({ "payload": { "vwc": { "id": format!("urn:vwc:{at}") } } })
        } else {
            json!({ "payload": {} })
        };
        WitnessRecord {
            remote_p_did: "did:webvh:bob".into(),
            relationship_did: RELATIONSHIP.into(),
            witnessed_at: DateTime::from_timestamp(at, 0).unwrap(),
            witnessed: Witnessed {
                session_id: format!("urn:uuid:{at}"),
                credential_id: format!("vwc-{at}"),
                witness: WITNESS.into(),
                vwc_digest_multibase: "z".into(),
                evidence: json!({ "session": { "id": format!("urn:uuid:{at}") }, "outcome": outcome }),
            },
        }
    }

    /// Nothing is disclosed unless selected; exactly the selected VWCs, each with its own
    /// evidence, are — whatever else the persona holds.
    #[test]
    fn personhood_carries_only_the_selected_vwcs() {
        let records: Vec<WitnessRecord> = (0..20).map(|i| record(i, true)).collect();

        // Default: no selection, no VWC, no ext.
        assert_eq!(personhood_ext(&records, &[]), (Vec::new(), None));

        let selected = vec!["urn:uuid:3".to_string(), "urn:uuid:17".to_string()];
        let (vwcs, ext) = personhood_ext(&records, &selected);
        assert_eq!(vwcs.len(), 2);
        assert_eq!(vwcs[0]["id"], "urn:vwc:3");
        assert_eq!(vwcs[1]["id"], "urn:vwc:17");
        let evidence = ext.unwrap()[WITNESS_EXT]["outcomeEvidence"].clone();
        assert_eq!(evidence.as_array().unwrap().len(), 2);
        assert_eq!(evidence[0]["session"]["id"], "urn:uuid:3");
        assert_eq!(evidence[1]["session"]["id"], "urn:uuid:17");

        // All twenty, when all twenty are selected: no rule drops any.
        let all: Vec<String> = records
            .iter()
            .map(|r| r.witnessed.session_id.clone())
            .collect();
        assert_eq!(personhood_ext(&records, &all).0.len(), 20);

        // An unknown id, or a record whose outcome carries no VWC, adds nothing.
        assert_eq!(
            personhood_ext(
                &[record(1, false)],
                &["urn:uuid:1".into(), "urn:uuid:x".into()]
            ),
            (Vec::new(), None)
        );
    }

    #[test]
    fn a_record_round_trips_and_an_empty_book_is_skipped() {
        let r = record(5, true);
        let back: WitnessRecord =
            serde_json::from_value(serde_json::to_value(&r).unwrap()).unwrap();
        assert_eq!(back, r);
        assert!(Witnessings::default().is_empty());
    }
}
