//! Pure protocol logic for inbound DIDComm message handling.
//!
//! These functions are the testable heart of the message-dispatch state
//! machine: they operate only over core domain types (`Account`, `Message`,
//! `Relationships`, `Tasks`, `DTGCredential`, `TDK`) and perform no async
//! I/O orchestration. The TUI's `process_inbound_message` orchestrator
//! imports and calls them.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use affinidi_tdk::{TDK, didcomm::Message};
use dtg_credentials::DTGCredential;
use serde_json::{Value, json};
use tracing::{debug, info, warn};
use uuid::Uuid;
use vta_sdk::protocols::join_requests::{
    JoinRequestStatusResponseBody, JoinRequestSubmitReceiptBody, VerdictEffect, VerdictResponse,
};
use vta_sdk::protocols::members::{RemovalCode, RemovalNoticeBody};

use crate::config::Config;
use crate::config::account::{Account, DecisionEvidence, PersonaId};
use crate::relationships::{RelationshipState, Relationships};
use crate::tasks::{TaskType, Tasks};

/// Reject inbound messages whose `created_time` is older than this. The
/// outbound side stamps a 48-hour expiry, so a 48-hour replay window is
/// the same horizon — anything older is either a replay or a clock skew
/// pathology and is safer to drop.
pub const MAX_MESSAGE_AGE_SECS: u64 = 48 * 60 * 60;

/// How far in the future a `created_time` may be before we treat it as
/// invalid (clock skew tolerance).
pub const MAX_FUTURE_SKEW_SECS: u64 = 5 * 60;

/// Maximum number of tasks allowed before rejecting new inbound messages.
pub const MAX_TASKS: usize = 10_000;

/// Standard message expiry: 48 hours.
pub const MESSAGE_EXPIRY_SECS: u64 = 60 * 60 * 48;

/// Build a timestamped DIDComm message with standard 48-hour expiry.
pub fn build_didcomm_message(
    type_url: &str,
    body: serde_json::Value,
    from: &str,
    to: &str,
    thid: Option<&str>,
) -> Result<Message, anyhow::Error> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut builder = Message::build(Uuid::new_v4().to_string(), type_url.to_string(), body)
        .from(from.to_string())
        .to(to.to_string())
        .created_time(now)
        .expires_time(now + MESSAGE_EXPIRY_SECS);
    if let Some(t) = thid {
        builder = builder.thid(t.to_string());
    }
    Ok(builder.finalize())
}

/// Bounded LRU of recently-seen message IDs used to deduplicate replays.
/// 1024 entries is comfortable for an active operator without bloating
/// memory; entries are O(36) bytes each (UUID).
pub struct SeenMessages {
    cap: usize,
    order: VecDeque<String>,
    set: HashSet<String>,
}

impl SeenMessages {
    /// New LRU with the default 1024-entry capacity.
    pub fn new() -> Self {
        Self::with_capacity(1024)
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            cap,
            order: VecDeque::with_capacity(cap),
            set: HashSet::with_capacity(cap),
        }
    }

    /// Returns `true` if `id` was already present (i.e. caller should
    /// reject as a replay). Otherwise records `id` and returns `false`.
    pub fn observe(&mut self, id: &str) -> bool {
        if self.set.contains(id) {
            return true;
        }
        if self.order.len() == self.cap
            && let Some(evicted) = self.order.pop_front()
        {
            self.set.remove(&evicted);
        }
        self.order.push_back(id.to_string());
        self.set.insert(id.to_string());
        false
    }
}

impl Default for SeenMessages {
    fn default() -> Self {
        Self::new()
    }
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Validate the message timestamps. Returns `Err(reason)` if the message
/// should be dropped as too old, expired, or implausibly future-dated.
pub fn check_message_age(message: &Message) -> Result<(), &'static str> {
    let now = unix_now();
    if let Some(created) = message.created_time {
        if created > now.saturating_add(MAX_FUTURE_SKEW_SECS) {
            return Err("created_time too far in future");
        }
        if now.saturating_sub(created) > MAX_MESSAGE_AGE_SECS {
            return Err("created_time older than replay window");
        }
    }
    if let Some(expires) = message.expires_time
        && expires < now
    {
        return Err("message already expired");
    }
    Ok(())
}

/// Check that a new task can be created: no ID collision and under capacity limits.
/// Returns Ok(()) or logs a warning and returns Err(()).
///
/// The `Result<(), ()>` shape is intentional — the only failure signal the
/// caller needs is "don't create the task"; the reason is already logged here.
/// Preserved verbatim from the pre-R17 TUI helper (now `pub` for the
/// orchestrator), so an `allow` keeps the signature unchanged.
#[allow(clippy::result_unit_err)]
pub fn check_task_capacity(
    config: &Config,
    task_id: &Arc<String>,
    from_did: &Arc<String>,
) -> Result<(), ()> {
    if config.private.tasks.get_by_id(task_id).is_some() {
        warn!(task_id = %task_id, from = %from_did, "rejecting duplicate task ID");
        return Err(());
    }
    if config.private.tasks.tasks.len() >= MAX_TASKS {
        warn!(
            "task limit reached ({}) — rejecting inbound message",
            MAX_TASKS
        );
        return Err(());
    }
    Ok(())
}

/// Reconcile a VTC `join-requests/submit-receipt` onto the matching Pending
/// community record: replace the placeholder request id (our submit message id,
/// echoed back as the receipt's `thid`) with the VTC's authoritative
/// `requestId`. The receipt must come from the community's own VTC DID
/// (anti-spoof) and match the placeholder we stored at submit time.
///
/// Returns `true` if a record was updated (Config needs saving).
pub fn handle_join_submit_receipt(
    account: &mut Account,
    message: &Message,
    from_did: &str,
) -> bool {
    let Some(thid) = message.thid.as_deref() else {
        warn!("join submit-receipt without thid — cannot correlate; ignoring");
        return false;
    };
    let placeholder = match Uuid::parse_str(thid) {
        Ok(u) => u,
        Err(e) => {
            warn!(thid, error = %e, "join submit-receipt thid is not a uuid — ignoring");
            return false;
        }
    };
    let body: JoinRequestSubmitReceiptBody = match serde_json::from_value(message.body.clone()) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "malformed join submit-receipt body — ignoring");
            return false;
        }
    };

    // Correlate to the specific pending membership (a community may now hold
    // several, one per persona) by the placeholder = our submit id.
    let Some(record) = account.membership_by_pending_request(from_did, placeholder) else {
        warn!(
            vtc = %from_did,
            thid,
            "join submit-receipt did not match a pending join with that id — ignoring",
        );
        return false;
    };
    // Adopt the VTC's id in place of our placeholder — and record that it *is*
    // the VTC's, which is what makes this join askable-about later.
    record.confirm_request_id(body.request_id);
    // The receipt is the VTC's acknowledgement that the submit arrived.
    record.mark_acknowledged(chrono::Utc::now());
    info!(
        vtc = %from_did,
        vtc_request_id = %body.request_id,
        receipt_status = %body.status,
        "reconciled join request id from VTC submit-receipt",
    );
    true
}

/// What a `credential-exchange/issue` did, beyond mutating the account.
///
/// A `bool` could not carry the one thing the caller needs: membership between
/// a persona and a VTC is a *pair* of credentials, and receiving the
/// community's half is the moment the member owes theirs back. Closing the
/// join that way is what `vtc/members/vmc/0.1`'s `requestId` is for.
///
/// The id has to be reported from here because activation destroys it —
/// `activate` replaces `Pending { request_id }` with `Active`, so by the time
/// the caller looks, there is nothing to read. That is why every reciprocal
/// VMC this client has ever sent carried `requestId: None`, leaving the
/// community's join request sitting `Approved` forever.
///
/// Modelled on [`StatusOutcome`], for the same reason it exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialIssueOutcome {
    /// A record changed and the config needs saving.
    pub changed: bool,
    /// The membership just went Active, closing this join request — the
    /// persona that owes the community its reciprocal VMC, and the request id
    /// that delivery should name. `None` when this credential did not admit
    /// anyone (a role VEC on an already-active membership, say).
    pub closed_join: Option<(PersonaId, uuid::Uuid)>,
}

impl CredentialIssueOutcome {
    pub const NONE: CredentialIssueOutcome = CredentialIssueOutcome {
        changed: false,
        closed_join: None,
    };
}

/// What an inbound DIDComm problem-report meant to the join handler.
///
/// A problem-report says "I refused the thing you sent me". This handler can
/// only interpret one kind: a refusal threaded on a *pending join request*. It
/// used to return an empty [`StatusOutcome`] for everything else and log a warn
/// naming the correlation miss — so a community refusing anything else at all
/// produced, on this client, nothing a user could see.
///
/// That is how the broken reciprocal-VMC exchange stayed invisible for its
/// entire life: the VTC rejected every delivery, said so in a problem-report
/// threaded on the delivery, and this client discarded each one as "not a join
/// I know about" while the UI reported the send as a success.
///
/// So the miss is now reportable rather than swallowed. This handler still
/// declines to *interpret* a report it cannot correlate — it genuinely does not
/// know what failed — but it hands the code and comment back so the caller can
/// put them where somebody will read them.
pub struct ProblemReportOutcome {
    /// The record change, if this report was a join refusal.
    pub status: StatusOutcome,
    /// `Some((code, comment))` when the report could not be matched to a
    /// pending join — i.e. it refused something else this client sent, and
    /// nothing here knows what. Surface it; do not drop it.
    pub unclaimed: Option<(String, String)>,
}

impl ProblemReportOutcome {
    /// A report this handler recognised and acted on.
    fn claimed(status: StatusOutcome) -> Self {
        Self {
            status,
            unclaimed: None,
        }
    }
}

/// Outcome of applying a VTC `join-requests/status-response` to a community.
pub struct StatusOutcome {
    /// The community record changed and the config needs saving.
    pub changed: bool,
    /// When the membership transitioned to an inactive (read-only) status, the
    /// persona whose session for this community must be deregistered (R-S-3 /
    /// D15) — `None` when nothing inactivated. Carrying the persona (not just a
    /// bool) is required for multi-membership: the VTC alone no longer identifies
    /// which session to tear down.
    pub inactivated: Option<PersonaId>,
}

impl StatusOutcome {
    const NONE: StatusOutcome = StatusOutcome {
        changed: false,
        inactivated: None,
    };
}

/// Extract the task-specific *payload* from a VTC Trust Task reply body.
///
/// The VTC replies to a Trust Task in one of two shapes, and which one you get
/// depends on how the reply was built, not on the message type:
///
/// - Anything dispatched through `dispatch_trust_task_core` is returned by
///   `vtc-service`'s `tt_didcomm_reply`, which sets the DIDComm body to the
///   **whole `#response` document** — `{id, threadId, type, issuer, …,
///   payload}` — with the task-specific members nested under `payload`. The
///   join verdict and the status response arrive this way.
/// - Replies the VTC hand-builds as a `Reply` carry the **bare body** with no
///   document around it. `join-requests/submit-receipt` arrives this way.
///
/// So a handler cannot deserialize the body directly and be right for both.
/// Prefer `payload` when present, else take the body whole: none of the bare
/// reply bodies has a `payload` member, so the test is unambiguous.
///
/// This also makes the handlers transport-agnostic. A TSP frame carries the
/// response document raw, with no DIDComm envelope around it, so it normalises
/// into exactly the document shape this already accepts (#185).
fn trust_task_reply_payload(body: &Value) -> Value {
    match body.get("payload") {
        Some(payload) => payload.clone(),
        None => body.clone(),
    }
}

/// Apply a VTC `join-requests/status-response` to the matching Pending community
/// (R-B-8). Correlated by the body's `request_id` against the Pending record's
/// stored id, and gated on the sender being the community's own VTC (anti-spoof).
/// Maps the protocol status onto the membership lifecycle:
///
/// - `approved` → `Active` (also reached via the issued VMC in
///   [`handle_credential_issue`]; idempotent here).
/// - `rejected` → `Rejected` (inactive — the caller deregisters the session).
/// - `deferred` → stays `Pending` ("more info required"); the content handling
///   (evaluating `needs` / presenting the DCQL) is a **D4 stub**, and a Pending
///   record already raises actions-required (R-S-2).
/// - `pending` / `withdrawn` / unknown → no transition (withdrawal is the
///   member-initiated leave, owned by T7).
pub fn handle_join_status_response(
    account: &mut Account,
    message: &Message,
    from_did: &str,
) -> StatusOutcome {
    let body: JoinRequestStatusResponseBody =
        match serde_json::from_value(trust_task_reply_payload(&message.body)) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "malformed join status-response body — ignoring");
                return StatusOutcome::NONE;
            }
        };
    // Correlate to the specific pending membership by the authoritative
    // request id (a community may hold several memberships).
    let Some(record) = account.membership_by_pending_request(from_did, body.request_id) else {
        warn!(vtc = %from_did, "status-response did not match a pending request id — ignoring");
        return StatusOutcome::NONE;
    };
    let persona = record.persona_ref;

    match body.status.as_str() {
        "approved" => {
            record.activate(chrono::Utc::now());
            info!(vtc = %from_did, "join approved by VTC — now Active");
            StatusOutcome {
                changed: true,
                inactivated: None,
            }
        }
        "rejected" => {
            // The poll is the recovery path for a rejection whose correlated
            // verdict was missed (dropped socket, decision taken while offline).
            // It now carries the decision's own code/reason/time — so a
            // re-fetched rejection persists the same evidence a live verdict
            // would have (issue #240). A rejection decided before the VTC
            // exposed these leaves them absent → "no reason given".
            record.reject(DecisionEvidence {
                code: body.code.clone(),
                reason: body.reason.clone(),
                decided_by: None,
                decided_at: body.decided_at,
                disposition: None,
            });
            info!(
                vtc = %from_did,
                code = body.code.as_deref().unwrap_or(""),
                "join rejected by VTC"
            );
            StatusOutcome {
                changed: true,
                inactivated: Some(persona),
            }
        }
        "withdrawn" => {
            // The VTC reports the request withdrawn — reconcile our local record
            // (it may have been cancelled from another client). `withdraw` is a
            // no-op unless still Pending.
            let changed = record.withdraw();
            info!(vtc = %from_did, "join withdrawn — reconciled to Withdrawn");
            StatusOutcome {
                changed,
                inactivated: changed.then_some(persona),
            }
        }
        "deferred" => {
            // "More info required" — stays Pending (still raises actions-required);
            // evaluating `needs` / presenting the DCQL is deferred to D4. The VTC
            // responded, so the submit was acknowledged (not dropped).
            let changed = record.mark_acknowledged(chrono::Utc::now());
            info!(
                vtc = %from_did,
                needs = ?body.needs,
                "join deferred — more information required (handling deferred to D4)"
            );
            StatusOutcome {
                changed,
                inactivated: None,
            }
        }
        other => {
            debug!(vtc = %from_did, status = %other, "status-response: no transition");
            StatusOutcome::NONE
        }
    }
}

/// Handle a VTC join-request `submit/#response` carrying a [`VerdictResponse`] —
/// the synchronous admission decision in the trust-task join model (it replaces
/// the old submit-receipt → status-response path). Correlate by `thid` = our
/// submit message id (the placeholder held on the `Pending` record), then map
/// the verdict effect: `allow` → Active, `deny` → Rejected; `refer` /
/// `request_more` leave the record Pending (logged — they still raise the
/// actions-required indicator). Mirrors [`handle_join_status_response`].
pub fn handle_join_verdict(
    account: &mut Account,
    message: &Message,
    from_did: &str,
) -> StatusOutcome {
    let Some(thid) = message.thid.as_deref() else {
        warn!("join verdict without thid — cannot correlate; ignoring");
        return StatusOutcome::NONE;
    };
    let Ok(placeholder) = Uuid::parse_str(thid) else {
        warn!(thid = %thid, "join verdict thid is not a uuid — ignoring");
        return StatusOutcome::NONE;
    };
    let body: VerdictResponse =
        match serde_json::from_value(trust_task_reply_payload(&message.body)) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "malformed join verdict body — ignoring");
                return StatusOutcome::NONE;
            }
        };
    let Some(record) = account.membership_by_pending_request(from_did, placeholder) else {
        warn!(vtc = %from_did, "verdict did not match a pending request id — ignoring");
        return StatusOutcome::NONE;
    };
    let persona = record.persona_ref;

    match body.verdict.effect {
        VerdictEffect::Allow => {
            record.activate(chrono::Utc::now());
            info!(vtc = %from_did, "join allowed by VTC — now Active");
            StatusOutcome {
                changed: true,
                inactivated: None,
            }
        }
        VerdictEffect::Deny => {
            // Adopt the VTC's request id and stamp acknowledgement, as the
            // Refer/RequestMore arms do — a denial is just as much a correlated
            // response, and leaving `receipt_at` unset made it read like a
            // dropped submit. Persist the policy's own code + reason as the
            // decision evidence (issue #240). No decision time on the verdict
            // wire, so `decided_at` stays absent here.
            record.confirm_request_id(body.request_id);
            record.mark_acknowledged(chrono::Utc::now());
            record.reject(DecisionEvidence {
                code: body.verdict.with.code.clone(),
                reason: body.verdict.with.reason.clone(),
                decided_by: None,
                decided_at: None,
                disposition: None,
            });
            info!(
                vtc = %from_did,
                code = body.verdict.with.code.as_deref().unwrap_or(""),
                reason = body.verdict.with.reason.as_deref().unwrap_or(""),
                "join denied by VTC policy — now Rejected"
            );
            StatusOutcome {
                changed: true,
                inactivated: Some(persona),
            }
        }
        VerdictEffect::Refer => {
            // The VTC responded — submit acknowledged — but the decision is
            // deferred to human review; stays Pending.
            //
            // The verdict envelope carries the VTC's own `requestId`, which this
            // used to read past: correlation is by `thid`, so nothing needed it.
            // A referred join is precisely the one that then sits Pending for as
            // long as a human takes, and without adopting the id here there is
            // no handle to ask about it with — the answer arrives only if the
            // VTC volunteers it.
            let changed = record.confirm_request_id(body.request_id)
                | record.mark_acknowledged(chrono::Utc::now());
            info!(
                vtc = %from_did,
                queue = body.verdict.with.queue.as_deref().unwrap_or(""),
                "join referred for human review — stays Pending"
            );
            StatusOutcome {
                changed,
                inactivated: None,
            }
        }
        VerdictEffect::RequestMore => {
            // The VTC responded — submit acknowledged — but needs more evidence;
            // stays Pending. Adopt its request id for the same reason `Refer`
            // does: this join outlives the exchange that produced it.
            let changed = record.confirm_request_id(body.request_id)
                | record.mark_acknowledged(chrono::Utc::now());
            info!(
                vtc = %from_did,
                needs = ?body.verdict.with.needs,
                "join needs more evidence — stays Pending"
            );
            StatusOutcome {
                changed,
                inactivated: None,
            }
        }
    }
}

/// Handle a DIDComm problem-report threaded to our join submit — the framework
/// failure path of the trust-task join (invalid/expired/malformed VIC, bad
/// signature). Correlate by `thid`, then branch on the `e.p.msg.*` code:
/// `forbidden` (the invitation was not accepted) → Rejected, surfacing the
/// `comment`; any other code (bad-request / internal) is logged but leaves the
/// record Pending (it's a transient/client problem, not a policy rejection).
pub fn handle_join_problem_report(
    account: &mut Account,
    message: &Message,
    from_did: &str,
) -> ProblemReportOutcome {
    use vta_sdk::protocols::problem_report_codes as codes;

    let (code, comment) = vta_sdk::protocols::extract_problem_report(&message.body);
    let unclaimed = || ProblemReportOutcome {
        status: StatusOutcome::NONE,
        unclaimed: Some((code.clone(), comment.clone())),
    };

    let Some(thid) = message.thid.as_deref() else {
        return unclaimed();
    };
    let Ok(placeholder) = Uuid::parse_str(thid) else {
        return unclaimed();
    };
    let Some(record) = account.membership_by_pending_request(from_did, placeholder) else {
        return unclaimed();
    };
    let persona = record.persona_ref;

    if code == codes::FORBIDDEN {
        // The problem-report's `comment` is free text; keep it verbatim as the
        // reason, and the report `code` as the code (issue #240). An empty
        // comment is "no reason given", not an empty reason.
        record.reject(DecisionEvidence {
            code: Some(code.clone()),
            reason: (!comment.is_empty()).then(|| comment.clone()),
            decided_by: None,
            decided_at: None,
            disposition: None,
        });
        info!(
            vtc = %from_did,
            comment = %comment,
            "join rejected by VTC — invitation not accepted (now Rejected)"
        );
        ProblemReportOutcome::claimed(StatusOutcome {
            changed: true,
            inactivated: Some(persona),
        })
    } else {
        // bad-request / internal / other: the submit didn't admit, but it's not a
        // policy rejection — surface the detail and leave the record Pending.
        warn!(vtc = %from_did, code = %code, comment = %comment, "join submit failed — left Pending");
        ProblemReportOutcome::claimed(StatusOutcome::NONE)
    }
}

/// Type-URI prefix of a framework `trust-task-error` document, version-agnostic
/// (`…/trust-task-error/0.1`, `/0.2`, …). Trust Task ceremony *failures* arrive
/// as these documents — never DIDComm problem-reports — so the dispatcher routes
/// any inbound message whose type starts with this prefix to
/// [`handle_join_trust_task_error`].
pub const TRUST_TASK_ERROR_TYPE_PREFIX: &str = "https://trusttasks.org/spec/trust-task-error/";

/// Whether `typ` is a framework `trust-task-error` document type (any version).
pub fn is_trust_task_error_type(typ: &str) -> bool {
    typ.starts_with(TRUST_TASK_ERROR_TYPE_PREFIX)
}

/// Whether a `trust-task-error` `code` is a definitive authorization denial of
/// the join (→ terminal `Rejected`) rather than a recoverable client / transient
/// failure (→ stays `Pending`). Denials won't succeed on a plain retry; the user
/// must act (different invitation, different identity, request access).
fn is_join_denial_code(code: &str) -> bool {
    matches!(code, "permissionDenied" | "forbidden" | "identityMismatch")
}

/// Handle a framework `trust-task-error` document threaded to our join submit —
/// the Trust Task ceremony failure path (malformed request, denied, internal, …)
/// that replaces the DIDComm problem-report for Trust Tasks. Without this, a
/// failed ceremony was an unknown message type and silently dropped, leaving the
/// membership stuck `Pending` forever.
///
/// Correlate by `thid` = our submit message id (the placeholder on the `Pending`
/// record), then branch on the error `code`:
///
/// - A definitive authorization denial (`permissionDenied` / `forbidden` /
///   `identityMismatch`) → `Rejected` (terminal; inactivates the session so the
///   loop deregisters it). Mirrors the `forbidden` branch of
///   [`handle_join_problem_report`].
/// - Any other code (malformed / unsupported / internal / unavailable / …) is a
///   client or transient failure, not a policy decision: surface the detail and
///   leave the record `Pending` so a corrected retry can still succeed.
pub fn handle_join_trust_task_error(
    account: &mut Account,
    message: &Message,
    from_did: &str,
) -> StatusOutcome {
    let Some(thid) = message.thid.as_deref() else {
        warn!("join trust-task-error without thid — cannot correlate; ignoring");
        return StatusOutcome::NONE;
    };
    let Ok(placeholder) = Uuid::parse_str(thid) else {
        warn!(thid = %thid, "join trust-task-error thid is not a uuid — ignoring");
        return StatusOutcome::NONE;
    };
    // Read the failure detail straight from the document body rather than parsing
    // a typed `TrustTask<ErrorPayload>`: the typed payload has required members
    // (e.g. `retryable`) that vary across framework versions, and a strict parse
    // would silently drop a failure we specifically want to surface. The
    // dispatcher already gated on the trust-task-error type; `from_did` + `thid`
    // are the anti-spoof / correlation gates below.
    let code = message
        .body
        .pointer("/payload/code")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let detail = message
        .body
        .pointer("/payload/message")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let Some(record) = account.membership_by_pending_request(from_did, placeholder) else {
        warn!(vtc = %from_did, code = %code, "trust-task-error did not match a pending request id — ignoring");
        return StatusOutcome::NONE;
    };

    if is_join_denial_code(&code) {
        // Persist the ceremony error's code + human `message` as the decision
        // evidence (issue #240). No decision time on this document.
        record.reject(DecisionEvidence {
            code: (!code.is_empty()).then(|| code.clone()),
            reason: (!detail.is_empty()).then(|| detail.clone()),
            decided_by: None,
            decided_at: None,
            disposition: None,
        });
        info!(
            vtc = %from_did,
            code = %code,
            detail = %detail,
            "join denied by VTC (trust-task-error) — now Rejected"
        );
        StatusOutcome {
            changed: true,
            inactivated: Some(record.persona_ref),
        }
    } else {
        // Not a policy denial — a malformed / unsupported / internal / transient
        // failure. Surface it, but keep the join recoverable (stays Pending) so a
        // corrected retry can still succeed. The VTC did respond, so the submit
        // was acknowledged (not silently dropped).
        let changed = record.mark_acknowledged(chrono::Utc::now());
        warn!(
            vtc = %from_did,
            code = %code,
            detail = %detail,
            "join submit failed (trust-task-error) — left Pending (recoverable)"
        );
        StatusOutcome {
            changed,
            inactivated: None,
        }
    }
}

/// Handle a VTC → member **removal notice** (`vtc/members/removal-notice/0.1`):
/// the community telling a member it removed them (issue #240). Unlike every
/// join-decision path above it is *unsolicited* — not threaded on any request we
/// sent — so it is correlated by its two named parties instead: the sender
/// (`from_did`, the community's VTC) and the removed member's persona
/// (`body.did`, which must be one of ours).
///
/// Transitions the matching **Active** membership to `Removed`, persisting the
/// notice's authority (`decided_by`), reason, decision time (`decided_at`) and
/// disposition as [`DecisionEvidence`]. `inactivated` names the persona so the
/// loop tears down its now-defunct session, as a rejection does.
///
/// Ignored (no transition) when it names no persona of ours, no membership of
/// that community as that persona, or a membership that is not Active — a stale
/// or duplicate notice must not clobber a `Left` the member chose, and the
/// removed member can no longer authenticate to the community to be told twice.
pub fn handle_member_removal_notice(
    account: &mut Account,
    message: &Message,
    from_did: &str,
) -> StatusOutcome {
    let body: RemovalNoticeBody = match serde_json::from_value(message.body.clone()) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "malformed removal-notice body — ignoring");
            return StatusOutcome::NONE;
        }
    };
    let Some(persona) = account.persona_id_for_did(&body.did) else {
        warn!(
            vtc = %from_did,
            "removal-notice names a DID that is not one of our personas — ignoring"
        );
        return StatusOutcome::NONE;
    };
    let Some(record) = account.membership_mut(from_did, persona) else {
        warn!(
            vtc = %from_did,
            "removal-notice for a community we hold no membership of as that persona — ignoring"
        );
        return StatusOutcome::NONE;
    };
    if !record.status.is_active() {
        // A removal only applies to an active member. A notice arriving for a
        // membership already terminal (a Left the member chose, an earlier
        // Removed) is stale or duplicate; applying it would overwrite the
        // member's own account of how it ended.
        info!(
            vtc = %from_did,
            status = ?record.status,
            "removal-notice for a non-active membership — ignoring"
        );
        return StatusOutcome::NONE;
    }
    // `decided_at` is RFC 3339 on the wire; keep the rest of the evidence even if
    // it fails to parse rather than dropping the whole notice.
    let decided_at = chrono::DateTime::parse_from_rfc3339(&body.decided_at)
        .map(|d| d.with_timezone(&chrono::Utc))
        .ok();
    let code = match body.code {
        RemovalCode::AdminRemoved => "adminRemoved",
        RemovalCode::Purged => "purged",
    };
    record.remove(DecisionEvidence {
        code: Some(code.to_string()),
        reason: body.reason.clone(),
        decided_by: Some(body.decided_by.clone()),
        decided_at,
        disposition: Some(body.disposition.clone()),
    });
    info!(
        vtc = %from_did,
        code = %code,
        disposition = %body.disposition,
        decided_by = %body.decided_by,
        "removed from community by VTC — now Removed"
    );
    StatusOutcome {
        changed: true,
        inactivated: Some(persona),
    }
}

/// Handle a VTC `credential-exchange/issue`: store the issued credential on the
/// matching community and, for the membership credential (VMC), flip the
/// membership to `Active`. The issuing VTC is the authcrypt sender; the
/// credential must be issued by that VTC and to the community's own persona
/// (anti-misdelivery).
///
/// See [`CredentialIssueOutcome`] for why this reports the join request it
/// closed rather than just whether anything changed.
pub fn handle_credential_issue(
    account: &mut Account,
    message: &Message,
    from_did: &str,
) -> CredentialIssueOutcome {
    // The known-holder delivery carries the VC at `credential_response.credential`.
    // `sealed` issues (invite / air-gap) are not handled here.
    let Some(credential) = message
        .body
        .get("credential_response")
        .and_then(|cr| cr.get("credential"))
        .cloned()
    else {
        warn!(vtc = %from_did, "credential-issue without credential_response.credential — ignoring");
        return CredentialIssueOutcome::NONE;
    };

    // Anti-misdelivery: issuer must be this community's VTC. The credential's
    // subject (a persona DID) also selects WHICH membership it is for — a
    // community may now hold several, one per persona.
    let issuer = credential.get("issuer").and_then(|i| match i {
        Value::String(s) => Some(s.as_str()),
        Value::Object(o) => o.get("id").and_then(Value::as_str),
        _ => None,
    });
    if issuer != Some(from_did) {
        warn!(vtc = %from_did, ?issuer, "issued credential's issuer is not the community VTC — ignoring");
        return CredentialIssueOutcome::NONE;
    }
    let Some(subject) = credential
        .get("credentialSubject")
        .and_then(|s| s.get("id"))
        .and_then(Value::as_str)
    else {
        warn!(vtc = %from_did, "issued credential has no subject — ignoring");
        return CredentialIssueOutcome::NONE;
    };
    // The subject must be one of our personas, and that persona must hold a
    // membership with this community.
    let Some(persona_id) = account.persona_id_for_did(subject) else {
        warn!(vtc = %from_did, "issued credential subject is not our persona — ignoring");
        return CredentialIssueOutcome::NONE;
    };

    // Classify the credential against the typed registry — the one place that
    // knows credential kinds, so a new kind is handled here without edits.
    let Some(kind) = crate::CredentialKind::from_credential(&credential) else {
        warn!(vtc = %from_did, "issued credential is of no known kind — ignoring");
        return CredentialIssueOutcome::NONE;
    };

    let Some(record) = account.membership_mut(from_did, persona_id) else {
        warn!(vtc = %from_did, "credential-issue for a community we don't hold a matching membership with — ignoring");
        return CredentialIssueOutcome::NONE;
    };
    record.credentials.insert(kind, credential);

    // Capture the join request id *before* activating. `activate` replaces
    // `Pending { request_id }` with `Active`, so this is the last moment the
    // id exists — which is why a caller could not simply read it back
    // afterwards and why the reciprocal VMC has always gone out with
    // `requestId: None`.
    let closed_join = if kind.activates_membership() && !record.status.is_active() {
        let request_id = match record.status {
            crate::config::account::CommunityStatus::Pending { request_id } => Some(request_id),
            _ => None,
        };
        record.activate(chrono::Utc::now());
        request_id.map(|id| (persona_id, id))
    } else {
        None
    };
    info!(
        vtc = %from_did,
        credential_kind = %kind.config_key(),
        // Whether this kind activates membership — distinct from the record's
        // resulting `status`, which may already have been active.
        activates_membership = kind.activates_membership(),
        "stored issued credential",
    );
    CredentialIssueOutcome {
        changed: true,
        closed_join,
    }
}

/// Vet an inbound `VRCIssued` message against local state (task R2).
///
/// Gates enforced:
/// 1. the authenticated DIDComm sender must map to an `Established`
///    relationship (same gate as the `VRCRequest` arm);
/// 2. the credential's `issuer` must be that relationship's remote persona
///    DID. VRCs are signed with the issuer's persona DID while the DIDComm
///    envelope may be sent from a relationship R-DID, so the binding goes
///    through the relationship record rather than naive `issuer == from`
///    string equality — this still pins the issuer to the authenticated
///    sender and rejects forged issuer strings;
/// 3. the message `thid` only resolves a pending task when that task is our
///    *own* outbound VRC request to this same sender. An attacker-chosen
///    `thid` must not be able to delete unrelated tasks.
///
/// Returns the task id of our pending outbound VRC request when the `thid`
/// legitimately resolves one, `Ok(None)` when there is no (matching) `thid`,
/// and `Err(reason)` when the message must be dropped.
pub fn vet_vrc_issued(
    relationships: &Relationships,
    tasks: &Tasks,
    vrc: &DTGCredential,
    from_did: &Arc<String>,
    thid: Option<&str>,
) -> Result<Option<Arc<String>>, String> {
    // Gate 1: sender must be an established relationship.
    let relationship = relationships
        .find_by_remote_did(from_did)
        .ok_or_else(|| "no relationship with sender".to_string())?;
    if relationship.state != RelationshipState::Established {
        return Err(format!(
            "relationship with sender is not established (state: {})",
            relationship.state
        ));
    }
    let remote_p_did = Arc::clone(&relationship.remote_p_did);

    // Gate 2: the issuer must be the identity the sender uses *in this
    // relationship* — their R-DID, or their persona DID for a relationship
    // established without one (`remote_did` equals `remote_p_did` there).
    //
    // This used to demand the persona DID, which forced the durable credential
    // to name an identity shared across every one of the sender's
    // relationships. Binding it to `remote_did` is also strictly tighter:
    // Gate 1 matched `from_did` — the authenticated DIDComm sender — against
    // this same field, so the credential is now pinned to the channel it
    // arrived on rather than to a persona that could have issued it anywhere.
    if vrc.issuer() != relationship.remote_did.as_str() {
        return Err(format!(
            "credential issuer ({}) is not the DID the sender uses in this \
             relationship ({})",
            vrc.issuer(),
            relationship.remote_did
        ));
    }

    // Gate 3: the thid may only resolve our own pending outbound VRC
    // request to this sender; anything else is ignored.
    let pending_request = thid.and_then(|thid| {
        let id = Arc::new(thid.to_string());
        let task = tasks.get_by_id(&id)?;
        let TaskType::VRCRequestOutbound {
            remote_p_did: task_remote_p_did,
        } = &task.type_
        else {
            return None;
        };
        (*task_remote_p_did == remote_p_did).then(|| Arc::clone(&id))
    });

    Ok(pending_request)
}

/// Cryptographically verify an inbound VRC's data-integrity proof (task R2).
///
/// The proof's `verificationMethod` must belong to the credential's issuer
/// DID — without that binding an attacker could present a proof made with
/// *their own* key over a credential naming someone else as issuer. The
/// public key is then resolved from the issuer's DID Document via the TDK
/// resolver and the proof verified over the proof-stripped credential.
pub async fn verify_vrc_proof(tdk: &TDK, vrc: &DTGCredential) -> Result<(), String> {
    let proof = check_vrc_issuer_binding(vrc)?;

    // `verify_data` expects the signed document with the proof stripped.
    let mut unsigned = vrc.clone();
    unsigned.credential_mut().proof = None;

    tdk.verify_data(&unsigned, None, &proof)
        .await
        .map_err(|e| format!("proof verification failed: {e}"))?;
    Ok(())
}

/// Verify a VRC's data-integrity proof against an **explicitly supplied** issuer
/// verifying key (raw public-key bytes), with no live [`TDK`] / DID resolution
/// and no network. Applies the same issuer ⇄ verification-method binding check
/// as [`verify_vrc_proof`], then verifies the proof via `dtg-credentials`'
/// key-based path. Lets callers (and fuzz harnesses) drive the proof verifier
/// directly by injecting the key instead of resolving it from the issuer DID.
pub fn verify_vrc_proof_with_key(
    vrc: &DTGCredential,
    public_key_bytes: &[u8],
) -> Result<(), String> {
    check_vrc_issuer_binding(vrc)?;
    vrc.verify_proof_with_public_key(public_key_bytes)
        .map_err(|e| format!("proof verification failed: {e}"))
}

/// Shared guard for the VRC proof verifiers: the credential must carry a
/// data-integrity proof and its `verification_method` must belong to the named
/// issuer (no "issuer signs with their own key over a credential naming someone
/// else"). Returns the proof on success.
fn check_vrc_issuer_binding(
    vrc: &DTGCredential,
) -> Result<affinidi_data_integrity::DataIntegrityProof, String> {
    let Some(proof) = vrc.credential().proof.clone() else {
        return Err("credential has no data-integrity proof".to_string());
    };
    let vm_did = proof
        .verification_method
        .split_once('#')
        .map_or(proof.verification_method.as_str(), |(did, _)| did);
    if vm_did != vrc.issuer() {
        return Err(format!(
            "proof verification method ({}) does not belong to the issuer ({})",
            proof.verification_method,
            vrc.issuer()
        ));
    }
    Ok(proof)
}

/// Extract the thread ID (`thid`) from a message, returning an error if missing.
pub fn require_thid(message: &Message) -> Result<Arc<String>, anyhow::Error> {
    message
        .thid
        .as_ref()
        .map(|s| Arc::new(s.to_string()))
        .ok_or_else(|| anyhow::anyhow!("message missing required 'thid' header"))
}

/// Validate that a string conforms to the DID Core 1.0 syntax.
///
///   did = "did:" method-name ":" method-specific-id
///   method-name = 1*( %x61-7A / DIGIT )
///   method-specific-id = *( *idchar ":" ) 1*idchar
///   idchar = ALPHA / DIGIT / "." / "-" / "_" / pct-encoded
///
/// The previous version was a `did:` prefix check, which let through
/// strings like `did:` followed by anything — including newlines and
/// zero-width characters that downstream code treated as routing
/// identities. We don't ship the full DID resolver here, but a strict
/// syntactic gate is cheap insurance against malformed payloads.
pub fn validate_did(did: &str) -> Result<(), anyhow::Error> {
    // Character-aligned truncation, not `&did[..64]`: this runs on unvalidated
    // inbound DIDs, and a byte cut inside a multi-byte scalar panics — turning
    // the rejection path into a remote crash (OVTC-01).
    let bail = || -> anyhow::Error {
        anyhow::anyhow!(
            "invalid DID format: '{}'",
            crate::display::truncate_chars(did, 64)
        )
    };

    let rest = did.strip_prefix("did:").ok_or_else(bail)?;
    let (method, msi) = rest.split_once(':').ok_or_else(bail)?;
    if method.is_empty()
        || !method
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    {
        return Err(bail());
    }
    if msi.is_empty() {
        return Err(bail());
    }
    // method-specific-id segments separated by `:`; each segment must
    // contain only idchar (ALPHA / DIGIT / "." / "-" / "_") or
    // pct-encoded triplets, and the final segment must be non-empty.
    let mut segments = msi.split(':');
    let last_segment_nonempty = msi.split(':').next_back().is_some_and(|s| !s.is_empty());
    if !last_segment_nonempty {
        return Err(bail());
    }
    if !segments.all(|seg| seg.chars().all(is_did_msi_char)) {
        return Err(bail());
    }
    Ok(())
}

/// Returns true for any character allowed in a DID method-specific-id.
/// Pct-encoded triplets (`%XX`) are accepted as `%`+hex+hex sequences,
/// validated character-by-character — a bad sequence shows up as a `%`
/// followed by a non-hex char and gets rejected at the boundary check.
pub fn is_did_msi_char(c: char) -> bool {
    matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '_' | '%')
}

/// Build a DIDComm finalize message for relationship establishment.
pub fn create_finalize_message(
    from: &str,
    to: &str,
    task_id: &Arc<String>,
) -> Result<Message, anyhow::Error> {
    build_didcomm_message(
        crate::protocol_urls::RELATIONSHIP_REQUEST_FINALIZE,
        json!({}),
        from,
        to,
        Some(task_id.as_str()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    // Asserted on throughout, but no longer named by the handlers themselves:
    // they go through `CommunityRecord`'s transitions rather than assigning a
    // status directly.
    use crate::config::account::CommunityStatus;

    fn msg(id: &str, created: Option<u64>, expires: Option<u64>) -> Message {
        let mut m =
            Message::build(id.to_string(), "test".to_string(), serde_json::json!({})).finalize();
        m.created_time = created;
        m.expires_time = expires;
        m
    }

    #[test]
    fn seen_messages_marks_first_observation_unseen() {
        let mut seen = SeenMessages::with_capacity(4);
        assert!(!seen.observe("a"));
    }

    #[test]
    fn seen_messages_detects_replay() {
        let mut seen = SeenMessages::with_capacity(4);
        assert!(!seen.observe("a"));
        assert!(seen.observe("a"));
    }

    #[test]
    fn seen_messages_evicts_oldest_at_capacity() {
        let mut seen = SeenMessages::with_capacity(2);
        assert!(!seen.observe("a"));
        assert!(!seen.observe("b"));
        // "b" still in cache.
        assert!(seen.observe("b"));
        // "c" pushes "a" out.
        assert!(!seen.observe("c"));
        // "a" was evicted — observing again should report unseen.
        assert!(!seen.observe("a"));
    }

    #[test]
    fn check_message_age_accepts_message_with_no_timestamps() {
        assert!(check_message_age(&msg("id", None, None)).is_ok());
    }

    #[test]
    fn check_message_age_rejects_old_messages() {
        let now = unix_now();
        let too_old = now - MAX_MESSAGE_AGE_SECS - 60;
        assert!(check_message_age(&msg("id", Some(too_old), None)).is_err());
    }

    #[test]
    fn check_message_age_rejects_future_messages() {
        let now = unix_now();
        let too_future = now + MAX_FUTURE_SKEW_SECS + 60;
        assert!(check_message_age(&msg("id", Some(too_future), None)).is_err());
    }

    #[test]
    fn check_message_age_accepts_within_skew() {
        let now = unix_now();
        // 1 minute in the future is fine.
        assert!(check_message_age(&msg("id", Some(now + 60), None)).is_ok());
    }

    #[test]
    fn check_message_age_rejects_expired_messages() {
        let now = unix_now();
        // expires_time in the past
        assert!(check_message_age(&msg("id", Some(now), Some(now - 60))).is_err());
    }

    // --- join submit-receipt reconciliation ---

    use crate::config::account::{Account, CommunityRecord, PersonaId, PersonaRecord};
    use chrono::Utc;
    use vta_sdk::protocols::credential_exchange::ISSUE as CREDENTIAL_ISSUE_TYPE;
    use vta_sdk::protocols::join_requests::{
        JOIN_REQUEST_STATUS_RESPONSE_TYPE, JOIN_REQUEST_SUBMIT_RECEIPT_TYPE,
    };

    /// The (single) membership a test set up for `vtc`.
    fn only<'a>(acct: &'a Account, vtc: &str) -> &'a CommunityRecord {
        acct.memberships()
            .find(|c| c.vtc_did == vtc)
            .expect("membership present")
    }

    fn pending_account(vtc: &str, placeholder: Uuid) -> Account {
        let mut acct = Account::default();
        acct.add_membership(CommunityRecord::new_pending(
            vtc.to_string(),
            None,
            "openvtc/x".to_string(),
            PersonaId::new(),
            placeholder,
            Utc::now(),
        ));
        acct
    }

    fn receipt(thid: &str, from: &str, request_id: Uuid, status: &str) -> Message {
        Message::build(
            Uuid::new_v4().to_string(),
            JOIN_REQUEST_SUBMIT_RECEIPT_TYPE.to_string(),
            serde_json::json!({ "requestId": request_id, "status": status }),
        )
        .from(from.to_string())
        .thid(thid.to_string())
        .finalize()
    }

    #[test]
    fn submit_receipt_reconciles_the_authoritative_request_id() {
        let vtc = "did:webvh:example:vtc";
        let placeholder = Uuid::new_v4();
        let mut acct = pending_account(vtc, placeholder);

        let real = Uuid::new_v4();
        let m = receipt(&placeholder.to_string(), vtc, real, "pending");
        assert!(handle_join_submit_receipt(&mut acct, &m, vtc));

        match &only(&acct, vtc).status {
            CommunityStatus::Pending { request_id } => assert_eq!(*request_id, real),
            other => panic!("expected Pending, got {other:?}"),
        }
    }

    #[test]
    fn submit_receipt_from_a_different_did_is_ignored() {
        let vtc = "did:webvh:example:vtc";
        let placeholder = Uuid::new_v4();
        let mut acct = pending_account(vtc, placeholder);

        // A receipt whose sender is not the community's VTC must not reconcile.
        let m = receipt(
            &placeholder.to_string(),
            "did:webvh:evil",
            Uuid::new_v4(),
            "pending",
        );
        assert!(!handle_join_submit_receipt(&mut acct, &m, "did:webvh:evil"));
        match &only(&acct, vtc).status {
            CommunityStatus::Pending { request_id } => assert_eq!(*request_id, placeholder),
            other => panic!("expected unchanged Pending, got {other:?}"),
        }
    }

    #[test]
    fn submit_receipt_with_mismatched_thid_is_ignored() {
        let vtc = "did:webvh:example:vtc";
        let placeholder = Uuid::new_v4();
        let mut acct = pending_account(vtc, placeholder);

        // thid does not match the stored placeholder.
        let m = receipt(&Uuid::new_v4().to_string(), vtc, Uuid::new_v4(), "pending");
        assert!(!handle_join_submit_receipt(&mut acct, &m, vtc));
        match &only(&acct, vtc).status {
            CommunityStatus::Pending { request_id } => assert_eq!(*request_id, placeholder),
            other => panic!("expected unchanged Pending, got {other:?}"),
        }
    }

    // --- status-response lifecycle resolution (R-B-8) ---

    fn status_response(from: &str, request_id: Uuid, status: &str) -> Message {
        Message::build(
            Uuid::new_v4().to_string(),
            JOIN_REQUEST_STATUS_RESPONSE_TYPE.to_string(),
            serde_json::json!({ "requestId": request_id, "status": status }),
        )
        .from(from.to_string())
        .finalize()
    }

    /// The status response in its wire form — the `#response` document, payload
    /// nested — as `tt_didcomm_reply` sends it.
    fn status_response_document(from: &str, request_id: Uuid, status: &str) -> Message {
        Message::build(
            Uuid::new_v4().to_string(),
            JOIN_REQUEST_STATUS_RESPONSE_TYPE.to_string(),
            serde_json::json!({
                "id": format!("urn:uuid:{}", Uuid::new_v4()),
                "threadId": format!("urn:uuid:{}", Uuid::new_v4()),
                "type": JOIN_REQUEST_STATUS_RESPONSE_TYPE,
                "issuer": from,
                "payload": { "requestId": request_id, "status": status },
            }),
        )
        .from(from.to_string())
        .finalize()
    }

    #[test]
    fn status_response_approved_activates_from_response_document() {
        let vtc = "did:webvh:example:vtc";
        let rid = Uuid::new_v4();
        let mut acct = pending_account(vtc, rid);

        let out = handle_join_status_response(
            &mut acct,
            &status_response_document(vtc, rid, "approved"),
            vtc,
        );
        assert!(
            out.changed,
            "an approved status response in its wire form must activate the membership"
        );
        assert!(matches!(only(&acct, vtc).status, CommunityStatus::Active));
    }

    /// Both reply shapes reach the same payload, and a bare body is left alone.
    #[test]
    fn reply_payload_accepts_document_and_bare_shapes() {
        let bare = serde_json::json!({ "requestId": "r", "status": "approved" });
        assert_eq!(trust_task_reply_payload(&bare), bare);

        let document = serde_json::json!({
            "id": "urn:uuid:1",
            "type": "https://example.org/x/1.0#response",
            "payload": bare.clone(),
        });
        assert_eq!(trust_task_reply_payload(&document), bare);
    }

    #[test]
    fn status_response_approved_activates() {
        let vtc = "did:webvh:example:vtc";
        let rid = Uuid::new_v4();
        let mut acct = pending_account(vtc, rid);

        let out =
            handle_join_status_response(&mut acct, &status_response(vtc, rid, "approved"), vtc);
        assert!(out.changed);
        assert!(out.inactivated.is_none(), "approval keeps the live session");
        let rec = only(&acct, vtc);
        assert!(rec.status.is_active());
        assert!(
            rec.member_since.is_some(),
            "member_since stamped on activate"
        );
    }

    #[test]
    fn status_response_rejected_inactivates_and_raises_badge() {
        let vtc = "did:webvh:example:vtc";
        let rid = Uuid::new_v4();
        let mut acct = pending_account(vtc, rid);

        let out =
            handle_join_status_response(&mut acct, &status_response(vtc, rid, "rejected"), vtc);
        assert!(out.changed);
        assert!(
            out.inactivated.is_some(),
            "a rejection must deregister the session (R-S-3)"
        );
        let rec = only(&acct, vtc);
        assert!(matches!(rec.status, CommunityStatus::Rejected));
        assert!(
            rec.needs_attention(),
            "an unacknowledged rejection nags (R-S-2)"
        );
    }

    // ----- decision evidence on the four reject paths (issue #240) -----------

    /// A polled rejection now carries code/reason/decidedAt (VTI #1058); the
    /// recovery path must persist them, so a rejection whose live verdict was
    /// missed is still explained.
    #[test]
    fn status_response_rejected_persists_decision_evidence() {
        let vtc = "did:webvh:example:vtc";
        let rid = Uuid::new_v4();
        let mut acct = pending_account(vtc, rid);

        let message = Message::build(
            Uuid::new_v4().to_string(),
            JOIN_REQUEST_STATUS_RESPONSE_TYPE.to_string(),
            serde_json::json!({
                "requestId": rid,
                "status": "rejected",
                "code": "admin-reject",
                "reason": "not this time",
                "decidedAt": "2026-08-23T09:14:02Z",
            }),
        )
        .from(vtc.to_string())
        .finalize();

        assert!(handle_join_status_response(&mut acct, &message, vtc).changed);
        let d = only(&acct, vtc)
            .decision
            .clone()
            .expect("a rejection records decision evidence");
        assert_eq!(d.code.as_deref(), Some("admin-reject"));
        assert_eq!(d.reason.as_deref(), Some("not this time"));
        assert!(d.decided_at.is_some(), "the decision time is persisted");
        assert!(
            d.decided_by.is_none(),
            "a join rejection names no verifiable authority"
        );
    }

    /// The oldest poll shape carries no evidence. It must still land as a
    /// *present but empty* decision, which the UI reads as "no reason given" —
    /// an explicit absence, distinct from a record predating the field.
    #[test]
    fn status_response_rejected_without_evidence_is_empty_not_absent() {
        let vtc = "did:webvh:example:vtc";
        let rid = Uuid::new_v4();
        let mut acct = pending_account(vtc, rid);

        assert!(
            handle_join_status_response(&mut acct, &status_response(vtc, rid, "rejected"), vtc)
                .changed
        );
        let d = only(&acct, vtc)
            .decision
            .clone()
            .expect("even an evidence-free rejection records a (empty) decision");
        assert!(d.is_empty(), "no fields travelled — 'no reason given'");
    }

    /// The `deny` verdict must persist code + reason, and — the bug the issue
    /// flagged — also acknowledge (stamp receipt_at) and adopt the VTC's request
    /// id, as the refer/request_more arms already do.
    #[test]
    fn verdict_deny_persists_evidence_and_acknowledges() {
        let vtc = "did:webvh:example:vtc";
        let rid = Uuid::new_v4();
        let mut acct = pending_account(vtc, rid);

        let with = serde_json::json!({ "code": "policy.denied", "reason": "membership full" });
        let out = handle_join_verdict(
            &mut acct,
            &verdict(&rid.to_string(), vtc, "deny", with),
            vtc,
        );
        assert!(out.changed);

        let rec = only(&acct, vtc);
        assert!(matches!(rec.status, CommunityStatus::Rejected));
        assert!(
            rec.receipt_at.is_some(),
            "a denial is a correlated response — it must stamp receipt_at, \
             not read like a dropped submit"
        );
        assert!(
            rec.request_id_confirmed,
            "the deny arm adopts the VTC's request id, like refer/request_more"
        );
        let d = rec.decision.clone().expect("deny records evidence");
        assert_eq!(d.code.as_deref(), Some("policy.denied"));
        assert_eq!(d.reason.as_deref(), Some("membership full"));
    }

    /// A FORBIDDEN problem-report persists its code and the free-text comment.
    #[test]
    fn problem_report_forbidden_persists_code_and_comment() {
        let vtc = "did:webvh:example:vtc";
        let rid = Uuid::new_v4();
        let mut acct = pending_account(vtc, rid);

        let out = handle_join_problem_report(
            &mut acct,
            &problem_report(
                &rid.to_string(),
                vtc,
                "e.p.msg.forbidden",
                "invitation rejected",
            ),
            vtc,
        );
        assert!(out.status.changed);
        let d = only(&acct, vtc)
            .decision
            .clone()
            .expect("forbidden records evidence");
        assert_eq!(d.code.as_deref(), Some("e.p.msg.forbidden"));
        assert_eq!(d.reason.as_deref(), Some("invitation rejected"));
    }

    /// An empty problem-report comment is "no reason given", not an empty reason.
    #[test]
    fn problem_report_forbidden_empty_comment_gives_no_reason() {
        let vtc = "did:webvh:example:vtc";
        let rid = Uuid::new_v4();
        let mut acct = pending_account(vtc, rid);

        handle_join_problem_report(
            &mut acct,
            &problem_report(&rid.to_string(), vtc, "e.p.msg.forbidden", ""),
            vtc,
        );
        let d = only(&acct, vtc).decision.clone().expect("records evidence");
        assert!(d.reason.is_none(), "an empty comment is an absent reason");
        assert_eq!(d.code.as_deref(), Some("e.p.msg.forbidden"));
    }

    /// A denial trust-task-error persists its code and human `message`.
    #[test]
    fn trust_task_error_denial_persists_code_and_detail() {
        let vtc = "did:webvh:example:vtc";
        let rid = Uuid::new_v4();
        let mut acct = pending_account(vtc, rid);

        let out = handle_join_trust_task_error(
            &mut acct,
            &trust_task_error(&rid.to_string(), vtc, "permissionDenied", "not on the list"),
            vtc,
        );
        assert!(out.changed);
        let d = only(&acct, vtc)
            .decision
            .clone()
            .expect("denial records evidence");
        assert_eq!(d.code.as_deref(), Some("permissionDenied"));
        assert_eq!(d.reason.as_deref(), Some("not on the list"));
    }

    // ----- removal notice (issue #240) --------------------------------------

    fn removal_notice(from: &str, body: serde_json::Value) -> Message {
        Message::build(
            Uuid::new_v4().to_string(),
            vta_sdk::protocols::members::MEMBER_REMOVAL_NOTICE_TYPE.to_string(),
            body,
        )
        .from(from.to_string())
        .finalize()
    }

    /// A removal notice for an active member transitions it to Removed, persists
    /// the full evidence (authority, reason, time, disposition), and deregisters
    /// the session.
    #[test]
    fn removal_notice_removes_active_member_with_evidence() {
        let vtc = "did:webvh:example:vtc";
        let persona = "did:webvh:example:persona";
        let mut acct = account_with_persona(vtc, persona);
        acct.memberships_mut().next().unwrap().activate(Utc::now());

        let out = handle_member_removal_notice(
            &mut acct,
            &removal_notice(
                vtc,
                serde_json::json!({
                    "did": persona,
                    "code": "adminRemoved",
                    "disposition": "tombstone",
                    "reason": "code of conduct",
                    "decidedAt": "2026-08-23T09:14:02Z",
                    "decidedBy": "did:key:z6MkAdmin",
                }),
            ),
            vtc,
        );
        assert!(out.changed);
        assert!(
            out.inactivated.is_some(),
            "a removal deregisters the session, like a rejection"
        );
        let rec = only(&acct, vtc);
        assert!(matches!(rec.status, CommunityStatus::Removed));
        assert!(rec.needs_attention(), "a fresh Removed nags (R-S-2)");
        let d = rec.decision.clone().expect("removal records evidence");
        assert_eq!(d.code.as_deref(), Some("adminRemoved"));
        assert_eq!(d.reason.as_deref(), Some("code of conduct"));
        assert_eq!(d.decided_by.as_deref(), Some("did:key:z6MkAdmin"));
        assert_eq!(d.disposition.as_deref(), Some("tombstone"));
        assert!(d.decided_at.is_some());
    }

    /// A purge with no reason keeps `reason` absent (not empty) — the member's
    /// only account of why says, truthfully, that none was given.
    #[test]
    fn removal_notice_without_reason_stays_absent() {
        let vtc = "did:webvh:example:vtc";
        let persona = "did:webvh:example:persona";
        let mut acct = account_with_persona(vtc, persona);
        acct.memberships_mut().next().unwrap().activate(Utc::now());

        handle_member_removal_notice(
            &mut acct,
            &removal_notice(
                vtc,
                serde_json::json!({
                    "did": persona,
                    "code": "purged",
                    "disposition": "purge",
                    "decidedAt": "2026-08-23T11:02:41Z",
                    "decidedBy": "did:key:z6MkSuperAdmin",
                }),
            ),
            vtc,
        );
        let d = only(&acct, vtc).decision.clone().expect("records evidence");
        assert!(d.reason.is_none(), "an omitted reason stays absent");
        assert_eq!(d.code.as_deref(), Some("purged"));
    }

    /// A removal notice naming a DID that is not one of our personas is ignored.
    #[test]
    fn removal_notice_for_unknown_persona_is_ignored() {
        let vtc = "did:webvh:example:vtc";
        let mut acct = account_with_persona(vtc, "did:webvh:example:persona");
        acct.memberships_mut().next().unwrap().activate(Utc::now());

        let out = handle_member_removal_notice(
            &mut acct,
            &removal_notice(
                vtc,
                serde_json::json!({
                    "did": "did:webvh:example:someone-else",
                    "code": "adminRemoved",
                    "disposition": "tombstone",
                    "decidedAt": "2026-08-23T09:14:02Z",
                    "decidedBy": "did:key:z6MkAdmin",
                }),
            ),
            vtc,
        );
        assert!(!out.changed);
        assert!(matches!(only(&acct, vtc).status, CommunityStatus::Active));
    }

    /// A stale/duplicate removal notice must not clobber a terminal state the
    /// member reached another way (e.g. a Left they chose).
    #[test]
    fn removal_notice_for_non_active_membership_is_ignored() {
        let vtc = "did:webvh:example:vtc";
        let persona = "did:webvh:example:persona";
        let mut acct = account_with_persona(vtc, persona);
        acct.memberships_mut().next().unwrap().leave();

        let out = handle_member_removal_notice(
            &mut acct,
            &removal_notice(
                vtc,
                serde_json::json!({
                    "did": persona,
                    "code": "adminRemoved",
                    "disposition": "tombstone",
                    "decidedAt": "2026-08-23T09:14:02Z",
                    "decidedBy": "did:key:z6MkAdmin",
                }),
            ),
            vtc,
        );
        assert!(!out.changed);
        assert!(
            matches!(only(&acct, vtc).status, CommunityStatus::Left),
            "the member's own Left is not overwritten"
        );
    }

    #[test]
    fn status_response_withdrawn_inactivates_without_badge() {
        let vtc = "did:webvh:example:vtc";
        let rid = Uuid::new_v4();
        let mut acct = pending_account(vtc, rid);

        let out =
            handle_join_status_response(&mut acct, &status_response(vtc, rid, "withdrawn"), vtc);
        assert!(out.changed);
        assert!(
            out.inactivated.is_some(),
            "a withdrawal must deregister the session (R-S-3)"
        );
        let rec = only(&acct, vtc);
        assert!(matches!(rec.status, CommunityStatus::Withdrawn));
        assert!(
            !rec.needs_attention(),
            "a voluntary withdrawal never nags (like Left)"
        );
    }

    #[test]
    fn status_response_deferred_stays_pending() {
        let vtc = "did:webvh:example:vtc";
        let rid = Uuid::new_v4();
        let mut acct = pending_account(vtc, rid);

        let out =
            handle_join_status_response(&mut acct, &status_response(vtc, rid, "deferred"), vtc);
        assert!(
            out.changed,
            "deferred is an acknowledgement — stamps receipt_at, needs persisting"
        );
        assert!(out.inactivated.is_none());
        assert!(
            only(&acct, vtc).receipt_at.is_some(),
            "the VTC responded — acknowledged"
        );
        assert!(matches!(
            only(&acct, vtc).status,
            CommunityStatus::Pending { .. }
        ));
    }

    // ----- Verdict-model join (trust-task) -----------------------------------

    fn verdict(thid: &str, from: &str, effect: &str, with: serde_json::Value) -> Message {
        Message::build(
            Uuid::new_v4().to_string(),
            vta_sdk::protocols::join_requests::JOIN_REQUEST_SUBMIT_RESPONSE_TYPE.to_string(),
            serde_json::json!({
                "requestId": Uuid::new_v4(),
                "verdict": { "effect": effect, "with": with },
            }),
        )
        .from(from.to_string())
        .thid(thid.to_string())
        .finalize()
    }

    /// The verdict as the VTC actually puts it on the wire: the whole
    /// `#response` Trust Task *document*, with the [`VerdictResponse`] nested
    /// under `payload`. `vtc-service`'s `tt_didcomm_reply` sets the DIDComm body
    /// to the parsed reply document, so this — not the bare payload the
    /// `verdict` helper builds — is what arrives.
    fn verdict_document(thid: &str, from: &str, effect: &str, with: serde_json::Value) -> Message {
        Message::build(
            Uuid::new_v4().to_string(),
            vta_sdk::protocols::join_requests::JOIN_REQUEST_SUBMIT_RESPONSE_TYPE.to_string(),
            serde_json::json!({
                "id": format!("urn:uuid:{}", Uuid::new_v4()),
                "threadId": thid,
                "type": vta_sdk::protocols::join_requests::JOIN_REQUEST_SUBMIT_RESPONSE_TYPE,
                "issuer": from,
                "payload": {
                    "requestId": Uuid::new_v4(),
                    "verdict": { "effect": effect, "with": with },
                },
            }),
        )
        .from(from.to_string())
        .thid(thid.to_string())
        .finalize()
    }

    #[test]
    fn verdict_allow_activates_from_response_document() {
        let vtc = "did:webvh:example:vtc";
        let rid = Uuid::new_v4();
        let mut acct = pending_account(vtc, rid);

        let out = handle_join_verdict(
            &mut acct,
            &verdict_document(&rid.to_string(), vtc, "allow", serde_json::json!({})),
            vtc,
        );
        assert!(
            out.changed,
            "an allow verdict in its wire form (payload nested in the #response \
             document) must activate the membership"
        );
        assert!(matches!(only(&acct, vtc).status, CommunityStatus::Active));
    }

    #[test]
    fn verdict_allow_activates() {
        let vtc = "did:webvh:example:vtc";
        let rid = Uuid::new_v4();
        let mut acct = pending_account(vtc, rid);

        let out = handle_join_verdict(
            &mut acct,
            &verdict(&rid.to_string(), vtc, "allow", serde_json::json!({})),
            vtc,
        );
        assert!(out.changed);
        assert!(out.inactivated.is_none());
        assert!(matches!(only(&acct, vtc).status, CommunityStatus::Active));
    }

    #[test]
    fn verdict_deny_rejects_and_inactivates() {
        let vtc = "did:webvh:example:vtc";
        let rid = Uuid::new_v4();
        let mut acct = pending_account(vtc, rid);

        let with = serde_json::json!({ "code": "policy.denied", "reason": "no" });
        let out = handle_join_verdict(
            &mut acct,
            &verdict(&rid.to_string(), vtc, "deny", with),
            vtc,
        );
        assert!(out.changed);
        assert!(out.inactivated.is_some(), "a deny deregisters the session");
        assert!(matches!(only(&acct, vtc).status, CommunityStatus::Rejected));
    }

    #[test]
    fn verdict_request_more_stays_pending() {
        let vtc = "did:webvh:example:vtc";
        let rid = Uuid::new_v4();
        let mut acct = pending_account(vtc, rid);

        let with = serde_json::json!({ "needs": ["proof-of-age"] });
        let out = handle_join_verdict(
            &mut acct,
            &verdict(&rid.to_string(), vtc, "request_more", with),
            vtc,
        );
        assert!(out.changed, "request_more acknowledges — stamps receipt_at");
        let rec = only(&acct, vtc);
        assert!(matches!(rec.status, CommunityStatus::Pending { .. }));
        assert!(rec.receipt_at.is_some(), "the VTC responded — acknowledged");
    }

    /// A verdict that leaves the join `Pending` is the one case where the
    /// community's own request id matters later: the join outlives the exchange
    /// that produced it, and the id is the only handle
    /// `join-requests/status` can name it by. Correlation here is by `thid`, so
    /// nothing *needed* the id — which is exactly why it used to be read past.
    #[test]
    fn a_verdict_that_stays_pending_adopts_the_communitys_request_id() {
        for effect in ["refer", "request_more"] {
            let vtc = "did:webvh:example:vtc";
            let placeholder = Uuid::new_v4();
            let vtc_request_id = Uuid::new_v4();
            let mut acct = pending_account(vtc, placeholder);
            assert!(
                !only(&acct, vtc).request_id_confirmed,
                "{effect}: before any reply we hold our own id, which the VTC has never seen"
            );
            // Askable regardless — it just cannot quote an id yet, so it asks
            // "what is my open request?". Adopting the id below is what lets
            // every later poll name the join the way the community does.
            assert!(only(&acct, vtc).is_pollable_pending());

            let message = Message::build(
                Uuid::new_v4().to_string(),
                vta_sdk::protocols::join_requests::JOIN_REQUEST_SUBMIT_RESPONSE_TYPE.to_string(),
                serde_json::json!({
                    "requestId": vtc_request_id,
                    "verdict": { "effect": effect, "with": {} },
                }),
            )
            .from(vtc.to_string())
            .thid(placeholder.to_string())
            .finalize();

            let out = handle_join_verdict(&mut acct, &message, vtc);
            assert!(
                out.changed,
                "{effect}: adopting the id is a change to persist"
            );

            let rec = only(&acct, vtc);
            match &rec.status {
                CommunityStatus::Pending { request_id } => assert_eq!(
                    *request_id, vtc_request_id,
                    "{effect}: the record now names the join the way the community does"
                ),
                other => panic!("{effect}: expected still-Pending, got {other:?}"),
            }
            assert!(
                rec.is_pollable_pending(),
                "{effect}: with the community's id, this join can now be asked about"
            );
        }
    }

    /// The submit-receipt path already adopted the id; what is new is recording
    /// that it *is* the community's, which is what the poll gates on.
    #[test]
    fn a_submit_receipt_makes_the_join_pollable() {
        let vtc = "did:webvh:example:vtc";
        let placeholder = Uuid::new_v4();
        let real = Uuid::new_v4();
        let mut acct = pending_account(vtc, placeholder);

        let message = Message::build(
            Uuid::new_v4().to_string(),
            vta_sdk::protocols::join_requests::JOIN_REQUEST_SUBMIT_RECEIPT_TYPE.to_string(),
            serde_json::json!({ "requestId": real, "status": "pending" }),
        )
        .from(vtc.to_string())
        .thid(placeholder.to_string())
        .finalize();

        assert!(handle_join_submit_receipt(&mut acct, &message, vtc));
        assert!(only(&acct, vtc).is_pollable_pending());
    }

    #[test]
    fn verdict_with_mismatched_thid_is_ignored() {
        let vtc = "did:webvh:example:vtc";
        let mut acct = pending_account(vtc, Uuid::new_v4());
        // thid is a *different* uuid than the pending placeholder.
        let out = handle_join_verdict(
            &mut acct,
            &verdict(
                &Uuid::new_v4().to_string(),
                vtc,
                "deny",
                serde_json::json!({}),
            ),
            vtc,
        );
        assert!(!out.changed);
        assert!(matches!(
            only(&acct, vtc).status,
            CommunityStatus::Pending { .. }
        ));
    }

    #[test]
    fn reply_routes_to_the_matching_membership_only() {
        // Two personas joined the SAME community; each Pending submit has its own
        // request id. A verdict threaded on one must transition only that one.
        let vtc = "did:webvh:example:vtc";
        let (rid_a, rid_b) = (Uuid::new_v4(), Uuid::new_v4());
        let (pa, pb) = (PersonaId::new(), PersonaId::new());
        let mut acct = Account::default();
        acct.add_membership(CommunityRecord::new_pending(
            vtc.into(),
            None,
            "openvtc/x".into(),
            pa,
            rid_a,
            Utc::now(),
        ));
        acct.add_membership(CommunityRecord::new_pending(
            vtc.into(),
            None,
            "openvtc/x".into(),
            pb,
            rid_b,
            Utc::now(),
        ));

        let out = handle_join_verdict(
            &mut acct,
            &verdict(&rid_a.to_string(), vtc, "allow", serde_json::json!({})),
            vtc,
        );
        assert!(out.changed);
        assert!(
            acct.membership(vtc, pa).unwrap().status.is_active(),
            "the membership whose request id matched is activated"
        );
        assert!(
            matches!(
                acct.membership(vtc, pb).unwrap().status,
                CommunityStatus::Pending { .. }
            ),
            "the other persona's membership is untouched"
        );
    }

    /// A framework `trust-task-error/0.2` document threaded on `thid`, carrying
    /// `code` (+ optional message) — the shape the VTC sends on a join failure.
    fn trust_task_error(thid: &str, from: &str, code: &str, message: &str) -> Message {
        Message::build(
            Uuid::new_v4().to_string(),
            format!("{}0.2", TRUST_TASK_ERROR_TYPE_PREFIX),
            serde_json::json!({
                "id": format!("urn:uuid:{}", Uuid::new_v4()),
                "type": format!("{}0.2", TRUST_TASK_ERROR_TYPE_PREFIX),
                "payload": { "code": code, "message": message },
            }),
        )
        .from(from.to_string())
        .thid(thid.to_string())
        .finalize()
    }

    #[test]
    fn trust_task_error_type_matches_any_version() {
        assert!(is_trust_task_error_type(
            "https://trusttasks.org/spec/trust-task-error/0.1"
        ));
        assert!(is_trust_task_error_type(
            "https://trusttasks.org/spec/trust-task-error/0.2"
        ));
        assert!(!is_trust_task_error_type(
            "https://trusttasks.org/spec/vtc/join-requests/submit/0.1"
        ));
    }

    #[test]
    fn trust_task_error_denial_rejects_and_inactivates() {
        let vtc = "did:webvh:example:vtc";
        let rid = Uuid::new_v4();
        let mut acct = pending_account(vtc, rid);

        let out = handle_join_trust_task_error(
            &mut acct,
            &trust_task_error(&rid.to_string(), vtc, "permissionDenied", "not allowed"),
            vtc,
        );
        assert!(out.changed);
        assert!(
            out.inactivated.is_some(),
            "a denial deregisters the session"
        );
        assert!(matches!(only(&acct, vtc).status, CommunityStatus::Rejected));
    }

    #[test]
    fn trust_task_error_malformed_stays_pending_recoverable() {
        let vtc = "did:webvh:example:vtc";
        let rid = Uuid::new_v4();
        let mut acct = pending_account(vtc, rid);

        let out = handle_join_trust_task_error(
            &mut acct,
            &trust_task_error(
                &rid.to_string(),
                vtc,
                "malformedRequest",
                "missing field `id`",
            ),
            vtc,
        );
        assert!(
            out.changed,
            "the VTC responded — stamps receipt_at, needs persisting"
        );
        assert!(
            out.inactivated.is_none(),
            "recoverable — no terminal transition"
        );
        let rec = only(&acct, vtc);
        assert!(
            matches!(rec.status, CommunityStatus::Pending { .. }),
            "stays Pending so a corrected retry can succeed"
        );
        assert!(
            rec.receipt_at.is_some(),
            "a trust-task-error is still an acknowledgement the submit arrived"
        );
    }

    #[test]
    fn trust_task_error_with_mismatched_thid_is_ignored() {
        let vtc = "did:webvh:example:vtc";
        let mut acct = pending_account(vtc, Uuid::new_v4());
        let out = handle_join_trust_task_error(
            &mut acct,
            &trust_task_error(&Uuid::new_v4().to_string(), vtc, "permissionDenied", ""),
            vtc,
        );
        assert!(!out.changed);
        assert!(matches!(
            only(&acct, vtc).status,
            CommunityStatus::Pending { .. }
        ));
    }

    fn problem_report(thid: &str, from: &str, code: &str, comment: &str) -> Message {
        Message::build(
            Uuid::new_v4().to_string(),
            vta_sdk::protocols::PROBLEM_REPORT_TYPE.to_string(),
            serde_json::json!({ "code": code, "comment": comment }),
        )
        .from(from.to_string())
        .thid(thid.to_string())
        .finalize()
    }

    /// A problem-report on a thread no pending join matches must be reported,
    /// not swallowed.
    ///
    /// This is the exact shape that hid the broken reciprocal-VMC exchange: the
    /// community refused every delivery and said so in a report threaded on the
    /// delivery, which correlates to no join, so the handler returned "nothing
    /// happened" and the only trace was a warn naming the correlation miss
    /// rather than the failure.
    #[test]
    fn a_report_matching_no_pending_join_is_handed_back_not_dropped() {
        let vtc = "did:webvh:example:vtc";
        let rid = Uuid::new_v4();
        let mut acct = pending_account(vtc, rid);

        // Threaded on something else entirely — a members/vmc delivery, say.
        let unrelated = Uuid::new_v4();
        let out = handle_join_problem_report(
            &mut acct,
            &problem_report(
                &unrelated.to_string(),
                vtc,
                "e.p.msg.bad-request",
                "member vmc has no top-level `id`",
            ),
            vtc,
        );

        let (code, comment) = out
            .unclaimed
            .expect("an uncorrelated report must be reported");
        assert_eq!(code, "e.p.msg.bad-request");
        assert!(
            comment.contains("member vmc"),
            "the community's own words must survive: {comment}"
        );
        assert!(
            !out.status.changed,
            "it still must not touch the pending join it does not belong to"
        );
        assert!(matches!(
            only(&acct, vtc).status,
            CommunityStatus::Pending { .. }
        ));
    }

    /// A report with no thread id at all cannot be correlated either, and is
    /// equally not a reason to stay quiet.
    #[test]
    fn a_report_with_no_thread_id_is_still_reported() {
        let vtc = "did:webvh:example:vtc";
        let mut acct = pending_account(vtc, Uuid::new_v4());
        let mut msg = problem_report("ignored", vtc, "e.p.msg.internal", "boom");
        msg.thid = None;

        let out = handle_join_problem_report(&mut acct, &msg, vtc);
        assert!(
            out.unclaimed.is_some(),
            "no thid is not a reason to drop it"
        );
    }

    #[test]
    fn problem_report_forbidden_rejects() {
        let vtc = "did:webvh:example:vtc";
        let rid = Uuid::new_v4();
        let mut acct = pending_account(vtc, rid);

        let out = handle_join_problem_report(
            &mut acct,
            &problem_report(
                &rid.to_string(),
                vtc,
                "e.p.msg.forbidden",
                "invitation rejected",
            ),
            vtc,
        );
        assert!(out.status.changed);
        assert!(out.status.inactivated.is_some());
        assert!(matches!(only(&acct, vtc).status, CommunityStatus::Rejected));
    }

    #[test]
    fn problem_report_bad_request_stays_pending() {
        let vtc = "did:webvh:example:vtc";
        let rid = Uuid::new_v4();
        let mut acct = pending_account(vtc, rid);

        let out = handle_join_problem_report(
            &mut acct,
            &problem_report(&rid.to_string(), vtc, "e.p.msg.bad-request", "malformed"),
            vtc,
        );
        assert!(
            !out.status.changed,
            "a client/transient error must not mark Rejected"
        );
        assert!(
            out.unclaimed.is_none(),
            "a report threaded on a known pending join is this handler's to interpret"
        );
        assert!(matches!(
            only(&acct, vtc).status,
            CommunityStatus::Pending { .. }
        ));
    }

    #[test]
    fn status_response_with_mismatched_request_id_is_ignored() {
        let vtc = "did:webvh:example:vtc";
        let mut acct = pending_account(vtc, Uuid::new_v4());

        // A reply correlated to a different request id must not transition us.
        let out = handle_join_status_response(
            &mut acct,
            &status_response(vtc, Uuid::new_v4(), "rejected"),
            vtc,
        );
        assert!(!out.changed);
        assert!(out.inactivated.is_none());
        assert!(matches!(
            only(&acct, vtc).status,
            CommunityStatus::Pending { .. }
        ));
    }

    #[test]
    fn status_response_from_unknown_community_is_ignored() {
        let mut acct = pending_account("did:webvh:example:vtc", Uuid::new_v4());
        let out = handle_join_status_response(
            &mut acct,
            &status_response("did:webvh:example:other", Uuid::new_v4(), "approved"),
            "did:webvh:example:other",
        );
        assert!(!out.changed);
    }

    // --- credential-issue outcome handling ---

    fn account_with_persona(vtc: &str, persona_did: &str) -> Account {
        let mut acct = Account::default();
        let pid = PersonaId::new();
        acct.personas.insert(
            pid,
            PersonaRecord {
                extra: serde_json::Map::new(),
                persona_id: pid,
                did: persona_did.to_string(),
                did_document: None,
                key_refs: Vec::new(),
                mediator_did: None,
                origin_context_id: String::new(),
                created_at: Utc::now(),
                label: None,
            },
        );
        acct.add_membership(CommunityRecord::new_pending(
            vtc.to_string(),
            None,
            "openvtc/x".to_string(),
            pid,
            Uuid::new_v4(),
            Utc::now(),
        ));
        acct
    }

    fn issue(from: &str, credential: serde_json::Value) -> Message {
        Message::build(
            Uuid::new_v4().to_string(),
            CREDENTIAL_ISSUE_TYPE.to_string(),
            serde_json::json!({ "credential_response": { "credential": credential } }),
        )
        .from(from.to_string())
        .finalize()
    }

    fn vc(types: &[&str], issuer: &str, subject: &str) -> serde_json::Value {
        serde_json::json!({
            "type": types,
            "issuer": issuer,
            "credentialSubject": { "id": subject },
        })
    }

    /// Admission must report the join request it closed.
    ///
    /// This is the whole reason the handler returns a struct rather than a
    /// bool: `activate` replaces `Pending { request_id }` with `Active`, so the
    /// id is destroyed by the very call that makes it relevant. A caller
    /// looking afterwards finds nothing — which is why every reciprocal VMC
    /// this client ever sent carried `requestId: None`, leaving the community's
    /// join request `Approved` forever.
    #[test]
    fn admission_reports_the_join_request_it_closed() {
        let vtc = "did:webvh:example:vtc";
        let persona = "did:webvh:example:persona";
        let mut acct = account_with_persona(vtc, persona);

        // The id the fixture's pending membership is waiting on.
        let pending_id = match only(&acct, vtc).status {
            crate::config::account::CommunityStatus::Pending { request_id } => request_id,
            ref other => panic!("fixture should start Pending, got {other:?}"),
        };
        let persona_id = only(&acct, vtc).persona_ref;

        let m = issue(
            vtc,
            vc(
                &["VerifiableCredential", "MembershipCredential"],
                vtc,
                persona,
            ),
        );
        let outcome = handle_credential_issue(&mut acct, &m, vtc);

        assert_eq!(
            outcome.closed_join,
            Some((persona_id, pending_id)),
            "the outcome must carry the request id and the persona that owes the reciprocal"
        );
        // And the id really is gone from the record by now — the point of
        // capturing it rather than reading it back.
        assert!(only(&acct, vtc).status.is_active());
    }

    /// A credential that does not admit anyone closes no join. A role VEC
    /// landing on an already-active membership must not re-send a reciprocal
    /// VMC naming a request that was closed long ago.
    #[test]
    fn a_credential_that_admits_nobody_closes_no_join() {
        let vtc = "did:webvh:example:vtc";
        let persona = "did:webvh:example:persona";
        let mut acct = account_with_persona(vtc, persona);

        // Admit first, so the membership is already Active.
        let vmc = issue(
            vtc,
            vc(
                &["VerifiableCredential", "MembershipCredential"],
                vtc,
                persona,
            ),
        );
        assert!(
            handle_credential_issue(&mut acct, &vmc, vtc)
                .closed_join
                .is_some()
        );

        // A second membership credential on an active membership: stored, but
        // it admits nobody, so there is no join to close.
        let again = issue(
            vtc,
            vc(
                &["VerifiableCredential", "MembershipCredential"],
                vtc,
                persona,
            ),
        );
        let outcome = handle_credential_issue(&mut acct, &again, vtc);
        assert!(outcome.changed, "the credential is still stored");
        assert_eq!(
            outcome.closed_join, None,
            "an already-active membership has no open join to close"
        );
    }

    #[test]
    fn credential_issue_vmc_activates_and_stores() {
        let vtc = "did:webvh:example:vtc";
        let persona = "did:webvh:example:persona";
        let mut acct = account_with_persona(vtc, persona);

        let m = issue(
            vtc,
            vc(
                &["VerifiableCredential", "MembershipCredential"],
                vtc,
                persona,
            ),
        );
        assert!(handle_credential_issue(&mut acct, &m, vtc).changed);

        let rec = only(&acct, vtc);
        assert!(rec.status.is_active());
        assert!(
            rec.credentials
                .contains_key(&crate::CredentialKind::Membership)
        );
    }

    #[test]
    fn credential_issue_role_vec_stores_without_activating() {
        let vtc = "did:webvh:example:vtc";
        let persona = "did:webvh:example:persona";
        let mut acct = account_with_persona(vtc, persona);

        let m = issue(
            vtc,
            vc(
                &["VerifiableCredential", "EndorsementCredential"],
                vtc,
                persona,
            ),
        );
        assert!(handle_credential_issue(&mut acct, &m, vtc).changed);

        let rec = only(&acct, vtc);
        assert!(
            !rec.status.is_active(),
            "role VEC must not activate on its own"
        );
        assert!(rec.credentials.contains_key(&crate::CredentialKind::Role));
    }

    /// The dispatch path is purely registry-driven: every kind in
    /// `CredentialKind::ALL` is classified and stored by `handle_credential_issue`
    /// with no per-kind branching, so adding a kind to the registry is the only
    /// change needed for it to be handled here (R19 acceptance criterion).
    #[test]
    fn credential_issue_handles_every_registered_kind() {
        let vtc = "did:webvh:example:vtc";
        let persona = "did:webvh:example:persona";

        for kind in crate::CredentialKind::ALL {
            let mut acct = account_with_persona(vtc, persona);
            let m = issue(
                vtc,
                vc(&["VerifiableCredential", kind.vc_type()], vtc, persona),
            );
            assert!(
                handle_credential_issue(&mut acct, &m, vtc).changed,
                "kind {kind:?} should be accepted",
            );
            let rec = only(&acct, vtc);
            assert!(
                rec.credentials.contains_key(kind),
                "kind {kind:?} should be stored under its registry key",
            );
            assert_eq!(
                rec.status.is_active(),
                kind.activates_membership(),
                "activation for {kind:?} must match the registry",
            );
        }
    }

    #[test]
    fn credential_issue_from_wrong_issuer_is_ignored() {
        let vtc = "did:webvh:example:vtc";
        let persona = "did:webvh:example:persona";
        let mut acct = account_with_persona(vtc, persona);

        // Issuer is not the community's VTC.
        let m = issue(
            vtc,
            vc(
                &["VerifiableCredential", "MembershipCredential"],
                "did:webvh:evil",
                persona,
            ),
        );
        assert!(!handle_credential_issue(&mut acct, &m, vtc).changed);
        assert!(!only(&acct, vtc).status.is_active());
    }

    #[test]
    fn credential_issue_for_wrong_subject_is_ignored() {
        let vtc = "did:webvh:example:vtc";
        let persona = "did:webvh:example:persona";
        let mut acct = account_with_persona(vtc, persona);

        // Subject is not our persona.
        let m = issue(
            vtc,
            vc(
                &["VerifiableCredential", "MembershipCredential"],
                vtc,
                "did:webvh:someone-else",
            ),
        );
        assert!(!handle_credential_issue(&mut acct, &m, vtc).changed);
        assert!(!only(&acct, vtc).status.is_active());
    }

    #[test]
    fn validate_did_accepts_well_formed_dids() {
        assert!(validate_did("did:web:example.com").is_ok());
        assert!(validate_did("did:webvh:abcdef0123:example.com").is_ok());
        assert!(validate_did("did:peer:2.Vz6Mk-something").is_ok());
        assert!(validate_did("did:key:z6MkpzExampleKey").is_ok());
        assert!(validate_did("did:web:example.com%3A8080:path").is_ok());
    }

    #[test]
    fn validate_did_rejects_old_prefix_loophole() {
        // The previous validator accepted these — current one must not.
        assert!(validate_did("did:").is_err());
        assert!(validate_did("did:abc").is_err()); // no msi
        assert!(validate_did("did::abc").is_err()); // empty method
        assert!(validate_did("not-a-did").is_err());
        assert!(validate_did("").is_err());
    }

    #[test]
    fn validate_did_rejects_uppercase_method() {
        assert!(validate_did("did:WEB:example.com").is_err());
    }

    #[test]
    fn validate_did_rejects_msi_with_invalid_chars() {
        assert!(validate_did("did:web:exam ple.com").is_err()); // space
        assert!(validate_did("did:web:exam\u{200E}ple.com").is_err()); // LRM
    }

    /// OVTC-01: the error path used to truncate the rejected input with a
    /// *byte* slice, so an invalid DID longer than the cap whose cut landed
    /// inside a multi-byte scalar panicked instead of returning `Err`. The
    /// input here is attacker-controlled (an inbound `RelationshipRequest`
    /// body), so the panic was a remote crash of the whole client.
    #[test]
    fn validate_did_rejects_oversized_multibyte_input_without_panicking() {
        // Each case puts a 2-, 3- and 4-byte scalar across the 64-byte cut.
        for (label, filler, scalar) in [
            ("2-byte", 63, '\u{0281}'),  // ʁ  — bytes 63..65
            ("3-byte", 62, '\u{20AC}'),  // €  — bytes 62..65
            ("4-byte", 61, '\u{1F600}'), // 😀 — bytes 61..65
        ] {
            let did = format!("{}{scalar}", "x".repeat(filler));
            assert!(did.len() > 64, "{label}: case must exceed the cap");
            assert!(
                validate_did(&did).is_err(),
                "{label}: must reject, not panic"
            );
        }
        // Same shape, but past the `did:` prefix so a later gate does the
        // rejecting — the truncation runs for every bail arm.
        let msi = format!("did:web:{}\u{1F600}", "x".repeat(60));
        assert!(validate_did(&msi).is_err());
    }

    // --- inbound VRC-issued vetting (task R2) ---

    use crate::relationships::Relationship;
    use affinidi_tdk::common::config::TDKConfig;
    use affinidi_tdk::dids::{DID, KeyType};

    fn relationship(remote_p: &str, remote_r: &str, state: RelationshipState) -> Relationship {
        Relationship {
            task_id: Arc::new(Uuid::new_v4().to_string()),
            our_did: Arc::new("did:webvh:example:us".to_string()),
            remote_did: Arc::new(remote_r.to_string()),
            remote_p_did: Arc::new(remote_p.to_string()),
            created: Utc::now(),
            state,
            our_persona: None,
            needs_reestablishment: false,
        }
    }

    fn relationships_with(rel: &Relationship) -> Relationships {
        let mut rels = Relationships::default();
        let key = Arc::clone(&rel.remote_p_did);
        rels.relationships.insert(key, rel.clone());
        rels
    }

    fn unsigned_vrc(issuer: &str) -> DTGCredential {
        DTGCredential::new_vrc(
            issuer.to_string(),
            "did:webvh:example:subject".to_string(),
            Utc::now(),
            None,
        )
    }

    #[test]
    fn vrc_issued_with_forged_issuer_is_dropped_and_tasks_untouched() {
        let sender = Arc::new("did:webvh:example:honest-sender".to_string());
        let rel = relationship(&sender, &sender, RelationshipState::Established);
        let rels = relationships_with(&rel);

        // A pending task whose id the attacker guesses as the thid.
        let mut tasks = Tasks::default();
        let pending = Arc::new(Uuid::new_v4().to_string());
        tasks.new_task(
            &pending,
            TaskType::VRCRequestOutbound {
                remote_p_did: Arc::clone(&rel.remote_p_did),
            },
        );

        let vrc = unsigned_vrc("did:web:ATTACKER_FORGED");
        let result = vet_vrc_issued(&rels, &tasks, &vrc, &sender, Some(pending.as_str()));
        assert!(result.is_err(), "forged issuer must be rejected");
        assert!(
            tasks.get_by_id(&pending).is_some(),
            "pending task must survive a rejected VRC"
        );
    }

    #[test]
    fn vrc_issued_without_relationship_is_dropped() {
        let sender = Arc::new("did:webvh:example:stranger".to_string());
        let rels = Relationships::default();
        let tasks = Tasks::default();

        let vrc = unsigned_vrc(sender.as_str());
        assert!(vet_vrc_issued(&rels, &tasks, &vrc, &sender, None).is_err());
    }

    #[test]
    fn vrc_issued_from_non_established_relationship_is_dropped() {
        let sender = Arc::new("did:webvh:example:half-shaken".to_string());
        let rel = relationship(&sender, &sender, RelationshipState::RequestSent);
        let rels = relationships_with(&rel);
        let tasks = Tasks::default();

        let vrc = unsigned_vrc(sender.as_str());
        assert!(vet_vrc_issued(&rels, &tasks, &vrc, &sender, None).is_err());
    }

    #[test]
    fn vrc_issued_thid_matching_unrelated_task_is_ignored() {
        let sender = Arc::new("did:webvh:example:sender".to_string());
        let rel = relationship(&sender, &sender, RelationshipState::Established);
        let rels = relationships_with(&rel);

        let mut tasks = Tasks::default();
        // An unrelated pending task (not an outbound VRC request).
        let unrelated = Arc::new(Uuid::new_v4().to_string());
        tasks.new_task(
            &unrelated,
            TaskType::RelationshipRequestOutbound {
                to: Arc::new("did:webvh:example:third-party".to_string()),
            },
        );
        // An outbound VRC request — but to a *different* sender.
        let other_rel = relationship(
            "did:webvh:example:other",
            "did:webvh:example:other",
            RelationshipState::Established,
        );
        let other_request = Arc::new(Uuid::new_v4().to_string());
        tasks.new_task(
            &other_request,
            TaskType::VRCRequestOutbound {
                remote_p_did: Arc::clone(&other_rel.remote_p_did),
            },
        );

        let vrc = unsigned_vrc(sender.as_str());
        for thid in [unrelated.as_str(), other_request.as_str()] {
            let resolved = vet_vrc_issued(&rels, &tasks, &vrc, &sender, Some(thid))
                .expect("message itself is acceptable");
            assert!(
                resolved.is_none(),
                "thid pointing at an unrelated task must not resolve it"
            );
        }
        assert!(tasks.get_by_id(&unrelated).is_some());
        assert!(tasks.get_by_id(&other_request).is_some());
    }

    #[test]
    fn vrc_issued_thid_resolves_our_matching_outbound_request() {
        let sender_p = "did:webvh:example:sender";
        let sender_r = "did:webvh:example:sender-rdid";
        // Envelope arrives from the sender's R-DID; issuer is their P-DID.
        let from = Arc::new(sender_r.to_string());
        let rel = relationship(sender_p, sender_r, RelationshipState::Established);
        let rels = relationships_with(&rel);

        let mut tasks = Tasks::default();
        let request = Arc::new(Uuid::new_v4().to_string());
        tasks.new_task(
            &request,
            TaskType::VRCRequestOutbound {
                remote_p_did: Arc::clone(&rel.remote_p_did),
            },
        );

        // Issued under the sender's relationship DID — the pairwise form.
        let vrc = unsigned_vrc(sender_r);
        let resolved = vet_vrc_issued(&rels, &tasks, &vrc, &from, Some(request.as_str()))
            .expect("legitimate VRC must pass vetting");
        assert_eq!(resolved, Some(request));
    }

    /// A VRC issued under the sender's *persona* DID, on a relationship that
    /// uses a relationship DID, is refused.
    ///
    /// This is the behaviour change: the persona-issued credential is exactly
    /// what correlated every relationship a persona had, because the VRC is the
    /// durable artifact both parties keep and may publish to the trust graph.
    /// Accepting it would leave the pairwise channel leading straight back to
    /// the persona.
    #[test]
    fn vrc_issued_under_the_senders_persona_did_is_refused() {
        let sender_p = "did:webvh:example:sender-persona";
        let sender_r = "did:peer:2.SENDER_RELATIONSHIP";
        let from = Arc::new(sender_r.to_string());
        let rel = relationship(sender_p, sender_r, RelationshipState::Established);
        let rels = relationships_with(&rel);

        let vrc = unsigned_vrc(sender_p);
        let err = vet_vrc_issued(&rels, &Tasks::default(), &vrc, &from, None)
            .expect_err("a persona-issued VRC must not pass vetting");
        assert!(
            err.contains("is not the DID the sender uses in this relationship"),
            "unexpected rejection reason: {err}"
        );
    }

    /// A relationship established without a dedicated relationship DID has
    /// `remote_did == remote_p_did`, so the persona-issued VRC still passes.
    /// The gate binds to the identity used in the relationship, whichever it is.
    #[test]
    fn vrc_issued_under_the_persona_passes_when_that_is_the_relationship_did() {
        let sender_p = "did:webvh:example:sender-persona";
        let from = Arc::new(sender_p.to_string());
        let rel = relationship(sender_p, sender_p, RelationshipState::Established);
        let rels = relationships_with(&rel);

        let vrc = unsigned_vrc(sender_p);
        vet_vrc_issued(&rels, &Tasks::default(), &vrc, &from, None)
            .expect("a relationship with no R-DID must still accept its persona-issued VRC");
    }

    // --- inbound VRC-issued proof verification (task R2 gate 4) ---

    async fn test_tdk() -> TDK {
        TDK::new(
            TDKConfig::builder()
                .with_load_environment(false)
                .build()
                .expect("TDK config builds"),
            None,
        )
        .await
        .expect("TDK builds")
    }

    #[tokio::test]
    async fn vrc_proof_validly_signed_credential_is_accepted() {
        let tdk = test_tdk().await;
        let (issuer_did, issuer_secret) =
            DID::generate_did_key(KeyType::Ed25519).expect("did:key generates");

        let mut vrc = unsigned_vrc(&issuer_did);
        vrc.sign(&issuer_secret, None).await.expect("signs");

        assert!(verify_vrc_proof(&tdk, &vrc).await.is_ok());
    }

    #[tokio::test]
    async fn vrc_proof_tampered_credential_is_rejected() {
        let tdk = test_tdk().await;
        let (issuer_did, issuer_secret) =
            DID::generate_did_key(KeyType::Ed25519).expect("did:key generates");

        let mut vrc = unsigned_vrc(&issuer_did);
        vrc.sign(&issuer_secret, None).await.expect("signs");

        // Tamper with the signed payload — the proof must no longer verify.
        vrc.credential_mut()
            .context
            .push("https://attacker.example/context/v1".to_string());
        assert!(verify_vrc_proof(&tdk, &vrc).await.is_err());
    }

    #[tokio::test]
    async fn vrc_proof_signed_by_non_issuer_key_is_rejected() {
        let tdk = test_tdk().await;
        let (_attacker_did, attacker_secret) =
            DID::generate_did_key(KeyType::Ed25519).expect("did:key generates");
        let (victim_did, _victim_secret) =
            DID::generate_did_key(KeyType::Ed25519).expect("did:key generates");

        // Attacker signs with their own key but names the victim as issuer:
        // the proof's verificationMethod won't belong to the issuer DID.
        let mut vrc = unsigned_vrc(&victim_did);
        vrc.sign(&attacker_secret, None).await.expect("signs");

        assert!(verify_vrc_proof(&tdk, &vrc).await.is_err());
    }

    #[tokio::test]
    async fn vrc_proof_unsigned_credential_is_rejected() {
        let tdk = test_tdk().await;
        let vrc = unsigned_vrc("did:webvh:example:issuer");
        assert!(verify_vrc_proof(&tdk, &vrc).await.is_err());
    }

    /// Raw Ed25519 public-key bytes embedded in a `did:key` (multibase
    /// `z`-base58btc of `0xed01 || pubkey`; strip the 2-byte multicodec prefix).
    fn did_key_pubkey_bytes(did_key: &str) -> Vec<u8> {
        let mb = did_key.strip_prefix("did:key:").expect("did:key prefix");
        let (_base, decoded) = multibase::decode(mb).expect("multibase decode");
        decoded[2..].to_vec()
    }

    #[tokio::test]
    async fn vrc_proof_with_key_accepts_matching_key_rejects_others() {
        let (issuer_did, issuer_secret) =
            DID::generate_did_key(KeyType::Ed25519).expect("did:key generates");
        let mut vrc = unsigned_vrc(&issuer_did);
        vrc.sign(&issuer_secret, None).await.expect("signs");

        // The injected issuer key verifies — no TDK / DID resolution involved.
        assert!(verify_vrc_proof_with_key(&vrc, &did_key_pubkey_bytes(&issuer_did)).is_ok());

        // A different key must not verify the same proof.
        let (other_did, _) = DID::generate_did_key(KeyType::Ed25519).expect("did:key generates");
        assert!(verify_vrc_proof_with_key(&vrc, &did_key_pubkey_bytes(&other_did)).is_err());
    }

    #[test]
    fn vrc_proof_with_key_rejects_unsigned() {
        // The issuer-binding guard fires before any key verification.
        let vrc = unsigned_vrc("did:webvh:example:issuer");
        assert!(verify_vrc_proof_with_key(&vrc, &[0u8; 32]).is_err());
    }
}
