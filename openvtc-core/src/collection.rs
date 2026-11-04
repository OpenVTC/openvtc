//! Collection claims for the personas whose mediator sockets this client holds (VTI-NTF-080 –
//! 093, `vta/collection/{claim,release}/0.1`).
//!
//! A persona DID advertises a mediator, and the mediator permits **one connection per DID**: a
//! second evicts the first. The member's VTA holds the persona's keys, so it can collect for the
//! persona itself (VTI-NTF-080) — and a VTA collecting beside this client would evict its socket
//! and be evicted in turn, losing exactly the messages either was there to take. So the two agree
//! who collects by a **collection claim**, a lease the VTA records:
//!
//! - **Claim before connecting** (VTI-NTF-083). A persona listener whose keys the VTA holds is
//!   connected only once the VTA has granted this client a claim for it. The claim asks for
//!   twenty-four hours ([`ASKED_CLAIM_SECS`]).
//! - **Renew at half-time**, and **close before the end** less this client's own clock-skew
//!   tolerance ([`CLOCK_SKEW`]) unless the renewal landed.
//! - **Stop, then release.** A listener removed for good is closed first and its claim released
//!   after ([`RELEASE_GRACE`] later, so a reconnect — which removes and re-adds — keeps it).
//! - **Refusals are said in words** ([`CollectionNotice`]). `claimHeld` — another client of the
//!   principal collects for the persona — and every other refusal leave the socket closed;
//!   `claimNotRenewable` closes it before the last end granted. `notCollectable` is the VTA
//!   stating it never collects for that identifier (VTI-NTF-080's exceptions), so nobody would be
//!   evicted: the socket connects without a claim, as it does against a VTA too old to serve
//!   claims at all.
//!
//! Received notifications are still handed to the VTA (`vta/notifications/deposit/0.1`,
//! VTI-NTF-092); that is [`crate::notifications`].

use std::collections::HashMap;
use std::sync::{Mutex, RwLock};

use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use vta_sdk::client::VtaClient;
use vta_sdk::error::VtaError;

use crate::specs::vta::collection::{claim::v0_1 as claim, release::v0_1 as release};

/// The claim this client asks for: twenty-four hours (VTI-NTF-083's SHOULD).
pub const ASKED_CLAIM_SECS: i64 = 86_400;

/// This client's own clock-skew tolerance: a socket is closed this long before its claim's end
/// unless the claim was renewed (VTI-NTF-083).
pub const CLOCK_SKEW: Duration = Duration::seconds(120);

/// How long after a listener is removed its claim is released, unless the listener came back
/// (a reconnect removes and re-adds within milliseconds).
pub const RELEASE_GRACE: std::time::Duration = std::time::Duration::from_secs(30);

/// How often a failed renewal is tried again before the socket must close.
const RENEW_RETRY: Duration = Duration::seconds(60);

/// Bound on the releases sent when the runtime shuts down.
const SHUTDOWN_RELEASE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The longest a refused persona waits before its claim is asked again.
const RETRY_CAP: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// What a persona listener claims: the persona DID, in the trust context it belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionTarget {
    /// The persona's trust context at the VTA.
    pub context_id: String,
    /// The persona DID.
    pub identifier: String,
}

/// What the VTA answered a claim with, and so whether this client may connect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClaimAnswer {
    /// Granted (or renewed): this client is the collector until `ends_at`.
    Granted {
        ends_at: DateTime<Utc>,
        renewed: bool,
    },
    /// `notCollectable`: the VTA never collects for this identifier (VTI-NTF-080's exceptions),
    /// so connecting evicts nobody.
    NotCollectable,
    /// The VTA does not serve `vta/collection/claim/0.1`: it predates collection and cannot
    /// collect, so connecting evicts nobody.
    Unsupported,
    /// `claimHeld`: another client of the principal holds a claim in force.
    Held,
    /// `claimNotRenewable`: this client's claim was released by another party with standing, or
    /// this client lost its standing; it still ends at its end.
    NotRenewable,
    /// The VTA answered with another refusal (no standing in the context, for one).
    Refused(String),
    /// No answer: the VTA could not be reached or did not answer in time.
    Unreachable(String),
}

impl ClaimAnswer {
    /// Whether this answer lets the socket connect.
    #[must_use]
    pub fn may_connect(&self) -> bool {
        matches!(
            self,
            Self::Granted { .. } | Self::NotCollectable | Self::Unsupported
        )
    }

    /// The words for the member, when the answer leaves the socket closed or open without a
    /// claim. `None` for a grant.
    #[must_use]
    pub fn notice(&self) -> Option<CollectionNotice> {
        match self {
            Self::Granted { .. } => None,
            Self::NotCollectable => Some(CollectionNotice::NotCollectedByVta),
            Self::Unsupported => Some(CollectionNotice::VtaPredatesClaims),
            Self::Held => Some(CollectionNotice::HeldElsewhere),
            Self::NotRenewable => Some(CollectionNotice::ReleasedElsewhere),
            Self::Refused(why) => Some(CollectionNotice::Refused(why.clone())),
            Self::Unreachable(why) => Some(CollectionNotice::VtaUnreachable(why.clone())),
        }
    }
}

/// What the member is told about a persona's collection, in words (the activity log).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CollectionNotice {
    /// The VTA never collects for this persona; its socket connects without a claim.
    NotCollectedByVta,
    /// The VTA predates collection claims; the socket connects without one.
    VtaPredatesClaims,
    /// Another client holds the claim; the socket stays closed.
    HeldElsewhere,
    /// The claim was released by another party; the socket closes before its end and stays
    /// closed until reconnected by hand.
    ReleasedElsewhere,
    /// The VTA refused the claim; the socket stays closed.
    Refused(String),
    /// The VTA did not answer; the socket stays closed and the claim is asked again later.
    VtaUnreachable(String),
    /// The claim could not be renewed in time, so the socket was closed before it ended.
    Lapsed,
}

impl std::fmt::Display for CollectionNotice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotCollectedByVta => f.write_str(
                "your VTA does not collect messages for this persona, so this app collects them \
                 without a claim",
            ),
            Self::VtaPredatesClaims => f.write_str(
                "your VTA is too old to take collection claims (it cannot collect for this \
                 persona either), so this app collects its messages without one",
            ),
            Self::HeldElsewhere => f.write_str(
                "another of your apps or devices is collecting this persona's messages, so this \
                 app has not connected it. Close it there, or release its claim \
                 (`pnm collection release`), and this app will connect it",
            ),
            Self::ReleasedElsewhere => f.write_str(
                "this app's claim to collect the persona's messages was released from elsewhere, \
                 so it disconnects the persona before the claim ends. Reconnect it from Settings \
                 to collect here again",
            ),
            Self::Refused(why) => write!(
                f,
                "your VTA refused to let this app collect the persona's messages ({why}), so it \
                 has not connected it"
            ),
            Self::VtaUnreachable(why) => write!(
                f,
                "your VTA could not be asked whether this app may collect the persona's messages \
                 ({why}), so it has not connected it yet and will ask again"
            ),
            Self::Lapsed => f.write_str(
                "this app could not renew its claim to collect the persona's messages in time, \
                 so it disconnected the persona; it will connect it again once the VTA answers",
            ),
        }
    }
}

/// The `vta/collection/claim/0.1` payload.
///
/// # Errors
///
/// A context id or DID the specification refuses.
pub fn claim_payload(target: &CollectionTarget, duration_secs: i64) -> Result<Value, String> {
    let p: claim::Payload = claim::Payload::builder()
        .context_id(target.context_id.as_str())
        .identifier(target.identifier.as_str())
        .duration_seconds(Some(duration_secs))
        .try_into()
        .map_err(|e| format!("vta/collection/claim payload: {e}"))?;
    serde_json::to_value(p).map_err(|e| e.to_string())
}

/// The `vta/collection/release/0.1` payload.
///
/// # Errors
///
/// A context id or DID the specification refuses.
pub fn release_payload(target: &CollectionTarget) -> Result<Value, String> {
    let p: release::Payload = release::Payload::builder()
        .context_id(target.context_id.as_str())
        .identifier(target.identifier.as_str())
        .try_into()
        .map_err(|e| format!("vta/collection/release payload: {e}"))?;
    serde_json::to_value(p).map_err(|e| e.to_string())
}

/// The local part of a declared error code (`vta/collection/claim:claimHeld` → `claimHeld`).
fn local_code(code: &str) -> &str {
    code.rsplit_once(':').map_or(code, |(_, local)| local)
}

/// Read a claim's outcome.
#[must_use]
pub fn classify(answer: Result<Value, VtaError>) -> ClaimAnswer {
    match answer {
        Ok(v) => match serde_json::from_value::<claim::Response>(v) {
            Ok(r) => ClaimAnswer::Granted {
                ends_at: r.ends_at,
                renewed: r.renewed.unwrap_or(false),
            },
            Err(e) => ClaimAnswer::Unreachable(format!("an answer that is not a grant: {e}")),
        },
        Err(VtaError::Rejected { code, message, .. }) => match local_code(&code) {
            "notCollectable" => ClaimAnswer::NotCollectable,
            "claimHeld" => ClaimAnswer::Held,
            "claimNotRenewable" => ClaimAnswer::NotRenewable,
            "unsupportedType" | "unsupportedVersion" => ClaimAnswer::Unsupported,
            _ => ClaimAnswer::Refused(crate::display::sanitize_display(
                &format!("{code}: {message}"),
                256,
            )),
        },
        Err(VtaError::UnsupportedTaskType { .. }) => ClaimAnswer::Unsupported,
        Err(
            e @ (VtaError::Forbidden(_)
            | VtaError::Auth(_)
            | VtaError::Validation(_)
            | VtaError::NotFound(_)
            | VtaError::Conflict(_)
            | VtaError::Gone(_)
            | VtaError::DidcommRemote { .. }),
        ) => ClaimAnswer::Refused(crate::display::sanitize_display(&e.to_string(), 256)),
        Err(e) => ClaimAnswer::Unreachable(crate::display::sanitize_display(&e.to_string(), 256)),
    }
}

/// Claim (or renew) collection of `target` for `duration_secs`.
pub async fn claim(vta: &VtaClient, target: &CollectionTarget, duration_secs: i64) -> ClaimAnswer {
    let payload = match claim_payload(target, duration_secs) {
        Ok(p) => p,
        Err(e) => return ClaimAnswer::Refused(e),
    };
    classify(vta.collection_claim_json(payload).await)
}

/// Release this client's claim for `target`. Call only once the socket is closed
/// (VTI-NTF-083).
///
/// # Errors
///
/// The VTA refused or could not be reached; the claim then ends at its end.
pub async fn release(vta: &VtaClient, target: &CollectionTarget) -> Result<(), String> {
    let payload = release_payload(target)?;
    vta.collection_release_json(payload)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// When a claim granted at `granted_at` and ending at `ends_at` is renewed: half-way.
#[must_use]
pub fn renew_at(granted_at: DateTime<Utc>, ends_at: DateTime<Utc>) -> DateTime<Utc> {
    granted_at + (ends_at - granted_at) / 2
}

/// The last instant the socket may stay open on a claim ending at `ends_at`.
#[must_use]
pub fn close_by(ends_at: DateTime<Utc>) -> DateTime<Utc> {
    ends_at - CLOCK_SKEW
}

/// The wait before a refused persona's claim is asked again, after `attempts` refusals.
#[must_use]
pub fn retry_after(answer: &ClaimAnswer, attempts: u32) -> std::time::Duration {
    let base = match answer {
        ClaimAnswer::Unreachable(_) => std::time::Duration::from_secs(30),
        _ => std::time::Duration::from_secs(60),
    };
    base.saturating_mul(1u32 << attempts.min(5)).min(RETRY_CAP)
}

/// The time until `at`, zero once it has passed.
fn until(at: DateTime<Utc>) -> std::time::Duration {
    (at - Utc::now()).to_std().unwrap_or_default()
}

/// A claim this client holds for one listener.
#[derive(Debug)]
struct Held {
    target: CollectionTarget,
    granted_at: DateTime<Utc>,
    ends_at: DateTime<Utc>,
    renewable: bool,
    /// Bumped by every grant, so a superseded renewal task stops.
    generation: u64,
    renewal: Option<tokio::task::AbortHandle>,
}

/// A persona whose claim was refused, waiting to be asked again.
#[derive(Clone)]
pub(crate) struct Waiting {
    pub(crate) spec: crate::didcomm::ListenerSpec,
    pub(crate) due: std::time::Instant,
    pub(crate) attempts: u32,
}

/// The claims of one messaging runtime: the VTA they are made at, the claims held per listener,
/// and the personas waiting to be asked again.
#[derive(Default)]
pub struct Collection {
    vta: RwLock<Option<VtaClient>>,
    held: Mutex<HashMap<String, Held>>,
    pub(crate) waiting: Mutex<HashMap<String, Waiting>>,
    /// The last notice per listener, so a retry that is refused the same way says nothing new.
    told: Mutex<HashMap<String, CollectionNotice>>,
    generation: std::sync::atomic::AtomicU64,
}

impl Collection {
    /// The VTA claims are made at. Replaced whenever the admin session is rebuilt.
    pub fn set_vta(&self, vta: Option<VtaClient>) {
        *self
            .vta
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = vta;
    }

    fn vta(&self) -> Option<VtaClient> {
        self.vta
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Whether `notice` is new for `listener_id` (and remember it).
    pub(crate) fn is_new(&self, listener_id: &str, notice: &CollectionNotice) -> bool {
        let mut told = self
            .told
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if told.get(listener_id) == Some(notice) {
            return false;
        }
        told.insert(listener_id.to_string(), notice.clone());
        true
    }

    /// Forget what `listener_id` was told: it was granted, so a later refusal is news again.
    pub(crate) fn forget_told(&self, listener_id: &str) {
        self.told
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(listener_id);
    }

    /// Ask the VTA for the claim `target` needs before `listener_id` connects.
    pub(crate) async fn ask(&self, target: &CollectionTarget) -> ClaimAnswer {
        match self.vta() {
            Some(vta) => claim(&vta, target, ASKED_CLAIM_SECS).await,
            None => ClaimAnswer::Unreachable("no session with your VTA".into()),
        }
    }

    /// Record a grant for `listener_id`, superseding any claim recorded for it. Returns the
    /// generation the renewal task runs under.
    pub(crate) fn record_grant(
        &self,
        listener_id: &str,
        target: &CollectionTarget,
        ends_at: DateTime<Utc>,
    ) -> u64 {
        let generation = self
            .generation
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        let mut held = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(old) = held.remove(listener_id)
            && let Some(task) = old.renewal
        {
            task.abort();
        }
        held.insert(
            listener_id.to_string(),
            Held {
                target: target.clone(),
                granted_at: Utc::now(),
                ends_at,
                renewable: true,
                generation,
                renewal: None,
            },
        );
        generation
    }

    /// Attach the renewal task of `generation` to its claim.
    pub(crate) fn attach_renewal(
        &self,
        listener_id: &str,
        generation: u64,
        task: tokio::task::AbortHandle,
    ) {
        let mut held = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match held.get_mut(listener_id) {
            Some(h) if h.generation == generation => h.renewal = Some(task),
            _ => task.abort(),
        }
    }

    /// The claim of `generation` for `listener_id`: (target, granted at, ends at, renewable).
    pub(crate) fn current(
        &self,
        listener_id: &str,
        generation: u64,
    ) -> Option<(CollectionTarget, DateTime<Utc>, DateTime<Utc>, bool)> {
        let held = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        held.get(listener_id)
            .filter(|h| h.generation == generation)
            .map(|h| (h.target.clone(), h.granted_at, h.ends_at, h.renewable))
    }

    /// Apply a renewal's answer to the claim of `generation`.
    pub(crate) fn renewed(&self, listener_id: &str, generation: u64, ends_at: DateTime<Utc>) {
        let mut held = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(h) = held
            .get_mut(listener_id)
            .filter(|h| h.generation == generation)
        {
            h.granted_at = Utc::now();
            h.ends_at = ends_at;
        }
    }

    /// The claim of `generation` can no longer be renewed: it ends at its end.
    pub(crate) fn unrenewable(&self, listener_id: &str, generation: u64) {
        let mut held = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(h) = held
            .get_mut(listener_id)
            .filter(|h| h.generation == generation)
        {
            h.renewable = false;
        }
    }

    /// Stop tracking the claim of `generation` (the VTA no longer collects for the identifier).
    pub(crate) fn drop_claim(&self, listener_id: &str, generation: u64) {
        let mut held = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if held
            .get(listener_id)
            .is_some_and(|h| h.generation == generation)
        {
            held.remove(listener_id);
        }
    }

    /// Release the claim recorded for `listener_id`, if any, and forget it. The caller has
    /// closed its socket.
    pub(crate) async fn release_now(&self, listener_id: &str) {
        let taken = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(listener_id);
        let Some(h) = taken else {
            return;
        };
        if let Some(task) = h.renewal {
            task.abort();
        }
        let Some(vta) = self.vta() else {
            return;
        };
        if let Err(e) = release(&vta, &h.target).await {
            tracing::debug!(
                listener = %crate::display::truncate_did(listener_id, 32),
                "the collection claim was not released ({e}); it ends at its end"
            );
        }
    }

    /// Whether a claim is recorded for `listener_id`.
    pub(crate) fn holds(&self, listener_id: &str) -> bool {
        self.held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(listener_id)
    }

    /// Release every claim held — the runtime is stopping, its sockets already closed — bounded
    /// as a whole.
    pub(crate) async fn release_all(&self) {
        let ids: Vec<String> = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .keys()
            .cloned()
            .collect();
        self.waiting
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        let all = futures_util::future::join_all(ids.iter().map(|id| self.release_now(id)));
        let _ = tokio::time::timeout(SHUTDOWN_RELEASE_TIMEOUT, all).await;
    }
}

/// The renewal of one claim, for as long as its listener is meant to be up: renew at half-time,
/// and close the socket before the end less [`CLOCK_SKEW`] unless renewed (VTI-NTF-083).
pub(crate) async fn renew_loop(
    service: crate::didcomm::Messaging,
    listener_id: String,
    generation: u64,
) {
    let collection = service.collection();
    loop {
        let Some((target, granted_at, ends_at, renewable)) =
            collection.current(&listener_id, generation)
        else {
            return;
        };
        let deadline = close_by(ends_at);
        let wake = if renewable {
            renew_at(granted_at, ends_at).min(deadline)
        } else {
            deadline
        };
        tokio::time::sleep(until(wake)).await;
        if !service.collects_for(&listener_id).await {
            // Removed for good: its socket is closed, so the claim goes.
            collection.release_now(&listener_id).await;
            return;
        }
        if !renewable || Utc::now() >= deadline {
            service.close_for_collection(&listener_id, renewable).await;
            return;
        }
        // Renew, retrying until the socket must close.
        loop {
            let answer = collection.ask(&target).await;
            match answer {
                ClaimAnswer::Granted { ends_at, .. } => {
                    collection.renewed(&listener_id, generation, ends_at);
                    break;
                }
                ClaimAnswer::NotCollectable | ClaimAnswer::Unsupported => {
                    // The VTA no longer collects for it at all, so nothing is evicted.
                    collection.drop_claim(&listener_id, generation);
                    service.tell(&listener_id, answer.notice());
                    return;
                }
                ClaimAnswer::NotRenewable | ClaimAnswer::Held | ClaimAnswer::Refused(_) => {
                    collection.unrenewable(&listener_id, generation);
                    service.tell(&listener_id, answer.notice());
                    break;
                }
                ClaimAnswer::Unreachable(_) => {
                    let next = Utc::now() + RENEW_RETRY;
                    if next >= deadline {
                        tokio::time::sleep(until(deadline)).await;
                        service.close_for_collection(&listener_id, true).await;
                        return;
                    }
                    tokio::time::sleep(until(next)).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn target() -> CollectionTarget {
        CollectionTarget {
            context_id: "personal".into(),
            identifier: "did:webvh:QmScid:example.com:alice".into(),
        }
    }

    fn rejected(code: &str) -> VtaError {
        VtaError::Rejected {
            code: code.into(),
            message: "refused".into(),
            details: None,
        }
    }

    /// VTI-NTF-083: the claim asks for twenty-four hours, for the persona in its context.
    #[test]
    fn the_claim_asks_for_twenty_four_hours() {
        let p = claim_payload(&target(), ASKED_CLAIM_SECS).unwrap();
        assert_eq!(
            p,
            json!({
                "contextId": "personal",
                "identifier": "did:webvh:QmScid:example.com:alice",
                "durationSeconds": 86400
            })
        );
        let r = release_payload(&target()).unwrap();
        assert_eq!(
            r,
            json!({ "contextId": "personal", "identifier": "did:webvh:QmScid:example.com:alice" })
        );
    }

    #[test]
    fn a_grant_is_read_with_its_end() {
        let a = classify(Ok(json!({
            "identifier": "did:webvh:QmScid:example.com:alice",
            "endsAt": "2026-11-05T10:00:00Z",
            "renewed": true
        })));
        assert_eq!(
            a,
            ClaimAnswer::Granted {
                ends_at: "2026-11-05T10:00:00Z".parse().unwrap(),
                renewed: true
            }
        );
        assert!(a.may_connect());
        assert!(a.notice().is_none());
    }

    /// The declared refusals by their local code; only `notCollectable` (and a VTA that cannot
    /// collect at all) lets the socket connect without a claim.
    #[test]
    fn the_refusals_decide_whether_to_connect() {
        let held = classify(Err(rejected("vta/collection/claim:claimHeld")));
        assert_eq!(held, ClaimAnswer::Held);
        assert!(!held.may_connect());
        let gone = classify(Err(rejected("vta/collection/claim:claimNotRenewable")));
        assert_eq!(gone, ClaimAnswer::NotRenewable);
        assert!(!gone.may_connect());
        let never = classify(Err(rejected("vta/collection/claim:notCollectable")));
        assert_eq!(never, ClaimAnswer::NotCollectable);
        assert!(never.may_connect());
        let old = classify(Err(VtaError::UnsupportedTaskType {
            type_uri: "https://trusttasks.org/spec/vta/collection/claim/0.1".into(),
            served_versions: vec![],
        }));
        assert_eq!(old, ClaimAnswer::Unsupported);
        assert!(old.may_connect());
        let denied = classify(Err(rejected("permissionDenied")));
        assert!(matches!(denied, ClaimAnswer::Refused(_)));
        assert!(!denied.may_connect());
        let silent = classify(Err(VtaError::DidcommTransport("timed out".into())));
        assert!(matches!(silent, ClaimAnswer::Unreachable(_)));
        assert!(!silent.may_connect());
        // An answer that does not read as a grant is not a grant.
        assert!(matches!(
            classify(Ok(json!({ "endsAt": "soon" }))),
            ClaimAnswer::Unreachable(_)
        ));
    }

    /// Renew at half the period granted; close before the end less the skew.
    #[test]
    fn renewal_is_at_half_time_and_the_socket_closes_before_the_end() {
        let granted: DateTime<Utc> = "2026-11-04T00:00:00Z".parse().unwrap();
        let ends: DateTime<Utc> = "2026-11-05T00:00:00Z".parse().unwrap();
        assert_eq!(
            renew_at(granted, ends),
            "2026-11-04T12:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
        assert_eq!(close_by(ends), ends - Duration::seconds(120));
        assert!(close_by(ends) > renew_at(granted, ends));
    }

    #[test]
    fn refused_claims_are_asked_again_with_backoff() {
        let held = ClaimAnswer::Held;
        assert_eq!(retry_after(&held, 0), std::time::Duration::from_secs(60));
        assert_eq!(retry_after(&held, 1), std::time::Duration::from_secs(120));
        assert_eq!(retry_after(&held, 30), RETRY_CAP);
        let silent = ClaimAnswer::Unreachable("x".into());
        assert_eq!(retry_after(&silent, 0), std::time::Duration::from_secs(30));
    }

    #[test]
    fn a_refusal_is_said_once() {
        let c = Collection::default();
        assert!(c.is_new("p", &CollectionNotice::HeldElsewhere));
        assert!(!c.is_new("p", &CollectionNotice::HeldElsewhere));
        assert!(c.is_new("p", &CollectionNotice::Lapsed));
        c.forget_told("p");
        assert!(c.is_new("p", &CollectionNotice::Lapsed));
    }

    #[test]
    fn a_superseded_grant_keeps_only_the_newest() {
        let c = Collection::default();
        let ends = Utc::now() + Duration::hours(24);
        let first = c.record_grant("p", &target(), ends);
        let second = c.record_grant("p", &target(), ends);
        assert!(c.current("p", first).is_none());
        assert!(c.current("p", second).is_some());
        c.unrenewable("p", second);
        assert!(!c.current("p", second).unwrap().3);
        c.drop_claim("p", first);
        assert!(c.holds("p"), "a stale generation does not drop the claim");
        c.drop_claim("p", second);
        assert!(!c.holds("p"));
    }
}
