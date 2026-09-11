//! DIDComm **transport** plumbing: listener construction, routing, outbound
//! sending, and listener lifecycle.
//!
//! Runs on the **delivery layer** (`affinidi-messaging-delivery`): one
//! [`MessagingService`] holding one `DidCommTransport` per identity, with a
//! durable outbox behind every send.
//!
//! It used to wrap `affinidi-messaging-didcomm-service`, the type-routed framework
//! both VTI services cut away from (#189). That crate is no longer a dependency of
//! this workspace.
//!
//! ## Why this is in `openvtc-core` and not the TUI
//!
//! It lived at `openvtc/src/state_handler/didcomm.rs` until the delivery-layer
//! migration (#189) needed it under test. `openvtc` is a **binary-only** crate
//! (`[[bin]]`, no `src/lib.rs`), so no integration test can import it — which is
//! why this module, alone among OpenVTC's messaging code, had no coverage beyond
//! two pure unit groups. Its failure mode is `duplicate-channel` and duelling
//! reconnect loops, which produce neither a compile error nor a failing unit
//! test, so rewriting it without integration coverage was the wrong trade.
//!
//! Nothing here referenced the binary crate, so the move is mechanical.
//!
//! ## Relationship to [`crate::messaging`]
//!
//! Deliberately separate, and the split is load-bearing:
//!
//! - [`crate::messaging`] is **pure protocol logic** — inbound handling over core
//!   domain types, no async I/O orchestration. That purity is what makes the
//!   dispatch state machine unit-testable, so transport plumbing must not leak
//!   into it.
//! - this module is the **transport**: sockets, listeners, mediators, retries.
//!
//! The one crossing point is [`crate::messaging::build_didcomm_message`],
//! re-exported below because building a message is pure and belongs with the
//! protocol logic.

use crate::config::Config;
use crate::relationships::RelationshipState;
/// A listener's live connection state, re-exported so consumers of this module
/// need not depend on `affinidi-messaging-core` directly.
pub use affinidi_messaging_core::ConnState;
use affinidi_messaging_core::MessageTransport;
use affinidi_messaging_core::types::Protocol;
use affinidi_messaging_delivery::{
    Delivery, InMemoryOutboxStore, MessagingService, OutboxStore, drain_loop_via,
};
use affinidi_messaging_sdk::DidCommTransport;
/// A picked-up frame, tagged by protocol — the stored-mail counterpart of the
/// live stream's `Protocol`-tagged `Inbound`.
use affinidi_messaging_sdk::protocols::message_pickup::InboundFrame;
use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::common::config::TDKConfig;
use affinidi_tdk::common::profiles::TDKProfile;
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::secrets_resolver::SecretsResolver;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::debug;

/// Anything that can go wrong bringing a listener up or sending through one.
#[derive(Debug, thiserror::Error)]
pub enum MessagingError {
    /// The identity's ATM / profile / websocket could not be established.
    #[error("could not bring up listener {listener_id}: {reason}")]
    Listener { listener_id: String, reason: String },
    /// A send named a listener that is not installed. Distinct from a transport
    /// failure: this is a caller bug or a torn-down listener, not the network
    /// (R6.4 — the operator must be able to tell them apart).
    #[error("no listener installed for {0}")]
    UnknownListener(String),
    /// Packing the message for the recipient failed.
    #[error("could not pack message for {recipient}: {reason}")]
    Pack { recipient: String, reason: String },
    /// The delivery layer rejected the send or the outbox enqueue.
    #[error("send failed: {0}")]
    Send(String),
}

/// How a listener is described, independently of the framework that runs it.
///
/// The delivery-layer swap replaces `ListenerConfig` (a
/// `affinidi-messaging-didcomm-service` type) with an ATM profile plus a
/// `DidCommTransport`, and the two have no common constructor. This spec is the
/// shape both can be built from — DID, mediator, label, secrets — so the callers
/// that build listeners (persona reconnect, relationship creation) name *what*
/// they want without naming *which* framework runs it.
///
/// Deliberately not `ListenerConfig` re-exported: keeping the framework type in
/// the signatures is what would force every caller to change again at the swap.
#[derive(Clone)]
pub struct ListenerSpec {
    /// The listener id — the DID, per [`persona_listener_id`].
    pub id: String,
    /// The identity this listener speaks as.
    pub did: String,
    /// The mediator it connects through.
    pub mediator_did: String,
    /// Human label for the messaging profile (the community, or the relationship).
    pub label: String,
    /// Signing + key-agreement secrets for [`did`](Self::did).
    pub secrets: Vec<Secret>,
}

impl std::fmt::Debug for ListenerSpec {
    /// Hand-written so the secrets are never rendered.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ListenerSpec")
            .field("id", &self.id)
            .field("did", &self.did)
            .field("mediator_did", &self.mediator_did)
            .field("label", &self.label)
            .field(
                "secrets",
                &format_args!("<{} redacted>", self.secrets.len()),
            )
            .finish()
    }
}

/// DIDComm trust-ping / trust-pong types.
///
/// Re-declared rather than imported from the framework: this module is moving off
/// `affinidi-messaging-didcomm-service`, and these two constants are the only part
/// of its type vocabulary the dispatcher still needs. `vtc-service` re-declared the
/// same pair for the same reason when it cut over.
const TRUST_PING_TYPE: &str = "https://didcomm.org/trust-ping/2.0/ping";
const TRUST_PONG_TYPE: &str = "https://didcomm.org/trust-ping/2.0/ping-response";

/// How often the drain retries a queued outbound message.
///
/// The outbox replaces the framework's `send_message_with_retry` (3 attempts, 2 s
/// exponential, on a disconnected listener). A short interval keeps the common
/// case — a send issued moments before the socket settles — feeling immediate;
/// the per-entry exponential backoff in `drain_once_via` is what stops a genuinely
/// unreachable mediator from being hammered.
const DRAIN_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

/// The delivery window for an outbound message before the outbox settles it
/// visibly rather than retrying forever (R1.2 — every wait is bounded).
///
/// Generous relative to the framework's ~6 s of retries, because the outbox
/// survives a reconnect where the old path simply failed. Past this the entry
/// becomes `Failed` and is surfaced, never a silent success.
const DELIVER_BY: std::time::Duration = std::time::Duration::from_secs(120);

/// How often listener connection state is sampled for the activity log.
///
/// The framework pushed `ListenerEvent`s; the delivery layer exposes a live state
/// per transport instead, so transitions are sampled. 500 ms is well inside human
/// perception for a status line and cheap — reading a `watch` borrow per transport.
const LIFECYCLE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// Two disconnects closer together than this are reported as rapid cycling —
/// usually a duplicate connection fighting itself for one DID.
const CYCLING_WINDOW: std::time::Duration = std::time::Duration::from_secs(10);

/// A drop that recovers within this is reported as a **reconnect**, not a fault.
///
/// The messaging stack reconnects on purpose, on a schedule. The mediator's
/// access token lives ~900 s and the SDK's websocket transport refreshes it
/// proactively at 80% of that, tearing the socket down and bringing it back as
/// part of the refresh: one drop per token per listener, every ~12 minutes, back
/// inside a second or two. That is the healthy steady state — it is what
/// affinidi-tdk-rs #716 *reduced* the count to, from four — and it is not
/// something an operator can act on.
///
/// Reporting it as `disconnected (no transport error reported)` made the
/// activity log's most alarming line the one it printed most often, which is the
/// failure mode that costs a real disconnect its meaning. So a drop is held
/// briefly before it is reported: if the listener returns first, the pair
/// becomes one calm line, and the `Disconnected` line keeps its meaning of "it
/// is *still* down".
///
/// 15 s is chosen to sit far above what a refresh costs (1-2 s observed) and far
/// below the supervisor's [`REBUILD_GRACE`] of 90 s, so nothing this suppresses
/// is anything the supervisor would have acted on either.
const RECONNECT_GRACE: std::time::Duration = std::time::Duration::from_secs(15);

/// How often held-back drops are re-examined. Bounds how late a real
/// disconnect can be reported: [`RECONNECT_GRACE`] plus one of these.
const PENDING_DROP_SWEEP: std::time::Duration = std::time::Duration::from_secs(1);

/// Buffered connection transitions per subscriber. Transitions are rare (a
/// listener connects, drops, reconnects), so this is generous; a subscriber that
/// still lags reports the gap rather than silently missing a state change.
const LISTENER_STATUS_CAPACITY: usize = 64;

/// How long a transport may sit non-`Connected` before the supervisor treats it as
/// dead and rebuilds it.
///
/// **This being generous is the safety property, not a conservatism.** A
/// `DidCommTransport` whose socket drops is *already retrying* inside its ATM —
/// `ConnState::Disconnected` means "dropped, retrying or idle", not "gone". If the
/// supervisor rebuilt on that, its fresh socket would race the ATM's own retry for
/// the same DID, and the mediator rejects the second with `duplicate-channel`: the
/// supervisor would *manufacture* the duelling-reconnect failure it exists to
/// recover from (#132).
///
/// So the grace period has to exceed the window in which a healthy reconnect
/// completes. 90 s is well past that while still bounding how long a genuinely
/// dead persona listener can strand a community (R1.2).
const REBUILD_GRACE: std::time::Duration = std::time::Duration::from_secs(90);

/// First rebuild backoff; doubles per consecutive failed attempt.
const REBUILD_BACKOFF_BASE: std::time::Duration = std::time::Duration::from_secs(5);

/// Rebuild backoff ceiling. Mirrors the framework's old `RestartPolicy`, which
/// capped at 60 s — a listener that cannot come back should keep trying forever at
/// a rate that neither hammers the mediator nor gives up on it.
const REBUILD_BACKOFF_CAP: std::time::Duration = std::time::Duration::from_secs(60);

/// How often the supervisor evaluates transports.
const SUPERVISOR_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// How many stored messages one pickup round asks the mediator for. The SDK
/// caps a delivery-request at 100; 50 keeps a single `delivery` response small
/// while still clearing a normal mailbox in one round trip.
const PICKUP_PAGE: usize = 50;

/// Ceiling on one pickup's total (R1.4 — a loop over a peer's data is bounded).
/// A mailbox larger than this is a pathology, not a backlog; the remainder stays
/// stored and is collected on the next connect rather than flooding the event
/// channel in one go.
const PICKUP_MAX: usize = 200;

/// Backoff before the `attempts`-th consecutive rebuild: 5 s, 10 s, 20 s, 40 s,
/// then capped at 60 s. `attempts == 0` (none yet) is no wait.
fn rebuild_backoff(attempts: u32) -> std::time::Duration {
    if attempts == 0 {
        return std::time::Duration::ZERO;
    }
    let shifted = REBUILD_BACKOFF_BASE
        .checked_mul(1u32 << attempts.saturating_sub(1).min(4))
        .unwrap_or(REBUILD_BACKOFF_CAP);
    shifted.min(REBUILD_BACKOFF_CAP)
}

/// Whether a transport that has been down for `down_for` is due a rebuild.
///
/// Split out from the supervisor loop because this is the whole risk: rebuilding
/// too eagerly causes `duplicate-channel`, and never rebuilding strands the
/// listener. A pure function is something tests can pin both ways.
fn rebuild_due(
    down_for: std::time::Duration,
    attempts: u32,
    since_last_attempt: Option<std::time::Duration>,
) -> bool {
    if down_for < REBUILD_GRACE {
        return false;
    }
    match since_last_attempt {
        None => true,
        Some(elapsed) => elapsed >= rebuild_backoff(attempts),
    }
}

/// What the supervisor knows about one transport that is currently down.
#[derive(Debug, Clone, Copy)]
struct DownSince {
    first_seen: std::time::Instant,
    attempts: u32,
    last_attempt: Option<std::time::Instant>,
}

/// One identity's wire: the ATM and profile outbound packing needs.
///
/// The delivery layer's `MessageTransport::send` takes **already-packed** bytes —
/// packing is `MessagingProtocol`'s concern, not the transport's — so sending *as*
/// an identity needs that identity's ATM, not just its transport. The framework
/// hid this behind `send_message(listener_id, …)`.
struct IdentityWire {
    atm: ATM,
    /// The ATM profile the wire speaks through. Held because message-pickup is a
    /// profile-scoped operation (`send_delivery_request_frames`,
    /// `send_messages_received`), and the transport does not surface the profile
    /// it was bound to.
    profile: Arc<ATMProfile>,
    did: String,
    /// Kept so the supervisor can rebuild this identity's wire from scratch.
    ///
    /// A `DidCommTransport` is bound to the ATM task that owns its websocket. That
    /// task retries internally, but if it dies outright the transport is stale
    /// forever and nothing else can revive it — the framework's `RestartPolicy`
    /// used to. Rebuilding means constructing a fresh ATM, profile and transport,
    /// which needs the same inputs as the first time.
    spec: ListenerSpec,
    /// This identity's outbox drain, held here rather than in
    /// [`MessagingInner::tasks`] so removing the listener can abort *its* drain
    /// and nobody else's.
    ///
    /// Load-bearing for teardown, not just tidiness: the drain owns a clone of
    /// the `Arc<dyn MessageTransport>`, which owns the ATM. A drain left running
    /// keeps the whole wire — and therefore its mediator socket — alive after the
    /// listener is gone.
    drain: tokio::task::JoinHandle<()>,
}

/// Stop a removed wire's drain and close its mediator websocket.
///
/// Everything here has to happen **before** the caller can install a listener for
/// the same DID again, which is why it is not left to `Drop`:
///
/// - `affinidi-messaging-sdk` has no `Drop` for `ATM`. Dropping the handle stops
///   nothing; the websocket task holds its own `Arc<SharedState>` and keeps
///   running — and reconnecting — indefinitely.
/// - The delivery layer's `remove_transport` aborts its forwarder and drops the
///   service's `Arc` to the transport, but the drain task holds another.
///
/// So a removal that only forgot the wire left a live, auto-reconnecting socket
/// holding the mediator's one-socket-per-DID slot. The next `add_listener` for
/// that DID then opened a second one and the two evicted each other forever —
/// which is what a user sees as a listener flapping every 30-60 s with "no
/// transport error reported". The SDK documents the same failure on
/// `ATM::graceful_shutdown`: an orphaned session "auto-reconnects on its own timer
/// and holds the mediator's one-socket-per-DID slot for its profile".
///
/// Returns the ATM with its remaining teardown (the deletion handler) still to
/// do. That step is bounded but not instant — up to the SDK's 5 s drain timeout —
/// so the caller chooses whether to await it or let it finish detached. The
/// socket, which is the part another listener contends for, is already closed
/// either way.
async fn quiesce_wire(listener_id: &str, wire: IdentityWire) -> ATM {
    wire.drain.abort();
    if let Err(e) = wire.profile.stop_websocket().await {
        // Non-fatal and worth exactly one line: the ATM shutdown that follows
        // stops the same websocket, so this is a "the fast path did not work"
        // note rather than a leak in its own right.
        debug!(
            listener = %crate::display::truncate_did(listener_id, 32),
            error = %e,
            "closing the listener's websocket returned an error; the ATM shutdown will retry it"
        );
    }
    wire.atm
}

/// The runtime messaging handle: one transport per identity, multiplexed through
/// one [`MessagingService`], with a durable outbox behind every send.
///
/// Replaces `DIDCommService`. The shape difference that matters: the framework
/// owned N *listeners*, and this owns N *transports keyed by identity* — the
/// transport determines the proven sender, so "send as this persona" is
/// `send_via(persona_did, …)` rather than a listener lookup.
///
/// Cheap to clone (`Arc` inside), because call sites hand it to spawned tasks.
#[derive(Clone)]
pub struct Messaging {
    inner: Arc<MessagingInner>,
}

/// A listener's connection transition, broadcast to every interested consumer.
///
/// Replaces the framework's `ListenerEvent`. Emitted by the single connection
/// poller [`Messaging`] owns, so the session manager and the activity log observe
/// the *same* transitions rather than each sampling independently and disagreeing.
#[derive(Debug, Clone)]
pub enum ListenerStatus {
    Connected {
        listener_id: String,
    },
    Disconnected {
        listener_id: String,
        /// Always `None` on the delivery layer: a transport surfaces a *state*,
        /// not a cause, and the framework's socket error has no equivalent here.
        /// Kept so the session manager's failed-vs-disconnected distinction stays
        /// expressible if the transport ever carries a reason.
        error: Option<String>,
    },
}

struct MessagingInner {
    service: Arc<MessagingService>,
    /// Connection transitions from the one poller.
    status_tx: tokio::sync::broadcast::Sender<ListenerStatus>,
    /// Shared by every identity's drain. One store, `via`-partitioned, so each
    /// entry is claimed by exactly one `drain_loop_via` (see
    /// `affinidi-messaging-delivery` 0.1.12).
    outbox: Arc<dyn OutboxStore>,
    identities: tokio::sync::RwLock<HashMap<String, IdentityWire>>,
    /// Where [`Messaging::pickup_stored`] hands a stored message off. The live
    /// dispatcher owns its own clone; this one exists because a pickup emits the
    /// *same* events by the *same* route, so a consumer cannot tell (and must
    /// not have to) whether a message was streamed or collected.
    event_tx: mpsc::UnboundedSender<DIDCommEvent>,
    /// Listener ids with a pickup currently running, so a flapping socket
    /// cannot stack overlapping drains of the same mailbox.
    pickup_in_flight: std::sync::Mutex<std::collections::HashSet<String>>,
    /// The runtime's own long-lived tasks — dispatcher, connection poller,
    /// transport supervisor, pickup collector — aborted on
    /// [`Messaging::shutdown`].
    ///
    /// Per-identity drains are **not** here: they live on their
    /// [`IdentityWire`], so that removing one listener aborts its drain without
    /// touching another's (see [`quiesce_wire`]).
    tasks: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl Messaging {
    /// Stand up an empty messaging runtime and start its inbound dispatcher.
    ///
    /// Listeners are added with [`add_listener`]; starting empty is what lets the
    /// dispatcher be running before the first transport connects, so no inbound
    /// frame is missed on a listener that comes up quickly.
    pub fn start(event_tx: mpsc::UnboundedSender<DIDCommEvent>) -> Self {
        let outbox: Arc<dyn OutboxStore> = Arc::new(InMemoryOutboxStore::new());
        let service = Arc::new(MessagingService::empty(outbox.clone()));
        let (status_tx, _) = tokio::sync::broadcast::channel(LISTENER_STATUS_CAPACITY);
        let inner = Arc::new(MessagingInner {
            service: service.clone(),
            status_tx: status_tx.clone(),
            outbox,
            identities: tokio::sync::RwLock::new(HashMap::new()),
            event_tx: event_tx.clone(),
            pickup_in_flight: std::sync::Mutex::new(std::collections::HashSet::new()),
            tasks: std::sync::Mutex::new(Vec::new()),
        });

        let dispatcher = tokio::spawn(dispatch_inbound(service.clone(), event_tx));
        let poller = tokio::spawn(poll_listener_status(service, status_tx));
        {
            let mut tasks = inner.tasks.lock().expect("tasks mutex");
            tasks.push(dispatcher);
            tasks.push(poller);
        }

        let messaging = Self { inner };
        let supervised = messaging.clone();
        let supervisor = tokio::spawn(async move { supervise_transports(supervised).await });
        let collecting = messaging.clone();
        let collector = tokio::spawn(async move { pickup_on_connect(collecting).await });
        {
            let mut tasks = messaging.inner.tasks.lock().expect("tasks mutex");
            tasks.push(supervisor);
            tasks.push(collector);
        }

        messaging
    }

    /// Whether a transport is installed for `listener_id`.
    pub async fn has_listener(&self, listener_id: &str) -> bool {
        self.inner.identities.read().await.contains_key(listener_id)
    }

    /// Every installed listener id.
    pub async fn list_listeners(&self) -> Vec<String> {
        self.inner.identities.read().await.keys().cloned().collect()
    }

    /// Remove a listener: close its mediator socket, stop its drain, and forget
    /// its wire. Queued outbox entries pinned to it stay queued — they are bound
    /// to an identity, and re-routing them would send from the wrong sender — and
    /// settle visibly when their delivery window expires.
    ///
    /// **Returns with the socket closed**, because every caller's next move is
    /// either to add a listener for the same DID (`reconnect_persona_listener_io`,
    /// the supervisor's rebuild, a re-join after a community was removed) or to
    /// leave that DID unserved. Both are wrong if the old socket is still up: see
    // Not an intra-doc link: `quiesce_wire` is private, and a public item linking
    // to it fails `rustdoc -D warnings`.
    /// `quiesce_wire` for what that costs.
    ///
    /// The ATM's remaining teardown finishes in a detached task. It is bounded
    /// (5 s at worst, waiting on the SDK's deletion handler) but this is called
    /// from the state-handler loop, which must not park on it (R13).
    pub async fn remove_listener(&self, listener_id: &str) {
        self.inner.service.remove_transport(listener_id);
        let removed = self.inner.identities.write().await.remove(listener_id);
        if let Some(wire) = removed {
            let atm = quiesce_wire(listener_id, wire).await;
            tokio::spawn(async move { atm.graceful_shutdown().await });
        }
    }

    /// This listener's live connection state, or `None` if not installed.
    pub fn listener_state(&self, listener_id: &str) -> Option<ConnState> {
        self.inner.service.transport_state(listener_id)
    }

    /// The DID a listener speaks as.
    ///
    /// For a persona listener this is the id itself; for a relationship listener
    /// the id is a hash, so the mapping has to be looked up rather than assumed.
    pub async fn listener_did(&self, listener_id: &str) -> Option<String> {
        self.inner
            .identities
            .read()
            .await
            .get(listener_id)
            .map(|wire| wire.did.clone())
    }

    /// Subscribe to listener connection transitions.
    ///
    /// Every subscriber sees the same transitions from the one poller, so the
    /// session manager and the activity log cannot disagree about whether a
    /// listener is up.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<ListenerStatus> {
        self.inner.status_tx.subscribe()
    }

    /// Wait until `listener_id` reports `Connected`, or `timeout` elapses.
    ///
    /// Polls the transport's live signal rather than latching at boot (R6.2), so a
    /// listener that connects, drops and reconnects reads truthfully throughout.
    pub async fn wait_connected(
        &self,
        listener_id: &str,
        timeout: std::time::Duration,
    ) -> Result<(), String> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match self.listener_state(listener_id) {
                Some(ConnState::Connected) => return Ok(()),
                state if tokio::time::Instant::now() >= deadline => {
                    return Err(format!(
                        "listener {listener_id} did not connect within {timeout:?} \
                         (last state: {state:?})"
                    ));
                }
                _ => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
            }
        }
    }

    /// Collect the messages the mediator is **holding** for `listener_id` and
    /// hand them to the state handler on the same channel a live frame uses.
    /// Returns how many were handed off.
    ///
    /// ## Why this exists
    ///
    /// A mediator live-streams a message only to a recipient that is connected
    /// at the instant it lands. Everything else is stored — and stored is where
    /// it stays: the mediator redelivers a stored inbox **only** when a new
    /// socket *displaces* an existing one for the same DID
    /// (`websocket_streaming.rs`, `if replacing`), and enabling live delivery
    /// does not drain anything. So a listener that connects for the first time —
    /// the applicant persona during a join, a community's session coming up
    /// after a restart, any identity whose socket was down when a reply arrived
    /// — hears nothing about what is already waiting for it.
    ///
    /// That is the shape of the join that sits `Pending` with the community's
    /// outbox reporting `Sent`, and it is why relaunching the app "fixes" it:
    /// the new process's socket displaces the old one and the mediator finally
    /// redelivers. Collecting explicitly makes that recovery ours rather than a
    /// side effect of how the previous process happened to exit.
    ///
    /// ## Contract
    ///
    /// Message-pickup 3.0 delivery-request, then `messages-received` for what
    /// was handed off — ack **after** handoff, never before, which is the same
    /// discipline the delivery layer's own dispatcher follows. A frame that
    /// could not be unsealed, mapped, or queued is deliberately **not** acked:
    /// it stays in the mailbox rather than being deleted unread, and the drain
    /// stops there (a stuck frame at the head of the queue would otherwise be
    /// re-fetched forever). Bounded at `PICKUP_MAX` messages per call (R1.4);
    /// the remainder is left for the next connect and logged rather than
    /// silently dropped.
    ///
    /// Delivery is at-least-once by design: a message may also arrive live. The
    /// runtime loop's `SeenMessages` is what makes that harmless.
    pub async fn pickup_stored(&self, listener_id: &str) -> Result<usize, MessagingError> {
        let (atm, profile) = {
            let identities = self.inner.identities.read().await;
            let wire = identities
                .get(listener_id)
                .ok_or_else(|| MessagingError::UnknownListener(listener_id.to_string()))?;
            (wire.atm.clone(), wire.profile.clone())
        };
        let fail = |reason: String| MessagingError::Listener {
            listener_id: listener_id.to_string(),
            reason,
        };

        let mut handed_off = 0usize;
        while handed_off < PICKUP_MAX {
            let batch = atm
                .message_pickup()
                .send_delivery_request_frames(&profile, Some(PICKUP_PAGE), true)
                .await
                .map_err(|e| fail(format!("delivery-request failed: {e}")))?;
            if batch.is_empty() {
                break;
            }
            let requested = batch.len();

            let mut acks: Vec<String> = Vec::with_capacity(requested);
            for (frame, attachment_id) in batch {
                // An attachment the mediator could not hand over: there is
                // nothing to deliver, but it must still be acked or every future
                // pickup re-fetches the same dead entry.
                let Some(frame) = frame else {
                    acks.push(attachment_id);
                    continue;
                };
                let Some((message, transport, from)) =
                    frame_to_message(&atm, &profile, frame).await
                else {
                    continue;
                };
                let events = classify_inbound(message, transport, from, listener_id.to_string());
                // An unroutable type is *handled* — the live path drops it too —
                // so ack it rather than leaving it to be re-fetched forever.
                if events.is_empty() {
                    acks.push(attachment_id);
                    continue;
                }
                // Ack only after the handoff succeeds, so a message we could not
                // take stays stored at the mediator and is offered again. The
                // channel is unbounded, so the only failure left is a departed
                // receiver (shutdown) — in which case leaving it stored is
                // exactly right: the next run collects it.
                let mut queued = true;
                for event in events {
                    if self.inner.event_tx.send(event).is_err() {
                        tracing::debug!(
                            "state handler has gone away during pickup — leaving the message stored"
                        );
                        queued = false;
                        break;
                    }
                }
                if queued {
                    handed_off += 1;
                    acks.push(attachment_id);
                }
            }

            if !acks.is_empty() {
                let acked = acks.len();
                if let Err(e) = atm
                    .message_pickup()
                    // `wait_for_response`: the reply is the mediator's status
                    // after the delete, so waiting is what makes a failed ack
                    // visible here instead of showing up as the same messages
                    // arriving again on the next connect.
                    .send_messages_received(&profile, &acks, true)
                    .await
                {
                    // The messages are already with the state handler; failing to
                    // ack only means the mediator serves them again, which
                    // `SeenMessages` absorbs. Not worth failing the pickup over.
                    tracing::warn!(
                        listener = %crate::display::truncate_did(listener_id, 32),
                        acked,
                        error = %e,
                        "could not acknowledge picked-up messages; they will be offered again"
                    );
                }
            }

            // Only continue once a *whole* full page was accounted for. A frame
            // left unacked stays at the head of the queue, so another round would
            // fetch the same page again — this is what makes the loop terminate
            // without ever deleting something we could not read.
            if acks.len() < requested || requested < PICKUP_PAGE {
                break;
            }
        }

        if handed_off >= PICKUP_MAX {
            tracing::warn!(
                listener = %crate::display::truncate_did(listener_id, 32),
                limit = PICKUP_MAX,
                "stored-message pickup hit its per-connect limit; the rest stays in the mailbox"
            );
        } else if handed_off > 0 {
            tracing::info!(
                listener = %crate::display::truncate_did(listener_id, 32),
                count = handed_off,
                "collected messages the mediator was holding"
            );
        }
        Ok(handed_off)
    }

    /// Stop every drain and the dispatcher, and close every transport.
    ///
    /// Unlike [`remove_listener`](Self::remove_listener) this **awaits** each
    /// ATM's full shutdown: a caller that shuts the runtime down and then builds
    /// a new one (the join flow does exactly that) would otherwise race its own
    /// orphans for the same DIDs.
    pub async fn shutdown(&self) {
        let handles: Vec<_> = std::mem::take(&mut *self.inner.tasks.lock().expect("tasks mutex"));
        for handle in handles {
            handle.abort();
        }
        let wires: Vec<(String, IdentityWire)> =
            self.inner.identities.write().await.drain().collect();
        for (id, wire) in wires {
            self.inner.service.remove_transport(&id);
            quiesce_wire(&id, wire).await.graceful_shutdown().await;
        }
    }
}

/// Fallback listener ID for the persona DID listener when no DID is available
/// (e.g. a State-A account with no persona).
pub const PERSONA_LISTENER_ID: &str = "persona";

/// The listener ID for a persona: **its DID, verbatim**.
///
/// This is an *identity key*, not a label. It keys the rapid-cycling detection
/// map in [`spawn_lifecycle_logger`] and is what reconnect logic matches on, so
/// it has to be collision-free. A DID is; a trailing path segment is not —
/// `did:webvh:ScidA:host1.example:magic-depart` and
/// `did:webvh:ScidB:host2.example:magic-depart` would collapse onto one id and
/// two personas would share a listener. Do not shorten it here.
///
/// It used to run the DID through `context_path::render_for_display` and the doc
/// promised a short slug (`silent-tongue`). That call was always a no-op: it
/// splits on `/`, which a DID has none of, so the whole DID came back. Removing
/// it changes no behaviour and stops the contract claiming something it never
/// delivered.
///
/// Display is a separate concern, handled where the id is *rendered* rather than
/// where it is minted: the runtime loop formats listener ids through
/// `resolve_did_to_display`, so the activity log reads
/// `Listener 'webvh.storm.ws/@magic-depart' connected`.
///
/// Derived from the DID alone (not the full `Config`) so the runtime and message
/// senders (`listener_id_for_did`) agree on the same id without extra context.
pub fn persona_listener_id(persona_did: &str) -> String {
    if persona_did.is_empty() {
        PERSONA_LISTENER_ID.to_string()
    } else {
        persona_did.to_string()
    }
}

/// Build a timestamped DIDComm message with standard 48-hour expiry.
///
/// Re-exported from [`crate::messaging`]; the implementation moved to
/// core (it is pure) so the protocol logic there can build its own messages.
pub use crate::messaging::build_didcomm_message;

/// Which transport carried a message — inbound or outbound.
///
/// A narrowed mirror of the messaging layer's `Protocol`, kept separate on
/// purpose: `Protocol` is `#[non_exhaustive]` and grows upstream, whereas this
/// only ever names transports OpenVTC actually speaks. A new `Protocol`
/// variant is dropped at the pump and never reaches here.
///
/// Serializable because it is also recorded on a `CommunityRecord`: a join that
/// is never acknowledged needs to say *which* transport went unanswered, and
/// that has to survive the restart you make to go looking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessagingTransport {
    /// Authcrypted DIDComm message off the mediator socket.
    DidComm,
    /// TSP frame, arriving on that *same* socket — see the pump's comment.
    Tsp,
}

impl std::fmt::Display for MessagingTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::DidComm => "DIDComm",
            Self::Tsp => "TSP",
        })
    }
}

/// Events sent from DIDComm router handlers to the state handler main loop.
#[derive(Debug)]
pub enum DIDCommEvent {
    /// An inbound message that needs business-logic processing.
    InboundMessage {
        message: Box<Message>,
        #[allow(dead_code)]
        from: Option<String>,
        /// Which transport actually carried this frame.
        ///
        /// The pump knows — it matches on `Protocol` to decode the payload —
        /// but used to drop it here, so every consumer that wanted to say how a
        /// message arrived had to guess. The activity log guessed "DIDComm" and
        /// was wrong for every TSP frame, which is the transport this stack
        /// prefers. Carrying it costs one field and makes the log able to tell
        /// the truth.
        transport: MessagingTransport,
    },
    /// A trust-ping was received — state handler decides whether to respond.
    TrustPingReceived {
        from: Option<String>,
        /// The listener that received the ping (needed to send pong back).
        listener_id: String,
        /// The original message ID (needed for pong thid).
        message_id: String,
    },
    /// A trust-pong response was received.
    TrustPongReceived { from: Option<String> },
}

/// The DIDComm event channel is **unbounded**, deliberately.
///
/// It used to be a 256-slot bounded channel whose overflow behaviour was
/// `try_send` → log → drop, on the reasoning that a pathological mediator should
/// not be able to grow memory without bound. That reasoning missed what a
/// dropped event costs here.
///
/// By the time an event reaches this channel the delivery layer has already
/// acked the message — `run_dispatcher` in `affinidi-messaging-delivery` acks
/// immediately after handing off to its subscriber broadcast — and an ack is a
/// delete at the mediator. So a dropped event is not a deferred message, it is a
/// **permanently destroyed** one, with a single `warn!` line as the only record.
/// These carry membership credentials and join verdicts; #221 is what that looks
/// like from the outside, and it took four services' logs to find.
///
/// Backpressure was never really available anyway. Blocking on a full channel
/// would stall this consumer, the layer's broadcast buffer would overflow
/// instead, and `subscribe()` swallows that as `Lagged` **silently** — strictly
/// worse than the warned drop it replaced. The only choice actually on offer is
/// where the loss happens, so we choose nowhere.
///
/// The memory concern is bounded in practice by the mediator: events arrive only
/// as fast as it delivers, the consumer is the state handler's `select!` (always
/// draining unless mid-await), and the payloads are small. Unbounded growth
/// requires a consumer stalled indefinitely, which is a bug that would strand the
/// UI too — visible, unlike the silent credential loss this replaces.
///
/// Kept as a named constant for the historical record and for anyone who goes
/// looking for the old capacity; nothing reads it.
#[deprecated(
    note = "the event channel is unbounded; this value is retained only to document what it was"
)]
pub const DIDCOMM_EVENT_CHANNEL_CAPACITY: usize = 256;

/// Reason string included in a "Reconnect failed" log entry, plus the
/// updated MediatorStatus the caller should drive into the connection
/// state. Returned to the caller so it can update the State accordingly
/// without this helper having to know about the outer state shape.
pub enum ReconnectOutcome {
    Connected,
    Failed(String),
}

/// Replace the persona listener and wait for it to come up. Used by the
/// mediator-change branch of SubmitEdit and by the manual ReconnectMediator
/// settings action — both go through this dance.
///
/// The work is split in two: `persona_listener_config` builds the new listener
/// config (local-only: reads secrets from the TDK resolver, no network), and
/// [`reconnect_persona_listener_io`] does the slow connect I/O. The runtime loop
/// (R13) drives them separately — building the config on its own thread and
/// handing only the I/O half to a background task — so the up-to-30 s wait no
/// longer parks the select loop. Returns:
///   * `Connected` once the listener reaches the connected state, or
///   * `Failed(reason)` on any error during the replace / connect path.
///
/// This is the I/O-only half: it tears down the existing persona listener,
/// installs the prebuilt `new_config`, and waits up to 30 s for it to connect.
/// It borrows nothing tied to the loop's `Config`/`TDK` — [`Messaging`] is
/// cheap to clone (`Arc`-based) and [`ListenerSpec`]/`listener_id` are owned —
/// which makes it `tokio::spawn`-friendly.
///
/// Active-persona only (these manual actions act on the active identity);
/// per-persona reconnect lands with the persona-selection slice.
pub async fn reconnect_persona_listener_io(
    service: &Messaging,
    listener_id: String,
    new_config: ListenerSpec,
) -> ReconnectOutcome {
    // Drop the old transport first. The mediator permits one websocket per DID,
    // rejecting a second with `duplicate-channel`, so adding before removing would
    // leave two sockets racing on the same identity — the duelling-reconnect
    // failure this codebase has already been bitten by (#132).
    service.remove_listener(&listener_id).await;
    if let Err(e) = add_listener(service, &new_config).await {
        return ReconnectOutcome::Failed(format!("{e:#}"));
    }
    match service
        .wait_connected(&listener_id, std::time::Duration::from_secs(30))
        .await
    {
        Ok(()) => ReconnectOutcome::Connected,
        Err(e) => ReconnectOutcome::Failed(e),
    }
}

/// Install a listener described by `spec` on a running [`Messaging`].
///
/// Brings up one identity's wire, in the order the SDK requires: secrets seeded
/// **before** `ATM::new` (the resolver is read during construction), profile via
/// `from_tdk_profile`, then `profile_add(_, true)` to connect the websocket —
/// `DidCommTransport::new` fails on a profile with no websocket running.
///
/// The transport is installed under `spec.id`, which is the identity's DID. That
/// is what makes `send_via` mean "send **as** this persona": the transport
/// determines the proven sender, so the wire is not interchangeable between
/// identities.
///
/// Each identity also gets its own `drain_loop_via` over the shared outbox, so a
/// retried message goes back out over the socket it was queued for rather than
/// whichever transport happens to be primary.
pub async fn add_listener(service: &Messaging, spec: &ListenerSpec) -> Result<(), MessagingError> {
    let fail = |reason: String| MessagingError::Listener {
        listener_id: spec.id.clone(),
        reason,
    };

    let tdk_profile = make_profile(
        &spec.did,
        &spec.mediator_did,
        &spec.label,
        spec.secrets.clone(),
    );
    let tdk = TDKSharedState::new(
        TDKConfig::builder()
            .build()
            .map_err(|e| fail(format!("TDK config: {e}")))?,
    )
    .await
    .map_err(|e| fail(format!("TDK init: {e}")))?;
    for secret in spec.secrets.clone() {
        tdk.secrets_resolver().insert(secret).await;
    }
    let atm = ATM::new(
        ATMConfig::builder()
            .build()
            .map_err(|e| fail(format!("ATM config: {e}")))?,
        Arc::new(tdk),
    )
    .await
    .map_err(|e| fail(format!("ATM init: {e}")))?;
    let atm_profile = ATMProfile::from_tdk_profile(&atm, &tdk_profile)
        .await
        .map_err(|e| fail(format!("profile: {e}")))?;
    let profile = atm
        .profile_add(&atm_profile, true)
        .await
        .map_err(|e| fail(format!("mediator connect: {e}")))?;
    let transport: Arc<dyn MessageTransport> = Arc::new(
        DidCommTransport::new(atm.clone(), profile.clone())
            .await
            .map_err(|e| fail(format!("transport bind: {e}")))?,
    );

    service
        .inner
        .service
        .add_transport(spec.id.clone(), transport.clone());

    // The drain belongs to this identity, so its handle rides on the wire: it has
    // to die with the listener, and it holds the transport Arc that keeps the ATM
    // (and its socket) alive until it does.
    let drain = tokio::spawn(drain_loop_via(
        service.inner.outbox.clone(),
        spec.id.clone(),
        transport,
        DRAIN_INTERVAL,
    ));
    let displaced = service.inner.identities.write().await.insert(
        spec.id.clone(),
        IdentityWire {
            atm,
            profile,
            did: spec.did.clone(),
            spec: spec.clone(),
            drain,
        },
    );

    // Nothing should reach here holding this id — every caller checks
    // `has_listener` or removes first — but an id inserted over silently drops the
    // old wire, and a dropped wire is a socket that never closes. Tear it down and
    // say so, rather than leaving the two to duel over the DID.
    if let Some(old) = displaced {
        tracing::warn!(
            listener = %crate::display::truncate_did(&spec.id, 32),
            "a listener was installed over an existing one; closing the one it replaced"
        );
        let atm = quiesce_wire(&spec.id, old).await;
        tokio::spawn(async move { atm.graceful_shutdown().await });
    }

    debug!(listener = %spec.id, "listener installed on the delivery layer");
    Ok(())
}

/// The single inbound dispatcher: read every transport's merged stream, classify
/// by message type, and forward as [`DIDCommEvent`].
///
/// Replaces the framework's `Router`. The delivery layer has no type-routed
/// dispatch — a consumer matches on the message itself — which is the same move
/// `vtc-service` made when it cut over. Acking is **not** done here: the service's
/// own dispatcher acks after handoff, never before.
async fn dispatch_inbound(
    service: Arc<MessagingService>,
    event_tx: mpsc::UnboundedSender<DIDCommEvent>,
) {
    let mut inbound = service.subscribe();
    while let Some(item) = inbound.next().await {
        // Both protocols arrive on this one stream — `DidCommTransport` owns the
        // single mediator socket and surfaces each, tagged. A DIDComm frame's
        // payload is the `Message` JSON (`to_inbound` in the SDK adapter); a TSP
        // frame's is a bare Trust Task document, which is normalised into the
        // same shape so everything below is transport-agnostic.
        let (message, transport) = match item.message.protocol {
            Protocol::DIDComm => match serde_json::from_slice::<Message>(&item.message.payload) {
                Ok(message) => (message, MessagingTransport::DidComm),
                Err(e) => {
                    debug!(error = %e, "inbound DIDComm frame is not a Message — dropped");
                    continue;
                }
            },
            Protocol::TSP => match tsp_frame_to_message(&item) {
                Some(message) => (message, MessagingTransport::Tsp),
                None => continue,
            },
            // A protocol OpenVTC does not speak — DIDComm v1 today, whatever
            // `Protocol` gains next. The enum is `#[non_exhaustive]` precisely so
            // a new variant is not a breaking change, and dropping is the honest
            // handling: nothing below could read the payload, and neither
            // listener we install ever negotiates one of these.
            other => {
                debug!(protocol = %other, "inbound frame on an unsupported protocol — dropped");
                continue;
            }
        };
        // The transport authenticated the sender; the plaintext `from` header is
        // sender-controlled. Prefer the cryptographically-bound one.
        let from = item.message.sender.clone().or_else(|| message.from.clone());

        for event in classify_inbound(message, transport, from, item.message.recipient.clone()) {
            // Unbounded: `send` fails only when the receiver is gone, which means
            // the state handler has shut down and there is nothing left to
            // deliver to. It can no longer fail because the channel is full —
            // see `DIDCOMM_EVENT_CHANNEL_CAPACITY` for why dropping there was
            // destroying messages the mediator had already deleted.
            if event_tx.send(event).is_err() {
                tracing::debug!("state handler has gone away — ending inbound dispatch");
                return;
            }
        }
    }
}

/// Unseal one picked-up frame into the shape [`classify_inbound`] takes, with
/// the cryptographically-bound sender the live path would have carried.
///
/// The live stream arrives pre-mapped by the SDK's transport adapter; a frame
/// collected from storage has not been through it, so the same two unsealings
/// happen here — DIDComm was already unpacked by the delivery-request handler
/// (which is where the metadata comes from), TSP is unsealed by `atm.tsp()`,
/// exactly as `tsp_to_inbound` does on the live path.
async fn frame_to_message(
    atm: &ATM,
    profile: &Arc<ATMProfile>,
    frame: InboundFrame,
) -> Option<(Message, MessagingTransport, Option<String>)> {
    match frame {
        InboundFrame::DidComm(message, meta) => {
            let from = authenticated_sender(&message, &meta);
            Some((*message, MessagingTransport::DidComm, from))
        }
        InboundFrame::Tsp(packed) => {
            // `unpack` authenticates the sender VID (resolve + verify), so
            // `sender` here is proven, not self-asserted — the same guarantee
            // the live path's `Inbound.message.sender` carries.
            let (payload, sender) = match atm.tsp().unpack(profile, &packed).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "could not unpack a stored TSP frame — leaving it in the mailbox");
                    return None;
                }
            };
            // The mediator keys a stored TSP frame on `sha256(packed)`, which is
            // the id the live path falls back to when the document carries none.
            let fallback_id = {
                use sha2::{Digest, Sha256};
                hex::encode(Sha256::digest(packed.as_bytes()))
            };
            let recipient = profile.inner.did.clone();
            let message =
                tsp_document_to_message(&payload, Some(&sender), &recipient, &fallback_id)?;
            Some((message, MessagingTransport::Tsp, Some(sender)))
        }
        // `InboundFrame` is `#[non_exhaustive]`: a protocol OpenVTC does not
        // speak. Left in the mailbox rather than acked — the same handling the
        // live dispatcher gives an unsupported `Protocol`, minus the deletion.
        other => {
            debug!(frame = ?std::mem::discriminant(&other), "picked-up frame on an unsupported protocol — left stored");
            None
        }
    }
}

/// The DID that actually authcrypted a picked-up DIDComm message, or `None`
/// when there is none.
///
/// A mirror of the SDK transport adapter's `authenticated_sender`, which is
/// private to that crate. The plaintext `from` header is sender-controlled: an
/// attacker can authcrypt with their own key (so `authenticated` is true) while
/// claiming a victim's `from`, and only the `from == DID(encrypted_from_kid)`
/// check rejects that. The live path gets this for free; a picked-up message
/// must not be the one place where it is skipped, because these messages carry
/// membership decisions and credentials.
///
/// Belongs upstream on `InboundFrame` rather than here — see the note in
/// [`Messaging::pickup_stored`].
fn authenticated_sender(
    message: &Message,
    meta: &affinidi_messaging_sdk::messages::compat::UnpackMetadata,
) -> Option<String> {
    if !meta.authenticated || meta.anonymous_sender {
        return None;
    }
    let kid = meta.encrypted_from_kid.as_deref()?;
    let key_did = kid.split_once('#').map(|(did, _)| did).unwrap_or(kid);
    match message.from.as_deref() {
        Some(from) if from == key_did => Some(from.to_string()),
        _ => None,
    }
}

/// The routing gate, compiled once and shared by the live dispatcher and the
/// stored-message pickup so the two admit **exactly** the same set.
///
/// It used to be compiled inside `dispatch_inbound`, where a compile failure
/// silently killed inbound dispatch for the process. The pattern is a `const`
/// covered by `catch_all_tests`, so a failure is a build-time bug; treating it
/// as one here is what lets both call sites share a single compiled regex
/// without either carrying an unreachable error path.
static CATCH_ALL: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(&format!("^(?:{OPENVTC_CATCH_ALL_PATTERN})$"))
        .expect("OPENVTC_CATCH_ALL_PATTERN is a constant, and `catch_all_tests` compiles it")
});

/// Classify one already-decoded inbound message into the events the state
/// handler consumes. Returns **zero or more**: an unroutable type yields none, a
/// trust-pong yields two (the log event and the message itself).
///
/// Peeled out of [`dispatch_inbound`] so [`Messaging::pickup_stored`] admits the
/// same messages by the same rules. A message the mediator stored while nobody
/// was listening is not a different kind of message, and a second copy of this
/// decision would be free to drift from the live one — which is the failure that
/// is invisible until a specific reply type stops arriving on one path only.
fn classify_inbound(
    message: Message,
    transport: MessagingTransport,
    from: Option<String>,
    listener_id: String,
) -> Vec<DIDCommEvent> {
    if message.typ == TRUST_PING_TYPE {
        // Not auto-answered: the state handler pongs only after checking the
        // sender has a relationship.
        return vec![DIDCommEvent::TrustPingReceived {
            from,
            listener_id,
            message_id: message.id.clone(),
        }];
    }
    if message.typ == TRUST_PONG_TYPE {
        // Forwarded as both: InboundMessage drives task removal, the pong
        // event drives the activity log.
        return vec![
            DIDCommEvent::TrustPongReceived { from: from.clone() },
            DIDCommEvent::InboundMessage {
                from,
                message: Box::new(message),
                transport,
            },
        ];
    }
    if CATCH_ALL.is_match(&message.typ) {
        tracing::info!(
            listener = %crate::display::truncate_did(&listener_id, 32),
            msg_type = %message.typ,
            from = ?from.as_deref().map(|d| crate::display::truncate_did(d, 32)),
            thid = ?message.thid,
            "inbound OpenVTC message received"
        );
        return vec![DIDCommEvent::InboundMessage {
            from,
            message: Box::new(message),
            transport,
        }];
    }
    // Pickup-status heartbeats and anything else: dropped, as the framework's
    // ignore-handler and fallback did.
    debug!(typ = %message.typ, "unhandled message type — dropped");
    Vec::new()
}

/// Normalise an inbound TSP frame into the [`Message`] shape the dispatcher and
/// the whole `crate::messaging` handler set already speak.
///
/// This is lossless rather than lossy, because the two transports carry the
/// **same document**. A VTC reply routed through `dispatch_trust_task_core` is
/// serialised once; DIDComm then wraps it in an envelope that repeats two of its
/// members outside (`tt_didcomm_reply` sets the message `type` from the
/// document's `type` and threads on the request's message id), whereas TSP
/// carries it bare. So the mapping just reads back out of the document what
/// DIDComm would have put in the envelope:
///
/// | `Message` field | taken from |
/// |---|---|
/// | `typ`  | the document's `type` |
/// | `thid` | the document's `threadId` |
/// | `id`   | the document's `id` (falling back to the frame hash) |
/// | `body` | the whole document — the same value `tt_didcomm_reply` sets |
/// | `from` | the TSP-authenticated sender VID, never a self-asserted field |
///
/// `body` being the whole document is what makes the handlers work unchanged:
/// they read their payload through `messaging::trust_task_reply_payload`, which
/// unwraps `payload` (#200). Had that fix not landed first, every TSP reply
/// would have parsed at the wrong nesting.
///
/// A frame that is not a JSON object, or carries no `type`, is dropped with a
/// warning rather than guessed at: unlike DIDComm there is no envelope to fall
/// back on, and inventing a type would route it to the wrong handler.
fn tsp_frame_to_message(item: &affinidi_messaging_core::transport::Inbound) -> Option<Message> {
    tsp_document_to_message(
        &item.message.payload,
        item.message.sender.as_deref(),
        &item.message.recipient,
        &item.message.id,
    )
}

/// The mapping itself, over an already-unsealed TSP payload.
///
/// Split from [`tsp_frame_to_message`] because the two ways a TSP frame reaches
/// us differ only in *who* unsealed it: the live stream arrives as an `Inbound`
/// the SDK's transport adapter already unpacked, while a frame picked up from
/// storage ([`Messaging::pickup_stored`]) is unsealed by this crate. The
/// document-to-`Message` rules above must not be written twice.
///
/// `fallback_id` is the frame hash — the id the SDK substitutes when the
/// document carries none.
fn tsp_document_to_message(
    payload: &[u8],
    sender: Option<&str>,
    recipient: &str,
    fallback_id: &str,
) -> Option<Message> {
    let doc: serde_json::Value = match serde_json::from_slice(payload) {
        Ok(doc) => doc,
        Err(e) => {
            tracing::warn!(error = %e, "inbound TSP frame is not JSON — dropped");
            return None;
        }
    };
    let Some(typ) = doc.get("type").and_then(|t| t.as_str()) else {
        tracing::warn!(
            "inbound TSP frame carries no `type` — dropped (a TSP frame has no \
             envelope to recover it from)"
        );
        return None;
    };

    // The document id, when it has one. A TSP frame carries no message id of its
    // own; the SDK substitutes the frame hash, which stays the fallback so a
    // malformed document still gets a unique id rather than an empty one.
    let id = doc
        .get("id")
        .and_then(|i| i.as_str())
        .unwrap_or(fallback_id)
        .to_string();

    let mut builder = Message::build(id, typ.to_string(), doc.clone());
    // `threadId` is the correlation key on this transport, and it is the request
    // *document* id — which OpenVTC makes equal to the request message id when it
    // sends (see `join::submit_join_request`), so one handle correlates a reply
    // arriving on either transport.
    if let Some(thid) = doc.get("threadId").and_then(|t| t.as_str()) {
        builder = builder.thid(thid.to_string());
    }
    if let Some(sender) = sender {
        builder = builder.from(sender.to_string());
    }
    Some(builder.to(recipient.to_string()).finalize())
}

/// Catch-all pattern for OpenVTC protocol messages + VTC Trust-Task
/// replies (e.g. `join-requests/submit-receipt`). The state handler
/// dispatches by type and ignores any it doesn't handle.
///
/// **Both VTC prefixes are accepted.** The VTC's Trust Tasks are moving
/// from the non-conformant `trusttasks.org/openvtc/vtc/…` authority to
/// the canonical registry at `trusttasks.org/spec/vtc/…`. This pattern
/// decides whether a message reaches the handler *at all*, so it must
/// accept the new prefix **before** any VTC starts emitting it —
/// otherwise migrated traffic is dropped here, silently, before dispatch
/// ever sees it. Accepting both also lets a migrated and an unmigrated
/// VTC be talked to during the rollout; the `openvtc/vtc/` arm can be
/// retired once no supported VTC emits it.
pub const OPENVTC_CATCH_ALL_PATTERN: &str = concat!(
    r"https://linuxfoundation\.org/openvtc/.*",
    r"|https://firstperson\.network/.*",
    r"|https://trusttasks\.org/openvtc/vtc/.*",
    r"|https://trusttasks\.org/spec/vtc/.*",
    r"|https://trusttasks\.org/spec/credential-exchange/.*",
    r"|https://trusttasks\.org/spec/vetting/.*",
    r"|https://trusttasks\.org/spec/trust-task-error/.*",
    r"|https://didcomm\.org/report-problem/.*",
);

/// Extract secrets for a DID from the TDK's secrets resolver.
///
/// Uses `config.key_info` to find the verification method IDs associated with the DID,
/// then looks up the corresponding secrets from the TDK's threaded secrets resolver.
async fn get_secrets_for_did(
    tdk: &affinidi_tdk::TDK,
    config: &Config,
    did: &str,
) -> Vec<affinidi_tdk::secrets_resolver::secrets::Secret> {
    let resolver = tdk.shared().secrets_resolver();

    let mut secrets = vec![];
    for key_id in config.key_info.keys() {
        if key_id.starts_with(did)
            && let Some(secret) = resolver.get_secret(key_id).await
        {
            secrets.push(secret);
        }
    }
    secrets
}

/// Create a `TDKProfile` from DID/mediator strings with optional secrets.
fn make_profile(
    did: &str,
    mediator: &str,
    alias: &str,
    secrets: Vec<affinidi_tdk::secrets_resolver::secrets::Secret>,
) -> TDKProfile {
    TDKProfile::new(alias, did, Some(mediator), secrets)
}

/// Build [`ListenerSpec`]s from the loaded `Config`.
///
/// Includes one persona listener per resolved identity (so every community's
/// persona receives messages), plus per-relationship listeners for established
/// relationships that use a dedicated R-DID (different from any persona DID).
///
/// Secrets for each DID are extracted from the TDK's secrets resolver
/// so that each listener can authenticate with the mediator.
pub async fn build_listener_configs(config: &Config, tdk: &affinidi_tdk::TDK) -> Vec<ListenerSpec> {
    // One persona listener per resolved identity. A single-persona account
    // yields exactly one — identical to the previous behaviour. `persona_dids`
    // is also the exclusion set for the R-DID listeners below.
    let mut configs = Vec::new();
    let mut persona_dids = std::collections::HashSet::new();
    for identity in config.identities.values() {
        let did = identity.did.as_str();
        if !persona_dids.insert(did.to_string()) {
            continue;
        }
        let persona_secrets = get_secrets_for_did(tdk, config, did).await;
        let mediator = identity
            .mediator_did
            .as_deref()
            .unwrap_or(config.mediator_did());
        let label = config.persona_profile_label_for(identity.persona_id);
        configs.push(ListenerSpec {
            id: persona_listener_id(did),
            did: did.to_string(),
            mediator_did: mediator.to_string(),
            label,
            secrets: persona_secrets,
        });
    }

    // Add listeners for each relationship with a dedicated R-DID.
    // Include pending relationships (RequestSent, RequestAccepted) so that
    // messages arriving during an in-progress handshake are received after restart.
    // Deduplicate by our_did to prevent multiple listeners for the same DID,
    // which would cause a reconnect loop as the mediator detects duplicates.
    // Exclude ALL persona DIDs (their own listeners carry those relationships).
    // Extract data from the Mutex before any .await to avoid holding the guard.
    let mut seen_dids = std::collections::HashSet::new();
    let r_did_entries: Vec<(String, String)> = config
        .private
        .relationships
        .relationships
        .iter()
        .filter_map(|(remote_p_did, rel)| {
            if matches!(
                rel.state,
                RelationshipState::Established
                    | RelationshipState::RequestSent
                    | RelationshipState::RequestAccepted
            ) && !persona_dids.contains(rel.our_did.as_str())
                && seen_dids.insert(rel.our_did.to_string())
            {
                Some((rel.our_did.to_string(), remote_p_did.to_string()))
            } else {
                None
            }
        })
        .collect();

    for (our_did, remote_p_did) in &r_did_entries {
        let r_did_secrets = get_secrets_for_did(tdk, config, our_did).await;
        configs.push(ListenerSpec {
            id: format!("rel-{}", short_did_id(our_did)),
            did: our_did.to_string(),
            mediator_did: config.mediator_did().to_string(),
            label: format!(
                "R-DID for {}",
                crate::display::truncate_did(remote_p_did, 32)
            ),
            secrets: r_did_secrets,
        });
    }

    debug!(
        persona_listeners = persona_dids.len(),
        r_did_listeners = r_did_entries.len(),
        total = configs.len(),
        "built listener configs"
    );

    configs
}

/// Determine the listener ID to use for sending messages from a given DID.
///
/// If `our_did` is one of our persona DIDs, use that persona's listener.
/// Otherwise, use the relationship-listener naming convention.
pub fn listener_id_for_did(our_did: &str, config: &Config) -> String {
    if config.is_persona_did(our_did) {
        persona_listener_id(our_did)
    } else {
        format!("rel-{}", short_did_id(our_did))
    }
}

/// Convenience wrapper: send a DIDComm message through the correct listener
/// based on the sender DID, with retry on transient failures.
pub async fn send_message(
    service: &Messaging,
    config: &Config,
    message: &Message,
    from_did: &str,
    to_did: &str,
) -> Result<(), MessagingError> {
    let listener_id = listener_id_for_did(from_did, config);
    send_message_via(service, message, &listener_id, to_did).await
}

/// Send a DIDComm message through a specific listener, durably.
///
/// Use this when the transport listener should differ from the logical sender —
/// for example, sending via the already-connected persona listener when a newly
/// created R-DID listener may not be ready yet.
pub async fn send_message_via(
    service: &Messaging,
    message: &Message,
    listener_id: &str,
    to_did: &str,
) -> Result<(), MessagingError> {
    tracing::info!(
        listener = %crate::display::truncate_did(listener_id, 32),
        msg_type = %message.typ,
        from = ?message
            .from
            .as_deref()
            .map(|d| crate::display::truncate_did(d, 32)),
        to = %crate::display::truncate_did(to_did, 32),
        thid = ?message.thid,
        "sending DIDComm message"
    );

    // Pack as the sending identity. `MessageTransport::send` takes already-packed
    // bytes — packing is the protocol's concern, not the transport's — so this
    // needs that identity's own ATM, which is why the wire is kept per listener.
    let packed = {
        let identities = service.inner.identities.read().await;
        let wire = identities
            .get(listener_id)
            .ok_or_else(|| MessagingError::UnknownListener(listener_id.to_string()))?;
        wire.atm
            .pack_encrypted(message, to_did, Some(&wire.did), Some(&wire.did))
            .await
            .map_err(|e| MessagingError::Pack {
                recipient: to_did.to_string(),
                reason: e.to_string(),
            })?
            .0
    };

    // `Guaranteed`, not `BestEffort`. The framework call this replaces
    // (`send_message_with_retry`) retried on a disconnected listener; `BestEffort`
    // has no retry, so a straight swap would trade a retry for a dropped message
    // whenever a send lands mid-reconnect. The outbox IS that retry, and a better
    // one: it survives the reconnect and settles visibly if the window expires.
    //
    // Keyed by the message id, so a re-send of the same message dedups at the
    // recipient rather than double-delivering.
    service
        .inner
        .service
        .send_via(
            listener_id,
            to_did,
            packed.into_bytes(),
            Delivery::Guaranteed {
                idempotency_key: Some(message.id.clone()),
                ordering_key: None,
                deliver_by: DELIVER_BY,
            },
        )
        .await
        .map(|_accepted| ())
        .map_err(|e| MessagingError::Send(e.to_string()))
}

/// A listener lifecycle event, ready to be rendered into the activity log.
///
/// Deliberately **not** a pre-formatted string. A listener is identified by its
/// DID, and turning a DID into what the operator should read — a verified agent
/// name, a contact alias, or a truncated DID — needs the `Config`, which lives
/// on the runtime loop thread and is not available to this detached task. So the
/// event carries the identifier and the loop formats it; see
/// `StateHandler::format_lifecycle_log`.
#[derive(Debug, Clone)]
pub enum LifecycleLog {
    /// A listener established its connection.
    Connected { listener_id: String },
    /// A listener's connection dropped, with the transport error if there was one.
    Disconnected {
        listener_id: String,
        error: Option<String>,
    },
    /// A listener dropped and came back quickly — reported as the single event
    /// it is, rather than as a fault followed by a recovery.
    // Not an intra-doc link: `RECONNECT_GRACE` is private, and a public item
    // linking to it fails `rustdoc -D warnings`.
    /// The window is `RECONNECT_GRACE`.
    Reconnected {
        listener_id: String,
        /// How long it was down, so the line is evidence rather than a claim
        /// about why.
        down_for: std::time::Duration,
    },
    /// A listener dropped again within the cycling window — usually a duplicate
    /// connection fighting itself.
    CyclingRapidly { listener_id: String },
    /// A listener is being restarted after a backoff.
    Restarting {
        listener_id: String,
        attempt: u32,
        delay: std::time::Duration,
    },
    /// The event stream lagged and dropped `count` events.
    Missed { count: u64 },
}

/// A drop that has happened but has not been reported yet — see
/// [`RECONNECT_GRACE`].
#[derive(Debug, Clone)]
struct HeldDrop {
    at: std::time::Instant,
    error: Option<String>,
}

/// Turns raw connection transitions into the lines an operator should see.
///
/// Split out of the logger task, and driven by an explicit `now`, because the
/// interesting behaviour is entirely about *timing* — which is the one thing a
/// spawned task with a real clock cannot be asked about in a test.
#[derive(Debug, Default)]
struct DropDebounce {
    held: HashMap<String, HeldDrop>,
    /// Drop timestamps, for the rapid-cycling heuristic. Independent of what is
    /// held: cycling is about how often a listener drops, not about how the
    /// drops are reported.
    last_disconnect: HashMap<String, std::time::Instant>,
}

impl DropDebounce {
    /// A listener dropped. Emits `CyclingRapidly` immediately when this is the
    /// second drop inside [`CYCLING_WINDOW`] — a duelling connection is exactly
    /// what must not be held back — and holds the drop itself.
    fn on_disconnect(
        &mut self,
        listener_id: String,
        error: Option<String>,
        now: std::time::Instant,
    ) -> Vec<LifecycleLog> {
        let mut out = Vec::new();
        if let Some(previous) = self.last_disconnect.get(&listener_id)
            && now.duration_since(*previous) < CYCLING_WINDOW
        {
            tracing::warn!(
                listener = %crate::display::truncate_did(&listener_id, 32),
                "rapid disconnect cycling detected"
            );
            out.push(LifecycleLog::CyclingRapidly {
                listener_id: listener_id.clone(),
            });
        }
        self.last_disconnect.insert(listener_id.clone(), now);
        // A second drop with one already held keeps the *earlier* timestamp:
        // the listener has been down since then, and reporting the later one
        // would restart a clock that never stopped.
        self.held
            .entry(listener_id)
            .or_insert(HeldDrop { at: now, error });
        out
    }

    /// A listener connected. One line either way: the pair when a held drop is
    /// still inside its grace, a plain connect otherwise (a first connect, or a
    /// recovery from an outage already reported).
    fn on_connect(&mut self, listener_id: String, now: std::time::Instant) -> LifecycleLog {
        match self.held.remove(&listener_id) {
            Some(drop) if now.duration_since(drop.at) < RECONNECT_GRACE => {
                LifecycleLog::Reconnected {
                    listener_id,
                    down_for: now.duration_since(drop.at),
                }
            }
            _ => LifecycleLog::Connected { listener_id },
        }
    }

    /// Drops that have outlived their grace: the listener is *still* down, so
    /// now the line is worth printing.
    fn due(&mut self, now: std::time::Instant) -> Vec<LifecycleLog> {
        let expired: Vec<String> = self
            .held
            .iter()
            .filter(|(_, drop)| now.duration_since(drop.at) >= RECONNECT_GRACE)
            .map(|(id, _)| id.clone())
            .collect();
        expired
            .into_iter()
            .map(|listener_id| {
                let drop = self.held.remove(&listener_id).expect("just listed");
                LifecycleLog::Disconnected {
                    listener_id,
                    error: drop.error,
                }
            })
            .collect()
    }
}

/// Subscribe to listener lifecycle transitions and forward them as
/// structured log events via the provided sender. Detects rapid reconnect
/// cycling, and coalesces the routine reconnect the mediator's token refresh
/// performs into one line (see the private `RECONNECT_GRACE`). Returns the
/// spawned task handle.
pub fn spawn_lifecycle_logger(
    service: &Messaging,
    log_tx: mpsc::UnboundedSender<LifecycleLog>,
) -> tokio::task::JoinHandle<()> {
    let mut status_rx = service.subscribe();
    tokio::spawn(async move {
        let mut debounce = DropDebounce::default();
        let mut sweep = tokio::time::interval(PENDING_DROP_SWEEP);

        loop {
            tokio::select! {
                event = status_rx.recv() => match event {
                    Ok(ListenerStatus::Connected { listener_id }) => {
                        let _ = log_tx.send(
                            debounce.on_connect(listener_id, std::time::Instant::now()),
                        );
                    }
                    Ok(ListenerStatus::Disconnected { listener_id, error }) => {
                        for log in debounce.on_disconnect(
                            listener_id,
                            error,
                            std::time::Instant::now(),
                        ) {
                            let _ = log_tx.send(log);
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                        let _ = log_tx.send(LifecycleLog::Missed { count });
                    }
                },
                _ = sweep.tick() => {
                    for log in debounce.due(std::time::Instant::now()) {
                        let _ = log_tx.send(log);
                    }
                }
            }
        }
    })
}

/// Rebuild transports whose ATM has died, so a listener cannot be stranded.
///
/// `DidCommTransport::inbound()` survives a socket drop — the ATM reconnects
/// underneath it — so ordinary churn needs nothing from this loop, and reacting to
/// it would be actively harmful (see [`REBUILD_GRACE`]). What it recovers is the
/// case the transport cannot: the ATM task itself dying, which leaves the transport
/// permanently `Disconnected` with nothing retrying behind it. The framework's
/// `RestartPolicy` covered that; the delivery layer has no equivalent, so this is
/// it.
///
/// A rebuild **removes before it adds**, because the mediator permits one websocket
/// per DID and rejects a second with `duplicate-channel`.
/// Collect a listener's stored mail every time its socket comes up.
///
/// Subscribes to the same connection transitions the session manager and the
/// activity log read, so "connected" means the one thing here it means
/// everywhere else. Every connect qualifies, not just the first: a reconnect is
/// exactly when a message may have landed with nobody attached.
///
/// Each pickup runs detached — the drain is network I/O and must not hold up the
/// next transition — and at most one per listener is in flight, so a flapping
/// socket cannot stack overlapping drains of the same mailbox.
async fn pickup_on_connect(service: Messaging) {
    let mut transitions = service.subscribe();
    loop {
        let listener_id = match transitions.recv().await {
            Ok(ListenerStatus::Connected { listener_id }) => listener_id,
            Ok(ListenerStatus::Disconnected { .. }) => continue,
            // Lagged: transitions were missed, not the mailbox. The next connect
            // collects whatever accumulated, and a listener that is up *now* is
            // covered by the supervisor's own reconnect path.
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
        };

        {
            let mut in_flight = service.inner.pickup_in_flight.lock().expect("pickup mutex");
            if !in_flight.insert(listener_id.clone()) {
                continue;
            }
        }

        let collector = service.clone();
        tokio::spawn(async move {
            if let Err(e) = collector.pickup_stored(&listener_id).await {
                // Never fatal: the socket is up and live delivery is on, so this
                // costs only what was already waiting. Named rather than
                // generic (R6.4) so an operator can tell an unreachable mediator
                // from a listener that was torn down mid-pickup.
                tracing::warn!(
                    listener = %crate::display::truncate_did(&listener_id, 32),
                    error = %e,
                    "could not collect stored messages after connect"
                );
            }
            collector
                .inner
                .pickup_in_flight
                .lock()
                .expect("pickup mutex")
                .remove(&listener_id);
        });
    }
}

async fn supervise_transports(service: Messaging) {
    let mut down: HashMap<String, DownSince> = HashMap::new();

    loop {
        tokio::time::sleep(SUPERVISOR_INTERVAL).await;
        let now = std::time::Instant::now();

        for (listener_id, state) in service.inner.service.transport_states() {
            if state == ConnState::Connected {
                // Recovered — forget its history so the next outage starts from a
                // full grace period and the first backoff step.
                down.remove(&listener_id);
                continue;
            }

            let tracked = down.entry(listener_id.clone()).or_insert(DownSince {
                first_seen: now,
                attempts: 0,
                last_attempt: None,
            });

            if !rebuild_due(
                now.duration_since(tracked.first_seen),
                tracked.attempts,
                tracked.last_attempt.map(|at| now.duration_since(at)),
            ) {
                continue;
            }

            let Some(spec) = service
                .inner
                .identities
                .read()
                .await
                .get(&listener_id)
                .map(|wire| wire.spec.clone())
            else {
                // Deliberately removed (community left, DID deleted) between the
                // state sample and here. Not ours to resurrect.
                down.remove(&listener_id);
                continue;
            };

            tracked.attempts = tracked.attempts.saturating_add(1);
            tracked.last_attempt = Some(now);
            let attempt = tracked.attempts;

            tracing::warn!(
                listener = %crate::display::truncate_did(&listener_id, 32),
                attempt,
                down_for_secs = now.duration_since(tracked.first_seen).as_secs(),
                "listener has not reconnected on its own — rebuilding its transport"
            );

            // Drop the dead transport first: one websocket per DID.
            service.remove_listener(&listener_id).await;
            match add_listener(&service, &spec).await {
                Ok(()) => tracing::info!(
                    listener = %crate::display::truncate_did(&listener_id, 32),
                    "transport rebuilt"
                ),
                Err(e) => tracing::warn!(
                    listener = %crate::display::truncate_did(&listener_id, 32),
                    attempt,
                    error = %e,
                    "transport rebuild failed; will retry with backoff"
                ),
            }
        }

        // Stop tracking transports that no longer exist.
        let live: std::collections::HashSet<String> = service
            .inner
            .service
            .transport_states()
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        down.retain(|id, _| live.contains(id));
    }
}

/// The one connection poller: sample every transport's live state and broadcast
/// the transitions.
///
/// The framework pushed `ListenerEvent`s; the delivery layer exposes a live
/// `ConnState` per transport instead (R6.2 — re-falsifiable, never a boot-time
/// latch), so transitions are derived by sampling. Doing that once and
/// broadcasting is what keeps every consumer's view identical.
async fn poll_listener_status(
    service: Arc<MessagingService>,
    status_tx: tokio::sync::broadcast::Sender<ListenerStatus>,
) {
    let mut seen: HashMap<String, ConnState> = HashMap::new();
    loop {
        tokio::time::sleep(LIFECYCLE_POLL_INTERVAL).await;

        let states = service.transport_states();
        for (listener_id, state) in &states {
            if seen.insert(listener_id.clone(), *state) == Some(*state) {
                continue;
            }
            let event = match state {
                ConnState::Connected => ListenerStatus::Connected {
                    listener_id: listener_id.clone(),
                },
                _ => ListenerStatus::Disconnected {
                    listener_id: listener_id.clone(),
                    error: None,
                },
            };
            // `Err` only means nobody is subscribed yet — not a failure.
            let _ = status_tx.send(event);
        }

        // Forget removed transports, so a re-added listener reports its connect
        // rather than looking like it never dropped.
        let live: std::collections::HashSet<&String> = states.iter().map(|(id, _)| id).collect();
        seen.retain(|id, _| live.contains(id));
    }
}

/// Build a single [`ListenerSpec`] for the persona DID.
pub async fn persona_listener_config(config: &Config, tdk: &affinidi_tdk::TDK) -> ListenerSpec {
    let secrets = get_secrets_for_did(tdk, config, config.persona_did()).await;
    ListenerSpec {
        id: persona_listener_id(config.persona_did()),
        did: config.persona_did().to_string(),
        mediator_did: config.mediator_did().to_string(),
        label: config.persona_profile_label(),
        secrets,
    }
}

/// Build the persona listener config for a **specific** persona (not necessarily
/// the active one), mirroring one iteration of [`build_listener_configs`]. Used
/// to bring a freshly-joined community's session live at runtime (R-B-5) without
/// a restart. Returns `None` if `persona_id` does not resolve to an identity.
pub async fn persona_listener_config_for(
    config: &Config,
    tdk: &affinidi_tdk::TDK,
    persona_id: crate::config::account::PersonaId,
) -> Option<ListenerSpec> {
    let ident = config.identities.get(&persona_id)?;
    let did = ident.did.as_str();
    let secrets = get_secrets_for_did(tdk, config, did).await;
    let mediator = ident
        .mediator_did
        .as_deref()
        .unwrap_or(config.mediator_did());
    let label = config.persona_profile_label_for(persona_id);
    Some(ListenerSpec {
        id: persona_listener_id(did),
        did: did.to_string(),
        mediator_did: mediator.to_string(),
        label,
        secrets,
    })
}

/// Start the DIDComm service with the given config.
pub async fn start_service(
    config: &Config,
    tdk: &affinidi_tdk::TDK,
    event_tx: mpsc::UnboundedSender<DIDCommEvent>,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<Messaging, MessagingError> {
    let service = start_empty_service(event_tx, shutdown);
    install_listeners(&service, config, tdk).await;
    Ok(service)
}

/// Stand the runtime up with **no** listeners, honouring `shutdown`.
///
/// Separated from [`start_service`] because a State-A account has no identity to
/// install a listener for, yet still needs the runtime live: the join flow can
/// then bring the applicant persona's socket up *before* it submits, which is
/// the whole of what stops a fast community reply from being stored unread.
/// `Messaging::start` is built for this — its dispatcher runs before the first
/// transport exists — so an empty service is a supported state, not a stub.
pub fn start_empty_service(
    event_tx: mpsc::UnboundedSender<DIDCommEvent>,
    shutdown: tokio_util::sync::CancellationToken,
) -> Messaging {
    let service = Messaging::start(event_tx);

    // The framework owned the shutdown token; now it is ours to honour. Dropping
    // every transport on cancel is what stops a stale socket racing the next
    // process for the same DID (`duplicate-channel`).
    let on_cancel = service.clone();
    tokio::spawn(async move {
        shutdown.cancelled().await;
        on_cancel.shutdown().await;
    });

    service
}

/// Install every listener `config` describes that is not already running.
///
/// Idempotent by listener id, because it is called after a path that may have
/// installed one already: a State-A join brings its own persona up mid-ceremony,
/// and re-adding that id would error on the duplicate (and, worse, race a second
/// socket against the live one for the same DID).
///
/// Listeners are installed one at a time rather than handed over as a set: each
/// is an independent mediator connect, and one persona whose mediator is down
/// must not stop the others coming up. A failure is logged and skipped — the
/// panel reports per-listener state, so a missing one is visible rather than
/// silent, and `reconnect_persona_listener_io` is the recovery path.
pub async fn install_listeners(service: &Messaging, config: &Config, tdk: &affinidi_tdk::TDK) {
    connect_listeners(service, build_listener_configs(config, tdk).await).await;
}

/// Bring up each spec's listener, skipping any already installed.
///
/// Split from [`install_listeners`] so a caller that cannot hold `Config`
/// across an await — it is not `Clone` — can still do this part off its own
/// thread. See [`spawn_install_listeners`].
pub async fn connect_listeners(service: &Messaging, specs: Vec<ListenerSpec>) {
    for spec in specs {
        if service.has_listener(&spec.id).await {
            continue;
        }
        if let Err(e) = add_listener(service, &spec).await {
            tracing::warn!(
                listener = %crate::display::truncate_did(&spec.id, 32),
                error = %e,
                "listener failed to come up; continuing without it"
            );
        }
    }
}

/// Bring the listeners up in the background, logging what came up.
///
/// Each listener costs a mediator authentication handshake and a websocket
/// connect, and they are installed one after another — so on an account with
/// several identities this is seconds of network, not microseconds. Startup ran
/// it inline on the state-handler thread, which is the only thread that services
/// UI actions: the loading screen offered "Press Enter to continue" and then
/// ignored the keypress until every socket was up. The Enter was not lost — it
/// sat in the action channel — so the main page arrived in one late jump, which
/// reads as a freeze.
///
/// Running a service with no listeners yet is already a supported state
/// (`start_empty_service` exists for it), and the runtime loop flips the
/// connection status from typed lifecycle events as each one lands, so nothing
/// downstream needs them to be up before the UI is live.
pub fn spawn_install_listeners(
    service: Messaging,
    specs: Vec<ListenerSpec>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        connect_listeners(&service, specs).await;
        // Logged here rather than at the call site: the point of the listing is
        // what actually came up, which is only known once the installs finish.
        let listeners = service.list_listeners().await;
        for id in &listeners {
            tracing::debug!(
                listener = %crate::display::truncate_did(id, 32),
                state = ?service.listener_state(id),
                "registered listener"
            );
        }
        tracing::info!(count = listeners.len(), "DIDComm listeners registered");
    })
}

/// Produce a short, collision-resistant identifier from a DID for listener IDs.
///
/// Uses a SHA-256 hash (first 16 hex chars) to avoid collisions that would occur
/// with simple truncation — did:peer DIDs share a long common prefix.
fn short_did_id(did: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(did.as_bytes());
    hex::encode(&hash[..8])
}

/// Build a relationship R-DID [`ListenerSpec`] from already-owned secrets.
///
/// Config/TDK-free, so a backgrounded relationship-creation task (R14) can build
/// the new R-DID listener from the secrets it just minted — no resolver lookup,
/// no `Config` borrow — keeping the task `'static` + `Send`.
pub fn relationship_listener_config_from_secrets(
    our_did: &str,
    remote_p_did: &str,
    mediator_did: &str,
    secrets: Vec<Secret>,
) -> ListenerSpec {
    ListenerSpec {
        id: format!("rel-{}", short_did_id(our_did)),
        did: our_did.to_string(),
        mediator_did: mediator_did.to_string(),
        label: format!(
            "R-DID for {}",
            crate::display::truncate_did(remote_p_did, 32)
        ),
        secrets,
    }
}

#[cfg(test)]
mod drop_debounce_tests {
    use super::{CYCLING_WINDOW, DropDebounce, LifecycleLog, RECONNECT_GRACE};
    use std::time::{Duration, Instant};

    const LISTENER: &str = "did:webvh:QmListener";

    /// The reported noise: one drop per mediator token, ~12 minutes apart, back
    /// inside a couple of seconds. It must read as one reconnect, not as a
    /// disconnect plus a recovery — and above all not as a fault, because there
    /// is nothing an operator can do about a scheduled token refresh.
    #[test]
    fn a_routine_refresh_reconnect_is_one_calm_line() {
        let mut debounce = DropDebounce::default();
        let dropped = Instant::now();

        assert!(
            debounce
                .on_disconnect(LISTENER.into(), None, dropped)
                .is_empty(),
            "a first drop is held, not reported"
        );
        assert!(
            debounce.due(dropped + Duration::from_secs(1)).is_empty(),
            "and stays held while it is still inside the grace"
        );

        let back = dropped + Duration::from_secs(2);
        match debounce.on_connect(LISTENER.into(), back) {
            LifecycleLog::Reconnected {
                listener_id,
                down_for,
            } => {
                assert_eq!(listener_id, LISTENER);
                assert_eq!(down_for, Duration::from_secs(2));
            }
            other => panic!("expected one Reconnected line, got {other:?}"),
        }

        assert!(
            debounce.due(back + RECONNECT_GRACE * 2).is_empty(),
            "nothing is left to report once the pair has been reported"
        );
    }

    /// The other half: a listener that does not come back must still be
    /// reported, or the suppression would cost the log the one line that
    /// matters.
    #[test]
    fn a_drop_that_does_not_recover_is_reported() {
        let mut debounce = DropDebounce::default();
        let dropped = Instant::now();
        debounce.on_disconnect(LISTENER.into(), None, dropped);

        assert!(
            debounce
                .due(dropped + RECONNECT_GRACE - Duration::from_millis(1))
                .is_empty(),
            "not yet — this is still within the grace"
        );

        let due = debounce.due(dropped + RECONNECT_GRACE);
        assert!(
            matches!(&due[..], [LifecycleLog::Disconnected { listener_id, error: None }] if listener_id == LISTENER),
            "got {due:?}"
        );
        assert!(
            debounce.due(dropped + RECONNECT_GRACE * 2).is_empty(),
            "reported once, not on every sweep"
        );
    }

    /// A transport error is the evidence for the line, so holding the drop must
    /// not lose it.
    #[test]
    fn a_held_drop_keeps_its_transport_error() {
        let mut debounce = DropDebounce::default();
        let dropped = Instant::now();
        debounce.on_disconnect(LISTENER.into(), Some("connection reset".into()), dropped);

        let due = debounce.due(dropped + RECONNECT_GRACE);
        assert!(
            matches!(&due[..], [LifecycleLog::Disconnected { error: Some(e), .. }] if e == "connection reset"),
            "got {due:?}"
        );
    }

    /// A recovery after the outage was already reported is a plain connect —
    /// the pair line would be a lie, because the drop was not brief.
    #[test]
    fn a_late_recovery_is_a_plain_connect() {
        let mut debounce = DropDebounce::default();
        let dropped = Instant::now();
        debounce.on_disconnect(LISTENER.into(), None, dropped);
        let _reported = debounce.due(dropped + RECONNECT_GRACE);

        assert!(matches!(
            debounce.on_connect(
                LISTENER.into(),
                dropped + RECONNECT_GRACE + Duration::from_secs(5)
            ),
            LifecycleLog::Connected { .. }
        ));
    }

    /// A first connect has no drop behind it.
    #[test]
    fn a_first_connect_is_a_plain_connect() {
        let mut debounce = DropDebounce::default();
        assert!(matches!(
            debounce.on_connect(LISTENER.into(), Instant::now()),
            LifecycleLog::Connected { .. }
        ));
    }

    /// Duelling sockets are exactly what must NOT be quietened: the cycling
    /// warning fires on the drop, before any grace can absorb it.
    #[test]
    fn rapid_cycling_still_warns_immediately() {
        let mut debounce = DropDebounce::default();
        let first = Instant::now();
        assert!(
            debounce
                .on_disconnect(LISTENER.into(), None, first)
                .is_empty()
        );
        debounce.on_connect(LISTENER.into(), first + Duration::from_millis(500));

        let second = first + Duration::from_secs(3);
        let out = debounce.on_disconnect(LISTENER.into(), None, second);
        assert!(
            matches!(&out[..], [LifecycleLog::CyclingRapidly { listener_id }] if listener_id == LISTENER),
            "a second drop inside the cycling window must warn at once, got {out:?}"
        );
    }

    /// Two drops far enough apart are the healthy refresh cadence, not cycling.
    #[test]
    fn drops_outside_the_cycling_window_do_not_warn() {
        let mut debounce = DropDebounce::default();
        let first = Instant::now();
        debounce.on_disconnect(LISTENER.into(), None, first);
        debounce.on_connect(LISTENER.into(), first + Duration::from_secs(2));

        let later = first + CYCLING_WINDOW + Duration::from_secs(1);
        assert!(
            debounce
                .on_disconnect(LISTENER.into(), None, later)
                .is_empty(),
            "a drop outside the window is not cycling"
        );
    }

    /// A second drop while one is already held must not restart the clock: the
    /// listener has been down since the first, and re-dating it would let a
    /// listener that drops every 14 s never be reported at all.
    #[test]
    fn a_repeated_drop_does_not_extend_the_grace() {
        let mut debounce = DropDebounce::default();
        let first = Instant::now();
        debounce.on_disconnect(LISTENER.into(), None, first);
        debounce.on_disconnect(LISTENER.into(), None, first + RECONNECT_GRACE / 2);

        assert_eq!(
            debounce.due(first + RECONNECT_GRACE).len(),
            1,
            "the hold is dated from the first drop"
        );
    }

    /// Listeners are independent: one going quiet must not hold another's line.
    #[test]
    fn listeners_are_held_independently() {
        let mut debounce = DropDebounce::default();
        let now = Instant::now();
        debounce.on_disconnect("a".into(), None, now);
        debounce.on_disconnect("b".into(), None, now + RECONNECT_GRACE);

        let due = debounce.due(now + RECONNECT_GRACE);
        assert!(
            matches!(&due[..], [LifecycleLog::Disconnected { listener_id, .. }] if listener_id == "a"),
            "only the one past its grace, got {due:?}"
        );
        assert!(matches!(
            debounce.on_connect("b".into(), now + RECONNECT_GRACE + Duration::from_secs(1)),
            LifecycleLog::Reconnected { .. }
        ));
    }
}

#[cfg(test)]
mod supervisor_policy_tests {
    use super::{
        ListenerSpec, REBUILD_BACKOFF_CAP, REBUILD_GRACE, rebuild_backoff, rebuild_due,
        spawn_install_listeners, start_empty_service,
    };
    use std::time::Duration;
    use tokio::sync::mpsc;

    /// The dangerous direction. A transport that dropped a moment ago is retrying
    /// inside its own ATM; rebuilding now would race a second websocket for the
    /// same DID and the mediator would reject one as `duplicate-channel` — the
    /// supervisor would cause the fault it exists to fix (#132).
    #[test]
    fn a_recent_drop_is_left_alone() {
        assert!(!rebuild_due(Duration::from_secs(1), 0, None));
        assert!(!rebuild_due(
            REBUILD_GRACE - Duration::from_secs(1),
            0,
            None
        ));
    }

    /// Bringing listeners up must not block the caller.
    ///
    /// This is the whole point of the split: each listener costs a mediator
    /// auth handshake and a websocket connect, in series, and startup used to
    /// await that on the state-handler thread — the one thread that services UI
    /// actions. The loading screen offered "Press Enter to continue" and then
    /// could not read the keypress until the last socket was up.
    ///
    /// The spec here names a mediator that cannot resolve, so the install is
    /// still in flight when the assertion runs: what is being pinned is that
    /// `spawn_install_listeners` *returns* while that is true.
    #[tokio::test]
    async fn installing_listeners_does_not_block_the_caller() {
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let service = start_empty_service(event_tx, tokio_util::sync::CancellationToken::new());
        let spec = ListenerSpec {
            id: "did:example:unreachable".to_string(),
            did: "did:example:unreachable".to_string(),
            mediator_did: "did:example:no-such-mediator".to_string(),
            label: "test".to_string(),
            secrets: Vec::new(),
        };

        let started = std::time::Instant::now();
        let handle = spawn_install_listeners(service.clone(), vec![spec]);
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_millis(200),
            "spawning the install must return immediately, took {elapsed:?}"
        );
        assert!(
            !service.has_listener("did:example:unreachable").await,
            "the unreachable listener must not have been installed synchronously"
        );

        handle.abort();
    }

    /// The other direction: past the grace period nothing else is coming, so a
    /// listener must not be stranded.
    #[test]
    fn a_transport_down_past_the_grace_period_is_rebuilt() {
        assert!(rebuild_due(REBUILD_GRACE, 0, None));
        assert!(rebuild_due(
            REBUILD_GRACE + Duration::from_secs(60),
            0,
            None
        ));
    }

    /// Consecutive failures back off rather than hammering the mediator.
    #[test]
    fn a_failed_rebuild_waits_before_the_next_attempt() {
        let down_for = REBUILD_GRACE + Duration::from_secs(600);
        assert!(
            !rebuild_due(down_for, 1, Some(Duration::from_secs(1))),
            "one second after a failed attempt is too soon"
        );
        assert!(
            rebuild_due(down_for, 1, Some(Duration::from_secs(5))),
            "the first backoff step has elapsed"
        );
    }

    #[test]
    fn backoff_doubles_and_then_caps() {
        assert_eq!(rebuild_backoff(0), Duration::ZERO);
        assert_eq!(rebuild_backoff(1), Duration::from_secs(5));
        assert_eq!(rebuild_backoff(2), Duration::from_secs(10));
        assert_eq!(rebuild_backoff(3), Duration::from_secs(20));
        assert_eq!(rebuild_backoff(4), Duration::from_secs(40));
        assert_eq!(rebuild_backoff(5), REBUILD_BACKOFF_CAP);
    }

    /// A listener that has been failing for hours must still be retried — capped,
    /// never abandoned. The framework's policy was `max_retries: None` and that
    /// property is worth keeping: a mediator that comes back should be picked up
    /// without restarting the app.
    #[test]
    fn a_long_outage_never_stops_retrying() {
        let forever = Duration::from_secs(60 * 60 * 24);
        assert_eq!(rebuild_backoff(u32::MAX), REBUILD_BACKOFF_CAP);
        assert!(rebuild_due(forever, u32::MAX, Some(REBUILD_BACKOFF_CAP)));
    }

    /// The grace period has to exceed the backoff ceiling, or a rebuild could be
    /// scheduled sooner than a healthy reconnect would have completed.
    #[test]
    fn the_grace_period_outlasts_the_backoff_ceiling() {
        assert!(REBUILD_GRACE > REBUILD_BACKOFF_CAP);
    }
}

#[cfg(test)]
mod persona_listener_id_tests {
    use super::{PERSONA_LISTENER_ID, persona_listener_id};

    /// The contract: the id *is* the DID. Stated as a test because the doc
    /// comment previously promised a slug and the code silently did this.
    #[test]
    fn the_id_is_the_did_verbatim() {
        let did = "did:webvh:QmR6e4:webvh.storm.ws:magic-depart";
        assert_eq!(persona_listener_id(did), did);
    }

    /// The reason not to "fix" this by slugging the trailing segment. Two
    /// personas on different hosts, with different SCIDs, share a final
    /// segment — slugging would key both onto one listener.
    #[test]
    fn personas_sharing_a_trailing_segment_get_distinct_ids() {
        let a = persona_listener_id("did:webvh:ScidA:host1.example:magic-depart");
        let b = persona_listener_id("did:webvh:ScidB:host2.example:magic-depart");
        assert_ne!(a, b, "listener_id is an identity key and must not collide");
    }

    /// A State-A account with no persona still needs a listener id.
    #[test]
    fn an_empty_did_falls_back_to_the_generic_id() {
        assert_eq!(persona_listener_id(""), PERSONA_LISTENER_ID);
    }
}

#[cfg(test)]
mod tsp_inbound_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::tsp_frame_to_message;
    use affinidi_messaging_core::transport::{Inbound, InboundAck};
    use affinidi_messaging_core::types::{Protocol, ReceivedMessage};

    const VERDICT_TYPE: &str = "https://trusttasks.org/spec/vtc/join-requests/submit/0.1#response";

    /// A TSP frame as the transport hands it over: the payload is the bare Trust
    /// Task document, and `sender` is the VID `unpack` authenticated.
    fn tsp_frame(payload: serde_json::Value, sender: Option<&str>) -> Inbound {
        Inbound {
            message: ReceivedMessage {
                id: "frame-hash".to_string(),
                sender: sender.map(str::to_string),
                recipient: "did:webvh:example:alice".to_string(),
                payload: serde_json::to_vec(&payload).unwrap(),
                protocol: Protocol::TSP,
                verified: true,
                encrypted: true,
            },
            thread_id: None,
            ack: InboundAck("frame-hash".to_string()),
        }
    }

    fn verdict_document(thread_id: &str) -> serde_json::Value {
        serde_json::json!({
            "id": "urn:uuid:11111111-1111-4111-8111-111111111111",
            "threadId": thread_id,
            "type": VERDICT_TYPE,
            "issuer": "did:webvh:example:vtc",
            "recipient": "did:webvh:example:alice",
            "payload": {
                "requestId": "22222222-2222-4222-8222-222222222222",
                "verdict": { "effect": "allow", "with": {} },
            },
        })
    }

    /// The whole point: a TSP frame must land in the same shape the DIDComm
    /// dispatcher already routes, with `type`/`threadId` lifted out of the
    /// document into the envelope positions DIDComm would have filled.
    #[test]
    fn verdict_document_normalises_into_a_message() {
        let thid = "urn:uuid:33333333-3333-4333-8333-333333333333";
        let doc = verdict_document(thid);
        let message =
            tsp_frame_to_message(&tsp_frame(doc.clone(), Some("did:webvh:example:vtc"))).unwrap();

        assert_eq!(message.typ, VERDICT_TYPE, "type comes from the document");
        assert_eq!(
            message.thid.as_deref(),
            Some(thid),
            "threadId is the correlation key on this transport"
        );
        assert_eq!(
            message.id, "urn:uuid:11111111-1111-4111-8111-111111111111",
            "the document id, not the frame hash, when the document has one"
        );
        assert_eq!(
            message.body, doc,
            "body is the whole document — the same value tt_didcomm_reply sets, \
             which is what lets the handlers read it unchanged"
        );
        assert_eq!(
            message.from.as_deref(),
            Some("did:webvh:example:vtc"),
            "from is the TSP-authenticated sender"
        );
    }

    /// The `from` header must never be recovered from the document's own
    /// `issuer`: that field is written by the sender, so trusting it would let
    /// any TSP peer claim to be the VTC.
    #[test]
    fn unauthenticated_frame_carries_no_sender() {
        let doc = verdict_document("urn:uuid:44444444-4444-4444-8444-444444444444");
        let message = tsp_frame_to_message(&tsp_frame(doc, None)).unwrap();

        assert!(
            message.from.is_none(),
            "a frame with no proven sender must not inherit the document's issuer"
        );
    }

    /// No envelope to fall back on, so an untyped document cannot be routed —
    /// dropping beats guessing a type and reaching the wrong handler.
    #[test]
    fn document_without_a_type_is_dropped() {
        let doc = serde_json::json!({ "id": "urn:uuid:5", "payload": {} });
        assert!(tsp_frame_to_message(&tsp_frame(doc, Some("did:webvh:example:vtc"))).is_none());
    }

    #[test]
    fn non_json_frame_is_dropped() {
        let mut frame = tsp_frame(serde_json::json!({}), Some("did:webvh:example:vtc"));
        frame.message.payload = b"not json at all".to_vec();
        assert!(tsp_frame_to_message(&frame).is_none());
    }

    /// A document with no `id` still needs a unique message id; the frame hash
    /// is the transport's own stable handle for it.
    #[test]
    fn frame_hash_is_the_id_fallback() {
        let doc = serde_json::json!({ "type": VERDICT_TYPE, "payload": {} });
        let message = tsp_frame_to_message(&tsp_frame(doc, Some("did:webvh:example:vtc"))).unwrap();
        assert_eq!(message.id, "frame-hash");
    }
}

#[cfg(test)]
mod catch_all_tests {
    use super::OPENVTC_CATCH_ALL_PATTERN;
    use regex::Regex;

    fn matches(uri: &str) -> bool {
        // `route_regex` anchors the whole type string, so mirror that
        // here rather than testing a substring match that would pass
        // for URIs the router would actually reject.
        Regex::new(&format!("^(?:{OPENVTC_CATCH_ALL_PATTERN})$"))
            .expect("catch-all pattern compiles")
            .is_match(uri)
    }

    /// The migration target. Without this arm, a migrated VTC's replies
    /// never reach the handler — dropped by the router, before dispatch.
    #[test]
    fn canonical_vtc_trust_tasks_are_routed() {
        for uri in [
            "https://trusttasks.org/spec/vtc/join-requests/submit/0.1",
            "https://trusttasks.org/spec/vtc/join-requests/submit/0.1#response",
            "https://trusttasks.org/spec/vtc/join-requests/status/0.1#response",
            "https://trusttasks.org/spec/vtc/members/self-remove/0.1",
        ] {
            assert!(matches(uri), "{uri} must reach the OpenVTC handler");
        }
    }

    /// Peer vetting tasks travel member to member, not through a community,
    /// so they live under their own prefix; and a refusal of any Trust Task
    /// arrives as a `trust-task-error`, which a vetter uses to refuse a request.
    /// Without these arms both are dropped before dispatch.
    #[test]
    fn vetting_tasks_and_trust_task_errors_are_routed() {
        for uri in [
            "https://trusttasks.org/spec/vetting/request/0.1",
            "https://trusttasks.org/spec/vetting/request/0.1#response",
            "https://trusttasks.org/spec/vetting/session/0.1",
            "https://trusttasks.org/spec/vetting/session/0.1#response",
            "https://trusttasks.org/spec/vetting/decline/0.1",
            "https://trusttasks.org/spec/vtc/vetting/revoke-statement/0.1#response",
            "https://trusttasks.org/spec/vtc/join-requests/manifest/0.2#response",
            "https://trusttasks.org/spec/trust-task-error/0.5",
        ] {
            assert!(matches(uri), "{uri} must reach the OpenVTC handler");
        }
    }

    /// The pre-migration prefix keeps working, so an unmigrated VTC is
    /// still reachable during the rollout.
    #[test]
    fn legacy_vtc_trust_tasks_still_route() {
        for uri in [
            "https://trusttasks.org/openvtc/vtc/spec/join-requests/submit/1.0",
            "https://trusttasks.org/openvtc/vtc/members/self-remove/1.0",
        ] {
            assert!(matches(uri), "{uri} must still reach the handler");
        }
    }

    #[test]
    fn the_other_arms_are_intact() {
        for uri in [
            "https://linuxfoundation.org/openvtc/anything",
            "https://firstperson.network/protocols/x",
            "https://trusttasks.org/spec/credential-exchange/offer/0.1",
            "https://didcomm.org/report-problem/2.0/problem-report",
        ] {
            assert!(matches(uri), "{uri} must reach the handler");
        }
    }

    /// The pattern is a routing gate, not a catch-everything: an
    /// unrelated canonical task must not be swept in.
    #[test]
    fn unrelated_types_are_not_routed() {
        for uri in [
            "https://trusttasks.org/spec/acl/list/0.1",
            "https://trusttasks.org/spec/policy/upsert/0.2",
            "https://example.com/whatever",
        ] {
            assert!(!matches(uri), "{uri} must NOT be routed here");
        }
    }
}
