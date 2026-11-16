//! The runtime loop (#528).
//!
//! The state the loop carries is the fields of [`Runtime`], and each `select!`
//! arm is one method on it, so every arm can be called from a test.
//! [`Runtime::run`] is a router: it waits for the next event, hands it to its
//! method, and runs the end-of-iteration work every arm falls through to.
//!
//! The arm methods live next to what they handle:
//!
//! | File | Arms |
//! |------|------|
//! | [`arms`] | actions, dispatch outcomes, presence, the admin-session supervisor, lifecycle/listener events, session reconcile, TSP store, saves, VTA sync |
//! | [`inbound_arm`] | inbound DIDComm events |
//! | [`timers`] | the periodic sweeps (capabilities/reply windows, pending expiry, join status, hidden vetting, community profiles, agent names) |
//!
//! Each method takes `&mut self` and destructures the fields it uses, so its
//! body reads as it did when the fields were locals, and the borrow checker
//! still sees disjoint borrows.
//!
//! The single-mutator invariant is unchanged: only these methods touch
//! `state` and `config`, and they all run on the loop's task.

#[allow(unused_imports)]
use crate::state_handler::state::PublishState;
mod arms;
mod inbound_arm;
#[cfg(test)]
mod tests;
mod timers;

use std::collections::{HashSet, VecDeque};

use affinidi_tdk::TDK;
use anyhow::Result;
use openvtc_core::config::Config;
use tokio::sync::{
    broadcast,
    mpsc::{self, UnboundedReceiver, UnboundedSender},
};
use tracing::{debug, warn};

use crate::{
    Interrupted, Terminator,
    state_handler::{
        StateHandler, actions::Action, background_dispatch, community_profile_poll,
        device_presence, didcomm, hidden_vetting_poll, join_flow, runtime_actions, save_coalesce,
        session_manager, state, state::State, verify_queue, vta_recovery, vta_sync_driver,
    },
};

/// What an arm asks the loop to do next.
#[derive(Debug)]
pub(super) enum Flow {
    /// Carry on: run the end-of-iteration work and wait for the next event.
    Continue,
    /// The arm provably changed nothing: skip the end-of-iteration work,
    /// including the state broadcast (#556). Only for arms that touched
    /// neither `state` nor `config` — there is no dirty tracking, so an arm
    /// that might have changed something returns [`Flow::Continue`].
    Quiet,
    /// Stop the loop with this outcome. The arm has already told the
    /// terminator when that is its job (an `Exit` action does; an interrupt,
    /// which came *from* the terminator, does not).
    Exit(Interrupted),
}

/// What `main_loop` brought up before the runtime can be assembled: the loaded
/// account, the admin VTA session and its supervisor, and the (possibly still
/// listener-less) messaging runtime.
///
/// Built once, before the State-A branch, and carried across it: a State-A
/// join hands these back rather than restarting.
pub(super) struct Startup {
    pub(super) handler: StateHandler,
    pub(super) terminator: Terminator,
    pub(super) action_rx: UnboundedReceiver<Action>,
    pub(super) interrupt_rx: broadcast::Receiver<Interrupted>,
    pub(super) state: State,
    pub(super) tdk: TDK,
    pub(super) config: Box<Config>,
    pub(super) admin_vta: Option<vta_sdk::client::VtaClient>,
    pub(super) presence_rx: UnboundedReceiver<device_presence::PresenceReport>,
    pub(super) vta_supervisor: vta_recovery::AdminVtaSupervisor,
    pub(super) didcomm_event_rx: UnboundedReceiver<didcomm::DIDCommEvent>,
    pub(super) shutdown_token: tokio_util::sync::CancellationToken,
    pub(super) didcomm_service: didcomm::Messaging,
    pub(super) tsp_dirty: std::sync::Arc<tokio::sync::Notify>,
}

/// The runtime loop's world: everything its arms read and write.
///
/// Field names match the loop locals they replaced, so the arm bodies did not
/// have to change to move.
pub(crate) struct Runtime {
    // ── Owner, UI and lifecycle channels ──
    pub(super) handler: StateHandler,
    pub(super) terminator: Terminator,
    pub(super) action_rx: UnboundedReceiver<Action>,
    pub(super) interrupt_rx: broadcast::Receiver<Interrupted>,

    // ── The single-mutator state ──
    pub(super) state: State,
    pub(super) config: Box<Config>,

    // ── Services ──
    pub(super) tdk: TDK,
    pub(super) admin_vta: Option<vta_sdk::client::VtaClient>,
    pub(super) vta_supervisor: vta_recovery::AdminVtaSupervisor,
    pub(super) presence_rx: UnboundedReceiver<device_presence::PresenceReport>,
    pub(super) didcomm_service: didcomm::Messaging,
    pub(super) shutdown_token: tokio_util::sync::CancellationToken,
    pub(super) session_manager: session_manager::SessionManager,
    pub(super) didcomm_event_rx: UnboundedReceiver<didcomm::DIDCommEvent>,
    pub(super) listener_events: broadcast::Receiver<didcomm::ListenerStatus>,
    pub(super) lifecycle_log_rx: UnboundedReceiver<didcomm::LifecycleLog>,
    pub(super) tsp_dirty: std::sync::Arc<tokio::sync::Notify>,
    /// Held so the listener install and the lifecycle logger are not detached
    /// anonymously; neither is awaited.
    _listener_install: tokio::task::JoinHandle<()>,
    _lifecycle_handle: tokio::task::JoinHandle<()>,

    // ── Inbound ──
    pub(super) seen_messages: openvtc_core::messaging::SeenMessages,
    /// Replies awaited by thread — a renewal's, a community profile's, an
    /// election answer from a community we hold no membership with. The
    /// inbound gate admits those only on a thread recorded here. Owned by
    /// this loop alone: send paths record into it on this thread before
    /// spawning, and inbound dispatch consumes from it.
    pub(super) pending_replies: openvtc_core::pending_replies::PendingReplies,
    pub(super) verifier: verify_queue::Verifier,
    pub(super) restore_backlog: VecDeque<openvtc_core::config::protected_config::DeferredInbound>,
    pub(super) witness_router: openvtc_core::witness::ReplyRouter,
    pub(super) ping_sent_at: Option<std::time::Instant>,

    // ── Background dispatch (R13) ──
    pub(super) dispatch_tx: UnboundedSender<background_dispatch::DispatchOutcome>,
    pub(super) dispatch_rx: UnboundedReceiver<background_dispatch::DispatchOutcome>,
    pub(super) in_flight: background_dispatch::InFlight,
    pub(super) contexts_checked: HashSet<String>,
    pub(super) grants_swept: bool,

    // ── Coalesced persistence (R11) ──
    pub(super) save: save_coalesce::SaveScheduler,
    pub(super) save_done_tx: UnboundedSender<Result<(), String>>,
    pub(super) save_done_rx: UnboundedReceiver<Result<(), String>>,

    // ── VTA account sync ──
    pub(super) vta_sync: vta_sync_driver::SyncDriver,
    pub(super) vta_sync_tick: tokio::time::Interval,
    pub(super) vta_sync_tx: UnboundedSender<openvtc_core::vta_sync::Exchange>,
    pub(super) vta_sync_rx: UnboundedReceiver<openvtc_core::vta_sync::Exchange>,

    // ── Timers and their pacers ──
    pub(super) pending_expiry_tick: tokio::time::Interval,
    pub(super) capabilities_sweep: tokio::time::Interval,
    pub(super) session_reconcile_tick: tokio::time::Interval,
    pub(super) agent_name_tick: tokio::time::Interval,
    pub(super) join_status_tick: tokio::time::Interval,
    pub(super) join_status_pacer: openvtc_core::join::status_poll::PollPacer,
    pub(super) community_profile_tick: tokio::time::Interval,
    pub(super) community_profile_pacer: community_profile_poll::ProfilePacer,
    pub(super) hidden_vetting_tick: tokio::time::Interval,
    pub(super) hidden_vetting_pacer: hidden_vetting_poll::HiddenVettingPacer,

    // ── The join flow ──
    /// The open join, if any (#529): a state machine this loop drives — its
    /// actions, its off-loop jobs' outcomes — rather than a loop of its own
    /// that would park this one.
    pub(super) join: join_flow::JoinDriver,
    /// The join flow to enter at the end of this iteration.
    pub(super) join_entry: Option<join_flow::JoinEntry>,
    /// Messages from a community whose join request is being sent, held
    /// until the request is recorded (see [`Runtime::on_inbound`]).
    pub(super) held_inbound: Vec<(
        didcomm::DIDCommEvent,
        Option<openvtc_core::inbound::PreVerified>,
    )>,
    /// A join waiting on a community's requirements (see `join_flow::AwaitingRequirements`).
    pub(super) awaiting_requirements: Option<join_flow::AwaitingRequirements>,
    /// A join parked on a hidden-vetting challenge (see
    /// `join_flow::AwaitingChallenge`) — the same hand-off, for the question
    /// a launch asks rather than the one the vetting page does.
    pub(super) awaiting_challenge: Option<join_flow::AwaitingChallenge>,
    /// A join parked on a wallet session (see `join_flow::AwaitingWallet`).
    pub(super) awaiting_wallet: Option<join_flow::AwaitingWallet>,
}

impl Runtime {
    /// Bring the runtime up on what `main_loop` started: install this account's
    /// listeners, register its sessions, seed the connection indicator, and
    /// build the loop's timers, pacers and channels.
    pub(super) async fn assemble(startup: Startup) -> Runtime {
        let Startup {
            handler,
            terminator,
            action_rx,
            interrupt_rx,
            mut state,
            tdk,
            mut config,
            admin_vta,
            presence_rx,
            vta_supervisor,
            didcomm_event_rx,
            shutdown_token,
            didcomm_service,
            tsp_dirty,
        } = startup;

        // Point the runtime active identity at the default working community and
        // refilter the community-scoped panels before the first paint (D10 /
        // R-C-6) — otherwise a multi-persona account renders empty panels until
        // the first event re-syncs (the per-path syncs above run with no
        // selection set yet).
        state.reconcile_selected_community_among(
            &config.account,
            Some(&config.identities.keys().copied().collect()),
        );
        let initial_active = state
            .selected_community
            .as_ref()
            .map(|(_, persona)| *persona);
        config.set_active_persona(initial_active);
        state.main_page.sync_from_config(&config);

        // Send initial state immediately so the UI renders without blocking.
        // Connecting only when there is a community session to connect: with no
        // live membership there is none, and "Connecting..." would sit on the
        // screen until the seed below corrected it — or read as a hang.
        state.connection.status = if config.account.memberships().any(|m| m.is_live()) {
            state::MediatorStatus::Connecting
        } else {
            state::MediatorStatus::NoActiveCommunity
        };
        let _ = handler.state_tx.publish(&state);

        // Install this account's listeners on the runtime started above. Skips
        // any that already exist, so a State-A join's own persona listener is
        // bound to rather than duplicated (one websocket per DID).
        //
        // The specs are built here because that needs `Config`, which is not
        // `Clone` and cannot cross into a task. Bringing the listeners *up* is
        // the expensive half — a mediator auth handshake and a websocket connect
        // each, in series — and that half runs off this thread. This is the only
        // thread that services UI actions, and the loading screen has already
        // been told to offer "Press Enter to continue": awaiting the connects
        // here meant the keypress sat unread in the action channel until the last
        // socket was up, and the main page then arrived in one late jump.
        // Outbound TSP sends (`tsp::send_trust_task`) run on `tdk.atm`; inbound
        // frames are unsealed by listener ATMs. Both must record relationships in
        // the one durable store, or the invite we send is `Pending` where no
        // listener looks and the peer's accept and replies are dropped (VTI-61).
        let tdk = match didcomm_service.tsp_store().adopt_into(tdk.clone()).await {
            Ok(adopted) => adopted,
            Err(e) => {
                warn!(error = %e, "could not share the TSP relationship store with the sending ATM");
                tdk
            }
        };

        let listener_specs = didcomm::build_listener_configs(&config, &tdk).await;
        let listener_install =
            didcomm::spawn_install_listeners(didcomm_service.clone(), listener_specs);

        // Process-lifetime LRU of inbound message IDs. Backstop for replay
        // and mediator-pickup duplicates beyond what the TDK already filters.
        let mut seen_messages = openvtc_core::messaging::SeenMessages::new();
        // Replies awaited by thread (see the `pending_replies` field).
        let mut pending_replies = openvtc_core::pending_replies::PendingReplies::default();

        // Forward lifecycle events (connect/disconnect/restart) to the activity log
        let (lifecycle_log_tx, lifecycle_log_rx) =
            mpsc::unbounded_channel::<didcomm::LifecycleLog>();
        let lifecycle_handle = didcomm::spawn_lifecycle_logger(&didcomm_service, lifecycle_log_tx);

        // Phase 2 (community/persona DIDComm connection) runs ASYNCHRONOUSLY: we
        // do NOT block the UI waiting for the listener. The main page is already
        // showing (Connecting); the persona connection proceeds in the
        // background and the runtime loop below flips the status to Connected the
        // moment a `ListenerEvent::Connected` arrives — and back to Connecting on
        // a disconnect. Subscribe to typed lifecycle events for that.
        let listener_events = didcomm_service.subscribe();

        // Supervised multi-session manager (D11/D15): one persona-session per
        // active community (a reused persona shares one), tracking per-session
        // connection status over the listeners `start_service` already launched.
        // Messaging runs through it from here on; at N=1 it holds one session and
        // behaves identically to the previous single global flag.
        let mut session_manager = session_manager::SessionManager::default();
        {
            use session_manager::RegisterOutcome;
            // NOTE: a mid-session leave/reject/expire does NOT yet deregister its
            // session (that is T6/T7), so until then `any_connected()` can read
            // live for a persona whose communities have all gone inactive. Startup
            // registers exactly the communities that require a live session at load
            // time (`IdentityRegistry::sessions`).
            let registry = openvtc_core::identity::IdentityRegistry::new(&config.account);
            let mut at_capacity = 0usize;
            for (persona_id, vtcs) in registry.sessions() {
                let Some(ctx) = config.identities.get(&persona_id) else {
                    // A live community whose persona didn't resolve to an identity
                    // has no listener either — surfaced here for parity, not silent.
                    debug!(%persona_id, "live-community persona missing from resolved identities — not tracked");
                    continue;
                };
                let lid = didcomm::persona_listener_id(&ctx.did);
                for vtc in vtcs {
                    if matches!(
                        session_manager.register(persona_id, &lid, vtc.clone()),
                        RegisterOutcome::AtCapacity
                    ) {
                        at_capacity += 1;
                        warn!(%persona_id, vtc = %vtc, "session manager at capacity — community not tracked");
                    }
                }
            }
            // No silent caps (D15): tell the user if any community exceeded the bound.
            if at_capacity > 0 {
                state.main_page.log(format!(
                    "Warning: {at_capacity} communit{} exceeded the session limit ({}) and are not actively connected.",
                    if at_capacity == 1 { "y" } else { "ies" },
                    session_manager.max_sessions(),
                ));
            }
        }

        // Seed the indicator from the messaging layer's *live* state rather than
        // assuming nothing is up yet. `ListenerStatus` is edge-triggered, and a
        // State-A join has already brought its persona listener up and connected
        // by the time this loop subscribes — the install step above binds to that
        // socket instead of reinstalling it, so no second `Connected` edge is
        // coming. Without this seed the session sits `Connecting` for the life of
        // the process over a perfectly live socket, which is the "Inbox:
        // Connecting…" that only a restart appeared to fix.
        //
        // Applied unconditionally rather than only when the reconcile changed
        // something: an account with no community session (an applicant whose
        // join is still being vetted) has nothing to change, and must still
        // land on `NoActiveCommunity` rather than the `Connecting` shown while
        // the page came up — no session will ever send the edge that moves it.
        super::reconcile_sessions(&mut session_manager, &didcomm_service, &mut state);
        super::apply_session_aggregate(&session_manager, &mut state);
        match state.connection.status {
            state::MediatorStatus::Connected => state.main_page.log("Connected to the mediator."),
            state::MediatorStatus::NoActiveCommunity => state
                .main_page
                .log("No community membership yet — no community session to connect."),
            _ => state.main_page.log("Connecting to the mediator…"),
        }
        let _ = handler.state_tx.publish(&state);

        // Background-dispatch plumbing (R13). Network-bound actions whose await
        // would otherwise park the whole select loop are spawned as background
        // tasks; they do I/O only and send their result back as a
        // `DispatchOutcome` on this channel. The select arm below applies the
        // outcome on the loop thread (the single mutator), keeping the loop live
        // during the wait. `in_flight` rejects a second action on a busy domain.
        let (dispatch_tx, dispatch_rx) =
            mpsc::unbounded_channel::<background_dispatch::DispatchOutcome>();

        // Coalesced + offloaded config persistence (R11). Mutation sites mark the
        // config dirty on the loop thread instead of saving inline; the
        // `deadline` arm below debounces a burst into a single `spawn_blocking`
        // save, with at most one in flight at a time. Durability-critical points
        // (Exit, passphrase/protection change, export) force-flush synchronously.
        let mut save = save_coalesce::SaveScheduler::new(handler.profile.clone());
        // Channel carrying a completed background save's success flag, so the loop
        // can clear the in-flight flag and re-arm if the config was dirtied again
        // while the save ran. Save failures are surfaced as a status/log here,
        // matching the pre-R11 inline `save_config` failure handling.
        let (save_done_tx, save_done_rx) = mpsc::unbounded_channel::<Result<(), String>>();

        // Account-state sync with the VTA (`openvtc_core::vta_sync`). The load
        // already ran one; report it, and save whatever it changed. From here
        // a cycle runs after each save and on a timer, off the loop: the plan
        // is taken here, the network half is spawned, and its result is merged
        // back here — the loop stays the only thing that mutates `config`.
        if let Some(report) = config.private.vta_sync.load_report.take() {
            for line in report.log_lines() {
                state.main_page.log(line);
            }
            if report.touched() {
                save.mark_dirty();
            }
        }
        let vta_sync = vta_sync_driver::SyncDriver::new(tokio::time::Instant::now());
        let mut vta_sync_tick = tokio::time::interval(vta_sync_driver::TICK);
        vta_sync_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let (vta_sync_tx, vta_sync_rx) =
            mpsc::unbounded_channel::<openvtc_core::vta_sync::Exchange>();

        // Network-bound checks on inbound messages (a DID resolve, a status
        // list fetch) run off this loop, one at a time, so a slow community
        // never freezes the UI. A message waiting on its check is not applied
        // at all; it comes back from `verifier` with the result and is
        // dispatched from the top. The queue is bounded, with a lane for the
        // communities we belong to and a cap per sender (`verify_queue`).
        let mut verifier = verify_queue::Verifier::new(tdk.clone());
        // Messages from communities that were still queued at the last exit.
        // The mediator deleted them on delivery, so their kept copies are the
        // only ones. They are queued again as room allows; the rest wait (kept)
        // until earlier checks finish, and none is dropped for want of room.
        let mut restore_backlog: VecDeque<_> =
            config.private.deferred_inbound.iter().cloned().collect();
        if super::restore_kept(
            &mut verifier,
            &mut restore_backlog,
            &mut config,
            &mut state,
            &tdk,
            &didcomm_service,
            &mut seen_messages,
            &mut pending_replies,
        )
        .await
        {
            save.mark_dirty();
        }

        let mut hidden_vetting_tick = tokio::time::interval(std::time::Duration::from_secs(30));
        hidden_vetting_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        Runtime {
            handler,
            terminator,
            action_rx,
            interrupt_rx,
            state,
            config,
            tdk,
            admin_vta,
            vta_supervisor,
            presence_rx,
            didcomm_service,
            shutdown_token,
            session_manager,
            didcomm_event_rx,
            listener_events,
            lifecycle_log_rx,
            tsp_dirty,
            _listener_install: listener_install,
            _lifecycle_handle: lifecycle_handle,
            seen_messages,
            pending_replies,
            verifier,
            restore_backlog,
            // Hands a witness's answers from the inbound arm to the witnessing
            // waiting on them (`witness_actions`); the job verifies each one
            // before reading it.
            witness_router: openvtc_core::witness::ReplyRouter::default(),
            // Track when a manual trust-ping was sent (for activity log latency
            // display).
            ping_sent_at: None,
            dispatch_tx,
            dispatch_rx,
            in_flight: background_dispatch::InFlight::default(),
            // Membership contexts already checked at the VTA this run. A failure
            // is logged and retried on the next launch rather than every tick.
            contexts_checked: HashSet::new(),
            // Whether this run has read the membership contexts' device grants
            // for the communities panel. Once a run; the device-access view
            // re-reads on demand.
            grants_swept: false,
            save,
            save_done_tx,
            save_done_rx,
            vta_sync,
            vta_sync_tick,
            vta_sync_tx,
            vta_sync_rx,
            // 7-day Pending timeout sweep (R-B-7 / D16). `interval`'s first tick
            // fires immediately, so a Pending that aged out while the app was
            // closed expires on launch; thereafter it sweeps hourly.
            pending_expiry_tick: tokio::time::interval(std::time::Duration::from_secs(3600)),
            // Reply-window sweep for the capabilities view (cheap no-op when the
            // view is closed or idle).
            capabilities_sweep: tokio::time::interval(std::time::Duration::from_secs(5)),
            // Backstop for the edge-triggered listener-status stream. A
            // transition that reaches nobody — the broadcast receiver lagging, a
            // listener adopted after its connect — would otherwise latch a
            // session's status (and the indicator) wrong until the next real
            // edge, which for a healthy socket may never come. Cheap: a read of
            // the transports' live state, no I/O and no allocation beyond the
            // listener ids.
            session_reconcile_tick: tokio::time::interval(std::time::Duration::from_secs(15)),
            // Agent-name refresh sweep. The first tick fires immediately so
            // names resolve shortly after launch; thereafter it picks up
            // newly-added DIDs (a fresh relationship/contact) and re-verifies
            // stale entries every few minutes. Cheap when there is nothing to do
            // — it only spawns a job when `agent_name_refresh_targets` finds
            // uncached/stale DIDs, and the resolver caches keep repeat sweeps
            // quiet.
            agent_name_tick: tokio::time::interval(std::time::Duration::from_secs(300)),
            // Reconcile Pending joins with their communities. The first tick
            // fires immediately, which is the point: a join still Pending at
            // launch is the one whose answer may have been lost, and asking is
            // how we find out rather than waiting to be told again. Per-record
            // backoff lives in the pacer, so a minute-by-minute tick does not
            // mean a minute-by-minute poll; ticks over an account with no
            // Pending join do no work at all.
            join_status_tick: tokio::time::interval(std::time::Duration::from_secs(60)),
            join_status_pacer: openvtc_core::join::status_poll::PollPacer::default(),
            // Ask each Active community, once per session, for its declared
            // `relationshipIdentifierDefault` (#241). The pacer asks each
            // community once, so this tick over communities already asked does
            // no work; a bare account (no Active membership) does none at all.
            community_profile_tick: tokio::time::interval(std::time::Duration::from_secs(60)),
            community_profile_pacer: community_profile_poll::ProfilePacer::default(),
            // The vetter side of hidden vetting: re-read each community we vet
            // for, enrol, and draw the token drip — on the communities' tick
            // windows and at least hourly, never on demand
            // (`hidden_vetting_poll`). The interval only checks the pacer; the
            // first check is at launch, which is when a client that was off
            // catches up the ticks it missed.
            hidden_vetting_tick,
            hidden_vetting_pacer: hidden_vetting_poll::HiddenVettingPacer::default(),
            join: join_flow::JoinDriver::new(true),
            join_entry: None,
            held_inbound: Vec::new(),
            awaiting_requirements: None,
            awaiting_challenge: None,
            awaiting_wallet: None,
        }
    }

    /// Run the loop until an arm asks it to stop, then shut down.
    pub(super) async fn run(mut self) -> Result<Interrupted> {
        // did-git-sign's install is read off the loop (#555), once now and
        // again when a view that shows it opens.
        crate::state_handler::settings_actions::refresh_did_git_sign(
            &mut self.state,
            &mut self.in_flight,
            &self.dispatch_tx,
        );
        let result = loop {
            let flow = tokio::select! {
                Some(action) = self.join.next_action(&mut self.action_rx) => {
                    let flow = self.on_action(action).await;
                    // A view that shows did-git-sign may just have opened: no
                    // I/O here, only whether a refresh is due.
                    crate::state_handler::settings_actions::maybe_refresh_did_git_sign(
                        &mut self.state,
                        &mut self.in_flight,
                        &self.dispatch_tx,
                    );
                    flow
                }
                // DIDComm inbound message events — as they arrive, or handed
                // back with the result of their off-loop check.
                Some((event, pre)) = super::next_inbound(&mut self.didcomm_event_rx, &mut self.verifier) => {
                    self.on_inbound(event, pre).await;
                    Flow::Continue
                }
                Some(outcome) = self.dispatch_rx.recv() => {
                    self.on_dispatch_outcome(outcome).await
                }
                Some(report) = self.presence_rx.recv() => {
                    self.on_presence(report).await;
                    Flow::Continue
                }
                _ = self.vta_supervisor.tick.tick() => {
                    self.on_vta_health_tick().await;
                    Flow::Continue
                }
                Some(outcome) = self.vta_supervisor.done_rx.recv() => {
                    self.on_vta_rebuilt(outcome).await;
                    Flow::Continue
                }
                Some(event) = self.lifecycle_log_rx.recv() => {
                    self.on_lifecycle_log(event).await;
                    Flow::Continue
                }
                ev = self.listener_events.recv() => {
                    self.on_listener_event(ev).await;
                    Flow::Continue
                }
                _ = self.session_reconcile_tick.tick() => {
                    if self.on_session_reconcile().await {
                        Flow::Continue
                    } else {
                        Flow::Quiet
                    }
                }
                _ = self.capabilities_sweep.tick() => {
                    self.on_capabilities_sweep().await;
                    Flow::Continue
                }
                _ = self.pending_expiry_tick.tick() => {
                    self.on_pending_expiry().await;
                    Flow::Continue
                }
                _ = self.join_status_tick.tick() => {
                    self.on_join_status_tick().await;
                    Flow::Continue
                }
                _ = self.hidden_vetting_tick.tick() => {
                    self.on_hidden_vetting_tick().await;
                    Flow::Continue
                }
                _ = self.community_profile_tick.tick() => {
                    self.on_community_profile_tick().await;
                    Flow::Continue
                }
                _ = self.agent_name_tick.tick() => {
                    self.on_agent_name_tick().await;
                    Flow::Continue
                }
                _ = self.tsp_dirty.notified() => {
                    self.on_tsp_dirty().await;
                    Flow::Continue
                }
                _ = self.save.wait_deadline() => {
                    self.on_save_deadline().await;
                    Flow::Continue
                }
                Some(result) = self.save_done_rx.recv() => {
                    self.on_save_done(result).await;
                    Flow::Continue
                }
                // Every two seconds, and almost always with nothing to start.
                _ = self.vta_sync_tick.tick() => {
                    // Always republished: the UI redraws only on keys or new
                    // state, and this 2 s tick is what keeps "now"-based
                    // displays (pending-join liveness, election and receive
                    // countdowns) moving, as on the old loop.
                    self.on_vta_sync_tick().await;
                    Flow::Continue
                }
                Some(ex) = self.vta_sync_rx.recv() => {
                    self.on_vta_sync_exchange(ex).await;
                    Flow::Continue
                }
                // (keepalive removed — WebSocket-level pings handle connectivity)
                // Catch and handle interrupt signal to gracefully shutdown
                Ok(interrupted) = self.interrupt_rx.recv() => Flow::Exit(interrupted),
            };
            match flow {
                Flow::Exit(interrupted) => {
                    // An open join is undone before the loop stops: a launch
                    // in flight rolls back what it made, as a cancel does.
                    self.cancel_join().await;
                    break interrupted;
                }
                Flow::Quiet => continue,
                Flow::Continue => {}
            }
            if let Some(interrupted) = self.end_of_iteration().await {
                break interrupted;
            }
        };
        self.shutdown().await;
        Ok(result)
    }

    /// The work every arm falls through to: enter the join flow when an arm
    /// asked for it, keep the working-community selection valid, and broadcast
    /// the state. `Some` when the join flow ended the application.
    async fn end_of_iteration(&mut self) -> Option<Interrupted> {
        // Enter the join flow: from the Communities panel, or back from waiting
        // on a community's requirements. Here rather than in an arm so every
        // way in is handled the same.
        if let Some(entry) = self.join_entry.take() {
            self.awaiting_requirements = None;
            self.awaiting_challenge = None;
            self.awaiting_wallet = None;
            let (join, mut ctx) = self.join_parts();
            let step = join.enter(&mut ctx, entry).await;
            if let Some(interrupted) = self.apply_join_step(step).await {
                return Some(interrupted);
            }
        }
        // Keep the working-context selection valid against any account change
        // this iteration applied (join/leave/status transition) before the UI
        // re-renders from the broadcast (D10 / R-C-6), then point the runtime
        // active identity at the selected community's persona so all
        // identity-derived reads scope to the working community. When the
        // working persona actually changes (e.g. the active community left and
        // the default shifted), refilter the community-scoped panels so the UI
        // reflects the new context this frame.
        self.state.reconcile_selected_community_among(
            &self.config.account,
            Some(&self.config.identities.keys().copied().collect()),
        );
        let active_persona = self
            .state
            .selected_community
            .as_ref()
            .map(|(_, persona)| *persona);
        if active_persona != self.config.active_persona {
            self.config.set_active_persona(active_persona);
            self.state.main_page.sync_from_config(&self.config);
        }
        let _ = self.handler.state_tx.publish(&self.state);
        None
    }

    /// Do what a join step asks of this loop. `Some` when it ends the
    /// application.
    pub(super) async fn apply_join_step(
        &mut self,
        step: join_flow::JoinStep,
    ) -> Option<Interrupted> {
        match step {
            join_flow::JoinStep::Continue => {}
            join_flow::JoinStep::Returned(joined) => {
                self.state.active_page = state::ActivePage::Main;
                // R-B-5 / D11: bring the new community's session up live so the
                // VTC's async receipt is received now, not only after a restart.
                if let Some(joined) = joined {
                    super::register_joined_session(
                        &mut self.session_manager,
                        &self.didcomm_service,
                        &self.tdk,
                        &self.config,
                        joined,
                        &mut self.state,
                    )
                    .await;
                    // What the new community's persona wears, now rather than at
                    // the next sweep — until then its row could only say it had
                    // not been read.
                    super::dispatch_binding_refresh(
                        &self.config,
                        self.admin_vta.as_ref(),
                        &mut self.in_flight,
                        &self.dispatch_tx,
                    );
                }
            }
            join_flow::JoinStep::AwaitRequirements(awaiting) => {
                self.awaiting_requirements = Some(awaiting);
            }
            join_flow::JoinStep::AwaitChallenge(awaiting) => {
                self.awaiting_challenge = Some(awaiting);
            }
            join_flow::JoinStep::AwaitWallet(awaiting) => {
                self.awaiting_wallet = Some(awaiting);
            }
            // F10 on a join page lands here. Like every other exit it must tell
            // the UI to stop: the UI leaves its loop only on an interrupt, so
            // breaking without one stopped this loop and left the screen up
            // reading keys nobody acted on — the "join page freezes, even F10
            // and Esc" report.
            join_flow::JoinStep::Exit(interrupted) => {
                if let Err(e) = self.terminator.terminate(interrupted.clone()) {
                    debug!("Failed to send terminate signal: {e}");
                }
                return Some(interrupted);
            }
        }
        None
    }

    /// End an open join, undoing a launch in flight — the loop is stopping.
    async fn cancel_join(&mut self) {
        if !self.join.is_active() {
            return;
        }
        let (join, mut ctx) = self.join_parts();
        join.cancel(&mut ctx).await;
        let _ = self.handler.state_tx.publish(&self.state);
    }

    /// The join driver, and everything it acts on, borrowed apart.
    pub(super) fn join_parts(&mut self) -> (&mut join_flow::JoinDriver, join_flow::JoinCtx<'_>) {
        let Runtime {
            join,
            state,
            config,
            tdk,
            admin_vta,
            didcomm_service,
            save,
            dispatch_tx,
            in_flight,
            handler,
            ..
        } = self;
        (
            join,
            join_flow::JoinCtx {
                state,
                config,
                tdk,
                admin_vta: admin_vta.as_ref(),
                messaging: Some(didcomm_service),
                profile: handler.profile.as_str(),
                save,
                dispatch_tx,
                in_flight,
                state_tx: &handler.state_tx,
            },
        )
    }

    /// Everything the loop owns, borrowed for an action handler.
    pub(super) fn action_ctx(&mut self) -> runtime_actions::ActionCtx<'_> {
        runtime_actions::ActionCtx {
            state: &mut self.state,
            config: &mut self.config,
            save: &mut self.save,
            in_flight: &mut self.in_flight,
            dispatch_tx: &self.dispatch_tx,
            tdk: &self.tdk,
            admin_vta: self.admin_vta.as_ref(),
            didcomm_service: &self.didcomm_service,
            session_manager: &mut self.session_manager,
            ping_sent_at: &mut self.ping_sent_at,
            state_tx: &self.handler.state_tx,
            profile: self.handler.profile.as_str(),
            witness_router: &self.witness_router,
            pending_replies: &mut self.pending_replies,
        }
    }

    /// Persist what is left to persist and close the services.
    async fn shutdown(mut self) {
        // R11: if a backgrounded coalesced save was still running when the loop
        // broke, wait for it to complete before the force-flush below. A
        // `spawn_blocking` task is NOT cancelled when its `JoinHandle` is dropped,
        // so that save is still live; running the shutdown save concurrently would
        // mean two `Config::save`s racing the same (non-atomic) file + keyring
        // writes. Draining the completion channel serialises shutdown after it.
        // After `finish`, `needs_flush()` is only still true if the config was
        // dirtied *after* the in-flight save's snapshot — exactly what the
        // force-flush must persist.
        if self.save.in_flight()
            && let Some(result) = self.save_done_rx.recv().await
        {
            self.save.finish(result.is_ok());
        }

        // R11 force-flush: persist the latest state before tearing down, so
        // coalescing never loses the final mutation on Exit/interrupt. Runs a
        // direct blocking save (the loop has broken; there is no runtime arm left
        // to schedule against). `needs_flush` is true when the config is dirty or
        // a background save was still in flight when the loop broke.
        if self.save.needs_flush() {
            match self.save.snapshot_now(&self.config) {
                Ok(pending) => {
                    if let Err(e) = pending.run() {
                        self.state
                            .main_page
                            .log_error("Failed to save config on exit", &e);
                    }
                }
                Err(e) => {
                    self.state
                        .main_page
                        .log_error("Failed to snapshot config on exit", &e);
                }
            }
        }

        // Shut down the DIDComm service gracefully
        self.shutdown_token.cancel();
        self.didcomm_service.shutdown().await;

        // Close the always-on admin VTA session.
        if let Some(c) = self.admin_vta {
            c.shutdown().await;
        }
    }
}
