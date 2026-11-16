//! A harness for the runtime loop (#528, #537).
//!
//! Every piece of the world the loop needs builds offline — `TDK` without an
//! environment file, `Messaging` with no listeners, an admin session that is
//! simply absent — so the harness assembles a real [`Runtime`] and drives one
//! arm at a time, or the whole loop until it is told to stop.

use std::time::{Duration, Instant};

use tokio::sync::{broadcast, mpsc, watch};

use super::*;
use crate::state_handler::{
    StartingMode,
    dispatch_util::{test_config, test_tdk},
    main_page::content::{CapabilitiesPhase, CapabilitiesView},
};

/// The ends of the runtime's channels a test plays the other side of.
struct Handles {
    action_tx: mpsc::UnboundedSender<Action>,
    interrupt_tx: broadcast::Sender<Interrupted>,
    /// Subscribed before the runtime starts, so it hears the terminator.
    interrupt_seen: broadcast::Receiver<Interrupted>,
    state_rx: watch::Receiver<std::sync::Arc<State>>,
    _event_tx: mpsc::UnboundedSender<didcomm::DIDCommEvent>,
    _presence_tx: mpsc::UnboundedSender<device_presence::PresenceReport>,
}

async fn runtime() -> (Runtime, Handles) {
    let (handler, state_rx) = StateHandler::new("runtime-test", StartingMode::NotSet);
    let (action_tx, action_rx) = mpsc::unbounded_channel();
    let (interrupt_tx, interrupt_rx) = broadcast::channel(4);
    let interrupt_seen = interrupt_tx.subscribe();
    let (event_tx, didcomm_event_rx) = mpsc::unbounded_channel();
    let (presence_tx, presence_rx) = mpsc::unbounded_channel();
    let shutdown_token = tokio_util::sync::CancellationToken::new();
    let didcomm_service = didcomm::start_empty_service(event_tx.clone(), shutdown_token.clone());
    let tsp_dirty = didcomm_service.tsp_store().dirty();
    let runtime = Runtime::assemble(Startup {
        handler,
        terminator: Terminator::new(interrupt_tx.clone()),
        action_rx,
        interrupt_rx,
        state: State::default(),
        tdk: test_tdk().await,
        config: Box::new(test_config()),
        admin_vta: None,
        presence_rx,
        vta_supervisor: vta_recovery::AdminVtaSupervisor::new(
            None,
            None,
            openvtc_core::vta_receive_leg::ReceiveLegTracker::new(),
        ),
        didcomm_event_rx,
        shutdown_token,
        didcomm_service,
        tsp_dirty,
    })
    .await;
    (
        runtime,
        Handles {
            action_tx,
            interrupt_tx,
            interrupt_seen,
            state_rx,
            _event_tx: event_tx,
            _presence_tx: presence_tx,
        },
    )
}

fn logged(state: &State, needle: &str) -> bool {
    state
        .main_page
        .activity_log
        .iter()
        .any(|e| e.summary.contains(needle))
}

fn ago(secs: u64) -> Instant {
    Instant::now()
        .checked_sub(Duration::from_secs(secs))
        .expect("the clock is past the test's offset")
}

#[tokio::test]
async fn an_account_with_no_community_assembles_to_no_active_community() {
    let (rt, h) = runtime().await;
    assert!(matches!(
        rt.state.connection.status,
        state::MediatorStatus::NoActiveCommunity
    ));
    assert!(logged(&rt.state, "No community membership yet"));
    // Assembling published what it set up, before any event arrived.
    assert!(matches!(
        h.state_rx.borrow().connection.status,
        state::MediatorStatus::NoActiveCommunity
    ));
}

#[tokio::test]
async fn exit_stops_the_loop_and_tells_the_terminator() {
    let (rt, mut h) = runtime().await;
    h.action_tx.send(Action::Exit).unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(10), rt.run())
        .await
        .expect("the loop stops on Exit")
        .expect("the loop returns its outcome");
    assert!(matches!(outcome, Interrupted::UserInt));
    assert!(
        matches!(h.interrupt_seen.try_recv(), Ok(Interrupted::UserInt)),
        "the UI is told to stop too, or it keeps reading keys nobody acts on"
    );
}

#[tokio::test]
async fn an_interrupt_stops_the_loop_with_that_interrupt() {
    let (rt, h) = runtime().await;
    h.interrupt_tx
        .send(Interrupted::OsSignal("SIGINT"))
        .unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(10), rt.run())
        .await
        .expect("the loop stops on an interrupt")
        .expect("the loop returns its outcome");
    assert!(matches!(outcome, Interrupted::OsSignal("SIGINT")));
}

#[tokio::test]
async fn the_end_of_an_iteration_broadcasts_the_state() {
    let (mut rt, mut h) = runtime().await;
    h.state_rx.mark_unchanged();
    rt.state.main_page.log("a line only this iteration wrote");
    assert!(rt.end_of_iteration().await.is_none());
    assert!(h.state_rx.has_changed().unwrap());
    assert!(logged(
        &h.state_rx.borrow(),
        "a line only this iteration wrote"
    ));
}

#[tokio::test]
async fn a_listener_connecting_is_tracked_and_a_drop_untracked() {
    let (mut rt, _h) = runtime().await;
    rt.on_listener_event(Ok(didcomm::ListenerStatus::Connected {
        listener_id: "listener-a".into(),
    }))
    .await;
    assert!(rt.state.connection.online_listeners.contains("listener-a"));
    rt.on_listener_event(Ok(didcomm::ListenerStatus::Disconnected {
        listener_id: "listener-a".into(),
        error: None,
    }))
    .await;
    assert!(!rt.state.connection.online_listeners.contains("listener-a"));
}

#[tokio::test]
async fn a_lifecycle_event_reaches_the_activity_log() {
    let (mut rt, _h) = runtime().await;
    let before = rt.state.main_page.activity_log.len();
    rt.on_lifecycle_log(didcomm::LifecycleLog::Connected {
        listener_id: "listener-b".into(),
    })
    .await;
    assert_eq!(rt.state.main_page.activity_log.len(), before + 1);
}

#[tokio::test]
async fn a_failed_save_is_said_and_left_dirty() {
    let (mut rt, _h) = runtime().await;
    rt.on_save_done(Err("disk full".into())).await;
    assert!(logged(&rt.state, "Failed to save config"));
}

#[tokio::test]
async fn a_dispatch_outcome_frees_its_domain() {
    let (mut rt, _h) = runtime().await;
    let domain = background_dispatch::DispatchDomain::AgentName;
    assert!(rt.in_flight.try_begin(domain));
    rt.on_dispatch_outcome(background_dispatch::DispatchOutcome::AgentName(Vec::new()))
        .await;
    assert!(!rt.in_flight.is_busy(domain));
}

#[tokio::test]
async fn a_vta_sync_tick_without_a_session_starts_nothing() {
    let (mut rt, _h) = runtime().await;
    assert!(!rt.on_vta_sync_tick().await, "quiet: nothing started");
    assert!(rt.vta_sync_rx.try_recv().is_err());
}

#[tokio::test]
async fn a_pong_is_timed_against_the_ping_and_closes_it() {
    let (mut rt, _h) = runtime().await;
    rt.ping_sent_at = Some(ago(1));
    rt.on_inbound(
        didcomm::DIDCommEvent::TrustPongReceived {
            from: Some("did:example:peer".into()),
        },
        None,
    )
    .await;
    assert!(rt.ping_sent_at.is_none());
    let status = rt
        .state
        .main_page
        .content_panel
        .relationships
        .status_message
        .as_ref()
        .expect("the pong is reported where the ping was sent");
    assert!(status.text.contains("reachable"));
}

#[tokio::test]
async fn an_unanswered_ping_runs_out_its_reply_window() {
    let (mut rt, _h) = runtime().await;
    rt.ping_sent_at = Some(ago(super::super::PING_REPLY_WINDOW.as_secs() + 1));
    rt.on_capabilities_sweep().await;
    assert!(rt.ping_sent_at.is_none());
    assert!(logged(&rt.state, "No reply to the ping"));
}

#[tokio::test]
async fn an_unanswered_capability_query_fails_closed() {
    let (mut rt, _h) = runtime().await;
    let mut view = CapabilitiesView::new(
        "did:example:vtc".into(),
        openvtc_core::config::account::PersonaId::new(),
        "A community".into(),
    );
    view.pending_thid = Some("thid-1".into());
    view.sent_at = Some(ago(31));
    rt.state.main_page.content_panel.capabilities.view = Some(view);
    rt.on_capabilities_sweep().await;
    let view = rt
        .state
        .main_page
        .content_panel
        .capabilities
        .view
        .as_ref()
        .unwrap();
    assert!(view.pending_thid.is_none());
    assert!(matches!(view.phase, CapabilitiesPhase::Failed(_)));
}

#[tokio::test]
async fn the_pending_expiry_sweep_over_an_empty_account_changes_nothing() {
    let (mut rt, _h) = runtime().await;
    rt.on_pending_expiry().await;
    assert!(
        !rt.save.needs_flush(),
        "nothing changed, so nothing to save"
    );
}

/// The join does not park the loop: with its screen up, the other arms still
/// run, and its actions are the join's (#529).
#[tokio::test]
async fn an_open_join_leaves_the_other_arms_running() {
    let (mut rt, _h) = runtime().await;
    assert!(matches!(
        rt.on_action(Action::StartJoin).await,
        Flow::Continue
    ));
    assert!(rt.end_of_iteration().await.is_none());
    assert!(rt.join.is_active());
    assert!(matches!(rt.state.active_page, state::ActivePage::Join));

    let domain = background_dispatch::DispatchDomain::AgentName;
    assert!(rt.in_flight.try_begin(domain));
    rt.on_dispatch_outcome(background_dispatch::DispatchOutcome::AgentName(Vec::new()))
        .await;
    assert!(!rt.in_flight.is_busy(domain), "another arm ran mid-join");

    assert!(matches!(
        rt.on_action(Action::JoinCancel).await,
        Flow::Continue
    ));
    assert!(!rt.join.is_active());
    assert!(matches!(rt.state.active_page, state::ActivePage::Main));
}

#[tokio::test]
async fn an_interrupt_with_a_join_open_stops_the_loop() {
    let (mut rt, h) = runtime().await;
    rt.on_action(Action::StartJoin).await;
    rt.end_of_iteration().await;
    assert!(rt.join.is_active());
    h.interrupt_tx.send(Interrupted::UserInt).unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(10), rt.run())
        .await
        .expect("the loop stops on an interrupt with a join open")
        .expect("the loop returns its outcome");
    assert!(matches!(outcome, Interrupted::UserInt));
}

#[tokio::test]
async fn f10_on_a_join_page_stops_the_loop_and_tells_the_terminator() {
    let (mut rt, mut h) = runtime().await;
    rt.on_action(Action::StartJoin).await;
    rt.end_of_iteration().await;
    assert!(matches!(
        rt.on_action(Action::Exit).await,
        Flow::Exit(Interrupted::UserInt)
    ));
    assert!(matches!(
        h.interrupt_seen.try_recv(),
        Ok(Interrupted::UserInt)
    ));
}
