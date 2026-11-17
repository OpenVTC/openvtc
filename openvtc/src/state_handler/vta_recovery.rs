//! Rebuilding the always-on admin VTA session when its replies stop arriving.
//!
//! A session whose mediator inbox is not being collected still *sends*: every
//! request reaches the VTA, the VTA answers, and each answer waits in an inbox
//! nobody reads until the mediator's per-peer cap refuses the rest. On
//! 2026-10-05 two admin sessions sat in that state for an hour and nothing in
//! OpenVTC noticed. The state is now counted — reply timeouts in a row on the
//! admin session, [`openvtc_core::vta_receive_leg`] — and the remedy is the one
//! this module drives: a *fresh* session, whose connect re-registers for live
//! delivery and drains the inbox. Retrying on the old one only queues another
//! reply.
//!
//! [`AdminVtaRecovery`] is the decision, kept free of I/O so it is testable:
//! when a rebuild is due (on the capped, jittered schedule of
//! [`RebuildBackoff`], R1.4), that only one runs at a time, and when the
//! schedule resets — once replies are seen again, not merely once a rebuild
//! connects. [`rebuild`] is the I/O, bounded by timeouts (R1.2). The state
//! handler loop owns both, and swaps the rebuilt client into every holder.

use super::main_page::MainPageState;
use super::main_page::content::{VtaReceiveStatus, VtaRecoveryView};
use openvtc_core::config::RuntimeVtaConnect;
use openvtc_core::vta_receive::{RebuildBackoff, replies_not_arriving_text, short_duration};
use openvtc_core::vta_receive_leg::{ReceiveHealth, ReceiveLegTracker};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::watch;
use tracing::{info, warn};
use vta_sdk::client::VtaClient;

/// How often the loop reads the admin session's receive health. The read is a
/// lock on three fields — no I/O — so this only bounds how stale the panel is and
/// how late a due rebuild starts.
pub(crate) const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// Ceiling on closing the stalled session before the rebuild (R1.2). A session
/// that has stopped collecting may not close cleanly either; it must not hold
/// the rebuild up.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// Ceiling on opening the fresh session (R1.2). The connect has its own
/// network timeouts; this is the backstop that turns a hang into an error the
/// schedule can back off from.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// Ceiling on the one read sent on the fresh session to see a reply come back.
const PROBE_TIMEOUT: Duration = Duration::from_secs(45);

/// Where recovery is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum RecoveryPhase {
    /// Replies are arriving (or nothing says otherwise).
    #[default]
    Healthy,
    /// Replies stopped; a rebuild is due at `at`.
    Waiting {
        /// When the rebuild is due.
        at: Instant,
    },
    /// A rebuild is running. No second one starts until it lands.
    Rebuilding,
    /// A rebuild connected, and no reply has been seen on the new session yet.
    /// The schedule is not reset until one is: a session that connects and
    /// stalls again is still failing.
    Reconnected,
}

/// A change worth telling the operator about. Returned by the methods that
/// cause one, so the loop logs each transition once rather than every check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Transition {
    /// Replies stopped; a rebuild is scheduled `in_` from now.
    Stalled {
        /// Reply timeouts in a row when it was noticed.
        consecutive_timeouts: u32,
        /// Delay until the rebuild.
        in_: Duration,
        /// Which rebuild this will be since replies last arrived (1-based).
        attempt: u32,
    },
    /// Replies are arriving again — on a rebuilt session, or on the old one.
    Recovered,
    /// A rebuild failed; the next is `in_` from now.
    RebuildFailed {
        /// Why.
        error: String,
        /// Delay until the next rebuild.
        in_: Duration,
        /// Which rebuild the next will be (1-based).
        attempt: u32,
    },
    /// A rebuild connected. Not yet [`Transition::Recovered`]: that waits for a
    /// reply on the new session.
    Rebuilt,
}

/// The admin session's recovery state machine. Pure: time and the jitter
/// sample are passed in.
#[derive(Clone, Debug, Default)]
pub(crate) struct AdminVtaRecovery {
    phase: RecoveryPhase,
    backoff: RebuildBackoff,
    /// The last rebuild's failure, for the panel. Cleared on recovery.
    last_error: Option<String>,
}

impl AdminVtaRecovery {
    /// Where recovery is.
    pub(crate) fn phase(&self) -> RecoveryPhase {
        self.phase
    }

    /// Rebuilds scheduled since replies last arrived.
    pub(crate) fn attempt(&self) -> u32 {
        self.backoff.attempt()
    }

    /// The last rebuild's failure, if the most recent one failed.
    pub(crate) fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    /// Read a health snapshot of the *current* admin session.
    ///
    /// Ignored while a rebuild runs: the snapshot is of the session being
    /// replaced.
    pub(crate) fn observe(
        &mut self,
        health: &ReceiveHealth,
        now: Instant,
        unit: f64,
    ) -> Option<Transition> {
        if self.phase == RecoveryPhase::Rebuilding {
            return None;
        }
        if health.replies_not_arriving() {
            return self.stall(health.consecutive_reply_timeouts, now, unit);
        }
        // Any reply resets the count, so a session with no timeouts in
        // a row *and* a reply on record is one whose replies arrive.
        let replying = health.consecutive_reply_timeouts == 0 && health.since_last_reply.is_some();
        match self.phase {
            RecoveryPhase::Reconnected | RecoveryPhase::Waiting { .. } if replying => {
                Some(self.recover())
            }
            _ => None,
        }
    }

    /// Replies stopped: schedule a rebuild, unless one is already scheduled or
    /// running.
    fn stall(&mut self, consecutive_timeouts: u32, now: Instant, unit: f64) -> Option<Transition> {
        match self.phase {
            RecoveryPhase::Healthy | RecoveryPhase::Reconnected => {
                let in_ = self.backoff.next_delay(unit);
                self.phase = RecoveryPhase::Waiting { at: now + in_ };
                Some(Transition::Stalled {
                    consecutive_timeouts,
                    in_,
                    attempt: self.backoff.attempt(),
                })
            }
            RecoveryPhase::Waiting { .. } | RecoveryPhase::Rebuilding => None,
        }
    }

    fn recover(&mut self) -> Transition {
        self.phase = RecoveryPhase::Healthy;
        self.backoff.reset();
        self.last_error = None;
        Transition::Recovered
    }

    /// Whether a rebuild should start now. `true` moves to
    /// [`RecoveryPhase::Rebuilding`], and nothing else returns `true` until
    /// [`finish`](Self::finish) — so two rebuilds never run at once.
    pub(crate) fn try_begin(&mut self, now: Instant) -> bool {
        match self.phase {
            RecoveryPhase::Waiting { at } if now >= at => {
                self.phase = RecoveryPhase::Rebuilding;
                true
            }
            _ => false,
        }
    }

    /// A rebuild landed.
    pub(crate) fn finish(
        &mut self,
        outcome: Result<(), String>,
        now: Instant,
        unit: f64,
    ) -> Transition {
        match outcome {
            Ok(()) => {
                self.phase = RecoveryPhase::Reconnected;
                self.last_error = None;
                Transition::Rebuilt
            }
            Err(error) => {
                let in_ = self.backoff.next_delay(unit);
                self.phase = RecoveryPhase::Waiting { at: now + in_ };
                self.last_error = Some(error.clone());
                Transition::RebuildFailed {
                    error,
                    in_,
                    attempt: self.backoff.attempt(),
                }
            }
        }
    }
}

/// Close the stalled session and open a fresh one.
///
/// The old session is closed *first*: a second session for the same DID would
/// fight it for the mediator's one live stream. Every step is bounded (R1.2).
/// Once connected, `receive` starts counting afresh for the new session and one
/// read-only call is sent so a reply has the chance to come back and close
/// recovery; its result only matters through that count.
pub(crate) async fn rebuild(
    old: Option<VtaClient>,
    connect: &RuntimeVtaConnect,
    receive: &ReceiveLegTracker,
) -> Result<VtaClient, String> {
    if let Some(old) = old
        && tokio::time::timeout(SHUTDOWN_TIMEOUT, old.shutdown())
            .await
            .is_err()
    {
        warn!(
            "closing the stalled admin VTA session took longer than {}s; opening the new one \
             anyway",
            SHUTDOWN_TIMEOUT.as_secs()
        );
    }
    let client = match tokio::time::timeout(CONNECT_TIMEOUT, connect.connect()).await {
        Ok(Ok(client)) => client,
        Ok(Err(e)) => return Err(e.to_string()),
        Err(_) => {
            return Err(format!(
                "opening a new VTA session did not finish within {}s",
                CONNECT_TIMEOUT.as_secs()
            ));
        }
    };
    receive.reset();
    match tokio::time::timeout(PROBE_TIMEOUT, async {
        receive.observe(client.list_contexts().await)
    })
    .await
    {
        Ok(Ok(_)) => info!("the rebuilt admin VTA session is receiving replies"),
        Ok(Err(e)) => warn!("the rebuilt admin VTA session's first request failed: {e}"),
        Err(_) => warn!(
            "the rebuilt admin VTA session's first request had no reply within {}s",
            PROBE_TIMEOUT.as_secs()
        ),
    }
    Ok(client)
}

/// What a rebuild sends back to the loop: the fresh client, or why not.
pub(crate) type RebuildOutcome = Result<VtaClient, String>;

/// Everything the state-handler loops need to watch and recover the admin
/// session, owned once in `run()` and lent to whichever loop is running — the
/// State-A degraded loop first, then the runtime loop — so a rebuild that
/// starts in one lands in the other rather than being lost at the hand-off.
pub(crate) struct AdminVtaSupervisor {
    recovery: AdminVtaRecovery,
    /// The admin session's receive leg, fed by every wrapped call on it.
    receive: ReceiveLegTracker,
    /// `None` for a local-key account: nothing to rebuild.
    connect: Option<Arc<RuntimeVtaConnect>>,
    /// Long-lived holders of the session (the device-presence task) follow it
    /// through this; `None` when nothing was spawned.
    watch: Option<watch::Sender<VtaClient>>,
    /// The health check's timer.
    pub(crate) tick: tokio::time::Interval,
    done_tx: UnboundedSender<RebuildOutcome>,
    /// Where a rebuild's outcome lands; the loop hands it to [`land`](Self::land).
    pub(crate) done_rx: UnboundedReceiver<RebuildOutcome>,
}

impl AdminVtaSupervisor {
    /// `receive` is the admin session's receive leg, already shared with the
    /// session's other observers (the device-presence task).
    pub(crate) fn new(
        connect: Option<RuntimeVtaConnect>,
        watch: Option<watch::Sender<VtaClient>>,
        receive: ReceiveLegTracker,
    ) -> Self {
        let mut tick = tokio::time::interval(HEALTH_CHECK_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let (done_tx, done_rx) = tokio::sync::mpsc::unbounded_channel();
        Self {
            recovery: AdminVtaRecovery::default(),
            receive,
            connect: connect.map(Arc::new),
            watch,
            tick,
            done_tx,
            done_rx,
        }
    }

    /// The admin session's receive leg, for a caller to count its calls on
    /// ([`ReceiveLegTracker::observe`]). It follows the session across rebuilds.
    pub(crate) fn receive(&self) -> &ReceiveLegTracker {
        &self.receive
    }

    /// One health check of the admin session, run from the loop's tick (and
    /// when a caller reports the session failing): record the snapshot for the
    /// panel, feed it to the recovery state machine, and — when a rebuild is due
    /// and none is running — spawn one, whose outcome comes back on
    /// [`done_rx`](Self::done_rx).
    pub(crate) fn check(&mut self, client: Option<&VtaClient>, main_page: &mut MainPageState) {
        let Some(client) = client else { return };
        let now = Instant::now();
        let health = self.receive.health_at(now);
        {
            let view = &mut main_page.content_panel.vta.receive;
            view.health = Some(health.clone());
            view.observed_at = Some(now);
        }
        if let Some(t) = self.recovery.observe(&health, now, rand::random::<f64>()) {
            announce(main_page, &t);
        }
        if let Some(connect) = self.connect.as_ref()
            && self.recovery.try_begin(now)
        {
            info!(
                attempt = self.recovery.attempt(),
                "rebuilding the admin VTA session: its replies are not arriving"
            );
            let old = client.clone();
            let connect = Arc::clone(connect);
            let receive = self.receive.clone();
            let done = self.done_tx.clone();
            tokio::spawn(async move {
                let outcome = rebuild(Some(old), &connect, &receive).await;
                // The loops have exited: nobody will own this session, so close
                // it rather than leak a second connection for this DID.
                if let Err(tokio::sync::mpsc::error::SendError(Ok(orphan))) = done.send(outcome) {
                    orphan.shutdown().await;
                }
            });
        }
        sync_view(&self.recovery, &mut main_page.content_panel.vta.receive);
    }

    /// A rebuild landed. Records it, publishes a new client to the long-lived
    /// holders, and returns it for the caller to put in place of its
    /// `admin_vta` — the one every later operation borrows or clones from.
    pub(crate) fn land(
        &mut self,
        outcome: RebuildOutcome,
        main_page: &mut MainPageState,
    ) -> Option<VtaClient> {
        let client = land(&mut self.recovery, outcome, &self.receive, main_page)?;
        if let Some(watch) = self.watch.as_ref() {
            watch.send_replace(client.clone());
        }
        Some(client)
    }
}

/// A rebuild landed: record it, and return the client to swap in, if any.
///
/// The caller replaces its `admin_vta` with the returned client and publishes it
/// to every long-lived holder (the device-presence task's watch).
fn land(
    recovery: &mut AdminVtaRecovery,
    outcome: RebuildOutcome,
    receive: &ReceiveLegTracker,
    main_page: &mut MainPageState,
) -> Option<VtaClient> {
    let now = Instant::now();
    let (transition, client) = match outcome {
        Ok(client) => (
            recovery.finish(Ok(()), now, rand::random::<f64>()),
            Some(client),
        ),
        Err(e) => (recovery.finish(Err(e), now, rand::random::<f64>()), None),
    };
    announce(main_page, &transition);
    let view = &mut main_page.content_panel.vta.receive;
    if client.is_some() {
        // Fresh session, fresh counters: show the new session's health, not the
        // stalled one's.
        view.health = Some(receive.health_at(now));
        view.observed_at = Some(now);
    }
    sync_view(recovery, view);
    client
}

/// Copy the recovery state into the panel's view.
pub(crate) fn sync_view(recovery: &AdminVtaRecovery, view: &mut VtaReceiveStatus) {
    view.recovery = match recovery.phase() {
        RecoveryPhase::Healthy => VtaRecoveryView::Healthy,
        RecoveryPhase::Waiting { at } => VtaRecoveryView::Waiting {
            at,
            attempt: recovery.attempt(),
        },
        RecoveryPhase::Rebuilding => VtaRecoveryView::Reconnecting {
            attempt: recovery.attempt(),
        },
        RecoveryPhase::Reconnected => VtaRecoveryView::Reconnected,
    };
    view.last_rebuild_error = recovery.last_error().map(str::to_owned);
}

/// Log a transition once — WARN for the failures, INFO for the recoveries — and
/// put it in the activity log.
fn announce(main_page: &mut MainPageState, t: &Transition) {
    match t {
        Transition::Stalled {
            consecutive_timeouts,
            in_,
            attempt,
        } => {
            warn!(
                consecutive_timeouts,
                attempt,
                "the VTA's replies are not reaching this app (its mediator inbox is not being \
                 collected); rebuilding the admin session in {}",
                short_duration(*in_)
            );
            main_page.log(format!(
                "WARNING: {}",
                replies_not_arriving_text(*consecutive_timeouts)
            ));
        }
        Transition::RebuildFailed {
            error,
            in_,
            attempt,
        } => {
            warn!(
                attempt,
                "rebuilding the admin VTA session failed: {error}; next try in {}",
                short_duration(*in_)
            );
            main_page.log(format!(
                "Reconnecting to your VTA failed: {error} — trying again in {}",
                short_duration(*in_)
            ));
        }
        Transition::Rebuilt => {
            info!("the admin VTA session was rebuilt");
            main_page.log("Reconnected to your VTA with a fresh session");
        }
        Transition::Recovered => {
            info!("the VTA's replies are reaching this app again");
            main_page.log("Replies from your VTA are arriving again");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stalled(n: u32) -> ReceiveHealth {
        ReceiveHealth {
            consecutive_reply_timeouts: n,
            since_last_reply: Some(Duration::from_secs(600)),
            since_last_timeout: Some(Duration::from_secs(1)),
        }
    }

    fn replying() -> ReceiveHealth {
        ReceiveHealth {
            since_last_reply: Some(Duration::from_secs(1)),
            ..ReceiveHealth::default()
        }
    }

    #[test]
    fn a_healthy_session_is_left_alone() {
        let mut r = AdminVtaRecovery::default();
        let now = Instant::now();
        assert_eq!(r.observe(&replying(), now, 0.5), None);
        assert_eq!(r.observe(&ReceiveHealth::default(), now, 0.5), None);
        // One timeout is below the breaker: the SDK's own self-repair's turn.
        assert_eq!(r.observe(&stalled(1), now, 0.5), None);
        assert!(!r.try_begin(now + Duration::from_secs(3600)));
        assert_eq!(r.phase(), RecoveryPhase::Healthy);
    }

    /// The reply-timeout errors themselves, counted on the leg, trigger the
    /// rebuild: two in a row is "replies not arriving".
    #[test]
    fn reply_timeout_errors_trigger_a_rebuild_after_the_first_backoff() {
        let mut r = AdminVtaRecovery::default();
        let now = Instant::now();
        let leg = ReceiveLegTracker::new();
        for _ in 0..openvtc_core::vta_receive_leg::REPLY_TIMEOUT_BREAKER {
            let _ = leg.observe::<()>(Err(vta_sdk::error::VtaError::TspTransport(
                "timed out waiting for the TSP reply to request 'urn:uuid:1'".into(),
            )));
        }
        let health = leg.health_at(now);
        assert!(health.replies_not_arriving());
        assert_eq!(
            r.observe(&health, now, 0.5),
            Some(Transition::Stalled {
                consecutive_timeouts: 2,
                in_: Duration::from_secs(5),
                attempt: 1,
            })
        );
        assert!(
            !r.try_begin(now + Duration::from_secs(4)),
            "not before the backoff"
        );
        assert!(r.try_begin(now + Duration::from_secs(5)));
        assert_eq!(r.phase(), RecoveryPhase::Rebuilding);
    }

    /// A reply timeout below the breaker is the SDK's own self-repair's turn
    /// (re-form the relationship, resend once), not a reason to rebuild.
    #[test]
    fn a_timeout_below_the_breaker_does_not_trigger_a_rebuild() {
        let mut r = AdminVtaRecovery::default();
        let now = Instant::now();
        let health = stalled(openvtc_core::vta_receive_leg::REPLY_TIMEOUT_BREAKER - 1);
        assert!(!health.replies_not_arriving());
        assert_eq!(r.observe(&health, now, 0.5), None);
        assert!(!r.try_begin(now + Duration::from_secs(3600)));
    }

    /// A landed rebuild hands back the new client for the loop to swap in; a
    /// failed one hands back nothing and leaves the panel saying why.
    #[tokio::test]
    async fn a_landed_rebuild_returns_the_client_to_swap_in() {
        let mut r = AdminVtaRecovery::default();
        let mut page = MainPageState::default();
        let now = Instant::now();
        r.observe(&stalled(2), now, 0.5);
        assert!(r.try_begin(now + Duration::from_secs(5)));

        let leg = ReceiveLegTracker::new();
        assert!(land(&mut r, Err("mediator down".into()), &leg, &mut page).is_none());
        let view = &page.content_panel.vta.receive;
        assert!(matches!(
            view.recovery,
            VtaRecoveryView::Waiting { attempt: 2, .. }
        ));
        assert_eq!(view.last_rebuild_error.as_deref(), Some("mediator down"));

        assert!(r.try_begin(Instant::now() + Duration::from_secs(60)));
        let fresh = VtaClient::new("https://vta.example");
        assert!(land(&mut r, Ok(fresh), &leg, &mut page).is_some());
        let view = &page.content_panel.vta.receive;
        assert_eq!(view.recovery, VtaRecoveryView::Reconnected);
        assert_eq!(view.last_rebuild_error, None);
        assert_eq!(
            view.health.as_ref().map(|h| h.consecutive_reply_timeouts),
            Some(0),
            "the panel shows the fresh session's counters"
        );
        assert!(
            page.activity_log
                .iter()
                .any(|e| e.summary.contains("Reconnected to your VTA")),
        );
    }

    #[test]
    fn a_rebuild_is_never_started_twice_concurrently() {
        let mut r = AdminVtaRecovery::default();
        let now = Instant::now();
        r.observe(&stalled(2), now, 0.5);
        let later = now + Duration::from_secs(10);
        assert!(r.try_begin(later));
        // While it runs: more stalls, more checks, a reply on the old session —
        // none starts a second rebuild or reschedules.
        assert_eq!(r.observe(&stalled(5), later, 0.5), None);
        assert_eq!(r.observe(&replying(), later, 0.5), None);
        for s in 0..1000 {
            assert!(!r.try_begin(later + Duration::from_secs(s)));
        }
        assert_eq!(r.phase(), RecoveryPhase::Rebuilding);
    }

    #[test]
    fn a_stall_already_scheduled_is_not_rescheduled() {
        let mut r = AdminVtaRecovery::default();
        let now = Instant::now();
        r.observe(&stalled(2), now, 0.5);
        assert_eq!(
            r.observe(&stalled(3), now + Duration::from_secs(1), 0.5),
            None
        );
        assert_eq!(r.attempt(), 1, "one stall, one scheduled rebuild");
    }

    #[test]
    fn failed_rebuilds_back_off_and_success_resets_only_on_a_reply() {
        let mut r = AdminVtaRecovery::default();
        let mut now = Instant::now();
        r.observe(&stalled(2), now, 0.5);

        // Three failures: 10 s, 20 s, 40 s after the first 5 s.
        for expected in [10, 20, 40] {
            now += Duration::from_secs(300);
            assert!(r.try_begin(now));
            match r.finish(Err("mediator down".into()), now, 0.5) {
                Transition::RebuildFailed { in_, .. } => {
                    assert_eq!(in_, Duration::from_secs(expected));
                }
                other => panic!("{other:?}"),
            }
            assert_eq!(r.last_error(), Some("mediator down"));
            assert!(!r.try_begin(now + Duration::from_secs(expected - 1)));
        }

        // A rebuild that connects is not yet a recovery…
        now += Duration::from_secs(300);
        assert!(r.try_begin(now));
        assert_eq!(r.finish(Ok(()), now, 0.5), Transition::Rebuilt);
        assert_eq!(r.phase(), RecoveryPhase::Reconnected);
        assert_eq!(r.attempt(), 4, "the schedule holds until a reply is seen");

        // …and if the new session stalls too, the backoff carries on (80 s),
        // rather than restarting at 5 s and rebuilding in a tight loop.
        match r.observe(&stalled(2), now, 0.5) {
            Some(Transition::Stalled { in_, attempt, .. }) => {
                assert_eq!(in_, Duration::from_secs(80));
                assert_eq!(attempt, 5);
            }
            other => panic!("{other:?}"),
        }

        // A reply on the rebuilt session resets it.
        now += Duration::from_secs(300);
        assert!(r.try_begin(now));
        r.finish(Ok(()), now, 0.5);
        assert_eq!(
            r.observe(&replying(), now, 0.5),
            Some(Transition::Recovered)
        );
        assert_eq!(r.phase(), RecoveryPhase::Healthy);
        assert_eq!(r.attempt(), 0);
        assert_eq!(r.last_error(), None);
        match r.observe(&stalled(2), now, 0.5) {
            Some(Transition::Stalled { in_, .. }) => assert_eq!(in_, Duration::from_secs(5)),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn replies_returning_before_the_rebuild_cancel_it() {
        let mut r = AdminVtaRecovery::default();
        let now = Instant::now();
        r.observe(&stalled(2), now, 0.5);
        assert_eq!(
            r.observe(&replying(), now, 0.5),
            Some(Transition::Recovered)
        );
        assert!(!r.try_begin(now + Duration::from_secs(3600)));
    }
}
