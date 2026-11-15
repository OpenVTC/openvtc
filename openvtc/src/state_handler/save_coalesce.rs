//! Coalesced, off-runtime `Config` persistence (R11).
//!
//! # The problem
//!
//! [`openvtc_core::config::Config::save`] is fully synchronous and expensive:
//! per call it clones the protected tier, serializes + AES-GCM encrypts both the
//! public/protected and secured tiers, writes + `chmod`s files, performs an OS
//! **keyring** `Entry::set_secret` syscall, and — on token-protected profiles —
//! blocking **PC/SC smart-card** I/O. Before R11 every config-mutating site
//! called it inline on the `tokio::select!` event-loop thread: once per
//! config-mutating inbound DIDComm message plus ~15 action sites. A mediator
//! redelivery *burst* therefore ran N sequential keyring+file+card writes,
//! blocking input the whole time.
//!
//! # The mechanism
//!
//! This module factors out a small, testable scheduler that the runtime loop
//! drives. It has three pieces of state — **dirty**, **in-flight**, and a
//! debounce **deadline** — and it preserves the single-mutator invariant: the
//! snapshot is taken on the loop thread (the only place `Config` is mutated) and
//! the actual blocking `save` runs on a `spawn_blocking` thread that owns the
//! snapshot.
//!
//! * Mutation sites call [`SaveScheduler::mark_dirty`] instead of saving inline.
//!   The first dirty mark arms a deadline `DEBOUNCE` in the future.
//! * The loop adds one select arm that waits until the deadline
//!   ([`SaveScheduler::wait_deadline`]). When it fires the loop calls
//!   [`SaveScheduler::take_for_save`]; if a save is dirty *and* not already in
//!   flight, that clears the dirty flag, marks in-flight, and returns a
//!   [`PendingSave`] the loop spawns via `spawn_blocking`.
//! * At most **one** save is in flight at a time. Marks that land while a save
//!   runs simply re-set the dirty flag; on completion ([`SaveScheduler::finish`])
//!   the scheduler re-arms a deadline so exactly one more save is scheduled.
//! * Durability-critical points call [`SaveScheduler::flush`] for a synchronous
//!   (awaited, still off-runtime) drain of any pending dirty state.
//!
//! The save *decision* logic (`mark_dirty` / `take_for_save` / `finish`) is pure
//! over the scheduler's own fields and unit-tested in isolation (see the tests
//! at the bottom and the coalescing/flush tests), following the
//! pure-handler + mini-loop style established by `background_dispatch`.

use std::time::Duration;

use openvtc_core::config::Config;
use openvtc_core::errors::OpenVTCError;
use tokio::time::Instant;

/// Debounce window: mutations within this window of the first dirty mark collapse
/// into a single save. Kept short (≤1 s, per the R11 plan risk row) so the
/// worst-case lost-state window on a crash stays small.
pub(crate) const DEBOUNCE: Duration = Duration::from_millis(750);

/// An owned, `Send + 'static` save request handed to a `spawn_blocking` thread.
///
/// Carries the [`Config`] snapshot (taken on the loop thread) and the profile
/// name. [`PendingSave::run`] performs the blocking `save` and is the *only*
/// place the heavy serialize/encrypt/keyring/card I/O runs — never on the async
/// runtime.
#[derive(Debug)]
pub(crate) struct PendingSave {
    snapshot: Config,
    profile: String,
}

impl PendingSave {
    /// Run the blocking save. Intended to be called inside `spawn_blocking` (or,
    /// on the shutdown force-flush, directly on a blocking context).
    pub(crate) fn run(self) -> Result<(), OpenVTCError> {
        self.snapshot.save(
            &self.profile,
            #[cfg(feature = "openpgp-card")]
            &|| {},
        )
    }
}

/// Coalescing scheduler for `Config::save`. Lives on the loop thread; not `Sync`
/// and never shared — the loop is the single owner/mutator.
pub(crate) struct SaveScheduler {
    profile: String,
    /// Config changed since the last save was *scheduled* and not yet persisted.
    dirty: bool,
    /// A save is currently running on a blocking thread.
    in_flight: bool,
    /// When the pending debounce fires. `None` when nothing is scheduled.
    deadline: Option<Instant>,
}

/// Why [`SaveScheduler::take_for_save`] declined to produce a [`PendingSave`].
/// Exposed for tests; the loop only cares about the `Some`/`None` distinction.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum SkipReason {
    /// Nothing has been marked dirty since the last scheduled save.
    NotDirty,
    /// A save is already running; the dirty flag is left set so `finish` re-arms.
    InFlight,
}

impl SaveScheduler {
    pub(crate) fn new(profile: impl Into<String>) -> Self {
        Self {
            profile: profile.into(),
            dirty: false,
            in_flight: false,
            deadline: None,
        }
    }

    /// Mark the config dirty: a coalesced save is requested. Arms the debounce
    /// deadline if one isn't already pending (so a burst of marks shares one
    /// deadline). Cheap and non-blocking — safe to call on the loop thread for
    /// every mutation.
    pub(crate) fn mark_dirty(&mut self) {
        self.mark_dirty_at(Instant::now());
    }

    /// `mark_dirty` with an injectable clock for tests.
    fn mark_dirty_at(&mut self, now: Instant) {
        self.dirty = true;
        // Arm a deadline only if none is pending. An existing deadline is *not*
        // pushed back by later marks (that would let a steady stream of
        // mutations starve the save indefinitely); the window is anchored to the
        // first mark of the burst.
        if self.deadline.is_none() {
            self.deadline = Some(now + DEBOUNCE);
        }
    }

    /// Whether a save is currently scheduled or running (for status/diagnostics).
    #[cfg(test)]
    pub(crate) fn is_pending(&self) -> bool {
        self.dirty || self.in_flight || self.deadline.is_some()
    }

    /// Whether a backgrounded save is currently running on a blocking thread.
    /// Used by the shutdown path to await an in-flight save before the
    /// force-flush, so the two never run concurrent `Config::save`s.
    pub(crate) fn in_flight(&self) -> bool {
        self.in_flight
    }

    /// A future that resolves when the debounce deadline elapses. Use as a
    /// `tokio::select!` arm: when nothing is scheduled it stays pending forever
    /// (so the arm is effectively disabled), so the loop only wakes for a save
    /// when one is actually due.
    pub(crate) async fn wait_deadline(&self) {
        match self.deadline {
            Some(when) => tokio::time::sleep_until(when).await,
            // Park forever — no save scheduled. The select arm never fires until
            // a future `mark_dirty` arms a deadline and the loop re-enters select.
            None => std::future::pending::<()>().await,
        }
    }

    /// Called when the debounce deadline fires. Decides whether to start a save.
    ///
    /// Returns `Ok(PendingSave)` (clearing dirty + the deadline and marking
    /// in-flight) when a save should start; `Err(SkipReason)` otherwise:
    /// - `NotDirty`: spurious wake, nothing to do.
    /// - `InFlight`: a save is already running; the deadline is cleared but the
    ///   dirty flag is left set so [`finish`](Self::finish) re-arms one more save.
    ///
    /// `snapshot_fn` builds the owned snapshot from the live config on the loop
    /// thread (the single mutator). It can fail (e.g. BIP32 root rebuild); on
    /// failure the dirty flag is *kept* and the deadline re-armed so the save is
    /// retried, and the error is returned to the caller to surface as today.
    pub(crate) fn take_for_save(
        &mut self,
        snapshot_fn: impl FnOnce() -> Result<Config, OpenVTCError>,
    ) -> Result<Result<PendingSave, OpenVTCError>, SkipReason> {
        if self.in_flight {
            // Leave `dirty` set; clear the deadline so the arm stops firing until
            // `finish` re-arms. (Should be rare: the deadline is normally cleared
            // when a save starts.)
            self.deadline = None;
            return Err(SkipReason::InFlight);
        }
        if !self.dirty {
            self.deadline = None;
            return Err(SkipReason::NotDirty);
        }
        // Build the snapshot on the loop thread.
        match snapshot_fn() {
            Ok(snapshot) => {
                self.dirty = false;
                self.deadline = None;
                self.in_flight = true;
                Ok(Ok(PendingSave {
                    snapshot,
                    profile: self.profile.clone(),
                }))
            }
            Err(e) => {
                // Snapshot failed: keep dirty + re-arm so we retry, and surface
                // the error (same as an inline save failure would).
                self.deadline = Some(Instant::now() + DEBOUNCE);
                Ok(Err(e))
            }
        }
    }

    /// Called when a spawned save completes (success *or* failure). Clears the
    /// in-flight flag; if the config was dirtied again while the save ran, re-arms
    /// exactly one more debounce so the latest state is eventually persisted.
    ///
    /// On a save *failure* the caller passes `succeeded = false`: the dirty flag
    /// is re-set and a deadline re-armed so the failed write is retried rather than
    /// silently dropped (the failure is also surfaced as a status/log by the
    /// caller, matching today's behaviour).
    pub(crate) fn finish(&mut self, succeeded: bool) {
        self.in_flight = false;
        if !succeeded {
            // Retry-on-failure: never silently drop a dirty save.
            self.dirty = true;
        }
        if self.dirty && self.deadline.is_none() {
            self.deadline = Some(Instant::now() + DEBOUNCE);
        }
    }

    /// Synchronous force-flush for durability-critical points (shutdown,
    /// passphrase/protection change, export, anything whose correctness depends
    /// on the persisted file being current).
    ///
    /// Builds a snapshot and persists it **now**, off the runtime via
    /// `spawn_blocking`, awaiting completion. This drains any pending dirty state:
    /// after a successful flush, `dirty` is cleared and the deadline disarmed.
    ///
    /// It does not wait for an already in-flight background save (the caller's
    /// mutation may post-date it); flushing unconditionally puts the *current*
    /// live state on disk now. Because that older save may land afterwards,
    /// the config is left dirty while one is in flight, and its `finish`
    /// writes the current state once more.
    ///
    /// # Errors
    ///
    /// Propagates a snapshot or save error so the caller can surface it exactly
    /// as the old inline save did. On error the dirty flag is left set so the
    /// state is retried by the normal debounce path.
    pub(crate) async fn flush(&mut self, config: &Config) -> Result<(), OpenVTCError> {
        let pending = PendingSave {
            snapshot: config.clone_for_save()?,
            profile: self.profile.clone(),
        };
        // Run the blocking save off the runtime and await it.
        let result = tokio::task::spawn_blocking(move || pending.run())
            .await
            .map_err(|e| OpenVTCError::Config(format!("save task panicked: {e}")))?;
        if result.is_ok() {
            self.settle_after_flush();
        }
        result
    }

    /// The bookkeeping after a successful [`flush`](Self::flush). A background
    /// save still in flight holds an *older* snapshot and may land after the
    /// flush, overwriting it; leaving the config dirty makes its
    /// [`finish`](Self::finish) schedule one more save of the current state.
    fn settle_after_flush(&mut self) {
        self.dirty = self.in_flight;
        self.deadline = None;
    }

    /// Build a [`PendingSave`] from the live config without touching the
    /// scheduler's dirty/in-flight state. Used by the shutdown path, which runs a
    /// *direct* blocking save after the loop has broken (no runtime arm left to
    /// schedule against).
    ///
    /// # Errors
    ///
    /// Propagates a snapshot error (e.g. BIP32 root rebuild failure).
    pub(crate) fn snapshot_now(&self, config: &Config) -> Result<PendingSave, OpenVTCError> {
        Ok(PendingSave {
            snapshot: config.clone_for_save()?,
            profile: self.profile.clone(),
        })
    }

    /// Whether anything still needs persisting (dirty or a save in flight). Used
    /// by the shutdown path to decide whether a final flush is needed.
    pub(crate) fn needs_flush(&self) -> bool {
        self.dirty || self.in_flight
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::dispatch_util::test_config;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A burst of N rapid `mark_dirty` calls within the debounce window collapses
    /// into a single save. We drive the scheduler's pure decision logic directly
    /// (no real timers): mark N times, then fire the deadline once and assert
    /// exactly one `PendingSave` is produced — proving ≪N saves for N marks.
    #[tokio::test(start_paused = true)]
    async fn coalesces_burst_into_single_save() {
        let mut sched = SaveScheduler::new("test");
        let saves = Arc::new(AtomicUsize::new(0));

        // Simulate a 5-message inbound burst: 5 dirty marks in quick succession.
        let n = 5;
        for _ in 0..n {
            sched.mark_dirty();
        }
        assert!(sched.is_pending(), "burst should leave a save scheduled");

        // The deadline fires once. Exactly one snapshot/save is produced for the
        // whole burst.
        let saves_in = saves.clone();
        let pending = sched
            .take_for_save(|| {
                saves_in.fetch_add(1, Ordering::SeqCst);
                test_config().clone_for_save()
            })
            .expect("a save should be due after a dirty burst")
            .expect("snapshot should succeed");
        drop(pending);
        // Model the spawned save completing: `take_for_save` marked the domain
        // in-flight, so the loop calls `finish` when the blocking save returns.
        sched.finish(true);

        // A second deadline fire with nothing newly dirty produces no save.
        let skip = sched.take_for_save(|| test_config().clone_for_save());
        assert_eq!(skip.unwrap_err(), SkipReason::NotDirty);

        assert_eq!(
            saves.load(Ordering::SeqCst),
            1,
            "5 dirty marks must coalesce into exactly 1 save (≪N)"
        );
    }

    /// At most one save in flight: while a save is running, the deadline firing
    /// must NOT start a second one. A mark that lands during the in-flight save
    /// is remembered and scheduled by `finish`.
    /// A flush that overlaps a background save must not let the older
    /// snapshot have the last word: the config stays dirty, and the
    /// background save's `finish` schedules a fresh one.
    #[test]
    fn a_flush_during_a_background_save_schedules_another() {
        let mut s = SaveScheduler::new("test");
        s.mark_dirty();
        s.dirty = false;
        s.in_flight = true; // a background save with an older snapshot
        s.settle_after_flush();
        assert!(s.dirty, "the overlapped flush must leave the config dirty");
        s.finish(true);
        assert!(s.deadline.is_some(), "finish must schedule another save");

        let mut idle = SaveScheduler::new("test");
        idle.mark_dirty();
        idle.settle_after_flush();
        assert!(!idle.dirty && idle.deadline.is_none());
    }

    #[test]
    fn at_most_one_in_flight_and_reschedules() {
        let mut sched = SaveScheduler::new("test");

        // First save starts.
        sched.mark_dirty();
        let _pending = sched
            .take_for_save(|| test_config().clone_for_save())
            .expect("first save due")
            .expect("snapshot ok");
        assert!(sched.in_flight());

        // A mutation lands while the save is in flight.
        sched.mark_dirty();
        // The deadline firing now must be rejected — only one save at a time.
        assert_eq!(
            sched
                .take_for_save(|| test_config().clone_for_save())
                .unwrap_err(),
            SkipReason::InFlight
        );

        // The in-flight save completes successfully; because we dirtied again,
        // `finish` re-arms exactly one more save.
        sched.finish(true);
        assert!(!sched.in_flight());
        assert!(
            sched.is_pending(),
            "a save dirtied mid-flight must be re-armed"
        );

        // …and that re-armed save is now takeable.
        let _pending = sched
            .take_for_save(|| test_config().clone_for_save())
            .expect("re-armed save due")
            .expect("snapshot ok");
    }

    /// A failed save is not silently dropped: `finish(false)` re-sets dirty and
    /// re-arms so the write is retried.
    #[test]
    fn failed_save_is_retried_not_dropped() {
        let mut sched = SaveScheduler::new("test");
        sched.mark_dirty();
        let _ = sched
            .take_for_save(|| test_config().clone_for_save())
            .expect("save due")
            .expect("snapshot ok");
        // The save failed.
        sched.finish(false);
        assert!(
            sched.is_pending(),
            "a failed save must leave the config dirty for retry, not drop it"
        );
        // The retry is takeable.
        assert!(
            sched
                .take_for_save(|| test_config().clone_for_save())
                .is_ok()
        );
    }

    /// Shutdown ordering invariant (R11): the runtime teardown awaits an
    /// in-flight background save (draining its completion → `finish`) BEFORE its
    /// force-flush, so the two never run concurrent `Config::save`s against the
    /// same (non-atomic) file/keyring. This asserts the scheduler bookkeeping
    /// that decision relies on.
    #[test]
    fn shutdown_awaits_inflight_then_flushes_only_if_newly_dirty() {
        // Case 1: nothing dirtied while the save ran → after awaiting it, the
        // shutdown force-flush is skipped (no redundant/concurrent save).
        let mut sched = SaveScheduler::new("test");
        sched.mark_dirty();
        let _pending = sched
            .take_for_save(|| test_config().clone_for_save())
            .expect("save due")
            .expect("snapshot ok");
        assert!(
            sched.in_flight(),
            "teardown must observe the in-flight save and await it"
        );
        sched.finish(true);
        assert!(
            !sched.needs_flush(),
            "after the awaited in-flight save, no redundant shutdown save is run"
        );

        // Case 2: a mutation lands while the save is in flight → after awaiting
        // the save, the shutdown force-flush must still persist the newer state
        // (now race-free, since the in-flight save already completed).
        let mut sched = SaveScheduler::new("test");
        sched.mark_dirty();
        let _pending = sched
            .take_for_save(|| test_config().clone_for_save())
            .expect("save due")
            .expect("snapshot ok");
        sched.mark_dirty(); // mutation during the in-flight save
        sched.finish(true);
        assert!(
            sched.needs_flush(),
            "a mutation during the in-flight save must still be flushed at shutdown"
        );
    }

    /// `flush` persists the current state synchronously and clears the dirty flag.
    /// This is the durability backstop for shutdown / settings changes / export.
    #[tokio::test]
    async fn flush_persists_and_clears_dirty() {
        // `test_config` is a BIP32 config whose `save` writes to the *test*
        // profile's keyring/files. Keyring access may be unavailable in CI, so we
        // only assert the scheduler bookkeeping: flush attempts a real save and,
        // on success, clears dirty. If the keyring is unavailable the save errors
        // and dirty stays set (the retry guarantee) — either way the *scheduler*
        // contract holds. We therefore assert the post-state matches the result.
        let config = test_config();
        let mut sched = SaveScheduler::new("openvtc-r11-flush-test");
        sched.mark_dirty();
        assert!(sched.needs_flush());

        match sched.flush(&config).await {
            Ok(()) => assert!(
                !sched.needs_flush(),
                "a successful flush must clear the dirty flag"
            ),
            Err(_) => assert!(
                sched.needs_flush(),
                "a failed flush must leave the config dirty for retry"
            ),
        }
    }

    /// The deadline arm parks forever when nothing is scheduled (so the select
    /// arm is effectively disabled until a `mark_dirty` arms it) and fires once
    /// armed. With paused time we can assert it does not resolve early.
    #[tokio::test(start_paused = true)]
    async fn wait_deadline_parks_until_armed_then_fires() {
        let mut sched = SaveScheduler::new("test");
        // Nothing scheduled: the deadline future must not resolve.
        tokio::select! {
            biased;
            _ = sched.wait_deadline() => panic!("deadline fired with nothing scheduled"),
            _ = tokio::time::sleep(Duration::from_secs(10)) => {}
        }

        // Arm it; now it fires after DEBOUNCE.
        sched.mark_dirty();
        let start = Instant::now();
        sched.wait_deadline().await;
        assert!(
            start.elapsed() >= DEBOUNCE,
            "deadline must wait the full debounce window"
        );
    }
}
