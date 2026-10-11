//! When the runtime loop syncs account state with the VTA
//! ([`openvtc_core::vta_sync`]).
//!
//! A cycle — pull, merge, push — is asked for after every completed save, so a
//! change made here reaches the VTA within seconds, and on a timer, so a
//! change made on another device arrives without one being made here. At most
//! one cycle runs at a time, and cycles are spaced so a burst of saves shares
//! one.
//!
//! Failures back off (R1.4): an unreachable VTA is retried on a doubling
//! interval up to a ceiling, and said once rather than on every retry. A VTA
//! that does not offer the store, or refuses this account, is not retried this
//! session — neither changes by waiting.
//!
//! The decision logic is pure over its own fields, like `save_coalesce`, so it
//! is unit-tested without a loop.

use std::time::Duration;

use openvtc_core::vta_sync::SyncError;
use tokio::time::Instant;

/// The least time between the end of one cycle and the start of the next, so
/// a burst of saves shares one cycle.
const MIN_GAP: Duration = Duration::from_secs(5);

/// How often to pull when nothing here has changed.
const PULL_EVERY: Duration = Duration::from_secs(60);

/// First retry delay after a transient failure; doubles per failure.
const BACKOFF_START: Duration = Duration::from_secs(30);

/// The longest retry delay.
const BACKOFF_MAX: Duration = Duration::from_secs(600);

/// How often the loop asks [`SyncDriver::should_start`].
pub(crate) const TICK: Duration = Duration::from_secs(2);

pub(crate) struct SyncDriver {
    in_flight: bool,
    /// Off for the rest of the session.
    disabled: bool,
    /// A cycle has been asked for and not yet started.
    wanted: bool,
    /// The earliest the next cycle may start.
    not_before: Instant,
    /// When the next timed pull is due.
    next_pull: Instant,
    /// Consecutive failed cycles.
    failures: u32,
}

impl SyncDriver {
    /// A driver whose first timed pull is one period away — the load has just
    /// synced.
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            in_flight: false,
            disabled: false,
            wanted: false,
            not_before: now,
            next_pull: now + PULL_EVERY,
            failures: 0,
        }
    }

    /// Ask for a cycle: something here changed.
    pub(crate) fn request(&mut self) {
        self.wanted = true;
    }

    /// Whether to start a cycle now. When this answers `true` the caller must
    /// start one and later call [`Self::finished`].
    pub(crate) fn should_start(&mut self, now: Instant) -> bool {
        if self.disabled || self.in_flight || now < self.not_before {
            return false;
        }
        if now >= self.next_pull {
            self.wanted = true;
        }
        if !self.wanted {
            return false;
        }
        self.in_flight = true;
        self.wanted = false;
        self.next_pull = now + PULL_EVERY;
        true
    }

    /// A cycle ended. Returns whether its error is worth telling the user —
    /// the first of a run of transient failures, or any permanent one.
    pub(crate) fn finished(&mut self, now: Instant, error: Option<&SyncError>) -> bool {
        self.in_flight = false;
        match error {
            None => {
                self.failures = 0;
                self.not_before = now + MIN_GAP;
                false
            }
            Some(e) if e.is_transient() => {
                self.failures += 1;
                let backoff = BACKOFF_START
                    .saturating_mul(1 << (self.failures - 1).min(8))
                    .min(BACKOFF_MAX);
                self.not_before = now + backoff;
                // Whatever this cycle was carrying still needs to go up.
                self.wanted = true;
                self.failures == 1
            }
            Some(SyncError::Contract(_)) => {
                // Possibly one odd record or answer; try again, slowly.
                self.failures += 1;
                self.not_before = now + BACKOFF_MAX;
                self.failures == 1
            }
            Some(_) => {
                self.disabled = true;
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_save_starts_a_cycle_and_a_burst_shares_it() {
        let t0 = Instant::now();
        let mut d = SyncDriver::new(t0);
        assert!(!d.should_start(t0), "nothing asked for");
        d.request();
        assert!(d.should_start(t0));
        d.request();
        assert!(!d.should_start(t0), "one at a time");
        assert!(!d.finished(t0, None));
        assert!(!d.should_start(t0 + Duration::from_secs(1)), "spaced");
        assert!(d.should_start(t0 + MIN_GAP));
    }

    #[test]
    fn a_quiet_session_still_pulls_on_the_timer() {
        let t0 = Instant::now();
        let mut d = SyncDriver::new(t0);
        assert!(!d.should_start(t0 + Duration::from_secs(30)));
        assert!(d.should_start(t0 + PULL_EVERY));
    }

    #[test]
    fn an_unreachable_vta_backs_off_and_is_reported_once() {
        let t0 = Instant::now();
        let mut d = SyncDriver::new(t0);
        let down = SyncError::Unreachable("down".into());
        d.request();
        assert!(d.should_start(t0));
        assert!(d.finished(t0, Some(&down)), "first failure is said");
        assert!(!d.should_start(t0 + Duration::from_secs(29)));
        let t1 = t0 + BACKOFF_START;
        assert!(d.should_start(t1), "retried, carrying the pending push");
        assert!(!d.finished(t1, Some(&down)), "not said again");
        assert!(!d.should_start(t1 + BACKOFF_START), "doubled");
        assert!(d.should_start(t1 + BACKOFF_START * 2));
    }

    #[test]
    fn a_vta_without_the_store_stops_the_session_sync() {
        let t0 = Instant::now();
        let mut d = SyncDriver::new(t0);
        d.request();
        assert!(d.should_start(t0));
        assert!(d.finished(t0, Some(&SyncError::Unsupported)));
        d.request();
        assert!(!d.should_start(t0 + BACKOFF_MAX * 2));
    }
}
