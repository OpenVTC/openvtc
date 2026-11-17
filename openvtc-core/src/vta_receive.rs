//! Whether the VTA's replies are reaching this app — the receive leg of the
//! admin VTA session — in words, and how long to wait between rebuilds of a
//! session whose replies have stopped.
//!
//! A send that succeeds says nothing about the receive leg: the request reached
//! the mediator, and the VTA answered it, but the answer waits in this app's
//! mediator inbox until the session collects it. A session that has stopped
//! collecting (observed 2026-10-05: two admin sessions, an hour, every VTA reply
//! refused once the mediator's per-peer queue filled) looks exactly like a VTA
//! that never answers — and retrying only queues another reply. The state is
//! detected by [`crate::vta_receive_leg`]; this module is where OpenVTC turns
//! it into words and a schedule.
//!
//! - [`replies_not_arriving_text`] is the one sentence for it (R6.4): neither
//!   "VTA unreachable" nor an auth failure, because it is neither.
//! - [`RebuildBackoff`] is the bounded, jittered schedule the runtime rebuilds
//!   the session on (R1.4).

use crate::vta_receive_leg::ReceiveHealth;
use std::time::Duration;

/// The state, without what is being done about it: the request *did* reach the
/// VTA (so it is not unreachable), and what is missing is the way back (so it is
/// not an auth or contract problem).
#[must_use]
pub fn replies_not_arriving_summary(consecutive_timeouts: u32) -> String {
    format!(
        "Your VTA received the request, but its replies aren't reaching this app — its \
         message inbox isn't being collected ({consecutive_timeouts} replies missed in a \
         row)."
    )
}

/// What the operator is told when replies have stopped arriving on the admin
/// session: [`replies_not_arriving_summary`], and that the app is already doing
/// the one thing that helps — rebuilding the session — so a retry by hand is not
/// needed.
#[must_use]
pub fn replies_not_arriving_text(consecutive_timeouts: u32) -> String {
    format!(
        "{} Reconnecting…",
        replies_not_arriving_summary(consecutive_timeouts)
    )
}

/// A short, human reading of a receive-leg health snapshot for a status line,
/// e.g. `last reply 12s ago` or `no reply for 4m 10s (3 missed in a row)`.
#[must_use]
pub fn describe_health(health: &ReceiveHealth) -> String {
    let last = match health.since_last_reply {
        Some(age) => format!("last reply {} ago", short_duration(age)),
        None => "no reply yet this session".to_string(),
    };
    match health.consecutive_reply_timeouts {
        0 => last,
        1 => format!("{last} (1 reply missed)"),
        n => format!("{last} ({n} missed in a row)"),
    }
}

/// `75s` → `1m 15s`; whole hours past that. Second precision only — this is
/// read by a person, not compared.
#[must_use]
pub fn short_duration(d: Duration) -> String {
    let s = d.as_secs();
    match s {
        0..=59 => format!("{s}s"),
        60..=3599 => format!("{}m {}s", s / 60, s % 60),
        _ => format!("{}h {}m", s / 3600, (s % 3600) / 60),
    }
}

/// First wait before rebuilding a session whose replies stopped.
pub const REBUILD_BACKOFF_BASE: Duration = Duration::from_secs(5);

/// Longest wait between rebuilds, however many have failed.
pub const REBUILD_BACKOFF_CAP: Duration = Duration::from_secs(300);

/// Jitter, as a fraction of the nominal delay either side of it. Two installs
/// sharing a mediator that stalled together must not rebuild in lock-step.
pub const REBUILD_BACKOFF_JITTER: f64 = 0.2;

/// Capped, jittered exponential backoff between session rebuilds (R1.4).
///
/// Nominal delays double from [`REBUILD_BACKOFF_BASE`] to [`REBUILD_BACKOFF_CAP`]
/// (5 s, 10 s, 20 s, … 5 min, 5 min, …); each is then moved by up to
/// ±[`REBUILD_BACKOFF_JITTER`] of itself and clamped to the cap. [`reset`]
/// returns to the base, and is called once replies are arriving again — not
/// merely when a rebuild connects, because a session that connects and then
/// stalls again (another process holding this DID's mediator connection) is
/// still failing and must keep backing off.
///
/// [`reset`]: Self::reset
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RebuildBackoff {
    attempt: u32,
}

impl RebuildBackoff {
    /// Rebuilds scheduled since the last reset.
    #[must_use]
    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    /// The un-jittered delay for attempt `attempt` (0-based).
    #[must_use]
    pub fn nominal(attempt: u32) -> Duration {
        // 2^6 × 5 s = 320 s is already past the cap; stop shifting there so a
        // long outage cannot overflow.
        let factor = 1u32 << attempt.min(6);
        REBUILD_BACKOFF_BASE
            .saturating_mul(factor)
            .min(REBUILD_BACKOFF_CAP)
    }

    /// The delay before the next rebuild, advancing the schedule.
    ///
    /// `unit` is a uniform sample in `[0, 1)` — passed in so the schedule is
    /// testable; the caller draws it from `rand`.
    pub fn next_delay(&mut self, unit: f64) -> Duration {
        let nominal = Self::nominal(self.attempt);
        self.attempt = self.attempt.saturating_add(1);
        let unit = unit.clamp(0.0, 1.0);
        let factor = 1.0 + REBUILD_BACKOFF_JITTER * (2.0 * unit - 1.0);
        nominal.mul_f64(factor).min(REBUILD_BACKOFF_CAP)
    }

    /// Back to the base delay.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replies_not_arriving_reads_as_its_own_state() {
        let text = replies_not_arriving_text(2);
        assert!(text.starts_with(&replies_not_arriving_summary(2)));
        assert!(text.contains("received the request"), "{text}");
        assert!(text.contains("replies aren't reaching this app"), "{text}");
        assert!(text.contains("inbox isn't being collected"), "{text}");
        assert!(text.contains("2 replies missed"), "{text}");
        assert!(text.ends_with("Reconnecting…"), "{text}");
        // Must not read as reachability or auth (R6.4).
        let lower = text.to_lowercase();
        for wrong in [
            "unreachable",
            "could not reach",
            "auth",
            "not accept",
            "rejected",
        ] {
            assert!(!lower.contains(wrong), "{wrong:?} in {text}");
        }
    }

    #[test]
    fn health_reads_for_a_person() {
        let mut h = ReceiveHealth::default();
        assert_eq!(describe_health(&h), "no reply yet this session");
        h.since_last_reply = Some(Duration::from_secs(12));
        assert_eq!(describe_health(&h), "last reply 12s ago");
        h.consecutive_reply_timeouts = 3;
        h.since_last_reply = Some(Duration::from_secs(250));
        assert_eq!(
            describe_health(&h),
            "last reply 4m 10s ago (3 missed in a row)"
        );
        h.consecutive_reply_timeouts = 1;
        assert!(describe_health(&h).ends_with("(1 reply missed)"));
        assert_eq!(short_duration(Duration::from_secs(3_725)), "1h 2m");
    }

    #[test]
    fn backoff_doubles_from_five_seconds_to_five_minutes() {
        let mut b = RebuildBackoff::default();
        // A mid sample (0.5) is exactly the nominal delay.
        let got: Vec<u64> = (0..9).map(|_| b.next_delay(0.5).as_secs()).collect();
        assert_eq!(got, vec![5, 10, 20, 40, 80, 160, 300, 300, 300]);
        assert_eq!(b.attempt(), 9);
    }

    #[test]
    fn backoff_jitter_stays_within_bounds_and_under_the_cap() {
        for attempt in 0..20 {
            let nominal = RebuildBackoff::nominal(attempt);
            for unit in [0.0, 0.25, 0.5, 0.75, 0.999_999] {
                let mut b = RebuildBackoff { attempt };
                let d = b.next_delay(unit);
                assert!(d <= REBUILD_BACKOFF_CAP, "{d:?} past the cap");
                assert!(
                    d >= nominal.mul_f64(1.0 - REBUILD_BACKOFF_JITTER) - Duration::from_millis(1)
                );
                assert!(
                    d <= nominal.mul_f64(1.0 + REBUILD_BACKOFF_JITTER) + Duration::from_millis(1)
                );
            }
        }
        // Different samples give different delays — the jitter is real.
        let lo = RebuildBackoff::default().next_delay(0.0);
        let hi = RebuildBackoff::default().next_delay(0.99);
        assert!(lo < hi);
        assert_eq!(lo, Duration::from_secs(4));
    }

    #[test]
    fn backoff_resets_to_the_base() {
        let mut b = RebuildBackoff::default();
        for _ in 0..5 {
            b.next_delay(0.5);
        }
        b.reset();
        assert_eq!(b.attempt(), 0);
        assert_eq!(b.next_delay(0.5), REBUILD_BACKOFF_BASE);
    }

    #[test]
    fn backoff_does_not_overflow_on_a_long_outage() {
        let mut b = RebuildBackoff { attempt: u32::MAX };
        assert!(b.next_delay(0.5) <= REBUILD_BACKOFF_CAP);
        assert_eq!(b.attempt(), u32::MAX);
    }
}
