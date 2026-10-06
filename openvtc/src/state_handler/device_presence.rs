//! Keeps this install visible to the rest of the account, and notices the
//! others.
//!
//! Runs as one long-lived background task (D13). It never touches `State` —
//! it sends [`PresenceReport`]s down a channel that the state-handler loop owns,
//! preserving the single-mutator rule, and it never blocks startup: the first
//! registration happens inside the task, so a VTA that is slow, offline, or does
//! not implement the device slice costs nothing but a log line.
//!
//! # Why it re-lists rather than only registering once
//!
//! A sibling that starts *after* us would otherwise be invisible until the next
//! launch — and the case that matters is precisely someone opening a second
//! instance while the first is running. Listing on each heartbeat costs one
//! extra trust task per interval and turns the mediator's mutual-eviction loop
//! from a mystery into a sentence.
//!
//! The listing has a second use: it is where this install sees the name its own
//! binding is showing. `displayName` is written once, at registration, and
//! re-registration is refused — so the heartbeat is the only thing that can
//! correct a machine that has been renamed since.

use openvtc_core::devices::{self, DeviceRecord};
use openvtc_core::vta_receive_leg::ReceiveLegTracker;
use std::collections::BTreeSet;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::watch;
use tracing::{debug, info, warn};
use vta_sdk::client::VtaClient;

/// What the presence task tells the loop.
#[derive(Clone, Debug)]
pub enum PresenceReport {
    /// This install's own binding, once claimed. Lets the loop name us and
    /// gives the sibling filter something to exclude.
    Registered {
        /// The VTA's id for our binding.
        device_id: String,
    },
    /// Siblings that were not live last time we looked.
    ///
    /// Only the *newly* seen ones, because the loop logs what it receives and a
    /// warning repeated every five minutes is one the user learns to ignore.
    NewSiblings(Vec<DeviceRecord>),
    /// Registration, listing or a heartbeat failed. Non-fatal, but shown: an
    /// absence of sibling warnings must not be mistaken for an absence of
    /// siblings, and a heartbeat that keeps failing is often the first sign the
    /// admin session itself has stopped hearing the VTA.
    Failing {
        /// Which call failed.
        what: PresenceCall,
        /// The error, as text.
        reason: String,
        /// The session's receive leg had tripped when it failed: requests reach
        /// the VTA, replies do not reach us. The loop rebuilds the session.
        replies_not_arriving: bool,
    },
    /// A call succeeded after a [`PresenceReport::Failing`].
    Recovered,
}

/// The presence task's calls to the VTA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresenceCall {
    /// `device/register`, once at launch.
    Register,
    /// `device/list`, every interval.
    List,
    /// `device/heartbeat`, every interval.
    Heartbeat,
}

impl PresenceCall {
    /// For a log line or the panel.
    pub fn label(self) -> &'static str {
        match self {
            PresenceCall::Register => "device registration",
            PresenceCall::List => "device listing",
            PresenceCall::Heartbeat => "device heartbeat",
        }
    }
}

/// Tracks whether the last call failed, so [`PresenceReport::Recovered`] is
/// sent once per recovery rather than after every success.
#[derive(Default)]
struct FailureLatch {
    failing: bool,
}

impl FailureLatch {
    /// A call failed: log it at WARN (every time — a failure every five minutes
    /// is not noise, and a debug line is what hid the 2026-10-05 stall) and
    /// build the report.
    ///
    /// `replies_not_arriving` is the session's receive health at the time
    /// ([`ReceiveHealth::replies_not_arriving`](openvtc_core::vta_receive_leg::ReceiveHealth::replies_not_arriving)).
    fn failed(
        &mut self,
        what: PresenceCall,
        e: &dyn std::fmt::Display,
        replies_not_arriving: bool,
    ) -> PresenceReport {
        self.failing = true;
        if replies_not_arriving {
            warn!(
                "{} failed — the VTA's replies are not reaching this app: {e}",
                what.label()
            );
        } else {
            warn!("{} failed: {e}", what.label());
        }
        PresenceReport::Failing {
            what,
            reason: e.to_string(),
            replies_not_arriving,
        }
    }

    /// A call succeeded: `Some(Recovered)` if the previous one had failed.
    fn succeeded(&mut self) -> Option<PresenceReport> {
        std::mem::take(&mut self.failing).then_some(PresenceReport::Recovered)
    }
}

/// Register this install, then heartbeat and watch for siblings until cancelled.
///
/// `self_did` is the DID this install authenticates to the VTA as — the durable
/// answer to "which of these bindings is mine", because only a first launch ever
/// learns its device id (see [`devices::register`]).
///
/// `client` follows the admin session: when the loop rebuilds it, the next call
/// here uses the new one, never the closed one.
///
/// `receive` is the admin session's receive leg: every call here is counted on
/// it, which makes the heartbeat and listing a periodic probe of whether the
/// VTA's replies still reach this app.
///
/// Returns when `tx` closes — i.e. when the state handler exits.
pub async fn run(
    client: watch::Receiver<VtaClient>,
    profile: String,
    self_did: Option<String>,
    receive: ReceiveLegTracker,
    tx: UnboundedSender<PresenceReport>,
) {
    let current = || client.borrow().clone();
    let mut latch = FailureLatch::default();
    let first = current();
    let mut self_id = match devices::register(&first, &profile, &receive).await {
        Ok(devices::Registration::Claimed(record)) => {
            info!(device_id = %record.device_id, "registered this install with the VTA");
            if tx
                .send(PresenceReport::Registered {
                    device_id: record.device_id.clone(),
                })
                .is_err()
            {
                return;
            }
            Some(record.device_id)
        }
        Ok(devices::Registration::AlreadyRegistered) => {
            // Every launch after the first. The binding is ours and still there;
            // we just were not told its id, and the listing below recovers it.
            debug!("this install is already registered with the VTA");
            None
        }
        Err(e) => {
            // Not fatal: a VTA without the device slice, or one briefly
            // unreachable, must not degrade anything the user came here for.
            let _ = tx.send(latch.failed(
                PresenceCall::Register,
                &e,
                receive.health().replies_not_arriving(),
            ));
            None
        }
    };

    // Siblings already reported, so a steady state stays quiet. Keyed by
    // device id rather than by the whole record, because `lastSeenAt` changes
    // on every heartbeat and would otherwise re-announce the same machine.
    let mut announced: BTreeSet<String> = BTreeSet::new();

    loop {
        let client = current();
        match devices::list(&client, &receive).await {
            Ok(all) => {
                if let Some(report) = latch.succeeded()
                    && tx.send(report).is_err()
                {
                    return;
                }
                let mine = all
                    .iter()
                    .find(|d| d.is_self(self_id.as_deref(), self_did.as_deref()));

                // Recover our own id from the listing when registration did not
                // hand it to us, so the loop names us the same way a first launch
                // does — and so a VTA that stops returning `consumerDid` still
                // has the id to fall back on.
                if self_id.is_none()
                    && let Some(recovered) = mine.map(|d| d.device_id.clone())
                {
                    debug!(device_id = %recovered, "recovered this install's binding from the listing");
                    if tx
                        .send(PresenceReport::Registered {
                            device_id: recovered.clone(),
                        })
                        .is_err()
                    {
                        return;
                    }
                    self_id = Some(recovered);
                }

                // Correct a drifted `displayName` now rather than on the next
                // beat. The name only travels on a heartbeat, so an install
                // opened and closed inside one interval would never send one and
                // the stale name would outlive every launch.
                if mine.is_some_and(|d| devices::name_correction_due(d, &profile)) {
                    debug!("this install's binding shows a stale name; correcting it");
                    if let Err(e) = devices::heartbeat(&client, &profile, &receive).await {
                        debug!("name correction failed; it will retry on the next beat: {e}");
                    }
                }
                let live = devices::live_siblings(
                    &all,
                    self_id.as_deref(),
                    self_did.as_deref(),
                    chrono::Utc::now(),
                );
                let fresh = newly_appeared(&mut announced, &live);
                if !fresh.is_empty() && tx.send(PresenceReport::NewSiblings(fresh)).is_err() {
                    return;
                }
            }
            Err(e) => {
                if tx
                    .send(latch.failed(
                        PresenceCall::List,
                        &e,
                        receive.health().replies_not_arriving(),
                    ))
                    .is_err()
                {
                    return;
                }
            }
        }

        tokio::time::sleep(devices::HEARTBEAT_INTERVAL).await;
        if tx.is_closed() {
            return;
        }
        // Re-read: the session may have been rebuilt during the sleep.
        let client = current();
        match devices::heartbeat(&client, &profile, &receive).await {
            Ok(()) => {
                if let Some(report) = latch.succeeded()
                    && tx.send(report).is_err()
                {
                    return;
                }
            }
            // One missed beat is tolerated by the liveness window, but a
            // heartbeat that fails is also the admin session failing — said
            // at WARN and shown in the panel, not left at debug.
            Err(e) => {
                if tx
                    .send(latch.failed(
                        PresenceCall::Heartbeat,
                        &e,
                        receive.health().replies_not_arriving(),
                    ))
                    .is_err()
                {
                    return;
                }
            }
        }
    }
}

/// Which of `live` have not been announced yet, updating `announced` to match.
///
/// Two properties, and both matter to whether the warning is worth having:
///
/// - A sibling seen again is **not** re-reported. `lastSeenAt` changes on every
///   heartbeat, so comparing whole records would re-announce the same machine
///   every interval, and a warning shown every five minutes is one the user
///   learns to scroll past.
/// - A sibling that goes away is **forgotten**, so closing and reopening that
///   instance announces it again. That is a fresh collision, not a duplicate.
fn newly_appeared(announced: &mut BTreeSet<String>, live: &[DeviceRecord]) -> Vec<DeviceRecord> {
    let fresh: Vec<DeviceRecord> = live
        .iter()
        .filter(|d| !announced.contains(&d.device_id))
        .cloned()
        .collect();

    // Rebuilt from what is live now, so departures drop out.
    *announced = live.iter().map(|d| d.device_id.clone()).collect();
    fresh
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: &str) -> DeviceRecord {
        DeviceRecord {
            device_id: id.to_string(),
            consumer_did: None,
            display_name: format!("OpenVTC on {id}"),
            platform: None,
            registered_at: None,
            last_seen_at: Some(chrono::Utc::now().to_rfc3339()),
            disabled_at: None,
            wiped_at: None,
        }
    }

    #[test]
    fn a_new_sibling_is_announced_once() {
        let mut announced = BTreeSet::new();
        let live = vec![record("laptop")];

        let first = newly_appeared(&mut announced, &live);
        assert_eq!(first.len(), 1, "first sighting must be announced");

        let second = newly_appeared(&mut announced, &live);
        assert!(
            second.is_empty(),
            "a steady state must stay quiet — a warning every interval is one \
             the user learns to ignore"
        );
    }

    /// `lastSeenAt` changes on every heartbeat. Keying on the whole record
    /// would re-announce the same machine forever.
    #[test]
    fn a_refreshed_timestamp_is_not_a_new_sibling() {
        let mut announced = BTreeSet::new();
        let _ = newly_appeared(&mut announced, &[record("laptop")]);

        let mut later = record("laptop");
        later.last_seen_at = Some((chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339());
        assert!(newly_appeared(&mut announced, &[later]).is_empty());
    }

    #[test]
    fn a_sibling_that_leaves_and_returns_is_announced_again() {
        let mut announced = BTreeSet::new();
        let _ = newly_appeared(&mut announced, &[record("laptop")]);

        // Closed: no longer live.
        assert!(newly_appeared(&mut announced, &[]).is_empty());

        // Reopened — a fresh collision, and worth saying so.
        let again = newly_appeared(&mut announced, &[record("laptop")]);
        assert_eq!(again.len(), 1);
    }

    #[test]
    fn only_the_new_one_is_announced_when_another_joins() {
        let mut announced = BTreeSet::new();
        let _ = newly_appeared(&mut announced, &[record("laptop")]);

        let fresh = newly_appeared(&mut announced, &[record("laptop"), record("desktop")]);
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].device_id, "desktop");
    }

    #[test]
    fn a_failure_is_reported_every_time_and_recovery_once() {
        let mut latch = FailureLatch::default();
        assert!(latch.succeeded().is_none(), "nothing to recover from");
        for _ in 0..2 {
            match latch.failed(PresenceCall::Heartbeat, &"timed out", true) {
                PresenceReport::Failing {
                    what,
                    reason,
                    replies_not_arriving,
                } => {
                    assert_eq!(what, PresenceCall::Heartbeat);
                    assert_eq!(reason, "timed out");
                    assert!(replies_not_arriving);
                }
                other => panic!("{other:?}"),
            }
        }
        assert!(matches!(latch.succeeded(), Some(PresenceReport::Recovered)));
        assert!(latch.succeeded().is_none(), "recovery is said once");
    }

    #[test]
    fn no_siblings_announces_nothing() {
        let mut announced = BTreeSet::new();
        assert!(newly_appeared(&mut announced, &[]).is_empty());
        assert!(announced.is_empty());
    }
}
