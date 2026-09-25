//! Ask a community what became of a join it has not answered.
//!
//! Every other way a `Pending` join resolves is the community volunteering
//! something: a verdict, a credential, a problem-report. If any of those is lost
//! — a socket that was down at the wrong moment, a mediator that dropped it, a
//! decision a human took days later and the push went nowhere — the record sits
//! `Pending` and nothing here ever asks. `join-requests/status/0.1` is the
//! protocol's answer to that, and OpenVTC has until now implemented only the
//! receiving half (`messaging::handle_join_status_response`).
//!
//! ## What can be polled
//!
//! Every `Pending` join, including one that never got *any* reply.
//!
//! That used to be untrue, and the exception swallowed the rule. The VTC mints
//! its own request id and tells us in the first correlated reply; until one
//! arrives we hold the id of the document we sent, which the VTC has never heard
//! of and answers `not found` for. So the only joins this module could ask about
//! were the ones that had already been answered once — and a join that never got
//! a reply, the case it exists for, could not be polled at all.
//!
//! The fallback named here was collecting the stored mail the reply is sitting
//! in. That is empty whenever the mail was acked and deleted before anything
//! consumed it, which is the same failure. Both recoveries had one blind spot and
//! shared it (#221): the record sat `Pending` for good, and the only way out was
//! editing the id into the config by hand.
//!
//! A poll now omits the id when we do not hold the community's, which asks
//! "what is my open request?" — resolved from the authenticated applicant, and
//! answered with the id. So the record repairs itself on the first reply and
//! quotes the real id from then on. [`CommunityRecord::request_id_confirmed`]
//! still decides *what we send*; it no longer decides whether we may ask.
//!
//! ## Pacing
//!
//! Per-record, in memory, never persisted: the first tick after launch polls
//! (a record that survived a restart is exactly the one worth reconciling),
//! then backs off 1 → 2 → 4 → 8 minutes, capped at [`POLL_BACKOFF_CAP`]. At most
//! [`MAX_POLLS_PER_TICK`] go out per tick, so an account with many parked joins
//! spreads them over several ticks instead of opening a fan of sends at one
//! community (R1.4). Deliberately in memory: the pacing is about *this*
//! process's politeness, and persisting it would let a stale on-disk backoff
//! suppress the poll a fresh launch most wants to make.
//!
//! [`CommunityRecord::request_id_confirmed`]: openvtc_core::config::account::CommunityRecord::request_id_confirmed

use std::collections::HashMap;
use std::time::{Duration, Instant};

use affinidi_tdk::TDK;
use affinidi_tdk::messaging::ATM;
use openvtc_core::config::Config;
use openvtc_core::config::account::{PendingPoll, PersonaId, VtcDid};
use openvtc_core::didcomm::MessagingTransport;
use tracing::debug;

/// Backoff after the n-th consecutive poll of one record: 1, 2, 4, 8 minutes,
/// then capped.
const POLL_BACKOFF_BASE: Duration = Duration::from_secs(60);

/// Ceiling on the per-record backoff. A join parked for human review can sit for
/// days; a poll every quarter of an hour is enough to notice the outcome
/// promptly without making this client a load source.
const POLL_BACKOFF_CAP: Duration = Duration::from_secs(900);

/// How many polls one tick may send, across all records.
const MAX_POLLS_PER_TICK: usize = 4;

/// The identity of a membership for pacing purposes: a community may hold
/// several, one per persona (multi-membership), and each is polled separately.
type PollKey = (VtcDid, PersonaId);

/// How long to wait before the `attempts`-th consecutive poll of one record.
/// `attempts == 0` (never polled) is no wait — the first tick after launch goes
/// straight out.
fn poll_backoff(attempts: u32) -> Duration {
    if attempts == 0 {
        return Duration::ZERO;
    }
    // The shift is clamped only to keep it from overflowing; `POLL_BACKOFF_CAP`
    // is what actually bounds the wait, so raising the cap raises the ceiling
    // without also having to find this shift.
    POLL_BACKOFF_BASE
        .checked_mul(1u32 << attempts.saturating_sub(1).min(8))
        .unwrap_or(POLL_BACKOFF_CAP)
        .min(POLL_BACKOFF_CAP)
}

/// Per-record poll pacing for the life of the process.
#[derive(Debug, Default)]
pub(crate) struct PollPacer {
    sent: HashMap<PollKey, Sent>,
}

#[derive(Debug, Clone, Copy)]
struct Sent {
    at: Instant,
    attempts: u32,
}

impl PollPacer {
    /// The records due a poll right now, newest-backoff first come first served,
    /// capped at [`MAX_POLLS_PER_TICK`]. Marks each returned record as polled, so
    /// a caller that then fails to send simply retries after the backoff rather
    /// than hammering an unreachable community.
    pub(crate) fn due(&mut self, candidates: Vec<PendingPoll>, now: Instant) -> Vec<PendingPoll> {
        // Forget records that are no longer pending (resolved, left, expired), so
        // a long-lived process doesn't accumulate their pacing entries and a
        // community re-joined later starts from a clean first poll.
        let live: std::collections::HashSet<PollKey> = candidates
            .iter()
            .map(|c| (c.vtc_did.clone(), c.persona_ref))
            .collect();
        self.sent.retain(|key, _| live.contains(key));

        let mut due = Vec::new();
        for candidate in candidates {
            if due.len() >= MAX_POLLS_PER_TICK {
                break;
            }
            let key = (candidate.vtc_did.clone(), candidate.persona_ref);
            let attempts = match self.sent.get(&key) {
                None => 0,
                Some(sent) => {
                    if now.duration_since(sent.at) < poll_backoff(sent.attempts) {
                        continue;
                    }
                    sent.attempts
                }
            };
            self.sent.insert(
                key,
                Sent {
                    at: now,
                    attempts: attempts.saturating_add(1),
                },
            );
            due.push(candidate);
        }
        due
    }
}

/// One poll, resolved against the account so the send needs no `Config` borrow
/// and can therefore be moved into a spawned task.
pub(crate) struct Poll {
    applicant_did: String,
    /// The persona's signing key: `join-requests/status/0.1` declares `proof`
    /// REQUIRED, so a poll is a signed document like the submit it chases.
    signing_secret: affinidi_tdk::secrets_resolver::secrets::Secret,
    profile: std::sync::Arc<affinidi_tdk::messaging::profiles::ATMProfile>,
    mediator_did: String,
    vtc_did: String,
    /// The community's id when we hold it; `None` asks "what is my open
    /// request?" — the only form available to a join whose first reply was lost.
    request_id: Option<uuid::Uuid>,
    /// The submit went out over TSP, so the poll must too — a community
    /// reachable only over TSP would never see a DIDComm poll.
    over_tsp: bool,
}

/// Resolve each due record to a sendable [`Poll`], dropping any whose persona no
/// longer resolves to a runtime identity (a deleted DID mid-flight): there is
/// nothing to speak as, and the record's own repair path is elsewhere.
///
/// A persona whose signing key cannot be read is dropped the same way: the poll
/// is a signed document, and an unsigned one would be refused by a community
/// enforcing the requirement rather than answered.
pub(crate) async fn build(config: &Config, tdk: &TDK, due: Vec<PendingPoll>) -> Vec<Poll> {
    let mut polls = Vec::new();
    for record in due {
        let Some(identity) = config.identities.get(&record.persona_ref) else {
            debug!(
                vtc = %record.vtc_did,
                "skipping status poll: the join's persona has no runtime identity"
            );
            continue;
        };
        let signing_secret = match config.get_persona_keys_for(record.persona_ref, tdk).await {
            Ok(keys) => keys.authentication.secret.clone(),
            Err(e) => {
                debug!(
                    vtc = %record.vtc_did, error = %e,
                    "skipping status poll: the join's persona has no readable signing key"
                );
                continue;
            }
        };
        polls.push(Poll {
            signing_secret,
            applicant_did: identity.persona_did().to_string(),
            profile: identity.profile().clone(),
            mediator_did: identity.mediator_did.clone().unwrap_or_default(),
            vtc_did: record.vtc_did,
            request_id: record.request_id,
            over_tsp: record.submit_transport == Some(MessagingTransport::Tsp),
        });
    }
    polls
}

/// Send each poll, one at a time. The reply is asynchronous — it arrives on the
/// persona's own listener and is applied by the inbound dispatch — so nothing is
/// awaited beyond the send, and a failure is logged rather than surfaced: this
/// is background reconciliation the operator did not initiate, it retries after
/// the backoff, and the fact it is reconciling (a `Pending` record, flagged once
/// past the grace window) is already on screen.
///
/// Sequential on purpose. The cap is four per tick, these are sends to
/// potentially the same community, and a fan of concurrent sends buys nothing
/// against a reply path that is asynchronous either way.
pub(crate) async fn send_all(atm: ATM, polls: Vec<Poll>) {
    for poll in polls {
        // TSP needs the community's *advertised* TSP mediator, resolved fresh:
        // it is the hop the routing layer seals to, and a document may have
        // changed since the submit.
        let tsp_mediator = if poll.over_tsp {
            openvtc_core::config::peer_tsp_mediator(&poll.vtc_did).await
        } else {
            None
        };
        let route = openvtc_core::join::Applicant {
            atm: &atm,
            profile: &poll.profile,
            persona_did: &poll.applicant_did,
            signer: &poll.signing_secret,
            vtc_did: &poll.vtc_did,
            mediator_did: &poll.mediator_did,
            tsp_mediator_did: tsp_mediator.as_deref(),
        };
        match openvtc_core::join::poll_join_status(&route, poll.request_id).await {
            Ok(()) => debug!(
                vtc = %poll.vtc_did,
                request_id = ?poll.request_id,
                "asked the community about a pending join"
            ),
            Err(e) => debug!(
                vtc = %poll.vtc_did,
                request_id = ?poll.request_id,
                error = %e,
                "could not ask the community about a pending join; will retry after the backoff"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn candidate(vtc: &str) -> PendingPoll {
        PendingPoll {
            vtc_did: vtc.to_string(),
            persona_ref: PersonaId::new(),
            request_id: Some(Uuid::new_v4()),
            submit_transport: Some(MessagingTransport::DidComm),
        }
    }

    #[test]
    fn the_first_tick_polls_immediately() {
        let mut pacer = PollPacer::default();
        let due = pacer.due(vec![candidate("did:webvh:a")], Instant::now());
        assert_eq!(due.len(), 1, "a record never polled is due at once");
    }

    #[test]
    fn a_second_tick_inside_the_backoff_is_not_due() {
        let mut pacer = PollPacer::default();
        let one = candidate("did:webvh:a");
        let now = Instant::now();
        assert_eq!(pacer.due(vec![one.clone()], now).len(), 1);
        assert!(
            pacer
                .due(vec![one.clone()], now + Duration::from_secs(30))
                .is_empty(),
            "30s after the first poll is inside the 60s backoff"
        );
        assert_eq!(
            pacer.due(vec![one], now + Duration::from_secs(61)).len(),
            1,
            "past the backoff it is due again"
        );
    }

    #[test]
    fn the_backoff_grows_and_then_caps() {
        assert_eq!(poll_backoff(0), Duration::ZERO);
        assert_eq!(poll_backoff(1), Duration::from_secs(60));
        assert_eq!(poll_backoff(2), Duration::from_secs(120));
        assert_eq!(poll_backoff(4), Duration::from_secs(480));
        // Capped, and — the part worth pinning — never overflows into a wait so
        // long the poll effectively stops.
        assert_eq!(poll_backoff(5), POLL_BACKOFF_CAP);
        assert_eq!(poll_backoff(u32::MAX), POLL_BACKOFF_CAP);
    }

    #[test]
    fn one_tick_sends_no_more_than_the_cap() {
        let mut pacer = PollPacer::default();
        let candidates: Vec<_> = (0..10)
            .map(|i| candidate(&format!("did:webvh:{i}")))
            .collect();
        let due = pacer.due(candidates.clone(), Instant::now());
        assert_eq!(
            due.len(),
            MAX_POLLS_PER_TICK,
            "a large backlog is spread over ticks, not sent at once"
        );
    }

    #[test]
    fn a_record_that_stops_being_pending_is_forgotten() {
        let mut pacer = PollPacer::default();
        let one = candidate("did:webvh:a");
        let now = Instant::now();
        assert_eq!(pacer.due(vec![one.clone()], now).len(), 1);
        // It resolved: absent from the candidates, so its pacing is dropped...
        assert!(pacer.due(vec![], now + Duration::from_secs(1)).is_empty());
        // ...and a later join of the same community starts from a fresh poll
        // rather than inheriting the old backoff.
        assert_eq!(pacer.due(vec![one], now + Duration::from_secs(2)).len(), 1);
    }
}
