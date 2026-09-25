//! The queue of inbound messages waiting on an off-loop check.
//!
//! A message whose handling needs a network-bound check (a DID resolve, a
//! status-list fetch) is set aside by dispatch
//! ([`super::message_dispatch::InboundEffects::deferred`]) and queued here. One
//! check runs at a time, spawned as its own task, and the message comes back
//! with the result ([`Verifier::finished`]) to be dispatched from the top.
//!
//! Bounded, because the messages come from whoever can reach our mediator:
//!
//! - **Two lanes.** Messages from communities we hold a membership with
//!   (credentials, removal notices, join and profile answers) go in the
//!   priority lane, and are always taken first; everything else (relationship
//!   requests, VRCs from peers) in the other. A stranger flooding the second
//!   lane never delays a community's removal notice.
//! - **Caps.** Each lane has a length cap and each sender a cap across both;
//!   a message over either is refused, not queued, and the caller says so.
//! - **Keyed on the authenticated sender.** The caller keys each message on
//!   the sender the transport bound to it, never the plaintext `from`: a
//!   forger claiming a community's DID spends its own share, not the
//!   community's, and rotating the claimed `from` gains nothing.
//! - **A rate on relationship requests.** Checking one resolves DIDs the
//!   requester chose, so at most [`MAX_REQUEST_CHECKS_PER_MINUTE`] are queued
//!   a minute, from everyone together.
//! - **Order per sender.** A sender's messages keep the lane their first
//!   queued one took, so they come back in the order they arrived.
//! - **A timeout per check** ([`JOB_TIMEOUT`]), and a check that panics or
//!   times out comes back as a failed check, so the message is refused (fail
//!   closed) and the queue moves on. Each check is its own task: a panic ends
//!   that check only, never the queue.

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use affinidi_tdk::{TDK, didcomm::Message};
use tokio::task::JoinHandle;
use tracing::warn;

use super::didcomm::MessagingTransport;
use super::message_dispatch::{Deferred, PreVerified};

/// The longest one check may take: a DID resolve and a status-list fetch are
/// each bounded at ten seconds (R1.2), so this is their sum with room to spare.
pub const JOB_TIMEOUT: Duration = Duration::from_secs(30);

/// Most messages queued in the priority lane (communities we belong to).
pub const MAX_PRIORITY_QUEUED: usize = 256;

/// Most messages queued in the other lane.
pub const MAX_OTHER_QUEUED: usize = 64;

/// Most messages one sender may have queued or being checked, across both
/// lanes.
pub const MAX_PER_SENDER: usize = 32;

/// Most relationship-request checks queued in a minute, across all senders.
pub const MAX_REQUEST_CHECKS_PER_MINUTE: usize = 20;

/// Which lane a message waits in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    /// A community we hold a membership with.
    Priority,
    /// Anyone else.
    Other,
}

/// Why a message was not queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refused {
    #[error("the verification queue is full")]
    LaneFull,
    #[error("this sender has too many messages waiting on verification")]
    SenderFull,
    #[error("too many relationship requests to check right now")]
    RateLimited,
    #[error("it has no authenticated sender")]
    Unauthenticated,
}

/// A message back from its check, to be dispatched from the top.
pub struct Finished {
    /// The key it was queued under (the authenticated sender).
    pub sender: String,
    pub message: Box<Message>,
    pub transport: MessagingTransport,
    pub pre: PreVerified,
}

struct Queued {
    deferred: Deferred,
    transport: MessagingTransport,
    sender: String,
}

struct Running {
    message: Box<Message>,
    transport: MessagingTransport,
    sender: String,
    /// What the check yields if its task panics.
    on_panic: Option<PreVerified>,
    handle: JoinHandle<PreVerified>,
}

/// The queue, and the one check running.
pub struct Verifier {
    tdk: TDK,
    timeout: Duration,
    priority: VecDeque<Queued>,
    other: VecDeque<Queued>,
    /// Per sender: messages queued or running, and the lane they use.
    senders: HashMap<String, (usize, Lane)>,
    running: Option<Running>,
    /// When recent relationship-request checks were queued.
    request_checks: VecDeque<std::time::Instant>,
}

impl Verifier {
    #[must_use]
    pub fn new(tdk: TDK) -> Self {
        Self::with_timeout(tdk, JOB_TIMEOUT)
    }

    #[must_use]
    pub fn with_timeout(tdk: TDK, timeout: Duration) -> Self {
        Self {
            tdk,
            timeout,
            priority: VecDeque::new(),
            other: VecDeque::new(),
            senders: HashMap::new(),
            running: None,
            request_checks: VecDeque::new(),
        }
    }

    /// Whether the lane or `sender` is at its cap, so an `enqueue` would be
    /// refused for want of room (not for rate).
    #[must_use]
    pub fn is_full_for(&self, sender: &str, lane: Lane) -> bool {
        let (count, lane) = self.senders.get(sender).copied().unwrap_or((0, lane));
        count >= MAX_PER_SENDER
            || match lane {
                Lane::Priority => self.priority.len() >= MAX_PRIORITY_QUEUED,
                Lane::Other => self.other.len() >= MAX_OTHER_QUEUED,
            }
    }

    /// Whether `sender` has anything queued or being checked. A message from
    /// it that needs no check waits behind that work rather than overtaking it.
    #[must_use]
    pub fn is_waiting_on(&self, sender: &str) -> bool {
        self.senders.contains_key(sender)
    }

    /// Queue `deferred` from `sender`, preferring `lane` (a sender already
    /// queued keeps its lane), and start it if nothing is running.
    ///
    /// # Errors
    ///
    /// [`Refused`] when the lane or the sender is at its cap; the message is
    /// not queued.
    pub fn enqueue(
        &mut self,
        deferred: Deferred,
        transport: MessagingTransport,
        sender: &str,
        lane: Lane,
    ) -> Result<Lane, Refused> {
        let (count, lane) = self.senders.get(sender).copied().unwrap_or((0, lane));
        if count >= MAX_PER_SENDER {
            return Err(Refused::SenderFull);
        }
        let (queue, cap) = match lane {
            Lane::Priority => (&mut self.priority, MAX_PRIORITY_QUEUED),
            Lane::Other => (&mut self.other, MAX_OTHER_QUEUED),
        };
        if queue.len() >= cap {
            return Err(Refused::LaneFull);
        }
        if deferred.job.is_relationship_request() {
            let now = std::time::Instant::now();
            while self
                .request_checks
                .front()
                .is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(60))
            {
                self.request_checks.pop_front();
            }
            if self.request_checks.len() >= MAX_REQUEST_CHECKS_PER_MINUTE {
                return Err(Refused::RateLimited);
            }
            self.request_checks.push_back(now);
        }
        queue.push_back(Queued {
            deferred,
            transport,
            sender: sender.to_string(),
        });
        self.senders.insert(sender.to_string(), (count + 1, lane));
        self.start_next();
        Ok(lane)
    }

    /// How many messages are queued or being checked.
    #[cfg(test)]
    #[must_use]
    pub fn len(&self) -> usize {
        self.priority.len() + self.other.len() + usize::from(self.running.is_some())
    }

    fn start_next(&mut self) {
        if self.running.is_some() {
            return;
        }
        let Some(next) = self.priority.pop_front().or_else(|| self.other.pop_front()) else {
            return;
        };
        let Queued {
            deferred: Deferred { message, job },
            transport,
            sender,
        } = next;
        let on_timeout = job.unfinished();
        let on_panic = Some(job.unfinished());
        let (tdk, timeout) = (self.tdk.clone(), self.timeout);
        let handle = tokio::spawn(async move {
            match tokio::time::timeout(timeout, job.run(tdk)).await {
                Ok(pre) => pre,
                Err(_) => {
                    warn!("an inbound message's check timed out — refused");
                    on_timeout
                }
            }
        });
        self.running = Some(Running {
            message: Box::new(message),
            transport,
            sender,
            on_panic,
            handle,
        });
    }

    /// The next message back from its check. Pending while nothing is
    /// running. Cancel-safe: dropped before it completes, the check keeps its
    /// place and a later call picks it up.
    pub async fn finished(&mut self) -> Finished {
        let Some(running) = self.running.as_mut() else {
            return std::future::pending().await;
        };
        let pre = match (&mut running.handle).await {
            Ok(pre) => pre,
            Err(e) => {
                warn!(error = %e, "an inbound message's check failed — refused");
                running
                    .on_panic
                    .take()
                    .expect("taken only once, when its task ends")
            }
        };
        let running = self.running.take().expect("running, awaited above");
        if let Some((count, _)) = self.senders.get_mut(&running.sender) {
            *count -= 1;
            if *count == 0 {
                self.senders.remove(&running.sender);
            }
        }
        self.start_next();
        Finished {
            sender: running.sender,
            message: running.message,
            transport: running.transport,
            pre,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::message_dispatch::VerifyJob;
    use super::*;
    use crate::state_handler::dispatch_util::test_tdk;

    fn barrier(id: &str) -> Deferred {
        Deferred {
            message: Message::build(id, "t", serde_json::json!({})).finalize(),
            job: VerifyJob::Barrier,
        }
    }

    /// A community's messages overtake everyone else's, a sender's keep their
    /// order, and the caps refuse rather than grow.
    #[tokio::test]
    async fn lanes_order_and_caps() {
        let mut v = Verifier::new(test_tdk().await);
        // The first runs at once; the rest queue.
        v.enqueue(
            barrier("p0"),
            MessagingTransport::DidComm,
            "peer",
            Lane::Other,
        )
        .unwrap();
        v.enqueue(
            barrier("p1"),
            MessagingTransport::DidComm,
            "peer",
            Lane::Other,
        )
        .unwrap();
        v.enqueue(
            barrier("c0"),
            MessagingTransport::DidComm,
            "vtc",
            Lane::Priority,
        )
        .unwrap();
        // A sender already queued keeps its lane, so its order holds.
        assert_eq!(
            v.enqueue(
                barrier("p2"),
                MessagingTransport::DidComm,
                "peer",
                Lane::Priority
            ),
            Ok(Lane::Other)
        );
        assert!(v.is_waiting_on("peer") && v.is_waiting_on("vtc"));
        let order: Vec<String> = {
            let mut out = Vec::new();
            for _ in 0..4 {
                out.push(v.finished().await.message.id);
            }
            out
        };
        assert_eq!(order, ["p0", "c0", "p1", "p2"]);
        assert!(!v.is_waiting_on("peer") && v.len() == 0);

        for i in 0..MAX_PER_SENDER {
            v.enqueue(
                barrier(&i.to_string()),
                MessagingTransport::DidComm,
                "noisy",
                Lane::Other,
            )
            .unwrap();
        }
        assert_eq!(
            v.enqueue(
                barrier("x"),
                MessagingTransport::DidComm,
                "noisy",
                Lane::Other
            ),
            Err(Refused::SenderFull)
        );
        // The other lane fills without touching the priority lane.
        let mut i = 0;
        let full = loop {
            match v.enqueue(
                barrier("y"),
                MessagingTransport::DidComm,
                &format!("s{}", i / MAX_PER_SENDER),
                Lane::Other,
            ) {
                Ok(_) => i += 1,
                Err(e) => break e,
            }
        };
        assert_eq!(full, Refused::LaneFull);
        assert!(
            v.enqueue(
                barrier("c"),
                MessagingTransport::DidComm,
                "vtc",
                Lane::Priority
            )
            .is_ok()
        );
    }

    /// Relationship-request checks (which resolve DIDs the requester chose)
    /// are rate-limited across all senders; other checks are not.
    #[tokio::test]
    async fn relationship_request_checks_are_rate_limited() {
        let mut v = Verifier::new(test_tdk().await);
        let request = |i: usize| Deferred {
            message: Message::build(format!("r{i}"), "t", serde_json::json!({})).finalize(),
            job: VerifyJob::DidBinding {
                did: format!("did:key:z{i}"),
                did_proof: None,
                persona: format!("did:key:z{i}"),
                persona_proof: None,
                peer: "did:key:zMe".into(),
                thid: format!("r{i}"),
                role: openvtc_core::relationships::BindingRole::Request,
            },
        };
        for i in 0..MAX_REQUEST_CHECKS_PER_MINUTE {
            v.enqueue(
                request(i),
                MessagingTransport::DidComm,
                &format!("s{i}"),
                Lane::Other,
            )
            .unwrap();
        }
        assert_eq!(
            v.enqueue(
                request(99),
                MessagingTransport::DidComm,
                "fresh",
                Lane::Other
            ),
            Err(Refused::RateLimited)
        );
        assert!(
            v.enqueue(
                barrier("b"),
                MessagingTransport::DidComm,
                "fresh",
                Lane::Other
            )
            .is_ok()
        );
    }

    /// A check that does not finish in time is refused, and the queue moves on.
    #[tokio::test]
    async fn a_check_that_hangs_is_refused_after_its_timeout() {
        let mut v = Verifier::with_timeout(test_tdk().await, Duration::from_millis(50));
        v.enqueue(
            Deferred {
                message: Message::build("slow", "t", serde_json::json!({})).finalize(),
                job: VerifyJob::Hang,
            },
            MessagingTransport::DidComm,
            "vtc",
            Lane::Priority,
        )
        .unwrap();
        v.enqueue(
            barrier("next"),
            MessagingTransport::DidComm,
            "vtc",
            Lane::Priority,
        )
        .unwrap();
        let first = v.finished().await;
        assert_eq!(first.message.id, "slow");
        assert!(matches!(
            first.pre,
            PreVerified::Operational(Err(
                openvtc_core::operational::OperationalError::CheckUnfinished
            ))
        ));
        assert_eq!(v.finished().await.message.id, "next");
    }

    /// A check that panics is refused, and the next one still runs.
    #[tokio::test]
    async fn a_check_that_panics_is_refused_and_the_queue_goes_on() {
        let mut v = Verifier::new(test_tdk().await);
        v.enqueue(
            Deferred {
                message: Message::build("boom", "t", serde_json::json!({})).finalize(),
                job: VerifyJob::Panic,
            },
            MessagingTransport::DidComm,
            "vtc",
            Lane::Priority,
        )
        .unwrap();
        v.enqueue(
            barrier("next"),
            MessagingTransport::DidComm,
            "vtc",
            Lane::Priority,
        )
        .unwrap();
        let first = v.finished().await;
        assert!(matches!(
            first.pre,
            PreVerified::Operational(Err(
                openvtc_core::operational::OperationalError::CheckUnfinished
            ))
        ));
        assert_eq!(v.finished().await.message.id, "next");
    }
}
