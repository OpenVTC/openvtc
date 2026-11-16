//! Replies we are waiting for from communities, by thread.
//!
//! Some answers are admitted only because we asked for them: a community's
//! answer to a renewal, its profile, or — from a community this persona holds
//! no membership with — an election answer (VTI-NTF-061, VTI-NTF-063). Each
//! request is recorded here, against the community it went to, before it is
//! sent; the inbound gate ([`crate::inbound`]) admits and takes an answer only
//! on a thread recorded here, from that community, while it is still waited
//! for.
//!
//! The table is **in memory and owned by whoever drives inbound handling**:
//! the TUI's runtime loop holds one for its lifetime, and each headless command
//! holds its own. It is passed explicitly to the send paths that record and to
//! the dispatcher that consumes — never a process-global — so the single
//! mutator owns it, and tests each use their own. A request is this process's:
//! an answer arriving after a restart is not taken (the member asks again).
//!
//! Each [`ReplyKind`] keeps the window, capacity, thread normalisation and
//! community comparison it has always had:
//!
//! | kind                          | waits  | at most | thread key                      | community     |
//! |-------------------------------|--------|---------|---------------------------------|---------------|
//! | [`ReplyKind::Renewal`]        | 600 s  | 64      | the UUID, `urn:uuid:` optional  | exact         |
//! | [`ReplyKind::CommunityProfile`] | 600 s | 256    | the thread id exactly           | exact         |
//! | [`ReplyKind::ElectionAnswer`] | 120 s  | 64      | `urn:uuid:` prefix optional     | same DID ([`vta_sdk::did_scid::same_reference`]) |

use std::collections::HashMap;
use std::time::{Duration, Instant};

use uuid::Uuid;

/// What a recorded request was, and so how its answer is matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReplyKind {
    /// `vtc/members/renew/0.1` ([`crate::renewal`]).
    Renewal,
    /// `vtc/community/profile/show/0.1` ([`crate::join::send_community_profile_show`]).
    CommunityProfile,
    /// A `vtc/elections/*` request to a community this persona may hold no
    /// membership with ([`crate::elections`]).
    ElectionAnswer,
}

impl ReplyKind {
    /// How long a request of this kind waits for its answer.
    #[must_use]
    pub const fn ttl(self) -> Duration {
        match self {
            ReplyKind::Renewal | ReplyKind::CommunityProfile => Duration::from_secs(600),
            ReplyKind::ElectionAnswer => Duration::from_secs(120),
        }
    }

    /// The most requests of this kind outstanding at once. A request past the
    /// cap is not recorded, and its answer is not taken.
    #[must_use]
    pub const fn capacity(self) -> usize {
        match self {
            ReplyKind::Renewal | ReplyKind::ElectionAnswer => 64,
            ReplyKind::CommunityProfile => 256,
        }
    }

    /// The key a thread id is recorded and looked up under, or `None` for a
    /// thread this kind can never answer.
    ///
    /// A renewal is sent with its document id as the DIDComm message id
    /// (`urn:uuid:<id>`), and a community may thread on either form, so it is
    /// keyed by the UUID. An election answer may thread on either form too. A
    /// profile answer threads on the document id exactly.
    fn key(self, thid: &str) -> Option<String> {
        let bare = || thid.strip_prefix("urn:uuid:").unwrap_or(thid);
        match self {
            ReplyKind::Renewal => Uuid::parse_str(bare()).ok().map(|id| id.to_string()),
            ReplyKind::CommunityProfile => Some(thid.to_string()),
            ReplyKind::ElectionAnswer => Some(bare().to_string()),
        }
    }

    /// Whether `from` is the community a request of this kind was sent to.
    /// An election's community may name itself with the `?src=` it is resolved
    /// through (VTI-KEY-163), so it is compared by DID.
    fn same_community(self, recorded: &str, from: &str) -> bool {
        match self {
            ReplyKind::Renewal | ReplyKind::CommunityProfile => recorded == from,
            ReplyKind::ElectionAnswer => vta_sdk::did_scid::same_reference(recorded, from),
        }
    }
}

/// What a request was for, recorded with it and handed back when its answer
/// is taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Purpose {
    /// A renewal `member_did` asked for.
    Renewal {
        /// The member DID the renewal was asked for.
        member_did: String,
    },
    /// A question for the community's profile.
    CommunityProfile,
    /// An election request.
    ElectionAnswer,
}

impl Purpose {
    /// Its kind.
    #[must_use]
    pub const fn kind(&self) -> ReplyKind {
        match self {
            Purpose::Renewal { .. } => ReplyKind::Renewal,
            Purpose::CommunityProfile => ReplyKind::CommunityProfile,
            Purpose::ElectionAnswer => ReplyKind::ElectionAnswer,
        }
    }
}

#[derive(Debug)]
struct Entry {
    community: String,
    purpose: Purpose,
    at: Instant,
}

impl Entry {
    fn live(&self, kind: ReplyKind, now: Instant) -> bool {
        now.saturating_duration_since(self.at) < kind.ttl()
    }
}

/// The requests we wait on an answer for: thread → community, purpose, and
/// when it was sent. See the [module docs](self).
#[derive(Debug, Default)]
pub struct PendingReplies {
    entries: HashMap<(ReplyKind, String), Entry>,
}

impl PendingReplies {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that the request threaded on `thid` was sent to `community`, so
    /// its answer is admitted. Done before the send, so an answer racing it is
    /// still recognised. Returns whether it was recorded: not for a thread the
    /// kind cannot be answered on, nor past the kind's capacity.
    pub fn record(&mut self, thid: &str, community: &str, purpose: Purpose) -> bool {
        self.record_at(thid, community, purpose, Instant::now())
    }

    fn record_at(&mut self, thid: &str, community: &str, purpose: Purpose, now: Instant) -> bool {
        let kind = purpose.kind();
        let Some(key) = kind.key(thid) else {
            return false;
        };
        self.entries.retain(|(k, _), e| e.live(*k, now));
        if self.entries.keys().filter(|(k, _)| *k == kind).count() >= kind.capacity() {
            return false;
        }
        self.entries.insert(
            (kind, key),
            Entry {
                community: community.to_string(),
                purpose,
                at: now,
            },
        );
        true
    }

    /// Whether `thid` answers a request of `kind` sent to `community`, still
    /// waited for. Does not consume it: an answer is [taken](Self::take) only
    /// once it has been verified, so a forged one cannot cancel the genuine
    /// answer still on its way.
    #[must_use]
    pub fn is_awaited(&self, kind: ReplyKind, community: &str, thid: &str) -> bool {
        self.is_awaited_at(kind, community, thid, Instant::now())
    }

    fn is_awaited_at(&self, kind: ReplyKind, community: &str, thid: &str, now: Instant) -> bool {
        self.live_entry(kind, community, thid, now).is_some()
    }

    /// Take the request of `kind` that `thid` answers, if it was sent to
    /// `community` and is still waited for. Consumes it: a request is answered
    /// once. An answer from any other community leaves it waiting.
    pub fn take(&mut self, kind: ReplyKind, community: &str, thid: &str) -> Option<Purpose> {
        self.take_at(kind, community, thid, Instant::now())
    }

    fn take_at(
        &mut self,
        kind: ReplyKind,
        community: &str,
        thid: &str,
        now: Instant,
    ) -> Option<Purpose> {
        let key = self.live_entry(kind, community, thid, now)?;
        self.entries.remove(&(kind, key)).map(|e| e.purpose)
    }

    /// Stop waiting on `thid`: its send failed, its view gave up on it, or its
    /// answer was taken elsewhere.
    pub fn forget(&mut self, kind: ReplyKind, thid: &str) {
        if let Some(key) = kind.key(thid) {
            self.entries.remove(&(kind, key));
        }
    }

    /// The key of the live entry of `kind` on `thid` sent to `community`.
    fn live_entry(
        &self,
        kind: ReplyKind,
        community: &str,
        thid: &str,
        now: Instant,
    ) -> Option<String> {
        let key = kind.key(thid)?;
        let entry = self.entries.get(&(kind, key.clone()))?;
        (entry.live(kind, now) && kind.same_community(&entry.community, community)).then_some(key)
    }

    /// How many requests are waited on (expired ones included until the next
    /// [`record`](Self::record) prunes them).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is waited on.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VTC: &str = "did:webvh:QmVtc:vtc.example";
    const MEMBER: &str = "did:example:member";

    fn renewal() -> Purpose {
        Purpose::Renewal {
            member_did: MEMBER.into(),
        }
    }

    /// A renewal answer is taken only from the community asked, only once, and
    /// on either form of the thread id.
    #[test]
    fn a_renewal_is_bound_to_the_request_it_answers() {
        let mut t = PendingReplies::new();
        let id = Uuid::new_v4();
        assert!(t.record(&id.to_string(), VTC, renewal()));
        assert!(!t.is_awaited(ReplyKind::Renewal, "did:example:other", &id.to_string()));
        assert!(t.is_awaited(ReplyKind::Renewal, VTC, &format!("urn:uuid:{id}")));
        assert_eq!(
            t.take(ReplyKind::Renewal, VTC, &id.to_string()),
            Some(renewal())
        );
        assert!(
            t.take(ReplyKind::Renewal, VTC, &id.to_string()).is_none(),
            "answered once"
        );
    }

    /// A renewal is keyed by its UUID, so a thread that is not one never
    /// matches — and an upper-case rendering of the same UUID does.
    #[test]
    fn a_renewal_thread_is_normalised_to_its_uuid() {
        let mut t = PendingReplies::new();
        let id = Uuid::new_v4();
        assert!(!t.record("not-a-uuid", VTC, renewal()));
        assert!(t.record(&format!("urn:uuid:{id}"), VTC, renewal()));
        let upper = id.to_string().to_uppercase();
        assert!(t.is_awaited(ReplyKind::Renewal, VTC, &upper));
        assert!(!t.is_awaited(ReplyKind::Renewal, VTC, "garbage"));
    }

    /// A profile answer threads on the document id exactly: no prefix
    /// stripping.
    #[test]
    fn a_profile_answer_is_taken_once_and_only_from_the_community_asked() {
        let mut t = PendingReplies::new();
        t.record("urn:uuid:q1", "did:webvh:vtc", Purpose::CommunityProfile);
        assert!(
            t.take(
                ReplyKind::CommunityProfile,
                "did:webvh:mallory",
                "urn:uuid:q1"
            )
            .is_none()
        );
        assert!(
            t.take(
                ReplyKind::CommunityProfile,
                "did:webvh:vtc",
                "urn:uuid:other"
            )
            .is_none()
        );
        assert!(
            t.take(ReplyKind::CommunityProfile, "did:webvh:vtc", "q1")
                .is_none(),
            "exact thread only"
        );
        assert_eq!(
            t.take(ReplyKind::CommunityProfile, "did:webvh:vtc", "urn:uuid:q1"),
            Some(Purpose::CommunityProfile)
        );
        assert!(
            t.take(ReplyKind::CommunityProfile, "did:webvh:vtc", "urn:uuid:q1")
                .is_none(),
            "answered once"
        );
    }

    /// An election answer is admitted only on a thread sent to that community,
    /// on either form of the thread, and no longer once forgotten.
    #[test]
    fn an_election_answer_is_admitted_only_on_its_thread() {
        let mut t = PendingReplies::new();
        let thid = "urn:uuid:00000000-0000-4000-8000-0000000000bb";
        assert!(!t.is_awaited(ReplyKind::ElectionAnswer, VTC, thid));
        t.record(thid, VTC, Purpose::ElectionAnswer);
        assert!(t.is_awaited(ReplyKind::ElectionAnswer, VTC, thid));
        assert!(t.is_awaited(
            ReplyKind::ElectionAnswer,
            VTC,
            "00000000-0000-4000-8000-0000000000bb"
        ));
        assert!(!t.is_awaited(ReplyKind::ElectionAnswer, "did:key:z6MkSomeoneElse", thid));
        t.forget(ReplyKind::ElectionAnswer, thid);
        assert!(!t.is_awaited(ReplyKind::ElectionAnswer, VTC, thid));
    }

    /// An election's community is compared by DID, so a `?src=` on the name it
    /// answers under does not make it someone else.
    #[test]
    fn an_election_community_is_compared_by_did() {
        let mut t = PendingReplies::new();
        let scid = "did:scid:vh:1:QmScid";
        t.record("t1", scid, Purpose::ElectionAnswer);
        assert!(t.is_awaited(
            ReplyKind::ElectionAnswer,
            &format!("{scid}?src=vtc.example"),
            "t1"
        ));
        // Renewals compare exactly.
        let id = Uuid::new_v4().to_string();
        t.record(&id, scid, renewal());
        assert!(!t.is_awaited(ReplyKind::Renewal, &format!("{scid}?src=vtc.example"), &id));
    }

    /// Each kind waits its own window.
    #[test]
    fn each_kind_expires_on_its_own_window() {
        let mut t = PendingReplies::new();
        let now = Instant::now();
        let id = Uuid::new_v4().to_string();
        t.record_at(&id, VTC, renewal(), now);
        t.record_at("p", VTC, Purpose::CommunityProfile, now);
        t.record_at("e", VTC, Purpose::ElectionAnswer, now);

        let before_election = now + Duration::from_secs(119);
        assert!(t.is_awaited_at(ReplyKind::ElectionAnswer, VTC, "e", before_election));
        let after_election = now + Duration::from_secs(120);
        assert!(!t.is_awaited_at(ReplyKind::ElectionAnswer, VTC, "e", after_election));
        assert!(t.is_awaited_at(ReplyKind::Renewal, VTC, &id, after_election));
        assert!(t.is_awaited_at(ReplyKind::CommunityProfile, VTC, "p", after_election));

        let after_all = now + Duration::from_secs(600);
        assert!(!t.is_awaited_at(ReplyKind::Renewal, VTC, &id, after_all));
        assert!(
            t.take_at(ReplyKind::CommunityProfile, VTC, "p", after_all)
                .is_none(),
            "an expired request is not taken"
        );
    }

    /// Each kind has its own cap, and a request past it is not recorded.
    /// Expired requests make room.
    #[test]
    fn each_kind_is_capped_on_its_own() {
        let mut t = PendingReplies::new();
        let now = Instant::now();
        for i in 0..64 {
            assert!(t.record_at(&format!("e{i}"), VTC, Purpose::ElectionAnswer, now));
        }
        assert!(!t.record_at("e-over", VTC, Purpose::ElectionAnswer, now));
        assert!(!t.is_awaited_at(ReplyKind::ElectionAnswer, VTC, "e-over", now));
        // Another kind is not crowded out.
        for i in 0..256 {
            assert!(t.record_at(&format!("p{i}"), VTC, Purpose::CommunityProfile, now));
        }
        assert!(!t.record_at("p-over", VTC, Purpose::CommunityProfile, now));
        for _ in 0..64 {
            assert!(t.record_at(&Uuid::new_v4().to_string(), VTC, renewal(), now));
        }
        assert!(!t.record_at(&Uuid::new_v4().to_string(), VTC, renewal(), now));

        // Once the election window passes, its requests are pruned on the next
        // record and there is room again.
        let later = now + ReplyKind::ElectionAnswer.ttl();
        assert!(t.record_at("e-later", VTC, Purpose::ElectionAnswer, later));
    }

    /// A take or check from the wrong community leaves the request waiting
    /// for the right one; kinds do not answer for each other.
    #[test]
    fn the_wrong_community_or_kind_takes_nothing() {
        let mut t = PendingReplies::new();
        let id = Uuid::new_v4().to_string();
        t.record(&id, VTC, renewal());
        assert!(
            t.take(ReplyKind::Renewal, "did:example:mallory", &id)
                .is_none()
        );
        assert!(t.take(ReplyKind::ElectionAnswer, VTC, &id).is_none());
        assert!(t.take(ReplyKind::CommunityProfile, VTC, &id).is_none());
        assert!(t.take(ReplyKind::Renewal, VTC, &id).is_some());
        assert!(t.is_empty());
    }

    /// Forgetting removes only that kind's request on that thread.
    #[test]
    fn forgetting_is_per_kind() {
        let mut t = PendingReplies::new();
        let id = Uuid::new_v4().to_string();
        t.record(&id, VTC, renewal());
        t.record(&id, VTC, Purpose::ElectionAnswer);
        assert_eq!(t.len(), 2);
        t.forget(ReplyKind::Renewal, &format!("urn:uuid:{id}"));
        assert!(!t.is_awaited(ReplyKind::Renewal, VTC, &id));
        assert!(t.is_awaited(ReplyKind::ElectionAnswer, VTC, &id));
    }
}
