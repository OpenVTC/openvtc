//! Questions put to a community whose answers arrive later: its manifest, the
//! vetter directory, a vetter's own profile, and a resend of a vetter's grant.
//!
//! Each question is a signed Trust Task sent over DIDComm. The answer is a
//! `#response` — or a `trust-task-error` — threaded on it, and it reaches the
//! inbound handler whenever the community gets round to it. Matching the two
//! takes the request's document id, which is what a [`CommunityQuery`] keeps.
//!
//! Questions live in memory only (`#[serde(skip)]` on the book). After a
//! restart nobody is waiting for an answer, and an answer to a question we no
//! longer remember is dropped. That is the right outcome for a directory page
//! nobody is looking at, and it also means a `trust-task-error` is claimed only
//! when it answers something we asked. Anything else still reaches the join
//! handler, which owns the other errors a community sends.

use chrono::{DateTime, Duration, Utc};
use vta_sdk::protocols::vetting::{
    VETTING_VETTER_PROFILE_ERR_NOT_ELIGIBLE, VETTING_VETTER_RESEND_ERR_NOT_GRANTED, vetters,
};

use super::book::VettingBook;
use crate::config::account::PersonaId;

/// How long a question waits before the person asking is told there was no
/// answer (R1.2: a quiet community is an error, not a hang).
pub const QUERY_TIMEOUT: Duration = Duration::seconds(30);

/// What was asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryKind {
    /// `vtc/join-requests/manifest/0.2`.
    Manifest,
    /// `vtc/vetting/vetters/list/0.1`.
    VetterList,
    /// `vtc/vetting/vetters/profile/0.1`.
    VetterProfile,
    /// `vtc/vetting/vetters/resend/0.1`.
    VetterResend,
}

impl QueryKind {
    /// What was asked for, as the end of "no answer about …".
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            QueryKind::Manifest => "its vetting requirements",
            QueryKind::VetterList => "its vetter directory",
            QueryKind::VetterProfile => "your vetter profile",
            QueryKind::VetterResend => "your vetter credential",
        }
    }
}

/// A question put to a community.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommunityQuery {
    /// The request document's id — what the answer threads on.
    pub document_id: String,
    /// The community asked.
    pub community: String,
    /// The persona that asked.
    pub persona: PersonaId,
    /// What was asked.
    pub kind: QueryKind,
    /// When.
    pub sent_at: DateTime<Utc>,
}

/// An answer to a [`CommunityQuery`], for whoever asked. Nothing here is
/// persisted; a published profile's record is updated by the handler itself.
///
/// No `PartialEq`: a directory page is the generated
/// `vtc/vetting/vetters/list/0.1` response, and the generated wire types derive
/// only `Serialize`, `Deserialize`, `Clone` and `Debug`. Comparing two answers
/// means comparing what they carry.
#[derive(Clone, Debug)]
pub enum CommunityAnswer {
    /// The community's manifest arrived and its requirements are now known.
    Manifest {
        /// The community.
        community: String,
    },
    /// A page of the vetter directory.
    Vetters {
        /// The list request's document id.
        query: String,
        /// The community.
        community: String,
        /// The page.
        page: vetters::list::v0_1::Response,
    },
    /// The community stored our vetter profile.
    ProfileStored {
        /// The community.
        community: String,
        /// Whether it lists us.
        listed: bool,
        /// When it stored the profile.
        updated_at: DateTime<Utc>,
    },
    /// The community is delivering our vetter credential again.
    Resent {
        /// The community.
        community: String,
        /// The credential's `validUntil`.
        valid_until: DateTime<Utc>,
    },
    /// The community refused the question.
    Refused {
        /// The request's document id.
        query: String,
        /// The community.
        community: String,
        /// What was asked.
        kind: QueryKind,
        /// The error code.
        code: String,
        /// The community's note, if any.
        message: Option<String>,
    },
    /// The community answered in a shape this client cannot read — a contract
    /// mismatch, not a refusal (R6.4).
    Unreadable {
        /// The request's document id.
        query: String,
        /// The community.
        community: String,
        /// What was asked.
        kind: QueryKind,
        /// The parser's detail.
        detail: String,
    },
}

impl CommunityAnswer {
    /// The community that answered.
    #[must_use]
    pub fn community(&self) -> &str {
        match self {
            CommunityAnswer::Manifest { community }
            | CommunityAnswer::Vetters { community, .. }
            | CommunityAnswer::ProfileStored { community, .. }
            | CommunityAnswer::Resent { community, .. }
            | CommunityAnswer::Refused { community, .. }
            | CommunityAnswer::Unreadable { community, .. } => community,
        }
    }
}

/// A refusal in words the person who asked can act on. `community` is the
/// community's display name.
///
/// The codes the registry defines get their own sentence. A framework code
/// says which kind of failure it was, because "denied", "could not read" and
/// "something broke there" call for different next steps (R6.4).
#[must_use]
pub fn refusal_words(kind: QueryKind, community: &str, code: &str) -> String {
    match code {
        VETTING_VETTER_PROFILE_ERR_NOT_ELIGIBLE => format!(
            "{community} did not accept your profile: it does not count you as an active member \
             holding a live vetter credential. If it named you a vetter, ask it to resend the \
             credential."
        ),
        VETTING_VETTER_RESEND_ERR_NOT_GRANTED => format!(
            "{community} holds no live vetter credential for you — it has not named you a \
             vetter, or the grant expired or was revoked. Ask its admins for the vetter role."
        ),
        c if c.ends_with("permissionDenied") => format!(
            "{community} would not answer this persona about {} ({code}).",
            kind.describe()
        ),
        c if c.ends_with("malformedRequest") => format!(
            "{community} could not read the request for {} ({code}) — this client and the \
             community disagree about the task, so try again after updating.",
            kind.describe()
        ),
        _ => format!(
            "{community} refused the request for {} ({code}).",
            kind.describe()
        ),
    }
}

impl VettingBook {
    /// Remember a question sent to a community.
    pub fn ask(&mut self, query: CommunityQuery) {
        self.queries.push(query);
    }

    /// The unanswered question of `kind` to `community`, if there is one.
    #[must_use]
    pub fn waiting_on(&self, community: &str, kind: QueryKind) -> Option<&CommunityQuery> {
        self.queries
            .iter()
            .find(|q| q.community == community && q.kind == kind)
    }

    /// Take the question `community`'s reply threaded on `thread` answers.
    /// `kind`, when given, must match too: a directory page threaded on a
    /// profile request answers nothing.
    pub fn take_query(
        &mut self,
        community: &str,
        thread: &str,
        kind: Option<QueryKind>,
    ) -> Option<CommunityQuery> {
        let i = self.queries.iter().position(|q| {
            q.community == community && q.document_id == thread && kind.is_none_or(|k| q.kind == k)
        })?;
        Some(self.queries.remove(i))
    }

    /// Take a manifest question to `community`: the one `thread` names, or else
    /// any. A manifest is the same whoever asked, so a reply to one question
    /// answers every question about it.
    pub fn take_manifest_queries(
        &mut self,
        community: &str,
        thread: Option<&str>,
    ) -> Vec<CommunityQuery> {
        let threaded =
            thread.and_then(|t| self.take_query(community, t, Some(QueryKind::Manifest)));
        let mut taken: Vec<CommunityQuery> = threaded.into_iter().collect();
        let (answered, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut self.queries)
            .into_iter()
            .partition(|q| q.community == community && q.kind == QueryKind::Manifest);
        self.queries = rest;
        taken.extend(answered);
        taken
    }

    /// Forget a question whose send failed, so nothing waits for it.
    pub fn forget_query(&mut self, document_id: &str) -> Option<CommunityQuery> {
        let i = self
            .queries
            .iter()
            .position(|q| q.document_id == document_id)?;
        Some(self.queries.remove(i))
    }

    /// Remove and return every question unanswered for `after`.
    pub fn expire_queries(&mut self, now: DateTime<Utc>, after: Duration) -> Vec<CommunityQuery> {
        let (expired, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut self.queries)
            .into_iter()
            .partition(|q| now - q.sent_at >= after);
        self.queries = rest;
        expired
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(id: &str, community: &str, kind: QueryKind, sent_at: DateTime<Utc>) -> CommunityQuery {
        CommunityQuery {
            document_id: id.into(),
            community: community.into(),
            persona: PersonaId::new(),
            kind,
            sent_at,
        }
    }

    #[test]
    fn a_reply_takes_only_the_question_it_threads_on() {
        let now = Utc::now();
        let mut book = VettingBook::default();
        book.ask(query("q1", "did:web:a", QueryKind::VetterList, now));
        book.ask(query("q2", "did:web:a", QueryKind::VetterProfile, now));

        assert!(
            book.take_query("did:web:b", "q1", None).is_none(),
            "another community cannot answer our question"
        );
        assert!(
            book.take_query("did:web:a", "q2", Some(QueryKind::VetterList))
                .is_none(),
            "a directory page does not answer a profile request"
        );
        assert_eq!(
            book.take_query("did:web:a", "q1", Some(QueryKind::VetterList))
                .map(|q| q.document_id),
            Some("q1".to_string())
        );
        assert!(book.take_query("did:web:a", "q1", None).is_none(), "once");
        assert!(
            book.waiting_on("did:web:a", QueryKind::VetterProfile)
                .is_some()
        );
    }

    #[test]
    fn a_manifest_answers_every_question_about_it() {
        let now = Utc::now();
        let mut book = VettingBook::default();
        book.ask(query("m1", "did:web:a", QueryKind::Manifest, now));
        book.ask(query("m2", "did:web:a", QueryKind::Manifest, now));
        book.ask(query("m3", "did:web:b", QueryKind::Manifest, now));
        let taken = book.take_manifest_queries("did:web:a", Some("unrelated-thread"));
        assert_eq!(taken.len(), 2);
        assert_eq!(book.queries.len(), 1);
    }

    #[test]
    fn unanswered_questions_expire_and_are_not_persisted() {
        let now = Utc::now();
        let mut book = VettingBook::default();
        book.ask(query(
            "old",
            "did:web:a",
            QueryKind::VetterResend,
            now - QUERY_TIMEOUT,
        ));
        book.ask(query("new", "did:web:a", QueryKind::VetterList, now));
        let expired = book.expire_queries(now, QUERY_TIMEOUT);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].document_id, "old");
        assert!(book.is_empty(), "questions are memory only");
        assert_eq!(serde_json::to_value(&book).unwrap(), serde_json::json!({}));
    }

    #[test]
    fn refusals_say_what_to_do_next() {
        let not_granted = refusal_words(
            QueryKind::VetterResend,
            "Kernel",
            VETTING_VETTER_RESEND_ERR_NOT_GRANTED,
        );
        assert!(not_granted.contains("has not named you a vetter"));
        let not_eligible = refusal_words(
            QueryKind::VetterProfile,
            "Kernel",
            VETTING_VETTER_PROFILE_ERR_NOT_ELIGIBLE,
        );
        assert!(not_eligible.contains("resend"));
        assert!(
            refusal_words(QueryKind::VetterList, "Kernel", "permissionDenied")
                .contains("would not answer this persona")
        );
        assert!(
            refusal_words(QueryKind::VetterList, "Kernel", "malformedRequest").contains("disagree")
        );
    }
}
