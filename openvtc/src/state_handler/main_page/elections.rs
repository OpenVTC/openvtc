//! The Elections panel's state: a community's elections, from the member's side.
//!
//! Display state only, rebuilt from the community's answers (`vtc/elections/list/0.3`,
//! `vtc/elections/show/0.3`) on every open and refresh. **Nothing here is persisted.** The
//! member's VTA holds the voter keys, the ticket and the receipts; the community holds the
//! record of who took a ticket; a copy kept here would be a third record to disagree.
//!
//! The one thing kept between views is when this app took a ticket
//! ([`ElectionsState::tickets_taken`]), in memory only, so the ballot screen can warn that a
//! vote cast straight after its ticket could be paired with it by time.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use openvtc_core::config::account::PersonaId;
use openvtc_core::elections::{
    AnswerDraft, BallotDraft, Cast, ElectionListItem, Kept, Manifest, Question, ReceiptOutcome,
    ShownElection, TicketRequest, VerifiedReceipt, question_optional, question_options,
};

pub use super::repos::{Severity, Status};

/// How recent a ticket taken by this app must be for the ballot screen to warn about timing.
pub const TICKET_TIMING_WINDOW: Duration = Duration::from_secs(60 * 60);

/// Whether the list has been read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ElectionsPhase {
    Loading,
    Loaded,
    /// The first read failed, and why.
    Failed(String),
}

/// Which screen of the panel is showing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    List,
    Detail,
    Ballot,
    Confirm,
    Result,
}

/// What a read of one election is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Intent {
    /// Show it.
    View,
    /// Take the ticket, and nothing else.
    Ticket,
    /// Vote — or, with no ticket held, take it and stop.
    Vote,
}

/// What an outstanding request to the community is for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// A page of the list.
    List,
    /// One election, read for `intent`.
    Show { election: String, intent: Intent },
    /// The ticket request for `election`.
    Issue { election: String },
}

/// A request to the community awaiting its answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pending {
    pub thid: String,
    pub sent_at: Instant,
    pub purpose: Purpose,
}

/// Where a ticket or a vote is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Reading the election again.
    Reading,
    /// The VTA is building the ticket request.
    Registering,
    /// The community is signing the ticket blind.
    Issuing,
    /// The VTA is unblinding the ticket.
    Accepting,
    /// The VTA is building and signing the cast.
    Building,
    /// The cast is on its way to the ballot box (after a pause).
    Casting,
    /// The VTA is keeping the receipt.
    Keeping,
}

impl Step {
    #[must_use]
    pub fn words(self) -> &'static str {
        match self {
            Step::Reading => "reading the election",
            Step::Registering => "your VTA is preparing the ticket request",
            Step::Issuing => "the community is signing your ticket without seeing it",
            Step::Accepting => "your VTA is taking the ticket",
            Step::Building => "your VTA is sealing your ballot under a one-time key",
            Step::Casting => {
                "waiting a moment (up to 20 s), then sending your ballot to the ballot box"
            }
            Step::Keeping => "your VTA is keeping the receipt",
        }
    }
}

/// A ticket or a vote in progress. One at a time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Flow {
    pub election: String,
    pub intent: Intent,
    pub step: Step,
}

/// The next step an answer calls for. Taken by the loop
/// ([`crate::state_handler::elections_actions::advance`]), which alone can send; a step that
/// finds its lane busy waits here for the next tick.
#[derive(Clone, Debug)]
pub enum Next {
    Refresh,
    ListPage {
        cursor: String,
    },
    /// Have the VTA build the ticket request.
    Register,
    /// Carry the ticket request to the community.
    SendIssue(TicketRequest),
    /// Hand the community's answer to the VTA.
    Accept {
        issued: serde_json::Value,
    },
    /// Have the VTA build the cast for this ballot.
    Vote {
        ballot: serde_json::Value,
    },
    /// Send the cast to the ballot box.
    Deliver(Cast),
    /// Hand the receipt to the VTA.
    Keep(Box<VerifiedReceipt>),
}

/// How a vote ended, for the result screen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VoteResult {
    /// The ballot box counted it; `kept` is what the VTA said of the receipt (`None` while it
    /// is being kept, or when it could not be).
    Counted {
        outcome: ReceiptOutcome,
        leaf_index: u64,
        kept: Option<Kept>,
        keep_error: Option<String>,
    },
    /// It did not reach a receipt; `resend` says whether sending the same cast again is the fix.
    Failed { why: String, resend: bool },
}

/// The ballot as the member fills it in, and where the cursor is.
#[derive(Clone, Debug)]
pub struct BallotForm {
    pub draft: BallotDraft,
    /// The focused question, an index into the manifest's questions as the draft holds them.
    pub question: usize,
    /// The focused option within it.
    pub option: usize,
    /// Why the last review did not pass.
    pub error: Option<String>,
}

/// The manifest question a draft answer answers.
fn question_for<'m>(manifest: &'m Manifest, key: &str) -> Option<&'m Question> {
    manifest
        .questions
        .iter()
        .find(|q| openvtc_core::elections::question_key(q) == Some(key))
}

impl BallotForm {
    #[must_use]
    pub fn new(manifest: &Manifest) -> Self {
        Self {
            draft: BallotDraft::new(manifest),
            question: 0,
            option: 0,
            error: None,
        }
    }

    /// The focused question.
    #[must_use]
    pub fn focused<'m>(&self, manifest: &'m Manifest) -> Option<&'m Question> {
        let (key, _, _) = self.draft.answers.get(self.question)?;
        question_for(manifest, key)
    }

    /// Move to another question; the option cursor goes to its first.
    pub fn move_question(&mut self, delta: isize) {
        let last = self.draft.answers.len().saturating_sub(1);
        self.question = self.question.saturating_add_signed(delta).min(last);
        self.option = 0;
    }

    /// Move the option cursor within the focused question.
    pub fn move_option(&mut self, manifest: &Manifest, delta: isize) {
        let n = self
            .focused(manifest)
            .map_or(0, |q| question_options(q).len());
        self.option = self
            .option
            .saturating_add_signed(delta)
            .min(n.saturating_sub(1));
    }

    /// Space: choose or unchoose the focused option (a single choice replaces), or put it in
    /// or take it out of a ranking (in goes last).
    pub fn toggle(&mut self, manifest: &Manifest) {
        let Some(q) = self.focused(manifest) else {
            return;
        };
        let Some(opt) = question_options(q).get(self.option) else {
            return;
        };
        let opt = opt.key.to_string();
        let single =
            matches!(q, Question::Choice { max_selections, .. } if max_selections.get() == 1);
        let Some((_, draft, abstain)) = self.draft.answers.get_mut(self.question) else {
            return;
        };
        match draft {
            AnswerDraft::Choice(chosen) | AnswerDraft::Ranking(chosen) => {
                if let Some(i) = chosen.iter().position(|k| *k == opt) {
                    chosen.remove(i);
                } else if single {
                    *chosen = vec![opt];
                } else {
                    chosen.push(opt);
                }
                *abstain = false;
            }
            AnswerDraft::Scores(_) | AnswerDraft::Text(_) => {}
        }
        self.error = None;
    }

    /// `+`/`-` on a score: the first press gives the question's lowest score, then steps
    /// within its bounds.
    pub fn adjust(&mut self, manifest: &Manifest, delta: i64) {
        let Some(Question::Score { min, max, .. }) = self.focused(manifest) else {
            return;
        };
        let (min, max) = (*min, *max);
        let option = self.option;
        if let Some((_, AnswerDraft::Scores(scores), abstain)) =
            self.draft.answers.get_mut(self.question)
            && let Some((_, value)) = scores.get_mut(option)
        {
            *value = Some(match value {
                None => min,
                Some(v) => v.saturating_add(delta).clamp(min, max),
            });
            *abstain = false;
        }
        self.error = None;
    }

    /// A character typed into a text answer, up to its length.
    pub fn type_char(&mut self, manifest: &Manifest, c: char) {
        let Some(Question::Text { max_length, .. }) = self.focused(manifest) else {
            return;
        };
        let max = max_length.get();
        if let Some((_, AnswerDraft::Text(text), abstain)) =
            self.draft.answers.get_mut(self.question)
            && (text.chars().count() as u64) < max
            && !c.is_control()
        {
            text.push(c);
            *abstain = false;
        }
        self.error = None;
    }

    pub fn backspace(&mut self) {
        if let Some((_, AnswerDraft::Text(text), _)) = self.draft.answers.get_mut(self.question) {
            text.pop();
        }
    }

    /// Leave the focused question blank (abstain), or answer it again — an optional one only.
    pub fn toggle_abstain(&mut self, manifest: &Manifest) {
        let optional = self.focused(manifest).is_some_and(question_optional);
        if !optional {
            self.error = Some("This question must be answered; it cannot be left blank.".into());
            return;
        }
        if let Some((_, _, abstain)) = self.draft.answers.get_mut(self.question) {
            *abstain = !*abstain;
        }
        self.error = None;
    }

    /// Whether the focused question is a text question (its keys type).
    #[must_use]
    pub fn typing(&self, manifest: &Manifest) -> bool {
        matches!(self.focused(manifest), Some(Question::Text { .. }))
    }
}

/// The open panel.
#[derive(Clone, Debug)]
pub struct ElectionsView {
    pub vtc_did: String,
    pub persona: PersonaId,
    /// The persona DID the community knows the member by.
    pub me: String,
    pub community: String,
    pub phase: ElectionsPhase,
    pub screen: Screen,
    /// The list, as the community last answered, in display order.
    pub elections: Vec<ElectionListItem>,
    incoming: Vec<ElectionListItem>,
    pub selected: usize,
    /// The election being looked at, as last read.
    pub shown: Option<Box<ShownElection>>,
    pub form: Option<BallotForm>,
    pub pending: Option<Pending>,
    pub flow: Option<Flow>,
    pub next: Option<Next>,
    /// The cast last built and not yet answered with a receipt: resent unchanged, never rebuilt.
    pub cast: Option<Cast>,
    pub result: Option<VoteResult>,
    pub status: Option<Status>,
}

impl ElectionsView {
    #[must_use]
    pub fn new(vtc_did: String, persona: PersonaId, me: String, community: String) -> Self {
        Self {
            vtc_did,
            persona,
            me,
            community,
            phase: ElectionsPhase::Loading,
            screen: Screen::List,
            elections: Vec::new(),
            incoming: Vec::new(),
            selected: 0,
            shown: None,
            form: None,
            pending: None,
            flow: None,
            next: None,
            cast: None,
            result: None,
            status: None,
        }
    }

    #[must_use]
    pub fn selected_item(&self) -> Option<&ElectionListItem> {
        self.elections.get(self.selected)
    }

    /// Take one page of the list; `last` says whether it was the last.
    pub fn take_page(&mut self, items: Vec<ElectionListItem>, last: bool) {
        self.incoming.extend(items);
        if last {
            let mut all = std::mem::take(&mut self.incoming);
            openvtc_core::elections::sort_for_display(&mut all);
            self.elections = all;
            self.selected = self.selected.min(self.elections.len().saturating_sub(1));
            self.phase = ElectionsPhase::Loaded;
        }
    }

    pub fn restart_pages(&mut self) {
        self.incoming.clear();
    }

    pub fn note(&mut self, severity: Severity, text: impl Into<String>) {
        self.status = Some(Status {
            text: text.into(),
            severity,
        });
    }

    pub fn clear_progress(&mut self) {
        if self
            .status
            .as_ref()
            .is_some_and(|s| s.severity == Severity::Progress)
        {
            self.status = None;
        }
    }

    /// Leave the ballot behind: after a vote, or when the member backs out of it.
    pub fn drop_ballot(&mut self) {
        self.form = None;
    }
}

/// The panel, when open, and what outlives it.
#[derive(Clone, Debug, Default)]
pub struct ElectionsState {
    pub view: Option<ElectionsView>,
    /// When this app took a ticket, by `(community, election)`. In memory only.
    pub tickets_taken: HashMap<(String, String), Instant>,
}

impl ElectionsState {
    /// Whether this app took `election`'s ticket at `vtc` within [`TICKET_TIMING_WINDOW`].
    #[must_use]
    pub fn ticket_taken_recently(&self, vtc: &str, election: &str, now: Instant) -> bool {
        self.tickets_taken
            .get(&(vtc.to_string(), election.to_string()))
            .is_some_and(|t| now.duration_since(*t) < TICKET_TIMING_WINDOW)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn manifest() -> Manifest {
        serde_json::from_value(json!({
            "electionId": "agm", "community": "did:key:z6MkC",
            "questions": [
                { "key": "chair", "type": "choice", "options": [{ "key": "a" }, { "key": "b" }],
                  "minSelections": 1, "maxSelections": 1, "optional": false },
                { "key": "board", "type": "choice", "options": [{ "key": "x" }, { "key": "y" }],
                  "minSelections": 0, "maxSelections": 2, "optional": true },
                { "key": "order", "type": "ranking", "options": [{ "key": "p" }, { "key": "q" }],
                  "partial": false, "optional": false },
                { "key": "score", "type": "score", "options": [{ "key": "s" }],
                  "min": 1, "max": 3, "optional": false },
                { "key": "note", "type": "text", "maxLength": 3, "optional": true }
            ],
            "secrecy": "open", "roll": { "rule": "members" },
            "registrationOpensAt": "2026-10-01T00:00:00Z", "votingOpensAt": "2026-10-02T00:00:00Z",
            "votingClosesAt": "2026-12-01T00:00:00Z", "revote": "replace",
            "board": { "visibility": "public", "auditors": [] }, "ballotBox": "did:key:z6MkB",
            "binding": false, "allowEarlyClose": false, "resultsBeforeClose": false,
            "textReleaseThreshold": 10
        }))
        .unwrap()
    }

    #[test]
    fn a_single_choice_is_a_radio_and_a_multiple_one_a_checkbox() {
        let m = manifest();
        let mut f = BallotForm::new(&m);
        f.toggle(&m);
        f.move_option(&m, 1);
        f.toggle(&m);
        assert_eq!(f.draft.answers[0].1, AnswerDraft::Choice(vec!["b".into()]));
        f.move_question(1);
        f.toggle(&m);
        f.move_option(&m, 1);
        f.toggle(&m);
        assert_eq!(
            f.draft.answers[1].1,
            AnswerDraft::Choice(vec!["x".into(), "y".into()])
        );
        f.toggle(&m);
        assert_eq!(f.draft.answers[1].1, AnswerDraft::Choice(vec!["x".into()]));
    }

    #[test]
    fn a_ranking_is_built_in_the_order_options_are_toggled_in() {
        let m = manifest();
        let mut f = BallotForm::new(&m);
        f.move_question(2);
        f.move_option(&m, 1);
        f.toggle(&m);
        f.move_option(&m, -1);
        f.toggle(&m);
        assert_eq!(
            f.draft.answers[2].1,
            AnswerDraft::Ranking(vec!["q".into(), "p".into()])
        );
    }

    #[test]
    fn a_score_starts_at_its_lowest_and_stays_in_bounds() {
        let m = manifest();
        let mut f = BallotForm::new(&m);
        f.move_question(3);
        f.adjust(&m, 1);
        assert_eq!(
            f.draft.answers[3].1,
            AnswerDraft::Scores(vec![("s".into(), Some(1))])
        );
        for _ in 0..5 {
            f.adjust(&m, 1);
        }
        assert_eq!(
            f.draft.answers[3].1,
            AnswerDraft::Scores(vec![("s".into(), Some(3))])
        );
    }

    #[test]
    fn text_is_typed_up_to_its_length_and_only_optional_questions_abstain() {
        let m = manifest();
        let mut f = BallotForm::new(&m);
        f.move_question(4);
        assert!(f.typing(&m));
        for c in "abcd".chars() {
            f.type_char(&m, c);
        }
        assert_eq!(f.draft.answers[4].1, AnswerDraft::Text("abc".into()));
        f.backspace();
        assert_eq!(f.draft.answers[4].1, AnswerDraft::Text("ab".into()));
        f.toggle_abstain(&m);
        assert!(f.draft.answers[4].2);
        f.move_question(-4);
        f.toggle_abstain(&m);
        assert!(!f.draft.answers[0].2);
        assert!(f.error.is_some());
    }

    #[test]
    fn a_ticket_taken_within_the_hour_is_recent() {
        let mut s = ElectionsState::default();
        let now = Instant::now();
        s.tickets_taken
            .insert(("did:key:zVtc".into(), "agm".into()), now);
        assert!(s.ticket_taken_recently("did:key:zVtc", "agm", now));
        assert!(!s.ticket_taken_recently("did:key:zVtc", "other", now));
        assert!(!s.ticket_taken_recently(
            "did:key:zVtc",
            "agm",
            now + TICKET_TIMING_WINDOW + Duration::from_secs(1)
        ));
    }
}
