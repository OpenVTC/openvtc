//! Community elections — the member's side of `vtc/elections/*` and the voting tasks.
//!
//! A community runs an election; its **ballot box**, a separate service, takes the casts.
//! A member reads the elections (`vtc/elections/list/0.3`, `vtc/elections/show/0.3`), takes a
//! **ticket** — a credential the community signs blind — and later casts a ballot with it. Two
//! parties are kept from learning what they must not (VTI-VOT-001 – 004, the threat model in
//! VTI's `docs/05-design-notes/community-voting-threat-model.md`):
//!
//! - the **community** never learns how anyone voted, nor which cast a ticket became: nothing
//!   this module sends it carries a ballot, a cast or a receipt ([`Request`] has no variant that
//!   could);
//! - the **ballot box** never learns who holds a ticket: the cast is signed by a key the
//!   member's VTA makes for that cast alone, and is posted from this client's own connection
//!   ([`post_cast`]), after a random pause ([`cast_delay`]), never through the member's
//!   messaging session.
//!
//! # Who does what
//!
//! - **The community's tasks** (`list`, `show`, `tickets/issue`) are built here, signed with the
//!   persona's own `authentication` key and sent on the membership's transport, exactly as
//!   `vtc/rooms/*` are ([`crate::community_rooms`]); the answer arrives on the inbound channel and
//!   is matched by thread id ([`parse_reply`]).
//! - **The member's VTA** holds every voter key: it builds the blinded ticket request
//!   (`vta/pcs/voter/register/0.3`, [`register`]), unblinds the community's answer
//!   (`vta/pcs/voter/accept/0.1`, [`accept`]), builds and signs the cast
//!   (`vta/pcs/vote/0.3` / `vta/pcs/vote-encrypted/0.4`, [`vote`]) and keeps the receipt
//!   (`vta/pcs/voter/receipt/0.1`, [`keep_receipt`]). The voter keys are derived in the
//!   persona's own context.
//! - **The ballot box** is reached over its advertised `TrustTaskHTTPS` endpoint
//!   ([`ballot_box_endpoint`]) — the sessionless cast door VTI-VOT-004 requires — and its
//!   receipt is believed only once its proof is shown to be the ballot box's, answering this
//!   cast, addressed to the cast's one-time key ([`check_receipt`] → [`VerifiedReceipt`]).
//!
//! # Resumable
//!
//! Every step answers a repeat with its first answer: the VTA repeats the same ticket request
//! until the ticket is held (then refuses `ticketHeld`, read as "already held"), the community
//! answers a resent ticket request with its first answer, and the ballot box answers the same
//! cast document resent with the receipt it gave (`alreadyCounted`). So a flow interrupted at
//! any step is finished by starting it again (R2.1), and no step here retries on its own.
//!
//! # Ballots are not logged
//!
//! Nothing here logs a ballot, an answer or a cast; [`BallotDraft`]'s `Debug` says how many
//! questions it answers and nothing else.

use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use trust_tasks_rs::{RequestPayload, TrustTask};
use uuid::Uuid;
use vta_sdk::client::VtaClient;

use crate::errors::OpenVTCError;
use crate::specs::voting::ballot::{cast::v0_1 as cast, cast_encrypted::v0_1 as cast_encrypted};
use crate::specs::vta::pcs::{
    vote::v0_3 as pcs_vote, vote_encrypted::v0_4 as pcs_vote_encrypted,
    voter::accept::v0_1 as pcs_accept, voter::receipt::v0_1 as pcs_receipt,
    voter::register::v0_3 as pcs_register,
};
use crate::specs::vtc::elections::{
    list::v0_3 as list, show::v0_3 as show, tickets::issue::v0_1 as issue,
};

/// The generated `vtc/elections/list/0.3` item and state.
pub use list::{ElectionListItem, RegistrarState};
/// The generated `vtc/elections/show/0.3` manifest and its parts.
pub use show::{Disclosure, Manifest, Question, QuestionOption};

/// Every community task this module sends or reads starts with this.
const TYPE_PREFIX: &str = "https://trusttasks.org/spec/vtc/elections/";

/// The prefix every refusal document's type carries.
const ERROR_TYPE_PREFIX: &str = "https://trusttasks.org/spec/trust-task-error/";

/// Longest text from a peer kept for display.
const MAX_PEER_TEXT: usize = 512;

/// The longest pause before a cast is sent, so its arrival is not timed to anything the member
/// did a moment before (`pnm elections vote` waits the same).
pub const MAX_CAST_DELAY: Duration = Duration::from_secs(20);

/// Round-trip budget for an ordinary VTA call, in seconds.
const VTA_TIMEOUT_SECS: u64 = 30;
/// Round-trip budget for building a cast — proving is pairing-heavy.
const VTA_PROOF_TIMEOUT_SECS: u64 = 90;

/// How long resolving the ballot box's DID may take (R1.2).
pub const RESOLVE_TIMEOUT: Duration = Duration::from_secs(15);

// ****************************************************************************
// Requests to the community
// ****************************************************************************

/// The ticket request the member's VTA built (`vta/pcs/voter/register/0.3`'s answer), to carry to
/// the community as `vtc/elections/tickets/issue/0.1`.
#[derive(Clone, Debug, PartialEq)]
pub struct TicketRequest {
    pub election_id: String,
    pub manifest_digest: String,
    /// The blinded request, exactly as the VTA answered it.
    pub request: Value,
}

/// One request to the community, as the member. None carries a ballot, a cast or a receipt —
/// by construction: there is no variant that could.
#[derive(Clone, Debug, PartialEq)]
pub enum Request {
    /// `vtc/elections/list/0.3`: the elections the member may take part in.
    List { cursor: Option<String> },
    /// `vtc/elections/show/0.3`: one election — its manifest, parameters and disclosure.
    Show { election_id: String },
    /// `vtc/elections/tickets/issue/0.1`: the blinded ticket request, for the community to sign.
    IssueTicket(TicketRequest),
}

impl Request {
    /// The request's Type URI.
    #[must_use]
    pub fn type_uri(&self) -> &'static str {
        use trust_tasks_rs::Payload as _;
        match self {
            Request::List { .. } => list::Payload::TYPE_URI,
            Request::Show { .. } => show::Payload::TYPE_URI,
            Request::IssueTicket(_) => issue::Payload::TYPE_URI,
        }
    }

    /// The payload, checked through the generated type: what the schema refuses fails here.
    fn payload(&self) -> Result<Value, OpenVTCError> {
        let bad =
            |e: &dyn std::fmt::Display| OpenVTCError::Config(format!("{}: {e}", self.type_uri()));
        let payload = match self {
            Request::List { cursor } => {
                let mut p = json!({});
                if let Some(c) = cursor {
                    p["cursor"] = Value::String(c.clone());
                }
                serde_json::from_value::<list::Payload>(p.clone()).map_err(|e| bad(&e))?;
                p
            }
            Request::Show { election_id } => {
                let p = json!({ "electionId": election_id });
                serde_json::from_value::<show::Payload>(p.clone()).map_err(|e| bad(&e))?;
                p
            }
            Request::IssueTicket(t) => {
                let p = json!({
                    "electionId": t.election_id,
                    "manifestDigest": t.manifest_digest,
                    "request": t.request,
                });
                serde_json::from_value::<issue::Payload>(p.clone()).map_err(|e| bad(&e))?;
                p
            }
        };
        Ok(payload)
    }
}

/// Build `request` as an addressed, dated, unsigned document from `issuer_did` (the persona the
/// community knows the member by) to `vtc_did`. Its fresh id is the `threadId` the answer
/// carries; sign it with [`crate::capabilities::sign_document`].
///
/// # Errors
///
/// A payload the schema refuses.
pub fn build(
    request: &Request,
    issuer_did: &str,
    vtc_did: &str,
) -> Result<TrustTask<Value>, OpenVTCError> {
    crate::trust_task_doc::build(
        request.type_uri(),
        issuer_did,
        vtc_did,
        format!("urn:uuid:{}", Uuid::new_v4()),
        request.payload()?,
    )
}

// ****************************************************************************
// The community's answers
// ****************************************************************************

/// An election as the community shows it: the generated response, and the payload **as
/// received**.
///
/// The raw payload is what goes to the VTA: the manifest's digest — which the ticket, every
/// ballot and the certification are bound to — is taken over the manifest's JSON, and the
/// generated type rewrites what it parses (timestamps, an optional member it keeps as `null`).
#[derive(Clone, Debug)]
pub struct ShownElection {
    pub typed: show::Response,
    pub raw: Value,
}

impl ShownElection {
    /// Read a `vtc/elections/show/0.3` payload.
    ///
    /// # Errors
    ///
    /// A payload the schema refuses.
    pub fn from_payload(raw: Value) -> Result<Self, String> {
        let typed = serde_json::from_value::<show::Response>(raw.clone())
            .map_err(|e| crate::display::sanitize_display(&e.to_string(), MAX_PEER_TEXT))?;
        Ok(Self { typed, raw })
    }

    #[must_use]
    pub fn election_id(&self) -> &str {
        self.typed.manifest.election_id.as_str()
    }

    #[must_use]
    pub fn manifest_digest(&self) -> &str {
        self.typed.manifest_digest.as_str()
    }

    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        &self.typed.manifest
    }

    /// The manifest exactly as the community sent it.
    #[must_use]
    pub fn raw_manifest(&self) -> &Value {
        &self.raw["manifest"]
    }

    /// The voting parameters exactly as the community sent them.
    #[must_use]
    pub fn raw_parameters(&self) -> &Value {
        &self.raw["parameters"]
    }

    /// The trustees' signed ceremony, for a sealed or tallied-encrypted election — absent until
    /// the trustees have formed the election key.
    #[must_use]
    pub fn raw_ceremony(&self) -> Option<&Value> {
        self.raw.get("ceremony").filter(|c| !c.is_null())
    }

    /// Whether the election is open (`secrecy: open`): its casts are not encrypted.
    #[must_use]
    pub fn is_open_secrecy(&self) -> bool {
        self.typed.manifest.secrecy == show::SecrecyLevel::Open
    }

    /// The title for display, or the election id.
    #[must_use]
    pub fn title(&self) -> String {
        let m = &self.typed.manifest;
        m.title.as_ref().map_or_else(
            || crate::display::sanitize_display(m.election_id.as_str(), 128),
            |t| crate::display::sanitize_display(t.as_str(), 256),
        )
    }

    /// The ballot box's DID (the manifest's `ballotBox`).
    #[must_use]
    pub fn ballot_box(&self) -> &str {
        self.typed.manifest.ballot_box.as_str()
    }

    /// Whether voting is open now, by the community's state.
    #[must_use]
    pub fn voting_open(&self) -> bool {
        self.typed.state == show::RegistrarState::Voting
    }

    /// Whether a ticket can be taken now: registration or voting is open.
    #[must_use]
    pub fn tickets_open(&self) -> bool {
        matches!(
            self.typed.state,
            show::RegistrarState::Registration | show::RegistrarState::Voting
        )
    }

    /// The state, in words.
    #[must_use]
    pub fn state_label(&self) -> &'static str {
        state_label(&self.typed.state.to_string())
    }

    /// The manifest's `textReleaseThreshold`: how many counted ballots must be in before any
    /// written answer is released (VTI-VOT-065).
    #[must_use]
    pub fn text_release_threshold(&self) -> u64 {
        self.typed.manifest.text_release_threshold.get()
    }

    /// What the member must be told, before taking a ticket and again when voting, when the
    /// election releases written answers after fewer than [`TEXT_RELEASE_THRESHOLD_ADVISED`]
    /// ballots (VTI-VOT-065, VTI-VOT-090). `None` at the advised threshold or above.
    #[must_use]
    pub fn text_release_warning(&self) -> Option<String> {
        text_release_warning(self.text_release_threshold())
    }
}

/// The `textReleaseThreshold` VTI-VOT-065 says an election SHOULD meet. voting/_shared/0.3
/// allows as low as 1; below this the member is warned (VTI-VOT-090).
pub const TEXT_RELEASE_THRESHOLD_ADVISED: u64 = 10;

/// The warning for an election whose written answers are released once `threshold` ballots are
/// counted, or `None` when `threshold` is at least [`TEXT_RELEASE_THRESHOLD_ADVISED`].
#[must_use]
pub fn text_release_warning(threshold: u64) -> Option<String> {
    (threshold < TEXT_RELEASE_THRESHOLD_ADVISED).then(|| {
        let ballots = if threshold == 1 {
            "1 ballot is".to_string()
        } else {
            format!("{threshold} ballots are")
        };
        format!(
            "Written answers are released once {ballots} counted. Below \
             {TEXT_RELEASE_THRESHOLD_ADVISED}, a written answer may identify who wrote it."
        )
    })
}

/// The community's answer to one request.
#[derive(Clone, Debug)]
pub enum Reply {
    List(Box<list::Response>),
    Show(Box<ShownElection>),
    /// The community's blind signature, to hand to the VTA ([`accept`]): the generated response
    /// and the payload as received.
    TicketIssued {
        typed: Box<issue::Response>,
        raw: Value,
    },
    /// A `trust-task-error`.
    Refused(Refusal),
    /// A response whose payload does not match the schema this client was built against — a
    /// contract mismatch, neither a refusal nor a lost message (R6.4).
    Unreadable {
        task: String,
        detail: String,
    },
}

/// Whether an inbound document type may be an answer to one of these requests.
#[must_use]
pub fn is_reply_type(typ: &str) -> bool {
    typ.starts_with(TYPE_PREFIX) || crate::messaging::is_trust_task_error_type(typ)
}

/// Classify a reply document, keyed by the thread it answers. `None` when it is neither one of
/// these responses nor a `trust-task-error`, or carries no `threadId`.
#[must_use]
pub fn parse_reply(doc: &TrustTask<Value>) -> Option<(String, Reply)> {
    use trust_tasks_rs::Payload as _;
    let thid = doc.thread_id.clone()?;
    if doc.type_uri.slug() == "trust-task-error" {
        return Some((
            thid,
            Reply::Refused(Refusal::from_error_payload(&doc.payload)),
        ));
    }
    if !doc.type_uri.is_response() {
        return None;
    }
    let unreadable = |task: &str, e: &dyn std::fmt::Display| Reply::Unreadable {
        task: task.to_string(),
        detail: crate::display::sanitize_display(&e.to_string(), MAX_PEER_TEXT),
    };
    let p = &doc.payload;
    let uri = doc.type_uri.to_string();
    let reply = match uri.as_str() {
        u if u == list::Response::TYPE_URI => {
            match serde_json::from_value::<list::Response>(p.clone()) {
                Ok(r) => Reply::List(Box::new(r)),
                Err(e) => unreadable("vtc/elections/list", &e),
            }
        }
        u if u == show::Response::TYPE_URI => match ShownElection::from_payload(p.clone()) {
            Ok(s) => Reply::Show(Box::new(s)),
            Err(e) => unreadable("vtc/elections/show", &e),
        },
        u if u == issue::Response::TYPE_URI => {
            match serde_json::from_value::<issue::Response>(p.clone()) {
                Ok(r) => Reply::TicketIssued {
                    typed: Box::new(r),
                    raw: p.clone(),
                },
                Err(e) => unreadable("vtc/elections/tickets/issue", &e),
            }
        }
        _ => return None,
    };
    Some((thid, reply))
}

/// The local part of a declared error code (`vtc/elections/show:electionUnknown` →
/// `electionUnknown`); a framework code is its own local part.
#[must_use]
pub fn local_code(code: &str) -> &str {
    code.rsplit_once(':').map_or(code, |(_, local)| local)
}

/// A `trust-task-error` from the community.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub code: String,
    pub message: Option<String>,
}

impl Refusal {
    fn from_error_payload(payload: &Value) -> Self {
        Refusal {
            code: payload.get("code").and_then(Value::as_str).map_or_else(
                || "unknown".to_string(),
                |c| crate::display::sanitize_display(c, 128),
            ),
            message: payload
                .get("message")
                .and_then(Value::as_str)
                .map(|m| crate::display::sanitize_display(m.trim(), MAX_PEER_TEXT))
                .filter(|m| !m.is_empty()),
        }
    }

    /// What happened and what to do about it.
    #[must_use]
    pub fn explain(&self) -> String {
        let detail = self
            .message
            .as_deref()
            .map(|m| format!(" ({m})"))
            .unwrap_or_default();
        match local_code(&self.code) {
            "electionUnknown" => "The community does not know that election — it may have \
                                  been removed. Refresh (r)."
                .to_string(),
            "notOpen" => "Tickets are not being issued for this election now: registration has \
                          not opened, or the election has closed."
                .to_string(),
            "manifestMismatch" => "The election changed since it was read. Refresh (r) and look \
                                   at it again before taking a ticket."
                .to_string(),
            "notEligible" => "The community's roll for this election does not include this \
                              persona."
                .to_string(),
            "alreadyIssued" => "The community already issued this persona's ticket, for another \
                                request than the one your VTA holds — it cannot be issued twice."
                .to_string(),
            "requestInvalid" => {
                format!("The community could not read the ticket request your VTA built{detail}.")
            }
            "notAMember" => {
                "The community does not count this persona as an active member.".to_string()
            }
            "unsupportedType" | "unsupportedVersion" => format!(
                "This community does not serve that request{detail} — it may predate community \
                 elections (vtc/elections/list/0.3)."
            ),
            "permissionDenied" => format!("The community refused{detail}."),
            other => format!("The community refused ({other}){detail}."),
        }
    }
}

// ****************************************************************************
// Listing
// ****************************************************************************

/// Where an election sits in the list: what the member can do with it first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Standing {
    /// Voting is open.
    VotingOpen,
    /// Tickets are being issued; voting has not opened.
    TicketsOpen,
    /// Registered with its ballot box, not yet issuing tickets.
    Upcoming,
    /// Closed, tallied, cancelled or refused.
    Over,
}

impl Standing {
    #[must_use]
    pub fn of(state: &RegistrarState) -> Self {
        match state {
            RegistrarState::Voting => Standing::VotingOpen,
            RegistrarState::Registration => Standing::TicketsOpen,
            RegistrarState::Registered | RegistrarState::PendingRegistration => Standing::Upcoming,
            _ => Standing::Over,
        }
    }

    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Standing::VotingOpen => "voting open",
            Standing::TicketsOpen => "tickets open",
            Standing::Upcoming => "upcoming",
            Standing::Over => "over",
        }
    }
}

/// A registrar state, in words.
#[must_use]
pub fn state_label(state: &str) -> &'static str {
    match state {
        "registered" => "upcoming",
        "registration" => "tickets open",
        "voting" => "voting open",
        "closed" => "closed",
        "tallied" => "tallied",
        "cancelled" => "cancelled",
        "pendingRegistration" => "being registered",
        "registrationRefused" => "refused by its ballot box",
        _ => "unknown",
    }
}

/// The elections in the order the member acts on them: voting open, tickets open, upcoming,
/// then the rest; each group by when voting closes.
pub fn sort_for_display(items: &mut [ElectionListItem]) {
    items.sort_by(|a, b| {
        Standing::of(&a.state)
            .cmp(&Standing::of(&b.state))
            .then(a.voting_closes_at.cmp(&b.voting_closes_at))
    });
}

/// An election's title for display, or its id.
#[must_use]
pub fn display_title(item: &ElectionListItem) -> String {
    item.title.as_ref().map_or_else(
        || crate::display::sanitize_display(item.election_id.as_str(), 128),
        |t| crate::display::sanitize_display(t.as_str(), 256),
    )
}

// ****************************************************************************
// The ballot
// ****************************************************************************

/// A question's key. `Option` so a later pinned version's question kinds can answer `None`.
#[must_use]
pub fn question_key(q: &Question) -> Option<&str> {
    match q {
        Question::Choice { key, .. }
        | Question::Ranking { key, .. }
        | Question::Score { key, .. }
        | Question::Text { key, .. } => Some(key.as_str()),
    }
}

/// Whether a question may be abstained on.
#[must_use]
pub fn question_optional(q: &Question) -> bool {
    match q {
        Question::Choice { optional, .. }
        | Question::Ranking { optional, .. }
        | Question::Score { optional, .. }
        | Question::Text { optional, .. } => *optional,
    }
}

/// A question's options (none for a text question).
#[must_use]
pub fn question_options(q: &Question) -> &[QuestionOption] {
    match q {
        Question::Choice { options, .. }
        | Question::Ranking { options, .. }
        | Question::Score { options, .. } => options,
        _ => &[],
    }
}

/// A question's wording for display, or its key.
#[must_use]
pub fn question_text(q: &Question) -> String {
    let text = match q {
        Question::Choice { text, .. }
        | Question::Ranking { text, .. }
        | Question::Score { text, .. }
        | Question::Text { text, .. } => text.as_ref().map(|t| t.as_str().to_string()),
    };
    crate::display::sanitize_display(
        &text.unwrap_or_else(|| question_key(q).unwrap_or("?").to_string()),
        512,
    )
}

/// An option's label for display, or its key.
#[must_use]
pub fn option_label(o: &QuestionOption) -> String {
    crate::display::sanitize_display(o.label.as_ref().map_or(o.key.as_str(), |l| l.as_str()), 256)
}

/// A broken ballot rule — the rules JSON Schema cannot state, as VTI's `vti_voting::rules::
/// check_ballot` holds them (VTI-VOT-032, VTI-VOT-045). Checked here so a member hears it in
/// words before anything is built; the VTA and the ballot box check the same again.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BallotError {
    #[error("this ballot is for another election, or another version of it — read it again")]
    ManifestMismatch,
    #[error("the ballot does not have the shape the election asks for ({0})")]
    Schema(String),
    #[error("the election asks no question {0}")]
    NoQuestion(String),
    #[error("question {0} is answered twice")]
    AnsweredTwice(String),
    #[error("question {0} needs exactly one kind of answer")]
    OneAnswer(String),
    #[error("question {0} must be answered: it cannot be left blank")]
    NotOptional(String),
    #[error("question {0} takes {1}")]
    WrongKind(String, &'static str),
    #[error("question {key}: choose between {min} and {max} (you chose {chosen})")]
    SelectionCount {
        key: String,
        min: u64,
        max: u64,
        chosen: u64,
    },
    #[error("question {0}: an option that is not on the ballot, or chosen twice")]
    UnknownOption(String),
    #[error("question {0}: rank every option")]
    RankEvery(String),
    #[error("question {0}: rank at least one option, each once")]
    RankSome(String),
    #[error("question {0}: give every option a score")]
    ScoreEvery(String),
    #[error("question {key}: each score must be between {min} and {max}")]
    ScoreBounds { key: String, min: i64, max: i64 },
    #[error("question {key}: at most {max} characters")]
    TextTooLong { key: String, max: u64 },
    #[error("question {0} is not answered (an optional question may be left blank)")]
    Unanswered(String),
}

/// How many answer members an answer carries. Exactly one is admitted.
fn members(a: &pcs_vote::Answer) -> usize {
    usize::from(a.choice.is_some())
        + usize::from(a.ranking.is_some())
        + usize::from(!a.scores.is_empty())
        + usize::from(a.text.is_some())
        + usize::from(a.abstain.is_some())
}

/// Check `ballot` (a `vta/pcs/vote/0.3` ballot, as JSON) against the election the community
/// shows: the same rules VTI's `check_ballot` holds. `manifest_digest` is the community's.
///
/// # Errors
///
/// The first rule broken.
pub fn check_ballot(
    manifest: &Manifest,
    manifest_digest: &str,
    ballot: &Value,
) -> Result<(), BallotError> {
    let b: pcs_vote::Ballot = serde_json::from_value(ballot.clone()).map_err(|e| {
        BallotError::Schema(crate::display::truncate_chars(&e.to_string(), 200).to_string())
    })?;
    if b.election_id.as_str() != manifest.election_id.as_str()
        || b.manifest_digest.as_str() != manifest_digest
    {
        return Err(BallotError::ManifestMismatch);
    }
    let mut answered = HashSet::new();
    for a in &b.answers {
        let qkey = a.question.as_str();
        let Some(q) = manifest
            .questions
            .iter()
            .find(|q| question_key(q) == Some(qkey))
        else {
            return Err(BallotError::NoQuestion(qkey.to_string()));
        };
        if !answered.insert(qkey) {
            return Err(BallotError::AnsweredTwice(qkey.to_string()));
        }
        if members(a) != 1 {
            return Err(BallotError::OneAnswer(qkey.to_string()));
        }
        if a.abstain.is_some() {
            if a.abstain != Some(Value::Bool(true)) || !question_optional(q) {
                return Err(BallotError::NotOptional(qkey.to_string()));
            }
            continue;
        }
        let opts: HashSet<&str> = question_options(q).iter().map(|o| o.key.as_str()).collect();
        match q {
            Question::Choice {
                min_selections,
                max_selections,
                ..
            } => {
                let Some(choice) = &a.choice else {
                    return Err(BallotError::WrongKind(qkey.to_string(), "a choice"));
                };
                let n = choice.len() as u64;
                if n < *min_selections || n > max_selections.get() {
                    return Err(BallotError::SelectionCount {
                        key: qkey.to_string(),
                        min: *min_selections,
                        max: max_selections.get(),
                        chosen: n,
                    });
                }
                if choice.iter().collect::<HashSet<_>>().len() != choice.len()
                    || choice.iter().any(|k| !opts.contains(k.as_str()))
                {
                    return Err(BallotError::UnknownOption(qkey.to_string()));
                }
            }
            Question::Ranking { partial, .. } => {
                let Some(ranking) = &a.ranking else {
                    return Err(BallotError::WrongKind(qkey.to_string(), "a ranking"));
                };
                let distinct = ranking.iter().collect::<HashSet<_>>().len() == ranking.len();
                if !(distinct && ranking.iter().all(|k| opts.contains(k.as_str()))) {
                    return Err(BallotError::UnknownOption(qkey.to_string()));
                }
                if *partial && ranking.is_empty() {
                    return Err(BallotError::RankSome(qkey.to_string()));
                }
                if !*partial && ranking.len() != opts.len() {
                    return Err(BallotError::RankEvery(qkey.to_string()));
                }
            }
            Question::Score { min, max, .. } => {
                if a.scores.is_empty() {
                    return Err(BallotError::WrongKind(qkey.to_string(), "scores"));
                }
                let scored: HashSet<&str> = a.scores.keys().map(|k| k.as_str()).collect();
                if scored != opts {
                    return Err(BallotError::ScoreEvery(qkey.to_string()));
                }
                if a.scores.values().any(|v| v < min || v > max) {
                    return Err(BallotError::ScoreBounds {
                        key: qkey.to_string(),
                        min: *min,
                        max: *max,
                    });
                }
            }
            Question::Text { max_length, .. } => {
                let Some(text) = &a.text else {
                    return Err(BallotError::WrongKind(qkey.to_string(), "text"));
                };
                if text.as_str().chars().count() as u64 > max_length.get() {
                    return Err(BallotError::TextTooLong {
                        key: qkey.to_string(),
                        max: max_length.get(),
                    });
                }
            }
        }
    }
    if let Some(q) = manifest
        .questions
        .iter()
        .find(|q| question_key(q).is_none_or(|k| !answered.contains(k)))
    {
        return Err(BallotError::Unanswered(
            question_key(q).unwrap_or("?").to_string(),
        ));
    }
    Ok(())
}

/// One question's answer as the member is filling it in. Its `Debug` names the kind only.
#[derive(Clone, PartialEq, Eq)]
pub enum AnswerDraft {
    /// The chosen option keys.
    Choice(Vec<String>),
    /// The option keys in the member's order of preference.
    Ranking(Vec<String>),
    /// A score per option, in the question's order; `None` until given one.
    Scores(Vec<(String, Option<i64>)>),
    Text(String),
}

/// A ballot as the member fills it in, one answer per question in the manifest's order.
///
/// Its `Debug` says how many questions it answers and nothing else: a ballot is never logged.
#[derive(Clone, PartialEq, Eq)]
pub struct BallotDraft {
    /// `(question key, answer, abstained)`.
    pub answers: Vec<(String, AnswerDraft, bool)>,
}

impl std::fmt::Debug for AnswerDraft {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            AnswerDraft::Choice(_) => "Choice(..)",
            AnswerDraft::Ranking(_) => "Ranking(..)",
            AnswerDraft::Scores(_) => "Scores(..)",
            AnswerDraft::Text(_) => "Text(..)",
        })
    }
}

impl std::fmt::Debug for BallotDraft {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BallotDraft {{ {} answers, .. }}", self.answers.len())
    }
}

impl BallotDraft {
    /// A blank ballot for `manifest`: nothing chosen, nothing ranked, nothing scored.
    #[must_use]
    pub fn new(manifest: &Manifest) -> Self {
        let answers = manifest
            .questions
            .iter()
            .filter_map(|q| {
                let key = question_key(q)?.to_string();
                let draft = match q {
                    Question::Choice { .. } => AnswerDraft::Choice(Vec::new()),
                    Question::Ranking { .. } => AnswerDraft::Ranking(Vec::new()),
                    Question::Score { options, .. } => AnswerDraft::Scores(
                        options.iter().map(|o| (o.key.to_string(), None)).collect(),
                    ),
                    Question::Text { .. } => AnswerDraft::Text(String::new()),
                };
                Some((key, draft, false))
            })
            .collect();
        Self { answers }
    }

    /// The ballot as `vta/pcs/vote/0.3` takes it. An unscored score is left out, so
    /// [`check_ballot`] says to score every option.
    #[must_use]
    pub fn to_ballot(&self, election_id: &str, manifest_digest: &str) -> Value {
        let answers: Vec<Value> = self
            .answers
            .iter()
            .map(|(key, draft, abstain)| {
                if *abstain {
                    return json!({ "question": key, "abstain": true });
                }
                match draft {
                    AnswerDraft::Choice(c) => json!({ "question": key, "choice": c }),
                    AnswerDraft::Ranking(r) => json!({ "question": key, "ranking": r }),
                    AnswerDraft::Scores(s) => {
                        let scores: BTreeMap<&str, i64> = s
                            .iter()
                            .filter_map(|(k, v)| v.map(|v| (k.as_str(), v)))
                            .collect();
                        json!({ "question": key, "scores": scores })
                    }
                    AnswerDraft::Text(t) => json!({ "question": key, "text": t }),
                }
            })
            .collect();
        json!({
            "electionId": election_id,
            "manifestDigest": manifest_digest,
            "answers": answers,
        })
    }
}

// ****************************************************************************
// The member's VTA
// ****************************************************************************

/// Why a call to the member's VTA did not succeed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VtaCallError {
    /// The VTA answered and refused, with the code its specification declares.
    #[error("{}", vta_refusal_words(code, message))]
    Refused { code: String, message: String },
    /// No answer: the VTA could not be reached, or did not reply in time.
    #[error("could not reach your VTA: {0}")]
    Unreachable(String),
    /// A request this client could not build, or an answer it could not read.
    #[error("a voting call to your VTA could not be read: {0}")]
    Unreadable(String),
}

impl VtaCallError {
    /// Whether the VTA refused with this local error code.
    #[must_use]
    pub fn is(&self, local: &str) -> bool {
        matches!(self, Self::Refused { code, .. } if local_code(code) == local)
    }
}

/// A refusal from the member's VTA, in words.
#[must_use]
pub fn vta_refusal_words(code: &str, message: &str) -> String {
    let detail = if message.is_empty() {
        String::new()
    } else {
        format!(
            " ({})",
            crate::display::sanitize_display(message, MAX_PEER_TEXT)
        )
    };
    match local_code(code) {
        "electionChanged" | "manifestMismatch" => format!(
            "Your VTA holds this election under another version of it: the election changed \
             since you took your ticket{detail}."
        ),
        "notOpen" => "Your VTA says voting is not open for this election now.".to_string(),
        "ballotInvalid" => format!("Your VTA refused the ballot{detail}."),
        "notFound" => "Your VTA holds no ticket for this election.".to_string(),
        "noRequestInFlight" => "Your VTA has no ticket request waiting for the community's \
                                answer — take the ticket again."
            .to_string(),
        "credentialInvalid" => "The community's answer to the ticket request did not check out \
                                at your VTA."
            .to_string(),
        "memberNotHeld" => "Your VTA holds no key for this persona.".to_string(),
        "unsupportedSecrecy" | "wrongLevel" => {
            format!("Your VTA cannot vote at this election's secrecy level{detail}.")
        }
        "electionKeyInvalid" => "The trustees' election key did not check out at your VTA: \
                                 not voting under it."
            .to_string(),
        "receiptInvalid" | "evidenceInvalid" => {
            format!("Your VTA could not check the ballot box's receipt{detail}.")
        }
        "unsupportedType" | "unsupportedVersion" => format!(
            "Your VTA does not serve this request{detail} — it may predate community voting \
             (vta/pcs/voter/register/0.3)."
        ),
        other => format!("Your VTA refused ({other}){detail}."),
    }
}

/// Send `payload` as `P`'s task to the VTA and read its answer.
///
/// The payload is checked through `P` and then sent **as given**: it carries the manifest the
/// community sent, whose digest is over its JSON (see [`ShownElection`]).
async fn call<P>(
    client: &VtaClient,
    payload: Value,
    timeout: u64,
) -> Result<(P::Response, Value), VtaCallError>
where
    P: RequestPayload,
    P::Response: DeserializeOwned,
{
    serde_json::from_value::<P>(payload.clone())
        .map_err(|e| VtaCallError::Unreadable(format!("{}: {e}", P::TYPE_URI)))?;
    let reply = client
        .dispatch_trust_task_document(P::TYPE_URI, payload, timeout)
        .await
        .map_err(|e| VtaCallError::Unreachable(e.to_string()))?;
    read_vta_reply::<P::Response>(&reply, P::TYPE_URI)
}

/// The answer, typed and as received: a signed document inside it (a cast) is carried on as
/// received, never re-serialised from the typed form, which would rewrite what was signed.
fn read_vta_reply<R: DeserializeOwned>(
    reply: &Value,
    task: &str,
) -> Result<(R, Value), VtaCallError> {
    let body = reply.get("payload").cloned().unwrap_or(Value::Null);
    let refused = reply
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|t| t.starts_with(ERROR_TYPE_PREFIX));
    if refused {
        let text = |k: &str| {
            body.get(k)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        return Err(VtaCallError::Refused {
            code: text("code"),
            message: text("message"),
        });
    }
    let typed = serde_json::from_value(body.clone())
        .map_err(|e| VtaCallError::Unreadable(format!("{task} answer: {e}")))?;
    Ok((typed, body))
}

/// Which VTA, which context the voter keys are derived in, which community.
#[derive(Clone, Copy)]
pub struct Voter<'a> {
    pub vta: &'a VtaClient,
    /// The persona's own context (`community_context::persona_context`).
    pub context_id: &'a str,
    pub community: &'a str,
}

/// What `vta/pcs/voter/register/0.3` said.
#[derive(Clone, Debug, PartialEq)]
pub enum Registered {
    /// The ticket request to carry to the community.
    Request(TicketRequest),
    /// The VTA already holds this election's ticket (`ticketHeld`).
    AlreadyHeld,
}

/// The `vta/pcs/voter/register/0.3` payload: no `member` — the request is the VTA's alone to
/// build, and this client signs `vtc/elections/tickets/issue` as the persona itself.
#[must_use]
pub fn register_payload(v: &Voter<'_>, shown: &ShownElection) -> Value {
    json!({
        "contextId": v.context_id,
        "community": v.community,
        "parameters": shown.raw_parameters(),
        "manifest": shown.raw_manifest(),
    })
}

/// Have the VTA build the blinded ticket request for the election `shown` describes — or say it
/// already holds the ticket. A repeat before the ticket is held answers the same request.
///
/// # Errors
///
/// The VTA refused (other than `ticketHeld`), could not be reached, or computed another manifest
/// digest than the community shows — in which case no ticket is taken.
pub async fn register(v: &Voter<'_>, shown: &ShownElection) -> Result<Registered, VtaCallError> {
    match call::<pcs_register::Payload>(v.vta, register_payload(v, shown), VTA_TIMEOUT_SECS).await {
        Ok((r, raw)) => registered_from(&r, &raw, shown.manifest_digest()),
        Err(e) if e.is("ticketHeld") => Ok(Registered::AlreadyHeld),
        Err(e) => Err(e),
    }
}

/// The ticket request out of a register answer, provided the VTA's digest is the community's.
fn registered_from(
    r: &pcs_register::Response,
    raw: &Value,
    community_digest: &str,
) -> Result<Registered, VtaCallError> {
    if r.manifest_digest.as_str() != community_digest {
        return Err(VtaCallError::Unreadable(
            "your VTA computed another manifest digest than the community shows; not taking a \
             ticket"
                .into(),
        ));
    }
    let request = raw["request"].clone();
    Ok(Registered::Request(TicketRequest {
        election_id: r.election_id.to_string(),
        manifest_digest: r.manifest_digest.to_string(),
        request,
    }))
}

/// The `vta/pcs/voter/accept/0.1` payload: the community's answer as received, without `ext`.
#[must_use]
pub fn accept_payload(v: &Voter<'_>, shown: &ShownElection, issued_raw: &Value) -> Value {
    let mut response = issued_raw.clone();
    if let Some(obj) = response.as_object_mut() {
        obj.remove("ext");
    }
    json!({
        "contextId": v.context_id,
        "community": v.community,
        "electionId": shown.election_id(),
        "parameters": shown.raw_parameters(),
        "response": response,
    })
}

/// Hand the community's blind signature to the VTA, which unblinds it into the ticket.
///
/// # Errors
///
/// The VTA refused or could not be reached.
pub async fn accept(
    v: &Voter<'_>,
    shown: &ShownElection,
    issued_raw: &Value,
) -> Result<(), VtaCallError> {
    call::<pcs_accept::Payload>(
        v.vta,
        accept_payload(v, shown, issued_raw),
        VTA_TIMEOUT_SECS,
    )
    .await
    .map(|_| ())
}

/// Why a vote could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VoteError {
    #[error("{0}")]
    Ballot(#[from] BallotError),
    #[error(
        "the trustees have not formed this election's key yet, so a ballot cannot be encrypted \
         to it — try again once voting opens"
    )]
    NoCeremony,
    #[error("{0}")]
    Vta(#[from] VtaCallError),
}

/// The `vta/pcs/vote/0.3` or `vta/pcs/vote-encrypted/0.4` payload, and which of the two.
///
/// # Errors
///
/// A ballot that breaks a rule, or an encrypted election whose key is not formed yet.
pub fn vote_payload(
    v: &Voter<'_>,
    shown: &ShownElection,
    ballot: &Value,
) -> Result<(Value, bool), VoteError> {
    check_ballot(shown.manifest(), shown.manifest_digest(), ballot)?;
    let mut payload = json!({
        "contextId": v.context_id,
        "community": v.community,
        "parameters": shown.raw_parameters(),
        "manifest": shown.raw_manifest(),
        "ballot": ballot,
    });
    if shown.is_open_secrecy() {
        return Ok((payload, false));
    }
    payload["ceremony"] = shown.raw_ceremony().cloned().ok_or(VoteError::NoCeremony)?;
    Ok((payload, true))
}

/// A signed cast document the VTA built, under a key made for this cast alone — to post to the
/// ballot box unchanged, and to resend unchanged if its answer is lost.
#[derive(Clone)]
pub struct Cast {
    pub document: Value,
}

impl std::fmt::Debug for Cast {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Cast {{ id: {:?}, .. }}", self.id())
    }
}

impl Cast {
    #[must_use]
    pub fn id(&self) -> &str {
        self.document
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
    }

    /// The one-time key's DID the cast is signed under.
    #[must_use]
    pub fn issuer(&self) -> &str {
        self.document
            .get("issuer")
            .and_then(Value::as_str)
            .unwrap_or_default()
    }

    #[must_use]
    pub fn type_uri(&self) -> &str {
        self.document
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
    }
}

/// Have the VTA build and sign the cast for `ballot` — encrypted to the trustees' key when the
/// election is sealed or tallied-encrypted.
///
/// # Errors
///
/// A ballot that breaks a rule (checked before the VTA is asked), no election key yet, or the
/// VTA refused or could not be reached.
pub async fn vote(v: &Voter<'_>, shown: &ShownElection, ballot: &Value) -> Result<Cast, VoteError> {
    let (payload, encrypted) = vote_payload(v, shown, ballot)?;
    let raw = if encrypted {
        call::<pcs_vote_encrypted::Payload>(v.vta, payload, VTA_PROOF_TIMEOUT_SECS)
            .await?
            .1
    } else {
        call::<pcs_vote::Payload>(v.vta, payload, VTA_PROOF_TIMEOUT_SECS)
            .await?
            .1
    };
    // The signed cast exactly as the VTA answered it: re-serialising the typed form could
    // rewrite what its proof covers.
    Ok(Cast {
        document: raw["castDocument"].clone(),
    })
}

/// What the VTA said of a receipt it kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kept {
    /// Kept; inclusion not yet checked against a head.
    Kept,
    /// Kept, and shown included in a head the community kept.
    Included,
    /// Kept, and shown **not** included.
    NotIncluded,
}

/// The `vta/pcs/voter/receipt/0.1` payload: the whole receipt document.
#[must_use]
pub fn receipt_payload(v: &Voter<'_>, election_id: &str, receipt: &VerifiedReceipt) -> Value {
    json!({
        "contextId": v.context_id,
        "community": v.community,
        "electionId": election_id,
        "receipt": receipt.document,
    })
}

/// Hand the ballot box's receipt to the VTA to keep.
///
/// # Errors
///
/// The VTA refused or could not be reached.
pub async fn keep_receipt(
    v: &Voter<'_>,
    election_id: &str,
    receipt: &VerifiedReceipt,
) -> Result<Kept, VtaCallError> {
    let (r, _) = call::<pcs_receipt::Payload>(
        v.vta,
        receipt_payload(v, election_id, receipt),
        VTA_TIMEOUT_SECS,
    )
    .await?;
    Ok(match r.status {
        pcs_receipt::ResponseStatus::Included => Kept::Included,
        pcs_receipt::ResponseStatus::NotIncluded => Kept::NotIncluded,
        _ => Kept::Kept,
    })
}

// ****************************************************************************
// The ballot box
// ****************************************************************************

/// Why a cast did not reach a receipt this client believes.
///
/// The variants are what R6.4 asks to tell apart: nowhere to send, could not reach (resend the
/// same cast), refused (and why, in words), or an answer that is not the ballot box's receipt
/// for this cast.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CastError {
    #[error("the ballot box {0} could not be resolved: {1}")]
    Resolve(String, String),
    #[error("the ballot box {0} advertises no https TrustTaskHTTPS endpoint to cast on")]
    NoEndpoint(String),
    #[error("the ballot box's endpoint cannot be used ({0})")]
    Blocked(String),
    /// Nothing came back: the same cast can be sent again.
    #[error(
        "the ballot box did not answer ({0}). Your vote may or may not have been counted: \
         sending the same cast again is safe, and is answered with its receipt"
    )]
    Unreachable(String),
    #[error("{}", cast_refusal_words(code.as_deref(), message))]
    Refused {
        status: u16,
        code: Option<String>,
        message: String,
    },
    #[error("the ballot box's answer could not be read ({0})")]
    Unreadable(String),
    #[error("the ballot box's answer could not be shown to be genuine ({0})")]
    Unproven(String),
    #[error("the answer was signed by {proven}, which is not this election's ballot box")]
    WrongSigner { proven: String },
    #[error("the ballot box's answer does not answer this cast")]
    WrongThread,
    #[error("the ballot box's answer is addressed to someone other than this cast's key")]
    WrongRecipient,
}

impl CastError {
    /// Whether the same cast document may simply be sent again.
    #[must_use]
    pub fn resendable(&self) -> bool {
        matches!(self, CastError::Unreachable(_))
    }
}

/// A ballot box's refusal of a cast (`voting/ballot/cast/0.1`, `cast-encrypted/0.1`), in words.
#[must_use]
pub fn cast_refusal_words(code: Option<&str>, message: &str) -> String {
    let detail = if message.is_empty() {
        String::new()
    } else {
        format!(
            " ({})",
            crate::display::sanitize_display(message, MAX_PEER_TEXT)
        )
    };
    match code.map(local_code) {
        Some("electionUnknown") => {
            "The ballot box does not know this election. It may not have been registered there \
             yet; ask the community."
                .to_string()
        }
        Some("notOpen") => "The ballot box is not taking votes for this election now.".to_string(),
        Some("manifestMismatch") => {
            "The ballot box holds this election under another version of it than your ballot \
             names. Read the election again."
                .to_string()
        }
        Some("ballotInvalid") => format!("The ballot box refused the ballot as invalid{detail}."),
        Some("classMismatch") => {
            "The ballot box did not accept your ticket for this election.".to_string()
        }
        Some("alreadyVoted") => {
            "You have already voted in this election, and it does not let a later vote replace \
             an earlier one."
                .to_string()
        }
        Some("castInvalid") => format!("The ballot box refused the cast as malformed{detail}."),
        Some("wrongLevel") => {
            "The ballot box expects this election's ballots at another secrecy level.".to_string()
        }
        Some(other) => format!("The ballot box refused the cast ({other}){detail}."),
        None => format!("The ballot box refused the cast{detail}."),
    }
}

/// The ballot box's `TrustTaskHTTPS` endpoint, from its resolved DID document: matched on the
/// service `type`, and only `https` (or loopback `http`).
///
/// # Errors
///
/// No such endpoint.
pub fn ballot_box_endpoint(doc: &Value, ballot_box: &str) -> Result<String, CastError> {
    vta_sdk::protocol::matching::ServiceCapabilities::from_did_document(doc)
        .rest
        .filter(|u| vta_sdk::protocol::matching::is_https_or_loopback(u))
        .ok_or_else(|| CastError::NoEndpoint(ballot_box.to_string()))
}

/// Resolve the ballot box's DID (within [`RESOLVE_TIMEOUT`]) and read its cast endpoint.
///
/// # Errors
///
/// It did not resolve, or advertises nowhere to cast.
pub async fn resolve_ballot_box(
    resolver: &DIDCacheClient,
    ballot_box: &str,
) -> Result<String, CastError> {
    let resolved = tokio::time::timeout(RESOLVE_TIMEOUT, resolver.resolve(ballot_box))
        .await
        .map_err(|_| {
            CastError::Resolve(
                ballot_box.to_string(),
                format!("no answer within {}s", RESOLVE_TIMEOUT.as_secs()),
            )
        })?
        .map_err(|e| CastError::Resolve(ballot_box.to_string(), e.to_string()))?;
    let doc = serde_json::to_value(&resolved.doc)
        .map_err(|e| CastError::Resolve(ballot_box.to_string(), e.to_string()))?;
    ballot_box_endpoint(&doc, ballot_box)
}

/// A random pause in `0..MAX_CAST_DELAY`, so the cast's arrival is not timed to the member's
/// last action. From the OS's generator: the pause is a privacy measure.
#[must_use]
pub fn cast_delay() -> Duration {
    use rand::Rng as _;
    let ms = rand::rngs::OsRng.gen_range(0..MAX_CAST_DELAY.as_millis() as u64);
    Duration::from_millis(ms)
}

/// `<base>/trust-tasks`, the HTTPS binding's document endpoint.
#[must_use]
pub fn cast_url(base: &str) -> String {
    format!("{}/trust-tasks", base.trim_end_matches('/'))
}

/// Post `cast` to the ballot box at `base`, **unchanged**, from this client's own connection —
/// never the member's messaging session — with the hardened foreign-fetch client (finite
/// timeouts, no redirects, no proxy, guarded DNS; R1.2). Returns the answer document as received.
///
/// # Errors
///
/// The URL may not be dialled, nothing came back ([`CastError::Unreachable`]: resend the same
/// cast), or the answer is a refusal or not a document.
pub async fn post_cast(base: &str, cast: &Cast) -> Result<Value, CastError> {
    let url = cast_url(base);
    let policy = vta_sdk::http::EndpointPolicy::process_default();
    vta_sdk::http::guard_foreign_url(&url, policy)
        .map_err(|e| CastError::Blocked(e.to_string()))?;
    let body =
        serde_json::to_vec(&cast.document).map_err(|e| CastError::Unreadable(e.to_string()))?;
    let response = vta_sdk::http::foreign_fetch_client_for(policy)
        .post(&url)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|e| CastError::Unreachable(e.to_string()))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|e| CastError::Unreachable(e.to_string()))?;
    read_cast_answer(status.as_u16(), &text)
}

/// Read the ballot box's HTTP answer: a refusal is a refusal whatever its status.
fn read_cast_answer(status: u16, text: &str) -> Result<Value, CastError> {
    let parsed: Option<Value> = serde_json::from_str(text).ok();
    let refusal = parsed.as_ref().filter(|d| {
        d.get("type")
            .and_then(Value::as_str)
            .is_some_and(|t| t.starts_with(ERROR_TYPE_PREFIX))
    });
    if let Some(d) = refusal {
        let field = |k: &str| {
            d.pointer(&format!("/payload/{k}"))
                .and_then(Value::as_str)
                .map(str::to_string)
        };
        return Err(CastError::Refused {
            status,
            code: field("code"),
            message: field("message").unwrap_or_default(),
        });
    }
    if !(200..300).contains(&status) {
        return Err(CastError::Refused {
            status,
            code: None,
            message: format!(
                "HTTP {status}: {}",
                crate::display::sanitize_display(text, 200)
            ),
        });
    }
    parsed.ok_or_else(|| CastError::Unreadable("not a JSON document".into()))
}

/// A receipt shown to be the ballot box's answer to this cast: its proof is by the ballot box's
/// DID, it threads on the cast's id and is addressed to the cast's one-time key. Only
/// [`check_receipt`] makes one.
#[derive(Clone, Debug)]
pub struct VerifiedReceipt {
    document: Value,
    /// `counted`, `replaced` or `alreadyCounted`.
    pub outcome: ReceiptOutcome,
    /// The cast's entry on the board.
    pub leaf_index: u64,
}

impl VerifiedReceipt {
    /// The whole receipt document, as received.
    #[must_use]
    pub fn document(&self) -> &Value {
        &self.document
    }
}

/// What the ballot box did with the cast.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptOutcome {
    Counted,
    /// Replaced an earlier vote (an election whose revote is `replace`).
    Replaced,
    /// The same cast, resent: counted the first time.
    AlreadyCounted,
}

impl ReceiptOutcome {
    #[must_use]
    pub fn words(self) -> &'static str {
        match self {
            ReceiptOutcome::Counted => "counted",
            ReceiptOutcome::Replaced => "counted, replacing your earlier vote",
            ReceiptOutcome::AlreadyCounted => "already counted (this cast was sent before)",
        }
    }
}

/// Check the ballot box's answer to `cast` and read it.
///
/// # Errors
///
/// The proof is missing, does not verify, or is not the ballot box's; the answer does not thread
/// on the cast or is not addressed to its key; or its payload is not a receipt.
pub async fn check_receipt(
    answer: Value,
    cast: &Cast,
    ballot_box: &str,
    resolver: &vta_sdk::trust_task_proof::TrustTaskVmResolver,
) -> Result<VerifiedReceipt, CastError> {
    // Proof first: nothing is read out of a document not shown to be the ballot box's.
    let proven = vta_sdk::trust_task_proof::verify_trust_task_proof_value(&answer, resolver)
        .await
        .map_err(|e| CastError::Unproven(e.to_string()))?;
    read_receipt(answer, &proven, cast, ballot_box)
}

/// [`check_receipt`] after the proof: `proven` is the DID it was shown to be by.
fn read_receipt(
    answer: Value,
    proven: &str,
    cast: &Cast,
    ballot_box: &str,
) -> Result<VerifiedReceipt, CastError> {
    if !vta_sdk::did_scid::same_reference(proven, ballot_box) {
        return Err(CastError::WrongSigner {
            proven: crate::display::sanitize_display(proven, 256),
        });
    }
    let field = |k: &str| answer.get(k).and_then(Value::as_str);
    if field("threadId") != Some(cast.id()) || cast.id().is_empty() {
        return Err(CastError::WrongThread);
    }
    if field("recipient") != Some(cast.issuer()) || cast.issuer().is_empty() {
        return Err(CastError::WrongRecipient);
    }
    let expected = format!("{}#response", cast.type_uri().trim_end_matches("#request"));
    if field("type") != Some(expected.as_str()) {
        return Err(CastError::Unreadable(format!(
            "an answer of type {}",
            crate::display::sanitize_display(field("type").unwrap_or("(none)"), 200)
        )));
    }
    let payload = answer.get("payload").cloned().unwrap_or(Value::Null);
    let (outcome, leaf_index) = if cast
        .type_uri()
        .starts_with("https://trusttasks.org/spec/voting/ballot/cast-encrypted/")
    {
        let r: cast_encrypted::Response =
            serde_json::from_value(payload).map_err(|e| CastError::Unreadable(e.to_string()))?;
        let o = match r.outcome {
            cast_encrypted::ResponseOutcome::Replaced => ReceiptOutcome::Replaced,
            cast_encrypted::ResponseOutcome::AlreadyCounted => ReceiptOutcome::AlreadyCounted,
            _ => ReceiptOutcome::Counted,
        };
        (o, r.leaf_index)
    } else {
        let r: cast::Response =
            serde_json::from_value(payload).map_err(|e| CastError::Unreadable(e.to_string()))?;
        let o = match r.outcome {
            cast::ResponseOutcome::Replaced => ReceiptOutcome::Replaced,
            cast::ResponseOutcome::AlreadyCounted => ReceiptOutcome::AlreadyCounted,
            _ => ReceiptOutcome::Counted,
        };
        (o, r.leaf_index)
    };
    Ok(VerifiedReceipt {
        document: answer,
        outcome,
        leaf_index,
    })
}

/// Send a cast to its election's ballot box and check the receipt: resolve the ballot box, wait
/// `delay`, post, verify. The whole of a cast's journey, for a background job.
///
/// # Errors
///
/// As [`resolve_ballot_box`], [`post_cast`] and [`check_receipt`].
pub async fn deliver_cast(
    resolver: &DIDCacheClient,
    ballot_box: &str,
    cast: &Cast,
    delay: Duration,
) -> Result<VerifiedReceipt, CastError> {
    let base = resolve_ballot_box(resolver, ballot_box).await?;
    tokio::time::sleep(delay).await;
    let answer = post_cast(&base, cast).await?;
    let vm = vta_sdk::trust_task_proof::TrustTaskVmResolver::new(resolver.clone());
    check_receipt(answer, cast, ballot_box, &vm).await
}

#[cfg(test)]
mod tests;
