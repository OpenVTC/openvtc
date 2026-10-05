//! Everything vetting persists, in one place: `ProtectedConfig::vetting`.
//!
//! Protected rather than public because it names people. An application lists
//! who is vetting the applicant; the vetter desk lists who asked to be vetted
//! and, briefly, the card they showed. None of it belongs in plaintext config.
//!
//! V0 keeps this client-local. Moving tickets and the desk into VTA appstate is
//! V1, once `spec/vta/appstate/*` exists (design §11.2).

use super::protocol::{Admission, CriterionMeta, JoinProtocol};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use vta_sdk::protocols::join_requests::manifest;
use vta_sdk::protocols::vetting::{CheckShape, VettingRequirements, documentation};

use super::applicant::{Application, RequestState};
use super::queries::CommunityQuery;
use super::registry::VetterProfileRecord;
use super::tickets::{GuessThrottle, Ticket};
use super::vetter::{DeskEntry, DeskState, IssuedStatement, VetterError};
use crate::config::account::{Account, CommunityRecord, PersonaId};

/// A vetter's own rules (design §11.2). Every number is the vetter's choice;
/// the community decides what counts, not what a vetter must accept.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VetterPolicy {
    /// Requests a persona holds open at once; more are refused with
    /// `capacity`.
    pub max_open_requests: usize,
    /// How long a session stays open for the applicant to answer.
    pub session_minutes: i64,
    /// `validUntil` of a statement, from issue. A community's
    /// `maxStatementAge` is applied by the community regardless.
    pub statement_validity_days: i64,
    /// Days a received card is kept after the statement is issued or the
    /// request declined; afterwards only its digest remains.
    ///
    /// Default 0: the card's values — a legal name, at least — are forgotten
    /// at the first prune after the request closes. They are only ever needed
    /// to make the decision, and the signed statement already commits to the
    /// card by its digest, which is kept.
    pub card_retention_days: i64,
    /// The documentation this vetter accepts (D16), offered to applicants.
    pub accepts_documentation: Vec<String>,
}

impl Default for VetterPolicy {
    fn default() -> Self {
        Self {
            max_open_requests: 10,
            session_minutes: 15,
            statement_validity_days: 180,
            card_retention_days: 0,
            accepts_documentation: vec![
                documentation::PASSPORT.into(),
                documentation::NATIONAL_ID.into(),
                documentation::DRIVER_LICENCE.into(),
            ],
        }
    }
}

impl VetterPolicy {
    fn is_default(&self) -> bool {
        self == &Self::default()
    }

    /// [`Self::session_minutes`] as a duration.
    #[must_use]
    pub fn session_length(&self) -> Duration {
        Duration::minutes(self.session_minutes.clamp(1, 60))
    }

    /// [`Self::statement_validity_days`] as a duration.
    #[must_use]
    pub fn statement_validity(&self) -> Duration {
        Duration::days(self.statement_validity_days.max(1))
    }
}

/// The claim types a session asks for when the community's requirements are
/// not known. Every vetter of one application must ask for the same set, or
/// the cards commit to different identities — so a vetter should fetch the
/// manifest rather than rely on this.
pub const FALLBACK_REQUIRED_CLAIMS: &[&str] = &["name.legal"];

/// A community's vetting criterion, as last read from its manifest.
///
/// No `PartialEq`: it carries the generated [`VettingRequirements`], and the
/// generated wire types derive only `Serialize`, `Deserialize`, `Clone` and
/// `Debug`. Two criteria are compared by what they serialise to
/// ([`same_requirements`]), which is what "the community changed what it asks"
/// actually means.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KnownCriterion {
    /// The community.
    pub community: String,
    /// The criterion id.
    pub criterion_id: String,
    /// Its `requirementsDigest`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requirements_digest: Option<String>,
    /// What it requires.
    pub requirements: VettingRequirements,
    /// When it was read.
    pub fetched_at: DateTime<Utc>,
}

impl KnownCriterion {
    /// Whether this criterion proves vetting with a PCS zero-knowledge proof
    /// rather than named statements — read the same way an application adopts
    /// it ([`super::hidden::read_mode`]), so the badge and the join agree.
    ///
    /// An unreadable or refused mode reads as not hidden: this answers "should
    /// the page say vetters are hidden", and saying so wrongly is the error
    /// that matters.
    #[must_use]
    pub fn hidden_vetting(&self) -> bool {
        serde_json::to_value(&self.requirements).is_ok_and(|vetting| {
            matches!(
                super::hidden::read_mode(&serde_json::json!({ "vetting": vetting })),
                Ok(super::hidden::Mode::Hidden(_))
            )
        })
    }
}

/// A request we finished as a vetter, kept as a record that we vetted
/// someone and nothing more.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VettedRecord {
    /// The community it was for.
    pub community: String,
    /// When it closed.
    pub closed_at: DateTime<Utc>,
    /// How it ended.
    pub outcome: VettedOutcome,
}

/// How a finished request ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VettedOutcome {
    /// We signed a statement — its id, to find it in [`VettingBook::issued`].
    Signed { statement_id: String },
    /// We declined.
    Declined,
}

/// How many times in a row a vetter-side refresh that could not send is
/// retried (on the loop's five-second sweep) before waiting for the hourly one
/// — bounded, so a listener that never comes up does not mean asking forever
/// (R1.4).
pub const VETTER_REFRESH_RETRIES: u8 = 12;

/// How long a closed request stays on the desk before it moves to
/// [`VettingBook::vetted`]. Long enough for the send that closed it to report
/// back — a failed send restores the request, and must find it still there.
pub const CLOSED_GRACE: Duration = Duration::minutes(10);

/// A community naming one of our personas a vetter: the role credential it
/// issued through `vtc/vetting/vetters/grant` (design §10.3). Presented to
/// applicants with every acceptance, and needed to hand out tickets.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VetterGrant {
    /// The community that issued it.
    pub community: String,
    /// Our persona it names.
    pub persona: PersonaId,
    /// The credential's `id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    /// Its `validUntil`. A grant without one is never treated as live.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    /// When it arrived.
    pub received_at: DateTime<Utc>,
    /// The signed credential, exactly as delivered.
    pub credential: serde_json::Value,
}

/// The most enrolment requests whose blinding state is kept for a late answer.
pub const MAX_PENDING_ENROLMENTS: usize = 8;

/// An enrolment request on its way, with what opens its answer. Memory only.
#[derive(Clone)]
pub struct PendingEnrolment {
    /// The request's document id — what the answer threads on.
    pub document_id: String,
    /// The community asked.
    pub community: String,
    /// The persona that asked.
    pub persona: PersonaId,
    /// The blinding state that unblinds the answer.
    pub blinding: std::sync::Arc<openvtc_vetting_pcs::vetter::EnrolmentBlinding>,
}

impl std::fmt::Debug for PendingEnrolment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The blinding state is a secret of the round trip; it is never printed.
        f.debug_struct("PendingEnrolment")
            .field("document_id", &self.document_id)
            .field("community", &self.community)
            .field("persona", &self.persona)
            .finish_non_exhaustive()
    }
}

/// Our hidden-vetting engine for one community and persona.
///
/// A vetter holds one of these per community that runs hidden vetting: the key its identifier
/// and every tag derive from, the class credentials it has been issued, and the tokens it has
/// drawn. It is created when the community first issues a class credential and kept until the
/// last label it holds has closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HiddenVetterState {
    /// The community whose parameters this engine was built under.
    pub community: String,
    /// Our persona there — the member the community enrolled.
    pub persona: PersonaId,
    /// The community's published parameters: its keys as they stood when we enrolled, and its
    /// labels, rates and tick length as it last published them.
    ///
    /// Kept beside the engine rather than looked up per attestation, because a parsed criterion
    /// drops `ext` — the manifest's own extension point is where these live, and a
    /// `VettingRequirements` that has been through serde no longer carries them.
    ///
    /// The keys are pinned and the rest follows the manifest ([`Self::adopt_published`]): a new
    /// month is new labels under the same keys, and drawing on last month's labels would only be
    /// refused. New keys are a different matter — see [`Self::rekeyed_at`].
    pub params: super::hidden::HiddenParams,
    /// The engine, as [`openvtc_vetting_pcs::snapshot::VetterSnapshot`] stores it.
    pub snapshot: openvtc_vetting_pcs::snapshot::VetterSnapshot,
    /// The last drip tick we were served, **per token label**, so the next ask is the next tick
    /// and a restart does not re-ask for one the community has already served.
    ///
    /// Per label because a vetter in event mode owes two draws a tick: the event's, and the
    /// ordinary monthly one that must not be skipped while the event runs (§5.1). One counter
    /// would make the second draw look already served.
    #[serde(default)]
    pub last_ticks: std::collections::BTreeMap<String, u32>,
    /// When we last drew tokens. The drip is a schedule, not a response to demand (§5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_drawn_at: Option<DateTime<Utc>>,
    /// Events we have asked to vet at, with where each request stands.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<HiddenEventState>,
    /// When the community enrolled us under each class label, by period (`2026-10`).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub enrolled_at: std::collections::BTreeMap<String, DateTime<Utc>>,
    /// How many tokens we have spent on attestations here. A count of our own, shown to us and
    /// sent nowhere: the drip never depends on it.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub tokens_spent: u32,
    /// The last tick we were served.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_draw: Option<HiddenDraw>,
    /// The community's last refusal of a hidden-vetting request of ours, until something it
    /// asked for succeeds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_refusal: Option<HiddenRefusal>,
    /// Not before this: the community said a tick we asked for had not begun there yet
    /// (`tickNotYet`), so the next pass waits for its window rather than asking again now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_at: Option<DateTime<Utc>>,
    /// When we noticed the community publishing keys other than the ones we enrolled under.
    ///
    /// The drip stops here. A credential and every token we hold were issued under the old
    /// keys, so under the new ones they count for nothing, and drawing on would only be
    /// refused; re-enrolling silently under keys we were not told about would be worse. The
    /// vetter is told, once, and decides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rekeyed_at: Option<DateTime<Utc>>,
    /// Questions of ours (enrolment or a draw) in a row that the community did not answer within
    /// the reply window. Drives the backoff of [`Self::retry_at`] (R1.4) and how the desk says
    /// it; any answer from the community — served or refused — resets it.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub unanswered: u32,
    /// A class period (`2026-10`) the community enrolled us under whose answer this client could
    /// not open — it arrived after a restart, or was lost. Cleared by an enrolment that is
    /// opened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lost_enrolment: Option<String>,
    /// Whether the schedule has asked once more under [`Self::lost_enrolment`]'s label.
    ///
    /// A community may re-issue a lost answer to the identifier it enrolled (VTI #1972), so a
    /// lost label is asked for again — once. One that does not re-issue refuses that ask too
    /// (`alreadyEnrolled`), and the schedule then stops until the label moves on, rather than
    /// collecting the same refusal every pass. `k` (get tokens) clears it: asking by hand is
    /// worth one more try, and the community bounds how many re-issues it signs.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub lost_reasked: bool,
    /// Enrolments asked for whose answers have not been opened yet, each with the blinding that
    /// opens it — **written to the protected config before the request is sent**.
    ///
    /// The community issues one credential per member per label and keeps no copy of its
    /// answer, so an answer that arrives when the blinding is gone (a restart between the ask
    /// and the answer) can never be opened, and asking again is refused (`alreadyEnrolled`) —
    /// a lock-out until the community publishes a new label. Kept here, the blinding outlives a
    /// restart, and a late answer is still this vetter's credential. As secret as the
    /// snapshot's `usk`, and kept in the same place. Bounded to [`MAX_PENDING_ENROLMENTS`];
    /// dropped once an answer to it is opened or refused.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enrolments_asked: Vec<AskedEnrolment>,
}

/// One enrolment request in flight, as [`HiddenVetterState::enrolments_asked`] keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AskedEnrolment {
    /// The request's document id — what the answer threads on.
    pub document_id: String,
    /// The class period asked for (`2026-10`).
    pub period: String,
    /// SECRET: the blinding that opens the answer ([`super::hidden::blinding_text`]).
    pub blinding: String,
    /// When it was asked.
    pub asked_at: DateTime<Utc>,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

/// The first wait after a hidden-vetting question goes unanswered. Doubled for each silence in
/// a row, up to [`HIDDEN_RETRY_CAP`].
pub const HIDDEN_RETRY_FIRST: chrono::Duration = chrono::Duration::minutes(1);

/// The longest a vetter waits between asks of a community that does not answer — the same hour
/// the schedule re-reads every community on anyway.
pub const HIDDEN_RETRY_CAP: chrono::Duration = chrono::Duration::hours(1);

/// How long to wait after the `n`th unanswered question in a row (`n` ≥ 1): 1, 2, 4, … minutes,
/// capped at [`HIDDEN_RETRY_CAP`].
#[must_use]
pub fn hidden_retry_after(n: u32) -> chrono::Duration {
    let doublings = n.saturating_sub(1).min(16);
    (HIDDEN_RETRY_FIRST * 2_i32.pow(doublings)).min(HIDDEN_RETRY_CAP)
}

/// Where a vetter stands for attesting under one community's hidden vetting, in the terms the
/// desk, the attest form and the ticket gate all say it: what it holds, and when that changes.
///
/// Read from the engine and the book as they are — nothing here is estimated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HiddenOutlook {
    /// Tokens held under a label the community still accepts — what an attestation can spend.
    pub usable: usize,
    /// Whether we hold a credential under the community's current class label.
    pub enrolled: bool,
    /// The class period (`2026-10`) we owe an enrolment under, when not [`Self::enrolled`].
    pub owed: Option<String>,
    /// The community enrolled us under the current label and the answer could not be opened
    /// ([`HiddenVetterState::lost_enrolment`]).
    pub enrolment_lost: bool,
    /// An enrolment or a draw is on its way and not yet answered.
    pub asking: bool,
    /// Questions in a row the community did not answer.
    pub unanswered: u32,
    /// Not before this does the schedule ask again (`tickNotYet`, or a silence's backoff).
    pub retry_at: Option<DateTime<Utc>>,
    /// When the next tick window this vetter draws under opens.
    pub next_window: Option<DateTime<Utc>>,
    /// The community publishes keys other than the ones we enrolled under; drawing stopped.
    pub rekeyed: bool,
    /// The community runs events a vetter can ask to vet at, for more tokens (`e`).
    pub events_offered: bool,
    /// The community's last refusal, until something succeeds.
    pub last_refusal: Option<HiddenRefusal>,
}

/// One served tick of the drip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HiddenDraw {
    /// The token label.
    pub label: String,
    /// The tick.
    pub tick: u32,
    /// How many tokens it added.
    pub taken: usize,
    /// When it arrived.
    pub at: DateTime<Utc>,
}

/// A community's refusal of a hidden-vetting request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HiddenRefusal {
    /// What was asked for, in a few words.
    pub what: String,
    /// The declared code.
    pub code: String,
    /// When.
    pub at: DateTime<Utc>,
}

/// One pass of a community's hidden-vetting schedule, from [`HiddenVetterState::plan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HiddenPlan {
    /// What taking the published parameters found.
    pub adopted: Adopted,
    /// Whether stored ticks were dropped as meaningless ([`super::hidden::settle_ticks`]).
    pub settled: bool,
    /// What to ask for, in order: one enrolment, or draws oldest first.
    pub owed: Vec<super::hidden::Due>,
}

/// What [`HiddenVetterState::adopt_published`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Adopted {
    /// Nothing new.
    Unchanged,
    /// New labels, rates or tick length, under the keys we enrolled under — taken.
    Updated,
    /// The community publishes keys other than ours. Nothing was taken, and the drip stops.
    Rekeyed {
        /// Whether this is the first pass to notice, so the vetter is told once.
        first: bool,
    },
}

impl HiddenVetterState {
    /// A freshly minted engine for `community`, enrolled under nothing yet.
    #[must_use]
    pub fn new(
        community: impl Into<String>,
        persona: PersonaId,
        params: super::hidden::HiddenParams,
        snapshot: openvtc_vetting_pcs::snapshot::VetterSnapshot,
    ) -> Self {
        Self {
            community: community.into(),
            persona,
            params,
            snapshot,
            last_ticks: std::collections::BTreeMap::new(),
            last_drawn_at: None,
            events: Vec::new(),
            enrolled_at: std::collections::BTreeMap::new(),
            tokens_spent: 0,
            last_draw: None,
            last_refusal: None,
            retry_at: None,
            rekeyed_at: None,
            unanswered: 0,
            lost_enrolment: None,
            lost_reasked: false,
            enrolments_asked: Vec::new(),
        }
    }

    /// Keep the blinding of an enrolment about to be asked for, bounded: the oldest goes first.
    pub fn remember_asked(&mut self, asked: AskedEnrolment) {
        self.enrolments_asked
            .retain(|a| a.document_id != asked.document_id);
        self.enrolments_asked.push(asked);
        let excess = self
            .enrolments_asked
            .len()
            .saturating_sub(MAX_PENDING_ENROLMENTS);
        self.enrolments_asked.drain(..excess);
    }

    /// Take the stored enrolment `thread` answers, if it is one of ours.
    pub fn take_asked(&mut self, thread: &str) -> Option<AskedEnrolment> {
        let i = self
            .enrolments_asked
            .iter()
            .position(|a| a.document_id == thread)?;
        Some(self.enrolments_asked.remove(i))
    }

    /// The period this vetter owes an enrolment under now, if any: the community's current class
    /// label, when no credential under it is held.
    #[must_use]
    pub fn enrolment_owed(&self) -> Option<String> {
        let period = self
            .params
            .vetter_labels
            .first()?
            .trim_start_matches("vetter/")
            .to_string();
        (!self.snapshot.credentials.contains_key(&period)).then_some(period)
    }

    /// The community did not answer a question of ours in time: wait before asking again, a
    /// little longer each time it stays silent (R1.4), and never longer than
    /// [`HIDDEN_RETRY_CAP`]. Returns when the next ask is due.
    pub fn unanswered_at(&mut self, now: DateTime<Utc>) -> DateTime<Utc> {
        self.unanswered = self.unanswered.saturating_add(1);
        let retry = now + hidden_retry_after(self.unanswered);
        self.retry_at = Some(retry);
        retry
    }

    /// The community answered a question of ours, served or refused: it is there, so the next
    /// silence starts the backoff again from the bottom.
    pub fn answered(&mut self) {
        if self.unanswered > 0 {
            self.unanswered = 0;
            self.retry_at = None;
        }
    }

    /// Take what the community publishes now, keeping the keys we enrolled under.
    ///
    /// Labels, rates, events and the tick length follow the manifest: a month rolls over to new
    /// labels under the same keys, and a vetter fed the labels it enrolled under would never
    /// re-enrol and never draw under the new month. Keys do not follow: if the published ones
    /// differ from ours, nothing is taken and [`Self::rekeyed_at`] is set.
    pub fn adopt_published(
        &mut self,
        live: &super::hidden::HiddenParams,
        now: DateTime<Utc>,
    ) -> Adopted {
        if !self.params.same_keys(live) {
            let first = self.rekeyed_at.is_none();
            self.rekeyed_at.get_or_insert(now);
            return Adopted::Rekeyed { first };
        }
        let mut changed = self.rekeyed_at.take().is_some();
        if self.params != *live {
            self.params = live.clone();
            changed = true;
        }
        if changed {
            Adopted::Updated
        } else {
            Adopted::Unchanged
        }
    }

    /// Plan one pass of this community's schedule: everything owed now, in the order to ask.
    ///
    /// Takes `live` — the parameters the community publishes now — first, so a new month's
    /// labels are what is drawn under and enrolled for. Owes nothing while the community
    /// publishes keys other than ours ([`Self::rekeyed_at`]) or while a `tickNotYet` wait
    /// ([`Self::retry_at`]) has not run out. `in_flight` is the draws already asked for whose
    /// answers are on their way: asking for one of those again would replace the serials its
    /// answer unblinds under.
    pub fn plan(
        &mut self,
        live: Option<&super::hidden::HiddenParams>,
        in_flight: &[(String, u32)],
        now: DateTime<Utc>,
    ) -> HiddenPlan {
        use super::hidden::{Due, MAX_DRAWS_PER_PASS, due, settle_ticks};
        let adopted = live.map_or(Adopted::Unchanged, |live| self.adopt_published(live, now));
        let mut plan = HiddenPlan {
            adopted,
            settled: false,
            owed: Vec::new(),
        };
        if self.rekeyed_at.is_some() {
            return plan;
        }
        let events = self.event_draws(now.date_naive());
        plan.settled = settle_ticks(&mut self.last_ticks, &self.params, &events, now);
        if self.retry_at.is_some_and(|t| t > now) {
            return plan;
        }
        // `last_ticks` advances only when the community answers, so a working copy — with the
        // draws already on their way counted as asked — is what stops one pass asking for the
        // same tick over and over.
        let mut ticks = self.last_ticks.clone();
        for (label, tick) in in_flight {
            let entry = ticks.entry(label.clone()).or_insert(*tick);
            *entry = (*entry).max(*tick);
        }
        while plan.owed.len() < MAX_DRAWS_PER_PASS {
            match due(&self.params, Some(&self.snapshot), &ticks, &events, now) {
                Due::Nothing => break,
                // Enrolment blocks every draw behind it, so it is the whole plan.
                // Under a label whose answer we lost, ask once more — a community that
                // re-issues to the same identifier answers it — and then stop: one that
                // does not only refuses again ([`Self::lost_reasked`]).
                Due::Enrol { period } if self.lost_enrolment.as_deref() == Some(&period) => {
                    if !self.lost_reasked {
                        self.lost_reasked = true;
                        plan.owed.push(Due::Enrol { period });
                    }
                    break;
                }
                enrol @ Due::Enrol { .. } => {
                    plan.owed.push(enrol);
                    break;
                }
                Due::Draw { label, tick, rate } => {
                    ticks.insert(label.clone(), tick);
                    plan.owed.push(Due::Draw { label, tick, rate });
                }
            }
        }
        plan
    }

    /// Record a served tick: the highest served per label, whatever order the answers arrive
    /// in, so a catch-up answered out of order never asks for a tick twice.
    pub fn record_served(&mut self, label: &str, tick: u32) {
        let entry = self.last_ticks.entry(label.to_string()).or_insert(tick);
        *entry = (*entry).max(tick);
    }

    /// Tokens held here, and how many of them are under a label the community still accepts.
    #[must_use]
    pub fn tokens(&self) -> (usize, usize) {
        let held = self.snapshot.tokens.len();
        let usable = self
            .snapshot
            .tokens
            .iter()
            .filter(|t| self.params.token_labels.contains(&t.label))
            .count();
        (held, usable)
    }

    /// The event labels this vetter may draw under today, with the rate each yields.
    ///
    /// Only the approved ones, and only while their label is still accepted. A label the
    /// community publishes says an event exists; it never says we are in its group, and drawing
    /// under one we were not approved for would be refused — and would announce that we tried.
    ///
    /// An approved event the community no longer publishes is not drawn under either: its first
    /// day is where its ticks are counted from, and without it there is no tick to ask for.
    #[must_use]
    pub fn event_draws(&self, today: chrono::NaiveDate) -> Vec<super::hidden::EventDraw> {
        self.events
            .iter()
            .filter(|e| e.state == super::wire::pcs::EVENT_APPROVED)
            .filter_map(|e| {
                let label = e.label.clone()?;
                let closes_after = e.closes_after?;
                let opens_on = self
                    .params
                    .events
                    .iter()
                    .find(|o| o.event_id == e.event_id)?
                    .start_date;
                (today <= closes_after).then_some(super::hidden::EventDraw {
                    label,
                    rate: e.drip_per_tick.unwrap_or(self.params.drip_per_tick),
                    opens_on,
                    closes_after,
                })
            })
            .collect()
    }
}

/// Where one event-mode request stands, as the community last answered it.
///
/// `group_size` is a count and never a roster: who else is at the event is the anonymity set the
/// event's smaller token label is bought with. It is kept because it is the only way a vetter
/// can tell the two reasons for waiting apart — nobody has approved it, or not enough people
/// have asked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HiddenEventState {
    /// The community's name for the gathering.
    pub event_id: String,
    /// The tier we asked for.
    pub tier: String,
    /// `pending` or `approved`, in the community's own words.
    pub state: String,
    pub group_size: usize,
    pub group_floor: usize,
    /// The token label, once the event is live. Absent while pending — reading one as
    /// permission to draw is the mistake this shape makes awkward.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drip_per_tick: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closes_after: Option<chrono::NaiveDate>,
    /// When we last heard about it.
    pub answered_at: DateTime<Utc>,
}

/// Where one community has put us as a vetter: its grant, and the profile we
/// last sent it. One row of the vetting desk's header.
#[derive(Clone, Debug, PartialEq)]
pub struct VetterStanding {
    /// The community that named us.
    pub community: String,
    /// Our persona it named.
    pub persona: PersonaId,
    /// When the grant lapses, if it says.
    pub valid_until: Option<DateTime<Utc>>,
    /// Whether it is live now. A lapsed row is still shown — see
    /// [`VettingBook::vetter_standing`].
    pub live: bool,
    /// Live, but not for much longer.
    pub expiring: bool,
    /// Where the profile we last sent this community stands, if we sent one.
    pub profile: Option<super::registry::ProfileState>,
}

/// A vetter grant that has lapsed, or is about to, and whose holder has not
/// been told.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantWarning {
    /// The community whose grant it is.
    pub community: String,
    /// Our persona it names.
    pub persona: PersonaId,
    /// Whether it has lapsed already, as opposed to being about to.
    pub expired: bool,
    /// When it lapses, or lapsed.
    pub valid_until: DateTime<Utc>,
}

impl GrantWarning {
    /// Its identity, for saying a thing once.
    ///
    /// Carries the expiry, so a *reissued* grant is a different warning rather
    /// than one already given — a renewal moves `validUntil`, and without it in
    /// the identity the next lapse would be silently treated as said.
    #[must_use]
    pub fn id(&self) -> String {
        format!(
            "vetter-grant:{}:{}:{}:{}",
            self.community,
            self.persona,
            self.valid_until.to_rfc3339(),
            if self.expired { "expired" } else { "expiring" }
        )
    }
}

/// How long before a vetter grant lapses the holder is told.
///
/// A lapsed grant is not a warning in the moment it matters: it is an
/// applicant's request refused as `notEligible`, at their end, for a reason
/// they cannot fix. Fourteen days is enough for the community to be asked and
/// answer — asking is `AskResend`, and the community has to act — without the
/// warning standing so long it becomes part of the furniture.
pub const GRANT_EXPIRY_WARNING_DAYS: i64 = 14;

impl VetterGrant {
    /// Unexpired at `now`. Revocation is the community's to apply: a revoked
    /// grant stops the vetter's statements counting there.
    #[must_use]
    pub fn is_live(&self, now: DateTime<Utc>) -> bool {
        self.valid_until.is_some_and(|until| until > now)
    }

    /// Live, but lapsing within [`GRANT_EXPIRY_WARNING_DAYS`].
    ///
    /// False once it has lapsed — an expired grant is not "expiring", and the
    /// two are different things to say. Use [`is_live`](Self::is_live) for
    /// that.
    #[must_use]
    pub fn is_expiring(&self, now: DateTime<Utc>) -> bool {
        self.is_live(now)
            && self.valid_until.is_some_and(|until| {
                until <= now + chrono::TimeDelta::days(GRANT_EXPIRY_WARNING_DAYS)
            })
    }
}

/// How a community presents itself, from its manifest's `branding`.
///
/// Presentation only: nothing is trusted because of it. Kept as this crate's
/// own type rather than the SDK's, which refuses unknown members — a config
/// written by a newer build must still open.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Branding {
    /// The name the community gives itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// `#rrggbb`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accent_color: Option<String>,
}

impl Branding {
    fn is_default(&self) -> bool {
        self == &Self::default()
    }

    /// What of `branding` this client keeps: nothing, if it breaks its schema.
    fn from_manifest(branding: &manifest::v0_2::CommunityBranding) -> Self {
        if branding.check_shape().is_err() {
            return Self::default();
        }
        Self {
            display_name: branding
                .display_name
                .as_ref()
                .map(|n| n.as_str().to_string()),
            accent_color: branding
                .accent_color
                .as_ref()
                .map(|c| c.as_str().to_string()),
        }
    }

    /// The accent colour as RGB.
    #[must_use]
    pub fn accent_rgb(&self) -> Option<(u8, u8, u8)> {
        self.accent_color.as_deref().and_then(parse_accent)
    }
}

/// `#rrggbb` as RGB; `None` for anything else.
#[must_use]
pub fn parse_accent(color: &str) -> Option<(u8, u8, u8)> {
    let hex = color.strip_prefix('#')?;
    if hex.len() != 6 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let channel = |i: usize| u8::from_str_radix(&hex[i..i + 2], 16).ok();
    Some((channel(0)?, channel(2)?, channel(4)?))
}

/// A community whose manifest we have read — whether or not it vets.
///
/// The criteria alone cannot say "this community does not vet": a manifest
/// with no vetting criterion leaves none behind. This record is what tells
/// "does not vet" apart from "never asked".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownCommunity {
    /// The community.
    pub community: String,
    /// Its branding, if it publishes any.
    #[serde(default, skip_serializing_if = "Branding::is_default")]
    pub branding: Branding,
    /// What it asks an applicant to tell it about themselves
    /// (`requestedAttributes`). Empty when it asks nothing, and on a record
    /// written before this was kept — the next manifest read fills it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requested: Vec<crate::persona::join_answers::Asked>,
    /// When its manifest was last read.
    pub fetched_at: DateTime<Utc>,
    /// The `join-requests` version it answered its manifest in, which is the
    /// one its submit is sent in. `None` on a record written before this was
    /// kept, which reads as "ask 0.3 first" ([`super::protocol`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<JoinProtocol>,
    /// Every criterion it publishes, vetting or not, in published order: the
    /// routes in, and what meeting each one does. [`VettingBook::criteria`]
    /// keeps only the vetting ones, with their requirements.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<CommunityCriterion>,
    /// Whether its DID document, when last resolved, listed a post-quantum
    /// (ML-DSA) key for signing. `None` until it has been resolved here — the
    /// DIDComm route learns the manifest without a resolve of its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_quantum_key: Option<bool>,
    /// How its vetters vet, as its manifest last said, and when that was read — the last-known
    /// value only ([`super::mode`]). `None` on a record written before this was kept, and for a
    /// manifest whose mode could not be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vetter_mode: Option<super::mode::ModeRead>,
}

/// One criterion a community publishes, as the join page and the submit need
/// it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommunityCriterion {
    pub id: String,
    /// What a submit names to be decided under it (`submit/0.3` `criterion`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requirements_digest: Option<String>,
    /// Whether meeting it admits or submits for review. `None` from a 0.2
    /// manifest, which does not say.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission: Option<Admission>,
    /// Whether it requires an invitation credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invitation_required: Option<bool>,
    /// Whether it asks for vetting.
    #[serde(default)]
    pub vetting: bool,
}

/// What this book knows of whether a community vets its members.
///
/// No `PartialEq`: [`Knowledge::Vetting`] borrows a [`KnownCriterion`], which
/// carries the generated requirements. Match on it rather than compare it.
#[derive(Clone, Copy, Debug)]
pub enum Knowledge<'a> {
    /// Its manifest has not been read.
    Unknown,
    /// Its manifest names no vetting.
    NoVetting,
    /// It vets: its first vetting criterion.
    Vetting(&'a KnownCriterion),
}

/// Whether two published requirements are the same value.
///
/// The generated [`VettingRequirements`] derives no `PartialEq`, so they are
/// compared as what they serialise to — the wire value, which is what a
/// community actually changed.
#[must_use]
pub fn same_requirements(a: &VettingRequirements, b: &VettingRequirements) -> bool {
    serde_json::to_value(a).ok() == serde_json::to_value(b).ok()
}

/// All vetting state, for both sides.
///
/// No `PartialEq`: it holds applications, desk entries and criteria, and those
/// carry generated wire types that derive none.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VettingBook {
    /// Our applications, one per community and persona.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applications: Vec<Application>,
    /// Tickets we have issued as a vetter.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tickets: Vec<Ticket>,
    /// Requests people have made of us as a vetter.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub desk: Vec<DeskEntry>,
    /// Statements we have signed, kept so we can withdraw them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issued: Vec<IssuedStatement>,
    /// Requests we finished, as a note that we vetted someone — moved here
    /// from [`desk`](Self::desk) once closed, and holding nothing about the
    /// person: no card, no claims, no DID. A signed statement's applicant is
    /// still in [`issued`](Self::issued), where withdrawing needs it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vetted: Vec<VettedRecord>,
    /// A request arrived on the desk since the vetter side last re-read the
    /// communities it vets for. Set by the inbound handler, which cannot send;
    /// taken by the loop, which then asks — so a community that turned on PCS
    /// ZKP vetting is known before the vetter opens a session. Never saved: it
    /// is about this run.
    #[serde(skip)]
    pub vetter_refresh_due: bool,
    /// Consecutive vetter-side refreshes that could not send — at start-up the
    /// listener is often not up yet. Each failure schedules another, up to
    /// [`VETTER_REFRESH_RETRIES`]; a refresh that sends resets it. Not saved.
    #[serde(skip)]
    pub vetter_refresh_failures: u8,
    /// Recent wrong ticket codes.
    #[serde(default, skip_serializing_if = "GuessThrottle::is_empty")]
    pub throttle: GuessThrottle,
    /// Vetting criteria read from community manifests.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub criteria: Vec<KnownCriterion>,
    /// Our rules as a vetter.
    #[serde(default, skip_serializing_if = "VetterPolicy::is_default")]
    pub policy: VetterPolicy,
    /// Communities that named one of our personas a vetter.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vetter_grants: Vec<VetterGrant>,
    /// Grant lapses we have already warned about, by
    /// [`GrantWarning::id`](GrantWarning::id).
    ///
    /// Persisted so the warning is raised **once** and stays dismissed. The
    /// inbox task itself cannot answer "have we said this yet?": dismissing a
    /// task removes it, so an absent task means either never-raised or
    /// read-and-dismissed, and re-deciding hourly would put a warning the
    /// operator has already dealt with back every hour until the community
    /// acts — which is not in their gift.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grant_warnings: Vec<String>,
    /// Communities whose manifests we have read, with their branding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub communities: Vec<KnownCommunity>,
    /// The `join-requests` version to ask a community in, learned from a
    /// refusal before any manifest arrived: a community that refused 0.3 as an
    /// unsupported version is asked in 0.2 from then on. A manifest's own
    /// version ([`KnownCommunity::protocol`]) takes precedence.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub protocol_hints: std::collections::BTreeMap<String, JoinProtocol>,
    /// The vetter profile we last sent each community, per persona.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vetter_profiles: Vec<VetterProfileRecord>,
    /// Our hidden-vetting engine per community, where one runs it.
    ///
    /// **This carries secrets.** A snapshot's `usk` is the key every tag of ours derives from,
    /// so a copy of one links every attestation that persona ever made. It belongs exactly where
    /// the persona keys belong, and in the design's intended shape it lives in the VTA rather
    /// than here — see `openvtc_vetting_pcs::snapshot`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hidden_vetter: Vec<HiddenVetterState>,
    /// Hidden-vetting parameters each community published in its manifest, by community DID.
    ///
    /// Kept whether or not we vet for that community, and separately from
    /// [`HiddenVetterState::params`], because the two answer different questions: this is *what
    /// the community publishes*, refreshed every time a manifest arrives, and that is *what our
    /// engine runs under* — this, adopted on each pass of the schedule, as long as its keys are
    /// the ones we enrolled under ([`HiddenVetterState::adopt_published`]).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub hidden_published: std::collections::BTreeMap<String, super::hidden::HiddenParams>,
    /// What [`Self::retire_nonconformant`] set aside, one sentence each, for the
    /// Vetting page. Persisted so the notice survives the save that drops the
    /// credentials, and cleared by the operator ([`Self::clear_retired_for`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retired: Vec<String>,
    /// Questions put to communities and not yet answered. Memory only — see
    /// [`super::queries`].
    #[serde(skip)]
    pub queries: Vec<CommunityQuery>,
    /// The blinding state of an enrolment in flight. **Memory only, and deliberately**: it is
    /// useless without the community's answer and dangerous to keep past it, so an answer that
    /// arrives after a restart is dropped and the vetter asks again. That costs nothing — a
    /// request whose answer was never unblinded issued no credential anyone will count.
    ///
    /// Kept per request, and **past the reply window**: a community that answers late has still
    /// enrolled us, and refuses every second request under the same label, so an answer dropped
    /// because the question timed out locks the vetter out until the label moves on. Bounded to
    /// [`MAX_PENDING_ENROLMENTS`]; the oldest goes first.
    #[serde(skip)]
    pub pending_enrolments: Vec<PendingEnrolment>,
    /// The drip ticks asked for and not yet answered, by request document id: `(label, tick)`.
    ///
    /// Memory only, like [`Self::queries`]: it is how a refusal, which names neither, finds the
    /// draw it refuses — and how a pass knows not to ask again for a tick whose answer is still
    /// on its way, which would replace the serials that answer unblinds under. After a restart
    /// nothing is on its way, and a tick asked for again replaces its stale serials.
    #[serde(skip)]
    pub draws_in_flight: std::collections::HashMap<String, (String, u32)>,
    /// When each community's mode was last asked for, and how the last attempt failed.
    /// **Memory only**: a failure is news about this run's network, not a fact about the
    /// community, and the reading it sits beside is persisted on its own ([`super::mode`]).
    #[serde(skip)]
    pub mode_checks: super::mode::ModeChecks,
    /// Communities seen changing mode between two readings, for the page to say once. Memory
    /// only.
    #[serde(skip)]
    pub mode_switches: Vec<super::mode::ModeSwitch>,
    /// Fields written by a newer build, preserved verbatim (D19).
    #[serde(flatten, default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl VettingBook {
    /// Set aside every stored vetting credential that does not conform to DTG
    /// Credentials v1, and say so in [`Self::retired`]. Run once on load
    /// (`ProtectedConfig::parse`).
    ///
    /// Two stores hold credentials:
    ///
    /// - **vetter grants** — the community role credential we present to
    ///   applicants. A pre-v1 one (a role endorsement credential) is refused by
    ///   every applicant under the current specification, so presenting it only
    ///   produces `notEligible` at the far end. Dropped; the community has to
    ///   grant the role again, as a VAC.
    /// - **held statements** — the Vetting Statements an application collected.
    ///   A pre-v1 statement is not a `vetted/1` VSC and a community will not
    ///   count it. Dropped; the application asks for vetting again.
    ///
    /// What we *issued* as a vetter is kept: it records an id and a digest for
    /// withdrawal, not a credential.
    ///
    /// Returns how many were set aside.
    pub fn retire_nonconformant(&mut self) -> usize {
        let mut notes = Vec::new();
        self.vetter_grants.retain(|grant| {
            match crate::dtg::nonconformance(&grant.credential) {
                None => true,
                Some(reason) => {
                    tracing::warn!(
                        community = %grant.community,
                        %reason,
                        "dropping a stored vetter role credential that does not conform to DTG Credentials v1"
                    );
                    notes.push(format!(
                        "Your vetter role credential from {} pre-dates DTG Credentials v1 and \
                         was set aside. Ask the community to grant the vetter role again.",
                        grant.community
                    ));
                    false
                }
            }
        });
        for application in &mut self.applications {
            let community = application.community.clone();
            application.statements.retain(|held| {
                match crate::dtg::nonconformance(&held.credential) {
                    None => true,
                    Some(reason) => {
                        tracing::warn!(
                            %community,
                            vetter = %held.vetter,
                            %reason,
                            "dropping a stored vetting statement that does not conform to DTG Credentials v1"
                        );
                        notes.push(format!(
                            "A vetting statement from {} for {community} pre-dates DTG \
                             Credentials v1 and was set aside. Ask to be vetted again.",
                            held.vetter
                        ));
                        false
                    }
                }
            });
        }
        let count = notes.len();
        for note in notes {
            if !self.retired.contains(&note) {
                self.retired.push(note);
            }
        }
        count
    }

    /// Our hidden-vetting engine for `community` and `persona`, if one has been enrolled.
    #[must_use]
    pub fn hidden_vetter(&self, community: &str, persona: PersonaId) -> Option<&HiddenVetterState> {
        self.hidden_vetter
            .iter()
            .find(|h| h.community == community && h.persona == persona)
    }

    /// Keep the blinding state of an enrolment request until its answer arrives — even late.
    pub fn remember_enrolment(&mut self, pending: PendingEnrolment) {
        self.pending_enrolments
            .retain(|p| p.document_id != pending.document_id);
        self.pending_enrolments.push(pending);
        let excess = self
            .pending_enrolments
            .len()
            .saturating_sub(MAX_PENDING_ENROLMENTS);
        self.pending_enrolments.drain(..excess);
    }

    /// The enrolment request `thread` names, sent to `community`, with what opens its answer.
    pub fn take_enrolment(&mut self, community: &str, thread: &str) -> Option<PendingEnrolment> {
        let i = self
            .pending_enrolments
            .iter()
            .position(|p| p.document_id == thread && p.community == community)?;
        Some(self.pending_enrolments.remove(i))
    }

    /// Where `persona` stands for attesting under `community`'s hidden vetting, or `None` when
    /// it holds no engine there.
    #[must_use]
    pub fn hidden_outlook(
        &self,
        community: &str,
        persona: PersonaId,
        now: DateTime<Utc>,
    ) -> Option<HiddenOutlook> {
        use super::queries::QueryKind;
        let held = self.hidden_vetter(community, persona)?;
        let owed = held.enrolment_owed();
        let events = held.event_draws(now.date_naive());
        // The answer to this label's enrolment was lost: recorded as such, or — on a record
        // written before that was — the community's last word was `alreadyEnrolled` during the
        // owed period. Either way asking again only collects the same refusal.
        let refused_as_enrolled = held.last_refusal.as_ref().is_some_and(|r| {
            r.code.ends_with(":alreadyEnrolled")
                && owed.as_deref() == Some(r.at.format("%Y-%m").to_string().as_str())
        });
        let asking = self.queries.iter().any(|q| {
            q.community == community
                && q.persona == persona
                && matches!(q.kind, QueryKind::PcsRoot | QueryKind::PcsTokens)
        });
        Some(HiddenOutlook {
            usable: held.tokens().1,
            enrolled: owed.is_none(),
            // Lost for good only once the one more ask has been answered with a refusal too;
            // until then — not yet asked, or on its way — there is still an answer to wait for.
            enrolment_lost: owed.is_some()
                && ((owed == held.lost_enrolment && held.lost_reasked && !asking)
                    || (held.lost_enrolment.is_none() && refused_as_enrolled)),
            owed,
            asking,
            unanswered: held.unanswered,
            retry_at: held.retry_at.filter(|t| *t > now),
            next_window: super::hidden::next_window(&held.params, &events, now),
            rekeyed: held.rekeyed_at.is_some(),
            events_offered: !held.params.events.is_empty(),
            last_refusal: held.last_refusal.clone(),
        })
    }

    /// The same, to write.
    pub fn hidden_vetter_mut(
        &mut self,
        community: &str,
        persona: PersonaId,
    ) -> Option<&mut HiddenVetterState> {
        self.hidden_vetter
            .iter_mut()
            .find(|h| h.community == community && h.persona == persona)
    }

    /// Attest to a request the hidden way: no statement, no signature, nothing that names us.
    ///
    /// The facts are the ones [`Self::statement_draft`] builds — the same checklist, the same
    /// refusals, the same identity commitment and card digest — so a vetter's obligations do not
    /// change with the path. What changes is the last step: instead of signing an endorsement
    /// whose issuer is this persona, the engine spends a token and produces an attestation that
    /// carries a tag in place of a name.
    ///
    /// The desk entry moves to `Attested` with the attestation's own identifier in place of a
    /// statement id, so the request closes exactly as the named path closes it. Nothing is added
    /// to [`Self::issued`]: there is no statement to withdraw, and a withdrawal on this path is a
    /// different mechanism (design §4.4).
    ///
    /// # Errors
    ///
    /// - [`VetterError::NoSuchRequest`] / [`VetterError::WrongState`] as for the named path.
    /// - [`VetterError::Shape`] if the checklist does not support the statement.
    /// - [`VetterError::Hidden`] if this persona holds no engine for the community, if the
    ///   request carries no PCS identifier, or if the engine has no live credential or no free
    ///   token — the last is `atCapacity`, and the vetter declines rather than attests.
    pub fn attest_hidden<R: rand::RngCore + rand::CryptoRng>(
        &mut self,
        request_id: &str,
        vetter_did: &str,
        attestation: super::vetter::Attestation,
        now: DateTime<Utc>,
        rng: &mut R,
    ) -> Result<serde_json::Value, VetterError> {
        let entry = self
            .desk_entry(request_id)
            .ok_or(VetterError::NoSuchRequest)?
            .clone();
        let applicant_id = super::hidden::read_request_ext(
            entry
                .request
                .ext
                .as_ref()
                .map(|e| serde_json::to_value(e).unwrap_or(serde_json::Value::Null))
                .as_ref(),
        )
        .map_err(VetterError::Hidden)?
        .ok_or_else(|| {
            VetterError::Hidden(super::hidden::HiddenError::Unreadable(
                "this request carries no hidden-vetting identifier, so there is nobody to attest \
                 to under this community's criterion"
                    .into(),
            ))
        })?;

        // The same draft the named path signs. Building it here is what keeps one checklist:
        // a claim the card does not carry, or a documentary method with nothing to rely on, is
        // refused on both paths by the same code.
        let draft = self.statement_draft(request_id, vetter_did, attestation, now)?;
        // The digest the applicant asked under. A vetter attests to the criterion the
        // applicant is applying for, and the community checks that the two agree.
        let digest = entry
            .request
            .requirements_digest
            .as_ref()
            .map(|d| d.as_str().to_string())
            .unwrap_or_default();
        let meta =
            super::hidden::statement_meta(&draft, &entry.community, &digest).ok_or_else(|| {
                VetterError::Hidden(super::hidden::HiddenError::Unreadable(
                    "the statement carries no vetter members, so it is not a vetter's to attest \
                     with"
                        .into(),
                ))
            })?;

        let state = self
            .hidden_vetter_mut(&entry.community, entry.persona)
            .ok_or(VetterError::Hidden(super::hidden::HiddenError::NotEnrolled))?;
        let params = state.params.clone();
        let wire = super::hidden::attest(
            &entry.community,
            &params,
            &mut state.snapshot,
            &applicant_id,
            meta,
            rng,
        )
        .map_err(VetterError::Hidden)?;
        state.tokens_spent = state.tokens_spent.saturating_add(1);

        let entry = self
            .desk_entry_mut(request_id)
            .ok_or(VetterError::NoSuchRequest)?;
        let DeskState::CardReceived { card, .. } = &entry.state else {
            return Err(VetterError::WrongState("be attested"));
        };
        entry.state = DeskState::Attested {
            statement_id: format!("urn:openvtc:hidden-attestation:{request_id}"),
            issued_at: now,
            card: card.clone(),
        };
        entry.updated_at = now;
        Ok(wire)
    }

    /// Nothing to persist — keeps a config without vetting byte-identical.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.applications.is_empty()
            && self.tickets.is_empty()
            && self.desk.is_empty()
            && self.issued.is_empty()
            && self.throttle.is_empty()
            && self.criteria.is_empty()
            && self.policy.is_default()
            && self.vetter_grants.is_empty()
            && self.communities.is_empty()
            && self.vetter_profiles.is_empty()
            && self.retired.is_empty()
            && self.extra.is_empty()
    }

    /// Keep `grant`, replacing an earlier one from the same community for the
    /// same persona. Returns whether anything changed.
    pub fn keep_vetter_grant(&mut self, grant: VetterGrant) -> bool {
        let same = |g: &VetterGrant| g.community == grant.community && g.persona == grant.persona;
        if let Some(existing) = self.vetter_grants.iter_mut().find(|g| same(g)) {
            if existing.credential == grant.credential {
                return false;
            }
            let community = grant.community.clone();
            *existing = grant;
            self.clear_retired_for(&community);
        } else {
            self.clear_retired_for(&grant.community.clone());
            self.vetter_grants.push(grant);
        }
        true
    }

    /// Drop the [`Self::retired`] notices about `community` once a conformant
    /// replacement from it has been stored.
    pub fn clear_retired_for(&mut self, community: &str) {
        self.retired.retain(|note| !note.contains(community));
    }

    /// `persona`'s live vetter grant from `community`.
    #[must_use]
    pub fn vetter_grant(
        &self,
        community: &str,
        persona: PersonaId,
        now: DateTime<Utc>,
    ) -> Option<&VetterGrant> {
        self.vetter_grants
            .iter()
            .find(|g| g.community == community && g.persona == persona && g.is_live(now))
    }

    /// Where we stand as a vetter with every community that has ever named us
    /// one — the grant it issued, live or lapsed, and where the profile we last
    /// sent it got to.
    ///
    /// **Lapsed grants are included, deliberately.** Everything else on the
    /// vetter side filters to a *live* grant, which is right — a lapsed vetter
    /// cannot hand out tickets and their requests would be refused. But that
    /// makes a lapse invisible exactly when it needs explaining: the communities
    /// simply stop being listed, with nothing saying why or that asking for the
    /// grant again (`AskResend`) is the fix. This is the one view that shows the
    /// lapse.
    ///
    /// Ordered by community, so the rows do not reshuffle between frames.
    #[must_use]
    pub fn vetter_standing(&self, now: DateTime<Utc>) -> Vec<VetterStanding> {
        let mut standing: Vec<VetterStanding> = self
            .vetter_grants
            .iter()
            .map(|grant| VetterStanding {
                community: grant.community.clone(),
                persona: grant.persona,
                valid_until: grant.valid_until,
                live: grant.is_live(now),
                expiring: grant.is_expiring(now),
                profile: self
                    .vetter_profile(&grant.community, grant.persona)
                    .map(|record| record.state.clone()),
            })
            .collect();
        standing.sort_by(|a, b| {
            a.community
                .cmp(&b.community)
                .then(a.persona.cmp(&b.persona))
        });
        standing
    }

    /// Grants that have lapsed or are about to, for warning their holder.
    ///
    /// A grant with no `validUntil` is skipped: it is never live, so there is
    /// nothing to lose, and a standing warning about a credential that never
    /// worked helps nobody.
    #[must_use]
    pub fn grants_needing_attention(&self, now: DateTime<Utc>) -> Vec<&VetterGrant> {
        self.vetter_grants
            .iter()
            .filter(|g| g.valid_until.is_some() && (!g.is_live(now) || g.is_expiring(now)))
            .collect()
    }

    /// The grant warnings owed right now and not yet given, recording them as
    /// given. Also forgets warnings whose grant no longer needs one, so a
    /// reissued grant that later lapses is warned about again.
    ///
    /// Returns what to raise. Empty is the common case and writes nothing, so
    /// an hourly caller costs a scan of a short list.
    ///
    /// The identity includes the *state*, so the step from "about to lapse" to
    /// "lapsed" is a second, different warning rather than a repeat of the
    /// first — they say different things and the second is the one that
    /// explains a desk gone quiet.
    pub fn take_grant_warnings(&mut self, now: DateTime<Utc>) -> Vec<GrantWarning> {
        let owed: Vec<GrantWarning> = self
            .grants_needing_attention(now)
            .into_iter()
            .map(|g| GrantWarning {
                community: g.community.clone(),
                persona: g.persona,
                expired: !g.is_live(now),
                valid_until: g.valid_until.unwrap_or(now),
            })
            .collect();

        // Forget anything no longer owed: a renewed grant, or one whose
        // "expiring" warning has been superseded by its "expired" one.
        let live_ids: Vec<String> = owed.iter().map(GrantWarning::id).collect();
        self.grant_warnings.retain(|id| live_ids.contains(id));

        let mut new = Vec::new();
        for warning in owed {
            let id = warning.id();
            if !self.grant_warnings.contains(&id) {
                self.grant_warnings.push(id);
                new.push(warning);
            }
        }
        new
    }

    /// Remember `community`'s vetting criteria from its manifest, replacing
    /// what was known. Returns whether anything changed.
    /// What `community` asks an applicant to tell it about themselves, as of
    /// its last manifest read. Empty when it asks nothing or has not been read.
    #[must_use]
    pub fn requested_attributes(
        &self,
        community: &str,
    ) -> Vec<crate::persona::join_answers::Asked> {
        self.communities
            .iter()
            .find(|c| c.community == community)
            .map(|c| c.requested.clone())
            .unwrap_or_default()
    }

    pub fn learn_manifest(
        &mut self,
        community: &str,
        manifest: &manifest::v0_2::Response,
        now: DateTime<Utc>,
    ) -> bool {
        self.learn_manifest_in(community, manifest, None, &[], now)
    }

    /// [`Self::learn_manifest`], recording the version the manifest arrived in
    /// and what that version says about each criterion beyond its 0.2 shape
    /// ([`super::protocol::read_manifest`]).
    pub fn learn_manifest_in(
        &mut self,
        community: &str,
        manifest: &manifest::v0_2::Response,
        protocol: Option<JoinProtocol>,
        meta: &[CriterionMeta],
        now: DateTime<Utc>,
    ) -> bool {
        let routes: Vec<CommunityCriterion> = manifest
            .criteria
            .iter()
            .map(|c| {
                let id = c.id.as_str().to_string();
                let m = meta.iter().find(|m| m.id == id);
                CommunityCriterion {
                    requirements_digest: c
                        .requirements_digest
                        .as_ref()
                        .map(|d| d.as_str().to_string()),
                    admission: m.and_then(|m| m.admission),
                    invitation_required: m.and_then(|m| m.invitation_required),
                    vetting: c.vetting.is_some(),
                    id,
                }
            })
            .collect();
        let fresh: Vec<KnownCriterion> = manifest
            .criteria
            .iter()
            .filter_map(|c| {
                let requirements = c.vetting.clone()?;
                requirements.check_shape().ok()?;
                Some(KnownCriterion {
                    community: community.to_string(),
                    criterion_id: c.id.as_str().to_string(),
                    requirements_digest: c
                        .requirements_digest
                        .as_ref()
                        .map(|d| d.as_str().to_string()),
                    requirements,
                    fetched_at: now,
                })
            })
            .collect();
        let known: Vec<&KnownCriterion> = self
            .criteria
            .iter()
            .filter(|k| k.community == community)
            .collect();
        let unchanged = known.len() == fresh.len()
            && known.iter().zip(&fresh).all(|(a, b)| {
                a.criterion_id == b.criterion_id
                    && a.requirements_digest == b.requirements_digest
                    && same_requirements(&a.requirements, &b.requirements)
            });
        self.criteria.retain(|k| k.community != community);
        self.criteria.extend(fresh);

        let branding = manifest
            .branding
            .as_ref()
            .map(Branding::from_manifest)
            .unwrap_or_default();
        let requested = crate::persona::join_answers::asked(manifest);
        // A re-read refreshes `fetched_at` without counting as a change: the
        // same manifest again is not worth a save.
        let branding_changed = match self
            .communities
            .iter_mut()
            .find(|c| c.community == community)
        {
            Some(known) => {
                known.fetched_at = now;
                let changed = known.branding != branding
                    || known.requested != requested
                    || known.routes != routes
                    || (protocol.is_some() && known.protocol != protocol);
                known.branding = branding;
                known.requested = requested;
                known.routes = routes;
                if protocol.is_some() {
                    known.protocol = protocol;
                }
                changed
            }
            None => {
                self.communities.push(KnownCommunity {
                    community: community.to_string(),
                    branding,
                    requested,
                    fetched_at: now,
                    protocol,
                    routes,
                    post_quantum_key: None,
                    vetter_mode: None,
                });
                true
            }
        };
        !unchanged || branding_changed
    }

    /// Whether `community` vets its members, as far as this book knows.
    ///
    /// Criteria recorded before communities were ([`KnownCommunity`]) still
    /// count as knowing that it vets.
    #[must_use]
    pub fn knowledge(&self, community: &str) -> Knowledge<'_> {
        if let Some(criterion) = self.criteria.iter().find(|k| k.community == community) {
            return Knowledge::Vetting(criterion);
        }
        if self.communities.iter().any(|c| c.community == community) {
            Knowledge::NoVetting
        } else {
            Knowledge::Unknown
        }
    }

    /// The `join-requests` version `community` answered in, or the one to ask
    /// first when it has not answered.
    #[must_use]
    pub fn protocol_for(&self, community: &str) -> JoinProtocol {
        self.communities
            .iter()
            .find(|c| c.community == community)
            .and_then(|c| c.protocol)
            .or_else(|| self.protocol_hints.get(community).copied())
            .unwrap_or_default()
    }

    /// `community` refused a request in `asked` as a version it does not
    /// serve: remember the version to fall back to and return it, or `None`
    /// when there is nothing older to try.
    pub fn fall_back_from(&mut self, community: &str, asked: JoinProtocol) -> Option<JoinProtocol> {
        let next = asked.fallback()?;
        self.protocol_hints.insert(community.to_string(), next);
        if let Some(known) = self
            .communities
            .iter_mut()
            .find(|c| c.community == community)
            && known.protocol == Some(asked)
        {
            known.protocol = Some(next);
        }
        Some(next)
    }

    /// Every criterion `community` publishes, in published order. Empty when
    /// its manifest has not been read.
    /// Record what `community`'s DID document says about post-quantum signing.
    /// Only for a community this book has a record of; the manifest read that
    /// makes one comes first.
    pub fn note_post_quantum_key(&mut self, community: &str, publishes: bool) {
        if let Some(known) = self
            .communities
            .iter_mut()
            .find(|c| c.community == community)
        {
            known.post_quantum_key = Some(publishes);
        }
    }

    /// Whether `community`'s DID document listed a post-quantum signing key
    /// when last resolved; `None` when it has not been resolved here.
    #[must_use]
    pub fn post_quantum_key(&self, community: &str) -> Option<bool> {
        self.communities
            .iter()
            .find(|c| c.community == community)
            .and_then(|c| c.post_quantum_key)
    }

    /// Whether `community` proves vetting with a PCS zero-knowledge proof, as
    /// far as its last-read requirements say.
    #[must_use]
    pub fn hidden_vetting(&self, community: &str) -> bool {
        self.criteria
            .iter()
            .any(|k| k.community == community && k.hidden_vetting())
    }

    #[must_use]
    pub fn routes(&self, community: &str) -> &[CommunityCriterion] {
        self.communities
            .iter()
            .find(|c| c.community == community)
            .map_or(&[], |c| c.routes.as_slice())
    }

    /// `community`'s branding, if it publishes any.
    #[must_use]
    pub fn branding(&self, community: &str) -> Option<&Branding> {
        self.communities
            .iter()
            .find(|c| c.community == community)
            .map(|c| &c.branding)
            .filter(|b| !b.is_default())
    }

    /// Give application `application_id` the requirements already known for
    /// its community — the criterion it chose, else the first — so a new
    /// application shows them before its own manifest request is answered.
    /// Returns whether anything changed.
    pub fn adopt_known_requirements(&mut self, application_id: &str) -> bool {
        let Some(app) = self.applications.iter().find(|a| a.id == application_id) else {
            return false;
        };
        let mut known = self
            .criteria
            .iter()
            .filter(|k| k.community == app.community);
        let chosen = app
            .criterion_id
            .as_deref()
            .and_then(|id| {
                self.criteria
                    .iter()
                    .find(|k| k.community == app.community && k.criterion_id == id)
            })
            .or_else(|| known.next())
            .cloned();
        let (Some(criterion), Some(app)) = (chosen, self.application_by_id_mut(application_id))
        else {
            return false;
        };
        let changed = !app
            .requirements
            .as_ref()
            .is_some_and(|r| same_requirements(r, &criterion.requirements))
            || app.requirements_digest != criterion.requirements_digest
            || app.criterion_id.as_deref() != Some(criterion.criterion_id.as_str());
        app.criterion_id = Some(criterion.criterion_id);
        app.requirements = Some(criterion.requirements);
        app.requirements_digest = criterion.requirements_digest;
        changed
    }

    /// Active memberships holding no live vetter grant — where a member the
    /// community did name a vetter may simply never have received the
    /// credential, and can ask for it again.
    #[must_use]
    pub fn resend_candidates<'a>(
        &self,
        account: &'a Account,
        now: DateTime<Utc>,
    ) -> Vec<&'a CommunityRecord> {
        account
            .memberships()
            .filter(|m| m.status.is_active())
            .filter(|m| self.vetter_grant(&m.vtc_did, m.persona_ref, now).is_none())
            .collect()
    }

    /// The claim types a session for `community` should require: those of the
    /// criterion with `digest` (what the applicant named), else the community's
    /// first vetting criterion, else [`FALLBACK_REQUIRED_CLAIMS`]. The second
    /// value says whether the community's requirements were known.
    #[must_use]
    pub fn required_claims_for(
        &self,
        community: &str,
        digest: Option<&str>,
    ) -> (Vec<String>, bool) {
        let mut ours = self.criteria.iter().filter(|k| k.community == community);
        let chosen = digest
            .and_then(|d| {
                self.criteria.iter().find(|k| {
                    k.community == community && k.requirements_digest.as_deref() == Some(d)
                })
            })
            .or_else(|| ours.next());
        match chosen {
            // `requiredClaims` is an optional list of the generated `ClaimType`
            // on this line, so an absent list and an empty one are one case.
            Some(k) => (
                k.requirements
                    .required_claims
                    .iter()
                    .flatten()
                    .map(|c| c.as_str().to_string())
                    .collect(),
                true,
            ),
            None => (
                FALLBACK_REQUIRED_CLAIMS
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                false,
            ),
        }
    }

    /// How long `community` says it takes to decide a join (`decisionSla`),
    /// from our application as `persona` or else what we know of its criteria.
    /// `None` when it has not said, or said something unparseable.
    #[must_use]
    pub fn decision_sla(&self, community: &str, persona: PersonaId) -> Option<Duration> {
        let from_application = self
            .application(community, persona)
            .and_then(|a| a.requirements.as_ref())
            .and_then(|r| r.decision_sla.clone());
        let from_criteria = || {
            self.criteria
                .iter()
                .filter(|k| k.community == community)
                .find_map(|k| k.requirements.decision_sla.clone())
        };
        from_application
            .or_else(from_criteria)
            .and_then(|sla| vta_sdk::protocols::vetting::parse_iso8601_duration(sla.as_str()))
    }

    /// Our application to `community` as `persona`.
    #[must_use]
    pub fn application(&self, community: &str, persona: PersonaId) -> Option<&Application> {
        self.applications
            .iter()
            .find(|a| a.community == community && a.persona == persona)
    }

    /// Mutable [`Self::application`].
    pub fn application_mut(
        &mut self,
        community: &str,
        persona: PersonaId,
    ) -> Option<&mut Application> {
        self.applications
            .iter_mut()
            .find(|a| a.community == community && a.persona == persona)
    }

    /// The application with this id.
    pub fn application_by_id_mut(&mut self, id: &str) -> Option<&mut Application> {
        self.applications.iter_mut().find(|a| a.id == id)
    }

    /// The application `persona` is making to `community`, started if there is
    /// none yet. `join_did` is the persona's DID, and the design fixes it when
    /// the application starts (D13).
    ///
    /// # Errors
    ///
    /// Only if the platform has no randomness for the commitment salt.
    pub fn start_application(
        &mut self,
        community: &str,
        persona: PersonaId,
        join_did: &str,
        now: DateTime<Utc>,
    ) -> Result<&mut Application, vta_sdk::vetting::VettingError> {
        if let Some(i) = self
            .applications
            .iter()
            .position(|a| a.community == community && a.persona == persona)
        {
            return Ok(&mut self.applications[i]);
        }
        self.applications
            .push(Application::new(community, persona, join_did, now)?);
        Ok(self.applications.last_mut().expect("just pushed"))
    }

    /// Drop the applications whose join is done and that have nothing left to
    /// present: `joined` says the application's persona is an active member of
    /// its community, and nothing it holds could be presented again — every
    /// named statement past its `validUntil`, and no hidden-vetting attestation
    /// held. Returns how many went.
    ///
    /// Kept until then on purpose. Leaving and rejoining as the same persona
    /// presents the statements it still holds (one vetting, not two), so an
    /// application is only noise once that can no longer happen.
    pub fn retire_joined(
        &mut self,
        joined: impl Fn(&Application) -> bool,
        now: DateTime<Utc>,
    ) -> usize {
        let before = self.applications.len();
        self.applications.retain(|a| {
            !(joined(a)
                && a.presentable_statements(now).is_empty()
                && !a.holds_hidden_attestation())
        });
        before - self.applications.len()
    }

    /// Abandon an application, returning it.
    ///
    /// Vetting is client-side until the join is submitted: nothing was sent to
    /// the community, so there is nothing to withdraw from it and nobody to
    /// tell. What goes is local — the application, the statements gathered for
    /// it, and the record of which vetters were asked.
    ///
    /// The vetters are the part worth knowing about. A vetter who accepted a
    /// request still holds it at their desk; abandoning here does not reach
    /// them, and a session they open afterwards will find no application to
    /// answer. That is a loose end this cannot tidy from one side, and it is
    /// why the caller confirms first.
    ///
    /// Needed because an application is otherwise permanent. Started as the
    /// wrong persona — easy, since the persona is fixed for its whole life —
    /// it would own that community's vetting route forever.
    pub fn abandon_application(&mut self, id: &str) -> Option<Application> {
        let i = self.applications.iter().position(|a| a.id == id)?;
        Some(self.applications.remove(i))
    }

    /// The desk entry with our `request_id`.
    #[must_use]
    pub fn desk_entry(&self, request_id: &str) -> Option<&DeskEntry> {
        self.desk.iter().find(|e| e.request_id == request_id)
    }

    /// Mutable [`Self::desk_entry`].
    pub fn desk_entry_mut(&mut self, request_id: &str) -> Option<&mut DeskEntry> {
        self.desk.iter_mut().find(|e| e.request_id == request_id)
    }

    /// Requests `persona` has accepted and not yet finished.
    #[must_use]
    pub fn open_requests(&self, persona: PersonaId) -> usize {
        self.desk
            .iter()
            .filter(|e| e.persona == persona && e.state.is_open())
            .count()
    }

    /// Let time pass: close sessions nobody answered, forget cards past their
    /// retention, move finished requests off the desk into
    /// [`vetted`](Self::vetted), and drop tickets that can admit nothing.
    /// Returns whether anything changed.
    pub fn prune(&mut self, now: DateTime<Utc>) -> bool {
        let mut changed = false;

        let before = self.tickets.len();
        self.tickets
            .retain(|t| t.is_live(now) || now - t.expires_at.min(now) < Duration::days(1));
        changed |= self.tickets.len() != before;

        let retention = Duration::days(self.policy.card_retention_days.max(0));
        for entry in &mut self.desk {
            changed |= entry.expire_session(now);
            changed |= entry.forget_card_after(retention, now);
        }

        // A finished request is noise on a desk of requests waiting on us. It
        // leaves once the grace is up and its card is forgotten, so a request
        // with a longer retention keeps its card until that has run too.
        let mut kept = Vec::with_capacity(self.desk.len());
        for entry in std::mem::take(&mut self.desk) {
            let closed = match &entry.state {
                DeskState::Attested {
                    statement_id,
                    issued_at,
                    card,
                } if card.card.is_none() => Some((
                    *issued_at,
                    VettedOutcome::Signed {
                        statement_id: statement_id.clone(),
                    },
                )),
                DeskState::Declined { at, card, .. }
                    if card.as_ref().is_none_or(|c| c.card.is_none()) =>
                {
                    Some((*at, VettedOutcome::Declined))
                }
                _ => None,
            };
            match closed {
                Some((closed_at, outcome)) if now - closed_at >= CLOSED_GRACE => {
                    self.vetted.push(VettedRecord {
                        community: entry.community,
                        closed_at,
                        outcome,
                    });
                    changed = true;
                }
                _ => kept.push(entry),
            }
        }
        self.desk = kept;

        for application in &mut self.applications {
            for request in &mut application.requests {
                if let RequestState::Session {
                    request_id,
                    session,
                    ..
                } = &request.state
                    && session.expires_at <= now
                {
                    request.state = RequestState::Accepted {
                        request_id: request_id.clone(),
                        accepts_documentation: Vec::new(),
                        session_hint: None,
                    };
                    request.updated_at = now;
                    changed = true;
                }
            }
        }
        changed
    }
}

impl DeskState {
    /// Still needs the vetter.
    #[must_use]
    pub fn is_open(&self) -> bool {
        matches!(
            self,
            DeskState::Accepted | DeskState::Session { .. } | DeskState::CardReceived { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A finished join keeps its application while a rejoin could still use
    /// it, and lets it go once nothing in it could be presented again.
    #[test]
    fn a_joined_application_goes_once_nothing_in_it_could_be_presented() {
        use super::super::applicant::HeldStatement;
        use vta_sdk::protocols::vetting::{VettingMethod, VettingRelationship};
        let now = Utc::now();
        let statement = |valid_until| HeldStatement {
            id: "s1".into(),
            vetter: "did:key:zVetter".into(),
            method: VettingMethod::InPerson,
            declared_relationship: VettingRelationship::None,
            document_classes: vec![],
            claims_verified: vec!["name.legal".into()],
            identity_commitment: "c".into(),
            valid_from: now - Duration::days(1),
            valid_until,
            received_at: now - Duration::days(1),
            credential: serde_json::json!({}),
        };
        let mut book = VettingBook::default();
        let joined = PersonaId::new();
        let other = PersonaId::new();
        book.start_application("did:web:a", joined, "did:key:zA", now)
            .unwrap();
        book.start_application("did:web:b", joined, "did:key:zA", now)
            .unwrap()
            .statements
            .push(statement(now + Duration::days(30)));
        book.start_application("did:web:c", other, "did:key:zB", now)
            .unwrap();
        let member = |a: &Application| a.persona == joined;

        // `a`: joined, nothing to present — goes. `b`: joined but its
        // statement is still valid — a rejoin could use it, so it stays. `c`:
        // not joined — an application in progress, untouched.
        assert_eq!(book.retire_joined(member, now), 1);
        let left: Vec<&str> = book
            .applications
            .iter()
            .map(|a| a.community.as_str())
            .collect();
        assert_eq!(left, ["did:web:b", "did:web:c"]);

        // Once `b`'s statement has expired, it goes too.
        assert_eq!(book.retire_joined(member, now + Duration::days(31)), 1);
        assert_eq!(book.applications.len(), 1);
    }

    #[test]
    fn an_empty_book_is_not_written() {
        let book = VettingBook::default();
        assert!(book.is_empty());
        assert_eq!(serde_json::to_value(&book).unwrap(), serde_json::json!({}));
    }

    #[test]
    fn one_application_per_community_and_persona() {
        let mut book = VettingBook::default();
        let persona = PersonaId::new();
        let now = Utc::now();
        let first = book
            .start_application("did:web:vtc", persona, "did:key:zA", now)
            .unwrap()
            .id
            .clone();
        let again = book
            .start_application("did:web:vtc", persona, "did:key:zA", now)
            .unwrap()
            .id
            .clone();
        assert_eq!(first, again);
        book.start_application("did:web:other", persona, "did:key:zA", now)
            .unwrap();
        assert_eq!(book.applications.len(), 2);
    }

    /// The parallel half of the rule above: one application per *persona*,
    /// several per community. A community may be joined by more than one
    /// persona, and being vetted as one says nothing about another.
    #[test]
    fn a_second_persona_gets_its_own_application_to_the_same_community() {
        let mut book = VettingBook::default();
        let now = Utc::now();
        let alice = PersonaId::new();
        let bob = PersonaId::new();
        book.start_application("did:web:vtc", alice, "did:key:zA", now)
            .unwrap();
        book.start_application("did:web:vtc", bob, "did:key:zB", now)
            .unwrap();
        assert_eq!(book.applications.len(), 2);
    }

    /// Without this an application is permanent, and its persona is fixed for
    /// its whole life — so one started as the wrong persona would own that
    /// community's vetting route forever.
    #[test]
    fn an_application_can_be_abandoned() {
        let mut book = VettingBook::default();
        let now = Utc::now();
        let persona = PersonaId::new();
        let id = book
            .start_application("did:web:vtc", persona, "did:key:zA", now)
            .unwrap()
            .id
            .clone();

        let gone = book.abandon_application(&id).expect("it was there");
        assert_eq!(gone.id, id);
        assert!(book.applications.is_empty());

        // Abandoning it twice is not an error the caller has to guard against.
        assert!(book.abandon_application(&id).is_none());

        // And the same persona may apply again afterwards — abandoning is a
        // clearing, not a bar.
        book.start_application("did:web:vtc", persona, "did:key:zA", now)
            .unwrap();
        assert_eq!(book.applications.len(), 1);
    }

    /// A `requirementsDigest` the published criterion accepts: base58btc, and
    /// at least 16 characters. The old `"zDigest"` is refused on this line.
    const DIGEST: &str = "zQmbWqxBEKC3P8tqsKc98xmWNzrzDtRLMiMPL8wBuTGsMnR";

    fn manifest(
        branding: Option<manifest::v0_2::CommunityBranding>,
        vetting: bool,
    ) -> manifest::v0_2::Response {
        let requirements: VettingRequirements = serde_json::from_value(serde_json::json!({
            "version": "0.1",
            "statementType": vta_sdk::protocols::vetting::VETTED_PREDICATE,
            "minStatements": 1,
            "acceptedMethods": ["inPerson"],
            "requiredClaims": ["name.legal"],
            "eligibleVetters": { "role": "vetter" }
        }))
        .unwrap();
        let criterion = manifest::v0_2::Criterion::try_from(
            manifest::v0_2::Criterion::builder()
                .id("c1")
                .presentation_definition(serde_json::Map::new())
                .vetting(vetting.then_some(requirements))
                .requirements_digest(Some(
                    manifest::v0_2::DigestMultibase::try_from(DIGEST).unwrap(),
                )),
        )
        .unwrap();
        manifest::v0_2::Response::try_from(
            manifest::v0_2::Response::builder()
                .community_did("did:web:vtc")
                .criteria(vec![criterion])
                .branding(branding),
        )
        .unwrap()
    }

    #[test]
    fn a_manifest_says_whether_a_community_vets_and_how_it_looks() {
        let mut book = VettingBook::default();
        let now = Utc::now();
        assert!(matches!(book.knowledge("did:web:vtc"), Knowledge::Unknown));

        let branding = manifest::v0_2::CommunityBranding::try_from(
            manifest::v0_2::CommunityBranding::builder()
                .display_name(Some(
                    manifest::v0_2::CommunityBrandingDisplayName::try_from("Kernel").unwrap(),
                ))
                .accent_color(Some(
                    manifest::v0_2::CommunityBrandingAccentColor::try_from("#1a2B3c").unwrap(),
                )),
        )
        .unwrap();
        assert!(book.learn_manifest("did:web:vtc", &manifest(Some(branding.clone()), true), now));
        assert!(matches!(
            book.knowledge("did:web:vtc"),
            Knowledge::Vetting(_)
        ));
        let known = book.branding("did:web:vtc").unwrap();
        assert_eq!(known.display_name.as_deref(), Some("Kernel"));
        assert_eq!(known.accent_rgb(), Some((0x1a, 0x2b, 0x3c)));
        assert!(
            !book.learn_manifest("did:web:vtc", &manifest(Some(branding), true), now),
            "the same manifest again is not a change"
        );

        assert!(book.learn_manifest("did:web:open", &manifest(None, false), now));
        assert!(matches!(
            book.knowledge("did:web:open"),
            Knowledge::NoVetting
        ));
        assert!(book.branding("did:web:open").is_none());

        // An accent the published type refuses cannot be built at all now, so
        // what still reaches this client is branding the schema admits and
        // `check_shape` refuses by hand: a `logoUrl` that is not an absolute
        // https URI.
        assert!(manifest::v0_2::CommunityBrandingAccentColor::try_from("red").is_err());
        let broken: manifest::v0_2::CommunityBranding = serde_json::from_value(serde_json::json!({
            "displayName": "Elsewhere",
            "logoUrl": "http://vtc.example/logo.png"
        }))
        .expect("the schema admits it");
        book.learn_manifest("did:web:broken", &manifest(Some(broken), false), now);
        assert!(
            book.branding("did:web:broken").is_none(),
            "a bad branding is dropped whole"
        );
    }

    #[test]
    fn only_rrggbb_is_an_accent() {
        assert_eq!(parse_accent("#ff0080"), Some((255, 0, 128)));
        for bad in ["ff0080", "#ff008", "#ff00800", "#gg0080", "#ff0 80"] {
            assert_eq!(parse_accent(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_new_application_takes_the_requirements_already_known() {
        let mut book = VettingBook::default();
        let now = Utc::now();
        book.learn_manifest("did:web:vtc", &manifest(None, true), now);
        let id = book
            .start_application("did:web:vtc", PersonaId::new(), "did:key:zA", now)
            .unwrap()
            .id
            .clone();
        assert!(book.adopt_known_requirements(&id));
        let app = book.application_by_id_mut(&id).unwrap();
        assert_eq!(app.criterion_id.as_deref(), Some("c1"));
        assert_eq!(app.requirements_digest.as_deref(), Some(DIGEST));
        assert!(
            !book.adopt_known_requirements(&id),
            "nothing new the second time"
        );
    }

    #[test]
    fn a_member_without_a_live_grant_can_ask_for_it_again() {
        let now = Utc::now();
        let mut account = Account::default();
        let persona = PersonaId::new();
        for (vtc, active) in [
            ("did:web:a", true),
            ("did:web:b", true),
            ("did:web:c", false),
        ] {
            let mut record = CommunityRecord::new_pending(
                vtc.to_string(),
                None,
                "openvtc/test".to_string(),
                persona,
                uuid::Uuid::new_v4(),
                now,
            );
            if active {
                record.activate(now);
            }
            account.add_membership(record);
        }
        let mut book = VettingBook::default();
        book.keep_vetter_grant(VetterGrant {
            community: "did:web:a".into(),
            persona,
            credential_id: None,
            valid_until: Some(now + Duration::days(30)),
            received_at: now,
            credential: serde_json::json!({}),
        });
        let candidates: Vec<&str> = book
            .resend_candidates(&account, now)
            .into_iter()
            .map(|m| m.vtc_did.as_str())
            .collect();
        assert_eq!(candidates, vec!["did:web:b"]);
    }

    /// A grant is warned about once as it approaches, once more when it
    /// actually lapses, and never again — a warning the operator has read and
    /// dismissed must not come back every hour for something only the community
    /// can fix.
    #[test]
    fn a_lapsing_grant_is_warned_about_once_per_state() {
        let now = Utc::now();
        let persona = PersonaId::new();
        let mut book = VettingBook::default();
        book.keep_vetter_grant(VetterGrant {
            community: "did:web:a".into(),
            persona,
            credential_id: None,
            valid_until: Some(now + Duration::days(3)),
            received_at: now,
            credential: serde_json::json!({}),
        });

        let first = book.take_grant_warnings(now);
        assert_eq!(first.len(), 1, "about to lapse");
        assert!(!first[0].expired);
        assert!(
            book.take_grant_warnings(now).is_empty(),
            "said once, not every sweep"
        );

        // It lapses. That is a second warning, and a different sentence: the
        // desk has stopped working rather than being about to.
        let later = now + Duration::days(4);
        let second = book.take_grant_warnings(later);
        assert_eq!(second.len(), 1);
        assert!(second[0].expired);
        assert!(book.take_grant_warnings(later).is_empty());
        assert_eq!(
            book.grant_warnings.len(),
            1,
            "the superseded 'expiring' warning is forgotten, not accumulated"
        );
    }

    /// A healthy grant says nothing, and a reissued one is warned about again
    /// when its own expiry comes round — the identity carries the expiry, so a
    /// renewal is not mistaken for something already said.
    #[test]
    fn a_renewed_grant_can_be_warned_about_again() {
        let now = Utc::now();
        let persona = PersonaId::new();
        let mut book = VettingBook::default();
        // A reissue is a different credential, not the same one with a new
        // date — `keep_vetter_grant` ignores a re-delivery of the identical
        // body, so the `validUntil` has to travel in the credential too.
        let grant = |until: DateTime<Utc>| VetterGrant {
            community: "did:web:a".into(),
            persona,
            credential_id: None,
            valid_until: Some(until),
            received_at: now,
            credential: serde_json::json!({ "validUntil": until.to_rfc3339() }),
        };

        book.keep_vetter_grant(grant(now + Duration::days(90)));
        assert!(
            book.take_grant_warnings(now).is_empty(),
            "a grant with months to run is not news"
        );

        book.keep_vetter_grant(grant(now + Duration::days(2)));
        assert_eq!(book.take_grant_warnings(now).len(), 1);

        // Reissued, then allowed to lapse again.
        book.keep_vetter_grant(grant(now + Duration::days(400)));
        assert!(book.take_grant_warnings(now).is_empty());
        assert!(
            book.grant_warnings.is_empty(),
            "the old warning is forgotten once the grant no longer needs it"
        );
        let much_later = now + Duration::days(395);
        assert_eq!(book.take_grant_warnings(much_later).len(), 1);
    }

    /// The desk header keeps a lapsed grant, alone among the vetter-side reads.
    /// Everything else filters to a live one, which is right and which is
    /// exactly why a lapse would otherwise be invisible: the communities simply
    /// stop being listed.
    #[test]
    fn the_standing_keeps_a_lapsed_grant_that_every_other_read_drops() {
        let now = Utc::now();
        let persona = PersonaId::new();
        let mut book = VettingBook::default();
        book.keep_vetter_grant(VetterGrant {
            community: "did:web:gone".into(),
            persona,
            credential_id: None,
            valid_until: Some(now - Duration::days(1)),
            received_at: now - Duration::days(400),
            credential: serde_json::json!({}),
        });

        assert!(
            book.vetter_grant("did:web:gone", persona, now).is_none(),
            "a lapsed grant is not a live one"
        );
        let standing = book.vetter_standing(now);
        assert_eq!(standing.len(), 1, "but the desk still shows it");
        assert!(!standing[0].live);
        assert!(
            !standing[0].expiring,
            "already gone is not 'about to go' — they are different sentences"
        );
        assert!(standing[0].profile.is_none(), "no profile was ever sent");
    }

    #[test]
    fn unknown_members_survive_a_round_trip() {
        let mut v = serde_json::to_value(VettingBook::default()).unwrap();
        v["vetterDirectory"] = serde_json::json!({ "listed": true });
        let book: VettingBook = serde_json::from_value(v).unwrap();
        assert!(!book.is_empty());
        assert_eq!(
            serde_json::to_value(&book).unwrap()["vetterDirectory"]["listed"],
            true
        );
    }

    /// A pre-v1 vetter grant is set aside on load with a notice, a conformant
    /// one stays, and a conformant replacement clears the notice.
    #[test]
    fn a_pre_v1_vetter_grant_is_set_aside_with_a_notice() {
        let community = "did:example:kernel";
        let grant = |credential: serde_json::Value| VetterGrant {
            community: community.to_string(),
            persona: PersonaId::new(),
            credential_id: None,
            valid_until: None,
            received_at: Utc::now(),
            credential,
        };
        let mut book = VettingBook::default();
        book.vetter_grants
            .push(grant(crate::dtg::fixtures::retired_role_endorsement(
                community,
                "did:example:m",
            )));
        book.vetter_grants
            .push(grant(crate::dtg::fixtures::role_vac(
                "did:example:other",
                "did:example:m",
                "vetter",
            )));
        assert_eq!(book.retire_nonconformant(), 1);
        assert_eq!(book.vetter_grants.len(), 1);
        assert_eq!(book.retired.len(), 1);
        assert!(book.retired[0].contains(community));
        assert!(!book.is_empty());

        book.keep_vetter_grant(grant(crate::dtg::fixtures::role_vac(
            community,
            "did:example:m",
            "vetter",
        )));
        assert!(
            book.retired.is_empty(),
            "the replacement answers the notice"
        );
    }
}
