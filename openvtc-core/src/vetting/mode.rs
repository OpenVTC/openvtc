//! How a community's vetters vet **now** — named statements, or a PCS zero-knowledge proof —
//! and how old that knowledge is.
//!
//! A community turns PCS ZKP vetting on by publishing hidden-vetting parameters on a criterion of
//! its join manifest (`vetting.ext`, the [`super::hidden::HIDDEN_VETTING_NS`] namespace), and off
//! by withdrawing them. The manifest is served live from the community's stored criteria, so it
//! is the one authoritative source, and it changes under us: a client that learned the mode once
//! and kept believing it would hand out tickets for a mode the community no longer runs, or gate
//! them on an enrolment the community no longer asks for.
//!
//! So the mode here is a **reading**, not a fact: what the last manifest said
//! ([`KnownCommunity::vetter_mode`](super::book::KnownCommunity::vetter_mode), persisted with
//! when it was read), plus whether the last attempt to read it failed and how ([`ModeFailure`],
//! memory only). Anything that *decides* on the mode — issuing a ticket — reads the manifest
//! afresh first and decides only on an answer that arrived after it asked. Anything that only
//! *shows* it — a badge — uses the last reading and says how old it is once that is older than
//! [`MODE_TTL`].

use std::collections::BTreeMap;

use chrono::{DateTime, Datelike, Duration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::book::VettingBook;
use super::hidden::{HiddenParams, Mode};
use super::queries::QueryKind;

/// How long a reading of a community's mode is taken as current. Past this the desk says how
/// old it is, and opening the desk or waiting on it reads it again.
pub const MODE_TTL: Duration = Duration::minutes(10);

/// The soonest a mode the client is only *showing* is asked for again after the last ask,
/// answered or not — so a community that does not answer is not asked every few seconds while
/// the desk is open (R1.4). A ticket always asks; it does not wait on this.
pub const MODE_REASK_AFTER: Duration = Duration::minutes(2);

/// The least time between two re-reads of one community's manifest that are not a ticket's own
/// ([`VettingBook::manifest_recently_asked`]).
pub const MANIFEST_MIN_GAP: Duration = Duration::seconds(30);

/// How a community's vetters vet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum VetterMode {
    /// Vetters sign statements that name them.
    Named,
    /// Vetting is counted from a PCS zero-knowledge proof; vetters enrol and spend tokens.
    PcsZkp,
}

impl VetterMode {
    /// The mode in a few words, as the page says it.
    #[must_use]
    pub fn words(self) -> &'static str {
        match self {
            VetterMode::Named => "named vetting",
            VetterMode::PcsZkp => "PCS ZKP",
        }
    }
}

/// The mode a manifest said, and when it was read. Persisted, as the last-known value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModeRead {
    /// What it said.
    pub mode: VetterMode,
    /// When its manifest was read.
    pub read_at: DateTime<Utc>,
}

/// Why the last attempt to read a community's mode failed. Each is a different next step
/// (R6.4): our side could not send, the community did not answer, it refused, or it answered in
/// a shape this client cannot read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModeFailure {
    /// The question never left: the mediator or this client's messaging could not send it.
    Unsent(String),
    /// Sent, and nothing came back within the reply window.
    Unanswered,
    /// The community refused the question, with this code.
    Refused(String),
    /// It answered, but not in a form this client can read — the two disagree about the task.
    Unreadable(String),
}

impl ModeFailure {
    /// The failure as the end of "could not read how … vets now: …".
    #[must_use]
    pub fn words(&self) -> String {
        match self {
            ModeFailure::Unsent(e) => format!(
                "the question could not be sent ({e}) — your mediator or connection may be down"
            ),
            ModeFailure::Unanswered => format!(
                "no answer within {} seconds — its service may be offline or slow",
                super::queries::QUERY_TIMEOUT.num_seconds()
            ),
            ModeFailure::Refused(code) => format!("it refused to say ({code})"),
            ModeFailure::Unreadable(detail) => format!(
                "it answered in a form this client cannot read — the two disagree about the \
                 manifest; it is not a refusal ({detail})"
            ),
        }
    }
}

/// The asking side of a community's mode: memory only, like the questions themselves.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ModeCheck {
    /// When we last asked.
    pub asked_at: Option<DateTime<Utc>>,
    /// The last failure, and when, until an answer arrives.
    pub failed: Option<(ModeFailure, DateTime<Utc>)>,
}

/// What this client knows of a community's mode: the last reading, and the last failure.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ModeReading {
    /// The last mode read, and when. `None` when it has never been read.
    pub read: Option<ModeRead>,
    /// The last attempt to read it failed, and when — kept only until an answer arrives.
    pub failed: Option<(ModeFailure, DateTime<Utc>)>,
    /// [`Self::read`] is inferred from what an older manifest left behind rather than recorded
    /// as a reading. Good enough to show; never enough to decide on ([`Self::read_since`]).
    pub inferred: bool,
}

impl ModeReading {
    /// The last mode read, however old.
    #[must_use]
    pub fn mode(&self) -> Option<VetterMode> {
        self.read.map(|r| r.mode)
    }

    /// Whether the reading is older than [`MODE_TTL`], or there is none.
    #[must_use]
    pub fn is_stale(&self, now: DateTime<Utc>) -> bool {
        self.read.is_none_or(|r| now - r.read_at > MODE_TTL)
    }

    /// The mode, if it was read at or after `since` — the only answer a decision may use.
    #[must_use]
    pub fn read_since(&self, since: DateTime<Utc>) -> Option<VetterMode> {
        self.read
            .filter(|r| !self.inferred && r.read_at >= since)
            .map(|r| r.mode)
    }

    /// The failure, if one happened at or after `since`.
    #[must_use]
    pub fn failed_since(&self, since: DateTime<Utc>) -> Option<&ModeFailure> {
        self.failed
            .as_ref()
            .filter(|(_, at)| *at >= since)
            .map(|(f, _)| f)
    }

    /// The last reading in words, with its age: "PCS ZKP, read 3 min ago", or "never read".
    #[must_use]
    pub fn last_known_words(&self, now: DateTime<Utc>) -> String {
        match self.read {
            Some(r) => format!("{}, read {}", r.mode.words(), age_words(now - r.read_at)),
            None => "never read".to_string(),
        }
    }
}

/// An age in words: "just now", "4 min ago", "3 h ago", "2 days ago".
#[must_use]
pub fn age_words(age: Duration) -> String {
    if age < Duration::minutes(1) {
        "just now".to_string()
    } else if age < Duration::hours(1) {
        format!("{} min ago", age.num_minutes())
    } else if age < Duration::days(2) {
        format!("{} h ago", age.num_hours())
    } else {
        format!("{} days ago", age.num_days())
    }
}

/// A community changed its mode between two readings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModeSwitch {
    /// The community.
    pub community: String,
    /// What the reading before said.
    pub from: VetterMode,
    /// What it says now.
    pub to: VetterMode,
    /// When the new reading arrived.
    pub at: DateTime<Utc>,
}

impl ModeSwitch {
    /// The switch in a sentence, naming the community as `name`.
    #[must_use]
    pub fn words(&self, name: &str) -> String {
        format!(
            "{name} switched from {} to {}.",
            self.from.words(),
            self.to.words()
        )
    }
}

/// Switches kept for the page to say before the oldest is dropped. Memory only.
const MAX_MODE_SWITCHES: usize = 16;

/// The first day of the period after `period` (`2026-10` → 1 Nov 2026), and that period's name.
///
/// Labels are the community's to publish and it does not roll them over by itself, so this is
/// the soonest the next *monthly* label can start, not a promise that it will. `None` for a
/// period that is not `YYYY-MM`.
#[must_use]
pub fn next_monthly_label(period: &str) -> Option<(String, NaiveDate)> {
    let (y, m) = period.split_once('-')?;
    let (y, m): (i32, u32) = (y.parse().ok()?, m.parse().ok()?);
    let first = NaiveDate::from_ymd_opt(y, m, 1)?;
    let next = first.checked_add_months(chrono::Months::new(1))?;
    Some((format!("{:04}-{:02}", next.year(), next.month()), next))
}

/// What a manifest payload says about the mode, read from its criteria **as received**
/// (`vetting.ext` does not survive a typed parse).
///
/// The first criterion that publishes hidden-vetting parameters wins, as the community's own
/// service serves one. None doing so is named vetting — unless a criterion could not be read at
/// all, in which case this client cannot tell, and says so rather than guessing.
pub(crate) fn read_payload(raw: &Value) -> Result<(VetterMode, Option<HiddenParams>), String> {
    let mut unreadable = None;
    for criterion in raw
        .get("criteria")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        match super::hidden::read_mode(criterion) {
            Ok(Mode::Hidden(p)) => return Ok((VetterMode::PcsZkp, Some(*p))),
            Ok(Mode::Named) => {}
            Err(e) => unreadable = unreadable.or(Some(e.to_string())),
        }
    }
    match unreadable {
        Some(e) => Err(e),
        None => Ok((VetterMode::Named, None)),
    }
}

impl VettingBook {
    /// What this client knows of `community`'s mode.
    ///
    /// A record written before readings were kept carries no [`ModeRead`]; it falls back to what
    /// the last manifest left behind — published parameters, or a criterion that hides its
    /// vetters — dated by when that manifest was read. Holding an engine for the community is
    /// deliberately **not** evidence: it says we enrolled once, not that the community still
    /// counts proofs.
    #[must_use]
    pub fn vetter_mode(&self, community: &str) -> ModeReading {
        let known = self.communities.iter().find(|c| c.community == community);
        let recorded = known.and_then(|c| c.vetter_mode);
        let read = recorded.or_else(|| {
            let pcs = self.hidden_published.contains_key(community)
                || self
                    .criteria
                    .iter()
                    .any(|k| k.community == community && k.hidden_vetting());
            known.map(|c| ModeRead {
                mode: if pcs {
                    VetterMode::PcsZkp
                } else {
                    VetterMode::Named
                },
                read_at: c.fetched_at,
            })
        });
        ModeReading {
            read,
            failed: self
                .mode_checks
                .get(community)
                .and_then(|c| c.failed.clone()),
            inferred: recorded.is_none() && read.is_some(),
        }
    }

    /// Whether `community` vets by PCS ZKP, as far as the last reading says.
    #[must_use]
    pub fn pcs_zkp(&self, community: &str) -> bool {
        self.vetter_mode(community).mode() == Some(VetterMode::PcsZkp)
    }

    /// Learn `community`'s mode from a manifest payload as received. `before` is the mode as
    /// known before this manifest was taken in (read it before [`Self::learn_manifest_in`],
    /// which moves the fallback). Returns whether the book changed.
    ///
    /// Also keeps [`Self::hidden_published`] — what the community publishes about hidden
    /// vetting — in step: set while it publishes parameters, dropped when it stops. An engine we
    /// already hold is kept — a credential does not become worthless because the advertisement
    /// moved — and takes the parameters read, under its own keys
    /// ([`HiddenVetterState::take_reading`](super::book::HiddenVetterState::take_reading)), so
    /// no draw is planned on a rate the community has moved off.
    pub fn learn_mode(
        &mut self,
        community: &str,
        raw: &Value,
        before: Option<VetterMode>,
        now: DateTime<Utc>,
    ) -> bool {
        let (mode, params) = match read_payload(raw) {
            Ok(read) => read,
            Err(detail) => {
                self.mode_failed(community, ModeFailure::Unreadable(detail), now);
                return false;
            }
        };
        let mut changed = false;
        match &params {
            Some(params) => {
                if self.hidden_published.get(community) != Some(params) {
                    self.hidden_published
                        .insert(community.to_string(), params.clone());
                    changed = true;
                    // Enrol now rather than at the next sweep: until enrolled, a vetter for
                    // this community can only refuse to attest.
                    self.vetter_refresh_due = true;
                }
            }
            None => changed |= self.hidden_published.remove(community).is_some(),
        }
        // Every engine held for this community takes the read now — rate, tick length, labels,
        // events — not at its next pass, so the desk shows what the community says and no
        // draw is planned on what it used to say. A pass that held its draws for this read runs
        // again on it.
        if let Some(live) = params.as_ref() {
            let mut resume = false;
            for held in self
                .hidden_vetter
                .iter_mut()
                .filter(|h| h.community == community)
            {
                held.take_reading(live, now);
                // Changed or not, the time read is worth a save: the desk shows it.
                changed = true;
                resume |= std::mem::take(&mut held.awaiting_read);
            }
            if resume {
                self.vetter_refresh_due = true;
            }
        }
        if let Some(known) = self
            .communities
            .iter_mut()
            .find(|c| c.community == community)
        {
            changed |= known.vetter_mode.is_none_or(|r| r.mode != mode);
            known.vetter_mode = Some(ModeRead { mode, read_at: now });
        }
        self.mode_checks
            .entry(community.to_string())
            .or_default()
            .failed = None;
        if let Some(from) = before.filter(|from| *from != mode) {
            self.mode_switches.push(ModeSwitch {
                community: community.to_string(),
                from,
                to: mode,
                at: now,
            });
            let excess = self.mode_switches.len().saturating_sub(MAX_MODE_SWITCHES);
            self.mode_switches.drain(..excess);
        }
        changed
    }

    /// We asked `community` for its manifest at `now`.
    pub fn mode_asked(&mut self, community: &str, now: DateTime<Utc>) {
        self.mode_checks
            .entry(community.to_string())
            .or_default()
            .asked_at = Some(now);
    }

    /// Reading `community`'s mode failed. A failure never replaces the reading itself: the
    /// last-known mode stays, shown with its age, and nothing decides on it.
    ///
    /// A question that was never sent ([`ModeFailure::Unsent`]) is not an ask: it does not hold
    /// the next one back. At start-up the persona's listener comes up a second or two after the
    /// first question is tried, and counting that attempt as asked kept the desk on "could not
    /// read how it vets now" for minutes after the connection was fine.
    pub fn mode_failed(&mut self, community: &str, failure: ModeFailure, now: DateTime<Utc>) {
        let check = self.mode_checks.entry(community.to_string()).or_default();
        if matches!(failure, ModeFailure::Unsent(_)) {
            check.asked_at = None;
        }
        check.failed = Some((failure, now));
    }

    /// A persona's listener has connected: whatever could not be sent before can be now. Forget
    /// the "could not be sent" failures — they described a connection that is back — and ask
    /// again on the next sweep rather than waiting out the retry budget.
    pub fn listener_connected(&mut self) {
        let mut any = false;
        for check in self.mode_checks.values_mut() {
            if matches!(check.failed, Some((ModeFailure::Unsent(_), _))) {
                check.failed = None;
                check.asked_at = None;
                any = true;
            }
        }
        if any || !self.hidden_vetter.is_empty() {
            self.vetter_refresh_failures = 0;
            self.vetter_refresh_due = true;
        }
    }

    /// Whether `community`'s mode is worth reading again for display: the reading is older than
    /// [`MODE_TTL`], nothing is asking already, and the last ask is at least
    /// [`MODE_REASK_AFTER`] old.
    #[must_use]
    pub fn mode_refresh_due(&self, community: &str, now: DateTime<Utc>) -> bool {
        self.vetter_mode(community).is_stale(now)
            && self.waiting_on(community, QueryKind::Manifest).is_none()
            && self
                .mode_checks
                .get(community)
                .and_then(|c| c.asked_at)
                .is_none_or(|at| now - at >= MODE_REASK_AFTER)
    }

    /// Whether `community`'s manifest was asked for, or arrived, within [`MANIFEST_MIN_GAP`],
    /// or a question for it is still open — so asking again now would only fetch the same
    /// answer. Every background or by-hand re-read checks this (R1.4): a key held down, or a
    /// chain of passes each due another, otherwise asked several times in seconds. A ticket's
    /// own read does not — it must be answered after it was asked.
    #[must_use]
    pub fn manifest_recently_asked(&self, community: &str, now: DateTime<Utc>) -> bool {
        let recent = |at: DateTime<Utc>| now - at < MANIFEST_MIN_GAP;
        self.waiting_on(community, QueryKind::Manifest).is_some()
            || self
                .mode_checks
                .get(community)
                .and_then(|c| c.asked_at)
                .is_some_and(recent)
            || self
                .communities
                .iter()
                .find(|c| c.community == community)
                .and_then(|c| c.vetter_mode)
                .is_some_and(|r| recent(r.read_at))
    }

    /// Whether `community`'s manifest is owed a read now whatever [`MANIFEST_MIN_GAP`] says: a
    /// draw was refused as over its rate (`overQuota`) after the last read and after the last
    /// ask, and no question is open. Once per refusal — the ask it causes is after it — so it
    /// never asks in a loop (R1.4).
    #[must_use]
    pub fn params_reread_owed(&self, community: &str) -> bool {
        let asked_at = self.mode_checks.get(community).and_then(|c| c.asked_at);
        self.waiting_on(community, QueryKind::Manifest).is_none()
            && self.hidden_vetter.iter().any(|h| {
                h.community == community
                    && h.reread_owed()
                    && h.over_quota
                        .as_ref()
                        .is_some_and(|q| asked_at.is_none_or(|a| a <= q.at))
            })
    }

    /// The switches seen since this was last called, oldest first.
    pub fn take_mode_switches(&mut self) -> Vec<ModeSwitch> {
        std::mem::take(&mut self.mode_switches)
    }
}

/// Mode checks by community, as the book holds them.
pub type ModeChecks = BTreeMap<String, ModeCheck>;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn manifest(pcs: bool) -> Value {
        let mut vetting = json!({ "minStatements": 1 });
        if pcs {
            vetting["ext"] = json!({
                super::super::hidden::HIDDEN_VETTING_NS: {
                    "suite": super::super::hidden::SUITE,
                    "helperKey": "zHelper",
                    "tokenKey": "zToken",
                    "vetterLabels": ["vetter/2026-10"],
                    "tokenLabels": ["token/2026-10"],
                }
            });
        }
        json!({ "criteria": [ { "id": "c1", "vetting": vetting } ] })
    }

    fn book_knowing(community: &str, now: DateTime<Utc>) -> VettingBook {
        let mut book = VettingBook::default();
        book.communities.push(super::super::book::KnownCommunity {
            community: community.into(),
            branding: Default::default(),
            requested: Vec::new(),
            fetched_at: now,
            protocol: None,
            routes: Vec::new(),
            post_quantum_key: None,
            vetter_mode: None,
        });
        book
    }

    const VTC: &str = "did:web:vtc.example";

    #[test]
    fn a_fresh_reading_replaces_a_stale_one() {
        let then = Utc::now() - Duration::hours(5);
        let now = Utc::now();
        let mut book = book_knowing(VTC, then);
        book.learn_mode(VTC, &manifest(true), None, then);
        assert_eq!(book.vetter_mode(VTC).mode(), Some(VetterMode::PcsZkp));
        assert!(book.vetter_mode(VTC).is_stale(now), "five hours old");
        assert!(book.mode_refresh_due(VTC, now));

        let before = book.vetter_mode(VTC).mode();
        book.learn_mode(VTC, &manifest(false), before, now);
        let reading = book.vetter_mode(VTC);
        assert_eq!(reading.mode(), Some(VetterMode::Named));
        assert!(!reading.is_stale(now));
        assert_eq!(reading.read_since(now), Some(VetterMode::Named));
        assert!(
            !book.hidden_published.contains_key(VTC),
            "a community that stopped publishing parameters is not believed to run PCS ZKP"
        );
        let switches = book.take_mode_switches();
        assert_eq!(switches.len(), 1);
        assert_eq!(
            switches[0].words("first-vtc"),
            "first-vtc switched from PCS ZKP to named vetting."
        );
        assert!(book.take_mode_switches().is_empty(), "said once");
    }

    #[test]
    fn an_engine_alone_is_not_pcs_mode() {
        let now = Utc::now();
        let mut book = book_knowing(VTC, now);
        book.learn_mode(VTC, &manifest(false), None, now);
        // Nothing about engines enters the reading: it is what the community publishes now.
        assert!(!book.pcs_zkp(VTC));
    }

    #[test]
    fn a_failure_is_kept_beside_the_last_reading_not_instead_of_it() {
        let then = Utc::now() - Duration::hours(1);
        let now = Utc::now();
        let mut book = book_knowing(VTC, then);
        book.learn_mode(VTC, &manifest(true), None, then);
        book.mode_failed(VTC, ModeFailure::Unanswered, now);
        let reading = book.vetter_mode(VTC);
        assert_eq!(reading.mode(), Some(VetterMode::PcsZkp), "last known stays");
        assert_eq!(
            reading.read_since(now),
            None,
            "but nothing may decide on it"
        );
        assert_eq!(reading.failed_since(now), Some(&ModeFailure::Unanswered));
        assert!(
            reading
                .last_known_words(now)
                .contains("PCS ZKP, read 1 h ago")
        );
        // An answer clears it.
        book.learn_mode(VTC, &manifest(true), Some(VetterMode::PcsZkp), now);
        assert!(book.vetter_mode(VTC).failed.is_none());
    }

    /// A question that never left (the listener was not up yet) does not hold the next ask
    /// back, and the listener connecting clears it and asks again at once.
    #[test]
    fn an_unsent_question_is_not_an_ask_and_a_connect_asks_again() {
        let now = Utc::now();
        let mut book = book_knowing(VTC, now - chrono::Duration::hours(1));
        book.mode_asked(VTC, now);
        book.mode_failed(
            VTC,
            ModeFailure::Unsent("no listener installed".into()),
            now,
        );
        assert!(
            book.mode_checks.get(VTC).and_then(|c| c.asked_at).is_none(),
            "an unsent question is not an ask"
        );
        assert!(
            book.mode_refresh_due(VTC, now),
            "so the next one is not held back"
        );

        book.vetter_refresh_due = false;
        book.listener_connected();
        assert!(
            book.vetter_mode(VTC).failed.is_none(),
            "the failure described a connection that is back"
        );
        assert!(
            book.vetter_refresh_due,
            "and the mode is asked for again now"
        );
    }

    #[test]
    fn an_unreadable_manifest_is_a_failure_not_a_mode() {
        let now = Utc::now();
        let mut book = book_knowing(VTC, now);
        let raw = json!({ "criteria": [ { "id": "c1", "vetting": {
            "extCritical": ["https://example.org/unknown"], "ext": {}
        } } ] });
        assert!(!book.learn_mode(VTC, &raw, None, now));
        let reading = book.vetter_mode(VTC);
        assert!(matches!(
            reading.failed_since(now),
            Some(ModeFailure::Unreadable(_))
        ));
        assert!(reading.read_since(now).is_none());
    }

    #[test]
    fn failures_say_which_kind_they_are() {
        let words: Vec<String> = [
            ModeFailure::Unsent("no mediator".into()),
            ModeFailure::Unanswered,
            ModeFailure::Refused("permissionDenied".into()),
            ModeFailure::Unreadable("missing field".into()),
        ]
        .iter()
        .map(ModeFailure::words)
        .collect();
        assert!(words[0].contains("could not be sent"));
        assert!(words[1].contains("no answer"));
        assert!(words[2].contains("refused"));
        assert!(words[3].contains("not a refusal"));
    }

    #[test]
    fn the_next_monthly_label_rolls_over_the_year() {
        assert_eq!(
            next_monthly_label("2026-10"),
            Some((
                "2026-11".into(),
                NaiveDate::from_ymd_opt(2026, 11, 1).unwrap()
            ))
        );
        assert_eq!(
            next_monthly_label("2026-12").map(|(l, _)| l),
            Some("2027-01".into())
        );
        assert_eq!(next_monthly_label("spring"), None);
    }

    #[test]
    fn a_shown_mode_is_not_asked_for_again_too_soon() {
        let now = Utc::now();
        let mut book = book_knowing(VTC, now - Duration::hours(2));
        assert!(book.mode_refresh_due(VTC, now));
        book.mode_asked(VTC, now);
        assert!(!book.mode_refresh_due(VTC, now + Duration::seconds(30)));
        assert!(book.mode_refresh_due(VTC, now + MODE_REASK_AFTER));
    }
}
