//! When to run the vetter side of hidden vetting: re-read each community's
//! manifest, enrol, and draw the token drip
//! (`docs/design/vetting-hidden-vetters-pcs.md` §5.1).
//!
//! ## On the schedule, never on demand
//!
//! A drip tick is a window of time a community publishes (`tickLength`, three
//! days by default). The fetch is **scheduled and unconditional**: it runs
//! whether or not this vetter attested to anyone, because a fetch that followed
//! activity would report it. So the pacer is driven by the communities' windows
//! alone — it is never told the wallet's balance, and nothing a vetter does at
//! the desk moves it.
//!
//! A pass runs shortly after each window opens, at a random moment in its first
//! stretch ([`jitter_cap`]), so a community's vetters do not all ask in the same
//! second and the moment of a fetch carries nothing. It also runs at least once
//! every [`MAX_GAP`]: the manifest is where a community announces a new month's
//! labels, a change of keys, or that it hides its vetters at all, and a vetter
//! that never re-read it never moved past the month it enrolled in. A pass that
//! was answered `tickNotYet` is brought forward to its retry time.
//!
//! In memory, never persisted: the first pass of a launch runs at once, which is
//! what a client that was off owes — the ticks it missed are caught up then.

use chrono::{DateTime, Duration, Utc};
use openvtc_core::vetting::VettingBook;
use openvtc_core::vetting::hidden;
use rand::Rng;

/// The longest the vetter side goes without a pass, whatever the windows say.
pub(crate) const MAX_GAP: Duration = Duration::hours(1);

/// The soonest a pass follows another. Keeps a window that opened a moment ago
/// from being raced, and a schedule that somehow never settles from spinning.
pub(crate) const MIN_GAP: Duration = Duration::seconds(30);

/// How far into a window of `length` the first pass may fall: an eighth of the
/// window, at most twenty minutes. Short enough that a new tick's tokens arrive
/// soon after it opens; long enough that the moment says nothing.
pub(crate) fn jitter_cap(length: Duration) -> Duration {
    (length / 8).min(Duration::minutes(20)).max(MIN_GAP)
}

/// When the vetter side next runs.
#[derive(Default)]
pub(crate) struct HiddenVettingPacer {
    next: Option<DateTime<Utc>>,
}

impl HiddenVettingPacer {
    /// Whether a pass is due. The first is due at once.
    pub(crate) fn due(&self, now: DateTime<Utc>) -> bool {
        self.next.is_none_or(|next| now >= next)
    }

    /// Bring the next pass forward to a retry set since it was scheduled.
    ///
    /// A question the community left unanswered sets [`HiddenVetterState::retry_at`] between
    /// passes, when the scheduled pass may be an hour away; without this the backoff would be
    /// the hour, whatever it said. Only a retry still to come counts, so a retry that has
    /// passed — and was acted on — never makes every check due again.
    ///
    /// [`HiddenVetterState::retry_at`]: openvtc_core::vetting::book::HiddenVetterState::retry_at
    pub(crate) fn pull_forward(&mut self, book: &VettingBook, now: DateTime<Utc>) {
        let Some(next) = self.next else {
            return;
        };
        if let Some(retry) = book
            .hidden_vetter
            .iter()
            .filter_map(|h| h.retry_at)
            .filter(|t| *t > now && *t < next)
            .min()
        {
            self.next = Some(retry);
        }
    }

    /// Set the next pass from what `book` holds now. Returns it.
    pub(crate) fn schedule<R: Rng>(
        &mut self,
        book: &VettingBook,
        now: DateTime<Utc>,
        rng: &mut R,
    ) -> DateTime<Utc> {
        let next = next_pass(book, now, |cap| {
            let secs = cap.num_seconds().max(1);
            Duration::seconds(rng.gen_range(0..=secs))
        });
        self.next = Some(next);
        next
    }
}

/// The next pass: the earliest window opening (plus `jitter` of up to its
/// [`jitter_cap`]) or `tickNotYet` retry over every community we hold an engine
/// for, but no later than [`MAX_GAP`] and no sooner than [`MIN_GAP`].
///
/// Read against what each community publishes now when we have it, because that
/// is what the pass will run on — a new month's labels open their first window
/// at midnight on the 1st.
pub(crate) fn next_pass(
    book: &VettingBook,
    now: DateTime<Utc>,
    mut jitter: impl FnMut(Duration) -> Duration,
) -> DateTime<Utc> {
    let mut next = now + MAX_GAP;
    for held in book.hidden_vetter.iter().filter(|h| h.rekeyed_at.is_none()) {
        let params = book
            .hidden_published
            .get(&held.community)
            .filter(|live| live.same_keys(&held.params))
            .unwrap_or(&held.params);
        let events = held.event_draws(now.date_naive());
        if let Some(opens) = hidden::next_window(params, &events, now) {
            next = next.min(opens + jitter(jitter_cap(params.tick_length())));
        }
        if let Some(retry) = held.retry_at.filter(|t| *t > now) {
            next = next.min(retry + jitter(MIN_GAP));
        }
    }
    next.max(now + MIN_GAP)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use openvtc_core::config::account::PersonaId;
    use openvtc_core::vetting::book::HiddenVetterState;
    use openvtc_core::vetting::hidden::HiddenParams;

    fn at(d: u32, h: u32, m: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, d, h, m, 0).unwrap()
    }

    fn params(tick_length: Option<&str>) -> HiddenParams {
        HiddenParams {
            suite: hidden::SUITE.into(),
            helper_key: "zHelper".into(),
            token_key: "zToken".into(),
            vetter_labels: vec!["vetter/2026-09".into()],
            token_labels: vec!["token/2026-09".into()],
            drip_per_tick: 3,
            events: Vec::new(),
            tick_length: tick_length.map(str::to_string),
        }
    }

    fn book(tick_length: Option<&str>) -> VettingBook {
        let mut book = VettingBook::default();
        book.hidden_vetter.push(HiddenVetterState::new(
            "did:example:vtc",
            PersonaId::new(),
            params(tick_length),
            // A snapshot with no key material: the pacer reads labels and times only.
            serde_json::from_value(serde_json::json!({ "member": "member", "usk": "", "id": "" }))
                .unwrap(),
        ));
        book
    }

    /// No engine yet: the manifest is still re-read hourly, which is how a vetter
    /// learns a community has started hiding its vetters at all.
    #[test]
    fn with_nothing_to_draw_the_vetter_side_still_runs_hourly() {
        let now = at(20, 9, 0);
        assert_eq!(
            next_pass(&VettingBook::default(), now, |_| Duration::zero()),
            now + MAX_GAP
        );
    }

    /// The next pass follows the next window's opening by a bounded random
    /// amount — and a window days away still leaves the hourly pass in place.
    #[test]
    fn a_pass_follows_each_window_opening_by_a_bounded_jitter() {
        // PT12H: September's tick 39 opens at 2026-09-20 12:00.
        let book = book(Some("PT12H"));
        let now = at(20, 11, 30);
        let mut asked = None;
        let next = next_pass(&book, now, |cap| {
            asked = Some(cap);
            cap
        });
        assert_eq!(
            asked,
            Some(Duration::minutes(20)),
            "an eighth of 12h, capped at 20 min"
        );
        assert_eq!(next, at(20, 12, 20));
        assert_eq!(next_pass(&book, now, |_| Duration::zero()), at(20, 12, 0));

        // P3D: the next window is the 22nd, so the hour wins.
        assert_eq!(
            next_pass(&super::tests::book(None), at(20, 9, 0), |_| Duration::zero(
            )),
            at(20, 10, 0)
        );
    }

    /// A `tickNotYet` brings the next pass forward to its retry, not to the next
    /// window.
    #[test]
    fn a_tick_not_yet_is_retried_at_its_time() {
        let mut book = book(None);
        let now = at(20, 9, 0);
        book.hidden_vetter[0].retry_at = Some(now + Duration::minutes(5));
        assert_eq!(
            next_pass(&book, now, |_| Duration::zero()),
            now + Duration::minutes(5)
        );
    }

    /// A re-keyed community schedules nothing of its own; the hourly pass still
    /// runs, so the vetter learns if its keys come back.
    #[test]
    fn a_rekeyed_community_schedules_nothing() {
        let mut book = book(Some("PT1H"));
        let now = at(20, 9, 30);
        book.hidden_vetter[0].rekeyed_at = Some(now);
        assert_eq!(next_pass(&book, now, |_| Duration::zero()), now + MAX_GAP);
    }

    /// A silence noticed between passes brings the next pass forward to its retry, and a
    /// retry that has already passed does not keep the pacer due.
    #[test]
    fn an_unanswered_question_brings_the_next_pass_forward() {
        let mut book = book(None);
        let now = at(20, 9, 0);
        let mut pacer = HiddenVettingPacer::default();
        let next = pacer.schedule(&book, now, &mut rand::thread_rng());
        assert!(
            next > now + Duration::minutes(2),
            "an hour away, or the next window"
        );

        let later = now + Duration::seconds(30);
        let retry = book.hidden_vetter[0].unanswered_at(later);
        assert_eq!(retry, later + Duration::minutes(1), "the first backoff");
        pacer.pull_forward(&book, later);
        assert!(!pacer.due(later));
        assert!(
            pacer.due(retry),
            "due at the retry, not at the scheduled pass"
        );

        // The pass ran and rescheduled; the past retry pulls nothing.
        let after = retry + Duration::seconds(1);
        pacer.schedule(&book, after, &mut rand::thread_rng());
        pacer.pull_forward(&book, after);
        assert!(!pacer.due(after));
    }

    #[test]
    fn the_pacer_is_due_at_once_and_then_when_scheduled() {
        let mut pacer = HiddenVettingPacer::default();
        let now = at(20, 9, 0);
        assert!(pacer.due(now));
        let next = pacer.schedule(&VettingBook::default(), now, &mut rand::thread_rng());
        assert!(!pacer.due(now));
        assert!(pacer.due(next));
    }
}
