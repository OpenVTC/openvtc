//! Getting a vetter back to the hidden-vetting key its community bound it to.
//!
//! A community binds each vetter to one PCS identifier at its first enrolment, for good, and
//! refuses any other from that member with `pcs-root:identifierRebound`. The key behind the
//! identifier is the VTA's, derived from the context's seed at a path the VTA's engine record
//! keeps; replace that record and the next enrolment derives a fresh key the community refuses.
//! Revoking and re-granting the vetter role does not touch the binding.
//!
//! The way back, in the order the specifications prefer it:
//!
//! 1. Ask the community which identifier it holds (`vtc/vetting/vetters/pcs-binding/show`).
//! 2. If the VTA's engine holds another, ask the VTA to restore the bound one
//!    (`vta/pcs/vetter/recover`), then enrol again — once.
//! 3. If the VTA cannot (`notFound`), only a community admin can reset the binding
//!    (`vtc/vetting/vetters/pcs-binding/reset`, which this client never sends). The community
//!    then takes the current key once none of the old key's labels is live, and the schedule
//!    enrols with it on the pass after the reset opens.
//!
//! [`KeyCheck`] is where that stands, kept on the engine's schedule
//! ([`HiddenVetterState::key`]). The bound identifier itself is kept only in memory
//! ([`HiddenVetterState::bound_id`]) for the one call that needs it, and dropped once the engine
//! matches — the specification asks a client to discard it then. A restart that forgot it
//! simply asks the community again.
//!
//! The decision is [`decide`], a pure function of the community's answer and the engine; every
//! transition is a method here, so the whole state machine is tested without a network.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use super::book::HiddenVetterState;

/// The generated `vtc/vetting/vetters/pcs-binding/show/0.1` wire types.
pub use crate::specs::vtc::vetting::vetters::pcs_binding::show::v0_1 as show;

/// How long after asking the community about our binding before asking again: while a reset
/// is awaited, or after a question that went unanswered or was refused (R1.4). The schedule
/// passes far more often than this; the binding is read at most this often.
pub const BINDING_REASK: Duration = Duration::minutes(15);

/// Where getting back to the bound key stands, for one engine. Absent while nothing is wrong.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyCheck {
    /// The step it is at.
    pub phase: KeyPhase,
    /// When it reached that step.
    pub since: DateTime<Utc>,
    /// When the community was last asked about the binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked_at: Option<DateTime<Utc>>,
    /// The admin reset the community last reported, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reset: Option<ResetState>,
    /// The VTA has been asked to restore the key during this check. It is asked once: its
    /// refusals are not retryable.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub recovery_tried: bool,
}

/// One step of a [`KeyCheck`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "step",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum KeyPhase {
    /// Refused as a different key: asking the community which one it bound us to.
    Checking,
    /// The community bound an identifier the engine does not hold: the VTA is asked to restore
    /// it.
    Recovering,
    /// Enrolling again, once. A second `identifierRebound` after this stops the check
    /// ([`KeyPhase::StillRefused`]) rather than going round again.
    Retrying {
        /// Why enrolling again should now be taken.
        why: RetryWhy,
    },
    /// The VTA cannot restore the key: a community admin has to reset the binding. The binding
    /// is read again every [`BINDING_REASK`] to follow the reset ([`KeyCheck::reset`]).
    Lost,
    /// Another of this account's contexts holds an engine with the bound key: vet from there.
    OtherContext {
        /// The VTA's message, which names the context.
        message: String,
    },
    /// The VTA refused to restore the key for a reason other than not finding it.
    RecoverRefused {
        /// The declared code.
        code: String,
        /// What the VTA said.
        message: String,
    },
    /// The community refused the enrolment again after the engine matched what it said it had
    /// bound, or after a reset it said was open. Nothing more is tried until asked by hand.
    StillRefused,
}

/// Why a [`KeyPhase::Retrying`] enrolment is expected to be taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RetryWhy {
    /// The VTA restored the bound key.
    Recovered,
    /// The engine already held the bound key.
    AlreadyHeld,
    /// The community holds no binding for us.
    NotBound,
    /// An admin reset the binding and no old label is live: the current key is taken.
    ResetOpen,
}

/// An admin's reset of our binding, as the community last reported it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResetState {
    /// When the admin reset it.
    pub reset_at: DateTime<Utc>,
    /// The old key's labels the community still accepts; a new key is refused until none is.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub waiting_on: Vec<String>,
    /// A new key is taken now.
    pub open: bool,
}

/// The community's answer about our binding, in this client's terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// The identifier the community bound us to, when it holds one.
    pub id: Option<String>,
    /// A pending admin reset.
    pub reset: Option<ResetState>,
}

impl From<show::Response> for Binding {
    fn from(r: show::Response) -> Self {
        Self {
            // `id` is present exactly when `bound` is; a `bound` with no `id` names nothing.
            id: r.id.filter(|_| r.bound).map(String::from),
            reset: r.reset.map(|reset| ResetState {
                reset_at: reset.reset_at,
                waiting_on: reset.waiting_on.into_iter().map(String::from).collect(),
                open: reset.open,
            }),
        }
    }
}

/// What to do on the community's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Enrol again with the engine's key, now.
    Enrol(RetryWhy),
    /// Ask the VTA to restore the key with this identifier.
    Recover {
        /// The identifier the community bound us to.
        bound_id: String,
    },
    /// Nothing will be taken until an admin resets the binding, or the reset opens.
    Wait,
}

/// The decision, from the community's `binding`, the identifier the VTA's engine holds
/// (`engine_id`, empty for no engine), and whether the VTA has already been asked to restore
/// the key in this check.
///
/// Recovery is tried before a pending reset is used: enrolling with the old key cancels the
/// reset and changes nothing about who the community counts, which is the outcome the
/// specification prefers.
#[must_use]
pub fn decide(binding: &Binding, engine_id: &str, recovery_tried: bool) -> Step {
    let Some(bound_id) = binding.id.as_deref() else {
        return Step::Enrol(RetryWhy::NotBound);
    };
    if bound_id == engine_id {
        return Step::Enrol(RetryWhy::AlreadyHeld);
    }
    if !recovery_tried {
        return Step::Recover {
            bound_id: bound_id.to_string(),
        };
    }
    match &binding.reset {
        Some(reset) if reset.open => Step::Enrol(RetryWhy::ResetOpen),
        _ => Step::Wait,
    }
}

/// How the VTA refused a recovery, by its declared code (R6.4: each has its own way on).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoverRefusal {
    /// `notFound`: no key it can derive has the identifier.
    NotFound,
    /// `heldInAnotherContext`, with the VTA's message naming the context.
    HeldInAnotherContext(String),
    /// Any other declared refusal — `memberMismatch`, `engineEnrolled`, or one this build does
    /// not know — with its code and message.
    Refused {
        /// The code.
        code: String,
        /// The message.
        message: String,
    },
}

impl RecoverRefusal {
    /// Classify a refusal of `vta/pcs/vetter/recover` by its code.
    #[must_use]
    pub fn from_code(code: &str, message: &str) -> Self {
        use super::pcs_vta::tasks::vetter::recover::v0_1::error_codes as codes;
        if code == codes::NOT_FOUND.code {
            Self::NotFound
        } else if code == codes::HELD_IN_ANOTHER_CONTEXT.code {
            Self::HeldInAnotherContext(message.to_string())
        } else {
            Self::Refused {
                code: code.to_string(),
                message: message.to_string(),
            }
        }
    }
}

/// The most of a VTA's message kept for the desk.
const MESSAGE_KEEP: usize = 300;

fn kept(message: &str) -> String {
    message.chars().take(MESSAGE_KEEP).collect()
}

impl KeyCheck {
    fn at(phase: KeyPhase, now: DateTime<Utc>) -> Self {
        Self {
            phase,
            since: now,
            asked_at: None,
            reset: None,
            recovery_tried: false,
        }
    }
}

impl HiddenVetterState {
    /// Whether enrolment is held while the key is sorted out: every step but
    /// [`KeyPhase::Retrying`] would only collect `identifierRebound` again.
    #[must_use]
    pub fn enrolment_held(&self) -> bool {
        self.key
            .as_ref()
            .is_some_and(|k| !matches!(k.phase, KeyPhase::Retrying { .. }))
    }

    /// The community refused our enrolment as a different key (`identifierRebound`).
    ///
    /// The first time, start a check: ask the community what it bound us to. After a retry —
    /// the engine matched what it said, or a reset it said was open — stop instead: going round
    /// again would only collect the same refusal.
    pub fn on_rebound(&mut self, now: DateTime<Utc>) {
        if let Some(k) = &mut self.key
            && matches!(k.phase, KeyPhase::Retrying { .. })
        {
            k.phase = KeyPhase::StillRefused;
            k.since = now;
            self.bound_id = None;
            return;
        }
        self.key = Some(KeyCheck::at(KeyPhase::Checking, now));
        self.bound_id = None;
    }

    /// Start the check again by hand: from the top, recovery included. Also starts one for a
    /// record whose last word from the community was `identifierRebound` but has no check — one
    /// kept before this client knew how. Returns whether a check was started.
    pub fn recheck_key(&mut self, now: DateTime<Utc>) -> bool {
        let rebound = self
            .last_refusal
            .as_ref()
            .is_some_and(|r| r.code.ends_with(":identifierRebound"));
        let restart = match &self.key {
            Some(k) => !matches!(k.phase, KeyPhase::Checking | KeyPhase::Recovering),
            None => rebound,
        };
        if restart {
            self.key = Some(KeyCheck::at(KeyPhase::Checking, now));
            self.bound_id = None;
        }
        restart
    }

    /// Whether the community should be asked about our binding now: to start the check, to
    /// follow a reset, or because a restart forgot the identifier a recovery needs. At most
    /// every [`BINDING_REASK`] once asked.
    #[must_use]
    pub fn binding_read_due(&self, now: DateTime<Utc>) -> bool {
        let Some(k) = &self.key else {
            return false;
        };
        let wants = match k.phase {
            KeyPhase::Checking | KeyPhase::Lost => true,
            KeyPhase::Recovering => self.bound_id.is_none(),
            _ => false,
        };
        wants && k.asked_at.is_none_or(|at| now - at >= BINDING_REASK)
    }

    /// The community was asked about our binding at `now`.
    pub fn binding_asked(&mut self, now: DateTime<Utc>) {
        if let Some(k) = &mut self.key {
            k.asked_at = Some(now);
        }
    }

    /// The community's answer about our binding. Returns the step taken, or `None` when no check
    /// was waiting for it.
    pub fn on_binding_shown(&mut self, binding: &Binding, now: DateTime<Utc>) -> Option<Step> {
        let k = self.key.as_mut()?;
        if !matches!(
            k.phase,
            KeyPhase::Checking | KeyPhase::Recovering | KeyPhase::Lost
        ) {
            return None;
        }
        k.reset.clone_from(&binding.reset);
        let step = decide(binding, &self.engine.id, k.recovery_tried);
        let next = match &step {
            Step::Enrol(_) => None,
            Step::Recover { .. } => Some(KeyPhase::Recovering),
            Step::Wait => Some(KeyPhase::Lost),
        };
        if let Some(next) = next
            && k.phase != next
        {
            k.phase = next;
            k.since = now;
        }
        match &step {
            Step::Enrol(why) => self.retry_enrolment(*why, now),
            Step::Recover { bound_id } => self.bound_id = Some(bound_id.clone()),
            Step::Wait => self.bound_id = None,
        }
        Some(step)
    }

    /// The identifier to ask the VTA to restore, when a recovery is owed.
    #[must_use]
    pub fn recovery_due(&self) -> Option<&str> {
        match &self.key {
            Some(k) if k.phase == KeyPhase::Recovering => self.bound_id.as_deref(),
            _ => None,
        }
    }

    /// The VTA restored the bound key (`recovered`), or already held it: take its engine and
    /// enrol again.
    pub fn on_recovered(
        &mut self,
        recovered: bool,
        engine: super::pcs_vta::VetterView,
        now: DateTime<Utc>,
    ) {
        self.take_engine(engine);
        if let Some(k) = &mut self.key {
            k.recovery_tried = true;
        }
        let why = if recovered {
            RetryWhy::Recovered
        } else {
            RetryWhy::AlreadyHeld
        };
        self.retry_enrolment(why, now);
    }

    /// The VTA refused to restore the key. `notFound` leaves a reset as the way on — taken at
    /// once if the community already reported one open.
    pub fn on_recover_refused(&mut self, refusal: RecoverRefusal, now: DateTime<Utc>) {
        self.bound_id = None;
        let Some(k) = &mut self.key else {
            return;
        };
        k.recovery_tried = true;
        k.since = now;
        let reset_open = k.reset.as_ref().is_some_and(|r| r.open);
        k.phase = match refusal {
            RecoverRefusal::NotFound if reset_open => {
                self.retry_enrolment(RetryWhy::ResetOpen, now);
                return;
            }
            RecoverRefusal::NotFound => KeyPhase::Lost,
            RecoverRefusal::HeldInAnotherContext(message) => KeyPhase::OtherContext {
                message: kept(&message),
            },
            RecoverRefusal::Refused { code, message } => KeyPhase::RecoverRefused {
                code,
                message: kept(&message),
            },
        };
    }

    /// The community enrolled us: whatever was wrong with the key is settled.
    pub fn key_settled(&mut self) {
        self.key = None;
        self.bound_id = None;
    }

    /// Enrol again, once, for `why`: the identifier is no longer needed, the refusal that
    /// started this is answered, and an enrolment the VTA still holds from the refused ask is
    /// not waited on.
    fn retry_enrolment(&mut self, why: RetryWhy, now: DateTime<Utc>) {
        self.bound_id = None;
        self.last_refusal = None;
        self.enrol_asked_at = None;
        if let Some(k) = &mut self.key {
            k.phase = KeyPhase::Retrying { why };
            k.since = now;
        }
    }
}

/// One line of the hidden-vetting view about the key: a label ("Key", "Reset"), what it says,
/// and whether it is something the vetter has to act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLine {
    /// "Key" or "Reset".
    pub label: &'static str,
    /// The words.
    pub text: String,
    /// Whether the vetter has to do something.
    pub act: bool,
}

/// What the hidden-vetting view says about the key, for `name` (the community's display name).
/// Text that came from the VTA is the caller's to sanitise; it is passed through `clean`.
#[must_use]
pub fn key_lines(check: &KeyCheck, name: &str, clean: impl Fn(&str) -> String) -> Vec<KeyLine> {
    let line = |label, text: String, act| KeyLine { label, text, act };
    let ask_admin = format!("ask an admin of {name} to reset your hidden-vetting key");
    match &check.phase {
        KeyPhase::Checking => vec![line(
            "Key",
            format!(
                "{name} knows you by another hidden-vetting key — asking it which one, to \
                 restore it at your VTA"
            ),
            false,
        )],
        KeyPhase::Recovering => vec![line(
            "Key",
            format!("{name} bound you to an earlier key — asking your VTA to restore it"),
            false,
        )],
        KeyPhase::Retrying { why } => vec![match why {
            RetryWhy::Recovered => line(
                "Key",
                "recovered by your VTA — enrolling again with it".to_string(),
                false,
            ),
            RetryWhy::AlreadyHeld => line(
                "Key",
                format!("your VTA holds the key {name} bound you to — enrolling again"),
                false,
            ),
            RetryWhy::NotBound => line(
                "Key",
                format!("{name} holds no earlier key for you — enrolling again"),
                false,
            ),
            RetryWhy::ResetOpen => line(
                "Reset",
                "open — enrolling now with your current key".to_string(),
                false,
            ),
        }],
        KeyPhase::Lost => match &check.reset {
            None => vec![line(
                "Key",
                format!(
                    "lost — your VTA cannot restore the key {name} bound you to; {ask_admin}. \
                     Re-granting the vetter role does not change it"
                ),
                true,
            )],
            Some(reset) => {
                let mut lines = vec![line(
                    "Key",
                    format!(
                        "lost — an admin of {name} reset it on {}",
                        reset.reset_at.format("%Y-%m-%d")
                    ),
                    false,
                )];
                lines.push(if reset.open || reset.waiting_on.is_empty() {
                    line(
                        "Reset",
                        "open — enrolling now with your current key".to_string(),
                        false,
                    )
                } else {
                    let labels: Vec<String> = reset.waiting_on.iter().map(|l| clean(l)).collect();
                    line(
                        "Reset",
                        format!(
                            "waiting for {} to retire — then you enrol with your current key",
                            labels.join(", ")
                        ),
                        false,
                    )
                });
                lines
            }
        },
        KeyPhase::OtherContext { message } => vec![line(
            "Key",
            format!(
                "held by another of your contexts — vet for {name} from that persona ({})",
                clean(message)
            ),
            true,
        )],
        KeyPhase::RecoverRefused { code, message } => {
            let local = code.rsplit_once(':').map_or(code.as_str(), |(_, l)| l);
            let text = match local {
                "engineEnrolled" => format!(
                    "your VTA will not replace its key: that key already holds a credential, \
                     tokens or attestations, yet {name} seemed to bind you to another. The \
                     binding read was likely stale — r checks it again"
                ),
                "memberMismatch" => format!(
                    "your VTA's engine for {name} in this context belongs to another member DID \
                     — vet as the persona it was made for; a reset does not change that"
                ),
                _ => format!(
                    "your VTA refused to restore it ({}): {}",
                    clean(code),
                    clean(message)
                ),
            };
            vec![line("Key", text, true)]
        }
        KeyPhase::StillRefused => vec![line(
            "Key",
            format!(
                "{name} still refuses the key your VTA holds, after checking it against the \
                 one it bound — {ask_admin} (r checks again)"
            ),
            true,
        )],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::account::PersonaId;
    use crate::vetting::hidden::HiddenParams;
    use crate::vetting::pcs_vta::VetterView;

    fn at(minutes: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_790_000_000, 0).unwrap() + Duration::minutes(minutes)
    }

    fn held(engine_id: &str) -> HiddenVetterState {
        let params: HiddenParams = serde_json::from_value(serde_json::json!({
            "suite": "ps-ddh-bls12381",
            "helperKey": "zHelper",
            "tokenKey": "zToken",
            "vetterLabels": ["vetter/2026-11"],
            "tokenLabels": ["token/2026-11"],
        }))
        .unwrap();
        let mut h = HiddenVetterState::new("did:web:vtc.example", PersonaId::new(), params);
        h.take_engine(VetterView {
            id: engine_id.into(),
            ..VetterView::default()
        });
        h
    }

    fn bound(id: &str) -> Binding {
        Binding {
            id: Some(id.into()),
            reset: None,
        }
    }

    fn reset(open: bool, waiting_on: &[&str]) -> ResetState {
        ResetState {
            reset_at: at(-60),
            waiting_on: waiting_on.iter().map(|s| (*s).to_string()).collect(),
            open,
        }
    }

    fn phase(h: &HiddenVetterState) -> KeyPhase {
        h.key.as_ref().unwrap().phase.clone()
    }

    #[test]
    fn the_decision_prefers_recovery_then_a_reset() {
        assert_eq!(
            decide(
                &Binding {
                    id: None,
                    reset: None
                },
                "zNew",
                false
            ),
            Step::Enrol(RetryWhy::NotBound)
        );
        assert_eq!(
            decide(&bound("zOld"), "zOld", false),
            Step::Enrol(RetryWhy::AlreadyHeld)
        );
        assert_eq!(
            decide(&bound("zOld"), "zNew", false),
            Step::Recover {
                bound_id: "zOld".into()
            }
        );
        // An open reset does not skip the recovery: the old key cancels the reset, and is the
        // outcome to prefer.
        let open = Binding {
            reset: Some(reset(true, &[])),
            ..bound("zOld")
        };
        assert!(matches!(decide(&open, "zNew", false), Step::Recover { .. }));
        assert_eq!(
            decide(&open, "zNew", true),
            Step::Enrol(RetryWhy::ResetOpen)
        );
        let waiting = Binding {
            reset: Some(reset(false, &["vetter/2026-10"])),
            ..bound("zOld")
        };
        assert_eq!(decide(&waiting, "zNew", true), Step::Wait);
        assert_eq!(decide(&bound("zOld"), "zNew", true), Step::Wait);
        // No engine at the VTA yet: recovery creates it.
        assert!(matches!(
            decide(&bound("zOld"), "", false),
            Step::Recover { .. }
        ));
    }

    #[test]
    fn a_rebound_key_is_recovered_and_enrolment_retried_once() {
        let mut h = held("zNew");
        assert!(!h.enrolment_held());
        h.on_rebound(at(0));
        assert_eq!(phase(&h), KeyPhase::Checking);
        assert!(
            h.enrolment_held(),
            "no enrolment while the key is sorted out"
        );
        assert!(h.binding_read_due(at(0)));
        h.binding_asked(at(0));
        assert!(!h.binding_read_due(at(1)), "asked once, not every pass");

        let step = h.on_binding_shown(&bound("zOld"), at(1));
        assert!(matches!(step, Some(Step::Recover { .. })));
        assert_eq!(h.recovery_due(), Some("zOld"));
        assert!(h.enrolment_held());

        h.on_recovered(
            true,
            VetterView {
                id: "zOld".into(),
                ..VetterView::default()
            },
            at(2),
        );
        assert_eq!(
            phase(&h),
            KeyPhase::Retrying {
                why: RetryWhy::Recovered
            }
        );
        assert_eq!(h.engine.id, "zOld");
        assert!(
            h.bound_id.is_none(),
            "the identifier is dropped once matched"
        );
        assert!(!h.enrolment_held(), "enrol again");
        assert!(h.recovery_due().is_none());

        // Refused again after that: stop rather than go round.
        h.on_rebound(at(3));
        assert_eq!(phase(&h), KeyPhase::StillRefused);
        assert!(h.enrolment_held());
        assert!(!h.binding_read_due(at(100)));

        // By hand: from the top.
        assert!(h.recheck_key(at(4)));
        assert_eq!(phase(&h), KeyPhase::Checking);
        assert!(h.binding_read_due(at(4)));

        // Enrolled: settled.
        h.key_settled();
        assert!(h.key.is_none());
        assert!(!h.enrolment_held());
    }

    #[test]
    fn a_key_the_vta_cannot_find_waits_for_a_reset_then_enrols() {
        let mut h = held("zNew");
        h.on_rebound(at(0));
        h.binding_asked(at(0));
        h.on_binding_shown(&bound("zOld"), at(1));
        h.on_recover_refused(RecoverRefusal::NotFound, at(2));
        assert_eq!(phase(&h), KeyPhase::Lost);
        assert!(h.enrolment_held());
        assert!(h.bound_id.is_none());
        // Followed, but not on every pass.
        assert!(!h.binding_read_due(at(3)));
        assert!(h.binding_read_due(at(0) + BINDING_REASK));

        // An admin reset it; an old label is still live.
        h.binding_asked(at(20));
        let waiting = Binding {
            reset: Some(reset(false, &["vetter/2026-10"])),
            ..bound("zOld")
        };
        assert_eq!(h.on_binding_shown(&waiting, at(21)), Some(Step::Wait));
        assert_eq!(phase(&h), KeyPhase::Lost);
        assert_eq!(
            h.key.as_ref().unwrap().reset.as_ref().unwrap().waiting_on,
            vec!["vetter/2026-10".to_string()]
        );
        assert!(h.recovery_due().is_none(), "the VTA is not asked twice");

        // The label retired: the current key is taken.
        let open = Binding {
            reset: Some(reset(true, &[])),
            ..bound("zOld")
        };
        assert_eq!(
            h.on_binding_shown(&open, at(40)),
            Some(Step::Enrol(RetryWhy::ResetOpen))
        );
        assert!(!h.enrolment_held());
    }

    #[test]
    fn a_reset_already_open_is_used_when_the_vta_cannot_find_the_key() {
        let mut h = held("zNew");
        h.on_rebound(at(0));
        let open = Binding {
            reset: Some(reset(true, &[])),
            ..bound("zOld")
        };
        assert!(matches!(
            h.on_binding_shown(&open, at(1)),
            Some(Step::Recover { .. })
        ));
        h.on_recover_refused(RecoverRefusal::NotFound, at(2));
        assert_eq!(
            phase(&h),
            KeyPhase::Retrying {
                why: RetryWhy::ResetOpen
            }
        );
    }

    #[test]
    fn the_other_refusals_stop_with_their_own_words() {
        use crate::vetting::pcs_vta::tasks::vetter::recover::v0_1::error_codes as codes;
        let name = "Kernel";
        let clean = |s: &str| s.to_string();
        let words = |refusal: RecoverRefusal| {
            let mut h = held("zNew");
            h.on_rebound(at(0));
            h.on_binding_shown(&bound("zOld"), at(1));
            h.on_recover_refused(refusal, at(2));
            assert!(h.enrolment_held());
            assert!(!h.binding_read_due(at(100)), "not asked again by itself");
            key_lines(h.key.as_ref().unwrap(), name, clean)
                .into_iter()
                .map(|l| l.text)
                .collect::<Vec<_>>()
                .join(" ")
        };
        let elsewhere = words(RecoverRefusal::from_code(
            codes::HELD_IN_ANOTHER_CONTEXT.code,
            "held in context work/communities",
        ));
        assert!(elsewhere.contains("work/communities"), "{elsewhere}");
        assert!(elsewhere.contains("from that persona"), "{elsewhere}");
        let enrolled = words(RecoverRefusal::from_code(codes::ENGINE_ENROLLED.code, "x"));
        assert!(enrolled.contains("will not replace its key"), "{enrolled}");
        let mismatch = words(RecoverRefusal::from_code(codes::MEMBER_MISMATCH.code, "x"));
        assert!(mismatch.contains("another member DID"), "{mismatch}");
        assert_ne!(enrolled, mismatch);
        let unknown = words(RecoverRefusal::from_code("vta/pcs/vetter/recover:new", "m"));
        assert!(
            unknown.contains("(vta/pcs/vetter/recover:new)"),
            "{unknown}"
        );
        assert_eq!(
            RecoverRefusal::from_code(codes::NOT_FOUND.code, ""),
            RecoverRefusal::NotFound
        );
    }

    #[test]
    fn the_desk_says_lost_and_what_the_reset_waits_on() {
        let clean = |s: &str| s.to_string();
        let mut check = KeyCheck::at(KeyPhase::Lost, at(0));
        let lost = key_lines(&check, "Kernel", clean);
        assert_eq!(lost.len(), 1);
        assert!(lost[0].act);
        assert!(
            lost[0]
                .text
                .contains("ask an admin of Kernel to reset your hidden-vetting key")
        );
        check.reset = Some(reset(false, &["vetter/2026-10"]));
        let waiting = key_lines(&check, "Kernel", clean);
        assert_eq!(waiting[1].label, "Reset");
        assert!(
            waiting[1]
                .text
                .contains("waiting for vetter/2026-10 to retire")
        );
        let retrying = key_lines(
            &KeyCheck::at(
                KeyPhase::Retrying {
                    why: RetryWhy::ResetOpen,
                },
                at(0),
            ),
            "Kernel",
            clean,
        );
        assert_eq!(retrying[0].label, "Reset");
        assert!(retrying[0].text.starts_with("open — enrolling now"));
        let recovered = key_lines(
            &KeyCheck::at(
                KeyPhase::Retrying {
                    why: RetryWhy::Recovered,
                },
                at(0),
            ),
            "Kernel",
            clean,
        );
        assert!(recovered[0].text.starts_with("recovered"));
    }

    /// The identifier is never written to the store; a restart that forgot it asks the
    /// community again rather than stalling.
    #[test]
    fn the_bound_identifier_is_not_persisted() {
        let mut h = held("zNew");
        h.on_rebound(at(0));
        h.binding_asked(at(0));
        h.on_binding_shown(&bound("zOld"), at(1));
        let stored = serde_json::to_string(&h).unwrap();
        assert!(!stored.contains("zOld"), "{stored}");
        let mut back: HiddenVetterState = serde_json::from_str(&stored).unwrap();
        assert_eq!(back.key, h.key);
        assert!(back.recovery_due().is_none());
        assert!(
            back.binding_read_due(at(0) + BINDING_REASK),
            "asked again to learn it"
        );
        back.on_binding_shown(&bound("zOld"), at(20));
        assert_eq!(back.recovery_due(), Some("zOld"));
    }

    #[test]
    fn the_show_answer_is_read_from_the_generated_type() {
        let r: show::Response = serde_json::from_value(serde_json::json!({
            "bound": true,
            "id": "z5jokfsiZx1sk1mJyQnBnR519B9mcQhw9a8LrF9VQdAjExwoLzcdVdZ2aXaH14a3mdF",
            "enrolledLabels": ["vetter/2026-09", "vetter/2026-10"],
            "reset": {
                "resetAt": "2026-11-02T14:20:00Z",
                "waitingOn": ["vetter/2026-10"],
                "open": false
            }
        }))
        .unwrap();
        let b = Binding::from(r);
        assert!(b.id.as_deref().unwrap().starts_with("z5jok"));
        let reset = b.reset.unwrap();
        assert_eq!(reset.waiting_on, vec!["vetter/2026-10".to_string()]);
        assert!(!reset.open);
        let unbound: show::Response =
            serde_json::from_value(serde_json::json!({ "bound": false, "enrolledLabels": [] }))
                .unwrap();
        assert_eq!(Binding::from(unbound).id, None);
    }
}
