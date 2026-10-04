//! An application as a journey: every step it takes, which are done, which one
//! is the holder's to take now, and which wait on someone else.
//!
//! The pages that walk an applicant through vetting draw from this, so the
//! order and the rules live in one place and can be tested without a screen.
//! It is built on [`Application::next_step`] — the step this marks current is
//! the one that function already names — so the journey and the one-line
//! "next:" hints elsewhere cannot disagree about what to do.
//!
//! Each step also says, in plain words, what it is for. The journey is meant to
//! teach the process as it goes: why a face, why a match code read aloud, what
//! the community will and will not learn. Those sentences are made here for the
//! same reason [`super::guide`] makes the requirement sentences: one wording,
//! wherever it is shown.

use chrono::{DateTime, Utc};

use super::applicant::{Application, NextStep, RequestState};

/// Where a step stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepState {
    /// Done.
    Done,
    /// The holder's to take now. At most one step is current.
    Current,
    /// Waiting on someone else — a vetter, or the community.
    Waiting,
    /// Not reached yet.
    Todo,
}

/// The steps of an application, in the order they are taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplicantStep {
    /// Learn what the community asks for.
    Requirements,
    /// Choose the face vetters see.
    Face,
    /// Ask vetters, with their tickets.
    Vetters,
    /// Meet each vetter: read the match code, send the card.
    Sessions,
    /// Collect enough statements.
    Statements,
    /// See what the community will receive, then join.
    Join,
}

impl ApplicantStep {
    /// Every step, in order.
    pub const ALL: [ApplicantStep; 6] = [
        ApplicantStep::Requirements,
        ApplicantStep::Face,
        ApplicantStep::Vetters,
        ApplicantStep::Sessions,
        ApplicantStep::Statements,
        ApplicantStep::Join,
    ];

    /// The step's name, short enough for a strip across the top of a page.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            ApplicantStep::Requirements => "Requirements",
            ApplicantStep::Face => "Face",
            ApplicantStep::Vetters => "Vetters",
            ApplicantStep::Sessions => "Sessions",
            ApplicantStep::Statements => "Statements",
            ApplicantStep::Join => "Join",
        }
    }

    /// What this step is for, in sentences a person reads before acting.
    ///
    /// `hidden` is whether the community proves vetting with a PCS
    /// zero-knowledge proof, which changes what the later steps mean for the
    /// vetters.
    #[must_use]
    pub fn explain(self, hidden: bool) -> &'static [&'static str] {
        match (self, hidden) {
            (ApplicantStep::Requirements, _) => &[
                "A community that vets its members publishes what it needs before it will \
                 decide on you: how many vetters, how they must check you, and what they check.",
                "Nothing about you has been sent yet. Reading the requirements first is how you \
                 decide whether to apply at all.",
            ],
            (ApplicantStep::Face, _) => &[
                "Vetters never see your whole identity. They see a face — the attributes you \
                 choose to show — and check it against your documents.",
                "The face is worn in this community's context, so the community sees the same \
                 face when you join. Its values must match your documents exactly.",
            ],
            (ApplicantStep::Vetters, _) => &[
                "A vetter is a member the community has named to vouch for people. You reach \
                 one with their ticket — a link or QR code they give you, or one found in the \
                 community's directory.",
                "Each request goes to one vetter. You need statements from different vetters, \
                 so ask as many as the requirements call for.",
            ],
            (ApplicantStep::Sessions, _) => &[
                "When you and a vetter are together — in person or on a call — they open a \
                 session, and both your screens show the same match code.",
                "Read it aloud and hear it read back. Matching codes prove the card you send \
                 reaches the person in front of you, not someone who intercepted the request.",
            ],
            (ApplicantStep::Statements, false) => &[
                "After checking you, each vetter signs a statement that they did, and sends it \
                 to you. You hold them; the community has none of them yet.",
                "These statements are named: when you join, the community sees which vetters \
                 vouched for you.",
            ],
            (ApplicantStep::Statements, true) => &[
                "After checking you, each vetter sends you an attestation. You hold them; the \
                 community has none of them yet.",
                "This community uses a PCS zero-knowledge proof: when you join, it learns that \
                 enough vetters vouched for you, but never which ones.",
            ],
            (ApplicantStep::Join, false) => &[
                "Joining sends the community your persona's DID, the vetting statements you \
                 hold, and what your face shows. Review it before it goes.",
                "Each statement names its vetter, so the community will see who vouched for \
                 you.",
            ],
            (ApplicantStep::Join, true) => &[
                "Joining sends the community your persona's DID, what your face shows, and a \
                 zero-knowledge proof built from the attestations you hold.",
                "The proof shows enough vetters vouched for you without revealing who — the \
                 community never sees a vetter's identity.",
            ],
        }
    }
}

/// One step of a journey, with where it stands and a few words about progress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JourneyStep<S> {
    pub step: S,
    pub state: StepState,
    /// Progress in a few words — "1 of 2", "Work" — when there is any.
    pub detail: Option<String>,
}

/// An application's journey, every step in order.
#[must_use]
pub fn applicant_journey(app: &Application, now: DateTime<Utc>) -> Vec<JourneyStep<ApplicantStep>> {
    let next = app.next_step(now);
    let evaluation = app.checklist(now);
    let satisfied = evaluation.as_ref().is_some_and(|e| e.satisfied());
    let needed = app
        .requirements
        .as_ref()
        .map(|r| r.min_statements.get() as usize);
    let held = app
        .statements
        .iter()
        .filter(|s| s.valid_until > now)
        .count();
    let asked = app
        .requests
        .iter()
        .filter(|r| {
            !matches!(
                r.state,
                RequestState::Declined { .. } | RequestState::Refused { .. }
            )
        })
        .count();
    let open_sessions = app
        .requests
        .iter()
        .filter(|r| matches!(r.state, RequestState::Session { ref card, .. } if card.is_none()))
        .count();
    let waiting_on_vetters = app.requests.iter().any(|r| {
        matches!(
            r.state,
            RequestState::Sent | RequestState::Accepted { .. } | RequestState::Session { .. }
        )
    });
    let cards_sent = app
        .requests
        .iter()
        .filter(|r| {
            matches!(r.state, RequestState::Session { ref card, .. } if card.is_some())
                || matches!(r.state, RequestState::Attested { .. })
        })
        .count();

    let known = app.requirements.is_some();
    let state_of = |step: ApplicantStep| -> StepState {
        match step {
            ApplicantStep::Requirements if known => StepState::Done,
            ApplicantStep::Requirements => StepState::Current,
            _ if !known => StepState::Todo,
            ApplicantStep::Face if app.face.is_some() => StepState::Done,
            // A card already sent shows a face was worn, recorded or not.
            ApplicantStep::Face if cards_sent > 0 || held > 0 => StepState::Done,
            ApplicantStep::Face => StepState::Current,
            _ if satisfied => match step {
                ApplicantStep::Join => StepState::Current,
                _ => StepState::Done,
            },
            ApplicantStep::Vetters if asked >= needed.unwrap_or(1) => StepState::Done,
            ApplicantStep::Vetters if matches!(next, NextStep::AskVetter) => StepState::Current,
            ApplicantStep::Vetters if asked > 0 => StepState::Done,
            ApplicantStep::Vetters => StepState::Current,
            ApplicantStep::Sessions if open_sessions > 0 => StepState::Current,
            ApplicantStep::Sessions if asked == 0 => StepState::Todo,
            ApplicantStep::Sessions if waiting_on_vetters => StepState::Waiting,
            ApplicantStep::Sessions => StepState::Done,
            ApplicantStep::Statements if waiting_on_vetters || held > 0 => StepState::Waiting,
            ApplicantStep::Statements => StepState::Todo,
            ApplicantStep::Join => StepState::Todo,
        }
    };
    let detail_of = |step: ApplicantStep| -> Option<String> {
        match step {
            ApplicantStep::Face => app.face.as_ref().map(|f| f.name.clone()),
            ApplicantStep::Vetters if asked > 0 => Some(format!("{asked} asked")),
            ApplicantStep::Sessions if open_sessions > 0 => Some(format!(
                "{open_sessions} code{} to read",
                if open_sessions == 1 { "" } else { "s" }
            )),
            ApplicantStep::Sessions if cards_sent > 0 => Some(format!("{cards_sent} card(s) sent")),
            ApplicantStep::Statements => needed.map(|n| format!("{} of {n}", held.min(n))),
            _ => None,
        }
    };

    let mut steps: Vec<JourneyStep<ApplicantStep>> = ApplicantStep::ALL
        .iter()
        .map(|&step| JourneyStep {
            step,
            state: state_of(step),
            detail: detail_of(step),
        })
        .collect();
    // One current step at most, and it is the first: a later step marked
    // current while an earlier one still is would offer two things to do.
    let mut seen_current = false;
    for s in &mut steps {
        if s.state == StepState::Current {
            if seen_current {
                s.state = StepState::Todo;
            }
            seen_current = true;
        }
    }
    steps
}

/// The step the holder takes now, if any — every other step is done, or
/// waits on someone else.
#[must_use]
pub fn current<S: Copy>(steps: &[JourneyStep<S>]) -> Option<S> {
    steps
        .iter()
        .find(|s| s.state == StepState::Current)
        .map(|s| s.step)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::account::PersonaId;
    use crate::vetting::applicant::ChosenFace;

    fn app() -> Application {
        Application::new(
            "did:web:vtc.example",
            PersonaId::new(),
            "did:key:zApplicant",
            Utc::now(),
        )
        .unwrap()
    }

    fn requirements() -> vta_sdk::protocols::vetting::VettingRequirements {
        serde_json::from_value(serde_json::json!({
            "version": "0.1",
            "statementType": vta_sdk::protocols::vetting::VETTED_PREDICATE,
            "minStatements": 2,
            "acceptedMethods": ["inPerson", "video"],
            "eligibleVetters": { "role": "vetter" }
        }))
        .unwrap()
    }

    fn states(app: &Application) -> Vec<StepState> {
        applicant_journey(app, Utc::now())
            .into_iter()
            .map(|s| s.state)
            .collect()
    }

    use StepState::{Current, Done, Todo};

    #[test]
    fn a_new_application_starts_by_learning_the_requirements() {
        let a = app();
        assert_eq!(states(&a), [Current, Todo, Todo, Todo, Todo, Todo]);
        assert_eq!(
            current(&applicant_journey(&a, Utc::now())),
            Some(ApplicantStep::Requirements)
        );
    }

    #[test]
    fn with_requirements_known_the_face_comes_next_then_vetters() {
        let mut a = app();
        a.requirements = Some(requirements());
        assert_eq!(states(&a), [Done, Current, Todo, Todo, Todo, Todo]);

        a.face = Some(ChosenFace {
            profile_id: "p".into(),
            name: "Work".into(),
        });
        let journey = applicant_journey(&a, Utc::now());
        assert_eq!(current(&journey), Some(ApplicantStep::Vetters));
        assert_eq!(journey[1].detail.as_deref(), Some("Work"));
        assert_eq!(journey[4].detail.as_deref(), Some("0 of 2"));
    }

    /// Every step explains itself, and the two vetting modes say different
    /// things where it matters: who the community learns vouched for you.
    #[test]
    fn every_step_explains_itself_and_hidden_mode_says_vetters_stay_hidden() {
        for step in ApplicantStep::ALL {
            assert!(!step.explain(false).is_empty(), "{step:?}");
            assert!(!step.explain(true).is_empty(), "{step:?}");
        }
        let named = ApplicantStep::Join.explain(false).join(" ");
        let hidden = ApplicantStep::Join.explain(true).join(" ");
        assert!(named.contains("see who vouched"), "{named}");
        assert!(hidden.contains("without revealing who"), "{hidden}");
    }
}
