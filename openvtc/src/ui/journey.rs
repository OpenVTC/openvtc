//! The drawing shared by every journey page: a strip of steps across the top
//! that shows where you are, and a box that says what is happening and why.
//!
//! The applicant's and the vetter's journeys look the same on purpose. They
//! are two halves of one exchange, and a vetter who has applied somewhere (or
//! an applicant who later vets) should recognise the shape at once.

use crate::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
};
use openvtc_core::vetting::journey::{JourneyStep, StepState};
use ratatui::{
    style::{Modifier, Style},
    text::{Line, Span},
};

/// The marker and style a step is drawn with.
fn look(state: StepState) -> (&'static str, Style) {
    match state {
        StepState::Done => ("✓", Style::new().fg(COLOR_SUCCESS)),
        StepState::Current => (
            "●",
            Style::new()
                .fg(COLOR_BORDER)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        ),
        StepState::Waiting => ("…", Style::new().fg(COLOR_ORANGE)),
        StepState::Todo => ("○", Style::new().fg(COLOR_DARK_GRAY)),
    }
}

/// The steps as one strip — `✓ Requirements ─ ● Face ─ ○ Vetters …` — with a
/// second line under it naming each step's progress where it has any.
///
/// Waiting is drawn apart from to-do: "the vetter has it" and "you have not
/// reached this" call for opposite things from the reader.
#[must_use]
pub fn strip<S: Copy>(
    steps: &[JourneyStep<S>],
    label: impl Fn(S) -> &'static str,
) -> Vec<Line<'static>> {
    let mut top = Vec::new();
    let mut under = Vec::new();
    for (i, step) in steps.iter().enumerate() {
        if i > 0 {
            top.push(Span::styled(" ─ ", Style::new().fg(COLOR_DARK_GRAY)));
            under.push(Span::raw("   "));
        }
        let (mark, style) = look(step.state);
        let text = format!("{mark} {}", label(step.step));
        let width = text.chars().count();
        top.push(Span::styled(text, style));
        let detail = step.detail.clone().unwrap_or_default();
        let detail: String = detail.chars().take(width).collect();
        under.push(Span::styled(
            format!("{detail:<width$}"),
            Style::new().fg(COLOR_DARK_GRAY),
        ));
    }
    vec![Line::from(top), Line::from(under)]
}

/// The "what is happening" box: a heading, then the step's explanation as
/// plain sentences. Drawn as text inside the page rather than a bordered
/// widget so it wraps with the page at any width.
#[must_use]
pub fn explainer(heading: &str, sentences: &[&str]) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(Span::styled(
        format!("What's happening — {heading}"),
        Style::new().fg(COLOR_BORDER).add_modifier(Modifier::BOLD),
    ))];
    for sentence in sentences {
        lines.push(Line::from(Span::styled(
            format!("  {sentence}"),
            Style::new().fg(COLOR_TEXT_DEFAULT),
        )));
    }
    lines
}

/// The legend for the strip's markers, for the foot of a journey page.
#[must_use]
pub fn legend() -> Line<'static> {
    let mut spans = Vec::new();
    for (state, words) in [
        (StepState::Done, "done"),
        (StepState::Current, "yours now"),
        (StepState::Waiting, "waiting on someone else"),
        (StepState::Todo, "to come"),
    ] {
        let (mark, style) = look(state);
        spans.push(Span::styled(
            format!("{mark} "),
            style.remove_modifier(Modifier::UNDERLINED),
        ));
        spans.push(Span::styled(
            format!("{words}   "),
            Style::new().fg(COLOR_DARK_GRAY),
        ));
    }
    Line::from(spans)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openvtc_core::vetting::journey::{ApplicantStep, JourneyStep};

    fn text(lines: &[Line<'_>]) -> String {
        lines
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn the_strip_marks_each_step_and_carries_its_progress_underneath() {
        let steps = vec![
            JourneyStep {
                step: ApplicantStep::Requirements,
                state: StepState::Done,
                detail: None,
            },
            JourneyStep {
                step: ApplicantStep::Face,
                state: StepState::Current,
                detail: Some("Work".into()),
            },
            JourneyStep {
                step: ApplicantStep::Statements,
                state: StepState::Waiting,
                detail: Some("1 of 2".into()),
            },
        ];
        let drawn = text(&strip(&steps, ApplicantStep::label));
        let mut lines = drawn.lines();
        assert_eq!(
            lines.next().unwrap(),
            "✓ Requirements ─ ● Face ─ … Statements"
        );
        let under = lines.next().unwrap();
        assert!(
            under.contains("Work") && under.contains("1 of 2"),
            "{under}"
        );
    }
}
