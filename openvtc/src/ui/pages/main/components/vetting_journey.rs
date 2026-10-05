//! The journey page: one application, or one desk request, drawn as the whole
//! process — every step in order, where it stands, what it is for, and the one
//! thing to do now.
//!
//! It wraps the Vetting page's own views rather than replacing them. When a
//! step opens a form (choosing a face, asking a vetter, sending a card,
//! attesting) the form is drawn here, under the strip, so the holder never
//! loses sight of where that form sits in the whole. When nothing is open, the
//! page says what the current step asks of them, or who it is waiting on.

use crate::colors::{
    COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
};
use crate::state_handler::main_page::content::{
    JourneySteps, JourneyView, VettingMode, VettingState,
};
use crate::ui::{badges, journey};
use openvtc_core::display::display_identifier;
use openvtc_core::vetting::journey::{ApplicantStep, StepState, VetterEnding, VetterStep, current};
use ratatui::{
    style::Style,
    text::{Line, Span},
};

fn dim() -> Style {
    Style::new().fg(COLOR_DARK_GRAY)
}

fn key(k: &str, what: &str) -> Vec<Span<'static>> {
    vec![
        Span::styled(format!("  {k}"), Style::new().fg(COLOR_SUCCESS).bold()),
        Span::styled(format!("  {what}"), Style::new().fg(COLOR_TEXT_DEFAULT)),
    ]
}

/// Draw the journey. `mode_lines` draws whichever of the Vetting page's views
/// is open, so a step's form appears here unchanged.
pub fn render(
    v: &VettingState,
    j: &JourneyView,
    mode_lines: fn(&mut Vec<Line<'static>>, &VettingState),
) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];
    let mut title = vec![Span::styled(
        j.title.clone(),
        Style::new().fg(COLOR_TEXT_DEFAULT).bold(),
    )];
    // Either way, on the title: which kind of vetting this is decides what
    // the community learns about the vetters, and both sides should know it
    // from the first line of the page.
    title.push(Span::raw("   "));
    title.push(if j.pcs_zkp {
        badges::pcs_zkp()
    } else {
        badges::vetters_named()
    });
    lines.push(Line::from(title));
    lines.push(Line::from(""));

    match &j.steps {
        JourneySteps::Applicant(steps) => {
            lines.extend(journey::strip(steps, ApplicantStep::label));
            lines.push(Line::from(""));
            if let Some(message) = &v.status_message {
                super::status::push_status(&mut lines, message, "");
                lines.push(Line::from(""));
            }
            // Explain the step the holder is on; when none is theirs, the one
            // they are waiting on — that is the one they will be wondering about.
            let focus = current(steps).or_else(|| {
                steps
                    .iter()
                    .find(|s| s.state == StepState::Waiting)
                    .map(|s| s.step)
            });
            if let Some(step) = focus {
                lines.extend(journey::explainer(step.label(), step.explain(j.pcs_zkp)));
                lines.push(Line::from(""));
            }
            if matches!(v.mode, VettingMode::List) {
                applicant_part(
                    &mut lines,
                    v,
                    focus,
                    steps
                        .iter()
                        .any(|s| s.step == ApplicantStep::Join && s.state == StepState::Current),
                );
            } else {
                mode_lines(&mut lines, v);
            }
        }
        JourneySteps::Vetter(steps, ending) => {
            lines.extend(journey::strip(steps, VetterStep::label));
            lines.push(Line::from(""));
            if let Some(message) = &v.status_message {
                super::status::push_status(&mut lines, message, "");
                lines.push(Line::from(""));
            }
            let focus = current(steps).or_else(|| {
                steps
                    .iter()
                    .find(|s| s.state == StepState::Waiting)
                    .map(|s| s.step)
            });
            if ending.is_none()
                && let Some(step) = focus
            {
                lines.extend(journey::explainer(step.label(), step.explain(j.pcs_zkp)));
                lines.push(Line::from(""));
            }
            if matches!(v.mode, VettingMode::List) {
                vetter_part(&mut lines, v, focus, *ending);
            } else {
                mode_lines(&mut lines, v);
            }
        }
    }

    lines.push(Line::from(""));
    lines.push(journey::legend());
    lines
}

/// The applicant's part now, and the people they are waiting on.
fn applicant_part(
    lines: &mut Vec<Line<'static>>,
    v: &VettingState,
    focus: Option<ApplicantStep>,
    joinable: bool,
) {
    let Some(app) = v.applications.get(v.selected) else {
        return;
    };
    lines.push(Line::from(Span::styled(
        "Your part now",
        Style::new().fg(COLOR_SOFT_PURPLE).bold(),
    )));
    match focus {
        Some(ApplicantStep::Requirements) => {
            lines.push(Line::from(key("m", "ask the community what it requires")));
        }
        Some(ApplicantStep::Face) => {
            lines.push(Line::from(key(
                "f",
                "choose the face vetters see, or make one",
            )));
        }
        Some(ApplicantStep::Vetters) => {
            lines.push(Line::from(key(
                "r",
                "ask a vetter with the ticket link they gave you",
            )));
            lines.push(Line::from(key(
                "v",
                "find a vetter in the community's directory",
            )));
        }
        Some(ApplicantStep::Sessions) if app.requests.iter().any(|r| r.card_session.is_some()) => {
            lines.push(Line::from(key(
                "Enter",
                "read the match code together, then preview and send your card",
            )));
        }
        Some(ApplicantStep::Join) if joinable => {
            lines.push(Line::from(key(
                "j",
                "see what the community will receive, then join",
            )));
        }
        _ => {
            lines.push(Line::from(Span::styled(
                "  Nothing to do until a vetter answers. You can leave this page — it moves on \
                 by itself, and the Inbox tells you when it is your turn.",
                dim(),
            )));
            lines.push(Line::from(key("r / v", "ask another vetter")));
        }
    }
    if !app.requests.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Your vetters",
            Style::new().fg(COLOR_SOFT_PURPLE).bold(),
        )));
        for request in &app.requests {
            let mut row = vec![
                Span::styled(
                    format!(
                        "  {}",
                        display_identifier(request.vetter_name.as_deref(), &request.vetter, 48)
                    ),
                    Style::new().fg(COLOR_TEXT_DEFAULT),
                ),
                Span::styled(format!("  {}", request.state), dim()),
            ];
            if let Some(code) = &request.match_code {
                row.push(Span::styled(
                    format!("  code {code}"),
                    Style::new().fg(COLOR_SUCCESS).bold(),
                ));
            }
            lines.push(Line::from(row));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Esc: back to your applications (nothing is lost)   x: abandon this application",
        dim(),
    )));
}

/// The vetter's part now.
fn vetter_part(
    lines: &mut Vec<Line<'static>>,
    v: &VettingState,
    focus: Option<VetterStep>,
    ending: Option<VetterEnding>,
) {
    // By id: a finished request leaves the desk list, so the highlight no
    // longer points at it — and pointing at the next row would show someone
    // else's card under this journey.
    let row = match &v.journey_target {
        Some(crate::state_handler::main_page::content::JourneyTarget::Desk(id)) => {
            v.desk.iter().find(|r| &r.request_id == id)
        }
        _ => None,
    };
    lines.push(Line::from(Span::styled(
        "Your part now",
        Style::new().fg(COLOR_SOFT_PURPLE).bold(),
    )));
    match (ending, focus) {
        (Some(VetterEnding::Signed), _) => lines.push(Line::from(Span::styled(
            "  Signed and sent. If you learn it was wrong, withdraw it from Issued on the desk.",
            Style::new().fg(COLOR_SUCCESS),
        ))),
        (Some(VetterEnding::Declined), _) => lines.push(Line::from(Span::styled(
            "  You declined this request. Nothing was sent to the community.",
            dim(),
        ))),
        (None, Some(VetterStep::Session)) => {
            lines.push(Line::from(key(
                "o",
                "open a session — when you are together",
            )));
        }
        (None, Some(VetterStep::Code)) => {
            let code = row.and_then(|r| r.match_code.clone()).unwrap_or_default();
            lines.push(Line::from(vec![
                Span::styled("  Read ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled(code, Style::new().fg(COLOR_SUCCESS).bold()),
                Span::styled(
                    " aloud and hear it read back. Their card arrives by itself once they send \
                     it.",
                    Style::new().fg(COLOR_TEXT_DEFAULT),
                ),
            ]));
            lines.push(Line::from(key(
                "o",
                "reopen the session (a new code) if it has lapsed",
            )));
        }
        (None, Some(VetterStep::Check | VetterStep::Sign)) => {
            lines.push(Line::from(key(
                "Enter",
                "check the person against their document, then sign",
            )));
        }
        _ => lines.push(Line::from(Span::styled(
            "  Waiting on the applicant.",
            Style::new().fg(COLOR_ORANGE),
        ))),
    }
    if let Some(row) = row.filter(|r| !r.claims.is_empty()) {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Their card",
            Style::new().fg(COLOR_SOFT_PURPLE).bold(),
        )));
        for (claim, value) in &row.claims {
            lines.push(Line::from(vec![
                Span::styled(format!("  {claim:<16}"), dim()),
                Span::styled(value.clone(), Style::new().fg(COLOR_TEXT_DEFAULT)),
            ]));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        if ending.is_some() {
            "Esc: back to your desk"
        } else {
            "Esc: back to your desk (nothing is lost)   x: decline (a reason is optional)"
        },
        dim(),
    )));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::main_page::content::{ApplicationRow, DeskRow, DeskStage};
    use openvtc_core::vetting::journey::JourneyStep;

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

    fn no_mode(_: &mut Vec<Line<'static>>, _: &VettingState) {}

    fn steps<S: Copy + PartialEq>(all: &[S], current: S) -> Vec<JourneyStep<S>> {
        let at = all.iter().position(|s| *s == current).unwrap();
        all.iter()
            .enumerate()
            .map(|(i, &step)| JourneyStep {
                step,
                state: match i.cmp(&at) {
                    std::cmp::Ordering::Less => StepState::Done,
                    std::cmp::Ordering::Equal => StepState::Current,
                    std::cmp::Ordering::Greater => StepState::Todo,
                },
                detail: None,
            })
            .collect()
    }

    /// The applicant's page shows the whole process, explains the step they
    /// are on, names the one key that takes it, and says how to leave.
    #[test]
    fn the_applicant_page_shows_the_process_and_the_step_to_take() {
        let v = VettingState {
            applications: vec![ApplicationRow {
                id: "a1".into(),
                community: "did:web:kernel".into(),
                community_name: None,
                accent: None,
                pcs_zkp: true,
                next_step: None,
                join_did: "did:key:zA".into(),
                requirements: Some("2 statements".into()),
                progress: None,
                satisfied: false,
                face: None,
                identity: Vec::new(),
                requests: Vec::new(),
                statements: 0,
            }]
            .into(),
            ..VettingState::default()
        };
        let j = JourneyView {
            title: "Applying to kernel as alice".into(),
            pcs_zkp: true,
            steps: JourneySteps::Applicant(steps(&ApplicantStep::ALL, ApplicantStep::Face)),
        };
        let drawn = text(&render(&v, &j, no_mode));
        assert!(drawn.contains("Applying to kernel as alice"), "{drawn}");
        assert!(drawn.contains("PCS ZKP"), "{drawn}");
        assert!(
            drawn.contains("✓ Requirements ─ ● Face ─ ○ Vetters"),
            "{drawn}"
        );
        assert!(drawn.contains("What's happening — Face"), "{drawn}");
        assert!(drawn.contains("choose the face vetters see"), "{drawn}");
        assert!(drawn.contains("Esc: back to your applications"), "{drawn}");
    }

    /// The vetter's page puts the match code in front of them with what to do
    /// with it, and says the card will arrive by itself.
    #[test]
    fn the_vetter_page_puts_the_match_code_in_front_of_them() {
        let v = VettingState {
            desk: vec![DeskRow {
                request_id: "r1".into(),
                applicant: "did:example:applicant".into(),
                applicant_name: None,
                community: "did:example:community".into(),
                pcs_zkp: false,
                state: "session open".into(),
                stage: DeskStage::Session,
                method: Some("in person".into()),
                match_code: Some("PFCD-EQ2G".into()),
                claims: Vec::new(),
                required_claims: Vec::new(),
                message: None,
            }]
            .into(),
            journey_target: Some(
                crate::state_handler::main_page::content::JourneyTarget::Desk("r1".into()),
            ),
            ..VettingState::default()
        };
        let j = JourneyView {
            title: "Vetting someone for kernel".into(),
            pcs_zkp: false,
            steps: JourneySteps::Vetter(steps(&VetterStep::ALL, VetterStep::Code), None),
        };
        let drawn = text(&render(&v, &j, no_mode));
        assert!(drawn.contains("What's happening — Match code"), "{drawn}");
        assert!(drawn.contains("Read PFCD-EQ2G aloud"), "{drawn}");
        assert!(drawn.contains("x: decline"), "{drawn}");
    }
}
