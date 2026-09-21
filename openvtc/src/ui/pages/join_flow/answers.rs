//! Join flow — what the community asks you to tell it about yourself.
//!
//! Shown when a community's manifest carries `requestedAttributes`. The page
//! lists what it asks and why, lets the person pick which of their faces
//! answers, and shows exactly what that face would send — before anything is.
//! Enter approves those values; the join then sends them through a disclosure,
//! so the person's own history records what they told the community.
//!
//! The answers are the person's own statement. The page says so, because a
//! community asking for a name is not a community verifying one.

use crate::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_SUCCESS, COLOR_TEXT_DEFAULT, COLOR_WARNING_ACCESSIBLE_RED,
};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::{
        Constraint::{Length, Min},
        Layout, Margin,
    },
    style::{Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Padding, Paragraph, Wrap},
};

use crate::{
    state_handler::{actions::Action, join::JoinState},
    ui::pages::join_flow::JoinFlow,
};

#[derive(Clone, Debug, Default)]
pub struct AnswersPage;

impl AnswersPage {
    pub fn handle_key_event(state: &mut JoinFlow, key: KeyEvent) {
        if state.props.state.processing {
            return;
        }
        let Some(answers) = state.props.state.answers.as_ref() else {
            return;
        };
        let selected = answers.selected;
        let last = answers.faces.len().saturating_sub(1);
        let action = match key.code {
            KeyCode::F(10) => Action::Exit,
            KeyCode::Up => Action::JoinAnswersSelect(selected.saturating_sub(1)),
            KeyCode::Down => Action::JoinAnswersSelect((selected + 1).min(last)),
            KeyCode::Enter => Action::JoinAnswersChoose,
            KeyCode::Esc => Action::JoinCancel,
            _ => return,
        };
        let _ = state.action_tx.send(action);
    }

    pub fn render(&self, state: &JoinState, frame: &mut Frame<'_>) {
        let [middle, bottom] = Layout::vertical([Min(0), Length(3)]).areas(frame.area());
        frame.render_widget(
            Block::bordered()
                .fg(COLOR_BORDER)
                .padding(Padding::proportional(1))
                .title(" The community asks about you "),
            middle,
        );
        let inner = middle.inner(Margin::new(3, 2));
        let lines = match state.answers.as_ref() {
            Some(answers) => lines(answers),
            None => vec![Line::styled(
                "Nothing is asked.",
                Style::new().fg(COLOR_DARK_GRAY),
            )],
        };
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
        frame.render_widget(
            Paragraph::new(Line::styled(
                "↑/↓ choose a face   Enter send these answers and join   Esc cancel",
                Style::new().fg(COLOR_DARK_GRAY),
            ))
            .block(Block::bordered().fg(COLOR_BORDER)),
            bottom,
        );
    }
}

/// The page body. Separate from `render` so it is testable as text.
pub(crate) fn lines(answers: &crate::state_handler::join::JoinAnswers) -> Vec<Line<'static>> {
    let mut out = vec![
        Line::styled(
            "What you tell them is your own statement — they see it as that, not as verified.",
            Style::new().fg(COLOR_DARK_GRAY),
        ),
        Line::default(),
    ];
    for a in &answers.asked {
        let kind = if a.required { "required" } else { "optional" };
        let mut spans = vec![
            Span::styled(
                format!("  {}", a.claim_type),
                Style::new().fg(COLOR_TEXT_DEFAULT).bold(),
            ),
            Span::styled(format!(" ({kind})"), Style::new().fg(COLOR_DARK_GRAY)),
        ];
        if let Some(p) = &a.purpose {
            spans.push(Span::styled(
                format!(" — {p}"),
                Style::new().fg(COLOR_DARK_GRAY),
            ));
        }
        out.push(Line::from(spans));
    }
    out.push(Line::default());
    out.push(Line::styled(
        "Answer with:",
        Style::new().fg(COLOR_BORDER).bold(),
    ));
    if answers.faces.is_empty() {
        out.push(Line::styled(
            "  You have no faces yet. Make one under Identity, then join again.",
            Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
        ));
    }
    for (i, (_, name)) in answers.faces.iter().enumerate() {
        let selected = i == answers.selected;
        let (marker, style) = if selected {
            ("▸ ", Style::new().fg(COLOR_SUCCESS).bold())
        } else {
            ("  ", Style::new().fg(COLOR_TEXT_DEFAULT))
        };
        out.push(Line::styled(format!("{marker}{name}"), style));
    }
    if !answers.faces.is_empty() {
        out.push(Line::default());
        out.push(Line::styled(
            "This face would send:",
            Style::new().fg(COLOR_BORDER).bold(),
        ));
        for (claim_type, value) in &answers.shown {
            let (text, style) = match value {
                Some(v) => (
                    format!("  {claim_type}: {}", display(v)),
                    Style::new().fg(COLOR_TEXT_DEFAULT),
                ),
                None => (
                    format!("  {claim_type}: — this face does not show it"),
                    Style::new().fg(COLOR_DARK_GRAY),
                ),
            };
            out.push(Line::styled(text, style));
        }
        let missing = answers.unanswered();
        if !missing.is_empty() {
            out.push(Line::styled(
                format!(
                    "  Required and not shown: {}. Pick another face, or add it under Identity.",
                    missing.join(", ")
                ),
                Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
            ));
        }
    }
    if let Some(e) = &answers.error {
        out.push(Line::default());
        out.push(Line::styled(
            e.clone(),
            Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
        ));
    }
    out
}

/// A value as a person reads it: strings bare, anything else as JSON.
fn display(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => crate::state_handler::main_page::sanitize_display(s, 80),
        other => crate::state_handler::main_page::sanitize_display(&other.to_string(), 80),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::join::JoinAnswers;
    use openvtc_core::persona::join_answers::Asked;
    use serde_json::json;

    fn text(answers: &JoinAnswers) -> String {
        lines(answers)
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

    fn page(shown: Vec<(&str, Option<serde_json::Value>)>) -> JoinAnswers {
        JoinAnswers {
            asked: vec![
                Asked {
                    claim_type: "name.display".into(),
                    required: true,
                    purpose: Some("So members know what to call you".into()),
                },
                Asked {
                    claim_type: "address.country".into(),
                    required: false,
                    purpose: None,
                },
            ],
            faces: vec![("p1".into(), "Work".into()), ("p2".into(), "Play".into())],
            selected: 1,
            shown: shown.into_iter().map(|(t, v)| (t.to_string(), v)).collect(),
            ..JoinAnswers::default()
        }
    }

    #[test]
    fn the_page_says_what_is_asked_why_and_exactly_what_would_leave() {
        let t = text(&page(vec![
            ("name.display", Some(json!("Ada"))),
            ("address.country", None),
        ]));
        assert!(
            t.contains("name.display (required) — So members know what to call you"),
            "{t}"
        );
        assert!(t.contains("▸ Play"), "the highlighted face is marked: {t}");
        assert!(t.contains("name.display: Ada"), "{t}");
        assert!(
            t.contains("address.country: — this face does not show it"),
            "{t}"
        );
        assert!(
            t.contains("not as verified"),
            "the answers are said to be self-asserted: {t}"
        );
        assert!(!t.contains("Required and not shown"), "{t}");
    }

    #[test]
    fn a_face_missing_a_required_answer_says_so_before_enter() {
        let t = text(&page(vec![
            ("name.display", None),
            ("address.country", Some(json!("SG"))),
        ]));
        assert!(t.contains("Required and not shown: name.display"), "{t}");
    }
}
