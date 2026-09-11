//! Join flow — what a vetting community asks of the people who join.
//!
//! Shown after the community's DID when that community vets its members
//! (`docs/design/vetting-process.md` §6.1, §12.3). It says in plain words what
//! the community requires before anything about the applicant is sent. It
//! shows this persona's application if there is one, and offers the ways on:
//! apply (or continue), join anyway, or cancel.
//!
//! While the community is still being asked, this page is drawn by the runtime
//! loop rather than the join flow, because that loop is the one that hears the
//! answer. So only the two keys that loop handles are offered then: join
//! without waiting, and cancel.

use crate::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS,
    COLOR_TEXT_DEFAULT, COLOR_WARNING_ACCESSIBLE_RED,
};
use crossterm::event::{KeyCode, KeyEvent};
use openvtc_core::config::community_context::ContextOption;
use openvtc_core::display::display_identifier;
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

use crate::state_handler::{
    actions::Action,
    join::{JoinState, JoinVettingView, VettingPhase},
    setup_sequence::MessageType,
};
use crate::ui::pages::join_flow::JoinFlow;
use crate::ui::pages::main::components::vetting_panel::accent_swatch;

#[derive(Clone, Debug, Default)]
pub struct VettingPage;

impl VettingPage {
    pub fn handle_key_event(state: &mut JoinFlow, key: KeyEvent) {
        if state.props.state.processing {
            return;
        }
        let Some(view) = &state.props.state.vetting else {
            if key.code == KeyCode::Esc {
                let _ = state.action_tx.send(Action::JoinCancel);
            }
            return;
        };
        let satisfied = matches!(
            &view.phase,
            VettingPhase::Known(known) if known.application.as_ref().is_some_and(|a| a.satisfied)
        );
        let action = match (&view.phase, key.code) {
            (_, KeyCode::F(10)) => Action::Exit,
            (_, KeyCode::Esc) => Action::JoinCancel,
            (_, KeyCode::Char('j' | 'J')) => Action::JoinVettingJoin,
            (VettingPhase::Unknown { .. }, KeyCode::Enter | KeyCode::Char('r' | 'R')) => {
                Action::JoinVettingAskAgain
            }
            (VettingPhase::Known(_), KeyCode::Enter) if satisfied => Action::JoinVettingJoin,
            (VettingPhase::Known(_), KeyCode::Enter | KeyCode::Char('a' | 'A')) => {
                Action::JoinVettingApply
            }
            (VettingPhase::Known(_), KeyCode::Up | KeyCode::BackTab) => {
                Action::JoinVettingField(false)
            }
            (VettingPhase::Known(_), KeyCode::Down | KeyCode::Tab) => {
                Action::JoinVettingField(true)
            }
            (VettingPhase::Known(_), KeyCode::Left) => Action::JoinVettingCycle(false),
            (VettingPhase::Known(_), KeyCode::Right) => Action::JoinVettingCycle(true),
            _ => return,
        };
        let _ = state.action_tx.send(action);
    }

    pub fn render(&self, state: &JoinState, frame: &mut Frame<'_>) {
        let [middle, bottom] = Layout::vertical([Min(0), Length(3)]).areas(frame.area());
        let Some(view) = &state.vetting else {
            return;
        };
        frame.render_widget(
            Block::bordered()
                .fg(COLOR_BORDER)
                .padding(Padding::proportional(1))
                .title(format!(" Joining {} ", view.name)),
            middle,
        );
        let inner = middle.inner(Margin::new(3, 2));
        frame.render_widget(
            Paragraph::new(body_lines(state, view)).wrap(Wrap { trim: false }),
            inner,
        );
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("[F10]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" to quit", Style::new().fg(COLOR_TEXT_DEFAULT)),
            ]))
            .block(Block::new().padding(Padding::new(2, 0, 1, 0))),
            bottom,
        );
    }
}

fn text() -> Style {
    Style::new().fg(COLOR_TEXT_DEFAULT)
}

fn dim() -> Style {
    Style::new().fg(COLOR_DARK_GRAY)
}

fn keys(pairs: &[(&str, &str)]) -> Line<'static> {
    let mut spans = Vec::new();
    for (key, what) in pairs {
        spans.push(Span::styled(
            format!("[{key}]"),
            Style::new().fg(COLOR_BORDER).bold(),
        ));
        spans.push(Span::styled(format!(" {what}   "), text()));
    }
    Line::from(spans)
}

fn choice(name: &str, shown: String, focused: bool) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            if focused { "▸ " } else { "  " },
            Style::new().fg(COLOR_SUCCESS).bold(),
        ),
        Span::styled(format!("{name:<10}"), text()),
        Span::styled(shown, Style::new().fg(COLOR_SOFT_PURPLE)),
        Span::styled(if focused { "  ←/→" } else { "" }, dim()),
    ])
}

/// The page's lines, below its border.
pub(crate) fn body_lines(state: &JoinState, view: &JoinVettingView) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    match &view.phase {
        VettingPhase::Asking => {
            lines.push(Line::from(vec![
                accent_swatch(view.accent),
                Span::styled(
                    format!("Asking {} what it requires before you join…", view.name),
                    Style::new().fg(COLOR_ORANGE).bold(),
                ),
            ]));
            lines.push(Line::default());
            lines.push(Line::styled(
                "This takes a few seconds and gives up after 15. The question comes from your \
                 active persona; nothing else about you is sent.",
                dim(),
            ));
            lines.push(Line::default());
            lines.push(keys(&[("J", "join without waiting"), ("ESC", "cancel")]));
        }
        VettingPhase::Unknown { reason } => {
            lines.push(Line::from(vec![
                accent_swatch(view.accent),
                Span::styled(
                    format!(
                        "Could not learn whether {} vets the people who join — {reason}.",
                        view.name
                    ),
                    Style::new().fg(COLOR_ORANGE),
                ),
            ]));
            lines.push(Line::default());
            lines.push(Line::styled(
                "If it does, a request that arrives without vetting statements goes to its \
                 moderators to decide.",
                dim(),
            ));
            lines.push(Line::default());
            lines.push(keys(&[
                ("ENTER/R", "ask again"),
                ("J", "join anyway"),
                ("ESC", "cancel"),
            ]));
        }
        VettingPhase::Known(known) => {
            lines.push(Line::from(vec![
                accent_swatch(view.accent),
                Span::styled(view.name.clone(), text().bold()),
                Span::styled(" vets the people who join.", text()),
            ]));
            lines.push(Line::default());
            lines.push(Line::styled(
                "Before it admits you, it asks for:",
                Style::new().fg(COLOR_BORDER).bold(),
            ));
            for requirement in &known.requirements {
                lines.push(Line::styled(
                    format!("  • {requirement}"),
                    Style::new().fg(COLOR_SOFT_PURPLE),
                ));
            }
            lines.push(Line::default());
            lines.push(Line::styled(
                format!(
                    "Nothing about you has been sent to {}. Each vetter sees the card you show \
                     them; the community sees only their statements.",
                    view.name
                ),
                dim(),
            ));
            if let Some(url) = &known.governance_url {
                lines.push(Line::styled(format!("How it decides: {url}"), dim()));
            }
            lines.push(Line::default());
            match &known.application {
                Some(app) => {
                    lines.push(Line::styled(
                        format!("Your application, as {}", app.persona_label),
                        Style::new().fg(COLOR_SUCCESS).bold(),
                    ));
                    lines.push(Line::styled(
                        format!(
                            "  {} statement{} held{}",
                            app.statements,
                            if app.statements == 1 { "" } else { "s" },
                            app.progress
                                .as_ref()
                                .map(|p| format!(" — {p}"))
                                .unwrap_or_default()
                        ),
                        text(),
                    ));
                    lines.push(Line::from(vec![
                        Span::styled("  Next: ", text()),
                        Span::styled(app.next_step.clone(), Style::new().fg(COLOR_SUCCESS).bold()),
                    ]));
                    lines.push(Line::default());
                    if app.satisfied {
                        lines.push(Line::styled(
                            format!(
                                "Joining now presents your {} vetting statement{} to {}.",
                                app.statements,
                                if app.statements == 1 { "" } else { "s" },
                                view.name
                            ),
                            Style::new().fg(COLOR_SUCCESS),
                        ));
                        lines.push(Line::default());
                        lines.push(keys(&[
                            ("ENTER", "join and present your statements"),
                            ("A", "open the application"),
                            ("ESC", "cancel"),
                        ]));
                    } else {
                        lines.push(keys(&[
                            ("ENTER", "continue on the Vetting page"),
                            (
                                "J",
                                "join anyway — the community refers the request to its moderators",
                            ),
                            ("ESC", "cancel"),
                        ]));
                    }
                }
                None => {
                    lines.push(Line::styled(
                        "Start an application",
                        Style::new().fg(COLOR_BORDER).bold(),
                    ));
                    let persona = known.personas.get(known.persona_index).map_or_else(
                        || "no persona yet — create one under My Identity".to_string(),
                        |p| format!("{}  ({})", p.label, p.did),
                    );
                    lines.push(choice("Apply as", persona, known.field == 0));
                    let context = known
                        .context_options
                        .get(known.context_index)
                        .map_or_else(|| "—".to_string(), ContextOption::summary);
                    lines.push(choice("Context", context, known.field == 1));
                    lines.push(Line::styled(
                        "The persona is fixed for the whole application: every card is signed by \
                         it, and it is the DID the community admits.",
                        dim(),
                    ));
                    lines.push(Line::default());
                    lines.push(keys(&[
                        ("ENTER", "start the application"),
                        ("↑/↓", "field"),
                        ("J", "join anyway — the community refers the request"),
                        ("ESC", "cancel"),
                    ]));
                }
            }
        }
    }
    // The DID under the name, so the community being joined is never only a
    // name it gave itself.
    if !lines.is_empty() {
        lines.insert(
            1,
            Line::styled(
                display_identifier(None, &view.community, 96).into_owned(),
                dim(),
            ),
        );
    }
    for message in &state.messages {
        if let MessageType::Error(error) = message {
            lines.push(Line::default());
            lines.push(Line::styled(
                error.clone(),
                Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
            ));
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::join::{JoinApplication, JoinPage, KnownVetting};
    use crate::state_handler::state::State;
    use crate::ui::component::Component;
    use crossterm::event::KeyModifiers;
    use openvtc_core::config::account::PersonaId;
    use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

    fn view(phase: VettingPhase) -> JoinVettingView {
        JoinVettingView {
            community: "did:web:kernel".into(),
            name: "Kernel".into(),
            accent: Some((0x33, 0x66, 0x99)),
            phase,
        }
    }

    fn known(satisfied: Option<bool>) -> VettingPhase {
        VettingPhase::Known(Box::new(KnownVetting {
            requirements: vec!["2 vetting statements".into()],
            application: satisfied.map(|satisfied| JoinApplication {
                id: "a1".into(),
                persona: PersonaId::new(),
                persona_label: "alice".into(),
                statements: 2,
                progress: None,
                next_step: "join".into(),
                satisfied,
            }),
            ..KnownVetting::default()
        }))
    }

    fn flow(phase: VettingPhase) -> (JoinFlow, UnboundedReceiver<Action>) {
        let (tx, rx) = unbounded_channel();
        let mut state = State::default();
        state.join.page = JoinPage::Vetting;
        state.join.vetting = Some(view(phase));
        (JoinFlow::new(&state, tx), rx)
    }

    fn press(flow: &mut JoinFlow, code: KeyCode) {
        VettingPage::handle_key_event(flow, KeyEvent::new(code, KeyModifiers::NONE));
    }

    #[test]
    fn enter_starts_an_application_or_joins_one_that_is_ready() {
        let (mut f, mut rx) = flow(known(None));
        press(&mut f, KeyCode::Enter);
        assert!(matches!(rx.try_recv(), Ok(Action::JoinVettingApply)));
        press(&mut f, KeyCode::Right);
        assert!(matches!(rx.try_recv(), Ok(Action::JoinVettingCycle(true))));
        press(&mut f, KeyCode::Char('j'));
        assert!(matches!(rx.try_recv(), Ok(Action::JoinVettingJoin)));

        let (mut f, mut rx) = flow(known(Some(true)));
        press(&mut f, KeyCode::Enter);
        assert!(matches!(rx.try_recv(), Ok(Action::JoinVettingJoin)));
        press(&mut f, KeyCode::Char('a'));
        assert!(matches!(rx.try_recv(), Ok(Action::JoinVettingApply)));
    }

    #[test]
    fn while_asking_or_unknown_only_the_ways_on_are_offered() {
        let (mut f, mut rx) = flow(VettingPhase::Asking);
        press(&mut f, KeyCode::Enter);
        assert!(rx.try_recv().is_err(), "nothing to confirm while asking");
        press(&mut f, KeyCode::Char('j'));
        assert!(matches!(rx.try_recv(), Ok(Action::JoinVettingJoin)));
        press(&mut f, KeyCode::Esc);
        assert!(matches!(rx.try_recv(), Ok(Action::JoinCancel)));

        let (mut f, mut rx) = flow(VettingPhase::Unknown {
            reason: "no answer".into(),
        });
        press(&mut f, KeyCode::Char('r'));
        assert!(matches!(rx.try_recv(), Ok(Action::JoinVettingAskAgain)));
    }

    fn text_of(lines: &[Line<'_>]) -> String {
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
    fn the_page_says_what_is_required_and_that_statements_go_with_the_join() {
        let state = JoinState::default();
        let lines = body_lines(&state, &view(known(Some(true))));
        let shown = text_of(&lines);
        assert!(shown.contains("Kernel vets the people who join."));
        assert!(shown.contains("• 2 vetting statements"));
        assert!(shown.contains("Joining now presents your 2 vetting statements to Kernel."));
        assert!(shown.contains("Nothing about you has been sent"));

        let lines = body_lines(&state, &view(known(Some(false))));
        assert!(text_of(&lines).contains("refers the request to its moderators"));
    }
}
