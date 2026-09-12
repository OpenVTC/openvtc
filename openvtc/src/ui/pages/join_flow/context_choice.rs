//! Join flow — where the community lives at the VTA.
//!
//! A context keeps its keys, faces and access grants apart from every other
//! context. The default is a new sub-context for this community alone; the
//! person may instead share a context they already use, or use the account's
//! top context. The new sub-context's name is typed in place on its row.

use crate::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
    COLOR_WARNING_ACCESSIBLE_RED,
};
use crossterm::event::{KeyCode, KeyEvent};
use openvtc_core::config::community_context::{ContextKind, ContextOption};
use openvtc_core::config::context_path::parse_sub_context_id;
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
    state_handler::{
        actions::Action,
        join::{IdentityPick, JoinState},
        setup_sequence::MessageType,
    },
    ui::pages::join_flow::JoinFlow,
};

#[derive(Clone, Debug, Default)]
pub struct ContextChoice;

impl ContextChoice {
    pub fn handle_key_event(state: &mut JoinFlow, key: KeyEvent) {
        if state.props.state.processing {
            return;
        }
        let js = &state.props.state;
        let selected = js.context_selected;
        let last = js.context_options.len().saturating_sub(1);
        let action = match key.code {
            KeyCode::F(10) => Action::Exit,
            KeyCode::Up => Action::JoinContextSelect(selected.saturating_sub(1)),
            KeyCode::Down => Action::JoinContextSelect((selected + 1).min(last)),
            KeyCode::Enter => Action::JoinContextChoose,
            KeyCode::Esc => Action::JoinCancel,
            KeyCode::Char(c) if js.new_context_selected() => {
                let mut slug = js.context_slug.clone();
                slug.push(c);
                Action::JoinContextSlug(slug)
            }
            KeyCode::Backspace if js.new_context_selected() => {
                let mut slug = js.context_slug.clone();
                slug.pop();
                Action::JoinContextSlug(slug)
            }
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
                .title(" Where should this community live? "),
            middle,
        );
        let inner = middle.inner(Margin::new(3, 2));

        let minting = state.picked_identity == Some(IdentityPick::Mint);
        let mut lines = vec![
            Line::styled(
                "Your VTA keeps each context's keys, faces and access apart.",
                Style::new().fg(COLOR_BORDER).bold(),
            ),
            Line::styled(
                "A community in a context of its own shares none of them with your other communities.",
                Style::new().fg(COLOR_DARK_GRAY),
            ),
            Line::default(),
        ];
        for (i, option) in state.context_options.iter().enumerate() {
            let selected = i == state.context_selected;
            let marker = if selected { "▸ " } else { "  " };
            let style = if selected {
                Style::new().fg(COLOR_SUCCESS).bold()
            } else if option.kind == ContextKind::New {
                Style::new().fg(COLOR_SOFT_PURPLE)
            } else {
                Style::new().fg(COLOR_TEXT_DEFAULT)
            };
            let (title, detail) = describe(state, option, minting);
            let mut spans = vec![Span::styled(format!("{marker}{title}"), style)];
            if selected && option.kind == ContextKind::New {
                spans.push(Span::styled("▎", Style::new().fg(COLOR_SUCCESS)));
            }
            lines.push(Line::from(spans));
            lines.push(Line::styled(
                format!("    {detail}"),
                Style::new().fg(COLOR_DARK_GRAY),
            ));
        }
        for message in &state.messages {
            if let MessageType::Error(text) = message {
                lines.push(Line::default());
                lines.push(Line::styled(
                    text.clone(),
                    Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
                ));
            }
        }
        lines.push(Line::default());
        lines.push(Line::from(vec![
            Span::styled("[↑/↓]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" select   ", Style::new().fg(COLOR_TEXT_DEFAULT)),
            Span::styled("[type]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(
                " name the new context   ",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ),
            Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" join   ", Style::new().fg(COLOR_TEXT_DEFAULT)),
            Span::styled("[ESC]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" cancel", Style::new().fg(COLOR_TEXT_DEFAULT)),
        ]));
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);

        let bottom_line = Line::from(vec![
            Span::styled("[F10]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" to quit", Style::new().fg(COLOR_TEXT_DEFAULT)),
        ]);
        frame.render_widget(
            Paragraph::new(bottom_line).block(Block::new().padding(Padding::new(2, 0, 1, 0))),
            bottom,
        );
    }
}

/// A row's title and the line beneath it.
fn describe(state: &JoinState, option: &ContextOption, minting: bool) -> (String, String) {
    match option.kind {
        ContextKind::New => {
            let parent = parse_sub_context_id(&option.context_id)
                .map_or(option.context_id.as_str(), |(parent, _)| parent);
            (
                format!("✦ A context of its own   {parent}/{}", state.context_slug),
                if minting {
                    "A new persona is made here — nothing is shared with your other communities"
                        .to_string()
                } else {
                    "This community's faces are kept here; the persona's keys stay where they are"
                        .to_string()
                },
            )
        }
        ContextKind::Existing => {
            let detail = if option.holds_persona_keys {
                "This persona's keys live here, so the community joins this context".to_string()
            } else if option.communities.is_empty() {
                "In use, with no communities yet".to_string()
            } else {
                let names: Vec<&str> = option
                    .communities
                    .iter()
                    .map(|did| state.community_name(did))
                    .collect();
                format!("Shared with {}", names.join(", "))
            };
            (option.context_id.clone(), detail)
        }
        ContextKind::Top => (
            format!("{} (your account's top context)", option.context_id),
            "Nothing is kept apart from your other communities".to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::{join::JoinPage, state::State};
    use crate::ui::component::Component;
    use crossterm::event::KeyModifiers;
    use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

    fn flow(selected: usize) -> (JoinFlow, UnboundedReceiver<Action>) {
        let (tx, rx) = unbounded_channel();
        let mut state = State::default();
        state.join.page = JoinPage::ContextChoice;
        state.join.picked_identity = Some(IdentityPick::Mint);
        state.join.context_slug = "kerne".to_string();
        state.join.context_options = vec![
            ContextOption {
                context_id: "openvtc/kernel".into(),
                kind: ContextKind::New,
                communities: vec![],
                holds_persona_keys: false,
            },
            ContextOption {
                context_id: "openvtc".into(),
                kind: ContextKind::Top,
                communities: vec![],
                holds_persona_keys: false,
            },
        ];
        state.join.context_selected = selected;
        (JoinFlow::new(&state, tx), rx)
    }

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn typing_on_the_new_row_names_the_context() {
        let (mut flow, mut rx) = flow(0);
        ContextChoice::handle_key_event(&mut flow, press(KeyCode::Char('l')));
        assert!(matches!(rx.try_recv(), Ok(Action::JoinContextSlug(s)) if s == "kernel"));
    }

    #[test]
    fn typing_elsewhere_does_nothing_and_enter_joins() {
        let (mut flow, mut rx) = flow(1);
        ContextChoice::handle_key_event(&mut flow, press(KeyCode::Char('x')));
        assert!(rx.try_recv().is_err());
        ContextChoice::handle_key_event(&mut flow, press(KeyCode::Enter));
        assert!(matches!(rx.try_recv(), Ok(Action::JoinContextChoose)));
        ContextChoice::handle_key_event(&mut flow, press(KeyCode::Up));
        assert!(matches!(rx.try_recv(), Ok(Action::JoinContextSelect(0))));
    }
}
