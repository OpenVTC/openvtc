//! Join flow — identity choice (R-B-3 / D1).
//!
//! After the VTC DID is entered, the operator chooses which identity to present:
//! reuse one of the account's existing personas, or mint a fresh, self-contained
//! one (D6). Reusing a persona links the user across those communities, so
//! selecting a reuse option arms a clear linkage warning that must be confirmed
//! before the join proceeds. Mirrors the other join pages' component shape.

use crate::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS,
    COLOR_TEXT_DEFAULT,
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
pub struct IdentityChoice;

impl IdentityChoice {
    pub fn handle_key_event(state: &mut JoinFlow, key: KeyEvent) {
        // Input is locked once a choice has launched the background sequence.
        if state.props.state.processing {
            return;
        }
        let js = &state.props.state;

        // The linkage warning owns input while armed: only confirm / cancel apply.
        if js.reuse_confirm.is_some() {
            match key.code {
                KeyCode::Char('y') | KeyCode::Enter => {
                    let _ = state.action_tx.send(Action::JoinReuseConfirm);
                }
                KeyCode::F(10) => {
                    let _ = state.action_tx.send(Action::Exit);
                }
                _ => {
                    let _ = state.action_tx.send(Action::JoinReuseCancel);
                }
            }
            return;
        }

        let selected = js.identity_selected;
        let mint_row = js.mint_row();
        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            KeyCode::Up => {
                let _ = state
                    .action_tx
                    .send(Action::JoinIdentitySelect(selected.saturating_sub(1)));
            }
            KeyCode::Down => {
                let _ = state
                    .action_tx
                    .send(Action::JoinIdentitySelect((selected + 1).min(mint_row)));
            }
            KeyCode::Enter => {
                let _ = state.action_tx.send(Action::JoinIdentityChoose);
            }
            // How the new persona is presented; meaningful on the mint row only.
            KeyCode::Char('m') if selected == mint_row => {
                let _ = state.action_tx.send(Action::JoinNewPersonaMethodCycle);
            }
            KeyCode::Esc => {
                let _ = state.action_tx.send(Action::JoinCancel);
            }
            _ => {}
        }
    }

    pub fn render(&self, state: &JoinState, frame: &mut Frame<'_>) {
        let [middle, bottom] = Layout::vertical([Min(0), Length(3)]).areas(frame.area());

        frame.render_widget(
            Block::bordered()
                .fg(COLOR_BORDER)
                .padding(Padding::proportional(1))
                .title(" Who should this community know you as? "),
            middle,
        );
        let inner = middle.inner(Margin::new(3, 2));

        // When a reuse is armed, the body is the linkage warning + confirm prompt.
        if let Some(persona_id) = state.reuse_confirm {
            let opt = state.persona_options.iter().find(|o| o.id == persona_id);
            let label = opt.map(|o| o.label.as_str()).unwrap_or("this persona");
            let mut lines = vec![
                Line::styled(
                    "Use a persona this community can already be linked to?",
                    Style::new().fg(COLOR_ORANGE).bold(),
                ),
                Line::default(),
                Line::styled(
                    format!(
                        "Being known here as \"{label}\" makes you the same person to \
                         anyone who sees both this community and the others using it."
                    ),
                    Style::new().fg(COLOR_TEXT_DEFAULT),
                ),
            ];
            if let Some(opt) = opt {
                if opt.linked_communities.is_empty() {
                    lines.push(Line::styled(
                        "No other community knows you by it yet.",
                        Style::new().fg(COLOR_DARK_GRAY),
                    ));
                } else {
                    lines.push(Line::default());
                    lines.push(Line::styled(
                        "Already known to:",
                        Style::new().fg(COLOR_DARK_GRAY),
                    ));
                    for c in &opt.linked_communities {
                        lines.push(Line::styled(
                            format!("  • {c}"),
                            Style::new().fg(COLOR_DARK_GRAY),
                        ));
                    }
                }
            }
            lines.push(Line::default());
            lines.push(Line::from(vec![
                Span::styled("[Y]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(
                    " reuse and continue   ",
                    Style::new().fg(COLOR_TEXT_DEFAULT),
                ),
                Span::styled("[N/ESC]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" go back", Style::new().fg(COLOR_TEXT_DEFAULT)),
            ]));
            frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
            render_bottom(frame, bottom);
            return;
        }

        // Otherwise the body is the selectable list: each persona, then "mint new".
        let mut lines = vec![
            Line::styled(
                "Choose the persona this community will know you as:",
                Style::new().fg(COLOR_BORDER).bold(),
            ),
            Line::default(),
        ];
        for (i, opt) in state.persona_options.iter().enumerate() {
            let selected = i == state.identity_selected;
            let marker = if selected { "▸ " } else { "  " };
            let style = if selected {
                Style::new().fg(COLOR_SUCCESS).bold()
            } else {
                Style::new().fg(COLOR_TEXT_DEFAULT)
            };
            let badge = match opt.valid_vic_count {
                0 => String::new(),
                1 => "  (1 invitation)".to_string(),
                n => format!("  ({n} invitations)"),
            };
            lines.push(Line::from(Span::styled(
                format!("{marker}{}{badge}", opt.label),
                style,
            )));
            let detail = if opt.linked_communities.is_empty() {
                format!("    {}", opt.did)
            } else {
                format!(
                    "    {}  ·  known to {} communit{}",
                    opt.did,
                    opt.linked_communities.len(),
                    if opt.linked_communities.len() == 1 {
                        "y"
                    } else {
                        "ies"
                    }
                )
            };
            lines.push(Line::styled(detail, Style::new().fg(COLOR_DARK_GRAY)));
        }
        // The trailing "mint new" row.
        let mint_selected = state.mint_row_selected();
        let marker = if mint_selected { "▸ " } else { "  " };
        let style = if mint_selected {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            Style::new().fg(COLOR_SOFT_PURPLE)
        };
        lines.push(Line::from(Span::styled(
            format!("{marker}✦ Be someone new to this community"),
            style,
        )));
        lines.push(Line::styled(
            "    A fresh persona DID — nothing links it to your other communities",
            Style::new().fg(COLOR_DARK_GRAY),
        ));
        let presented = match state.new_persona_did_method {
            None => "your account's default".to_string(),
            Some(method) => format!("did:{method}"),
        };
        lines.push(Line::styled(
            format!("    Presented as {presented}  [m] change"),
            Style::new().fg(COLOR_DARK_GRAY),
        ));
        lines.push(Line::default());
        lines.push(Line::from(vec![
            Span::styled("[↑/↓]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" select   ", Style::new().fg(COLOR_TEXT_DEFAULT)),
            Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" choose   ", Style::new().fg(COLOR_TEXT_DEFAULT)),
            Span::styled("[ESC]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" cancel", Style::new().fg(COLOR_TEXT_DEFAULT)),
        ]));

        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
        render_bottom(frame, bottom);
    }
}

fn render_bottom(frame: &mut Frame, area: ratatui::layout::Rect) {
    let bottom_line = Line::from(vec![
        Span::styled("[F10]", Style::new().fg(COLOR_BORDER).bold()),
        Span::styled(" to quit", Style::new().fg(COLOR_TEXT_DEFAULT)),
    ]);
    frame.render_widget(
        Paragraph::new(bottom_line).block(Block::new().padding(Padding::new(2, 0, 1, 0))),
        area,
    );
}

#[cfg(test)]
mod tests {
    //! Key-routing tests for the identity-choice page (R-B-3). `Action` derives
    //! neither `PartialEq` nor `Debug`, so assertions pattern-match the variant.
    use super::*;
    use crate::state_handler::{
        join::{JoinPage, JoinState, PersonaOption},
        state::State,
    };
    use crate::ui::component::Component;
    use crossterm::event::KeyModifiers;
    use openvtc_core::config::account::PersonaId;
    use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

    fn flow_with(mutate: impl FnOnce(&mut JoinState)) -> (JoinFlow, UnboundedReceiver<Action>) {
        let (tx, rx) = unbounded_channel();
        let mut state = State::default();
        state.join.page = JoinPage::IdentityChoice;
        state.join.persona_options = vec![
            PersonaOption {
                id: PersonaId::new(),
                label: "alice".to_string(),
                did: "did:webvh:a".to_string(),
                linked_communities: Vec::new(),
                valid_vic_count: 0,
            },
            PersonaOption {
                id: PersonaId::new(),
                label: "bob".to_string(),
                did: "did:webvh:b".to_string(),
                linked_communities: Vec::new(),
                valid_vic_count: 0,
            },
        ];
        mutate(&mut state.join);
        (JoinFlow::new(&state, tx), rx)
    }

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn down_moves_selection_down() {
        let (mut flow, mut rx) = flow_with(|_| {});
        IdentityChoice::handle_key_event(&mut flow, press(KeyCode::Down));
        match rx.try_recv() {
            Ok(Action::JoinIdentitySelect(1)) => {}
            _ => panic!("expected JoinIdentitySelect(1)"),
        }
    }

    #[test]
    fn m_on_the_mint_row_changes_how_the_new_persona_is_presented() {
        let (mut flow, mut rx) = flow_with(|js| js.identity_selected = js.mint_row());
        IdentityChoice::handle_key_event(&mut flow, press(KeyCode::Char('m')));
        assert!(matches!(rx.try_recv(), Ok(Action::JoinNewPersonaMethodCycle)));

        // On a reuse row it is not a choice that applies.
        let (mut flow, mut rx) = flow_with(|js| js.identity_selected = 0);
        IdentityChoice::handle_key_event(&mut flow, press(KeyCode::Char('m')));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn enter_chooses_the_highlight() {
        let (mut flow, mut rx) = flow_with(|_| {});
        IdentityChoice::handle_key_event(&mut flow, press(KeyCode::Enter));
        match rx.try_recv() {
            Ok(Action::JoinIdentityChoose) => {}
            _ => panic!("expected JoinIdentityChoose"),
        }
    }

    #[test]
    fn esc_cancels_the_flow() {
        let (mut flow, mut rx) = flow_with(|_| {});
        IdentityChoice::handle_key_event(&mut flow, press(KeyCode::Esc));
        match rx.try_recv() {
            Ok(Action::JoinCancel) => {}
            _ => panic!("expected JoinCancel"),
        }
    }

    #[test]
    fn armed_warning_confirms_and_cancels() {
        // y confirms the reuse.
        let (mut flow, mut rx) = flow_with(|js| {
            let pid = js.persona_options[0].id;
            js.reuse_confirm = Some(pid);
        });
        IdentityChoice::handle_key_event(&mut flow, press(KeyCode::Char('y')));
        match rx.try_recv() {
            Ok(Action::JoinReuseConfirm) => {}
            _ => panic!("expected JoinReuseConfirm"),
        }

        // Any other key (here Esc) backs out of the warning.
        let (mut flow, mut rx) = flow_with(|js| {
            let pid = js.persona_options[0].id;
            js.reuse_confirm = Some(pid);
        });
        IdentityChoice::handle_key_event(&mut flow, press(KeyCode::Esc));
        match rx.try_recv() {
            Ok(Action::JoinReuseCancel) => {}
            _ => panic!("expected JoinReuseCancel"),
        }
    }
}
