//! The "create a new persona DID" overlay — its keys and its rendering.
//!
//! Lifted off the main page so the join flow can host the same overlay. A join
//! that needs a persona used to say "create one under My Identity", which meant
//! leaving the flow, finding the right pane, and coming back to start the join
//! again — and the community DID had to be entered a second time. The overlay
//! floats over whichever page opened it; nothing about it is page-specific, and
//! the phases, the keys and the wording must not fork between the two callers.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::Layout,
    text::{Line, Span},
    widgets::Paragraph,
};
use tokio::sync::mpsc::UnboundedSender;

use crate::colors::{
    COLOR_BORDER, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
    COLOR_WARNING_ACCESSIBLE_RED,
};

use crate::state_handler::actions::Action;
use crate::state_handler::main_page::content::CreatePersonaState;

pub fn handle_key(
    overlay: &CreatePersonaState,
    key: KeyEvent,
    action_tx: &UnboundedSender<Action>,
) {
    use crate::state_handler::main_page::content::CreatePersonaPhase;
    match overlay.phase {
        CreatePersonaPhase::Label => match key.code {
            KeyCode::Enter => {
                let _ = action_tx.send(Action::CreatePersonaSubmit);
            }
            KeyCode::Esc => {
                let _ = action_tx.send(Action::CreatePersonaClose);
            }
            _ => {
                let _ = action_tx.send(Action::CreatePersonaInput(key));
            }
        },
        CreatePersonaPhase::Path => {
            use crate::state_handler::main_page::content::PersonaPathChoice;
            let action = match key.code {
                KeyCode::Up => Action::CreatePersonaPathChoice(PersonaPathChoice::Auto),
                KeyCode::Down => Action::CreatePersonaPathChoice(PersonaPathChoice::Custom),
                KeyCode::Enter => Action::CreatePersonaSubmit,
                KeyCode::Esc => Action::CreatePersonaBack,
                // Everything else edits the path, which is also how the
                // typed row gets chosen — see `CreatePersonaPathInput`.
                _ => Action::CreatePersonaPathInput(key),
            };
            let _ = action_tx.send(action);
        }
        CreatePersonaPhase::Context => {
            let selected = overlay.context_selected;
            let last = overlay.context_options.len().saturating_sub(1);
            let new_row = overlay.context_options.get(selected).is_some_and(|o| {
                o.kind == openvtc_core::config::community_context::ContextKind::New
            });
            let action = match key.code {
                KeyCode::Up => Action::CreatePersonaContextSelect(selected.saturating_sub(1)),
                KeyCode::Down => Action::CreatePersonaContextSelect((selected + 1).min(last)),
                KeyCode::Enter => Action::CreatePersonaSubmit,
                KeyCode::Esc => Action::CreatePersonaBack,
                KeyCode::Char(c) if new_row => {
                    Action::CreatePersonaContextSlug(format!("{}{c}", overlay.context_slug))
                }
                KeyCode::Backspace if new_row => {
                    let mut slug = overlay.context_slug.clone();
                    slug.pop();
                    Action::CreatePersonaContextSlug(slug)
                }
                _ => return,
            };
            let _ = action_tx.send(action);
        }
        // Mint in progress: lock input (no cancel — the sequence is short and
        // persists atomically).
        CreatePersonaPhase::Working => {}
        CreatePersonaPhase::Done => match key.code {
            KeyCode::Char('c') => {
                let _ = action_tx.send(Action::CreatePersonaCopy);
            }
            _ => {
                let _ = action_tx.send(Action::CreatePersonaClose);
            }
        },
        CreatePersonaPhase::Failed => {
            let _ = action_tx.send(Action::CreatePersonaClose);
        }
    }
}

pub fn render(frame: &mut Frame, overlay: &CreatePersonaState) {
    use crate::state_handler::main_page::content::CreatePersonaPhase;
    use ratatui::{
        layout::{Constraint, Flex},
        style::Style,
        widgets::{Block, Clear, Padding},
    };

    let area = frame.area();
    // The context and path choices both carry full paths, so they are wider
    // and grow with what they list. `Done` shows the minted `did:webvh` in
    // full — around a hundred characters of SCID, host and path — and at 64 it
    // was cut off mid-identifier, which is the one thing on that screen worth
    // reading: it is what you hand to a community to be issued an invitation.
    let choosing = overlay.phase == CreatePersonaPhase::Context;
    let path = overlay.phase == CreatePersonaPhase::Path;
    let done = overlay.phase == CreatePersonaPhase::Done;
    let popup_width = if choosing || path || done {
        96u16
    } else {
        64u16
    }
    .min(area.width.saturating_sub(4));
    let popup_height = if choosing {
        (overlay.context_options.len() + overlay.messages.len()) as u16 + 9
    } else if path {
        // Two rows, the worked example and its pointer, the explanatory lines,
        // the charset hint, the key line, and whatever the path was refused
        // for.
        overlay.messages.len() as u16 + 17
    } else {
        11u16
    }
    .min(area.height.saturating_sub(2))
    .max(7);

    let [popup_area] = Layout::vertical([Constraint::Length(popup_height)])
        .flex(Flex::Center)
        .areas(area);
    let [popup_area] = Layout::horizontal([Constraint::Length(popup_width)])
        .flex(Flex::Center)
        .areas(popup_area);

    frame.render_widget(Clear, popup_area);

    let block = Block::bordered()
        .title(" Create persona DID ")
        .title_style(Style::new().fg(COLOR_ORANGE).bold())
        .border_style(Style::new().fg(COLOR_ORANGE))
        .padding(Padding::uniform(1));

    let mut lines: Vec<Line> = Vec::new();
    match overlay.phase {
        CreatePersonaPhase::Label => {
            lines.push(Line::from(Span::styled(
                "Label for the new persona:",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            )));
            lines.push(Line::from(Span::styled(
                format!("> {}", overlay.label.value()),
                Style::new().fg(COLOR_SOFT_PURPLE).bold(),
            )));
            lines.push(Line::default());
            for msg in &overlay.messages {
                lines.push(Line::from(Span::styled(
                    msg.clone(),
                    Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
                )));
            }
            lines.push(Line::from(Span::styled(
                "⏎ next   esc cancel",
                Style::new().fg(COLOR_BORDER),
            )));
        }
        CreatePersonaPhase::Path => {
            use crate::state_handler::main_page::content::PersonaPathChoice;
            let custom = overlay.path_choice == PersonaPathChoice::Custom;
            lines.push(Line::from(Span::styled(
                "Where should this persona's DID live on the hosting server?",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            )));
            lines.push(Line::default());
            // "Path" means nothing until you have seen one in place. A DID with
            // its last segment picked out says in one line what a paragraph
            // about hosting servers does not — and this is the only screen
            // where the choice is open, because the path is inside the
            // identifier and nothing can move it afterwards.
            lines.push(Line::from(Span::styled(
                "  The path is the last part of the DID:",
                Style::new().fg(COLOR_BORDER),
            )));
            let lead = "did:webvh:QmXi1\u{2026}U83F:webvh.example.com:";
            lines.push(Line::from(vec![
                Span::raw("    "),
                Span::styled(lead, Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled("alice", Style::new().fg(COLOR_SUCCESS).bold()),
            ]));
            lines.push(Line::from(vec![
                Span::raw(" ".repeat(4 + lead.chars().count())),
                Span::styled("\u{2514} the path", Style::new().fg(COLOR_SUCCESS)),
            ]));
            lines.push(Line::from(Span::styled(
                "  It is part of the identifier, so it cannot be changed afterwards.",
                Style::new().fg(COLOR_BORDER),
            )));
            lines.push(Line::default());

            let row = |selected: bool, text: String| {
                let style = if selected {
                    Style::new().fg(COLOR_SUCCESS).bold()
                } else {
                    Style::new().fg(COLOR_TEXT_DEFAULT)
                };
                Line::from(Span::styled(
                    format!("{}{text}", if selected { "▸ " } else { "  " }),
                    style,
                ))
            };
            lines.push(row(
                !custom,
                "Server-assigned  (a random, unguessable path)".to_string(),
            ));
            lines.push(row(
                custom,
                format!(
                    "My own path:  {}{}",
                    overlay.path.value(),
                    if custom { "▎" } else { "" }
                ),
            ));
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                if custom {
                    "Lowercase letters, digits and hyphens; '/' separates segments."
                } else {
                    "A typed path is public and memorable — and may already be taken."
                },
                Style::new().fg(COLOR_BORDER),
            )));
            for msg in &overlay.messages {
                lines.push(Line::from(Span::styled(
                    msg.clone(),
                    Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
                )));
            }
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "↑/↓ choose   type: name the path   ⏎ next   esc back",
                Style::new().fg(COLOR_BORDER),
            )));
        }
        CreatePersonaPhase::Context => {
            use openvtc_core::config::community_context::ContextKind;
            lines.push(Line::from(Span::styled(
                "Where should this persona's keys and DID live?",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            )));
            lines.push(Line::from(Span::styled(
                "A persona is presented from the context it is minted in.",
                Style::new().fg(COLOR_BORDER),
            )));
            lines.push(Line::default());
            for (i, option) in overlay.context_options.iter().enumerate() {
                let selected = i == overlay.context_selected;
                let text = match option.kind {
                    ContextKind::New => {
                        let parent = openvtc_core::config::context_path::parse_sub_context_id(
                            &option.context_id,
                        )
                        .map_or(option.context_id.as_str(), |(parent, _)| parent);
                        format!(
                            "{parent}/{}{}  (a context of its own)",
                            overlay.context_slug,
                            if selected { "▎" } else { "" }
                        )
                    }
                    ContextKind::Existing | ContextKind::Top => option.summary(),
                };
                let style = if selected {
                    Style::new().fg(COLOR_SUCCESS).bold()
                } else {
                    Style::new().fg(COLOR_TEXT_DEFAULT)
                };
                lines.push(Line::from(Span::styled(
                    format!("{}{text}", if selected { "▸ " } else { "  " }),
                    style,
                )));
            }
            for msg in &overlay.messages {
                lines.push(Line::from(Span::styled(
                    msg.clone(),
                    Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
                )));
            }
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "↑/↓ choose   type: name the new context   ⏎ create   esc back",
                Style::new().fg(COLOR_BORDER),
            )));
        }
        CreatePersonaPhase::Working => {
            for msg in &overlay.messages {
                lines.push(Line::from(Span::styled(
                    msg.clone(),
                    Style::new().fg(COLOR_TEXT_DEFAULT),
                )));
            }
        }
        CreatePersonaPhase::Done => {
            lines.push(Line::from(Span::styled(
                "✓ Persona created",
                Style::new().fg(COLOR_SUCCESS).bold(),
            )));
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                overlay.did.clone().unwrap_or_default(),
                Style::new().fg(COLOR_SOFT_PURPLE),
            )));
            lines.push(Line::default());
            if overlay.copied {
                lines.push(Line::from(Span::styled(
                    "(copied to clipboard)",
                    Style::new().fg(COLOR_SUCCESS),
                )));
            }
            lines.push(Line::from(Span::styled(
                "c: copy again   ⏎/esc close",
                Style::new().fg(COLOR_BORDER),
            )));
        }
        CreatePersonaPhase::Failed => {
            for msg in &overlay.messages {
                lines.push(Line::from(Span::styled(
                    msg.clone(),
                    Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
                )));
            }
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "⏎/esc close",
                Style::new().fg(COLOR_BORDER),
            )));
        }
    }

    frame.render_widget(Paragraph::new(lines).block(block), popup_area);
}
