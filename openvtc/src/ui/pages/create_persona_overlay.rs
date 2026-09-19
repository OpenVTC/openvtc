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
        // Two screens behind one phase. The default one asks nothing — the
        // server picks the path — so its only keys are "create" and the one
        // that opens the other screen. Once a path is being typed every key
        // belongs to the input, which is why `p` is bound here and nowhere
        // inside the editor.
        CreatePersonaPhase::Path => {
            use crate::state_handler::main_page::content::PersonaPathChoice;
            let typing = overlay.path_choice == PersonaPathChoice::Custom;
            let action = match key.code {
                KeyCode::Enter => Action::CreatePersonaSubmit,
                // Esc leaves the path editor rather than the whole step: the
                // way out of "my own path" is "let the server pick", and a key
                // that skipped both screens at once would take the label with
                // it.
                KeyCode::Esc if typing => Action::CreatePersonaPathChoice(PersonaPathChoice::Auto),
                KeyCode::Esc => Action::CreatePersonaBack,
                KeyCode::Char('p') if !typing => {
                    Action::CreatePersonaPathChoice(PersonaPathChoice::Custom)
                }
                _ if typing => Action::CreatePersonaPathInput(key),
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
    use crate::state_handler::main_page::content::{CreatePersonaPhase, PersonaPathChoice};
    use ratatui::{
        layout::{Constraint, Flex},
        style::Style,
        widgets::{Block, Clear, Padding},
    };

    let area = frame.area();
    // The path screen carries a whole worked DID, and `Done` shows the minted
    // one in full — around a hundred characters of SCID, host and path — which
    // at 64 was cut off mid-identifier, the one thing on that screen worth
    // reading: it is what you hand to a community to be issued an invitation.
    let label = overlay.phase == CreatePersonaPhase::Label;
    let path = overlay.phase == CreatePersonaPhase::Path;
    let done = overlay.phase == CreatePersonaPhase::Done;
    let popup_width = if path || done { 96u16 } else { 76u16 }.min(area.width.saturating_sub(4));
    let popup_height = if path {
        // The worked example and its pointer, the explanatory lines, the
        // agent-name note or the typed path and its charset hint, the key line,
        // and whatever the path was refused for.
        overlay.messages.len() as u16
            + if overlay.path_choice == PersonaPathChoice::Custom {
                17
            } else {
                16
            }
    } else if label {
        overlay.messages.len() as u16 + 14
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
        // "Label" on its own is a box with no clue what belongs in it, on the
        // first screen of the first thing anyone makes here. What it is *for*
        // is one line, and an example sitting in the empty field is worth more
        // than another sentence explaining it.
        CreatePersonaPhase::Label => {
            lines.push(Line::from(Span::styled(
                "What should this persona be called?",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            )));
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "  A name for you, to tell your personas apart in OpenVTC — and it names",
                Style::new().fg(COLOR_BORDER),
            )));
            lines.push(Line::from(Span::styled(
                "  the context its keys live in. Communities are shown the DID, not this,",
                Style::new().fg(COLOR_BORDER),
            )));
            lines.push(Line::from(Span::styled(
                "  and you can rename it later.",
                Style::new().fg(COLOR_BORDER),
            )));
            lines.push(Line::default());
            let typed = overlay.label.value();
            lines.push(Line::from(vec![
                Span::styled("> ", Style::new().fg(COLOR_SOFT_PURPLE).bold()),
                if typed.is_empty() {
                    // A placeholder, not a value: dimmed, and gone the moment
                    // anything is typed, so nobody submits the example.
                    Span::styled(
                        "e.g. Work, Conference, Alice",
                        Style::new().fg(COLOR_BORDER),
                    )
                } else {
                    Span::styled(typed.to_string(), Style::new().fg(COLOR_SOFT_PURPLE).bold())
                },
            ]));
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
            let custom = overlay.path_choice == PersonaPathChoice::Custom;
            lines.push(Line::from(Span::styled(
                "Where should this persona's DID live on the hosting server?",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            )));
            lines.push(Line::default());
            // "Path" means nothing until you have seen one in place. A DID with
            // its last segment picked out says in one line what a paragraph
            // about hosting servers does not — and this is the only screen
            // where it is open at all, because the path is inside the
            // identifier and nothing can move it afterwards.
            lines.push(Line::from(Span::styled(
                "  The path is the last part of the DID:",
                Style::new().fg(COLOR_BORDER),
            )));
            let lead = "did:webvh:QmXi1\u{2026}U83F:webvh.example.com:";
            // The example shows the outcome of the screen you are on, so the
            // default is not illustrated with a name nobody is going to get.
            let typed = overlay.path.value();
            let example = if !custom {
                "x7f2q9"
            } else if typed.is_empty() {
                "alice"
            } else {
                typed
            };
            lines.push(Line::from(vec![
                Span::raw("    "),
                Span::styled(lead, Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled(example.to_string(), Style::new().fg(COLOR_SUCCESS).bold()),
            ]));
            lines.push(Line::from(vec![
                Span::raw(" ".repeat(4 + lead.chars().count())),
                Span::styled("\u{2514} the path", Style::new().fg(COLOR_SUCCESS)),
            ]));
            if custom {
                lines.push(Line::from(Span::styled(
                    "  It is part of the identifier, so it cannot be changed afterwards.",
                    Style::new().fg(COLOR_BORDER),
                )));
                lines.push(Line::default());
                lines.push(Line::from(vec![
                    Span::styled("  Your path:  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                    Span::styled(
                        format!("{typed}\u{258e}"),
                        Style::new().fg(COLOR_SUCCESS).bold(),
                    ),
                ]));
                lines.push(Line::default());
                lines.push(Line::from(Span::styled(
                    "Lowercase letters, digits and hyphens; '/' separates segments. A typed",
                    Style::new().fg(COLOR_BORDER),
                )));
                lines.push(Line::from(Span::styled(
                    "path is public forever, and may already be taken.",
                    Style::new().fg(COLOR_BORDER),
                )));
            } else {
                lines.push(Line::from(Span::styled(
                    "  It is part of the identifier, so it cannot be changed",
                    Style::new().fg(COLOR_BORDER),
                )));
                lines.push(Line::from(Span::styled(
                    "  afterwards — so the server picks a random one.",
                    Style::new().fg(COLOR_BORDER),
                )));
                lines.push(Line::default());
                // The question this screen used to leave hanging. A typed path
                // reads like the way to get a memorable identifier, and it is
                // the expensive way: permanent, public, and possibly taken. The
                // cheap way exists and is reversible, so say so here rather
                // than let someone buy the permanent one by mistake.
                lines.push(Line::from(Span::styled(
                    "A memorable name does not have to live in the DID: an agent name",
                    Style::new().fg(COLOR_BORDER),
                )));
                lines.push(Line::from(Span::styled(
                    "(example.com/@alice) points at it, and can be changed later.",
                    Style::new().fg(COLOR_BORDER),
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
                if custom {
                    "⏎ create   esc: let the server pick"
                } else {
                    "⏎ create   p: choose the path yourself   esc back"
                },
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
