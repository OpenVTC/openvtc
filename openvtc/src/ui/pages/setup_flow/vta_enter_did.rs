//! Online VTA provisioning — step 1: ask for the VTA DID.
//!
//! Replaces the legacy paste-credential-bundle flow. On submit we resolve the
//! VTA service URL and mint an ephemeral `did:key` used as the admin identity
//! the operator will authorise via PNM in the next step.

use crate::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS,
    COLOR_TEXT_DEFAULT, COLOR_WARNING_ACCESSIBLE_RED,
};
use crossterm::event::{Event, KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::{
        Constraint::{Length, Min},
        Layout, Margin, Rect,
    },
    style::{Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Padding, Paragraph, Wrap},
};
use tui_input::{Input, backend::crossterm::EventHandler};

use crate::{
    state_handler::{
        actions::Action,
        setup_sequence::{Completion, MessageType, SetupState},
    },
    ui::pages::setup_flow::{SetupFlow, render_setup_header},
};

#[derive(Clone, Debug, Default)]
pub struct VtaEnterDid {
    pub vta_did: Input,
    /// True while the backend resolves the URL + mints the setup key.
    pub processing: bool,
}

impl VtaEnterDid {
    pub fn handle_key_event(state: &mut SetupFlow, key: KeyEvent) {
        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            KeyCode::Enter => match state.props.state.vta.completed {
                Completion::CompletedFail => {
                    // Reset error state so the user can edit and resubmit.
                    state.vta_enter_did.processing = false;
                }
                Completion::CompletedOK | Completion::NotFinished
                    if !state.vta_enter_did.processing =>
                {
                    let did = state.vta_enter_did.vta_did.value().trim().to_string();
                    if !did.is_empty() {
                        state.vta_enter_did.processing = true;
                        let _ = state.action_tx.send(Action::VtaSubmitDid(did));
                    }
                }
                _ => {}
            },
            KeyCode::Esc if !state.vta_enter_did.processing => {
                state.vta_enter_did.vta_did.reset();
            }
            _ if !state.vta_enter_did.processing => {
                state.vta_enter_did.vta_did.handle_event(&Event::Key(key));
            }
            _ => {
                // Input is locked while resolution is in flight.
            }
        }
    }

    pub fn render(&self, state: &SetupState, frame: &mut Frame<'_>) {
        let [top, middle, bottom] =
            Layout::vertical([Length(3), Min(0), Length(3)]).areas(frame.area());

        render_setup_header(frame, top, state);

        frame.render_widget(
            Block::bordered()
                .fg(COLOR_BORDER)
                .padding(Padding::proportional(1))
                .title(" Connect to your VTA "),
            middle,
        );

        let content: [Rect; 3] =
            Layout::vertical([Length(4), Length(2), Min(0)]).areas(middle.inner(Margin::new(3, 2)));

        let [prompt_col, input_col] = Layout::horizontal([Length(2), Min(0)]).areas(content[1]);

        frame.render_widget(
            Paragraph::new(vec![
                Line::styled(
                    "OpenVTC connects to a Verifiable Trust Agent (VTA) for DID management,",
                    Style::new().fg(COLOR_DARK_GRAY),
                ),
                Line::styled(
                    "key management, context provisioning, and DIDComm relay.",
                    Style::new().fg(COLOR_DARK_GRAY),
                ),
                Line::default(),
                Line::styled("Enter the VTA's DID:", Style::new().fg(COLOR_BORDER).bold()),
            ]),
            content[0],
        );

        frame.render_widget(
            Paragraph::new(Span::styled(
                "> ",
                Style::new().fg(COLOR_SOFT_PURPLE).bold(),
            )),
            prompt_col,
        );
        render_input(&self.vta_did, frame, input_col);

        let mut lines = Vec::new();
        if self.processing {
            for msg in state.vta.messages.iter() {
                match msg {
                    MessageType::Info(info) => {
                        lines.push(Line::styled(
                            format!("INFO: {info}"),
                            Style::new().fg(COLOR_SUCCESS),
                        ));
                    }
                    MessageType::Error(err) => {
                        lines.push(Line::styled(
                            format!("ERROR: {err}"),
                            Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
                        ));
                    }
                }
            }
            if state.vta.messages.is_empty() {
                lines.push(Line::styled(
                    "Resolving VTA endpoint…",
                    Style::new().fg(COLOR_DARK_GRAY),
                ));
            }
            if let Completion::CompletedFail = state.vta.completed {
                lines.push(Line::default());
                lines.push(Line::styled(
                    "Press [ENTER] to edit the DID and try again.",
                    Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
                ));
            }
        } else {
            lines.extend_from_slice(&[
                Line::styled("Examples:", Style::new().fg(COLOR_ORANGE).bold()),
                Line::styled(
                    "  • did:webvh:QmRoot…:vta.example.com",
                    Style::new().fg(COLOR_ORANGE).italic(),
                ),
                Line::styled(
                    "  • did:scid:vh:1:QmRoot…?src=vta.example.com",
                    Style::new().fg(COLOR_ORANGE).italic(),
                ),
                Line::styled(
                    "  • did:web:vta.example.com",
                    Style::new().fg(COLOR_ORANGE).italic(),
                ),
                Line::default(),
                Line::styled(
                    "Don't know your VTA's DID? Look it up via PNM:",
                    Style::new().fg(COLOR_BORDER).bold(),
                ),
                Line::styled(
                    "  $ pnm vta info",
                    Style::new().fg(COLOR_SOFT_PURPLE).bold(),
                ),
                Line::default(),
                Line::from(vec![
                    Span::styled("[ESC]", Style::new().fg(COLOR_BORDER).bold()),
                    Span::styled(" to clear input  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                    Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
                    Span::styled(" to continue", Style::new().fg(COLOR_TEXT_DEFAULT)),
                ]),
            ]);
        }
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), content[2]);

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

fn render_input(input: &Input, frame: &mut Frame, area: Rect) {
    let width = area.width.max(3) - 3;
    let scroll = input.visual_scroll(width as usize);
    frame.render_widget(
        Paragraph::new(Span::styled(
            input.value(),
            Style::new().fg(COLOR_SOFT_PURPLE),
        ))
        .scroll((0, scroll as u16)),
        area,
    );
    let x = input.visual_cursor().max(scroll) - scroll;
    frame.set_cursor_position((area.x + x as u16, area.y))
}
