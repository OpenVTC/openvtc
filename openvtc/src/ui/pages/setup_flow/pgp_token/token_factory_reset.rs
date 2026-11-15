use crate::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_SUCCESS, COLOR_TEXT_DEFAULT, COLOR_WARNING_ACCESSIBLE_RED,
};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::{
        Constraint::{Length, Min},
        Layout,
    },
    style::{Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Padding, Paragraph, Wrap},
};

use crate::{
    state_handler::{
        actions::Action,
        setup_sequence::{MessageType, SetupState},
    },
    ui::pages::setup_flow::{
        SetupFlow,
        navigation::{SetupEvent, handle_nav_result, navigate},
        render_setup_header,
    },
};

#[derive(Copy, Clone, Debug, Default)]
pub struct TokenFactoryReset {
    pub options: TokenFactoryResetOptions,

    /// Resetting and writing keys to the token
    state: ResetState,
}

#[derive(Copy, Clone, Debug, Default)]
enum ResetState {
    #[default]
    Choice,
    Resetting,
    Writing,
}

#[derive(Copy, Clone, Debug, Default)]
pub enum TokenFactoryResetOptions {
    #[default]
    Reset,
    NoReset,
}

impl TokenFactoryResetOptions {
    /// Switches to the next panel when pressing `TAB`
    pub fn switch(&self) -> Self {
        match self {
            TokenFactoryResetOptions::Reset => TokenFactoryResetOptions::NoReset,
            TokenFactoryResetOptions::NoReset => TokenFactoryResetOptions::Reset,
        }
    }
}

impl TokenFactoryReset {
    pub fn handle_key_event(state: &mut SetupFlow, key: KeyEvent) {
        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            KeyCode::Tab | KeyCode::Up | KeyCode::Down => {
                state.token_factory_reset.options = state.token_factory_reset.options.switch();
            }
            KeyCode::Enter => {
                if let TokenFactoryResetOptions::Reset = state.token_factory_reset.options {
                    match state.token_factory_reset.state {
                        ResetState::Choice => {
                            // Start factory reset
                            state.token_factory_reset.state = ResetState::Resetting;
                            let _ = state.action_tx.send(Action::FactoryReset(
                                state.token_select.selected_token.clone(),
                            ));
                        }
                        ResetState::Resetting => {
                            if state.props.state.token_reset.completed_reset {
                                // Start writing keys
                                state.token_factory_reset.state = ResetState::Writing;
                                let _ = state.action_tx.send(Action::TokenWriteKeys(
                                    state.token_select.selected_token.clone(),
                                ));
                            }
                        }
                        ResetState::Writing => {
                            if state.props.state.token_reset.completed_writing {
                                let result =
                                    navigate(SetupEvent::TokenWritingComplete, &state.props.state);
                                handle_nav_result(result, state);
                            }
                        }
                    }
                } else {
                    match state.token_factory_reset.state {
                        ResetState::Choice => {
                            // Start factory reset
                            state.token_factory_reset.state = ResetState::Writing;
                            let _ = state.action_tx.send(Action::TokenWriteKeys(
                                state.token_select.selected_token.clone(),
                            ));
                        }
                        ResetState::Resetting => {}
                        ResetState::Writing => {
                            if state.props.state.token_reset.completed_writing {
                                let result =
                                    navigate(SetupEvent::TokenWritingComplete, &state.props.state);
                                handle_nav_result(result, state);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    pub fn render(&self, state: &SetupState, frame: &mut Frame) {
        let [top, middle, bottom] =
            Layout::vertical([Length(3), Min(0), Length(3)]).areas(frame.area());

        render_setup_header(frame, top, state);

        let block = Block::bordered()
            .fg(COLOR_BORDER)
            .padding(Padding::proportional(1))
            .title(" Factory reset token ");

        let mut lines = vec![
            Line::styled(
                "Hardware tokens may retain previous configurations, keys, or application data from prior use, which can cause conflicts when writing OpenVTC keys.",
                Style::new().fg(COLOR_DARK_GRAY),
            ),
            Line::default(),
            Line::styled(
                "Would you like to perform a factory reset on your hardware token?",
                Style::new().fg(COLOR_BORDER).bold(),
            ),
            Line::default(),
        ];

        // Render the active choice
        if let TokenFactoryResetOptions::Reset = self.options {
            lines.push(Line::styled(
                "[✓] Factory reset (recommended)",
                Style::new().fg(COLOR_SUCCESS).bold(),
            ));
            lines.push(Line::styled(
                "    Clears all existing data and restores default settings for a clean start.",
                Style::new().fg(COLOR_DARK_GRAY),
            ));
            lines.push(Line::styled(
                "[ ] Do not reset token",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ));
        } else {
            lines.push(Line::styled(
                "[ ] Factory reset (recommended)",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ));
            lines.push(Line::styled(
                "[✓] Do not reset token",
                Style::new().fg(COLOR_SUCCESS).bold(),
            ));
            lines.push(Line::styled(
                "    Write keys to the token in its current state. Only use if the token is new or already clean.",
                Style::new().fg(COLOR_DARK_GRAY),
            ));
        }

        lines.push(Line::default());

        match self.state {
            ResetState::Choice => {
                lines.push(Line::from(vec![
                    Span::styled("[TAB]", Style::new().fg(COLOR_BORDER).bold()),
                    Span::styled(" to select  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                    Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
                    Span::styled(" to continue", Style::new().fg(COLOR_TEXT_DEFAULT)),
                ]));
            }
            ResetState::Resetting => {
                lines.push(Line::default());
                lines.push(Line::styled(
                    "Hardware token setup status",
                    Style::new().fg(COLOR_BORDER).bold().underlined(),
                ));
                lines.push(Line::default());

                for msg in state.token_reset.messages.iter() {
                    match msg {
                        MessageType::Info(info) => {
                            lines.push(Line::styled(
                                format!("INFO: {}", info),
                                Style::new().fg(COLOR_SUCCESS),
                            ));
                        }
                        MessageType::Error(err) => {
                            lines.push(Line::styled(
                                format!("ERROR: {}", err),
                                Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
                            ));
                        }
                    }
                }

                if state.token_reset.completed_reset {
                    lines.push(Line::default());
                    lines.push(Line::from(vec![
                        Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
                        Span::styled(" to continue", Style::new().fg(COLOR_TEXT_DEFAULT)),
                    ]));
                }
            }
            ResetState::Writing => {
                lines.push(Line::default());
                lines.push(Line::styled(
                    "Hardware token setup status",
                    Style::new().fg(COLOR_BORDER).bold().underlined(),
                ));
                lines.push(Line::default());

                for msg in state.token_reset.messages.iter() {
                    match msg {
                        MessageType::Info(info) => {
                            lines.push(Line::styled(
                                format!("INFO: {}", info),
                                Style::new().fg(COLOR_SUCCESS),
                            ));
                        }
                        MessageType::Error(err) => {
                            lines.push(Line::styled(
                                format!("ERROR: {}", err),
                                Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
                            ));
                        }
                    }
                }

                if state.token_reset.completed_writing {
                    lines.push(Line::default());
                    lines.push(Line::from(vec![
                        Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
                        Span::styled(" to continue", Style::new().fg(COLOR_TEXT_DEFAULT)),
                    ]));
                }
            }
        }

        frame.render_widget(
            Paragraph::new(lines)
                .block(block)
                .wrap(Wrap { trim: false }),
            middle,
        );

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
