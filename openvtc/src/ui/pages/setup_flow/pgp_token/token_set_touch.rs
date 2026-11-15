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
pub struct TokenSetTouch {
    started: bool,
    option: TokenSetTouchOptions,
}

#[derive(Copy, Clone, Debug, Default)]
pub enum TokenSetTouchOptions {
    #[default]
    SetTouch,
    NoTouch,
}

impl TokenSetTouchOptions {
    /// Switches to the next panel when pressing `TAB`
    pub fn switch(&self) -> Self {
        match self {
            TokenSetTouchOptions::SetTouch => TokenSetTouchOptions::NoTouch,
            TokenSetTouchOptions::NoTouch => TokenSetTouchOptions::SetTouch,
        }
    }
}

impl TokenSetTouch {
    pub fn handle_key_event(state: &mut SetupFlow, key: KeyEvent) {
        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            KeyCode::Tab | KeyCode::Up | KeyCode::Down => {
                state.token_set_touch.option = state.token_set_touch.option.switch();
            }
            KeyCode::Enter => {
                if !state.token_set_touch.started {
                    state.token_set_touch.started = true;
                    let _ = state.action_tx.send(Action::SetTouchPolicy(
                        state.token_select.selected_token.clone(),
                    ));
                } else if state.props.state.token_set_touch.completed {
                    let result = navigate(SetupEvent::TokenTouchComplete, &state.props.state);
                    handle_nav_result(result, state);
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
            .title(" Set token touch policy ");

        let mut lines = vec![
            Line::styled(
                "With touch enabled, signing requires a physical tap on your hardware token, preventing use without your knowledge.",
                Style::new().fg(COLOR_DARK_GRAY),
            ),
            Line::default(),
            Line::styled(
                "Would you like to require a physical touch for signing?",
                Style::new().fg(COLOR_BORDER).bold(),
            ),
            Line::default(),
        ];

        // Render the active choice
        if let TokenSetTouchOptions::SetTouch = self.option {
            lines.push(Line::styled(
                "[✓] Enable touch for signing (recommended)",
                Style::new().fg(COLOR_SUCCESS).bold(),
            ));
            lines.push(Line::styled(
                "    Require physical confirmation on the token for each signing operation.",
                Style::new().fg(COLOR_DARK_GRAY),
            ));
            lines.push(Line::styled(
                "[ ] Do not enable touch for signing",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ));
        } else {
            lines.push(Line::styled(
                "[ ] Enable touch for signing (recommended)",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ));
            lines.push(Line::styled(
                "[✓] Do not enable touch for signing",
                Style::new().fg(COLOR_SUCCESS).bold(),
            ));
            lines.push(Line::styled(
                "    Signing operations can proceed without physical confirmation on the token.",
                Style::new().fg(COLOR_DARK_GRAY),
            ));
        }

        lines.push(Line::default());

        if !state.token_set_touch.messages.is_empty() {
            lines.push(Line::default());
            lines.push(Line::styled(
                "Hardware token touch setup status",
                Style::new().fg(COLOR_BORDER).bold().underlined(),
            ));
            lines.push(Line::default());
        }

        for msg in state.token_set_touch.messages.iter() {
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

        if !self.started {
            lines.push(Line::from(vec![
                Span::styled("[TAB]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" to select  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" to continue", Style::new().fg(COLOR_TEXT_DEFAULT)),
            ]));
        } else if state.token_set_touch.completed {
            lines.push(Line::default());
            lines.push(Line::from(vec![
                Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" to continue", Style::new().fg(COLOR_TEXT_DEFAULT)),
            ]));
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
