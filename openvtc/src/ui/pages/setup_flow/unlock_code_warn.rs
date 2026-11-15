use crate::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
    COLOR_WARNING_ACCESSIBLE_RED,
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
    state_handler::{actions::Action, setup_sequence::SetupState},
    ui::pages::setup_flow::{
        SetupFlow,
        navigation::{SetupEvent, handle_nav_result, navigate},
        render_setup_header,
    },
};

// ****************************************************************************
// UnlockCodeWarn
// ****************************************************************************
#[derive(Copy, Clone, Debug, Default)]
pub enum UnlockCodeWarn {
    #[default]
    UseCode,
    AckRisk,
}
impl UnlockCodeWarn {
    /// Switches to the next panel when pressing `TAB`
    pub fn switch(&self) -> Self {
        match self {
            UnlockCodeWarn::UseCode => UnlockCodeWarn::AckRisk,
            UnlockCodeWarn::AckRisk => UnlockCodeWarn::UseCode,
        }
    }
}
impl UnlockCodeWarn {
    pub fn handle_key_event(state: &mut SetupFlow, key: KeyEvent) {
        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            KeyCode::Tab | KeyCode::Up | KeyCode::Down => {
                state.unlock_code_warn = state.unlock_code_warn.switch();
            }
            KeyCode::Enter => {
                let event = match state.unlock_code_warn {
                    UnlockCodeWarn::UseCode => SetupEvent::ReturnToSetCode,
                    UnlockCodeWarn::AckRisk => SetupEvent::AcceptNoCodeRisk,
                };
                handle_nav_result(navigate(event, &state.props.state), state);
            }
            _ => {}
        }
    }

    pub fn render(&self, state: &SetupState, frame: &mut Frame) {
        let [top, middle, bottom] =
            Layout::vertical([Length(3), Min(0), Length(3)]).areas(frame.area());

        render_setup_header(frame, top, state);

        let block = Block::bordered()
            .fg(COLOR_ORANGE)
            .padding(Padding::proportional(1))
            .title(" SECURITY WARNING ");

        let mut lines = vec![
            Line::styled(
                "⚠️ Without an unlock code, your cryptographic keys, configuration, and private data will be stored unencrypted on this computer.",
                Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED).bold(),
            ),
            Line::default(),
            Line::styled(
                "Anyone who gains access to this device can use your keys to sign messages, decrypt data, impersonate your identity, and access your private information.",
                Style::new().fg(COLOR_ORANGE),
            ),
            Line::default(),
            Line::styled(
                "Are you sure you want to continue without an unlock code?",
                Style::new().fg(COLOR_BORDER).bold(),
            ),
            Line::default(),
        ];

        // Render the active choice
        if let UnlockCodeWarn::UseCode = self {
            lines.push(Line::styled(
                "[✓] No, take me back to set an unlock code (recommended)",
                Style::new().fg(COLOR_SUCCESS).bold(),
            ));
            lines.push(Line::styled(
                "    Encrypt and protect your keys, configuration, and private data for safer storage.",
                Style::new().fg(COLOR_DARK_GRAY),
            ));
            lines.push(Line::styled(
                "[ ] Yes, I understand the risks and want to continue",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ));
        } else {
            lines.push(Line::styled(
                "[ ] No, take me back to set an unlock code (recommended)",
                Style::new().fg(COLOR_TEXT_DEFAULT),
            ));
            lines.push(Line::styled(
                "[✓] Yes, I understand the risks and want to continue",
                Style::new().fg(COLOR_SUCCESS).bold(),
            ));
            lines.push(Line::styled(
                "    Skip encryption. Only recommended for testing or development environments where security is not a concern.",
                Style::new().fg(COLOR_DARK_GRAY),
            ));
        }

        lines.push(Line::default());
        lines.push(Line::from(vec![
            Span::styled("[TAB]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" to select  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
            Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" to confirm", Style::new().fg(COLOR_TEXT_DEFAULT)),
        ]));

        frame.render_widget(
            Paragraph::new(lines)
                .block(block)
                .wrap(Wrap { trim: false }),
            middle,
        );

        let bottom_line = Line::from(vec![
            Span::styled("[F10]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" to quit  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
            Span::styled("[ESC]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" to go back", Style::new().fg(COLOR_TEXT_DEFAULT)),
        ]);

        frame.render_widget(
            Paragraph::new(bottom_line).block(Block::new().padding(Padding::new(2, 0, 1, 0))),
            bottom,
        );
    }
}
