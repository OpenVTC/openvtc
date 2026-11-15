use crate::colors::{COLOR_BORDER, COLOR_DARK_GRAY, COLOR_TEXT_DEFAULT};
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

#[derive(Copy, Clone, Debug, Default)]
pub struct TokenStart {}

impl TokenStart {
    pub fn handle_key_event(state: &mut SetupFlow, key: KeyEvent) {
        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            KeyCode::Char('s') | KeyCode::Char('S') => {
                let result = navigate(SetupEvent::TokenSkipped, &state.props.state);
                handle_nav_result(result, state);
            }
            KeyCode::Enter => {
                let _ = state.action_tx.send(Action::GetTokens);
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
            .title(" Set up hardware token ");

        let lines = vec![
            Line::styled(
                "For enhanced security, you can protect your OpenVTC profile with a hardware token. This step is recommended but optional.",
                Style::new().fg(COLOR_DARK_GRAY),
            ),
            Line::default(),
            Line::styled(
                "Do you have an OpenPGP-compatible hardware token (e.g., NitroKey or YubiKey)?",
                Style::new().fg(COLOR_BORDER).bold(),
            ),
            Line::default(),
            Line::styled(
                "Plug it in now to continue.",
                Style::new().fg(COLOR_TEXT_DEFAULT).bold(),
            ),
            Line::default(),
            Line::from(vec![
                Span::styled("[S]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" to skip setup  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" to continue", Style::new().fg(COLOR_TEXT_DEFAULT)),
            ]),
        ];

        frame.render_widget(
            Paragraph::new(lines).block(block).wrap(Wrap { trim: true }),
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
