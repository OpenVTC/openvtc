use crate::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
    COLOR_WARNING_ACCESSIBLE_RED,
};
use crossterm::event::{Event, KeyCode, KeyEvent};
use openvtc_core::config::{MIN_PASSPHRASE_LENGTH, validate_passphrase};
use ratatui::{
    Frame,
    layout::{
        Constraint::{Length, Min},
        Layout, Margin, Rect,
    },
    style::{Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Padding, Paragraph},
};
use secrecy::SecretString;
use tui_input::{Input, backend::crossterm::EventHandler};

use crate::{
    state_handler::{actions::Action, setup_sequence::SetupState},
    ui::pages::setup_flow::{
        SetupFlow,
        navigation::{SetupEvent, handle_nav_result, navigate},
        render_setup_header,
    },
};

// ****************************************************************************
// UnlockCodeSet
// ****************************************************************************

#[derive(Clone, Debug, Default)]
pub struct UnlockCodeSet {
    /// 0 = passphrase, 1 = confirm passphrase
    pub active_input: u8,

    pub passphrase: Input,
    pub confirm: Input,
    /// User-visible error from the most recent Enter press. Cleared on the
    /// next keystroke so the user sees fresh feedback as they retype.
    pub error_msg: Option<String>,
}

impl UnlockCodeSet {
    fn passphrases_match(&self) -> bool {
        !self.passphrase.value().is_empty() && self.passphrase.value() == self.confirm.value()
    }

    pub fn handle_key_event(state: &mut SetupFlow, key: KeyEvent) {
        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            KeyCode::Tab | KeyCode::Up | KeyCode::Down => {
                state.unlock_code_set.active_input = if state.unlock_code_set.active_input == 0 {
                    1
                } else {
                    0
                };
            }
            KeyCode::Enter => {
                if state.unlock_code_set.passphrase.value().is_empty() {
                    state.unlock_code_set.error_msg =
                        Some("Please enter an unlock code.".to_string());
                    return;
                }
                if !state.unlock_code_set.passphrases_match() {
                    state.unlock_code_set.error_msg =
                        Some("Unlock codes do not match.".to_string());
                    return;
                }
                // Every unlock path refuses a code below the minimum length,
                // so a shorter one set here would lock the profile for good.
                if validate_passphrase(state.unlock_code_set.passphrase.value()).is_err() {
                    state.unlock_code_set.error_msg = Some(format!(
                        "Unlock codes must be at least {MIN_PASSPHRASE_LENGTH} characters."
                    ));
                    return;
                }
                state.unlock_code_set.error_msg = None;
                let passphrase =
                    SecretString::from(state.unlock_code_set.passphrase.value().to_string());
                // The action carries the secret; drop the plaintext from the
                // input buffers.
                state.unlock_code_set.passphrase.reset();
                state.unlock_code_set.confirm.reset();
                let result = navigate(SetupEvent::UnlockCodeSet { passphrase }, &state.props.state);
                handle_nav_result(result, state);
            }
            KeyCode::Esc => {
                if state.unlock_code_set.active_input == 0 {
                    state.unlock_code_set.passphrase.reset();
                } else {
                    state.unlock_code_set.confirm.reset();
                }
                state.unlock_code_set.error_msg = None;
            }
            _ => {
                // Handle text input
                state.unlock_code_set.error_msg = None;
                if state.unlock_code_set.active_input == 0 {
                    state
                        .unlock_code_set
                        .passphrase
                        .handle_event(&Event::Key(key));
                } else {
                    state.unlock_code_set.confirm.handle_event(&Event::Key(key));
                }
            }
        }
    }

    pub fn render(&self, state: &SetupState, frame: &mut Frame<'_>) {
        let [top, middle, bottom] =
            Layout::vertical([Length(3), Min(0), Length(3)]).areas(frame.area());

        render_setup_header(frame, top, state);

        // 0: Header / instructions
        // 1: Passphrase input
        // 2: Confirm label
        // 3: Confirm input
        // 4: Match status + key bindings
        let content: [Rect; 5] =
            Layout::vertical([Length(5), Length(2), Length(2), Length(2), Min(0)])
                .areas(middle.inner(Margin::new(3, 2)));

        let [input0_prompt, input0_box] = Layout::horizontal([Length(2), Min(0)]).areas(content[1]);
        let [input1_prompt, input1_box] = Layout::horizontal([Length(2), Min(0)]).areas(content[3]);

        frame.render_widget(
            Block::bordered()
                .fg(COLOR_BORDER)
                .padding(Padding::proportional(1))
                .title(" Enter unlock code "),
            middle,
        );

        frame.render_widget(
            Paragraph::new(vec![
                Line::styled(
                    "Your unlock code will encrypt and protect your cryptographic keys, configuration, and private data.",
                    Style::new().fg(COLOR_DARK_GRAY),
                ),
                Line::default(),
                Line::styled(
                    "Create a strong unlock code (at least 8 characters):",
                    Style::new().fg(COLOR_BORDER).bold(),
                ),
                Line::styled(
                    "Use a long, unique code. Letters, numbers, spaces, and symbols are supported.",
                    Style::new().fg(COLOR_DARK_GRAY),
                ),
            ]),
            content[0],
        );

        frame.render_widget(
            Paragraph::new(Span::styled(
                "> ",
                Style::new().fg(COLOR_SOFT_PURPLE).bold(),
            )),
            input0_prompt,
        );

        render_input(&self.passphrase, frame, input0_box, self.active_input == 0);

        frame.render_widget(
            Paragraph::new(Line::styled(
                "Confirm unlock code:",
                Style::new().fg(COLOR_BORDER).bold(),
            )),
            content[2],
        );

        frame.render_widget(
            Paragraph::new(Span::styled(
                "> ",
                Style::new().fg(COLOR_SOFT_PURPLE).bold(),
            )),
            input1_prompt,
        );

        render_input(&self.confirm, frame, input1_box, self.active_input == 1);

        let mut footer: Vec<Line<'_>> = Vec::new();

        // Live match indicator — only once the user has started typing into the
        // confirm field, so we don't nag them before they've had a chance.
        if !self.confirm.value().is_empty() {
            if self.passphrases_match() {
                footer.push(Line::styled(
                    "Unlock codes match.",
                    Style::new().fg(COLOR_SUCCESS).bold(),
                ));
            } else {
                footer.push(Line::styled(
                    "Unlock codes do not match.",
                    Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED).bold(),
                ));
            }
            footer.push(Line::default());
        }

        footer.push(Line::from(vec![
            Span::styled("[TAB]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" to select  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
            Span::styled("[ESC]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" to go back  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
            Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" to continue", Style::new().fg(COLOR_TEXT_DEFAULT)),
        ]));

        if let Some(err) = &self.error_msg {
            footer.push(Line::default());
            footer.push(Line::styled(
                err.clone(),
                Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED).bold(),
            ));
        }
        frame.render_widget(Paragraph::new(footer), content[4]);

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

fn render_input(input: &Input, frame: &mut Frame, area: Rect, active: bool) {
    // keep 1 for borders and 1 for cursor
    let width = area.width.max(3) - 3;
    let scroll = input.visual_scroll(width as usize);
    let mut s = String::new();
    for _ in 0..input.value().len() {
        s.push('*');
    }
    let text = Span::styled(s, Style::new().fg(COLOR_SOFT_PURPLE));

    frame.render_widget(Paragraph::new(text).scroll((0, scroll as u16)), area);

    if active {
        let x = input.visual_cursor().max(scroll) - scroll;
        frame.set_cursor_position((area.x + x as u16, area.y))
    }
}
