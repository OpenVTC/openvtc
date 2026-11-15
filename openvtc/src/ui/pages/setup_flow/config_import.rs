use crate::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
    COLOR_WARNING_ACCESSIBLE_RED,
};
use crate::{
    state_handler::{
        actions::Action,
        setup_sequence::{Completion, MessageType, SetupState},
    },
    ui::pages::setup_flow::{SetupFlow, render_setup_header},
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

// ****************************************************************************
// Config Import
// ****************************************************************************
#[derive(Clone, Debug)]
pub struct ConfigImport {
    /// 0 = filename
    /// 1 = config unlock passphrase
    /// 2 = new openvtc unlock passphrase
    pub active_input: u8,

    pub filename: Input,
    pub config_unlock_passphrase: Input,
    pub new_unlock_passphrase: Input,
    pub processing: bool,
    /// Input problem found before anything was sent to the handler.
    pub error_msg: Option<String>,
}

impl Default for ConfigImport {
    fn default() -> Self {
        Self {
            active_input: 0,
            filename: Input::new("export.openvtc".to_string()),
            config_unlock_passphrase: Input::default(),
            new_unlock_passphrase: Input::default(),
            processing: false,
            error_msg: None,
        }
    }
}

impl ConfigImport {
    pub fn handle_key_event(state: &mut SetupFlow, key: KeyEvent) {
        // Unlock the inputs once the backend has responded with a failure, so
        // the user can edit fields and retry. On success the user is prompted
        // to exit, so keeping the inputs locked is fine.
        if state.config_import.processing
            && matches!(
                state.props.state.config_import.completed,
                Completion::CompletedFail
            )
        {
            state.config_import.processing = false;
        }

        // NOTE: if let statements are experimental still in Rust
        // So we create a boolean here instead
        let completed_ok = matches!(
            state.props.state.config_import.completed,
            Completion::CompletedOK
        );
        let locked = state.config_import.processing;

        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            KeyCode::Tab | KeyCode::Down if !completed_ok && !locked => {
                if state.config_import.active_input == 2 {
                    state.config_import.active_input = 0;
                } else {
                    state.config_import.active_input += 1;
                }
            }
            KeyCode::Up if !completed_ok && !locked => {
                if state.config_import.active_input == 0 {
                    state.config_import.active_input = 2;
                } else {
                    state.config_import.active_input -= 1;
                }
            }
            KeyCode::Enter if !locked => {
                if let Completion::CompletedOK = state.props.state.config_import.completed {
                    let _ = state.action_tx.send(Action::Exit);
                } else {
                    // Blank is allowed (the backup may carry no unlock code);
                    // a short code is not, as it could never be used to unlock.
                    let new_code = state.config_import.new_unlock_passphrase.value();
                    if !new_code.is_empty() && validate_passphrase(new_code).is_err() {
                        state.config_import.error_msg = Some(format!(
                            "The new unlock code must be at least {MIN_PASSPHRASE_LENGTH} characters."
                        ));
                        state.config_import.active_input = 2;
                        return;
                    }
                    state.config_import.error_msg = None;
                    state.config_import.processing = true;
                    let _ = state.action_tx.send(Action::ImportConfig(
                        state.config_import.filename.value().to_string(),
                        SecretString::from(state.config_import.config_unlock_passphrase.value()),
                        SecretString::from(state.config_import.new_unlock_passphrase.value()),
                    ));
                    // The action carries SecretString copies; drop the
                    // plaintext from the tui_input buffers so it isn't
                    // re-rendered (masked) every frame or left in heap memory.
                    state.config_import.config_unlock_passphrase.reset();
                    state.config_import.new_unlock_passphrase.reset();
                }
            }
            KeyCode::Esc if !completed_ok && !locked => match state.config_import.active_input {
                0 => state.config_import.filename.reset(),
                1 => state.config_import.config_unlock_passphrase.reset(),
                2 => state.config_import.new_unlock_passphrase.reset(),
                _ => {}
            },
            _ if !completed_ok && !locked => {
                state.config_import.error_msg = None;
                // Handle text input
                match state.config_import.active_input {
                    0 => state.config_import.filename.handle_event(&Event::Key(key)),
                    1 => state
                        .config_import
                        .config_unlock_passphrase
                        .handle_event(&Event::Key(key)),
                    2 => state
                        .config_import
                        .new_unlock_passphrase
                        .handle_event(&Event::Key(key)),
                    _ => None,
                };
            }
            _ => {}
        }
    }

    pub fn render(&self, state: &SetupState, frame: &mut Frame<'_>) {
        let [top, middle, bottom] =
            Layout::vertical([Length(3), Min(0), Length(3)]).areas(frame.area());

        render_setup_header(frame, top, state);

        // 0: Input 0 Header (Filename)
        // 1: INPUT <-- Filename
        // 2: Input 1 Header (passphrase)
        // 3: INPUT <-- Config Unlock Passphrase
        // 4: Input 2 Header (passphrase)
        // 5: INPUT <-- New Unlock Passphrase
        // 6: Messages & Key Bindings
        let content: [Rect; 7] = Layout::vertical([
            Length(1),
            Length(2),
            Length(1),
            Length(2),
            Length(1),
            Length(2),
            Min(0),
        ])
        .areas(middle.inner(Margin::new(3, 2)));

        let [input0_prompt, input0_box] = Layout::horizontal([Length(2), Min(0)]).areas(content[1]);
        let [input1_prompt, input1_box] = Layout::horizontal([Length(2), Min(0)]).areas(content[3]);
        let [input2_prompt, input2_box] = Layout::horizontal([Length(2), Min(0)]).areas(content[5]);

        frame.render_widget(
            Block::bordered()
                .fg(COLOR_BORDER)
                .padding(Padding::proportional(1))
                .title(" Import profile backup "),
            middle,
        );

        frame.render_widget(
            Paragraph::new(Line::styled(
                "Backup file path:",
                Style::new().fg(COLOR_BORDER).bold(),
            )),
            content[0],
        );

        frame.render_widget(
            Paragraph::new(Span::styled(
                "> ",
                Style::new().fg(COLOR_SOFT_PURPLE).bold(),
            )),
            input0_prompt,
        );

        render_input(
            &self.filename,
            frame,
            input0_box,
            false,
            self.active_input == 0,
        );

        frame.render_widget(
            Paragraph::new(Line::styled(
                "Backup file passphrase (leave blank if none):",
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

        render_input(
            &self.config_unlock_passphrase,
            frame,
            input1_box,
            true,
            self.active_input == 1,
        );

        frame.render_widget(
            Paragraph::new(Line::styled(
                "New unlock code for this profile (leave blank for none):",
                Style::new().fg(COLOR_BORDER).bold(),
            )),
            content[4],
        );
        frame.render_widget(
            Paragraph::new(Span::styled(
                "> ",
                Style::new().fg(COLOR_SOFT_PURPLE).bold(),
            )),
            input2_prompt,
        );

        render_input(
            &self.new_unlock_passphrase,
            frame,
            input2_box,
            true,
            self.active_input == 2,
        );

        // Show any error messages
        let mut lines = Vec::new();
        if let Some(err) = &self.error_msg {
            lines.push(Line::styled(
                format!("ERROR: {err}"),
                Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
            ));
        }
        for msg in state.config_import.messages.iter() {
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
        lines.push(Line::default());

        if let Completion::CompletedOK = state.config_import.completed {
            lines.push(Line::styled(
                "You need to exit and reload OpenVTC to activate the imported configuration.",
                Style::new().fg(COLOR_DARK_GRAY),
            ));
            lines.push(Line::default());
            lines.push(Line::from(vec![
                Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" to exit", Style::new().fg(COLOR_TEXT_DEFAULT)),
            ]));
        } else {
            lines.push(Line::from(vec![
                Span::styled("[TAB]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" to select  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled("[ESC]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" to go back  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" to continue", Style::new().fg(COLOR_TEXT_DEFAULT)),
            ]));
        }
        frame.render_widget(Paragraph::new(lines), content[6]);

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

fn render_input(input: &Input, frame: &mut Frame, area: Rect, password: bool, active: bool) {
    // keep 1 for borders and 1 for cursor
    let width = area.width.max(3) - 3;
    let scroll = input.visual_scroll(width as usize);
    let text = if password {
        let mut s = String::new();
        for _ in 0..input.value().len() {
            s.push('*');
        }
        Span::styled(s, Style::new().fg(COLOR_SOFT_PURPLE))
    } else {
        Span::styled(
            input.value().to_string(),
            Style::new().fg(COLOR_SOFT_PURPLE),
        )
    };

    frame.render_widget(Paragraph::new(text).scroll((0, scroll as u16)), area);

    if active {
        let x = input.visual_cursor().max(scroll) - scroll;
        frame.set_cursor_position((area.x + x as u16, area.y))
    }
}
