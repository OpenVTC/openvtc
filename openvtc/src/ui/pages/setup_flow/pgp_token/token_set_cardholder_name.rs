use crate::colors::{
    COLOR_BORDER, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
    COLOR_WARNING_ACCESSIBLE_RED,
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
    widgets::{Block, Padding, Paragraph},
};
use tui_input::{Input, backend::crossterm::EventHandler};

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

#[derive(Clone, Debug, Default)]
pub struct TokenSetCardholderName {
    started: bool,
    pub(crate) name: Input,
}

impl TokenSetCardholderName {
    pub fn handle_key_event(state: &mut SetupFlow, key: KeyEvent) {
        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            KeyCode::Enter => {
                if !state.token_set_cardholder_name.started {
                    if state.token_set_cardholder_name.name.value().is_empty() {
                        let result = navigate(SetupEvent::TokenNameSkipped, &state.props.state);
                        handle_nav_result(result, state);
                    } else {
                        state.token_set_cardholder_name.started = true;
                        let _ = state.action_tx.send(Action::SetTokenName(
                            state.token_select.selected_token.clone(),
                            state.token_set_cardholder_name.name.value().to_string(),
                        ));
                    }
                } else if state.props.state.token_cardholder_name.completed {
                    let result = navigate(SetupEvent::TokenNameDone, &state.props.state);
                    handle_nav_result(result, state);
                }
            }
            KeyCode::Esc => {
                state.token_set_cardholder_name.name.reset();
            }
            _ => {
                // Handle text input
                state
                    .token_set_cardholder_name
                    .name
                    .handle_event(&Event::Key(key));
            }
        }
    }

    pub fn render(&self, state: &SetupState, frame: &mut Frame) {
        let [top, middle, bottom] =
            Layout::vertical([Length(3), Min(0), Length(3)]).areas(frame.area());

        render_setup_header(frame, top, state);

        frame.render_widget(
            Block::bordered()
                .fg(COLOR_BORDER)
                .padding(Padding::proportional(1))
                .title(" Set token cardholder name "),
            middle,
        );

        // 0: Input 0 Header
        // 1: INPUT
        // 2: Key Bindings
        let content: [Rect; 3] =
            Layout::vertical([Length(4), Length(2), Min(0)]).areas(middle.inner(Margin::new(2, 2)));

        let [input0_prompt, input0_box] = Layout::horizontal([Length(2), Min(0)]).areas(content[1]);

        frame.render_widget(
            Paragraph::new(vec![
                Line::styled(
                    "Enter your token cardholder name using the format below or leave blank to skip setting:",
                    Style::new().fg(COLOR_BORDER).bold(),
                ),
                Line::default(),
                Line::from(vec![
                    Span::styled("ℹ️ Note: Use the recommended format ", Style::new().fg(COLOR_ORANGE)),
                    Span::styled(
                        "LAST_NAME<<FIRST_NAME<OTHER<OTHER",
                        Style::new().fg(COLOR_ORANGE).bold(),
                    ),
                ]),
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

        render_input(&self.name, frame, input0_box);

        let mut lines = Vec::new();

        if !state.token_cardholder_name.messages.is_empty() {
            lines.push(Line::default());
            lines.push(Line::styled(
                "Cardholder name setup status",
                Style::new().fg(COLOR_BORDER).bold().underlined(),
            ));
            lines.push(Line::default());
        }

        for msg in state.token_cardholder_name.messages.iter() {
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
                Span::styled("[ESC]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" to clear input  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
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

        frame.render_widget(Paragraph::new(lines), content[2]);

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
    // keep 1 for borders and 1 for cursor
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
