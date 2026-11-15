use std::sync::Arc;

use crate::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS,
    COLOR_TEXT_DEFAULT, COLOR_WARNING_ACCESSIBLE_RED,
};
use crossterm::event::{Event, KeyCode, KeyEvent};
use openpgp_card::{Card, state::Open};
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
use secrecy::SecretString;
use tokio::sync::Mutex;
use tui_input::{Input, backend::crossterm::EventHandler};

use crate::{
    state_handler::{actions::Action, setup_sequence::SetupState},
    ui::pages::setup_flow::{
        SetupFlow,
        navigation::{SetupEvent, handle_nav_result, navigate},
        render_setup_header,
    },
};

#[derive(Clone, Default)]
pub struct TokenSelect {
    pub selected: usize,
    pub selected_token: Option<Arc<Mutex<Card<Open>>>>,
    pub ask_admin_pin: bool,
    pub token_admin_pin: Input,
}

impl TokenSelect {
    pub fn handle_key_event(state: &mut SetupFlow, key: KeyEvent) {
        match key.code {
            KeyCode::F(10) => {
                let _ = state.action_tx.send(Action::Exit);
            }
            KeyCode::Tab | KeyCode::Down if !state.token_select.ask_admin_pin => {
                let token_count = state.props.state.tokens.tokens.len();
                state.token_select.selected = (state.token_select.selected + 1) % (token_count + 1);
            }
            KeyCode::Up if !state.token_select.ask_admin_pin => {
                let token_count = state.props.state.tokens.tokens.len();
                if state.token_select.selected == 0 {
                    state.token_select.selected = token_count;
                } else {
                    state.token_select.selected -= 1;
                }
            }
            KeyCode::Char('r') | KeyCode::Char('R') if !state.token_select.ask_admin_pin => {
                let _ = state.action_tx.send(Action::GetTokens);
            }
            KeyCode::Esc if state.token_select.ask_admin_pin => {
                state.token_select.token_admin_pin.reset();
            }
            KeyCode::Enter => {
                if state.token_select.ask_admin_pin {
                    // Get Admin PIN from input
                    let admin_pin = if state.token_select.token_admin_pin.value().is_empty() {
                        SecretString::new("12345678".to_string().into())
                    } else {
                        SecretString::new(
                            state
                                .token_select
                                .token_admin_pin
                                .value()
                                .to_string()
                                .into(),
                        )
                    };
                    let token = if let Some(token) = &state.token_select.selected_token {
                        // Need to get ADMIN Pin from the user
                        let mut lock = match token.try_lock() {
                            Ok(lock) => lock,
                            Err(_) => {
                                let _ = state.action_tx.send(Action::Exit);
                                return;
                            }
                        };
                        let open_card = match lock.transaction() {
                            Ok(card) => card,
                            Err(_) => {
                                // Token likely unplugged - exit gracefully
                                let _ = state.action_tx.send(Action::Exit);
                                return;
                            }
                        };
                        match open_card.application_identifier() {
                            Ok(id) => id.ident(),
                            Err(_) => {
                                let _ = state.action_tx.send(Action::Exit);
                                return;
                            }
                        }
                    } else {
                        // No valid token selected - should not happen, exit gracefully
                        let _ = state.action_tx.send(Action::Exit);
                        return;
                    };
                    let _ = state.action_tx.send(Action::SetAdminPin(token, admin_pin));
                } else {
                    // Selected Token - Now get Admin PIN
                    // `selected` persists across state updates while the token
                    // list can shrink (unplug / refresh), so look it up safely.
                    match state
                        .props
                        .state
                        .tokens
                        .tokens
                        .get(state.token_select.selected)
                    {
                        Some(token) => {
                            state.token_select.selected_token = Some(token.clone());
                            state.token_select.ask_admin_pin = true;
                        }
                        None => {
                            state.token_select.selected_token = None;
                            let result = navigate(SetupEvent::TokenNoSelection, &state.props.state);
                            handle_nav_result(result, state);
                        }
                    }
                }
            }
            _ if state.token_select.ask_admin_pin => {
                state
                    .token_select
                    .token_admin_pin
                    .handle_event(&Event::Key(key));
            }
            _ => {}
        }
    }

    pub fn render(&self, state: &SetupState, frame: &mut Frame) {
        let [top, middle, bottom] =
            Layout::vertical([Length(3), Min(0), Length(3)]).areas(frame.area());

        render_setup_header(frame, top, state);

        if self.ask_admin_pin {
            // Need to get ADMIN Pin from the user
            let Some(token) = state.tokens.tokens.get(self.selected) else {
                return;
            };
            let mut lock = match token.try_lock() {
                Ok(lock) => lock,
                Err(_) => return,
            };
            let mut open_card = match lock.transaction() {
                Ok(card) => card,
                Err(_) => return,
            };
            let app_identifier = match open_card.application_identifier() {
                Ok(id) => id,
                Err(_) => return,
            };

            // 0: Selected Token
            // 1: Input 0 Header (ADMIN PIN)
            // 2: INPUT <-- ADMIN PIN
            // 3: Key Bindings
            let content: [Rect; 5] =
                Layout::vertical([Length(2), Length(2), Length(2), Length(2), Min(0)])
                    .areas(middle.inner(Margin::new(4, 2)));

            let [input0_prompt, input0_box] =
                Layout::horizontal([Length(2), Min(0)]).areas(content[3]);

            let block = Block::bordered()
                .fg(COLOR_BORDER)
                .padding(Padding::proportional(1))
                .title(" Step 3/6: Get admin PIN ");
            frame.render_widget(block, middle);

            frame.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled("Selected Card: ", Style::new().fg(COLOR_SUCCESS).bold()),
                    Span::styled(
                        app_identifier.ident(),
                        Style::new().fg(COLOR_TEXT_DEFAULT).bold(),
                    ),
                    Span::styled(" Manufacturer: ", Style::new().fg(COLOR_SUCCESS).bold()),
                    Span::styled(
                        app_identifier.manufacturer_name(),
                        Style::new().fg(COLOR_TEXT_DEFAULT).bold(),
                    ),
                    Span::styled(" Cardholder Name: ", Style::new().fg(COLOR_SUCCESS).bold()),
                    Span::styled(
                        open_card.cardholder_name().unwrap_or("NOT SET".to_string()),
                        Style::new().fg(COLOR_TEXT_DEFAULT).bold(),
                    ),
                ])),
                content[0],
            );

            frame.render_widget(
                Paragraph::new(Line::from(vec![Span::styled(
                    "Enter the admin PIN for the selected token:",
                    Style::new().fg(COLOR_BORDER).bold(),
                )])),
                content[1],
            );

            frame.render_widget(
                Paragraph::new(Line::from(vec![Span::styled(
                    "Leave blank for default PIN '12345678'.",
                    Style::new().fg(COLOR_DARK_GRAY),
                )])),
                content[2],
            );

            frame.render_widget(
                Paragraph::new(Span::styled(
                    "> ",
                    Style::new().fg(COLOR_SOFT_PURPLE).bold(),
                )),
                input0_prompt,
            );
            render_input(&self.token_admin_pin, frame, input0_box);

            frame.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled("[ESC]", Style::new().fg(COLOR_BORDER).bold()),
                    Span::styled(" to go back  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                    Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
                    Span::styled(" to continue", Style::new().fg(COLOR_TEXT_DEFAULT)),
                ])),
                content[4],
            );
        } else {
            let block = Block::bordered()
                .fg(COLOR_BORDER)
                .padding(Padding::proportional(1))
                .title(" Step 2/6: Select hardware token ");

            let mut lines = Vec::new();
            if !state.tokens.messages.is_empty() {
                for msg in state.tokens.messages.iter() {
                    lines.push(Line::styled(
                        format!("ERROR: {msg}"),
                        Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED).italic(),
                    ));
                }
                lines.push(Line::default());
            }

            if state.tokens.tokens.is_empty() {
                lines.push(Line::styled(
                    "No OpenPGP-compatible hardware tokens were detected on your system.",
                    Style::new().fg(COLOR_ORANGE),
                ));
                lines.push(Line::default());
                lines.push(Line::styled(
                    "If you have a token, ensure it is properly plugged in and recognised by your system, then rescan.",
                    Style::new().fg(COLOR_TEXT_DEFAULT).bold(),
                ));
                lines.push(Line::default());
                lines.push(Line::from(vec![
                    Span::styled("[R]", Style::new().fg(COLOR_BORDER).bold()),
                    Span::styled(
                        " to rescan for tokens  |  ",
                        Style::new().fg(COLOR_TEXT_DEFAULT),
                    ),
                    Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
                    Span::styled(
                        " to continue without a token",
                        Style::new().fg(COLOR_TEXT_DEFAULT),
                    ),
                ]));
                frame.render_widget(
                    Paragraph::new(lines).block(block).wrap(Wrap { trim: true }),
                    middle,
                );
            } else {
                // Show tokens
                lines.push(Line::styled(
                    "The following hardware tokens were detected from your system.",
                    Style::new().fg(COLOR_DARK_GRAY),
                ));
                lines.push(Line::default());
                lines.push(Line::styled(
                    "Select one to securely store your keys, or continue without a token:",
                    Style::new().fg(COLOR_BORDER).bold(),
                ));
                lines.push(Line::default());
                for (index, card) in state.tokens.tokens.iter().enumerate() {
                    let mut lock = match card.try_lock() {
                        Ok(lock) => lock,
                        Err(_) => continue,
                    };
                    let mut open_card = match lock.transaction() {
                        Ok(card) => card,
                        Err(_) => {
                            continue;
                        }
                    };
                    let app_identifier = match open_card.application_identifier() {
                        Ok(id) => id,
                        Err(_) => continue,
                    };
                    if index == self.selected {
                        // Highlight selected
                        lines.push(Line::from(vec![
                            Span::styled("[✓] Card: ", Style::new().fg(COLOR_SUCCESS).bold()),
                            Span::styled(
                                app_identifier.ident(),
                                Style::new().fg(COLOR_SOFT_PURPLE).bold(),
                            ),
                            Span::styled(" Manufacturer: ", Style::new().fg(COLOR_SUCCESS).bold()),
                            Span::styled(
                                app_identifier.manufacturer_name(),
                                Style::new().fg(COLOR_SOFT_PURPLE).bold(),
                            ),
                            Span::styled(
                                " CardHolder Name: ",
                                Style::new().fg(COLOR_SUCCESS).bold(),
                            ),
                            Span::styled(
                                open_card.cardholder_name().unwrap_or("NOT SET".to_string()),
                                Style::new().fg(COLOR_SOFT_PURPLE).bold(),
                            ),
                        ]));
                    } else {
                        lines.push(Line::from(vec![
                            Span::styled("[ ] Card: ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                            Span::styled(
                                app_identifier.ident(),
                                Style::new().fg(COLOR_SOFT_PURPLE),
                            ),
                            Span::styled(" Manufacturer: ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                            Span::styled(
                                app_identifier.manufacturer_name(),
                                Style::new().fg(COLOR_SOFT_PURPLE),
                            ),
                            Span::styled(" CardHolder Name: ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                            Span::styled(
                                open_card.cardholder_name().unwrap_or("NOT SET".to_string()),
                                Style::new().fg(COLOR_SOFT_PURPLE),
                            ),
                        ]));
                    }
                }
                if self.selected >= state.tokens.tokens.len() {
                    lines.push(Line::styled(
                        "[✓] Do not use a hardware token",
                        Style::new().fg(COLOR_SUCCESS).bold(),
                    ));
                } else {
                    lines.push(Line::styled(
                        "[ ] Do not use a hardware token",
                        Style::new().fg(COLOR_TEXT_DEFAULT),
                    ));
                }

                lines.push(Line::default());
                lines.push(Line::from(vec![
                    Span::styled("[R]", Style::new().fg(COLOR_BORDER).bold()),
                    Span::styled(
                        " to rescan for tokens  |  ",
                        Style::new().fg(COLOR_TEXT_DEFAULT),
                    ),
                    Span::styled("[TAB]", Style::new().fg(COLOR_BORDER).bold()),
                    Span::styled(" to select  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                    Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
                    Span::styled(" to continue", Style::new().fg(COLOR_TEXT_DEFAULT)),
                ]));

                frame.render_widget(
                    Paragraph::new(lines).block(block).wrap(Wrap { trim: true }),
                    middle,
                );
            }
        }

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
    let mut s = String::new();
    for _ in 0..input.value().len() {
        s.push('*');
    }
    let text = Span::styled(s, Style::new().fg(COLOR_SOFT_PURPLE));

    frame.render_widget(Paragraph::new(text).scroll((0, scroll as u16)), area);

    let x = input.visual_cursor().max(scroll) - scroll;
    frame.set_cursor_position((area.x + x as u16, area.y))
}
