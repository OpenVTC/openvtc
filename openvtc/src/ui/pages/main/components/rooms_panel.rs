//! Rooms panel — a community's data rooms, opened from the Communities panel with `o`.
//!
//! One list: every room the community has offered this persona, and where each stands
//! — the community's record (`vtc/rooms/memberships/list`) beside the member's VTA's
//! custody (`rooms/keys/list`), read the way the member portal and `pnm` read them, so
//! all three show the same thing.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::style::Style;
use ratatui::text::{Line, Span};

use crate::colors::{
    COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT, COLOR_WARNING_ACCESSIBLE_RED,
};
use crate::state_handler::main_page::content::ContentPanelState;
use crate::state_handler::main_page::rooms::{AcceptStep, RoomsPhase, Severity, Status};
use crate::state_handler::main_page::shorten_did;
use crate::state_handler::state::ConnectionState;
use openvtc_core::community_rooms::{self, Standing};

use super::panel::Panel;
use crate::ui::pages::main::keymap::{self, k};

pub struct RoomsPanel;

fn dim(text: impl Into<String>) -> Span<'static> {
    Span::styled(text.into(), Style::default().fg(COLOR_DARK_GRAY))
}

fn text(text: impl Into<String>) -> Span<'static> {
    Span::styled(text.into(), Style::default().fg(COLOR_TEXT_DEFAULT))
}

fn push_status(lines: &mut Vec<Line<'static>>, status: &Status) {
    let style = super::status::severity_style(status.severity);
    for part in super::status::wrap_text(
        &status.text,
        super::status::content_width().saturating_sub(6).max(20),
    ) {
        lines.push(Line::from(Span::styled(format!("    {part}"), style)));
    }
}

fn standing_style(standing: Standing) -> Style {
    Style::default().fg(match standing {
        Standing::Joined => COLOR_SUCCESS,
        Standing::Offered | Standing::Unfinished | Standing::Suspended => COLOR_ORANGE,
        Standing::NeedsReadmission => COLOR_WARNING_ACCESSIBLE_RED,
        Standing::Admitted | Standing::Removed => COLOR_DARK_GRAY,
    })
}

impl Panel for RoomsPanel {
    fn render(
        &self,
        state: &ContentPanelState,
        _connection: &ConnectionState,
    ) -> Vec<Line<'static>> {
        let Some(view) = &state.rooms.view else {
            return vec![Line::from("no rooms view open")];
        };
        let mut lines = vec![Line::from(vec![
            Span::styled(
                format!("  Data rooms — {}", view.community),
                Style::default().fg(COLOR_TEXT_DEFAULT).bold(),
            ),
            dim(format!("    as {}", shorten_did(&view.me, 40))),
        ])];

        match &view.phase {
            RoomsPhase::Loading => {
                lines.push(Line::from(""));
                lines.push(Line::from(dim(
                    "    asking the community which rooms it has offered you…",
                )));
                // Why it is not asking yet (a busy lane), when it is not.
                if let Some(status) = &view.status {
                    lines.push(Line::from(""));
                    push_status(&mut lines, status);
                }
                lines.push(Line::from(""));
                keymap::footer(&mut lines, "    ", &bindings(view));
                return lines;
            }
            RoomsPhase::Failed(detail) => {
                lines.push(Line::from(""));
                push_status(
                    &mut lines,
                    &Status {
                        text: detail.clone(),
                        severity: Severity::Error,
                    },
                );
                lines.push(Line::from(""));
                keymap::footer(&mut lines, "    ", &bindings(view));
                return lines;
            }
            RoomsPhase::Loaded => {}
        }

        lines.push(Line::from(""));
        let rows = view.rows();
        if rows.is_empty() {
            lines.push(Line::from(dim(
                "    The community has offered you no rooms.",
            )));
        } else {
            lines.push(Line::from(dim(format!(
                "      {:<30}{:<12}{:<20}{}",
                "ROOM", "TIER", "ACCESS", "STANDING"
            ))));
            for (i, row) in rows.iter().enumerate() {
                let selected = i == view.selected;
                let name_style = if selected {
                    Style::default().fg(COLOR_SUCCESS).bold()
                } else {
                    Style::default().fg(COLOR_TEXT_DEFAULT)
                };
                let actions: Vec<String> =
                    row.room.actions.0.iter().map(ToString::to_string).collect();
                let label: String = community_rooms::display_label(&row.room)
                    .chars()
                    .take(28)
                    .collect();
                lines.push(Line::from(vec![
                    Span::raw(if selected { "    ▸ " } else { "      " }),
                    Span::styled(format!("{label:<30}"), name_style),
                    text(format!("{:<12}", row.room.visibility.to_string())),
                    text(format!("{:<20}", actions.join(", "))),
                    Span::styled(row.standing.label(), standing_style(row.standing)),
                    dim(community_rooms::RoomCondition::of(&row.room)
                        .label()
                        .map(|l| format!(" · {l}"))
                        .unwrap_or_default()),
                ]));
                if selected {
                    if let Some(d) = &row.room.description {
                        lines.push(Line::from(dim(format!(
                            "        {}",
                            crate::state_handler::main_page::sanitize_display(d.as_str(), 300)
                        ))));
                    }
                    lines.push(Line::from(dim(format!(
                        "        {}",
                        shorten_did(row.room.room_id.as_str(), 60)
                    ))));
                    let explain = match row.standing {
                        Standing::Unfinished => row.room.repeat_accept_until.map(|u| {
                            format!(
                                "Accepted on another surface (or interrupted); finish joining \
                                 here by {}.",
                                u.format("%Y-%m-%d %H:%M UTC")
                            )
                        }),
                        Standing::NeedsReadmission => Some(
                            "Admitted, but your VTA never joined and the community no longer \
                             keeps what it needs: ask an administrator to re-admit you."
                                .to_string(),
                        ),
                        Standing::Admitted => Some(
                            "Admitted — whether your VTA holds its keys can't be read without \
                             your VTA."
                                .to_string(),
                        ),
                        _ => None,
                    };
                    if let Some(e) = explain {
                        lines.push(Line::from(dim(format!("        {e}"))));
                    }
                    if let Some(e) = community_rooms::RoomCondition::of(&row.room).explain() {
                        lines.push(Line::from(dim(format!("        {e}"))));
                    }
                }
            }
        }

        if let Some(e) = &view.held_error {
            lines.push(Line::from(""));
            lines.push(Line::from(dim(format!("    {e}"))));
        }
        if let Some(flow) = &view.accept {
            let step = match flow.step {
                AcceptStep::Collecting => "collecting the offer",
                AcceptStep::Preparing => "your VTA is storing credentials and the KeyPackage",
                AcceptStep::Accepting => "accepting with the community",
                AcceptStep::Joining => "your VTA is joining from the Welcome",
            };
            lines.push(Line::from(""));
            lines.push(Line::from(dim(format!("    Accepting — {step}…"))));
        }
        if let Some(status) = &view.status {
            lines.push(Line::from(""));
            push_status(&mut lines, status);
        }

        lines.push(Line::from(""));
        keymap::footer(&mut lines, "    ", &bindings(view));
        lines.push(Line::from(dim(
            "    The same rooms, in the same state, as your member portal and pnm show.",
        )));
        lines
    }
}

/// The Rooms panel's keys: navigate, accept, refresh, close.
/// Whether the highlighted room can be accepted now.
fn acceptable(view: &crate::state_handler::main_page::rooms::RoomsView) -> bool {
    view.selected_row().is_some_and(|r| {
        r.standing.acceptable() && community_rooms::RoomCondition::of(&r.room).admits()
    }) && view.accept.is_none()
}

/// The view's keys, gated as [`rooms_key`] gates them.
fn bindings(view: &crate::state_handler::main_page::rooms::RoomsView) -> Vec<keymap::Binding> {
    let mut keys = Vec::new();
    if matches!(view.phase, RoomsPhase::Loaded) {
        if !view.rooms.is_empty() {
            keys.push(k("↑/↓ or j/k", "move"));
        }
        if acceptable(view) {
            keys.push(k("Enter/a", "accept"));
        }
        keys.push(k("r", "refresh"));
    } else {
        keys.push(k("r", "retry"));
    }
    keys.push(k("Esc", "back"));
    keys
}

pub(super) fn rooms_key(
    key: KeyEvent,
    view: &crate::state_handler::main_page::rooms::RoomsView,
) -> Option<crate::state_handler::actions::RoomsAction> {
    use crate::state_handler::actions::RoomsAction as R;
    let last = view.rooms.len().saturating_sub(1);
    let listed = matches!(view.phase, RoomsPhase::Loaded) && !view.rooms.is_empty();
    Some(match key.code {
        KeyCode::Esc => R::Back,
        KeyCode::Char('r') => R::Refresh,
        KeyCode::Up | KeyCode::Char('k') if listed => R::Select(view.selected.saturating_sub(1)),
        KeyCode::Down | KeyCode::Char('j') if listed => R::Select((view.selected + 1).min(last)),
        KeyCode::Enter | KeyCode::Char('a') if acceptable(view) => R::Accept,
        _ => return None,
    })
}
