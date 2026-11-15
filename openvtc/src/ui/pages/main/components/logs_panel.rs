//! Logs panel — scrollable activity log with selection and clipboard copy.

use super::status::wrap_text;
use crate::colors::{COLOR_DARK_GRAY, COLOR_SUCCESS, COLOR_TEXT_DEFAULT};
use crate::state_handler::actions::Action;
use crate::state_handler::main_page::MainPanel;
use crate::state_handler::main_page::{ActivityLogEntry, content::LogsState};
use crate::ui::pages::main::keymap::{self, k};
use crate::ui::pages::main::{MainPage, copy_to_clipboard};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    style::{Style, Stylize},
    text::{Line, Span},
};
use std::collections::VecDeque;
use std::sync::Arc;

/// Render the logs panel as a scrollable list of activity log entries.
///
/// Entries are shown newest-first with a selection highlight.
/// Hotkeys: Enter = view detail, c = copy selected, a = copy all, Esc = back.
pub fn render(
    logs_state: &LogsState,
    activity_log: &VecDeque<Arc<ActivityLogEntry>>,
) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from("")];

    let total = activity_log.len();
    lines.push(
        Line::from(format!(" Activity Log ({} entries)", total))
            .fg(COLOR_SUCCESS)
            .bold(),
    );
    lines.push(Line::from(""));

    if total == 0 {
        lines.push(Line::from("  No log entries yet.").fg(COLOR_DARK_GRAY));
        lines.push(Line::from(""));
        lines.push(
            Line::from("  Activity will appear here as you use the app.").fg(COLOR_DARK_GRAY),
        );
        lines.push(Line::from(""));
        keymap::footer(&mut lines, "  ", &[k("Esc", "back")]);
        return lines;
    }

    let entries: Vec<&Arc<ActivityLogEntry>> = activity_log.iter().rev().collect();

    // Detail view — show full text of the selected entry
    if logs_state.detail_view {
        if let Some(entry) = entries.get(logs_state.selected_index) {
            lines.push(
                Line::from(format!(
                    " Entry {} of {}",
                    logs_state.selected_index + 1,
                    total
                ))
                .fg(COLOR_DARK_GRAY),
            );
            lines.push(Line::from(""));

            // Show detail if available, otherwise show the summary
            let display_text = entry.detail.as_deref().unwrap_or(&entry.summary);

            // Word-wrap the full entry text at ~76 chars per line
            for wrapped_line in wrap_text(display_text, 76) {
                lines.push(Line::from(vec![Span::styled(
                    format!("  {}", wrapped_line),
                    Style::new().fg(COLOR_TEXT_DEFAULT),
                )]));
            }

            lines.push(Line::from(""));
            keymap::footer(
                &mut lines,
                "  ",
                &[k("Enter/Esc", "back to the list"), k("c", "copy")],
            );
        }
        return lines;
    }

    // List view — show entries with truncation
    for (i, entry) in entries.iter().enumerate() {
        let is_selected = i == logs_state.selected_index;
        let prefix = if is_selected { "▸ " } else { "  " };
        let style = if is_selected {
            Style::new().fg(COLOR_SUCCESS).bold()
        } else {
            Style::new().fg(COLOR_TEXT_DEFAULT)
        };

        // Truncate long entries for list display. Character-aligned — a summary
        // can carry peer-supplied text, and a byte cut would panic mid-scalar.
        let display = openvtc_core::display::truncate_did(&entry.summary, 80).into_owned();

        lines.push(Line::from(vec![Span::styled(
            format!("{}{}", prefix, display),
            style,
        )]));
    }

    lines.push(Line::from(""));
    let mut keys = Vec::new();
    if total > 1 {
        keys.push(k("↑/↓", "move"));
    }
    keys.extend([
        k("Enter", "view detail"),
        k("c", "copy selected"),
        k("a", "copy all"),
        k("Esc", "back"),
    ]);
    keymap::footer(&mut lines, "  ", &keys);

    lines
}

impl MainPage {
    pub(in crate::ui::pages::main) fn handle_logs_key(&mut self, key: KeyEvent) -> bool {
        let total = self.props.main_page.activity_log.len();

        // Detail view mode — Esc or Enter to close
        if self.logs_detail_view {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => {
                    self.logs_detail_view = false;
                    return true;
                }
                KeyCode::Char('c') if total > 0 => {
                    let entries: Vec<_> = self.props.main_page.activity_log.iter().rev().collect();
                    if let Some(entry) = entries.get(self.logs_selected) {
                        copy_to_clipboard(&entry.summary, "Log entry", &self.action_tx);
                    }
                    return true;
                }
                _ => return false,
            }
        }

        match key.code {
            KeyCode::Up if self.logs_selected > 0 => {
                self.logs_selected -= 1;
                true
            }
            KeyCode::Down if self.logs_selected + 1 < total => {
                self.logs_selected += 1;
                true
            }
            KeyCode::Enter if total > 0 => {
                self.logs_detail_view = true;
                true
            }
            KeyCode::Char('c') if total > 0 => {
                // Copy selected log entry to clipboard
                let entries: Vec<_> = self.props.main_page.activity_log.iter().rev().collect();
                if let Some(entry) = entries.get(self.logs_selected) {
                    copy_to_clipboard(&entry.summary, "Log entry", &self.action_tx);
                }
                true
            }
            KeyCode::Char('a') if total > 0 => {
                // Copy all log entries to clipboard
                let all_text: String = self
                    .props
                    .main_page
                    .activity_log
                    .iter()
                    .rev()
                    .map(|e| e.summary.as_str())
                    .collect::<Vec<_>>()
                    .join("\n");
                copy_to_clipboard(&all_text, "All log entries", &self.action_tx);
                true
            }
            KeyCode::Esc => {
                let _ = self
                    .action_tx
                    .send(Action::MainPanelSwitch(MainPanel::MainMenu));
                true
            }
            _ => false,
        }
    }
}
