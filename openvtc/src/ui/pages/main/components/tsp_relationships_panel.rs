//! The TSP Rev 3 relationships pane.
//!
//! Read-only status: one row per joined community, showing the state of the
//! §7.2.2 relationship the joining persona holds with that community's VTC. The
//! relationships themselves are formed and answered by the protocol layer
//! (`openvtc_core::tsp` on send; the SDK's transport adapter on receive); this
//! pane is the window onto whether each community connection is established.
//!
//! Kept deliberately separate from `relationships_panel` (the DIDComm pairwise
//! model) — a different keyspace, lifecycle and wire.

use super::panel::Panel;
use crate::colors::{
    COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
};
use crate::state_handler::{
    main_page::content::{ContentPanelState, TspRelationshipsState},
    state::ConnectionState,
};
use crate::ui::pages::main::keymap::{self, k};
use openvtc_core::display::truncate_did_centered;
use ratatui::{
    style::{Style, Stylize},
    text::{Line, Span},
};

/// Width a VTC / persona DID is centre-truncated to on a row.
const DID_WIDTH: usize = 44;

/// TSP Rev 3 relationships panel.
pub struct TspRelationshipsPanel;

impl Panel for TspRelationshipsPanel {
    fn render(
        &self,
        state: &ContentPanelState,
        _connection: &ConnectionState,
    ) -> Vec<Line<'static>> {
        render(&state.tsp_relationships, state.selected)
    }
}

/// Render the TSP relationships panel. `panel_focused` is whether the content
/// panel holds keyboard focus (so the cursor affordance is only drawn when the
/// keys that move it are actually routed here).
pub fn render(state: &TspRelationshipsState, panel_focused: bool) -> Vec<Line<'static>> {
    let label_style = Style::new().fg(COLOR_TEXT_DEFAULT);

    let mut lines = vec![
        Line::from(""),
        Line::from(" TSP Relationships").fg(COLOR_SUCCESS).bold(),
        Line::from(""),
        Line::from(Span::styled(
            "  The Trust Spanning Protocol relationship each community connection rests on.",
            Style::new().fg(COLOR_DARK_GRAY),
        )),
        Line::from(Span::styled(
            "  A Trust Task only reaches a community once its relationship is formed (§7.2.2).",
            Style::new().fg(COLOR_DARK_GRAY),
        )),
        Line::from(""),
    ];

    if state.rows.is_empty() {
        lines.push(Line::from(Span::styled(
            "  No TSP relationships yet — join a community to form one.",
            label_style,
        )));
        lines.push(Line::from(""));
        keymap::footer(&mut lines, "  ", &bindings(state));
        return lines;
    }

    for (i, row) in state.rows.iter().enumerate() {
        let selected = panel_focused && i == state.selected_index;
        let cursor = if selected { "▶ " } else { "  " };
        let state_color = if row.established {
            COLOR_SUCCESS
        } else if row.state == "None" {
            COLOR_DARK_GRAY
        } else {
            // Pending / Invite received — in flight.
            COLOR_ORANGE
        };

        lines.push(Line::from(vec![
            Span::styled(cursor, Style::new().fg(COLOR_SUCCESS)),
            Span::styled(row.community_label.clone(), label_style.bold()),
            Span::styled("  —  ", Style::new().fg(COLOR_DARK_GRAY)),
            Span::styled(row.state.clone(), Style::new().fg(state_color).bold()),
        ]));
        lines.push(Line::from(vec![
            Span::styled("      community: ", label_style),
            Span::styled(
                truncate_did_centered(&row.vtc_did, DID_WIDTH).into_owned(),
                Style::new().fg(COLOR_SOFT_PURPLE),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("      persona:   ", label_style),
            Span::styled(
                truncate_did_centered(&row.persona_did, DID_WIDTH).into_owned(),
                Style::new().fg(COLOR_SOFT_PURPLE),
            ),
        ]));
        lines.push(Line::from(""));
    }
    keymap::footer(&mut lines, "  ", &bindings(state));

    lines
}

/// The panel's keys: it is focusable, so it moves its cursor and goes back.
fn bindings(state: &TspRelationshipsState) -> Vec<keymap::Binding> {
    let mut keys = Vec::new();
    if state.rows.len() > 1 {
        keys.push(k("↑/↓", "move"));
    }
    keys.push(k("Esc", "back"));
    keys
}

impl crate::ui::pages::main::MainPage {
    /// TSP Relationships keys (#580): the panel draws a cursor when focused,
    /// so ↑/↓ move it, and Esc returns to the menu.
    pub(in crate::ui::pages::main) fn handle_tsp_key(
        &mut self,
        key: crossterm::event::KeyEvent,
    ) -> bool {
        use crate::state_handler::actions::Action;
        use crate::state_handler::main_page::MainPanel;
        use crossterm::event::KeyCode;
        let tsp = &self.props.main_page.content_panel.tsp_relationships;
        let (selected, count) = (tsp.selected_index, tsp.rows.len());
        let action = match key.code {
            KeyCode::Up if count > 1 => Action::TspSelect(selected.saturating_sub(1)),
            KeyCode::Down if count > 1 => Action::TspSelect((selected + 1).min(count - 1)),
            KeyCode::Esc => Action::MainPanelSwitch(MainPanel::MainMenu),
            _ => return false,
        };
        let _ = self.action_tx.send(action);
        true
    }
}
