//! Content panel — the right-hand pane that draws the selected menu's panel,
//! plus the Help view's key handling.

use crate::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
    COLOR_WARNING_ACCESSIBLE_RED,
};
use crate::state_handler::actions::Action;
use crate::state_handler::main_page::MainPanel;
use crate::state_handler::{
    main_page::{
        ActivityLogEntry,
        content::ContentPanelState,
        menu::{MainMenu, MenuPanelState},
    },
    state::{ConnectionState, MediatorStatus},
};
use crate::ui::pages::main::MainPage;
use crate::ui::pages::main::copy_to_clipboard;
use crate::ui::pages::main::keymap::{self, k};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::{Alignment, Margin, Rect},
    style::{Style, Stylize},
    symbols::merge::MergeStrategy,
    text::{Line, Span},
    widgets::{
        Block, BorderType, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Wrap,
    },
};

use super::{
    communities_panel::CommunitiesPanel, credentials_panel::CredentialsPanel,
    inbox_panel::InboxPanel, panel::Panel, relationships_panel::RelationshipsPanel,
    settings_panel::SettingsPanel, vta_panel::VtaPanel,
};

// ****************************************************************************
// Render the Content panel
// ****************************************************************************
impl ContentPanelState {
    /// Render the content panel based on current state.
    ///
    /// Applies a single central `Wrap { trim: false }` so every subview gets
    /// right-edge wrapping for free, and a vertical `scroll_offset` driven by
    /// the parent so PageUp/PageDown/Home/End work uniformly across panels.
    ///
    /// Returns the maximum reachable scroll offset given the current content
    /// and inner panel height, so the caller can clamp its stored offset.
    #[allow(clippy::too_many_arguments)]
    pub fn render(
        &self,
        frame: &mut Frame,
        rect: Rect,
        menu: &MenuPanelState,
        connection: &ConnectionState,
        activity_log: &std::collections::VecDeque<std::sync::Arc<ActivityLogEntry>>,
        logs_selected: usize,
        logs_detail_view: bool,
        scroll_offset: u16,
    ) -> u16 {
        let content_block = if self.selected {
            Block::bordered()
                .merge_borders(MergeStrategy::Fuzzy)
                .border_type(BorderType::Double)
                .fg(COLOR_SUCCESS)
                .title("Content")
        } else {
            Block::bordered()
                .merge_borders(MergeStrategy::Fuzzy)
                .fg(COLOR_BORDER)
                .title("Content")
        };

        // Record this frame's usable content width before any panel renders, so
        // status messages wrap to the terminal rather than a fixed 76 columns.
        // Two columns come off for the panel's own leading indentation.
        super::status::set_wrap_width(content_block.inner(rect).width.saturating_sub(2) as usize);
        // And its height, for the one thing that cannot be scrolled into view.
        super::status::set_content_height(content_block.inner(rect).height as usize);

        let panel: Option<Box<dyn Panel>> = match menu.selected_menu {
            MainMenu::Communities => {
                if self.capabilities.view.is_some() {
                    Some(Box::new(super::capabilities_panel::CapabilitiesPanel))
                } else if self.repos.view.is_some() {
                    Some(Box::new(super::repos_panel::ReposPanel))
                } else if self.rooms.view.is_some() {
                    Some(Box::new(super::rooms_panel::RoomsPanel))
                } else if self.elections.view.is_some() {
                    Some(Box::new(super::elections_panel::ElectionsPanel))
                } else {
                    Some(Box::new(CommunitiesPanel))
                }
            }
            MainMenu::Inbox => Some(Box::new(InboxPanel)),
            MainMenu::Relationships => Some(Box::new(RelationshipsPanel)),
            MainMenu::Credentials => Some(Box::new(CredentialsPanel)),
            MainMenu::Settings => Some(Box::new(SettingsPanel)),
            MainMenu::Vta => Some(Box::new(VtaPanel)),
            MainMenu::TspRelationships => Some(Box::new(
                super::tsp_relationships_panel::TspRelationshipsPanel,
            )),
            MainMenu::Identity => Some(Box::new(super::identity_panel::IdentityPanel)),
            MainMenu::Vetting => Some(Box::new(super::vetting_panel::VettingPanel)),
            _ => None,
        };

        let lines = if let Some(p) = panel {
            p.render(self, connection)
        } else {
            match menu.selected_menu {
                MainMenu::Logs => {
                    use super::logs_panel;
                    let mut logs_state = self.logs.clone();
                    logs_state.selected_index = logs_selected;
                    logs_state.detail_view = logs_detail_view;
                    logs_panel::render(&logs_state, activity_log)
                }
                MainMenu::Help => render_status_help(
                    &self.settings,
                    &self.inbox,
                    &self.relationships,
                    &self.credentials,
                    connection,
                ),
                MainMenu::Quit => {
                    vec![
                        Line::from(""),
                        Line::from("Press Enter in the menu, or F10 anywhere, to quit.")
                            .fg(COLOR_WARNING_ACCESSIBLE_RED),
                    ]
                }
                // Covered by the Panel trait above; included for exhaustiveness.
                _ => vec![],
            }
        };

        // Block borders occupy one column/row on each side.
        let inner_width = rect.width.saturating_sub(2);
        let inner_height = rect.height.saturating_sub(2);

        // Approximate the number of visual rows after wrapping at `inner_width`.
        // Ratatui's `Paragraph::line_count` is gated behind an unstable feature,
        // so we fall back to a character-count-based estimate. For the content
        // we show here (ASCII DIDs, JSON, labels) this matches actual wrap
        // behavior closely enough to drive PageDown clamping and the scrollbar.
        let total_lines = wrapped_line_count(&lines, inner_width);
        let max_scroll = total_lines.saturating_sub(inner_height);
        let offset = scroll_offset.min(max_scroll);

        frame.render_widget(
            Paragraph::new(lines)
                .alignment(Alignment::Left)
                .wrap(Wrap { trim: false })
                .scroll((offset, 0))
                .block(content_block),
            rect,
        );

        // Only draw the scrollbar when there is content beyond the viewport.
        if max_scroll > 0 {
            let mut sb_state = ScrollbarState::new(total_lines as usize)
                .viewport_content_length(inner_height as usize)
                .position(offset as usize);
            frame.render_stateful_widget(
                Scrollbar::new(ScrollbarOrientation::VerticalRight)
                    .begin_symbol(None)
                    .end_symbol(None),
                rect.inner(Margin {
                    horizontal: 0,
                    vertical: 1,
                }),
                &mut sb_state,
            );
        }

        max_scroll
    }
}

/// Approximate how many visual rows `lines` will occupy after wrapping at
/// `width` columns. Counts characters per line (not unicode display width) —
/// close enough for ASCII-heavy content (DIDs, JSON, settings), and only used
/// to bound scroll offset and size the scrollbar thumb.
fn wrapped_line_count(lines: &[Line<'_>], width: u16) -> u16 {
    if width == 0 {
        return lines.len().try_into().unwrap_or(u16::MAX);
    }
    let w = width as usize;
    let total: usize = lines
        .iter()
        .map(|line| {
            let len: usize = line.iter().map(|s| s.content.chars().count()).sum();
            if len == 0 { 1 } else { len.div_ceil(w) }
        })
        .sum();
    total.try_into().unwrap_or(u16::MAX)
}

/// Render the combined status + help panel.
fn render_status_help(
    settings: &crate::state_handler::main_page::content::SettingsState,
    inbox: &crate::state_handler::main_page::content::InboxState,
    relationships: &crate::state_handler::main_page::content::RelationshipsState,
    credentials: &crate::state_handler::main_page::content::CredentialsState,
    connection: &ConnectionState,
) -> Vec<Line<'static>> {
    let label_style = Style::new().fg(COLOR_TEXT_DEFAULT);
    let value_style = Style::new().fg(COLOR_SOFT_PURPLE);

    let mut lines = vec![
        Line::from(""),
        Line::from(" Status").fg(COLOR_SUCCESS).bold(),
        Line::from(""),
    ];

    // Show clipboard/status feedback if present
    if let Some(msg) = &settings.status_message {
        super::status::push_status(&mut lines, msg, "  ");
        lines.push(Line::from(""));
    }

    let hint_style = Style::new().fg(COLOR_DARK_GRAY);

    // Verified agent name, above the DID it belongs to.
    if let Some(agent_name) = &settings.persona_agent_name {
        lines.push(Line::from(vec![
            Span::styled("  Agent name:   ", label_style),
            Span::styled(agent_name.clone(), value_style),
        ]));
    }

    // Persona DID (full) with copy hotkey
    lines.push(Line::from(vec![
        Span::styled("  Persona DID:  ", label_style),
        Span::styled(settings.persona_did.clone(), value_style),
        Span::styled("  [1] copy", hint_style),
    ]));

    // Mediator DID (full) with copy hotkey
    lines.push(Line::from(vec![
        Span::styled("  Mediator DID: ", label_style),
        Span::styled(settings.mediator_did.clone(), value_style),
        Span::styled("  [2] copy", hint_style),
    ]));

    // Protection type
    lines.push(Line::from(vec![
        Span::styled("  Protection:   ", label_style),
        Span::styled(settings.protection_type.clone(), value_style),
    ]));

    lines.push(Line::from(""));

    // Counts
    let rel_count = relationships.relationships.len();
    let task_count = inbox.tasks.len();
    let vrc_received = credentials.received.len();
    let vrc_issued = credentials.issued.len();

    lines.push(Line::from(vec![
        Span::styled("  Relationships: ", label_style),
        Span::styled(rel_count.to_string(), value_style),
        Span::styled("    Tasks: ", label_style),
        Span::styled(task_count.to_string(), value_style),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  VRCs received: ", label_style),
        Span::styled(vrc_received.to_string(), value_style),
        Span::styled("    VRCs issued: ", label_style),
        Span::styled(vrc_issued.to_string(), value_style),
    ]));

    lines.push(Line::from(""));

    // Connection status
    let conn_line = match &connection.status {
        MediatorStatus::Connected => Line::from(vec![
            Span::styled("  Connection:   ", label_style),
            Span::styled("Connected", Style::new().fg(COLOR_SUCCESS)),
        ]),
        MediatorStatus::Connecting => Line::from(vec![
            Span::styled("  Connection:   ", label_style),
            Span::styled("Connecting...", label_style),
        ]),
        MediatorStatus::Failed(failure) => {
            // Which class of failure, the error itself, and what to do about
            // it (R6.4, #585) — then `r` retries from here.
            lines.push(Line::from(vec![
                Span::styled("  Connection:   ", label_style),
                Span::styled(
                    failure.short(),
                    Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED).bold(),
                ),
            ]));
            super::status::push_error(&mut lines, &failure.reason, "                ");
            Line::from(Span::styled(
                format!("                {}", failure.class.remedy()),
                Style::new().fg(COLOR_DARK_GRAY),
            ))
        }
        MediatorStatus::Initializing(step) => Line::from(vec![
            Span::styled("  Connection:   ", label_style),
            Span::styled(format!("Initialising: {}", step), label_style),
        ]),
        MediatorStatus::Unknown => Line::from(vec![
            Span::styled("  Connection:   ", label_style),
            Span::styled("Not connected", Style::new().fg(COLOR_DARK_GRAY)),
        ]),
        MediatorStatus::NoActiveCommunity => Line::from(vec![
            Span::styled("  Connection:   ", label_style),
            Span::styled("No active community", Style::new().fg(COLOR_DARK_GRAY)),
        ]),
        MediatorStatus::PersonaOnline => Line::from(vec![
            Span::styled("  Connection:   ", label_style),
            Span::styled(
                "No community yet · persona online",
                Style::new().fg(COLOR_SUCCESS),
            ),
        ]),
    };
    lines.push(conn_line);

    // Git signing section — only shown when did-git-sign is configured for
    // this persona. The principal + ssh-ed25519 pair is what GitHub /
    // GitLab / etc. need: SSH public key in the host's signing-key
    // settings, and the principal in the local allowed_signers file.
    if let Some(info) = &settings.did_git_sign {
        lines.push(Line::from(""));
        lines.push(Line::from(" Git Signing").fg(COLOR_SUCCESS).bold());
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("  Principal:    ", label_style),
            Span::styled(info.did_key_id.clone(), value_style),
            Span::styled("  [3] copy", hint_style),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  SSH key:      ", label_style),
            Span::styled(info.ssh_public_key.clone(), value_style),
            Span::styled("  [4] copy", hint_style),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  Config:       ", label_style),
            Span::styled(info.config_path.clone(), value_style),
        ]));
        lines.push(Line::from(""));
        lines.push(
            Line::from("  Paste the SSH key into your git host's SSH keys page")
                .fg(COLOR_DARK_GRAY),
        );
        lines.push(
            Line::from("  with usage type 'Signing' to verify your signed commits.")
                .fg(COLOR_DARK_GRAY),
        );
    }

    // Keyboard shortcuts: the same tables the footer row and `?` use, so
    // this list cannot drift from the keys that work (#580).
    lines.push(Line::from(""));
    lines.push(Line::from(" Keyboard Shortcuts").fg(COLOR_SUCCESS).bold());
    lines.push(Line::from(""));
    let shortcut = |b: &keymap::Binding| {
        Line::from(vec![
            Span::styled(format!("  {:<12} ", b.key), Style::new().fg(COLOR_SUCCESS)),
            Span::styled(b.does.clone(), Style::new().fg(COLOR_TEXT_DEFAULT)),
        ])
    };
    lines.extend(keymap::global().iter().map(shortcut));
    lines.push(Line::from(""));
    lines.push(Line::from("  In the menu").fg(COLOR_DARK_GRAY));
    lines.extend(keymap::menu().iter().map(shortcut));
    lines.push(Line::from(""));
    lines.push(
        Line::from("  Every panel lists its own keys at its foot; ? shows them all.")
            .fg(COLOR_DARK_GRAY),
    );
    lines.push(Line::from("  Ctrl+C always quits.").fg(COLOR_DARK_GRAY));
    lines.push(Line::from(""));
    keymap::footer(&mut lines, " ", &help_bindings(settings));

    lines
}

/// The Help / Status view's own keys.
fn help_bindings(
    settings: &crate::state_handler::main_page::content::SettingsState,
) -> Vec<keymap::Binding> {
    let mut keys = vec![
        k("r", "reconnect messaging"),
        k("1", "copy persona DID"),
        k("2", "copy mediator DID"),
    ];
    if settings.did_git_sign.is_some() {
        keys.push(k("3", "copy signing principal"));
        keys.push(k("4", "copy SSH key"));
    }
    keys.push(k("Esc", "back"));
    keys
}

impl MainPage {
    pub(in crate::ui::pages::main) fn handle_help_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            // Retry messaging: the reconnect the Settings mediator row also
            // offers (#585).
            KeyCode::Char('r') => {
                let _ = self.action_tx.send(Action::Settings(
                    crate::state_handler::actions::SettingsAction::ReconnectMediator,
                ));
                true
            }
            KeyCode::Char('1') => {
                // Copy persona DID to clipboard
                let did = self
                    .props
                    .main_page
                    .content_panel
                    .settings
                    .persona_did
                    .clone();
                copy_to_clipboard(&did, "Persona DID", &self.action_tx);
                true
            }
            KeyCode::Char('2') => {
                // Copy mediator DID to clipboard
                let did = self
                    .props
                    .main_page
                    .content_panel
                    .settings
                    .mediator_did
                    .clone();
                copy_to_clipboard(&did, "Mediator DID", &self.action_tx);
                true
            }
            KeyCode::Char('3')
                if self
                    .props
                    .main_page
                    .content_panel
                    .settings
                    .did_git_sign
                    .is_some() =>
            {
                if let Some(info) = &self.props.main_page.content_panel.settings.did_git_sign {
                    copy_to_clipboard(
                        &info.did_key_id,
                        "Signing principal (DID#kid)",
                        &self.action_tx,
                    );
                }
                true
            }
            KeyCode::Char('4')
                if self
                    .props
                    .main_page
                    .content_panel
                    .settings
                    .did_git_sign
                    .is_some() =>
            {
                if let Some(info) = &self.props.main_page.content_panel.settings.did_git_sign {
                    copy_to_clipboard(
                        &info.ssh_public_key,
                        "SSH signing public key",
                        &self.action_tx,
                    );
                }
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
