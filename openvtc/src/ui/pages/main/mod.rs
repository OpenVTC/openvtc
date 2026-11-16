//! The main page: the menu, the content panel and the header, and the keys
//! that drive them.
//!
//! [`MainPage`] renders a read-only snapshot of `State` and turns key events
//! into `Action`s; it never mutates `State` or touches `Config`. Each panel's
//! drawing lives in `components/`, and its key handling in the panel's own
//! `keys.rs` (or beside its renderer). This file holds the page-level router
//! (`handle_key_event`: overlays first, then `?`, then the focused panel, then
//! the global keys), the overlays (create persona, agent names, add VIC,
//! community switcher) and the frame layout.
//!
//! Start with `handle_key_event` and `render`. Every view's keys are a
//! `keymap::Binding` table, and `keymap_tests.rs` checks each handler against
//! its footer.

use crate::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS,
    COLOR_TEXT_DEFAULT, COLOR_WARNING_ACCESSIBLE_RED,
};
use crate::ui::shared::Shared;
use crate::{
    state_handler::{
        actions::{Action, SettingsAction},
        main_page::{MainPageState, MainPanel, menu::MainMenu},
        state::{ConnectionState, MediatorStatus, State},
    },
    ui::component::{Component, ComponentRender},
};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use openvtc_core::display::truncate_did_centered;
use ratatui::{
    Frame,
    layout::{
        Alignment,
        Constraint::{Length, Min, Percentage},
        Layout,
    },
    style::Stylize,
    symbols::merge::MergeStrategy,
    text::{Line, Span},
    widgets::{Block, Paragraph},
};
use std::cell::Cell;
use tokio::sync::mpsc::UnboundedSender;

pub mod components;
pub(crate) mod confirm;
pub(crate) mod keymap;
#[cfg(test)]
mod keymap_tests;
mod secret_buffer;
pub(crate) mod text_input;

use secret_buffer::SecretBuffer;

/// MainPage handles the UI and the state of the primary openvtc interface
pub struct MainPage {
    /// Action sender
    pub action_tx: UnboundedSender<Action>,

    /// State Mapped MainPage Props
    props: Props,

    /// Secure passphrase buffer — never cloned into State, wiped when cleared
    passphrase_buffer: SecretBuffer,
    /// Secure confirm passphrase buffer — never cloned into State, wiped when cleared
    confirm_buffer: SecretBuffer,
    /// Logs panel selected index (local to UI, not in State)
    logs_selected: usize,
    /// Whether the logs panel is showing the detail view of a selected entry
    logs_detail_view: bool,
    /// Vertical scroll offset (in wrapped lines) applied to the content panel.
    /// Mutated by the key handler; clamped at render time.
    content_scroll: u16,
    /// Max reachable scroll offset from the most recent render — written by
    /// render (via `Cell`) and read by the key handler to clamp PageDown/End.
    content_scroll_max: Cell<u16>,
    /// Identifier for the active content view (menu + mode). When it changes
    /// across frames, we reset `content_scroll` so a fresh view starts at top.
    last_view_id: String,
    /// The focused view's keys, as its footer advertised them in the last
    /// frame (see [`keymap`]). What `?` lists, and what decides whether an
    /// unhandled key earns a hint.
    panel_keys: std::cell::RefCell<Vec<keymap::Binding>>,
    /// The `?` key overlay is open.
    help_open: bool,
    /// One line of feedback for a key that did nothing, shown in the footer
    /// row until the next key.
    key_feedback: Option<String>,
    /// The focused text field's cursor: the field, the text it held after
    /// the last edit, and the cursor (in characters). See [`text_input`].
    field_cursor: Option<(String, String, usize)>,
}

/// Number of lines to scroll per PageUp / PageDown press.
const CONTENT_PAGE: u16 = 10;

struct Props {
    main_page: Shared<MainPageState>,
    connection: Shared<ConnectionState>,
}

impl From<&std::sync::Arc<State>> for Props {
    fn from(state: &std::sync::Arc<State>) -> Self {
        Props {
            main_page: Shared::new(state, |s| &s.main_page),
            connection: Shared::new(state, |s| &s.connection),
        }
    }
}

impl Component for MainPage {
    fn new(state: &std::sync::Arc<State>, action_tx: UnboundedSender<Action>) -> Self
    where
        Self: Sized,
    {
        MainPage {
            action_tx: action_tx.clone(),
            // set the props
            props: Props::from(state),
            passphrase_buffer: SecretBuffer::default(),
            confirm_buffer: SecretBuffer::default(),
            logs_selected: 0,
            logs_detail_view: false,
            content_scroll: 0,
            content_scroll_max: Cell::new(0),
            last_view_id: view_id(&state.main_page),
            panel_keys: std::cell::RefCell::new(Vec::new()),
            help_open: false,
            key_feedback: None,
            field_cursor: None,
        }
        .move_with_state(state)
    }

    fn move_with_state(mut self, state: &std::sync::Arc<State>) -> Self
    where
        Self: Sized,
    {
        let new_id = view_id(&state.main_page);
        if new_id != self.last_view_id {
            // Switching menu or mode (e.g. list → detail) starts the new view
            // at the top, even if the previous view was scrolled down.
            self.content_scroll = 0;
            self.last_view_id = new_id;
        }
        self.props = Props::from(state);
        self
    }

    fn handle_key_event(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }
        self.key_feedback = None;

        // The key overlay is read, then dismissed by any key.
        if self.help_open {
            self.help_open = false;
            return;
        }

        // An open overlay owns all input; a key it does not take says so.
        if let Some(taken) = self.handle_overlay_key(key) {
            if !taken {
                self.key_feedback = Some(Self::unused(&key));
            }
            return;
        }
        // Ctrl+K opens the community switcher (R-C-7) from anywhere on the
        // main page.
        if key.code == KeyCode::Char('k') && key.modifiers.contains(KeyModifiers::CONTROL) {
            let _ = self.action_tx.send(Action::OpenCommunitySwitcher);
            return;
        }

        // `?` lists the focused view's keys — unless a text field has the
        // focus, where `?` is a character like any other.
        let content_selected = self.props.main_page.content_panel.selected;
        let typing = content_selected && self.typing();
        if key.code == KeyCode::Char('?') && !typing {
            self.help_open = true;
            return;
        }

        // Content panel key handling (when content panel is focused)
        if content_selected && self.handle_content_key_event(key) {
            return;
        }

        // A text field has the focus: a key the form did not take goes no
        // further — it must not switch panels or reach the menu (#578).
        if typing && key.code != KeyCode::F(10) {
            self.key_feedback = Some(format!(
                "{} does nothing in this field — Esc leaves it, ? lists the keys",
                keymap::describe(&key)
            ));
            return;
        }
        // Nor on an open vetting form: it takes Tab and the arrows only where
        // they do something, and one it does not take must not move the
        // focus off the form.
        if content_selected && self.vetting_form_open() && key.code != KeyCode::F(10) {
            self.key_feedback = Some(format!(
                "{} does nothing on this form — Esc leaves it, ? lists the keys",
                keymap::describe(&key)
            ));
            return;
        }

        let menu_focused = self.props.main_page.menu_panel.selected && !content_selected;
        match key.code {
            KeyCode::F(10) => {
                let _ = self.action_tx.send(Action::Exit);
            }
            KeyCode::Up | KeyCode::Char('k') if menu_focused => {
                let _ = self.action_tx.send(Action::MainMenuSelected(
                    self.props.main_page.menu_panel.selected_menu.prev(),
                ));
            }
            KeyCode::Down | KeyCode::Char('j') if menu_focused => {
                let _ = self.action_tx.send(Action::MainMenuSelected(
                    self.props.main_page.menu_panel.selected_menu.next(),
                ));
            }
            KeyCode::Tab | KeyCode::Left | KeyCode::Right => {
                let next_panel = match self.props.main_page.menu_panel.selected {
                    true => MainPanel::ContentPanel,
                    false => MainPanel::MainMenu,
                };
                let _ = self.action_tx.send(Action::MainPanelSwitch(next_panel));
            }
            KeyCode::Enter => {
                if self.props.main_page.menu_panel.selected_menu == MainMenu::Quit {
                    let _ = self.action_tx.send(Action::Exit);
                } else if self.props.main_page.menu_panel.selected {
                    let _ = self
                        .action_tx
                        .send(Action::MainPanelSwitch(MainPanel::ContentPanel));
                } else {
                    self.key_feedback = Some(Self::unused(&key));
                }
            }
            // PgUp/PgDn/Home/End scroll the content panel from wherever the
            // focus is; they are consumed above when it has the focus.
            KeyCode::PageUp | KeyCode::PageDown | KeyCode::Home | KeyCode::End => {}
            // A key that does nothing here says so, rather than vanishing.
            _ => self.key_feedback = Some(Self::unused(&key)),
        }
    }

    fn handle_paste_event(&mut self, text: &str) {
        use crate::state_handler::main_page::content::SettingsMode;

        // The add-VIC overlay owns paste while open — the operator pastes the VIC
        // JSON straight into the import field (checked before the panel guard).
        if self.props.main_page.add_vic.is_some() {
            let _ = self
                .action_tx
                .send(Action::AddVicPaste(text.trim().to_string()));
            return;
        }

        if !self.props.main_page.content_panel.selected {
            return;
        }

        let menu = self.props.main_page.menu_panel.selected_menu.clone();
        let trimmed = text.trim();

        // A ticket link pasted into the request form fills the whole form,
        // whichever field has the focus.
        if menu == MainMenu::Vetting
            && matches!(
                self.props.main_page.content_panel.vetting.mode,
                crate::state_handler::main_page::content::VettingMode::RequestVetter { .. }
            )
            && trimmed.to_ascii_lowercase().starts_with("vetting-ticket:")
        {
            let _ = self.action_tx.send(Action::Vetting(
                crate::state_handler::actions::VettingAction::PasteTicket(trimmed.to_string()),
            ));
            return;
        }
        // Every other text field: inserted at the cursor (#578).
        if self.paste_into_focused_field(trimmed) {
            return;
        }

        // Passphrase fields: the secure buffers take the paste. The path
        // field is a focused text field, handled above.
        if menu == MainMenu::Settings {
            {
                match &self.props.main_page.content_panel.settings.mode {
                    SettingsMode::ExportConfig { active_field, .. }
                    | SettingsMode::ImportConfig { active_field, .. } => {
                        if *active_field == 1 {
                            // Passphrase field — append to secure buffer
                            self.passphrase_buffer.push_str(trimmed);
                            let _ = self.action_tx.send(Action::Settings(
                                SettingsAction::PassphraseLen(self.passphrase_buffer.len()),
                            ));
                        } else {
                            // Export's confirmation field
                            self.confirm_buffer.push_str(trimmed);
                            let _ = self.action_tx.send(Action::Settings(
                                SettingsAction::ExportConfirmLen(self.confirm_buffer.len()),
                            ));
                        }
                    }
                    SettingsMode::ChangeProtection { active_field, .. } => {
                        if *active_field == 1 {
                            self.passphrase_buffer.push_str(trimmed);
                            let _ = self.action_tx.send(Action::Settings(
                                SettingsAction::ProtectionPassphraseLen(
                                    self.passphrase_buffer.len(),
                                ),
                            ));
                        } else if *active_field == 2 {
                            self.confirm_buffer.push_str(trimmed);
                            let _ = self.action_tx.send(Action::Settings(
                                SettingsAction::ProtectionConfirmLen(self.confirm_buffer.len()),
                            ));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

/// The grant form's focused text field: the DID, or the device's name.
fn grant_form_text(form: &crate::state_handler::main_page::content::GrantForm) -> &str {
    if form.field == 0 {
        &form.did
    } else {
        &form.name
    }
}

// ****************************************************************************
// Key map: `?` overlay and feedback
// ****************************************************************************
impl MainPage {
    /// Whether the focused view is a text field taking typing, by its own
    /// advertised keys.
    fn typing(&self) -> bool {
        self.panel_keys
            .borrow()
            .iter()
            .any(keymap::Binding::is_typing)
    }

    /// Whether the Vetting page has a form or view open over its lists.
    fn vetting_form_open(&self) -> bool {
        self.props.main_page.menu_panel.selected_menu == MainMenu::Vetting
            && !matches!(
                self.props.main_page.content_panel.vetting.mode,
                crate::state_handler::main_page::content::VettingMode::List
            )
    }

    /// Feedback for a key the focused view does not take.
    fn unused(key: &KeyEvent) -> String {
        format!(
            "{} does nothing here — ? lists this panel's keys",
            keymap::describe(key)
        )
    }

    /// The keys `?` lists: the focused view's, or the menu's.
    fn help_bindings(&self) -> (String, Vec<keymap::Binding>) {
        if self.props.main_page.content_panel.selected {
            (
                self.props.main_page.menu_panel.selected_menu.to_string(),
                self.panel_keys.borrow().clone(),
            )
        } else {
            ("Menu".to_string(), keymap::menu())
        }
    }

    /// The `?` overlay: the focused view's keys, then the keys that work
    /// everywhere — drawn from the same tables the footers are.
    fn render_help_overlay(&self, frame: &mut Frame) {
        use ratatui::layout::Rect;
        use ratatui::widgets::Clear;
        let (title, panel) = self.help_bindings();
        let global = keymap::global();
        let width_of = |b: &keymap::Binding| b.key.chars().count();
        let key_col = panel
            .iter()
            .chain(global.iter())
            .map(width_of)
            .max()
            .unwrap_or(4)
            .max(4);
        let row = |b: &keymap::Binding| {
            Line::from(vec![
                Span::styled(
                    format!("  {:<key_col$}  ", b.key),
                    ratatui::style::Style::default().fg(COLOR_SUCCESS),
                ),
                Span::styled(
                    b.does.clone(),
                    ratatui::style::Style::default().fg(COLOR_TEXT_DEFAULT),
                ),
            ])
        };
        let mut lines = vec![Line::from(format!(" {title}")).fg(COLOR_ORANGE).bold()];
        if panel.is_empty() {
            lines.push(Line::from("  (no keys of its own)").fg(COLOR_DARK_GRAY));
        }
        lines.extend(panel.iter().map(row));
        lines.push(Line::from(""));
        lines.push(Line::from(" Everywhere").fg(COLOR_ORANGE).bold());
        lines.extend(global.iter().map(row));
        lines.push(Line::from(""));
        lines.push(Line::from(" any key: close").fg(COLOR_DARK_GRAY));

        let area = frame.area();
        let content_w = lines.iter().map(Line::width).max().unwrap_or(20) as u16 + 4;
        let w = content_w.min(area.width);
        let h = (lines.len() as u16 + 2).min(area.height);
        let rect = Rect {
            x: area.x + (area.width - w) / 2,
            y: area.y + (area.height - h) / 2,
            width: w,
            height: h,
        };
        frame.render_widget(Clear, rect);
        frame.render_widget(
            Paragraph::new(lines).block(Block::bordered().fg(COLOR_SOFT_PURPLE).title(" Keys ")),
            rect,
        );
    }
}

// ****************************************************************************
// Content panel key event handling
// ****************************************************************************
impl MainPage {
    /// Handle key events when the content panel is focused.
    /// Returns true if the event was consumed.
    fn handle_content_key_event(&mut self, key: KeyEvent) -> bool {
        // A focused text field takes its editing keys — characters, ←/→,
        // Home/End, Backspace/Del and the editing chords — before anything
        // else, so ←/→ move the cursor instead of switching panels (#578). A
        // Ctrl or Alt chord the view lists as its own stays the view's.
        let chord = key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT);
        let listed = chord
            && self
                .panel_keys
                .borrow()
                .iter()
                .any(|b| !b.is_typing() && b.matches(&key));
        if !listed && self.edit_focused_field(&key) {
            return true;
        }

        // Vertical scroll for the content panel is handled centrally here,
        // before per-menu dispatch, so it works uniformly on every view
        // without conflicting with Up/Down selection bindings.
        match key.code {
            KeyCode::PageUp => {
                let max = self.content_scroll_max.get();
                let cur = self.content_scroll.min(max);
                self.content_scroll = cur.saturating_sub(CONTENT_PAGE);
                return true;
            }
            KeyCode::PageDown => {
                let max = self.content_scroll_max.get();
                self.content_scroll = self.content_scroll.saturating_add(CONTENT_PAGE).min(max);
                return true;
            }
            KeyCode::Home => {
                self.content_scroll = 0;
                return true;
            }
            KeyCode::End => {
                self.content_scroll = self.content_scroll_max.get();
                return true;
            }
            _ => {}
        }

        // A Ctrl or Alt chord is never a letter (#578): it reaches the view
        // only where the view lists that chord as one of its keys.
        //
        // Before the first frame nothing is advertised yet, and nothing is
        // gated.
        let advertised = !self.panel_keys.borrow().is_empty();
        if advertised
            && key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
            && matches!(key.code, KeyCode::Char(_))
            && !self
                .panel_keys
                .borrow()
                .iter()
                .any(|b| !b.is_typing() && b.matches(&key))
        {
            return false;
        }

        let menu = self.props.main_page.menu_panel.selected_menu.clone();

        match menu {
            MainMenu::Inbox => self.handle_inbox_key(key),
            MainMenu::Relationships => self.handle_relationships_key(key),
            MainMenu::Credentials => self.handle_credentials_key(key),
            MainMenu::Settings => self.handle_settings_key(key),
            MainMenu::Logs => self.handle_logs_key(key),
            MainMenu::Help => self.handle_help_key(key),
            MainMenu::Communities => self.handle_communities_key(key),
            MainMenu::Identity => self.handle_personas_key(key),
            MainMenu::Vta => self.handle_vta_key(key),
            MainMenu::Vetting => self.handle_vetting_key(key),
            MainMenu::TspRelationships => self.handle_tsp_key(key),
            MainMenu::Quit => false,
        }
    }

    /// The open overlay's handling of `key` — whether it took it — or `None`
    /// when no overlay is open. Each overlay takes exactly the keys its key
    /// line lists.
    pub(super) fn handle_overlay_key(&mut self, key: KeyEvent) -> Option<bool> {
        if self.props.main_page.create_persona.is_some() {
            Some(self.handle_create_persona_key(key))
        } else if self.props.main_page.agent_names.is_some() {
            Some(self.handle_agent_name_manager_key(key))
        } else if self.props.main_page.add_vic.is_some() {
            Some(self.handle_add_vic_key(key))
        } else if self.props.main_page.switcher.is_some() {
            Some(self.handle_switcher_key(key))
        } else {
            None
        }
    }

    /// Create-persona overlay keys. Label phase: Enter goes on to the path
    /// choice, Esc cancels, other keys edit the label. Path phase: ↑/↓ choose
    /// server-assigned or typed, typing edits the path (and picks the typed
    /// row), Enter goes on to the context choice, Esc goes back. Context phase:
    /// ↑/↓ choose, typing names a new sub-context, Enter mints, Esc goes back to
    /// the path. Working phase takes no keys. Done/Failed:
    /// `c` re-copies the DID (Done only), any other key closes. Called only
    /// while the overlay is open, where it owns all input.
    fn handle_create_persona_key(&mut self, key: KeyEvent) -> bool {
        let Some(overlay) = self.props.main_page.create_persona.as_ref() else {
            return false;
        };
        crate::ui::pages::create_persona_overlay::handle_key(overlay, key, &self.action_tx)
    }

    /// Agent-name manager overlay keys. `Ready` phase: Enter claims the typed
    /// name, ↑/↓ move the row selection, Space parks/resumes the selected name,
    /// `d`/Delete removes it, Esc closes, text keys edit the input. `Loading`
    /// and `Working` take no keys (a mutation is in flight). Called only while
    /// the overlay is open, where it owns all input.
    fn handle_agent_name_manager_key(&mut self, key: KeyEvent) -> bool {
        use crate::state_handler::main_page::content::AgentNameManagerPhase;
        let Some(overlay) = self.props.main_page.agent_names.as_ref() else {
            return false;
        };
        // A remove is armed: it owns all input — only y/Enter confirms (releasing
        // the name, which anyone can then reclaim); anything else backs out.
        if overlay.confirm_remove.is_some() {
            match key.code {
                KeyCode::Char('y') if crate::ui::pages::main::confirm::is_yes(&key) => {
                    let _ = self.action_tx.send(Action::AgentNameManagerRemove);
                }
                _ => {
                    let _ = self.action_tx.send(Action::AgentNameManagerCancelRemove);
                }
            }
            return true;
        }
        match overlay.phase {
            AgentNameManagerPhase::Ready => match key.code {
                KeyCode::Enter => {
                    let _ = self.action_tx.send(Action::AgentNameManagerClaim);
                }
                KeyCode::Esc => {
                    let _ = self.action_tx.send(Action::AgentNameManagerClose);
                }
                KeyCode::Up => {
                    let _ = self.action_tx.send(Action::AgentNameManagerSelect(false));
                }
                KeyCode::Down => {
                    let _ = self.action_tx.send(Action::AgentNameManagerSelect(true));
                }
                // Space parks/resumes; `d`/Delete arms the remove confirm — both
                // act on the selected row and only when there is one.
                KeyCode::Char(' ') if !overlay.names.is_empty() => {
                    let _ = self.action_tx.send(Action::AgentNameManagerToggle);
                }
                KeyCode::Char('d') | KeyCode::Delete if !overlay.names.is_empty() => {
                    let _ = self.action_tx.send(Action::AgentNameManagerConfirmRemove);
                }
                _ if keymap::is_text_edit(&key) => {
                    let _ = self.action_tx.send(Action::AgentNameManagerInput(key));
                }
                _ => return false,
            },
            // A list load or mutation is in flight: lock input.
            AgentNameManagerPhase::Loading | AgentNameManagerPhase::Working => return false,
        }
        true
    }

    /// Add-VIC overlay keys. Input phase: Enter stores, Esc cancels, other keys
    /// edit the paste field. Working takes no keys. Done/Failed: any key closes.
    /// Called only while the overlay is open, where it owns all input.
    fn handle_add_vic_key(&mut self, key: KeyEvent) -> bool {
        use crate::state_handler::main_page::content::AddVicPhase;
        let Some(overlay) = self.props.main_page.add_vic.as_ref() else {
            return false;
        };
        match overlay.phase {
            AddVicPhase::Input => match key.code {
                KeyCode::Enter => {
                    let _ = self.action_tx.send(Action::AddVicSubmit);
                }
                KeyCode::Esc => {
                    let _ = self.action_tx.send(Action::AddVicClose);
                }
                _ if keymap::is_text_edit(&key) => {
                    let _ = self.action_tx.send(Action::AddVicInput(key));
                }
                _ => return false,
            },
            AddVicPhase::Working => return false,
            AddVicPhase::Done | AddVicPhase::Failed => {
                let _ = self.action_tx.send(Action::AddVicClose);
            }
        }
        true
    }

    /// Community switcher overlay keys (R-C-7): ↑/↓ move the highlight, Enter
    /// switches the working community, Esc (or Ctrl+K again) dismisses. Called
    /// only while the overlay is open, where it owns all input.
    fn handle_switcher_key(&mut self, key: KeyEvent) -> bool {
        let Some(switcher) = self.props.main_page.switcher.as_ref() else {
            return false;
        };
        let count = switcher.items.len();
        let selected = switcher.selected;
        match key.code {
            KeyCode::Up if count > 0 => {
                let _ = self
                    .action_tx
                    .send(Action::CommunitySwitcherMove(selected.saturating_sub(1)));
            }
            KeyCode::Down if count > 0 => {
                let _ = self
                    .action_tx
                    .send(Action::CommunitySwitcherMove((selected + 1).min(count - 1)));
            }
            KeyCode::Enter if selected < count => {
                let _ = self.action_tx.send(Action::CommunitySwitcherSelect);
            }
            KeyCode::Esc => {
                let _ = self.action_tx.send(Action::CloseCommunitySwitcher);
            }
            KeyCode::Char('k') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                let _ = self.action_tx.send(Action::CloseCommunitySwitcher);
            }
            _ => return false,
        }
        true
    }
}

/// Stable identifier for the currently-displayed content view, derived from
/// the active menu and its per-panel mode. When this changes across frames
/// (e.g. list → detail, or switching menus), the content panel scroll offset
/// is reset to 0 so the new view starts at the top.
/// Break `text` into lines that fit `width` columns, splitting on whitespace and
/// hard-splitting any single token longer than the width.
///
/// Overlay status text is rendered as discrete `Line`s, which a `Paragraph`
/// clips rather than wraps — so a long message loses its tail silently. That is
/// worst for exactly the messages worth reading: a decode failure quotes the
/// field that was missing and the payload that arrived, and both sit at the end.
///
/// The hard split matters because these messages carry DIDs and JSON, which
/// contain no spaces to break on.
pub(crate) fn wrap_text(text: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![text.to_string()];
    }
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();

    for word in text.split_whitespace() {
        let mut word = word;
        // A token longer than the whole width can never fit beside anything;
        // emit it in width-sized pieces.
        while word.chars().count() > width {
            if !current.is_empty() {
                lines.push(std::mem::take(&mut current));
            }
            let head: String = word.chars().take(width).collect();
            let consumed = head.len();
            lines.push(head);
            word = &word[consumed..];
        }
        if word.is_empty() {
            continue;
        }
        let extra = if current.is_empty() {
            word.chars().count()
        } else {
            word.chars().count() + 1
        };
        if current.chars().count() + extra > width && !current.is_empty() {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }

    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

fn view_id(page: &MainPageState) -> String {
    use crate::state_handler::main_page::content::{
        CredentialsMode, RelationshipsMode, SettingsMode,
    };
    let menu = &page.menu_panel.selected_menu;
    let mode: &str = match menu {
        MainMenu::Inbox => {
            if page.content_panel.inbox.active_task.is_some() {
                "detail"
            } else {
                "list"
            }
        }
        MainMenu::Credentials => match &page.content_panel.credentials.mode {
            CredentialsMode::List => "list",
            CredentialsMode::Detail { .. } => "detail",
            CredentialsMode::NewRequest { .. } => "new",
        },
        MainMenu::Relationships => match &page.content_panel.relationships.mode {
            RelationshipsMode::List => "list",
            RelationshipsMode::Detail { .. } => "detail",
            RelationshipsMode::NewRequest { .. } => "new",
            RelationshipsMode::EditAlias { .. } => "edit",
            RelationshipsMode::Witness { .. } => "witness",
        },
        MainMenu::Settings => match &page.content_panel.settings.mode {
            SettingsMode::View => "view",
            SettingsMode::EditFriendlyName { .. } => "edit-name",
            SettingsMode::ExportConfig { .. } => "export",
            SettingsMode::ImportConfig { .. } => "import",
            SettingsMode::ChangeProtection { .. } => "protect",
            #[cfg(feature = "openpgp-card")]
            SettingsMode::TokenManagement { .. } => "token",
            #[cfg(feature = "openpgp-card")]
            SettingsMode::TokenResetConfirm { .. } => "token-reset",
            SettingsMode::WipeConfirm { .. } => "wipe",
            SettingsMode::ThemePicker { .. } => "theme",
        },
        MainMenu::Vetting => components::vetting_panel::mode_id(&page.content_panel.vetting),
        _ => "",
    };
    format!("{menu:?}:{mode}")
}

/// The account's self-display name for the top-right header slot, or `None` when
/// it would only repeat the community chip already shown top-left.
///
/// An account may carry the community's name in `public.friendly_name` — a
/// legacy value older joins wrote there, or one the user typed in themselves —
/// and this slot would render the community a second time. Either way the top
/// bar should read "community · you", never "community · community · you".
fn header_self_name<'a>(name: &'a str, community: &str) -> Option<&'a str> {
    let name = name.trim();
    (!name.is_empty() && name != community.trim()).then_some(name)
}

/// Copy text to the system clipboard, log the result to the activity log,
/// and update the status panel message to give the user visual feedback.
fn copy_to_clipboard(
    text: &str,
    label: &str,
    action_tx: &tokio::sync::mpsc::UnboundedSender<Action>,
) {
    match crate::clipboard::copy_to_clipboard(text) {
        Ok(method) => {
            tracing::info!(label, method = method.label(), "copied to clipboard");
            let _ = action_tx.send(Action::Settings(SettingsAction::ClipboardCopied(
                crate::state_handler::main_page::status::Status::success(format!(
                    "✓ {label} copied via {}",
                    method.label()
                )),
            )));
        }
        Err(e) => {
            tracing::warn!(label, error = %e, "failed to copy to clipboard");
            let _ = action_tx.send(Action::Settings(SettingsAction::ClipboardCopied(
                crate::state_handler::main_page::status::Status::error(format!(
                    "✗ Copy failed: {e}"
                )),
            )));
        }
    }
}

// ****************************************************************************
// Render the page
// ****************************************************************************
impl ComponentRender<()> for MainPage {
    fn render(&self, frame: &mut Frame, _props: ()) {
        keymap::begin_frame();
        text_input::set_cursor(self.focused_field().map(|f| self.field_cursor(&f)));
        // On a short terminal the activity log gives up rows so the whole
        // menu fits; on a narrow one the menu keeps the width its longest
        // item needs (#576).
        let area = frame.area();
        let log_rows = if area.height < 32 { 4 } else { 8 };
        let [main_top, main_middle, main_log, main_bottom] =
            Layout::vertical([Length(2), Min(0), Length(log_rows), Length(1)]).areas(area);

        let top =
            Layout::horizontal([Percentage(35), Percentage(30), Percentage(35)]).split(main_top);
        let menu_width = components::menu_panel::MENU_WIDTH.max(area.width / 5);
        let middle = Layout::horizontal([Length(menu_width), Min(0)]).split(main_middle);

        // Top-left: the working community name with a ▾ switcher affordance
        // (R-C-7a), or the dashboard title when there's no active community.
        let community = &self.props.main_page.config.community;
        let top_left = if community.is_empty() {
            Line::from(" OpenVTC Dashboard").fg(COLOR_SUCCESS)
        } else {
            Line::from(vec![
                Span::styled(
                    format!(" {community} "),
                    ratatui::style::Style::default().fg(COLOR_SUCCESS),
                ),
                Span::styled("▾", ratatui::style::Style::default().fg(COLOR_ORANGE)),
            ])
        };
        frame.render_widget(Paragraph::new(top_left).alignment(Alignment::Left), top[0]);

        // Connection status indicator
        let connection_line = match &self.props.connection.status {
            MediatorStatus::Connected => Line::from(Span::styled(
                "Connected",
                ratatui::style::Style::default().fg(COLOR_SUCCESS),
            )),
            MediatorStatus::Connecting => Line::from(Span::styled(
                "Connecting...",
                ratatui::style::Style::default().fg(COLOR_TEXT_DEFAULT),
            )),
            // The class, not a truncated error text: an unreachable mediator,
            // a refusal and a contract mismatch need different fixes (R6.4,
            // #585). The full reason and the retry are on Help / Status.
            MediatorStatus::Failed(failure) => Line::from(vec![
                Span::styled(
                    format!("✗ {}", failure.short()),
                    ratatui::style::Style::default()
                        .fg(COLOR_WARNING_ACCESSIBLE_RED)
                        .bold(),
                ),
                Span::styled(
                    " · see Help",
                    ratatui::style::Style::default().fg(COLOR_DARK_GRAY),
                ),
            ]),
            MediatorStatus::Initializing(step) => Line::from(vec![
                Span::styled(
                    "Initialising: ",
                    ratatui::style::Style::default().fg(COLOR_ORANGE),
                ),
                Span::styled(
                    step.to_string(),
                    ratatui::style::Style::default().fg(COLOR_TEXT_DEFAULT),
                ),
            ]),
            MediatorStatus::Unknown => Line::from(Span::styled(
                "Mediator: --",
                ratatui::style::Style::default().fg(COLOR_ORANGE),
            )),
            MediatorStatus::NoActiveCommunity => Line::from(Span::styled(
                "No active community",
                ratatui::style::Style::default().fg(COLOR_ORANGE),
            )),
            // Not a membership yet, but reachable: an applicant being vetted
            // sees that their vetters' answers can get through.
            MediatorStatus::PersonaOnline => Line::from(Span::styled(
                "No community yet · persona online",
                ratatui::style::Style::default().fg(COLOR_SUCCESS),
            )),
        };
        frame.render_widget(
            Paragraph::new(connection_line).alignment(Alignment::Center),
            top[1],
        );

        // Top-right: who *we* are. The account's self-display name goes above the
        // active persona's identity — but only when it says something the chrome
        // isn't already saying. An account whose `friendly_name` holds the
        // community's name (a legacy value older joins wrote) would render the
        // community a second time, right of the community chip top-left.
        // Suppressing the duplicate leaves the top bar reading
        // "community · you" instead of "community · community · you".
        let mut top_right = Vec::new();
        if let Some(self_name) = header_self_name(
            &self.props.main_page.config.name,
            &self.props.main_page.config.community,
        ) {
            top_right.push(Line::from(self_name.to_string()).fg(COLOR_SUCCESS));
        }
        top_right.push(
            Line::from(match &self.props.main_page.config.agent_name {
                // A verified agent name is short and human-readable — show it
                // whole in place of the truncated DID.
                Some(name) => name.clone(),
                None => truncate_did_centered(&self.props.main_page.config.did, 30).into_owned(),
            })
            .fg(COLOR_TEXT_DEFAULT),
        );
        frame.render_widget(
            Paragraph::new(top_right).alignment(Alignment::Right),
            top[2],
        );

        // Middle block
        // Left = menu
        // right = actual content

        // Main Menu
        // A journey takes the whole width: the menu would be a second place to
        // go in the middle of a process whose point is one place at a time.
        // Esc closes the journey and the menu comes back.
        let journey_open = self.props.main_page.menu_panel.selected_menu == MainMenu::Vetting
            && self.props.main_page.content_panel.vetting.journey.is_some();
        let content_area = if journey_open {
            main_middle
        } else {
            self.props.main_page.menu_panel.render(
                frame,
                middle[0],
                &self.props.main_page.menu_badges(),
            );
            middle[1]
        };
        let max_scroll = self.props.main_page.content_panel.render(
            frame,
            content_area,
            &self.props.main_page.menu_panel,
            &self.props.connection,
            &self.props.main_page.activity_log,
            self.logs_selected,
            self.logs_detail_view,
            self.content_scroll,
        );
        self.content_scroll_max.set(max_scroll);
        let mut keys = keymap::take_advertised();

        // Activity log panel
        let log_block = Block::bordered()
            .merge_borders(MergeStrategy::Fuzzy)
            .fg(COLOR_BORDER)
            .title(" Activity Log ");
        let log_inner = log_block.inner(main_log);
        frame.render_widget(log_block, main_log);

        let log = &self.props.main_page.activity_log;
        let visible_lines = log_inner.height as usize;
        let skip = if log.len() > visible_lines {
            log.len() - visible_lines
        } else {
            0
        };
        // Each entry in its severity's colour, with a glyph so an error is
        // told apart without colour too (#584).
        let log_lines: Vec<Line> = log
            .iter()
            .skip(skip)
            .map(|entry| {
                use crate::state_handler::main_page::status::Severity;
                let (glyph, style) = match entry.severity {
                    Severity::Error => ("✗ ", components::status::severity_style(Severity::Error)),
                    Severity::Warning => {
                        ("! ", components::status::severity_style(Severity::Warning))
                    }
                    Severity::Success => {
                        ("✓ ", components::status::severity_style(Severity::Success))
                    }
                    Severity::Info | Severity::Progress => {
                        ("  ", ratatui::style::Style::default().fg(COLOR_DARK_GRAY))
                    }
                };
                Line::from(Span::styled(format!("{glyph}{}", entry.summary), style))
            })
            .collect();
        frame.render_widget(Paragraph::new(log_lines), log_inner);

        // Bottom row: the keys that work everywhere, from the same table `?`
        // lists, quit first so it survives a narrow terminal (#576). Feedback
        // for a key that did nothing takes the row until the next key. A
        // development trust-anchor override takes the front of the line for
        // the whole session, so an overridden run cannot be mistaken for a
        // normal one.
        let mut bottom = Vec::new();
        if let Some(banner) = &self.props.main_page.dev_override {
            bottom.push(Span::styled(
                format!(" {banner} "),
                ratatui::style::Style::default()
                    .fg(ratatui::style::Color::Black)
                    .bg(COLOR_WARNING_ACCESSIBLE_RED)
                    .bold(),
            ));
        }
        match &self.key_feedback {
            Some(feedback) => bottom.push(Span::styled(
                format!(" {feedback}"),
                ratatui::style::Style::default().fg(COLOR_ORANGE),
            )),
            None => {
                // Quit and `?` lead, and the rest is kept only while it fits,
                // so the row is never cut off mid-hint.
                let mut keys = Vec::new();
                for b in keymap::global() {
                    keys.push(b);
                    if keymap::line(" ", &keys).width() > usize::from(main_bottom.width) {
                        keys.pop();
                        break;
                    }
                }
                bottom.extend(keymap::line(" ", &keys).spans);
            }
        }
        frame.render_widget(
            Paragraph::new(Line::from(bottom)).alignment(Alignment::Left),
            main_bottom,
        );

        // Community switcher overlay (R-C-7) floats over everything when open.
        if let Some(switcher) = self.props.main_page.switcher.as_ref() {
            self.render_switcher_overlay(frame, switcher);
        }
        // Create-persona overlay floats over everything when open.
        if let Some(overlay) = self.props.main_page.create_persona.as_ref() {
            self.render_create_persona_overlay(frame, overlay);
        }
        // Add-VIC (import invitation) overlay floats over everything when open.
        if let Some(overlay) = self.props.main_page.add_vic.as_ref() {
            self.render_add_vic_overlay(frame, overlay);
        }
        // Agent-name manager overlay floats over everything when open.
        if let Some(overlay) = self.props.main_page.agent_names.as_ref() {
            self.render_agent_name_manager_overlay(frame, overlay);
        }

        // An overlay owns the keyboard while it is open, so its keys are the
        // ones `?` and the feedback go by.
        let overlay_keys = keymap::take_advertised();
        if !overlay_keys.is_empty() {
            keys = overlay_keys;
        }
        self.panel_keys.replace(keys);

        if self.help_open {
            self.render_help_overlay(frame);
        }
    }
}

impl MainPage {
    /// Render the quick community-switcher popup (R-C-7): a centered overlay
    /// listing the Active communities, the current one marked, the highlighted
    /// one styled. Mirrors the hardware-token overlay's centering pattern.
    fn render_switcher_overlay(
        &self,
        frame: &mut Frame,
        switcher: &crate::state_handler::main_page::content::CommunitySwitcherState,
    ) {
        use ratatui::{
            layout::{Constraint, Flex},
            style::Style,
            widgets::{Block, Clear, Padding},
        };

        let area = frame.area();
        // Header + footer (3 lines) plus one line per entry, within bounds.
        let rows = switcher.items.len() as u16;
        // rows + border(2) + padding(2) + blank line + footer line.
        let popup_height = (rows + 6).min(area.height.saturating_sub(2)).max(6);
        let popup_width = 52u16.min(area.width.saturating_sub(4));

        let [popup_area] = Layout::vertical([Constraint::Length(popup_height)])
            .flex(Flex::Center)
            .areas(area);
        let [popup_area] = Layout::horizontal([Constraint::Length(popup_width)])
            .flex(Flex::Center)
            .areas(popup_area);

        frame.render_widget(Clear, popup_area);

        let block = Block::bordered()
            .title(" Switch community ")
            .title_style(Style::new().fg(COLOR_ORANGE).bold())
            .border_style(Style::new().fg(COLOR_ORANGE))
            .padding(Padding::uniform(1));

        let mut lines: Vec<Line> = switcher
            .items
            .iter()
            .enumerate()
            .map(|(i, item)| {
                let marker = if i == switcher.selected { "▸ " } else { "  " };
                let current = if item.is_current { "  (active)" } else { "" };
                // Disambiguate multiple memberships of the same community by the
                // presented persona.
                let persona = if item.persona_label.is_empty() {
                    String::new()
                } else {
                    format!("  as {}", item.persona_label)
                };
                let style = if i == switcher.selected {
                    Style::new().fg(COLOR_SUCCESS).bold()
                } else {
                    Style::new().fg(COLOR_TEXT_DEFAULT)
                };
                Line::from(Span::styled(
                    format!("{marker}{}{persona}{current}", item.display_name),
                    style,
                ))
            })
            .collect();
        lines.push(Line::default());
        lines.push(keymap::overlay_line(&[
            keymap::k("↑/↓", "select"),
            keymap::k("Enter", "switch"),
            keymap::k("Esc/Ctrl+K", "close"),
        ]));

        frame.render_widget(Paragraph::new(lines).block(block), popup_area);
    }

    /// Render the create-persona popup: a centered overlay walking the label
    /// input → progress → result (the DID + copy hint). Mirrors the switcher
    /// overlay's centering pattern.
    fn render_create_persona_overlay(
        &self,
        frame: &mut Frame,
        overlay: &crate::state_handler::main_page::content::CreatePersonaState,
    ) {
        crate::ui::pages::create_persona_overlay::render(frame, overlay);
    }

    /// Render the agent-name manager popup: the persona's registry (served and
    /// parked names), a claim input, and the row actions. Mirrors the
    /// create-persona overlay's centering.
    fn render_agent_name_manager_overlay(
        &self,
        frame: &mut Frame,
        overlay: &crate::state_handler::main_page::content::AgentNameManagerState,
    ) {
        use crate::state_handler::main_page::content::AgentNameManagerPhase;
        use ratatui::{
            layout::{Constraint, Flex},
            style::Style,
            widgets::{Block, Clear, Padding},
        };

        let area = frame.area();
        let popup_width = 68u16.min(area.width.saturating_sub(4));
        // Inner width: two border columns and `Padding::uniform(1)` either side.
        let inner_width = popup_width.saturating_sub(4) as usize;

        // Wrapped up front, because the popup has to be tall enough to show it.
        let message_lines: Vec<String> = overlay
            .message
            .as_deref()
            .map(|m| wrap_text(m, inner_width))
            .unwrap_or_default();

        // Grow by whatever the message needs beyond the single line the base
        // height already allows, then clamp to the screen.
        let extra = message_lines.len().saturating_sub(1) as u16;
        let popup_height = 16u16
            .saturating_add(extra)
            .min(area.height.saturating_sub(2))
            .max(9);

        let [popup_area] = Layout::vertical([Constraint::Length(popup_height)])
            .flex(Flex::Center)
            .areas(area);
        let [popup_area] = Layout::horizontal([Constraint::Length(popup_width)])
            .flex(Flex::Center)
            .areas(popup_area);

        frame.render_widget(Clear, popup_area);

        let title = if overlay.persona_label.is_empty() {
            " Agent names ".to_string()
        } else {
            format!(" Agent names — {} ", overlay.persona_label)
        };
        let block = Block::bordered()
            .title(title)
            .title_style(Style::new().fg(COLOR_ORANGE).bold())
            .border_style(Style::new().fg(COLOR_ORANGE))
            .padding(Padding::uniform(1));

        let mut lines: Vec<Line> = Vec::new();
        match overlay.phase {
            AgentNameManagerPhase::Loading => {
                lines.push(Line::from(Span::styled(
                    "Loading agent names…",
                    Style::new().fg(COLOR_TEXT_DEFAULT),
                )));
            }
            AgentNameManagerPhase::Ready | AgentNameManagerPhase::Working => {
                if overlay.names.is_empty() {
                    // "No agent names yet" is a claim about the registry, and we
                    // can only make it when the registry actually answered. With
                    // a failed read it is not just unknown but likely wrong —
                    // the read that failed is the one *after* a successful claim.
                    let (text, style) = if overlay.list_stale {
                        (
                            "Registry could not be read — any names on this DID are not shown.",
                            Style::new().fg(COLOR_ORANGE),
                        )
                    } else {
                        ("No agent names yet.", Style::new().fg(COLOR_DARK_GRAY))
                    };
                    lines.push(Line::from(Span::styled(text, style)));
                } else {
                    for (i, row) in overlay.names.iter().enumerate() {
                        let marker = if i == overlay.selected { "▸ " } else { "  " };
                        let host = if overlay.host.is_empty() {
                            "@".to_string()
                        } else {
                            format!("{}/@", overlay.host)
                        };
                        let status = if row.enabled { "served" } else { "parked" };
                        let status_style = if row.enabled {
                            Style::new().fg(COLOR_SUCCESS)
                        } else {
                            Style::new().fg(COLOR_DARK_GRAY)
                        };
                        let name_style = if i == overlay.selected {
                            Style::new().fg(COLOR_SUCCESS).bold()
                        } else {
                            Style::new().fg(COLOR_TEXT_DEFAULT)
                        };
                        lines.push(Line::from(vec![
                            Span::styled(format!("{marker}{host}{}", row.name), name_style),
                            Span::styled(format!("   [{status}]"), status_style),
                        ]));
                    }
                }
                lines.push(Line::default());
                // The claim input.
                let prefix = if overlay.host.is_empty() {
                    "@".to_string()
                } else {
                    format!("{}/@", overlay.host)
                };
                lines.push(Line::from(vec![
                    Span::styled("Claim: ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                    Span::styled(
                        format!("{prefix}{}", overlay.input.value()),
                        Style::new().fg(COLOR_SOFT_PURPLE).bold(),
                    ),
                ]));
            }
        }

        if !message_lines.is_empty() {
            lines.push(Line::default());
            for msg_line in &message_lines {
                lines.push(Line::from(Span::styled(
                    msg_line.clone(),
                    Style::new().fg(COLOR_ORANGE),
                )));
            }
        }

        lines.push(Line::default());
        // An armed remove confirmation overrides the normal hint with a warning.
        let armed = overlay
            .confirm_remove
            .and_then(|i| overlay.names.get(i))
            .map(|row| row.name.as_str());
        if let Some(name) = armed {
            lines.push(
                Line::from(crate::ui::pages::main::confirm::prompt(&format!(
                    "Release @{name}? It becomes free for anyone to reclaim."
                )))
                .fg(COLOR_ORANGE)
                .bold(),
            );
        } else {
            let hint = match overlay.phase {
                AgentNameManagerPhase::Working | AgentNameManagerPhase::Loading => {
                    Line::from(Span::styled("working…", Style::new().fg(COLOR_BORDER)))
                }
                AgentNameManagerPhase::Ready => {
                    let mut keys = vec![
                        keymap::k(keymap::TYPE, "a name"),
                        keymap::k("Enter", "claim"),
                        keymap::k("↑/↓", "select"),
                    ];
                    if !overlay.names.is_empty() {
                        keys.push(keymap::k("Space", "park/resume"));
                        keys.push(keymap::k("d/Del", "remove"));
                    }
                    keys.push(keymap::k("Esc", "close"));
                    keymap::overlay_line(&keys)
                }
            };
            lines.push(hint);
        }

        frame.render_widget(Paragraph::new(lines).block(block), popup_area);
    }

    fn render_add_vic_overlay(
        &self,
        frame: &mut Frame,
        overlay: &crate::state_handler::main_page::content::AddVicState,
    ) {
        use crate::state_handler::main_page::content::AddVicPhase;
        use ratatui::{
            layout::{Constraint, Flex},
            style::Style,
            widgets::{Block, Clear, Padding},
        };

        let area = frame.area();
        let popup_width = 64u16.min(area.width.saturating_sub(4));
        let popup_height = 11u16.min(area.height.saturating_sub(2)).max(7);

        let [popup_area] = Layout::vertical([Constraint::Length(popup_height)])
            .flex(Flex::Center)
            .areas(area);
        let [popup_area] = Layout::horizontal([Constraint::Length(popup_width)])
            .flex(Flex::Center)
            .areas(popup_area);

        frame.render_widget(Clear, popup_area);

        let block = Block::bordered()
            .title(" Import invitation credential ")
            .title_style(Style::new().fg(COLOR_ORANGE).bold())
            .border_style(Style::new().fg(COLOR_ORANGE))
            .padding(Padding::uniform(1));

        let mut lines: Vec<Line> = Vec::new();
        match overlay.phase {
            AddVicPhase::Input => {
                lines.push(Line::from(Span::styled(
                    "Paste an invitation credential (VIC) JSON, then press Enter:",
                    Style::new().fg(COLOR_TEXT_DEFAULT),
                )));
                // The pasted JSON can be long; show a char count + short preview
                // rather than the full body in the popup.
                let val = overlay.input.value();
                let preview = if val.chars().count() > 40 {
                    let head: String = val.chars().take(40).collect();
                    format!("{head}…")
                } else {
                    val.to_string()
                };
                lines.push(Line::from(Span::styled(
                    if val.is_empty() {
                        "> (nothing pasted yet)".to_string()
                    } else {
                        format!("> {preview}   ({} chars)", val.chars().count())
                    },
                    Style::new().fg(COLOR_SOFT_PURPLE).bold(),
                )));
                lines.push(Line::default());
                for msg in &overlay.messages {
                    lines.push(Line::from(Span::styled(
                        msg.clone(),
                        Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
                    )));
                }
                lines.push(keymap::overlay_line(&[
                    keymap::k(keymap::TYPE, "paste the VIC"),
                    keymap::k("Enter", "store"),
                    keymap::k("Esc", "cancel"),
                ]));
            }
            AddVicPhase::Working => {
                for msg in &overlay.messages {
                    lines.push(Line::from(Span::styled(
                        msg.clone(),
                        Style::new().fg(COLOR_TEXT_DEFAULT),
                    )));
                }
            }
            AddVicPhase::Done => {
                lines.push(Line::from(Span::styled(
                    "✓ Invitation credential stored",
                    Style::new().fg(COLOR_SUCCESS).bold(),
                )));
                lines.push(Line::default());
                lines.push(keymap::overlay_line(&[keymap::k(
                    "Enter/Esc",
                    "close (so does any key)",
                )]));
            }
            AddVicPhase::Failed => {
                for msg in &overlay.messages {
                    lines.push(Line::from(Span::styled(
                        msg.clone(),
                        Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
                    )));
                }
                lines.push(Line::default());
                lines.push(keymap::overlay_line(&[keymap::k(
                    "Enter/Esc",
                    "close (so does any key)",
                )]));
            }
        }

        frame.render_widget(Paragraph::new(lines).block(block), popup_area);
    }
}

#[cfg(test)]
mod header_tests {
    use super::header_self_name;

    /// A distinct self-name is the point of the slot and is kept.
    #[test]
    fn a_distinct_self_name_is_shown() {
        assert_eq!(
            header_self_name("Glenn", "webvh.storm.ws/@first-vtc"),
            Some("Glenn")
        );
    }

    /// The regression: a join copied the community's name into `friendly_name`,
    /// so the header announced the community either side of the connection
    /// indicator.
    #[test]
    fn a_self_name_equal_to_the_community_is_suppressed() {
        assert_eq!(
            header_self_name("webvh.storm.ws/@first-vtc", "webvh.storm.ws/@first-vtc"),
            None
        );
    }

    /// Whitespace must not smuggle the duplicate back in.
    #[test]
    fn the_comparison_ignores_surrounding_whitespace() {
        assert_eq!(header_self_name("  Acme  ", "Acme"), None);
    }

    #[test]
    fn an_empty_self_name_is_suppressed() {
        assert_eq!(header_self_name("", "Acme"), None);
        assert_eq!(header_self_name("   ", ""), None);
    }
}

#[cfg(test)]
mod wrap_text_tests {
    use super::wrap_text;

    #[test]
    fn wraps_on_whitespace_within_the_width() {
        let got = wrap_text("the quick brown fox jumps", 10);
        assert_eq!(got, vec!["the quick", "brown fox", "jumps"]);
        assert!(got.iter().all(|l| l.chars().count() <= 10));
    }

    /// The case that actually matters here: decode errors quote DIDs and JSON,
    /// which contain no spaces. Without a hard split an over-long token would
    /// still overflow its line and be clipped — the bug this fixes.
    #[test]
    fn hard_splits_a_token_longer_than_the_width() {
        let did =
            "did:webvh:QmXi1PZD4NEvcvjfErAzVoCGtBFEv7dhXZQJHvcFY4U83F:webvh.storm.ws:first-vtc";
        let got = wrap_text(did, 20);
        assert!(
            got.iter().all(|l| l.chars().count() <= 20),
            "every line must fit: {got:?}"
        );
        assert_eq!(got.concat(), did, "no characters may be lost");
    }

    #[test]
    fn keeps_the_whole_message_when_it_fits() {
        assert_eq!(wrap_text("short", 40), vec!["short"]);
    }

    /// A realistic decode failure must survive wrapping intact — the field name
    /// and the payload excerpt are the whole point of the message.
    #[test]
    fn preserves_a_decode_error_in_full() {
        let msg = "decoding agent-name list result: missing field `names`. \
                   VTA sent: {\"did\":\"did:webvh:QmXi1PZD4NEvcvjfErAzVoCGtBFEv7dhXZQJHvcFY4U83F\"}";
        let got = wrap_text(msg, 64);
        assert!(got.iter().all(|l| l.chars().count() <= 64), "{got:?}");
        let rejoined = got.join(" ");
        assert!(rejoined.contains("missing field"), "{rejoined}");
        assert!(rejoined.contains("names"), "{rejoined}");
        assert!(rejoined.contains("VTA sent"), "{rejoined}");
    }

    #[test]
    fn degenerate_widths_do_not_panic_or_drop_text() {
        assert_eq!(wrap_text("abc", 0), vec!["abc"]);
        assert_eq!(wrap_text("", 10), vec![""]);
        assert_eq!(wrap_text("aaaa", 1).concat(), "aaaa");
    }
}

#[cfg(test)]
mod key_handler_tests {
    //! Key-handler tests for the main page (R26 slice 2): construct a `MainPage`
    //! over a `State`, feed a `KeyEvent` through the public `handle_key_event`
    //! entry point, and assert on the `Action`(s) emitted on the channel. There
    //! is at least one test per content panel, with the R25 destructive-confirm
    //! flow (arm → confirm/cancel) covered for every panel that has one.
    //!
    //! `Action` and its sub-enums derive neither `PartialEq` nor `Debug`, so
    //! assertions pattern-match the expected variant rather than `assert_eq!`.
    use super::*;
    use crate::state_handler::actions::{
        CredentialAction, InboxAction, PersonaAction, RelationshipAction,
    };
    use crate::state_handler::main_page::content::{
        CommunitySend, CommunitySummary, CommunitySwitcherState, CredentialTab, CredentialsMode,
        InboxConfirm, ManagedDid, PersonaConfirm, PersonaMode, PersonaTab, RawCredential,
        RelationshipSummary, RelationshipsMode, SwitcherItem, TaskKind, TaskSummary, VrcSummary,
    };
    use components::repos_panel::keys::{repos_copy_path, repos_key};
    use crossterm::event::KeyModifiers;
    use std::sync::Arc;
    use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

    /// Build a focused `MainPage` on the given menu, after `mutate` populates the
    /// panel state. Returns the page and the receiver to read emitted actions.
    pub(super) fn page_for(
        menu: MainMenu,
        mutate: impl FnOnce(&mut State),
    ) -> (MainPage, UnboundedReceiver<Action>) {
        let (tx, rx) = unbounded_channel();
        let mut state = State::default();
        state.main_page.menu_panel.selected_menu = menu;
        // The content panel must be focused for keys to route to its handler.
        state.main_page.content_panel.selected = true;
        mutate(&mut state);
        let page = MainPage::new(&std::sync::Arc::new(state.clone()), tx);
        (page, rx)
    }

    /// A `Press` key event (the only kind `handle_key_event` acts on).
    pub(super) fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    /// A Ctrl-modified `Press` key event.
    pub(super) fn ctrl(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::CONTROL)
    }

    /// A minimal Communities-panel summary row for key-routing tests.
    pub(super) fn community_summary(name: &str) -> CommunitySummary {
        community_summary_with(name, true, false, false)
    }

    /// A summary with explicit active/inactive/pending status, for the leave/
    /// cancel/archive/delete key-gating tests.
    pub(super) fn community_summary_with(
        name: &str,
        is_active: bool,
        is_inactive: bool,
        is_pending: bool,
    ) -> CommunitySummary {
        CommunitySummary {
            post_quantum: false,
            pcs_zkp: false,
            display_name: name.to_string(),
            status_label: if is_active { "Active" } else { "Left" }.to_string(),
            persona_label: "persona".to_string(),
            member_since: String::new(),
            favourite: false,
            is_active,
            is_inactive,
            is_pending,
            pending_unacknowledged: false,
            approved_awaiting_credential: false,
            credential_resend_note: None,
            credential_refused: None,
            submit_transport: None,
            archived: false,
            needs_attention: false,
            persona_did: "did:example:persona".to_string(),
            persona_agent_name: None,
            vtc_did: format!("did:example:{name}"),
            vtc_agent_name: None,
            sub_context_id: format!("top/{name}"),
            context_note: String::new(),
            has_own_context: true,
            request_id: String::new(),
            has_membership_credential: false,
            has_role_credential: false,
            role_names: Vec::new(),
            retired_credentials: Vec::new(),
            accent: None,
            decision: None,
        }
    }

    pub(super) fn switcher_item(name: &str, is_current: bool) -> SwitcherItem {
        SwitcherItem {
            vtc_did: format!("did:example:{name}"),
            persona_ref: openvtc_core::config::account::PersonaId::new(),
            display_name: name.to_string(),
            persona_label: String::new(),
            is_current,
        }
    }

    pub(super) fn rel_summary(remote_p_did: &str) -> RelationshipSummary {
        RelationshipSummary {
            remote_p_did: remote_p_did.to_string(),
            alias: None,
            agent_name: None,
            state: "Established".to_string(),
            our_did: "did:example:me".to_string(),
            remote_did: "did:example:them".to_string(),
            created: String::new(),
            vrcs_issued: Vec::new(),
            vrcs_received: Vec::new(),
            witnessings: Vec::new(),
            needs_reestablishment: false,
        }
    }

    pub(super) fn vrc_summary(vrc_id: &str) -> VrcSummary {
        VrcSummary {
            vrc_id: vrc_id.to_string(),
            remote_p_did: "did:example:them".to_string(),
            remote_agent_name: None,
            raw_json: RawCredential::Value(Arc::new(serde_json::Value::Null)),
            alias: None,
            issuer: "did:example:issuer".to_string(),
            issuer_agent_name: None,
            subject: "did:example:subject".to_string(),
            subject_agent_name: None,
            valid_from: String::new(),
            valid_until: None,
            kind: None,
            subject_is_self: false,
            subject_label: None,
            post_quantum: false,
            validity: String::new(),
            status: "valid".to_string(),
            note: None,
            facts: Vec::new(),
        }
    }

    pub(super) fn task_summary(id: &str) -> TaskSummary {
        TaskSummary {
            id: id.to_string(),
            type_display: "Trust Ping".to_string(),
            kind: TaskKind::TrustPing,
            remote_did: "did:example:them".to_string(),
            remote_agent_name: None,
            created: String::new(),
        }
    }

    // ----- Vetting -----------------------------------------------------------

    fn vetting_action(
        rx: &mut UnboundedReceiver<Action>,
    ) -> crate::state_handler::actions::VettingAction {
        match rx.try_recv() {
            Ok(Action::Vetting(action)) => action,
            _ => panic!("expected a Vetting action"),
        }
    }

    /// A vetting page with a row in every list: a persona to apply as, an
    /// application, a request at the desk, a ticket (with no link) and a
    /// signed statement — so each list's verbs have something to act on.
    pub(super) fn vetting_rows(s: &mut State) {
        use crate::state_handler::main_page::content::{
            ApplicationRow, DeskRow, DeskStage, IssuedRow, TicketRow, VettingPersona,
        };
        let v = &mut s.main_page.content_panel.vetting;
        v.personas = vec![VettingPersona {
            persona: openvtc_core::config::account::PersonaId::new(),
            did: "did:key:zP".into(),
            label: "p".into(),
        }]
        .into();
        v.applications = vec![ApplicationRow {
            id: "a".into(),
            community: "did:web:kernel".into(),
            community_name: None,
            accent: None,
            pcs_zkp: false,
            next_step: None,
            join_did: "did:key:zA".into(),
            requirements: None,
            criterion: None,
            progress: None,
            satisfied: false,
            face: None,
            identity: Vec::new(),
            requests: Vec::new(),
            statements: 0,
        }]
        .into();
        v.desk = vec![DeskRow {
            request_id: "r1".into(),
            applicant: "did:example:applicant".into(),
            applicant_name: None,
            community: "did:example:community".into(),
            pcs_zkp: false,
            pcs_tokens: None,
            pcs_events: false,
            state: "accepted".into(),
            stage: DeskStage::Accepted,
            method: None,
            match_code: None,
            claims: Vec::new(),
            required_claims: Vec::new(),
            message: None,
        }]
        .into();
        v.tickets = vec![TicketRow {
            id: "t1".into(),
            code: "ABCD".into(),
            community: "c".into(),
            uses_left: 1,
            expires: "soon".into(),
            live: true,
            uri: None,
            mode_note: None,
        }]
        .into();
        v.issued = vec![IssuedRow {
            id: "st1".into(),
            applicant: "did:example:applicant".into(),
            community: "c".into(),
            method: "in person".into(),
            issued: "today".into(),
            valid_until: "next year".into(),
            withdrawal: None,
            withdrawal_recorded: false,
        }]
        .into();
    }

    #[test]
    fn vetting_list_keys_follow_the_tab() {
        use crate::state_handler::actions::VettingAction as V;
        use crate::state_handler::main_page::content::VettingTab;

        let (mut page, mut rx) = page_for(MainMenu::Vetting, vetting_rows);
        page.handle_key_event(press(KeyCode::Char('n')));
        assert!(matches!(vetting_action(&mut rx), V::StartApplication));

        // The same key means nothing on the desk…
        let (mut page, mut rx) = page_for(MainMenu::Vetting, |s| {
            vetting_rows(s);
            s.main_page.content_panel.vetting.tab = VettingTab::Desk;
        });
        page.handle_key_event(press(KeyCode::Char('n')));
        assert!(rx.try_recv().is_err());
        // …where `x` arms a decline.
        page.handle_key_event(press(KeyCode::Char('x')));
        assert!(matches!(vetting_action(&mut rx), V::ArmDecline));

        let (mut page, mut rx) = page_for(MainMenu::Vetting, |_| {});
        page.handle_key_event(press(KeyCode::Tab));
        assert!(matches!(vetting_action(&mut rx), V::SwitchTab));
    }

    /// `j` on an application is the join that application was made for. It
    /// carries the community, because being told "go and get vetted" and then
    /// having to find the community's DID again is what made applying feel like
    /// abandoning the join.
    #[test]
    fn j_on_an_application_joins_the_community_it_names() {
        use crate::state_handler::main_page::content::{ApplicationRow, VettingTab};

        let row = |community: &str| ApplicationRow {
            id: "a1".into(),
            community: community.into(),
            community_name: None,
            accent: None,
            pcs_zkp: false,
            next_step: None,
            join_did: "did:key:zA".into(),
            requirements: None,
            criterion: None,
            progress: None,
            satisfied: false,
            face: None,
            identity: Vec::new(),
            requests: Vec::new(),
            statements: 0,
        };
        let (mut page, mut rx) = page_for(MainMenu::Vetting, |s| {
            let vetting = &mut s.main_page.content_panel.vetting;
            vetting.applications = vec![row("did:web:kernel"), row("did:web:other")].into();
            vetting.selected = 1;
        });
        page.handle_key_event(press(KeyCode::Char('j')));
        assert!(matches!(
            rx.try_recv(),
            Ok(Action::StartJoinFor(did)) if did == "did:web:other"
        ));

        // With no application under the cursor there is no join to take up, so
        // the key does nothing rather than starting one for a community it
        // would have to invent.
        let (mut page, mut rx) = page_for(MainMenu::Vetting, |_| {});
        page.handle_key_event(press(KeyCode::Char('j')));
        assert!(rx.try_recv().is_err());

        // The desk is the other side of vetting; `j` is not its key.
        let (mut page, mut rx) = page_for(MainMenu::Vetting, |s| {
            let vetting = &mut s.main_page.content_panel.vetting;
            vetting.applications = vec![row("did:web:kernel")].into();
            vetting.tab = VettingTab::Desk;
        });
        page.handle_key_event(press(KeyCode::Char('j')));
        assert!(rx.try_recv().is_err());
    }

    /// The make-a-face form, as a holder with no attributes meets it: the row
    /// that needs a value takes typing (spaces too — it is a name), and once
    /// the value is an attribute the same row's Space and ←/→ choose instead.
    #[test]
    fn the_new_face_form_types_into_a_needed_value_and_chooses_a_held_one() {
        use crate::state_handler::actions::VettingAction as V;
        use crate::state_handler::main_page::content::{
            NewFaceFocus, NewFaceForm, PoolRow, VettingMode,
        };
        use ratatui::{Terminal, backend::TestBackend};

        let open = |pool: Vec<PoolRow>| {
            let form = NewFaceForm::open(
                "a1".into(),
                vec!["name.legal".into()],
                Vec::new(),
                pool,
                "Vetting".into(),
            );
            page_for(MainMenu::Vetting, move |s| {
                s.main_page.content_panel.vetting.mode = VettingMode::NewFace(Box::new(form));
            })
        };

        let (mut page, mut rx) = open(Vec::new());
        assert_eq!(
            match &page.props.main_page.content_panel.vetting.mode {
                VettingMode::NewFace(form) => form.focus,
                _ => unreachable!(),
            },
            NewFaceFocus::Asked(0),
            "the form opens on what is missing"
        );
        page.handle_key_event(press(KeyCode::Char('A')));
        assert!(matches!(vetting_action(&mut rx), V::Input(text) if text == "A"));
        page.handle_key_event(press(KeyCode::Char(' ')));
        assert!(
            matches!(vetting_action(&mut rx), V::Input(text) if text == " "),
            "a space is part of a name, not a tick"
        );
        page.handle_key_event(press(KeyCode::Enter));
        assert!(matches!(vetting_action(&mut rx), V::Submit));

        let mut terminal = Terminal::new(TestBackend::new(120, 40)).expect("test terminal");
        terminal
            .draw(|frame| page.render(frame, ()))
            .expect("render");
        let screen: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect();
        assert!(
            screen.contains("Make a face for this community"),
            "{screen}"
        );
        assert!(
            screen.contains("Your legal name (name.legal), exactly as on your documents:"),
            "{screen}"
        );
        assert!(
            screen.contains("0 of 1 required attribute ready — type your legal name below"),
            "{screen}"
        );
        assert!(!screen.contains("Tick at least one"), "{screen}");
        assert!(!screen.contains("under My Identity"), "{screen}");

        let held = |id: &str| PoolRow {
            attribute_id: id.into(),
            claim_type: "name.legal".into(),
            label: "name.legal".into(),
            value: Some("Alice Example".into()),
        };
        let (mut page, mut rx) = open(vec![held("one"), held("two")]);
        // Opened ready, so the focus is on the name; move to the claim row.
        page.handle_key_event(press(KeyCode::Down));
        assert!(matches!(vetting_action(&mut rx), V::NextField));
        // The page's props are not re-derived here: put the focus where the
        // loop would have. On the name, → moves the cursor (#578); on the
        // claim row it chooses.
        if let VettingMode::NewFace(form) = &mut page.props.main_page.content_panel.vetting.mode {
            form.focus = NewFaceFocus::Asked(0);
        }
        page.handle_key_event(press(KeyCode::Right));
        assert!(matches!(vetting_action(&mut rx), V::Cycle(true)));
        page.handle_key_event(press(KeyCode::Char(' ')));
        assert!(matches!(vetting_action(&mut rx), V::Toggle));
    }

    #[test]
    fn vetting_forms_take_text_cycle_and_tick() {
        use crate::state_handler::actions::VettingAction as V;
        use crate::state_handler::main_page::content::{AttestForm, VettingMode};

        // A focused text field takes typing, spaces included.
        let (mut page, mut rx) = page_for(MainMenu::Vetting, |s| {
            s.main_page.content_panel.vetting.mode = VettingMode::RequestVetter {
                application_id: "a1".into(),
                entry: "vetting-ticket:abc".into(),
                vetter: String::new(),
                ticket: None,
                note: None,
            };
        });
        page.handle_key_event(press(KeyCode::Char('Q')));
        assert!(matches!(vetting_action(&mut rx), V::Input(text) if text == "vetting-ticket:abcQ"));

        // In the checklist, the arrows cycle a choice and Space ticks a box —
        // each only on a row where it does something.
        let attest_on = |field: usize| {
            page_for(MainMenu::Vetting, move |s| {
                s.main_page.content_panel.vetting.mode = VettingMode::Attest {
                    request_id: "r1".into(),
                    form: AttestForm {
                        field,
                        ..AttestForm::default()
                    },
                };
            })
        };
        let (mut page, mut rx) = attest_on(0);
        page.handle_key_event(press(KeyCode::Right));
        assert!(matches!(vetting_action(&mut rx), V::Cycle(true)));
        page.handle_key_event(press(KeyCode::Char(' ')));
        assert!(rx.try_recv().is_err(), "the method is not a box to tick");
        page.handle_key_event(press(KeyCode::Enter));
        assert!(matches!(vetting_action(&mut rx), V::Submit));
        let (mut page, mut rx) = attest_on(4);
        page.handle_key_event(press(KeyCode::Char(' ')));
        assert!(matches!(vetting_action(&mut rx), V::Toggle));
        page.handle_key_event(press(KeyCode::Right));
        assert!(rx.try_recv().is_err(), "the attestation is not a choice");

        // A decline is confirmed with y, and n keeps the request — while the
        // reason has focus. On the note, both are letters of what is typed.
        let declining = |field: usize| {
            move |s: &mut State| {
                s.main_page.content_panel.vetting.mode = VettingMode::ConfirmDecline {
                    request_id: "r1".into(),
                    reason_index: 0,
                    message: String::new(),
                    field,
                };
            }
        };
        let (mut page, mut rx) = page_for(MainMenu::Vetting, declining(0));
        page.handle_key_event(press(KeyCode::Char('n')));
        assert!(matches!(vetting_action(&mut rx), V::Back));
        page.handle_key_event(press(KeyCode::Right));
        assert!(matches!(vetting_action(&mut rx), V::Cycle(true)));

        let (mut page, mut rx) = page_for(MainMenu::Vetting, declining(1));
        page.handle_key_event(press(KeyCode::Char('n')));
        assert!(
            matches!(vetting_action(&mut rx), V::Input(text) if text == "n"),
            "typed into the note, not taken as `keep it`"
        );
    }

    #[test]
    fn vetting_directory_results_page_and_ask_while_filters_take_text() {
        use crate::state_handler::actions::VettingAction as V;
        use crate::state_handler::main_page::content::{
            DIRECTORY_FIELDS, DirectoryView, ListedVetterRow, VettingMode,
        };
        let row = ListedVetterRow {
            did: "did:key:zCarol".into(),
            name: "Carol".into(),
            languages: "en".into(),
            location: None,
            methods: "in person".into(),
            documentation: "passport".into(),
            availability: None,
            contact_hint: None,
            events: vec![],
            grant_until: "2027-09-01".into(),
        };
        let on = |field: usize| {
            let row = row.clone();
            page_for(MainMenu::Vetting, move |s| {
                s.main_page.content_panel.vetting.mode =
                    VettingMode::Directory(Box::new(DirectoryView {
                        results: vec![row],
                        searched: true,
                        field,
                        ..DirectoryView::default()
                    }));
            })
        };
        let (mut page, mut rx) = on(DIRECTORY_FIELDS);
        page.handle_key_event(press(KeyCode::Char('n')));
        assert!(matches!(vetting_action(&mut rx), V::DirectoryPage(true)));
        page.handle_key_event(press(KeyCode::Char('p')));
        assert!(matches!(vetting_action(&mut rx), V::DirectoryPage(false)));
        page.handle_key_event(press(KeyCode::Char('a')));
        assert!(matches!(vetting_action(&mut rx), V::AskListedVetter));
        page.handle_key_event(press(KeyCode::Enter));
        assert!(matches!(vetting_action(&mut rx), V::Submit));

        // On the language filter the same letters are typing.
        let (mut page, mut rx) = on(1);
        page.handle_key_event(press(KeyCode::Char('n')));
        assert!(matches!(vetting_action(&mut rx), V::Input(text) if text == "n"));
    }

    /// The profile and the vetter credential belong to the desk, not to one of
    /// its views: `p` and `g` work from all three, not only from Tickets — a
    /// list the profile has nothing to do with.
    #[test]
    fn vetting_desk_opens_the_profile_and_resend_from_every_view() {
        use crate::state_handler::actions::VettingAction as V;
        use crate::state_handler::main_page::content::{DeskView, VettingTab};

        for view in DeskView::ALL {
            let (mut page, mut rx) = page_for(MainMenu::Vetting, |s| {
                s.main_page.content_panel.vetting.tab = VettingTab::Desk;
                s.main_page.content_panel.vetting.desk_view = view;
            });
            page.handle_key_event(press(KeyCode::Char('p')));
            assert!(
                matches!(vetting_action(&mut rx), V::EditProfile),
                "p must open the profile from {view:?}"
            );
            page.handle_key_event(press(KeyCode::Char('g')));
            assert!(
                matches!(vetting_action(&mut rx), V::AskResend),
                "g must ask for the credential again from {view:?}"
            );
        }
    }

    /// A view's own keys stay its own, and ←/→ move between them.
    #[test]
    fn vetting_desk_views_own_their_keys() {
        use crate::state_handler::actions::VettingAction as V;
        use crate::state_handler::main_page::content::{DeskView, VettingTab};

        let desk_on = |view: DeskView| {
            page_for(MainMenu::Vetting, move |s| {
                vetting_rows(s);
                s.main_page.content_panel.vetting.tab = VettingTab::Desk;
                s.main_page.content_panel.vetting.desk_view = view;
            })
        };

        let (mut page, mut rx) = desk_on(DeskView::Requests);
        page.handle_key_event(press(KeyCode::Char('x')));
        assert!(matches!(vetting_action(&mut rx), V::ArmDecline));
        page.handle_key_event(press(KeyCode::Char('t')));
        assert!(
            rx.try_recv().is_err(),
            "a ticket is handed out from the Tickets view"
        );
        page.handle_key_event(press(KeyCode::Right));
        assert!(matches!(vetting_action(&mut rx), V::SwitchDeskView(true)));
        page.handle_key_event(press(KeyCode::Left));
        assert!(matches!(vetting_action(&mut rx), V::SwitchDeskView(false)));

        let (mut page, mut rx) = desk_on(DeskView::Tickets);
        page.handle_key_event(press(KeyCode::Char('t')));
        assert!(matches!(vetting_action(&mut rx), V::NewTicket));
        // A QR code has to be whole on screen to scan, so it gets a view of its
        // own rather than a share of the desk.
        page.handle_key_event(press(KeyCode::Enter));
        assert!(matches!(vetting_action(&mut rx), V::ShowTicket));
        page.handle_key_event(press(KeyCode::Char('x')));
        assert!(rx.try_recv().is_err(), "declining is the Requests view's");
        // A ticket with no link: copying the link does nothing.
        page.handle_key_event(press(KeyCode::Char('u')));
        assert!(rx.try_recv().is_err());

        // Enter on a request opens its journey — the ticket view is the
        // Tickets view's Enter, not the desk's — and `a` still goes straight to
        // attesting for a vetter who knows where they are.
        let (mut page, mut rx) = desk_on(DeskView::Requests);
        page.handle_key_event(press(KeyCode::Enter));
        assert!(matches!(vetting_action(&mut rx), V::OpenJourney));
        page.handle_key_event(press(KeyCode::Char('a')));
        assert!(matches!(vetting_action(&mut rx), V::StartAttest));

        let (mut page, mut rx) = desk_on(DeskView::Issued);
        page.handle_key_event(press(KeyCode::Char('w')));
        assert!(matches!(vetting_action(&mut rx), V::ArmWithdraw));

        // Applications has no desk views, so ←/→ fall through to the page and
        // move panel focus, as they do on every other panel.
        let (mut page, mut rx) = page_for(MainMenu::Vetting, vetting_rows);
        page.handle_key_event(press(KeyCode::Right));
        assert!(
            matches!(rx.try_recv(), Ok(Action::MainPanelSwitch(_))),
            "on Applications the arrows still move panel focus"
        );
        page.handle_key_event(press(KeyCode::Char('v')));
        assert!(matches!(vetting_action(&mut rx), V::FindVetters));
    }

    /// Esc leaves the content panel. The desk consumes ←/→ for its views, so
    /// without this there would be no way back to the menu from it.
    #[test]
    fn vetting_esc_returns_focus_to_the_menu() {
        use crate::state_handler::main_page::content::{DeskView, VettingTab};

        for (tab, view) in [
            (VettingTab::Applications, DeskView::Requests),
            (VettingTab::Desk, DeskView::Requests),
            (VettingTab::Desk, DeskView::Tickets),
            (VettingTab::Desk, DeskView::Issued),
        ] {
            let (mut page, mut rx) = page_for(MainMenu::Vetting, move |s| {
                s.main_page.content_panel.vetting.tab = tab;
                s.main_page.content_panel.vetting.desk_view = view;
            });
            page.handle_key_event(press(KeyCode::Esc));
            assert!(
                matches!(
                    rx.try_recv(),
                    Ok(Action::MainPanelSwitch(MainPanel::MainMenu))
                ),
                "Esc must leave the panel from {tab:?}/{view:?}"
            );
        }
    }

    #[test]
    fn vetting_profile_event_rows_remove_and_ticks_toggle() {
        use crate::state_handler::actions::VettingAction as V;
        use crate::state_handler::main_page::content::{
            PROFILE_FIELDS, VetterProfileForm, VettingMode,
        };
        use openvtc_core::vetting::book::VetterPolicy;
        use openvtc_core::vetting::registry::{EventDraft, ProfileDraft};
        let form = |field: usize| {
            let mut draft = ProfileDraft::new(&VetterPolicy::default());
            draft.events.push(EventDraft::default());
            VetterProfileForm {
                membership_index: 0,
                draft,
                field,
                event: None,
                error: None,
                state_line: None,
            }
        };
        let (mut page, mut rx) = page_for(MainMenu::Vetting, |s| {
            s.main_page.content_panel.vetting.mode =
                VettingMode::Profile(Box::new(form(PROFILE_FIELDS)));
        });
        page.handle_key_event(press(KeyCode::Char('x')));
        assert!(matches!(vetting_action(&mut rx), V::RemoveEvent));

        let (mut page, mut rx) = page_for(MainMenu::Vetting, |s| {
            s.main_page.content_panel.vetting.mode = VettingMode::Profile(Box::new(form(1)));
        });
        page.handle_key_event(press(KeyCode::Char(' ')));
        assert!(matches!(vetting_action(&mut rx), V::Toggle));
        page.handle_key_event(press(KeyCode::Char('x')));
        assert!(rx.try_recv().is_err(), "x removes nothing off an event row");
    }

    /// With a journey open, only the steps reached take their keys — a key
    /// for a step still to come does nothing — and Esc closes the journey.
    #[test]
    fn a_journey_takes_only_the_keys_of_steps_reached() {
        use crate::state_handler::actions::VettingAction as V;
        use crate::state_handler::main_page::content::{ApplicationRow, JourneySteps, JourneyView};
        use openvtc_core::vetting::journey::{ApplicantStep, JourneyStep, StepState};
        let open = |s: &mut State| {
            let v = &mut s.main_page.content_panel.vetting;
            v.applications = vec![ApplicationRow {
                id: "a1".into(),
                community: "did:web:kernel".into(),
                community_name: None,
                accent: None,
                pcs_zkp: false,
                next_step: None,
                join_did: "did:key:zA".into(),
                requirements: None,
                criterion: None,
                progress: None,
                satisfied: false,
                face: None,
                identity: Vec::new(),
                requests: Vec::new(),
                statements: 0,
            }]
            .into();
            v.journey = Some(JourneyView {
                title: "Applying to kernel as alice".into(),
                pcs_zkp: false,
                steps: JourneySteps::Applicant(
                    ApplicantStep::ALL
                        .iter()
                        .map(|&step| JourneyStep {
                            step,
                            state: if step == ApplicantStep::Requirements {
                                StepState::Current
                            } else {
                                StepState::Todo
                            },
                            detail: None,
                        })
                        .collect(),
                ),
            });
        };
        let (mut page, mut rx) = page_for(MainMenu::Vetting, open);
        for early in ['f', 'r', 'v', 'j'] {
            page.handle_key_event(press(KeyCode::Char(early)));
            assert!(
                rx.try_recv().is_err(),
                "`{early}` is for a step not reached"
            );
        }
        page.handle_key_event(press(KeyCode::Enter));
        assert!(rx.try_recv().is_err(), "no session to send a card to yet");
        page.handle_key_event(press(KeyCode::Char('m')));
        assert!(matches!(vetting_action(&mut rx), V::RefreshRequirements));
        page.handle_key_event(press(KeyCode::Esc));
        assert!(matches!(vetting_action(&mut rx), V::CloseJourney));
    }

    /// `h` on the desk opens the hidden-vetting view, and `d` there draws now.
    #[test]
    fn vetting_desk_opens_hidden_vetting_on_h_and_draws_on_d() {
        use crate::state_handler::actions::VettingAction as V;
        use crate::state_handler::main_page::content::{VettingMode, VettingTab};
        let (mut page, mut rx) = page_for(MainMenu::Vetting, |s: &mut State| {
            s.main_page.content_panel.vetting.tab = VettingTab::Desk;
        });
        page.handle_key_event(press(KeyCode::Char('h')));
        assert!(matches!(vetting_action(&mut rx), V::OpenHiddenVetting));
        // Getting tokens is one key from anywhere on the desk.
        page.handle_key_event(press(KeyCode::Char('k')));
        assert!(matches!(vetting_action(&mut rx), V::DrawNow));

        let (mut page, mut rx) = page_for(MainMenu::Vetting, |s: &mut State| {
            s.main_page.content_panel.vetting.tab = VettingTab::Desk;
            s.main_page.content_panel.vetting.hidden = vec![Default::default()].into();
            s.main_page.content_panel.vetting.mode = VettingMode::HiddenVetting { index: 0 };
        });
        page.handle_key_event(press(KeyCode::Char('d')));
        assert!(matches!(vetting_action(&mut rx), V::DrawNow));
        page.handle_key_event(press(KeyCode::Esc));
        assert!(matches!(vetting_action(&mut rx), V::Back));
    }

    /// The card page is where a missing face shows up, so `f` chooses one    /// The card page is where a missing face shows up, so `f` chooses one
    /// there rather than only after backing out to the application.
    #[test]
    fn vetting_card_chooses_the_face_on_f() {
        use crate::state_handler::actions::VettingAction as V;
        use crate::state_handler::main_page::content::VettingMode;
        let (mut page, mut rx) = page_for(MainMenu::Vetting, |s: &mut State| {
            vetting_rows(s);
            s.main_page.content_panel.vetting.mode = VettingMode::SendCard {
                application_id: "a".into(),
                session_id: "s".into(),
                preview: None,
            };
        });
        page.handle_key_event(press(KeyCode::Char('f')));
        assert!(matches!(vetting_action(&mut rx), V::ChooseFace));
    }

    /// The holder-grant view ends with "then press f", and that key has to
    /// work. It was unbound, so the one thing the screen asks for did nothing —
    /// and with no field and no rows, nothing else visibly worked either, which
    /// left the view looking frozen until the app was restarted.
    #[test]
    fn vetting_holder_grant_retries_on_f() {
        use crate::state_handler::actions::VettingAction as V;
        use crate::state_handler::main_page::content::VettingMode;
        let grant = |s: &mut State| {
            s.main_page.content_panel.vetting.mode = VettingMode::HolderGrant {
                credential_did: Some("did:key:z6MkThisInstall".into()),
            };
        };
        let (mut page, mut rx) = page_for(MainMenu::Vetting, grant);
        page.handle_key_event(press(KeyCode::Char('f')));
        assert!(matches!(vetting_action(&mut rx), V::ChooseFace));

        // And the way out still works, so the view is never a dead end.
        let (mut page, mut rx) = page_for(MainMenu::Vetting, grant);
        page.handle_key_event(press(KeyCode::Esc));
        assert!(matches!(vetting_action(&mut rx), V::Back));
    }

    /// Asking a vetter is one field. The link carries the vetter's DID, so a
    /// separate box for it only ever held what the paste was about to
    /// overwrite — and Tab had a second field to move to that nobody typed in.
    #[test]
    fn vetting_ask_a_vetter_is_one_field() {
        use crate::state_handler::actions::VettingAction as V;
        use crate::state_handler::main_page::content::VettingMode;
        let (mut page, mut rx) = page_for(MainMenu::Vetting, |s| {
            s.main_page.content_panel.vetting.mode = VettingMode::RequestVetter {
                application_id: "a1".into(),
                entry: String::new(),
                vetter: String::new(),
                ticket: None,
                note: None,
            };
        });
        // Whatever is typed reaches the one field, wherever the cursor "is".
        page.handle_key_event(press(KeyCode::Char('v')));
        assert!(matches!(vetting_action(&mut rx), V::Input(t) if t == "v"));
        page.handle_key_event(press(KeyCode::Enter));
        assert!(matches!(vetting_action(&mut rx), V::Submit));
    }

    #[test]
    fn vetting_a_pasted_ticket_link_fills_the_request_form() {
        use crate::state_handler::actions::VettingAction as V;
        use crate::state_handler::main_page::content::VettingMode;
        let request = |s: &mut State| {
            s.main_page.content_panel.vetting.mode = VettingMode::RequestVetter {
                application_id: "a1".into(),
                entry: String::new(),
                vetter: String::new(),
                ticket: None,
                note: None,
            };
        };
        let (mut page, mut rx) = page_for(MainMenu::Vetting, request);
        page.handle_paste_event("  vetting-ticket:?v=1&community=did%3Akey%3Az&vetter=x  ");
        assert!(matches!(
            vetting_action(&mut rx),
            V::PasteTicket(text) if text.starts_with("vetting-ticket:")
        ));
        let (mut page, mut rx) = page_for(MainMenu::Vetting, request);
        page.handle_paste_event("did:key:zCarol");
        assert!(matches!(vetting_action(&mut rx), V::Input(text) if text == "did:key:zCarol"));
    }

    // ----- Communities -------------------------------------------------------

    #[test]
    fn communities_confirm_commits_and_cancels() {
        // y/Enter while a removal is armed commits the delete at that index.
        let (mut page, mut rx) = page_for(MainMenu::Communities, |s| {
            s.main_page.content_panel.communities.confirm_delete = Some(2);
        });
        page.handle_key_event(press(KeyCode::Char('y')));
        match rx.try_recv() {
            Ok(Action::DeleteCommunity(2)) => {}
            _ => panic!("expected DeleteCommunity(2)"),
        }

        // Any other key cancels.
        let (mut page, mut rx) = page_for(MainMenu::Communities, |s| {
            s.main_page.content_panel.communities.confirm_delete = Some(0);
        });
        page.handle_key_event(press(KeyCode::Char('n')));
        match rx.try_recv() {
            Ok(Action::CommunityCancelDelete) => {}
            _ => panic!("expected CommunityCancelDelete"),
        }
    }

    #[test]
    fn communities_f_toggles_favourite_at_selection() {
        // R-C-4: `f` on the Communities panel stars the highlighted row.
        let (mut page, mut rx) = page_for(MainMenu::Communities, |s| {
            s.main_page.content_panel.communities.items = vec![
                community_summary("a"),
                community_summary("b"),
                community_summary("c"),
            ]
            .into();
            s.main_page.content_panel.communities.selected_index = 1;
        });
        page.handle_key_event(press(KeyCode::Char('f')));
        match rx.try_recv() {
            Ok(Action::ToggleFavourite(1)) => {}
            _ => panic!("expected ToggleFavourite(1)"),
        }
    }

    /// A "Joining" row sits after the memberships: Down reaches it, Enter opens
    /// its application on the Vetting page, and the membership keys stay inert
    /// there rather than acting on whichever membership shares the index.
    #[test]
    fn communities_enter_on_a_joining_row_opens_its_application() {
        use crate::state_handler::actions::VettingAction as V;
        use crate::state_handler::main_page::content::JoiningSummary;
        let joining = || JoiningSummary {
            application_id: "app-1".to_string(),
            community_name: "Globex".to_string(),
            accent: None,
            persona_label: "Work".to_string(),
            standing: "1 of 1 statement — ready to join".to_string(),
            ready: true,
        };

        let (mut page, mut rx) = page_for(MainMenu::Communities, |s| {
            s.main_page.content_panel.communities.items = vec![community_summary("a")].into();
            s.main_page.content_panel.communities.joining = vec![joining()].into();
        });
        page.handle_key_event(press(KeyCode::Down));
        assert!(matches!(rx.try_recv(), Ok(Action::CommunitySelect(1))));

        let (mut page, mut rx) = page_for(MainMenu::Communities, |s| {
            s.main_page.content_panel.communities.items = vec![community_summary("a")].into();
            s.main_page.content_panel.communities.joining = vec![joining()].into();
            s.main_page.content_panel.communities.selected_index = 1;
        });
        page.handle_key_event(press(KeyCode::Enter));
        assert!(matches!(
            rx.try_recv(),
            Ok(Action::Vetting(V::OpenApplication(id))) if id == "app-1"
        ));
        page.handle_key_event(press(KeyCode::Char('f')));
        assert!(
            rx.try_recv().is_err(),
            "no membership is under the cursor for `f` to star"
        );
    }

    #[test]
    fn communities_a_acknowledges_at_selection() {
        // R-S-2: `a` on the Communities panel acknowledges the highlighted row.
        let (mut page, mut rx) = page_for(MainMenu::Communities, |s| {
            s.main_page.content_panel.communities.items =
                vec![community_summary("a"), community_summary("b")].into();
            s.main_page.content_panel.communities.selected_index = 1;
        });
        page.handle_key_event(press(KeyCode::Char('a')));
        match rx.try_recv() {
            Ok(Action::AcknowledgeCommunity(1)) => {}
            _ => panic!("expected AcknowledgeCommunity(1)"),
        }
    }

    /// `r` on an Active community opens its Repos view; on a Pending one it
    /// does nothing (there is no community to govern repositories yet).
    #[test]
    fn communities_r_opens_repos_for_active_rows_only() {
        use crate::state_handler::actions::ReposAction as R;
        let (mut page, mut rx) = page_for(MainMenu::Communities, |s| {
            s.main_page.content_panel.communities.items =
                vec![community_summary_with("a", true, false, false)].into();
        });
        page.handle_key_event(press(KeyCode::Char('r')));
        assert!(matches!(rx.try_recv(), Ok(Action::Repos(R::Open(0)))));

        let (mut page, mut rx) = page_for(MainMenu::Communities, |s| {
            s.main_page.content_panel.communities.items =
                vec![community_summary_with("a", false, false, true)].into();
        });
        page.handle_key_event(press(KeyCode::Char('r')));
        assert!(rx.try_recv().is_err());
    }

    pub(super) fn repos_view() -> crate::state_handler::main_page::repos::ReposView {
        crate::state_handler::main_page::repos::ReposView::new(
            "did:webvh:vtc".into(),
            openvtc_core::config::account::PersonaId(uuid::Uuid::nil()),
            "did:webvh:me".into(),
            "Acme".into(),
        )
    }

    /// The local keys: clone, sign, set up, workspace — and while a workspace
    /// form or removal is open, it has the keys.
    #[test]
    fn the_repos_view_maps_its_local_keys() {
        use crate::state_handler::actions::{ReposAction as R, WorkspaceAction as W};
        use crate::state_handler::main_page::repos::{WorkspaceChange, WorkspaceForm};
        use openvtc_core::git_workspace::CloneProtocol;

        let list = repos_view();
        for (key, want) in [
            (KeyCode::Char('c'), W::Clone),
            (KeyCode::Char('e'), W::Sign),
            (KeyCode::Char('E'), W::Unsign),
            (KeyCode::Char('s'), W::SetUp),
            (KeyCode::Char('S'), W::RemoveArm),
            (KeyCode::Char('u'), W::UseStart),
            (KeyCode::Char('w'), W::SettingsStart),
            (KeyCode::Char('f'), W::AccountStart),
            (KeyCode::Char('F'), W::Fork),
            (KeyCode::Char('R'), W::RemotesToSsh),
        ] {
            assert_eq!(repos_key(press(key), &list), Some(R::Workspace(want)));
        }
        // Nothing checked out: `p` has no path to copy.
        assert_eq!(repos_copy_path(&list), None);

        let mut form = repos_view();
        form.workspace.form = Some(WorkspaceForm::Settings {
            root: "~/sr".into(),
            protocol: Some(CloneProtocol::Https),
            error: None,
        });
        assert_eq!(
            repos_key(press(KeyCode::Char('c')), &form),
            Some(R::Workspace(W::SettingsInput("~/src".into()))),
            "typing in the form never clones"
        );
        assert_eq!(
            repos_key(press(KeyCode::Backspace), &form),
            Some(R::Workspace(W::SettingsInput("~/s".into())))
        );
        assert_eq!(
            repos_key(press(KeyCode::Tab), &form),
            Some(R::Workspace(W::SettingsProtocol))
        );
        assert_eq!(
            repos_key(press(KeyCode::Enter), &form),
            Some(R::Workspace(W::SettingsSubmit))
        );
        assert_eq!(
            repos_key(press(KeyCode::Esc), &form),
            Some(R::Workspace(W::Cancel))
        );

        let mut armed = repos_view();
        armed.workspace.confirm = Some(WorkspaceChange::RemoveIdentity);
        assert_eq!(
            repos_key(press(KeyCode::Char('y')), &armed),
            Some(R::Workspace(W::Confirm))
        );
        assert_eq!(
            repos_key(press(KeyCode::Enter), &armed),
            Some(R::Workspace(W::Cancel)),
            "only y confirms a removal"
        );
    }

    /// The Repos view owns the keys while open: its screen keys, an armed
    /// change's y/any, and the add form's fields.
    #[test]
    fn the_repos_view_maps_its_keys() {
        use crate::state_handler::actions::ReposAction as R;
        use crate::state_handler::main_page::repos::{AddPersonForm, ArmedChange, ReposScreen};

        let list = repos_view();
        assert_eq!(
            repos_key(press(KeyCode::Char('n')), &list),
            Some(R::NewStart)
        );
        assert_eq!(repos_key(press(KeyCode::Enter), &list), Some(R::OpenRepo));
        assert_eq!(
            repos_key(press(KeyCode::Char('l')), &list),
            Some(R::LinkStart)
        );
        assert_eq!(
            repos_key(press(KeyCode::Char('a')), &list),
            None,
            "add is per repo"
        );

        let mut repo = repos_view();
        repo.screen = ReposScreen::Repo {
            resource: "github.com/acme/widgets".into(),
        };
        assert_eq!(
            repos_key(press(KeyCode::Char('a')), &repo),
            Some(R::AddStart)
        );
        assert_eq!(
            repos_key(press(KeyCode::Char('x')), &repo),
            Some(R::RevokeArm)
        );
        assert_eq!(
            repos_key(press(KeyCode::Char('t')), &repo),
            Some(R::TransferArm)
        );
        assert_eq!(
            repos_key(
                KeyEvent::new(KeyCode::Char('A'), KeyModifiers::SHIFT),
                &repo
            ),
            Some(R::ArchiveArm)
        );
        assert_eq!(
            repos_key(press(KeyCode::Char('v')), &repo),
            Some(R::DriftRevertArm)
        );
        assert_eq!(
            repos_key(press(KeyCode::Char('o')), &repo),
            Some(R::DriftAdoptArm)
        );
        assert_eq!(
            repos_key(press(KeyCode::Char('v')), &list),
            None,
            "drift is per repo"
        );

        let mut armed = repo.clone();
        armed.confirm = Some(ArmedChange {
            request: openvtc_core::git_ns::Request::Archive {
                resource: "github.com/acme/widgets".into(),
            },
            summary: String::new(),
        });
        assert_eq!(
            repos_key(press(KeyCode::Char('y')), &armed),
            Some(R::Confirm)
        );
        assert_eq!(
            repos_key(press(KeyCode::Enter), &armed),
            Some(R::Cancel),
            "Enter does not confirm"
        );
        assert_eq!(
            repos_key(press(KeyCode::Char('x')), &armed),
            Some(R::Cancel)
        );

        let mut adding = repo;
        adding.add = Some(AddPersonForm::new("github.com/acme/widgets".into()));
        assert_eq!(
            repos_key(press(KeyCode::Char('k')), &adding),
            Some(R::AddInput {
                field: 0,
                value: "k".into()
            })
        );
        assert_eq!(
            repos_key(ctrl(KeyCode::Char('d')), &adding),
            Some(R::AddToggleExternal)
        );
        assert_eq!(
            repos_key(press(KeyCode::Tab), &adding),
            Some(R::AddField(1))
        );
        assert_eq!(
            repos_key(press(KeyCode::Enter), &adding),
            Some(R::AddSubmit)
        );
    }

    /// The new-repository form's owner picker (field 4): typing filters,
    /// Ctrl+D pastes a DID, Ctrl+A adds it, and Enter still submits the
    /// whole form rather than the owner field.
    #[test]
    fn the_new_repo_owner_field_maps_its_keys() {
        use crate::state_handler::actions::ReposAction as R;
        use crate::state_handler::main_page::repos::{NewRepoForm, ReposScreen};

        let mut naming = repos_view();
        let mut form = NewRepoForm {
            field: 4,
            ..NewRepoForm::default()
        };
        form.owner_query = "da".into();
        naming.screen = ReposScreen::NewRepo(form);
        assert_eq!(
            repos_key(press(KeyCode::Char('n')), &naming),
            Some(R::NewOwnerQuery("dan".into()))
        );
        assert_eq!(
            repos_key(ctrl(KeyCode::Char('a')), &naming),
            Some(R::NewOwnerAdd)
        );
        assert_eq!(
            repos_key(ctrl(KeyCode::Char('d')), &naming),
            Some(R::NewOwnerToggleExternal)
        );
        assert_eq!(
            repos_key(press(KeyCode::Enter), &naming),
            Some(R::NewSubmit),
            "Enter submits the form, not the owner field"
        );
        assert_eq!(
            repos_key(press(KeyCode::Backspace), &naming),
            Some(R::NewOwnerQuery("d".into()))
        );

        let mut empty_query = naming.clone();
        if let ReposScreen::NewRepo(form) = &mut empty_query.screen {
            form.owner_query.clear();
        }
        assert_eq!(
            repos_key(press(KeyCode::Backspace), &empty_query),
            Some(R::NewOwnerRemoveLast),
            "backspace on an empty query drops the last owner, chip-input style"
        );
    }

    /// A pasted DID lands in the add form's person field.
    #[test]
    fn communities_leave_archive_delete_are_status_gated() {
        // Active row: `l` arms a leave; `d`/`x` do nothing (must leave first).
        let active = || {
            page_for(MainMenu::Communities, |s| {
                s.main_page.content_panel.communities.items =
                    vec![community_summary_with("a", true, false, false)].into();
            })
        };
        let (mut page, mut rx) = active();
        page.handle_key_event(press(KeyCode::Char('l')));
        match rx.try_recv() {
            Ok(Action::CommunityConfirmLeave(0)) => {}
            _ => panic!("expected CommunityConfirmLeave(0)"),
        }
        // Active row: `m` arms issuing this membership's reciprocal VMC to the
        // community — it is sent to someone else, so it confirms (#579).
        let (mut page, mut rx) = active();
        page.handle_key_event(press(KeyCode::Char('m')));
        match rx.try_recv() {
            Ok(Action::CommunityConfirmSend(CommunitySend::IssueVmc(0))) => {}
            _ => panic!("expected CommunityConfirmSend(IssueVmc(0))"),
        }
        // Active row: `R` arms asking the community to renew this membership.
        let (mut page, mut rx) = active();
        page.handle_key_event(press(KeyCode::Char('R')));
        match rx.try_recv() {
            Ok(Action::CommunityConfirmSend(CommunitySend::Renew(0))) => {}
            _ => panic!("expected CommunityConfirmSend(Renew(0))"),
        }
        // Active row: `c` opens the community's capabilities view (the
        // cancel-pending-join meaning of `c` is Pending-only; the two are
        // disjoint by status).
        let (mut page, mut rx) = active();
        page.handle_key_event(press(KeyCode::Char('c')));
        match rx.try_recv() {
            Ok(Action::CapabilitiesOpen(0)) => {}
            _ => panic!("expected CapabilitiesOpen(0) for Active rows"),
        }
        let (mut page, mut rx) = active();
        page.handle_key_event(press(KeyCode::Char('d')));
        assert!(
            rx.try_recv().is_err(),
            "delete is gated off for Active rows"
        );
        let (mut page, mut rx) = active();
        page.handle_key_event(press(KeyCode::Char('x')));
        assert!(
            rx.try_recv().is_err(),
            "archive is gated off for Active rows"
        );

        // Inactive row: `x` archives, `d` arms delete; `l` does nothing.
        let inactive = || {
            page_for(MainMenu::Communities, |s| {
                s.main_page.content_panel.communities.items =
                    vec![community_summary_with("a", false, true, false)].into();
            })
        };
        let (mut page, mut rx) = inactive();
        page.handle_key_event(press(KeyCode::Char('x')));
        match rx.try_recv() {
            Ok(Action::ArchiveCommunity(0)) => {}
            _ => panic!("expected ArchiveCommunity(0)"),
        }
        let (mut page, mut rx) = inactive();
        page.handle_key_event(press(KeyCode::Char('d')));
        match rx.try_recv() {
            Ok(Action::CommunityConfirmDelete(0)) => {}
            _ => panic!("expected CommunityConfirmDelete(0)"),
        }
        let (mut page, mut rx) = inactive();
        page.handle_key_event(press(KeyCode::Char('l')));
        assert!(
            rx.try_recv().is_err(),
            "leave is gated off for inactive rows"
        );
        let (mut page, mut rx) = inactive();
        page.handle_key_event(press(KeyCode::Char('R')));
        assert!(
            rx.try_recv().is_err(),
            "renew is gated off for inactive rows"
        );

        // Pending row: `c` arms a cancel; `d`/`x`/`l` do nothing.
        let pending = || {
            page_for(MainMenu::Communities, |s| {
                s.main_page.content_panel.communities.items =
                    vec![community_summary_with("a", false, false, true)].into();
            })
        };
        let (mut page, mut rx) = pending();
        page.handle_key_event(press(KeyCode::Char('c')));
        match rx.try_recv() {
            Ok(Action::CommunityConfirmWithdraw(0)) => {}
            _ => panic!("expected CommunityConfirmWithdraw(0)"),
        }
        for (k, what) in [
            ('d', "delete"),
            ('x', "archive"),
            ('l', "leave"),
            ('R', "renew"),
        ] {
            let (mut page, mut rx) = pending();
            page.handle_key_event(press(KeyCode::Char(k)));
            assert!(
                rx.try_recv().is_err(),
                "{what} is gated off for pending rows"
            );
        }
    }

    #[test]
    fn communities_leave_confirm_commits_and_cancels() {
        let (mut page, mut rx) = page_for(MainMenu::Communities, |s| {
            s.main_page.content_panel.communities.confirm_leave = Some(0);
        });
        page.handle_key_event(press(KeyCode::Char('y')));
        match rx.try_recv() {
            Ok(Action::LeaveCommunity(0)) => {}
            _ => panic!("expected LeaveCommunity(0)"),
        }

        let (mut page, mut rx) = page_for(MainMenu::Communities, |s| {
            s.main_page.content_panel.communities.confirm_leave = Some(0);
        });
        page.handle_key_event(press(KeyCode::Char('n')));
        match rx.try_recv() {
            Ok(Action::CommunityCancelLeave) => {}
            _ => panic!("expected CommunityCancelLeave"),
        }
    }

    #[test]
    fn communities_cancel_confirm_commits_and_cancels() {
        let (mut page, mut rx) = page_for(MainMenu::Communities, |s| {
            s.main_page.content_panel.communities.confirm_withdraw = Some(0);
        });
        page.handle_key_event(press(KeyCode::Char('y')));
        match rx.try_recv() {
            Ok(Action::WithdrawJoin(0)) => {}
            _ => panic!("expected WithdrawJoin(0)"),
        }

        let (mut page, mut rx) = page_for(MainMenu::Communities, |s| {
            s.main_page.content_panel.communities.confirm_withdraw = Some(0);
        });
        page.handle_key_event(press(KeyCode::Char('n')));
        match rx.try_recv() {
            Ok(Action::CommunityCancelWithdraw) => {}
            _ => panic!("expected CommunityCancelWithdraw"),
        }
    }

    #[test]
    fn communities_v_toggles_show_archived() {
        let (mut page, mut rx) = page_for(MainMenu::Communities, |_| {});
        page.handle_key_event(press(KeyCode::Char('v')));
        match rx.try_recv() {
            Ok(Action::ToggleShowArchived) => {}
            _ => panic!("expected ToggleShowArchived"),
        }
    }

    // ----- Community switcher overlay (R-C-7) --------------------------------

    #[test]
    fn ctrl_k_opens_switcher() {
        // Ctrl+K opens the quick switcher from the main page (here, no overlay yet).
        let (mut page, mut rx) = page_for(MainMenu::Communities, |_| {});
        page.handle_key_event(ctrl(KeyCode::Char('k')));
        match rx.try_recv() {
            Ok(Action::OpenCommunitySwitcher) => {}
            _ => panic!("expected OpenCommunitySwitcher"),
        }
    }

    #[test]
    fn open_switcher_owns_input_and_navigates() {
        // While the overlay is open it owns all input: ↑/↓ move, Enter switches,
        // Esc and Ctrl+K both close.
        let build = || {
            page_for(MainMenu::Communities, |s| {
                s.main_page.switcher = Some(CommunitySwitcherState {
                    items: vec![switcher_item("a", true), switcher_item("b", false)],
                    selected: 0,
                });
            })
        };

        let (mut page, mut rx) = build();
        page.handle_key_event(press(KeyCode::Down));
        match rx.try_recv() {
            Ok(Action::CommunitySwitcherMove(1)) => {}
            _ => panic!("expected CommunitySwitcherMove(1)"),
        }

        let (mut page, mut rx) = build();
        page.handle_key_event(press(KeyCode::Enter));
        match rx.try_recv() {
            Ok(Action::CommunitySwitcherSelect) => {}
            _ => panic!("expected CommunitySwitcherSelect"),
        }

        let (mut page, mut rx) = build();
        page.handle_key_event(press(KeyCode::Esc));
        match rx.try_recv() {
            Ok(Action::CloseCommunitySwitcher) => {}
            _ => panic!("expected CloseCommunitySwitcher on Esc"),
        }

        let (mut page, mut rx) = build();
        page.handle_key_event(ctrl(KeyCode::Char('k')));
        match rx.try_recv() {
            Ok(Action::CloseCommunitySwitcher) => {}
            _ => panic!("expected CloseCommunitySwitcher on Ctrl+K"),
        }
    }

    // ----- Identity pane: personas ---------------------------------------------

    pub(super) fn persona(did: &str, label: &str, bound: usize) -> ManagedDid {
        ManagedDid {
            did: did.to_string(),
            did_locator: None,
            agent_name: None,
            label: label.to_string(),
            bound_communities: bound,
            is_active: false,
        }
    }

    /// Two personas, the second one an orphan and selected.
    fn personas_with_orphan_selected() -> impl Fn(&mut State) {
        move |s: &mut State| {
            let p = &mut s.main_page.content_panel.identity;
            p.personas = vec![
                persona("did:webvh:example.com:alice", "Alice", 1),
                persona("did:webvh:example.com:bob", "Bob", 0),
            ]
            .into();
            p.persona_selected = 1;
        }
    }

    /// Removing a persona is armed here and answered by the existing
    /// identity-deletion path — the pane owns the question, not a second
    /// implementation of the answer.
    #[test]
    fn personas_confirm_commits_and_cancels() {
        let (mut page, mut rx) = page_for(MainMenu::Identity, |s| {
            s.main_page.content_panel.identity.confirm = PersonaConfirm::DeletePersona(1);
        });
        page.handle_key_event(press(KeyCode::Char('y')));
        match rx.try_recv() {
            Ok(Action::DeleteDid(1)) => {}
            _ => panic!("expected DeleteDid(1)"),
        }
        // Enter does not delete (#579).
        let (mut page, mut rx) = page_for(MainMenu::Identity, |s| {
            s.main_page.content_panel.identity.confirm = PersonaConfirm::DeletePersona(1);
        });
        page.handle_key_event(press(KeyCode::Enter));
        assert!(!matches!(rx.try_recv(), Ok(Action::DeleteDid(_))));

        let (mut page, mut rx) = page_for(MainMenu::Identity, |s| {
            s.main_page.content_panel.identity.confirm = PersonaConfirm::DeletePersona(0);
        });
        page.handle_key_event(press(KeyCode::Esc));
        match rx.try_recv() {
            Ok(Action::DidCancelDelete) => {}
            _ => panic!("expected DidCancelDelete"),
        }
    }

    /// Only an orphan arms: a persona a community still presents cannot be
    /// deleted without leaving that community, and the deletion path refuses
    /// it. Arming anyway would put a question that has already been answered.
    #[test]
    fn personas_d_arms_only_on_an_orphan_persona() {
        let (mut page, mut rx) = page_for(MainMenu::Identity, personas_with_orphan_selected());
        page.handle_key_event(press(KeyCode::Char('d')));
        match rx.try_recv() {
            Ok(Action::DidConfirmDelete(1)) => {}
            _ => panic!("expected DidConfirmDelete(1)"),
        }

        let (mut page, mut rx) = page_for(MainMenu::Identity, |s| {
            let p = &mut s.main_page.content_panel.identity;
            p.personas = vec![persona("did:webvh:example.com:alice", "Alice", 1)].into();
            p.persona_selected = 0;
        });
        page.handle_key_event(press(KeyCode::Char('d')));
        assert!(
            rx.try_recv().is_err(),
            "a persona a community presents must not arm a deletion"
        );
    }

    // ----- Community contexts ----------------------------------------------

    fn context_action(
        rx: &mut UnboundedReceiver<Action>,
    ) -> Option<crate::state_handler::actions::CommunityContextAction> {
        match rx.try_recv() {
            Ok(Action::CommunityContext(action)) => Some(action),
            _ => None,
        }
    }

    fn device_grant(did: &str) -> openvtc_core::community_access::DeviceGrant {
        openvtc_core::community_access::DeviceGrant {
            did: did.to_string(),
            role: "application".to_string(),
            label: None,
            contexts: vec!["top/a".to_string()],
            elsewhere: vec![],
            expires_at: None,
        }
    }

    fn device_view() -> crate::state_handler::main_page::content::DeviceAccessView {
        crate::state_handler::main_page::content::DeviceAccessView {
            community: "a".to_string(),
            context_id: "top/a".to_string(),
            can_grant: true,
            selected: 0,
            form: None,
            confirm_revoke: false,
            busy: false,
            message: None,
        }
    }

    /// `D` deletes a finished membership's own context, and is not offered on
    /// a live row or on a row in the top context.
    #[test]
    fn communities_shift_d_starts_a_context_deletion_only_where_one_can_happen() {
        use crate::state_handler::actions::CommunityContextAction as C;
        let (mut page, mut rx) = page_for(MainMenu::Communities, |s| {
            s.main_page.content_panel.communities.items =
                vec![community_summary_with("a", false, true, false)].into();
        });
        page.handle_key_event(press(KeyCode::Char('D')));
        assert!(matches!(context_action(&mut rx), Some(C::DeleteStart(0))));

        for summary in [
            community_summary_with("a", true, false, false),
            CommunitySummary {
                has_own_context: false,
                ..community_summary_with("a", false, true, false)
            },
        ] {
            let (mut page, mut rx) = page_for(MainMenu::Communities, |s| {
                s.main_page.content_panel.communities.items = vec![summary].into();
            });
            page.handle_key_event(press(KeyCode::Char('D')));
            assert!(context_action(&mut rx).is_none());
        }
    }

    #[test]
    fn communities_g_opens_device_access_for_an_own_context_only() {
        use crate::state_handler::actions::CommunityContextAction as C;
        let (mut page, mut rx) = page_for(MainMenu::Communities, |s| {
            s.main_page.content_panel.communities.items = vec![community_summary("a")].into();
        });
        page.handle_key_event(press(KeyCode::Char('g')));
        assert!(matches!(context_action(&mut rx), Some(C::DevicesOpen(0))));

        let (mut page, mut rx) = page_for(MainMenu::Communities, |s| {
            s.main_page.content_panel.communities.items = vec![CommunitySummary {
                has_own_context: false,
                ..community_summary("a")
            }]
            .into();
        });
        page.handle_key_event(press(KeyCode::Char('g')));
        assert!(context_action(&mut rx).is_none());
    }

    /// While a deletion is open every letter is part of the confirmation —
    /// `j` does not start a join — and a running delete takes no keys at all.
    #[test]
    fn a_context_deletion_owns_the_keys_while_open() {
        use crate::state_handler::actions::CommunityContextAction as C;
        use crate::state_handler::main_page::content::{ContextDeletePhase, ContextDeleteView};
        use openvtc_core::config::community_context::ContextDeletionPreview;
        let view = |phase| ContextDeleteView {
            vtc_did: "did:example:a".to_string(),
            persona: openvtc_core::config::account::PersonaId::new(),
            community: "a".to_string(),
            context_id: "top/a".to_string(),
            takes_persona: None,
            phase,
            typed: "DELET".to_string(),
        };
        let (mut page, mut rx) = page_for(MainMenu::Communities, |s| {
            s.main_page.content_panel.communities.items = vec![community_summary("a")].into();
            s.main_page.content_panel.communities.context_delete = Some(view(
                ContextDeletePhase::Ready(ContextDeletionPreview::default()),
            ));
        });
        page.handle_key_event(press(KeyCode::Char('E')));
        assert!(matches!(context_action(&mut rx), Some(C::DeleteInput(t)) if t == "DELETE"));
        page.handle_key_event(press(KeyCode::Char('j')));
        assert!(matches!(context_action(&mut rx), Some(C::DeleteInput(t)) if t == "DELETj"));
        page.handle_key_event(press(KeyCode::Backspace));
        assert!(matches!(context_action(&mut rx), Some(C::DeleteInput(t)) if t == "DELE"));
        page.handle_key_event(press(KeyCode::Enter));
        assert!(matches!(context_action(&mut rx), Some(C::DeleteConfirm)));
        page.handle_key_event(press(KeyCode::Esc));
        assert!(matches!(context_action(&mut rx), Some(C::DeleteCancel)));
        page.handle_paste_event("DELETE");
        assert!(
            rx.try_recv().is_err(),
            "the confirmation is typed, not pasted"
        );

        let (mut page, mut rx) = page_for(MainMenu::Communities, |s| {
            s.main_page.content_panel.communities.context_delete =
                Some(view(ContextDeletePhase::Deleting));
        });
        page.handle_key_event(press(KeyCode::Esc));
        page.handle_key_event(press(KeyCode::Char('j')));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn device_access_keys_drive_the_list() {
        use crate::state_handler::actions::CommunityContextAction as C;
        use crate::state_handler::main_page::content::GrantListing;
        let with_grant = |s: &mut State| {
            s.main_page.content_panel.communities.device_access = Some(device_view());
            s.main_page.content_panel.communities.device_grants.insert(
                "top/a".to_string(),
                GrantListing::Loaded(vec![device_grant("did:key:zA")]),
            );
        };
        let (mut page, mut rx) = page_for(MainMenu::Communities, with_grant);
        for (code, expected) in [
            (KeyCode::Char('n'), "GrantStart"),
            (KeyCode::Char('x'), "RevokeArm"),
            (KeyCode::Char('r'), "DevicesRefresh"),
            (KeyCode::Down, "DevicesSelect"),
            (KeyCode::Esc, "DevicesClose"),
        ] {
            page.handle_key_event(press(code));
            let got = match context_action(&mut rx) {
                Some(C::GrantStart) => "GrantStart",
                Some(C::RevokeArm) => "RevokeArm",
                Some(C::DevicesRefresh) => "DevicesRefresh",
                Some(C::DevicesSelect(0 | 1)) => "DevicesSelect",
                Some(C::DevicesClose) => "DevicesClose",
                _ => "something else",
            };
            assert_eq!(got, expected, "{code:?}");
        }

        // A finished membership takes no new device.
        let (mut page, mut rx) = page_for(MainMenu::Communities, |s| {
            with_grant(s);
            if let Some(v) = s.main_page.content_panel.communities.device_access.as_mut() {
                v.can_grant = false;
            }
        });
        page.handle_key_event(press(KeyCode::Char('n')));
        assert!(context_action(&mut rx).is_none());

        // An armed revocation is confirmed with `y` and dropped by anything else.
        let (mut page, mut rx) = page_for(MainMenu::Communities, |s| {
            with_grant(s);
            if let Some(v) = s.main_page.content_panel.communities.device_access.as_mut() {
                v.confirm_revoke = true;
            }
        });
        page.handle_key_event(press(KeyCode::Char('y')));
        assert!(matches!(context_action(&mut rx), Some(C::RevokeConfirm)));
        page.handle_key_event(press(KeyCode::Char('n')));
        assert!(matches!(context_action(&mut rx), Some(C::RevokeCancel)));
    }

    #[test]
    fn the_grant_form_takes_typing_paste_and_the_expiry() {
        use crate::state_handler::actions::CommunityContextAction as C;
        use crate::state_handler::main_page::content::GrantForm;
        let with_form = |field: usize| {
            move |s: &mut State| {
                s.main_page.content_panel.communities.device_access =
                    Some(crate::state_handler::main_page::content::DeviceAccessView {
                        form: Some(GrantForm {
                            did: "did:key:z".to_string(),
                            field,
                            ..GrantForm::default()
                        }),
                        ..device_view()
                    });
            }
        };
        let (mut page, mut rx) = page_for(MainMenu::Communities, with_form(0));
        page.handle_key_event(press(KeyCode::Char('6')));
        assert!(matches!(
            context_action(&mut rx),
            Some(C::GrantInput { field: 0, value }) if value == "did:key:z6"
        ));
        page.handle_paste_event("  6MkPasted \n");
        assert!(matches!(
            context_action(&mut rx),
            Some(C::GrantInput { field: 0, value }) if value == "did:key:z6MkPasted"
        ));
        page.handle_key_event(press(KeyCode::Tab));
        assert!(matches!(context_action(&mut rx), Some(C::GrantField(1))));
        page.handle_key_event(press(KeyCode::Enter));
        assert!(matches!(context_action(&mut rx), Some(C::GrantSubmit)));
        page.handle_key_event(press(KeyCode::Esc));
        assert!(matches!(context_action(&mut rx), Some(C::GrantCancel)));

        let (mut page, mut rx) = page_for(MainMenu::Communities, with_form(2));
        page.handle_key_event(press(KeyCode::Right));
        assert!(matches!(
            context_action(&mut rx),
            Some(C::GrantExpiry(i)) if i == openvtc_core::community_access::DEFAULT_EXPIRY + 1
        ));
        page.handle_key_event(press(KeyCode::Char('q')));
        assert!(
            context_action(&mut rx).is_none(),
            "the expiry is chosen, not typed"
        );
    }

    /// Both path rows, the typed path and the key line are all on screen. The
    /// overlay sizes itself per phase, so a phase whose height was not counted
    /// loses its last lines silently — here that would be the very choice the
    /// phase exists to offer.
    /// "Path" means nothing until you have seen one in place, so the phase
    /// that asks for it shows a DID with its last segment picked out. The
    /// choice is only open here — the path is inside the identifier.
    /// The first screen of the first thing anyone makes here. "Label for the
    /// new persona:" over an empty box said what to fill in and nothing about
    /// what it was for, so the field gets both: a line of explanation and an
    /// example sitting in it.
    #[test]
    fn the_label_phase_says_what_the_label_is_for() {
        use crate::state_handler::main_page::content::{CreatePersonaPhase, CreatePersonaState};
        use ratatui::{Terminal, backend::TestBackend};

        let draw = |overlay: CreatePersonaState| {
            let (page, _rx) = page_for(MainMenu::Identity, move |s: &mut State| {
                s.main_page.create_persona = Some(overlay.clone());
            });
            let mut terminal = Terminal::new(TestBackend::new(120, 40)).expect("test terminal");
            terminal
                .draw(|frame| page.render(frame, ()))
                .expect("render");
            terminal
                .backend()
                .buffer()
                .content()
                .iter()
                .map(ratatui::buffer::Cell::symbol)
                .collect::<String>()
        };

        let empty = draw(CreatePersonaState {
            phase: CreatePersonaPhase::Label,
            ..Default::default()
        });
        assert!(empty.contains("tell your personas apart"), "{empty}");
        assert!(
            empty.contains("Communities are shown the DID, not this"),
            "and what it is not: {empty}"
        );
        assert!(empty.contains("e.g. Work, Conference, Alice"), "{empty}");

        // The example is a placeholder, not a value: the moment anything is
        // typed it is gone, so nobody submits it by pressing Enter.
        let typed = draw(CreatePersonaState {
            phase: CreatePersonaPhase::Label,
            label: tui_input::Input::new("Conference".to_string()),
            ..Default::default()
        });
        assert!(typed.contains("Conference"), "{typed}");
        assert!(!typed.contains("e.g. Work"), "{typed}");
    }

    #[test]
    fn the_path_phase_shows_where_the_path_sits_in_a_did() {
        use crate::state_handler::main_page::content::{CreatePersonaPhase, CreatePersonaState};
        use ratatui::{Terminal, backend::TestBackend};

        let (page, _rx) = page_for(MainMenu::Identity, |s: &mut State| {
            s.main_page.create_persona = Some(CreatePersonaState {
                phase: CreatePersonaPhase::Path,
                ..Default::default()
            });
        });
        let mut terminal = Terminal::new(TestBackend::new(120, 40)).expect("test terminal");
        terminal
            .draw(|frame| page.render(frame, ()))
            .expect("render");
        let drawn: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect();

        assert!(
            drawn.contains("The path is the last part of the DID"),
            "{drawn}"
        );
        assert!(drawn.contains("did:webvh:"), "a worked example: {drawn}");
        assert!(drawn.contains("the path"), "and a pointer at it: {drawn}");
        assert!(
            drawn.contains("cannot be changed"),
            "and why it is worth getting right: {drawn}"
        );
    }

    /// `m` chooses how the persona is presented, on the default path screen
    /// only — while a path is being typed it is a letter of the path. The
    /// worked example follows the choice.
    #[test]
    fn create_persona_path_phase_chooses_the_did_method() {
        use crate::state_handler::main_page::content::{
            CreatePersonaPhase, CreatePersonaState, PersonaPathChoice,
        };
        use ratatui::{Terminal, backend::TestBackend};

        let (mut page, mut rx) = page_for(MainMenu::Identity, |s: &mut State| {
            s.main_page.create_persona = Some(CreatePersonaState {
                phase: CreatePersonaPhase::Path,
                ..Default::default()
            });
        });
        page.handle_key_event(press(KeyCode::Char('m')));
        assert!(matches!(
            rx.try_recv(),
            Ok(Action::CreatePersonaMethodCycle)
        ));

        let (mut page, mut rx) = page_for(MainMenu::Identity, |s: &mut State| {
            s.main_page.create_persona = Some(CreatePersonaState {
                phase: CreatePersonaPhase::Path,
                path_choice: PersonaPathChoice::Custom,
                ..Default::default()
            });
        });
        page.handle_key_event(press(KeyCode::Char('m')));
        assert!(
            matches!(rx.try_recv(), Ok(Action::CreatePersonaPathInput(k)) if k.code == KeyCode::Char('m')),
        );

        let (page, _rx) = page_for(MainMenu::Identity, |s: &mut State| {
            s.main_page.create_persona = Some(CreatePersonaState {
                phase: CreatePersonaPhase::Path,
                did_method: Some(vta_sdk::did_scid::DidMethod::Scid),
                ..Default::default()
            });
        });
        let mut terminal = Terminal::new(TestBackend::new(120, 40)).expect("test terminal");
        terminal
            .draw(|frame| page.render(frame, ()))
            .expect("render");
        let drawn: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect();
        assert!(drawn.contains("did:scid:vh:1:"), "{drawn}");
        assert!(drawn.contains("Presented as did:scid"), "{drawn}");
    }

    #[test]
    fn create_persona_path_overlay_leads_with_the_server_assigned_outcome() {
        use crate::state_handler::main_page::content::{CreatePersonaPhase, CreatePersonaState};
        use ratatui::{Terminal, backend::TestBackend};

        let (page, _rx) = page_for(MainMenu::Identity, |s: &mut State| {
            s.main_page.create_persona = Some(CreatePersonaState {
                phase: CreatePersonaPhase::Path,
                ..Default::default()
            });
        });
        let mut terminal = Terminal::new(TestBackend::new(120, 40)).expect("test terminal");
        terminal
            .draw(|frame| page.render(frame, ()))
            .expect("render");
        let drawn: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect();

        // No choice is put on the default screen — it says what will happen and
        // where a memorable name actually comes from.
        assert!(
            !drawn.contains("Server-assigned"),
            "no rows to pick: {drawn}"
        );
        assert!(!drawn.contains("My own path"), "{drawn}");
        assert!(drawn.contains("the server picks a random one"), "{drawn}");
        assert!(
            drawn.contains("an agent name"),
            "the cheap, reversible way to a memorable name: {drawn}"
        );
        assert!(
            drawn.contains("p: choose the path yourself"),
            "and the typed path is still reachable: {drawn}"
        );
    }

    /// `p` opens the editor, and the screen then shows the typed path in the
    /// worked example rather than the random one it will no longer get.
    #[test]
    fn create_persona_custom_path_screen_shows_what_was_typed() {
        use crate::state_handler::main_page::content::{
            CreatePersonaPhase, CreatePersonaState, PersonaPathChoice,
        };
        use ratatui::{Terminal, backend::TestBackend};

        let (page, _rx) = page_for(MainMenu::Identity, |s: &mut State| {
            s.main_page.create_persona = Some(CreatePersonaState {
                phase: CreatePersonaPhase::Path,
                path_choice: PersonaPathChoice::Custom,
                path: tui_input::Input::new("alice".to_string()),
                ..Default::default()
            });
        });
        let mut terminal = Terminal::new(TestBackend::new(120, 40)).expect("test terminal");
        terminal
            .draw(|frame| page.render(frame, ()))
            .expect("render");
        let drawn: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect();

        assert!(drawn.contains("Your path:  alice"), "{drawn}");
        assert!(
            drawn.contains("webvh.example.com:alice"),
            "the example shows the outcome of the screen you are on: {drawn}"
        );
        assert!(
            drawn.contains("Esc: let the server pick"),
            "the way out of the editor is the other outcome, not the label: {drawn}"
        );
    }

    /// Path phase: the default screen takes only `p`, Enter and Esc; inside the
    /// editor every other key is the path being typed, and Esc comes back out
    /// of the editor rather than out of the step.
    #[test]
    fn create_persona_path_phase_keys() {
        use crate::state_handler::main_page::content::{
            CreatePersonaPhase, CreatePersonaState, PersonaPathChoice,
        };
        let (mut page, mut rx) = page_for(MainMenu::Identity, |s: &mut State| {
            s.main_page.create_persona = Some(CreatePersonaState {
                phase: CreatePersonaPhase::Path,
                ..Default::default()
            });
        });

        page.handle_key_event(press(KeyCode::Char('a')));
        assert!(
            rx.try_recv().is_err(),
            "the default screen has no field, so a stray letter does nothing"
        );
        page.handle_key_event(press(KeyCode::Char('p')));
        assert!(matches!(
            rx.try_recv(),
            Ok(Action::CreatePersonaPathChoice(PersonaPathChoice::Custom))
        ));
        page.handle_key_event(press(KeyCode::Enter));
        assert!(matches!(rx.try_recv(), Ok(Action::CreatePersonaSubmit)));
        page.handle_key_event(press(KeyCode::Esc));
        assert!(
            matches!(rx.try_recv(), Ok(Action::CreatePersonaBack)),
            "Esc steps back to the label, it does not close the overlay"
        );

        let (mut page, mut rx) = page_for(MainMenu::Identity, |s: &mut State| {
            s.main_page.create_persona = Some(CreatePersonaState {
                phase: CreatePersonaPhase::Path,
                path_choice: PersonaPathChoice::Custom,
                ..Default::default()
            });
        });
        // `p` is a letter once the path is being typed, not a verb — otherwise
        // the one key that opens the editor is the one it cannot hold.
        page.handle_key_event(press(KeyCode::Char('p')));
        assert!(
            matches!(rx.try_recv(), Ok(Action::CreatePersonaPathInput(k)) if k.code == KeyCode::Char('p')),
        );
        page.handle_key_event(press(KeyCode::Esc));
        assert!(
            matches!(
                rx.try_recv(),
                Ok(Action::CreatePersonaPathChoice(PersonaPathChoice::Auto))
            ),
            "Esc leaves the editor for the server-assigned screen, not the label"
        );
    }
    #[test]
    fn personas_n_opens_create_persona() {
        let (mut page, mut rx) = page_for(MainMenu::Identity, |_| {});
        page.handle_key_event(press(KeyCode::Char('n')));
        match rx.try_recv() {
            Ok(Action::StartCreatePersona) => {}
            _ => panic!("expected StartCreatePersona"),
        }
    }

    #[test]
    fn personas_g_opens_agent_name_manager_for_the_selected_persona() {
        let (mut page, mut rx) = page_for(MainMenu::Identity, personas_with_orphan_selected());
        page.handle_key_event(press(KeyCode::Char('g')));
        match rx.try_recv() {
            Ok(Action::StartAgentNameManager(1)) => {}
            _ => panic!("expected StartAgentNameManager(1)"),
        }
    }

    // ----- Identity pane: tabs and their verbs -------------------------------

    /// Tab moves between the pane's five tabs; the verbs that follow belong to
    /// whichever one is showing.
    #[test]
    fn personas_tab_moves_between_tabs() {
        let (mut page, mut rx) = page_for(MainMenu::Identity, |_| {});
        page.handle_key_event(press(KeyCode::Tab));
        assert!(matches!(
            rx.try_recv(),
            Ok(Action::Persona(PersonaAction::TabNext))
        ));

        let (mut page, mut rx) = page_for(MainMenu::Identity, |_| {});
        page.handle_key_event(press(KeyCode::BackTab));
        assert!(matches!(
            rx.try_recv(),
            Ok(Action::Persona(PersonaAction::TabPrev))
        ));
    }

    /// The attribute verbs only fire on the Attributes tab, and only with a row
    /// under the cursor.
    #[test]
    fn personas_attribute_keys_map_to_actions() {
        use openvtc_core::persona::pool::PoolAttribute;
        let open = || {
            page_for(MainMenu::Identity, |s| {
                let p = &mut s.main_page.content_panel.identity;
                p.tab = PersonaTab::Attributes;
                p.attributes = vec![PoolAttribute {
                    attribute_id: "01A".into(),
                    ..PoolAttribute::default()
                }]
                .into();
            })
        };

        for (key, want) in [
            (KeyCode::Char('n'), PersonaAction::AttributeNew),
            (KeyCode::Char('e'), PersonaAction::AttributeEdit(0)),
            (KeyCode::Char('d'), PersonaAction::AttributeDeleteArm(0)),
            (KeyCode::Char('v'), PersonaAction::ToggleValues),
            (KeyCode::Char('s'), PersonaAction::RevealValue(0)),
            (KeyCode::Char('r'), PersonaAction::Refresh),
        ] {
            let (mut page, mut rx) = open();
            page.handle_key_event(press(key));
            match rx.try_recv() {
                Ok(Action::Persona(got)) => assert_eq!(
                    std::mem::discriminant(&got),
                    std::mem::discriminant(&want),
                    "{key:?}"
                ),
                _ => panic!("expected a persona action for {key:?}"),
            }
        }
    }

    /// `s` needs a row under the cursor. On an empty list it is not a verb, and
    /// a pane that consumed it would swallow a key that meant nothing here.
    #[test]
    fn personas_reveal_needs_a_row() {
        let (mut page, mut rx) = page_for(MainMenu::Identity, |s| {
            s.main_page.content_panel.identity.tab = PersonaTab::Attributes;
        });
        page.handle_key_event(press(KeyCode::Char('s')));
        assert!(rx.try_recv().is_err(), "no attribute, no reveal");
    }

    /// An armed confirmation owns `y`/`n` — every other pane verb is suppressed
    /// while a destructive question is on screen.
    #[test]
    fn personas_confirmation_owns_the_keyboard() {
        let armed = || {
            page_for(MainMenu::Identity, |s| {
                let p = &mut s.main_page.content_panel.identity;
                p.tab = PersonaTab::Attributes;
                p.confirm = PersonaConfirm::DeleteAttribute {
                    attribute_id: "01A".into(),
                    name: "Work email".into(),
                    cascade: false,
                };
            })
        };

        let (mut page, mut rx) = armed();
        page.handle_key_event(press(KeyCode::Char('y')));
        assert!(matches!(
            rx.try_recv(),
            Ok(Action::Persona(PersonaAction::ConfirmYes))
        ));

        // `n` would open the attribute editor if it reached the tab. It does
        // not: while a question is armed it is the answer "no".
        let (mut page, mut rx) = armed();
        page.handle_key_event(press(KeyCode::Char('n')));
        assert!(matches!(
            rx.try_recv(),
            Ok(Action::Persona(PersonaAction::ConfirmNo))
        ));
    }

    /// A space is a space on the name field, and a tick on the entry list. A
    /// form that swallowed it everywhere could not name a profile "Work
    /// laptop".
    #[test]
    fn personas_space_ticks_only_on_the_entry_list() {
        use crate::state_handler::main_page::content::{ProfileForm, ProfileFormFocus};
        let with_focus = |focus: ProfileFormFocus| {
            page_for(MainMenu::Identity, move |s| {
                s.main_page.content_panel.identity.mode = PersonaMode::Profile(ProfileForm {
                    focus,
                    ..ProfileForm::default()
                });
            })
        };

        let (mut page, mut rx) = with_focus(ProfileFormFocus::Entries);
        page.handle_key_event(press(KeyCode::Char(' ')));
        assert!(matches!(
            rx.try_recv(),
            Ok(Action::Persona(PersonaAction::FormToggleEntry))
        ));

        let (mut page, mut rx) = with_focus(ProfileFormFocus::Name);
        page.handle_key_event(press(KeyCode::Char(' ')));
        assert!(matches!(
            rx.try_recv(),
            Ok(Action::Persona(PersonaAction::FormKey(_)))
        ));
    }

    /// A form with a write in flight swallows input rather than editing a
    /// request that is already on the wire.
    #[test]
    fn personas_a_working_form_swallows_input() {
        use crate::state_handler::main_page::content::AttributeForm;
        let (mut page, mut rx) = page_for(MainMenu::Identity, |s| {
            s.main_page.content_panel.identity.mode = PersonaMode::Attribute(AttributeForm {
                working: true,
                ..AttributeForm::default()
            });
        });
        page.handle_key_event(press(KeyCode::Char('x')));
        assert!(
            rx.try_recv().is_err(),
            "no action while a save is in flight"
        );
    }

    #[test]
    fn agent_name_manager_ready_keys_map_to_actions() {
        use crate::state_handler::main_page::content::{
            AgentNameManagerPhase, AgentNameManagerState, AgentNameRow,
        };
        let open = || {
            page_for(MainMenu::Vta, |s| {
                s.main_page.agent_names = Some(AgentNameManagerState {
                    persona_did: "did:webvh:example.com:alice".into(),
                    phase: AgentNameManagerPhase::Ready,
                    names: vec![AgentNameRow {
                        name: "alice".into(),
                        enabled: true,
                    }],
                    ..Default::default()
                });
            })
        };

        let (mut page, mut rx) = open();
        page.handle_key_event(press(KeyCode::Enter));
        assert!(matches!(rx.try_recv(), Ok(Action::AgentNameManagerClaim)));

        let (mut page, mut rx) = open();
        page.handle_key_event(press(KeyCode::Char(' ')));
        assert!(matches!(rx.try_recv(), Ok(Action::AgentNameManagerToggle)));

        // `d` arms the remove confirmation; it does not remove directly.
        let (mut page, mut rx) = open();
        page.handle_key_event(press(KeyCode::Char('d')));
        assert!(matches!(
            rx.try_recv(),
            Ok(Action::AgentNameManagerConfirmRemove)
        ));

        let (mut page, mut rx) = open();
        page.handle_key_event(press(KeyCode::Esc));
        assert!(matches!(rx.try_recv(), Ok(Action::AgentNameManagerClose)));

        // A plain character edits the input rather than triggering an action.
        let (mut page, mut rx) = open();
        page.handle_key_event(press(KeyCode::Char('x')));
        assert!(matches!(
            rx.try_recv(),
            Ok(Action::AgentNameManagerInput(_))
        ));
    }

    #[test]
    fn agent_name_manager_remove_confirm_gate() {
        use crate::state_handler::main_page::content::{
            AgentNameManagerPhase, AgentNameManagerState, AgentNameRow,
        };
        // An armed remove: y/Enter confirms, anything else cancels — and no
        // other Ready-phase key acts while it is armed.
        let armed = || {
            page_for(MainMenu::Vta, |s| {
                s.main_page.agent_names = Some(AgentNameManagerState {
                    phase: AgentNameManagerPhase::Ready,
                    names: vec![AgentNameRow {
                        name: "alice".into(),
                        enabled: true,
                    }],
                    confirm_remove: Some(0),
                    ..Default::default()
                });
            })
        };

        let (mut page, mut rx) = armed();
        page.handle_key_event(press(KeyCode::Char('y')));
        assert!(matches!(rx.try_recv(), Ok(Action::AgentNameManagerRemove)));

        // Enter does not confirm a removal (#579): it cancels, like any other key.
        let (mut page, mut rx) = armed();
        page.handle_key_event(press(KeyCode::Enter));
        assert!(matches!(
            rx.try_recv(),
            Ok(Action::AgentNameManagerCancelRemove)
        ));

        let (mut page, mut rx) = armed();
        page.handle_key_event(press(KeyCode::Esc));
        assert!(matches!(
            rx.try_recv(),
            Ok(Action::AgentNameManagerCancelRemove)
        ));

        // A stray key while armed cancels rather than editing the input.
        let (mut page, mut rx) = armed();
        page.handle_key_event(press(KeyCode::Char('x')));
        assert!(matches!(
            rx.try_recv(),
            Ok(Action::AgentNameManagerCancelRemove)
        ));
    }

    #[test]
    fn agent_name_manager_working_swallows_input() {
        use crate::state_handler::main_page::content::{
            AgentNameManagerPhase, AgentNameManagerState,
        };
        let (mut page, mut rx) = page_for(MainMenu::Vta, |s| {
            s.main_page.agent_names = Some(AgentNameManagerState {
                phase: AgentNameManagerPhase::Working,
                ..Default::default()
            });
        });
        page.handle_key_event(press(KeyCode::Enter));
        assert!(
            rx.try_recv().is_err(),
            "input is locked while a mutation is in flight"
        );
    }

    /// The menu's identity entry opens a panel like every other one.
    ///
    /// Minting a persona is a key inside the pane, not a menu item that fires
    /// an action instead of switching panels.
    #[test]
    fn menu_enter_on_identity_switches_to_the_panel() {
        let (mut page, mut rx) = page_for(MainMenu::Identity, |s| {
            s.main_page.menu_panel.selected = true;
            s.main_page.content_panel.selected = false;
        });
        page.handle_key_event(press(KeyCode::Enter));
        match rx.try_recv() {
            Ok(Action::MainPanelSwitch(MainPanel::ContentPanel)) => {}
            _ => panic!("expected a switch to the content panel"),
        }
    }

    #[test]
    fn create_persona_label_phase_keys() {
        use crate::state_handler::main_page::content::CreatePersonaState;
        // The open overlay owns all input regardless of the focused panel.
        let open = || {
            page_for(MainMenu::Identity, |s| {
                s.main_page.create_persona = Some(CreatePersonaState::default());
            })
        };

        let (mut page, mut rx) = open();
        page.handle_key_event(press(KeyCode::Char('a')));
        match rx.try_recv() {
            Ok(Action::CreatePersonaInput(_)) => {}
            _ => panic!("expected CreatePersonaInput"),
        }

        let (mut page, mut rx) = open();
        page.handle_key_event(press(KeyCode::Enter));
        match rx.try_recv() {
            Ok(Action::CreatePersonaSubmit) => {}
            _ => panic!("expected CreatePersonaSubmit"),
        }

        let (mut page, mut rx) = open();
        page.handle_key_event(press(KeyCode::Esc));
        match rx.try_recv() {
            Ok(Action::CreatePersonaClose) => {}
            _ => panic!("expected CreatePersonaClose"),
        }
    }

    #[test]
    fn create_persona_done_phase_keys() {
        use crate::state_handler::main_page::content::{CreatePersonaPhase, CreatePersonaState};
        let done = || {
            page_for(MainMenu::Identity, |s| {
                s.main_page.create_persona = Some(CreatePersonaState {
                    phase: CreatePersonaPhase::Done,
                    did: Some("did:webvh:example:alice".to_string()),
                    copied: true,
                    ..Default::default()
                });
            })
        };

        // `c` re-copies; any other key closes.
        let (mut page, mut rx) = done();
        page.handle_key_event(press(KeyCode::Char('c')));
        match rx.try_recv() {
            Ok(Action::CreatePersonaCopy) => {}
            _ => panic!("expected CreatePersonaCopy"),
        }

        let (mut page, mut rx) = done();
        page.handle_key_event(press(KeyCode::Enter));
        match rx.try_recv() {
            Ok(Action::CreatePersonaClose) => {}
            _ => panic!("expected CreatePersonaClose"),
        }
    }

    // ----- VIC manager -------------------------------------------------------

    use crate::state_handler::main_page::content::{
        AddVicPhase, AddVicState, VicLifecycle, VicSummary,
    };

    pub(super) fn vic(id: &str, lifecycle: VicLifecycle) -> VicSummary {
        VicSummary {
            id: id.to_string(),
            issuer: "did:webvh:example:community".to_string(),
            issuer_agent_name: None,
            status: "valid".to_string(),
            lifecycle,
            valid_until: String::new(),
        }
    }

    /// The VIC list with the given rows, selected at index 0.
    pub(super) fn vta_vics(rows: Vec<VicSummary>) -> impl Fn(&mut State) {
        move |s: &mut State| {
            let vta = &mut s.main_page.content_panel.vta;
            vta.vics = rows.clone().into();
            vta.vic_selected_index = 0;
        }
    }

    #[test]
    fn vta_a_opens_add_vic() {
        let (mut page, mut rx) = page_for(MainMenu::Vta, |_| {});
        page.handle_key_event(press(KeyCode::Char('a')));
        match rx.try_recv() {
            Ok(Action::StartAddVic) => {}
            _ => panic!("expected StartAddVic"),
        }
    }

    /// Tab asks for the invitation-credential listing.
    ///
    /// The panel holds one list (the persona list is on the identity pane), so
    /// asking for it is the whole of what the key does — it does not move focus.
    #[test]
    fn vta_r_asks_for_the_vic_listing() {
        let (mut page, mut rx) = page_for(MainMenu::Vta, |_| {});
        page.handle_key_event(press(KeyCode::Char('r')));
        match rx.try_recv() {
            Ok(Action::VicRefresh) => {}
            _ => panic!("expected VicRefresh"),
        }
        assert!(rx.try_recv().is_err(), "no second action expected");
    }

    #[test]
    fn vta_vic_delete_confirm_cycle() {
        // `d` on an active VIC arms the soft-delete confirmation.
        let (mut page, mut rx) = page_for(
            MainMenu::Vta,
            vta_vics(vec![vic("urn:vic:1", VicLifecycle::Active)]),
        );
        page.handle_key_event(press(KeyCode::Char('d')));
        match rx.try_recv() {
            Ok(Action::VicConfirmDelete(0)) => {}
            _ => panic!("expected VicConfirmDelete(0)"),
        }

        // Armed: `y` commits the soft-delete; Enter does not (#579).
        let (mut page, mut rx) = page_for(MainMenu::Vta, |s| {
            s.main_page.content_panel.vta.confirm_delete_vic = Some(0);
        });
        page.handle_key_event(press(KeyCode::Char('y')));
        match rx.try_recv() {
            Ok(Action::DeleteVic(0)) => {}
            _ => panic!("expected DeleteVic(0)"),
        }
        let (mut page, mut rx) = page_for(MainMenu::Vta, |s| {
            s.main_page.content_panel.vta.confirm_delete_vic = Some(0);
        });
        page.handle_key_event(press(KeyCode::Enter));
        assert!(!matches!(rx.try_recv(), Ok(Action::DeleteVic(_))));

        // Armed: any other key cancels.
        let (mut page, mut rx) = page_for(MainMenu::Vta, |s| {
            s.main_page.content_panel.vta.confirm_delete_vic = Some(0);
        });
        page.handle_key_event(press(KeyCode::Esc));
        match rx.try_recv() {
            Ok(Action::VicCancelDelete) => {}
            _ => panic!("expected VicCancelDelete"),
        }
    }

    #[test]
    fn vta_vic_purge_confirm_commits() {
        let (mut page, mut rx) = page_for(MainMenu::Vta, |s| {
            s.main_page.content_panel.vta.confirm_purge_vic = Some(0);
        });
        page.handle_key_event(press(KeyCode::Char('y')));
        match rx.try_recv() {
            Ok(Action::PurgeVic(0)) => {}
            _ => panic!("expected PurgeVic(0)"),
        }
    }

    #[test]
    fn vta_vic_unarchive_and_restore_by_lifecycle() {
        // `u` on an archived VIC unarchives it.
        let (mut page, mut rx) = page_for(
            MainMenu::Vta,
            vta_vics(vec![vic("urn:vic:1", VicLifecycle::Archived)]),
        );
        page.handle_key_event(press(KeyCode::Char('u')));
        match rx.try_recv() {
            Ok(Action::VicUnarchive(0)) => {}
            _ => panic!("expected VicUnarchive(0)"),
        }

        // `u` on a soft-deleted VIC restores it.
        let (mut page, mut rx) = page_for(
            MainMenu::Vta,
            vta_vics(vec![vic("urn:vic:1", VicLifecycle::Deleted)]),
        );
        page.handle_key_event(press(KeyCode::Char('u')));
        match rx.try_recv() {
            Ok(Action::VicRestore(0)) => {}
            _ => panic!("expected VicRestore(0)"),
        }
    }

    #[test]
    fn add_vic_overlay_input_keys() {
        let open = || {
            page_for(MainMenu::Vta, |s| {
                s.main_page.add_vic = Some(AddVicState::default());
            })
        };

        let (mut page, mut rx) = open();
        page.handle_key_event(press(KeyCode::Enter));
        match rx.try_recv() {
            Ok(Action::AddVicSubmit) => {}
            _ => panic!("expected AddVicSubmit"),
        }

        let (mut page, mut rx) = open();
        page.handle_key_event(press(KeyCode::Esc));
        match rx.try_recv() {
            Ok(Action::AddVicClose) => {}
            _ => panic!("expected AddVicClose"),
        }

        let (mut page, mut rx) = open();
        page.handle_key_event(press(KeyCode::Char('x')));
        match rx.try_recv() {
            Ok(Action::AddVicInput(_)) => {}
            _ => panic!("expected AddVicInput"),
        }
    }

    #[test]
    fn add_vic_done_phase_closes() {
        let (mut page, mut rx) = page_for(MainMenu::Vta, |s| {
            s.main_page.add_vic = Some(AddVicState {
                phase: AddVicPhase::Done,
                ..Default::default()
            });
        });
        page.handle_key_event(press(KeyCode::Enter));
        match rx.try_recv() {
            Ok(Action::AddVicClose) => {}
            _ => panic!("expected AddVicClose"),
        }
    }

    #[test]
    fn create_persona_working_phase_swallows_input() {
        use crate::state_handler::main_page::content::{CreatePersonaPhase, CreatePersonaState};
        let (mut page, mut rx) = page_for(MainMenu::Vta, |s| {
            s.main_page.create_persona = Some(CreatePersonaState {
                phase: CreatePersonaPhase::Working,
                ..Default::default()
            });
        });
        page.handle_key_event(press(KeyCode::Enter));
        assert!(
            rx.try_recv().is_err(),
            "the Working phase locks input until the mint resolves"
        );
    }

    // ----- Inbox -------------------------------------------------------------

    #[test]
    fn inbox_d_and_c_arm_confirmation() {
        // `d` on a selected task arms a dismiss confirmation (R25) — it does not
        // dismiss instantly.
        let (mut page, mut rx) = page_for(MainMenu::Inbox, |s| {
            s.main_page.content_panel.inbox.tasks = Arc::from(vec![task_summary("t1")]);
        });
        page.handle_key_event(press(KeyCode::Char('d')));
        match rx.try_recv() {
            Ok(Action::Inbox(InboxAction::ConfirmDismiss { task_id })) => {
                assert_eq!(task_id, "t1");
            }
            _ => panic!("expected Inbox(ConfirmDismiss)"),
        }

        // `c` arms a clear-all confirmation.
        let (mut page, mut rx) = page_for(MainMenu::Inbox, |s| {
            s.main_page.content_panel.inbox.tasks = Arc::from(vec![task_summary("t1")]);
        });
        page.handle_key_event(press(KeyCode::Char('c')));
        match rx.try_recv() {
            Ok(Action::Inbox(InboxAction::ConfirmClearAll)) => {}
            _ => panic!("expected Inbox(ConfirmClearAll)"),
        }
    }

    #[test]
    fn inbox_confirm_commits_and_cancels() {
        // A pending dismiss commits on y.
        let (mut page, mut rx) = page_for(MainMenu::Inbox, |s| {
            s.main_page.content_panel.inbox.confirm = Some(InboxConfirm::Dismiss {
                task_id: "t1".to_string(),
            });
        });
        page.handle_key_event(press(KeyCode::Char('y')));
        match rx.try_recv() {
            Ok(Action::Inbox(InboxAction::DismissTask { task_id })) => {
                assert_eq!(task_id, "t1");
            }
            _ => panic!("expected Inbox(DismissTask)"),
        }

        // A pending clear-all commits on `y` only; Enter cancels (#579).
        let (mut page, mut rx) = page_for(MainMenu::Inbox, |s| {
            s.main_page.content_panel.inbox.confirm = Some(InboxConfirm::ClearAll);
        });
        page.handle_key_event(press(KeyCode::Char('y')));
        match rx.try_recv() {
            Ok(Action::Inbox(InboxAction::ClearAll)) => {}
            _ => panic!("expected Inbox(ClearAll)"),
        }
        let (mut page, mut rx) = page_for(MainMenu::Inbox, |s| {
            s.main_page.content_panel.inbox.confirm = Some(InboxConfirm::ClearAll);
        });
        page.handle_key_event(press(KeyCode::Enter));
        match rx.try_recv() {
            Ok(Action::Inbox(InboxAction::CancelConfirm)) => {}
            _ => panic!("expected Enter to cancel"),
        }

        // Any other key cancels.
        let (mut page, mut rx) = page_for(MainMenu::Inbox, |s| {
            s.main_page.content_panel.inbox.confirm = Some(InboxConfirm::ClearAll);
        });
        page.handle_key_event(press(KeyCode::Esc));
        match rx.try_recv() {
            Ok(Action::Inbox(InboxAction::CancelConfirm)) => {}
            _ => panic!("expected Inbox(CancelConfirm)"),
        }
    }

    // ----- Relationships -----------------------------------------------------

    #[test]
    fn relationship_detail_d_arms_then_confirms() {
        // `d` in the detail view arms a removal (R25), carrying the remote DID.
        let (mut page, mut rx) = page_for(MainMenu::Relationships, |s| {
            s.main_page.content_panel.relationships.relationships =
                Arc::from(vec![rel_summary("did:example:partner")]);
            s.main_page.content_panel.relationships.mode = RelationshipsMode::Detail {
                index: 0,
                selected_vrc: None,
            };
        });
        page.handle_key_event(press(KeyCode::Char('d')));
        match rx.try_recv() {
            Ok(Action::Relationship(RelationshipAction::ConfirmRemove { remote_p_did })) => {
                assert_eq!(remote_p_did, "did:example:partner");
            }
            _ => panic!("expected Relationship(ConfirmRemove)"),
        }

        // While armed, y commits the Remove.
        let (mut page, mut rx) = page_for(MainMenu::Relationships, |s| {
            s.main_page.content_panel.relationships.mode = RelationshipsMode::Detail {
                index: 0,
                selected_vrc: None,
            };
            s.main_page.content_panel.relationships.confirm_delete =
                Some("did:example:partner".to_string());
        });
        page.handle_key_event(press(KeyCode::Char('y')));
        match rx.try_recv() {
            Ok(Action::Relationship(RelationshipAction::Remove { remote_p_did })) => {
                assert_eq!(remote_p_did, "did:example:partner");
            }
            _ => panic!("expected Relationship(Remove)"),
        }
    }

    // ----- Credentials -------------------------------------------------------

    #[test]
    fn credential_detail_d_arms_then_confirms() {
        // `d` in the detail view arms a removal (R25) on a non-membership tab.
        let (mut page, mut rx) = page_for(MainMenu::Credentials, |s| {
            s.main_page.content_panel.credentials.selected_tab = CredentialTab::Received;
            s.main_page.content_panel.credentials.received = Arc::from(vec![vrc_summary("vrc1")]);
            s.main_page.content_panel.credentials.mode = CredentialsMode::Detail { index: 0 };
        });
        page.handle_key_event(press(KeyCode::Char('d')));
        match rx.try_recv() {
            Ok(Action::Credential(CredentialAction::ConfirmRemove { vrc_id })) => {
                assert_eq!(vrc_id, "vrc1");
            }
            _ => panic!("expected Credential(ConfirmRemove)"),
        }

        // While armed, y commits the Remove.
        let (mut page, mut rx) = page_for(MainMenu::Credentials, |s| {
            s.main_page.content_panel.credentials.mode = CredentialsMode::Detail { index: 0 };
            s.main_page.content_panel.credentials.confirm_delete = Some("vrc1".to_string());
        });
        page.handle_key_event(press(KeyCode::Char('y')));
        match rx.try_recv() {
            Ok(Action::Credential(CredentialAction::Remove { vrc_id })) => {
                assert_eq!(vrc_id, "vrc1");
            }
            _ => panic!("expected Credential(Remove)"),
        }
    }

    #[test]
    fn credential_detail_d_does_nothing_on_the_vetting_tab() {
        // A vetting statement belongs to its application; there is no
        // local-only removal, so `d` must not arm one.
        let (mut page, mut rx) = page_for(MainMenu::Credentials, |s| {
            s.main_page.content_panel.credentials.selected_tab = CredentialTab::Vetting;
            s.main_page.content_panel.credentials.vetting = Arc::from(vec![vrc_summary("st1")]);
            s.main_page.content_panel.credentials.mode = CredentialsMode::Detail { index: 0 };
        });
        page.handle_key_event(press(KeyCode::Char('d')));
        assert!(
            !matches!(
                rx.try_recv(),
                Ok(Action::Credential(CredentialAction::ConfirmRemove { .. }))
            ),
            "no removal is armed for a vetting statement"
        );
    }

    // ----- Settings / Logs / Help (one nav test each) ------------------------

    #[test]
    fn settings_view_down_moves_selection() {
        // Default settings mode is View at index 0; Down advances the selection.
        let (mut page, mut rx) = page_for(MainMenu::Settings, |_| {});
        page.handle_key_event(press(KeyCode::Down));
        match rx.try_recv() {
            Ok(Action::Settings(SettingsAction::Select(1))) => {}
            _ => panic!("expected Settings(Select(1))"),
        }
    }

    #[test]
    fn logs_esc_returns_to_menu() {
        let (mut page, mut rx) = page_for(MainMenu::Logs, |_| {});
        page.handle_key_event(press(KeyCode::Esc));
        match rx.try_recv() {
            Ok(Action::MainPanelSwitch(MainPanel::MainMenu)) => {}
            _ => panic!("expected MainPanelSwitch(MainMenu)"),
        }
    }

    #[test]
    fn help_esc_returns_to_menu() {
        let (mut page, mut rx) = page_for(MainMenu::Help, |_| {});
        page.handle_key_event(press(KeyCode::Esc));
        match rx.try_recv() {
            Ok(Action::MainPanelSwitch(MainPanel::MainMenu)) => {}
            _ => panic!("expected MainPanelSwitch(MainMenu)"),
        }
    }

    fn elections_action(
        rx: &mut UnboundedReceiver<Action>,
    ) -> Option<crate::state_handler::actions::ElectionsAction> {
        match rx.try_recv() {
            Ok(Action::Elections(action)) => Some(action),
            _ => None,
        }
    }

    /// An election shown in the panel, for its key and render tests, whose written answers are
    /// released once `threshold` ballots are in.
    fn shown_election_releasing_at(
        state: &str,
        threshold: u64,
    ) -> Box<openvtc_core::elections::ShownElection> {
        Box::new(
            openvtc_core::elections::ShownElection::from_payload(serde_json::json!({
                "manifest": {
                    "electionId": "agm", "community": "did:key:zVtc", "title": "Annual meeting",
                    "questions": [
                        { "key": "chair", "type": "choice", "text": "Who chairs?",
                          "options": [{ "key": "a", "label": "Ann" }, { "key": "b", "label": "Bo" }],
                          "minSelections": 1, "maxSelections": 1, "optional": false },
                        { "key": "note", "type": "text", "maxLength": 20, "optional": true }
                    ],
                    "secrecy": "open", "roll": { "rule": "members" },
                    "registrationOpensAt": "2026-10-01T00:00:00Z",
                    "votingOpensAt": "2026-10-02T00:00:00Z",
                    "votingClosesAt": "2026-12-01T00:00:00Z", "revote": "replace",
                    "board": { "visibility": "public", "auditors": [] },
                    "ballotBox": "did:key:z6MkBox", "binding": false, "allowEarlyClose": false,
                    "resultsBeforeClose": false, "textReleaseThreshold": threshold
                },
                "manifestDigest": "zQmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
                "state": state,
                "parameters": { "suite": "ps-ddh-bls12381", "votingKey": "zKey" },
                "disclosure": {
                    "ballotBox": "did:key:z6MkBox", "ballotBoxOperator": "Example Ballots",
                    "sameOperator": true, "boardVisibility": "public", "auditors": [],
                    "revote": "replace", "coercionResistance": false
                },
                "checkpoints": []
            }))
            .unwrap(),
        )
    }

    pub(super) fn with_elections(
        screen: crate::state_handler::main_page::elections::Screen,
    ) -> impl FnOnce(&mut State) {
        with_elections_releasing_at(screen, 10)
    }

    /// [`with_elections`] on an election that releases written answers at `threshold`.
    fn with_elections_releasing_at(
        screen: crate::state_handler::main_page::elections::Screen,
        threshold: u64,
    ) -> impl FnOnce(&mut State) {
        move |s: &mut State| {
            use crate::state_handler::main_page::elections::{BallotForm, ElectionsView};
            let mut view = ElectionsView::new(
                "did:key:zVtc".into(),
                Default::default(),
                "did:key:zAlice".into(),
                "Acme".into(),
            );
            let shown = shown_election_releasing_at("voting", threshold);
            view.form = Some(BallotForm::new(shown.manifest()));
            view.shown = Some(shown);
            view.screen = screen;
            s.main_page.content_panel.elections.view = Some(view);
        }
    }

    fn drawn(page: &MainPage) -> String {
        use ratatui::{Terminal, backend::TestBackend};
        let mut terminal = Terminal::new(TestBackend::new(140, 60)).expect("test terminal");
        terminal
            .draw(|frame| page.render(frame, ()))
            .expect("render");
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect()
    }

    /// `e` on an Active community opens its elections; the panel's keys follow its screen.
    #[test]
    fn e_opens_elections_and_the_panel_keys_follow_the_screen() {
        use crate::state_handler::actions::ElectionsAction as E;
        use crate::state_handler::main_page::elections::Screen;

        let (mut page, mut rx) = page_for(MainMenu::Communities, |s| {
            s.main_page.content_panel.communities.items = vec![community_summary("a")].into();
        });
        page.handle_key_event(press(KeyCode::Char('e')));
        assert!(matches!(elections_action(&mut rx), Some(E::Open(0))));

        let (mut page, mut rx) = page_for(MainMenu::Communities, with_elections(Screen::Detail));
        page.handle_key_event(press(KeyCode::Char('v')));
        assert!(matches!(elections_action(&mut rx), Some(E::Vote)));
        page.handle_key_event(press(KeyCode::Char('t')));
        assert!(matches!(elections_action(&mut rx), Some(E::TakeTicket)));

        // On the ballot, a choice question takes space; a text question takes the letters,
        // `a` included, and leaves the question blank only with Ctrl-a.
        let (mut page, mut rx) = page_for(MainMenu::Communities, with_elections(Screen::Ballot));
        page.handle_key_event(press(KeyCode::Char(' ')));
        assert!(matches!(elections_action(&mut rx), Some(E::BallotToggle)));
        page.handle_key_event(press(KeyCode::Char('a')));
        assert!(matches!(elections_action(&mut rx), Some(E::BallotAbstain)));
        page.handle_key_event(press(KeyCode::Enter));
        assert!(matches!(elections_action(&mut rx), Some(E::Review)));
        let (mut page, mut rx) = page_for(MainMenu::Communities, |s| {
            with_elections(Screen::Ballot)(s);
            if let Some(f) = s
                .main_page
                .content_panel
                .elections
                .view
                .as_mut()
                .and_then(|v| v.form.as_mut())
            {
                f.question = 1;
            }
        });
        // Drawn first: the ballot's footer lists Ctrl-a, which is what makes
        // the chord the ballot's rather than the text field's.
        let _ = drawn(&page);
        page.handle_key_event(press(KeyCode::Char('a')));
        assert!(matches!(
            elections_action(&mut rx),
            Some(E::BallotText(t)) if t == "a"
        ));
        page.handle_key_event(ctrl(KeyCode::Char('a')));
        assert!(matches!(elections_action(&mut rx), Some(E::BallotAbstain)));

        // Only `y` casts; anything else goes back to the ballot.
        let (mut page, mut rx) = page_for(MainMenu::Communities, with_elections(Screen::Confirm));
        page.handle_key_event(press(KeyCode::Enter));
        assert!(matches!(elections_action(&mut rx), Some(E::Back)));
        page.handle_key_event(press(KeyCode::Char('y')));
        assert!(matches!(elections_action(&mut rx), Some(E::Cast)));
    }

    /// The detail says who runs the ballot box, warns when it is the community's own
    /// operator, and says a vote can be proven; the ballot shows the questions.
    #[test]
    fn the_election_detail_discloses_and_the_ballot_renders() {
        use crate::state_handler::main_page::elections::Screen;

        let (page, _rx) = page_for(MainMenu::Communities, with_elections(Screen::Detail));
        let text = drawn(&page);
        assert!(text.contains("Annual meeting"), "{text}");
        assert!(text.contains("Example Ballots"), "{text}");
        assert!(text.contains("same operator"), "{text}");
        assert!(text.contains("prove how you voted"), "{text}");
        assert!(text.contains("v: vote"), "{text}");

        let (page, _rx) = page_for(MainMenu::Communities, with_elections(Screen::Ballot));
        let text = drawn(&page);
        assert!(text.contains("Who chairs?"), "{text}");
        assert!(text.contains("( ) Ann"), "{text}");
        assert!(
            !text.contains("less than an hour"),
            "no ticket taken here: {text}"
        );

        let (page, _rx) = page_for(MainMenu::Communities, |s| {
            with_elections(Screen::Ballot)(s);
            s.main_page.content_panel.elections.tickets_taken.insert(
                ("did:key:zVtc".into(), "agm".into()),
                std::time::Instant::now(),
            );
        });
        let text = drawn(&page);
        assert!(text.contains("less than an hour"), "{text}");
    }

    /// VTI-VOT-065 / VTI-VOT-090: an election releasing written answers below 10 ballots warns
    /// the member before a ticket is taken (the detail) and when voting (ballot and
    /// confirmation); at 10 nothing is said.
    #[test]
    fn vti_vot_090_a_low_text_release_threshold_is_warned_before_ticket_and_vote() {
        use crate::state_handler::main_page::elections::Screen;

        for screen in [Screen::Detail, Screen::Ballot, Screen::Confirm] {
            let (page, _rx) = page_for(
                MainMenu::Communities,
                with_elections_releasing_at(screen, 3),
            );
            let text = drawn(&page);
            assert!(
                text.contains("Written answers are released once 3 ballots are counted."),
                "{screen:?}: {text}"
            );
            assert!(
                text.contains("Below 10, a written answer may identify"),
                "{screen:?}: {text}"
            );

            let (page, _rx) = page_for(MainMenu::Communities, with_elections(screen));
            let text = drawn(&page);
            assert!(
                !text.contains("Written answers are released"),
                "{screen:?}: {text}"
            );
        }
    }
    // ----- One confirmation rule (#579) ------------------------------------

    /// Every action sent for `code` on a page armed by `arm`.
    fn sent_for(menu: MainMenu, arm: &dyn Fn(&mut State), code: KeyCode) -> Vec<Action> {
        let (mut page, mut rx) = page_for(menu, arm);
        page.handle_key_event(press(code));
        let mut sent = Vec::new();
        while let Ok(action) = rx.try_recv() {
            sent.push(action);
        }
        sent
    }

    /// A held Enter — the key that opened the view a moment earlier — must
    /// never commit a destructive or outward-facing action; `y` must.
    #[test]
    fn enter_never_commits_a_confirmation_and_y_does() {
        use crate::state_handler::actions::VettingAction as V;
        use crate::state_handler::main_page::content::{
            AgentNameManagerPhase, AgentNameManagerState, AgentNameRow, PROTECTION_CONFIRM_REMOVE,
            SettingsMode, VettingMode,
        };
        type Arm = Box<dyn Fn(&mut State)>;
        type Commit = fn(&Action) -> bool;
        fn one_community(s: &mut State) {
            s.main_page.content_panel.communities.items =
                Arc::from(vec![community_summary("Acme")]);
        }
        let cases: Vec<(&str, MainMenu, Arm, Commit)> = vec![
            (
                "community delete",
                MainMenu::Communities,
                Box::new(|s| {
                    one_community(s);
                    s.main_page.content_panel.communities.confirm_delete = Some(0);
                }),
                |a| matches!(a, Action::DeleteCommunity(0)),
            ),
            (
                "community leave",
                MainMenu::Communities,
                Box::new(|s| {
                    one_community(s);
                    s.main_page.content_panel.communities.confirm_leave = Some(0);
                }),
                |a| matches!(a, Action::LeaveCommunity(0)),
            ),
            (
                "community withdraw",
                MainMenu::Communities,
                Box::new(|s| {
                    one_community(s);
                    s.main_page.content_panel.communities.confirm_withdraw = Some(0);
                }),
                |a| matches!(a, Action::WithdrawJoin(0)),
            ),
            (
                "issue VMC",
                MainMenu::Communities,
                Box::new(|s| {
                    one_community(s);
                    s.main_page.content_panel.communities.confirm_send =
                        Some(CommunitySend::IssueVmc(0));
                }),
                |a| matches!(a, Action::IssueMemberVmc(0)),
            ),
            (
                "renew membership",
                MainMenu::Communities,
                Box::new(|s| {
                    one_community(s);
                    s.main_page.content_panel.communities.confirm_send =
                        Some(CommunitySend::Renew(0));
                }),
                |a| matches!(a, Action::RenewMembership(0)),
            ),
            (
                "inbox dismiss",
                MainMenu::Inbox,
                Box::new(|s| {
                    s.main_page.content_panel.inbox.confirm = Some(InboxConfirm::Dismiss {
                        task_id: "t1".into(),
                    });
                }),
                |a| matches!(a, Action::Inbox(InboxAction::DismissTask { .. })),
            ),
            (
                "inbox clear all",
                MainMenu::Inbox,
                Box::new(|s| {
                    s.main_page.content_panel.inbox.confirm = Some(InboxConfirm::ClearAll);
                }),
                |a| matches!(a, Action::Inbox(InboxAction::ClearAll)),
            ),
            (
                "inbox reject (sent to the peer)",
                MainMenu::Inbox,
                Box::new(|s| {
                    s.main_page.content_panel.inbox.confirm = Some(InboxConfirm::Reject {
                        task_id: "t1".into(),
                        vrc: false,
                    });
                }),
                |a| matches!(a, Action::Inbox(InboxAction::RejectRelationship { .. })),
            ),
            (
                "relationship remove",
                MainMenu::Relationships,
                Box::new(|s| {
                    s.main_page.content_panel.relationships.mode = RelationshipsMode::Detail {
                        index: 0,
                        selected_vrc: None,
                    };
                    s.main_page.content_panel.relationships.confirm_delete =
                        Some("did:example:partner".into());
                }),
                |a| matches!(a, Action::Relationship(RelationshipAction::Remove { .. })),
            ),
            (
                "credential remove",
                MainMenu::Credentials,
                Box::new(|s| {
                    s.main_page.content_panel.credentials.mode =
                        CredentialsMode::Detail { index: 0 };
                    s.main_page.content_panel.credentials.confirm_delete = Some("vrc1".into());
                }),
                |a| matches!(a, Action::Credential(CredentialAction::Remove { .. })),
            ),
            (
                "invitation credential delete",
                MainMenu::Vta,
                Box::new(|s| {
                    s.main_page.content_panel.vta.confirm_delete_vic = Some(0);
                }),
                |a| matches!(a, Action::DeleteVic(0)),
            ),
            (
                "agent name remove",
                MainMenu::Vta,
                Box::new(|s| {
                    s.main_page.agent_names = Some(AgentNameManagerState {
                        phase: AgentNameManagerPhase::Ready,
                        names: vec![AgentNameRow {
                            name: "alice".into(),
                            enabled: true,
                        }],
                        confirm_remove: Some(0),
                        ..Default::default()
                    });
                }),
                |a| matches!(a, Action::AgentNameManagerRemove),
            ),
            (
                "persona delete",
                MainMenu::Identity,
                Box::new(|s| {
                    s.main_page.content_panel.identity.confirm = PersonaConfirm::DeletePersona(0);
                }),
                |a| matches!(a, Action::DeleteDid(0)),
            ),
            (
                "remove passphrase",
                MainMenu::Settings,
                Box::new(|s| {
                    s.main_page.content_panel.settings.mode = SettingsMode::ChangeProtection {
                        selected_option: 1,
                        passphrase_len: 0,
                        confirm_len: 0,
                        active_field: PROTECTION_CONFIRM_REMOVE,
                    };
                }),
                |a| matches!(a, Action::Settings(SettingsAction::RemovePassphrase)),
            ),
            (
                "abandon an application",
                MainMenu::Vetting,
                Box::new(|s| {
                    s.main_page.content_panel.vetting.mode = VettingMode::ConfirmAbandon {
                        application_id: "a1".into(),
                    };
                }),
                |a| matches!(a, Action::Vetting(V::Submit)),
            ),
            (
                "delete a ticket",
                MainMenu::Vetting,
                Box::new(|s| {
                    s.main_page.content_panel.vetting.mode = VettingMode::ConfirmDeleteTicket {
                        ticket_id: "t1".into(),
                    };
                }),
                |a| matches!(a, Action::Vetting(V::Submit)),
            ),
        ];
        for (what, menu, arm, is_commit) in &cases {
            let on_enter = sent_for(menu.clone(), arm.as_ref(), KeyCode::Enter);
            assert!(
                !on_enter.iter().any(is_commit),
                "{what}: Enter must not commit"
            );
            let on_y = sent_for(menu.clone(), arm.as_ref(), KeyCode::Char('y'));
            assert!(on_y.iter().any(is_commit), "{what}: y must commit");
        }
    }

    /// Reject in the Inbox detail is sent to the peer, so `r` arms it rather
    /// than sending it.
    #[test]
    fn inbox_reject_arms_a_confirmation() {
        use crate::state_handler::main_page::content::ActiveTaskView;
        let (mut page, mut rx) = page_for(MainMenu::Inbox, |s| {
            s.main_page.content_panel.inbox.active_task =
                Some(ActiveTaskView::RelationshipRequestInbound {
                    task_id: "t1".into(),
                    from_did: "did:example:them".into(),
                    from_agent_name: None,
                    their_did: "did:example:them".into(),
                    reason: None,
                    name: None,
                });
        });
        page.handle_key_event(press(KeyCode::Char('r')));
        match rx.try_recv() {
            Ok(Action::Inbox(InboxAction::ConfirmReject {
                task_id,
                vrc: false,
            })) => {
                assert_eq!(task_id, "t1");
            }
            _ => panic!("expected ConfirmReject"),
        }
    }

    /// Removing the passphrase from Settings arms a confirmation first.
    #[test]
    fn remove_passphrase_arms_a_confirmation() {
        use crate::state_handler::main_page::content::{PROTECTION_CONFIRM_REMOVE, SettingsMode};
        let (mut page, mut rx) = page_for(MainMenu::Settings, |s| {
            s.main_page.content_panel.settings.mode = SettingsMode::ChangeProtection {
                selected_option: 1,
                passphrase_len: 0,
                confirm_len: 0,
                active_field: 0,
            };
        });
        page.handle_key_event(press(KeyCode::Enter));
        match rx.try_recv() {
            Ok(Action::Settings(SettingsAction::ProtectionTabSwitch(f))) => {
                assert_eq!(f, PROTECTION_CONFIRM_REMOVE);
            }
            _ => panic!("expected the removal to be armed"),
        }
    }
}
