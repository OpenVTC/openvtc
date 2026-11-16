//! One text-input behaviour for the main page's forms (#578).
//!
//! The main page's forms keep their text in `State` as plain strings and set
//! it through actions. Every such field is edited here, through `tui_input` —
//! the same editor the setup and join screens use — with a cursor kept on the
//! page:
//!
//! - typing inserts at the cursor; Backspace/Del delete either side of it;
//! - ←/→ move within the field, Ctrl+←/→ by word, Home/End (and Ctrl+A/E) to
//!   either end; Ctrl+U, Ctrl+W and Ctrl+K delete the line, the word before
//!   and the rest of the line;
//! - a paste is inserted at the cursor, wherever a field takes paste;
//! - keys the field does not take go to the form (Enter, Esc, Tab, ↑/↓), and
//!   a key the view lists as its own chord (Ctrl+A on a field that "adds an
//!   owner") is the view's.
//!
//! [`MainPage::focused_field`] is the single list of the main page's string
//! fields; the cursor is drawn by [`cursor_spans`].

use crossterm::event::{Event, KeyEvent};
use ratatui::{style::Style, text::Span};
use std::cell::Cell;
use tui_input::{Input, backend::crossterm::EventHandler};

use crate::state_handler::actions::{
    Action, CommunityContextAction, CredentialAction, ElectionsAction, RelationshipAction,
    ReposAction, SettingsAction, VettingAction, WorkspaceAction,
};
use crate::state_handler::main_page::content::{
    ContextDeletePhase, CredentialsMode, RelationshipsMode, SettingsMode,
};
use crate::state_handler::main_page::menu::MainMenu;
use crate::ui::pages::main::MainPage;

/// The focused text field: what it holds and how to set it.
pub(crate) struct Field {
    /// Which field, so the cursor is not carried from one to another.
    pub id: String,
    pub value: String,
    /// Whether a paste is accepted. A typed confirmation word is not: typing
    /// it is the point.
    pub paste: bool,
    /// Backspace in the empty field belongs to the form (it removes the last
    /// owner chip on the new-repository form).
    form_backspace: bool,
    set: Box<dyn Fn(String) -> Action>,
}

impl Field {
    fn new(id: impl Into<String>, value: &str, set: impl Fn(String) -> Action + 'static) -> Self {
        Self {
            id: id.into(),
            value: value.to_string(),
            paste: true,
            form_backspace: false,
            set: Box::new(set),
        }
    }

    fn form_backspace(mut self) -> Self {
        self.form_backspace = true;
        self
    }

    fn no_paste(mut self) -> Self {
        self.paste = false;
        self
    }

    /// The action that sets the field to `value`.
    pub(crate) fn set(&self, value: String) -> Action {
        (self.set)(value)
    }
}

thread_local! {
    /// The focused field's cursor (in characters) for this frame, recorded by
    /// the page before the panels render — carried like the status wrap width.
    static CURSOR: Cell<Option<usize>> = const { Cell::new(None) };
}

/// Record the focused field's cursor for this frame.
pub(crate) fn set_cursor(cursor: Option<usize>) {
    CURSOR.set(cursor);
}

/// A field's text with the cursor drawn where it is, when the field has the
/// focus; the text alone otherwise.
pub(crate) fn cursor_spans(value: &str, focused: bool, style: Style) -> Vec<Span<'static>> {
    if !focused {
        return vec![Span::styled(value.to_string(), style)];
    }
    let chars = value.chars().count();
    caret_at(value, CURSOR.get().unwrap_or(chars), style)
}

/// A field held as a `tui_input::Input` in the view state (the identity
/// forms): its text, with the caret drawn at the input's own cursor when it
/// has the focus.
pub(crate) fn input_spans(input: &Input, focused: bool, style: Style) -> Vec<Span<'static>> {
    if !focused {
        return vec![Span::styled(input.value().to_string(), style)];
    }
    caret_at(input.value(), input.cursor(), style)
}

/// `value` split at character `at` (clamped to its end), with the caret
/// between the halves.
fn caret_at(value: &str, at: usize, style: Style) -> Vec<Span<'static>> {
    let at = at.min(value.chars().count());
    let split = value.char_indices().nth(at).map_or(value.len(), |(i, _)| i);
    vec![
        Span::styled(value[..split].to_string(), style),
        Span::styled("▏", style),
        Span::styled(value[split..].to_string(), style),
    ]
}

/// What `key` does to `value` with the cursor at `cursor`: the new value and
/// cursor, or `None` when the key is not an editing key.
pub(crate) fn apply(value: &str, cursor: usize, key: &KeyEvent) -> Option<(String, usize)> {
    if !is_edit_key(key) {
        return None;
    }
    let mut input = Input::new(value.to_string()).with_cursor(cursor);
    // `None` here is an edit that changes nothing (→ at the end).
    let _ = input.handle_event(&Event::Key(*key));
    Some((input.value().to_string(), input.cursor()))
}

/// Whether `key` is one the editor takes.
pub(crate) fn is_edit_key(key: &KeyEvent) -> bool {
    tui_input::backend::crossterm::to_input_request(&Event::Key(*key)).is_some()
}

impl MainPage {
    /// The text field that has the focus on the main page, if any — the one
    /// list of the page's string fields.
    pub(crate) fn focused_field(&self) -> Option<Field> {
        let page = &self.props.main_page;
        if !page.content_panel.selected
            || page.create_persona.is_some()
            || page.agent_names.is_some()
            || page.add_vic.is_some()
            || page.switcher.is_some()
        {
            return None;
        }
        let content = &page.content_panel;
        match page.menu_panel.selected_menu {
            MainMenu::Relationships => match &content.relationships.mode {
                RelationshipsMode::NewRequest {
                    did_input,
                    alias_input,
                    reason_input,
                    active_field,
                    ..
                } => {
                    let field = *active_field;
                    let value = match field {
                        0 => did_input,
                        1 => alias_input,
                        2 => reason_input,
                        _ => return None,
                    };
                    Some(Field::new(format!("rel-new:{field}"), value, move |v| {
                        Action::Relationship(RelationshipAction::InputUpdate { field, value: v })
                    }))
                }
                RelationshipsMode::EditAlias { alias_input, .. } => {
                    Some(Field::new("rel-alias", alias_input, |v| {
                        Action::Relationship(RelationshipAction::EditAliasUpdate(v))
                    }))
                }
                RelationshipsMode::Witness { witness_input, .. } => {
                    Some(Field::new("rel-witness", witness_input, |v| {
                        Action::Relationship(RelationshipAction::WitnessInputUpdate(v))
                    }))
                }
                _ => None,
            },
            MainMenu::Credentials => match &content.credentials.mode {
                CredentialsMode::NewRequest { reason_input, .. }
                    if content
                        .relationships
                        .relationships
                        .iter()
                        .any(|r| r.state == "Established") =>
                {
                    Some(Field::new("cred-reason", reason_input, |v| {
                        Action::Credential(CredentialAction::ReasonUpdate(v))
                    }))
                }
                _ => None,
            },
            MainMenu::Settings => match &content.settings.mode {
                SettingsMode::EditFriendlyName { input } => {
                    Some(Field::new("settings-name", input, |v| {
                        Action::Settings(SettingsAction::FieldUpdate(v))
                    }))
                }
                SettingsMode::ExportConfig {
                    path_input,
                    active_field: 0,
                    ..
                }
                | SettingsMode::ImportConfig {
                    path_input,
                    active_field: 0,
                    ..
                } => Some(Field::new("settings-path", path_input, |v| {
                    Action::Settings(SettingsAction::FormFieldUpdate { field: 0, value: v })
                })),
                SettingsMode::WipeConfirm { confirm_input } => Some(
                    Field::new("settings-wipe", confirm_input, |v| {
                        Action::Settings(SettingsAction::WipeProfileInput(v))
                    })
                    .no_paste(),
                ),
                #[cfg(feature = "openpgp-card")]
                SettingsMode::TokenResetConfirm { confirm_input, .. } => Some(
                    Field::new("settings-reset", confirm_input, |v| {
                        Action::Settings(SettingsAction::TokenFactoryResetInput(v))
                    })
                    .no_paste(),
                ),
                _ => None,
            },
            MainMenu::Vetting => {
                let vetting = &content.vetting;
                let text = vetting.mode.focused_text()?;
                Some(Field::new(
                    format!("vetting:{}", super::view_id(page)),
                    text,
                    |v| Action::Vetting(VettingAction::Input(v)),
                ))
            }
            MainMenu::Communities => self.communities_field(),
            _ => None,
        }
    }

    /// The Communities page's text fields, in the order its views take the
    /// keyboard.
    fn communities_field(&self) -> Option<Field> {
        let content = &self.props.main_page.content_panel;
        if content.capabilities.view.is_some() {
            return None;
        }
        if let Some(view) = &content.repos.view {
            return repos_field(view);
        }
        if content.rooms.view.is_some() {
            return None;
        }
        if let Some(view) = &content.elections.view {
            let form = view.form.as_ref()?;
            let shown = view.shown.as_ref()?;
            if view.screen != crate::state_handler::main_page::elections::Screen::Ballot
                || !form.typing(shown.manifest())
            {
                return None;
            }
            return Some(Field::new(
                format!("ballot:{}", form.question),
                form.text().unwrap_or_default(),
                |v| Action::Elections(ElectionsAction::BallotText(v)),
            ));
        }
        if content.communities.personhood_evidence.is_some() {
            return None;
        }
        if let Some(view) = &content.communities.context_delete {
            return matches!(view.phase, ContextDeletePhase::Ready(_)).then(|| {
                Field::new("context-delete", &view.typed, |v| {
                    Action::CommunityContext(CommunityContextAction::DeleteInput(v))
                })
                .no_paste()
            });
        }
        let view = content.communities.device_access.as_ref()?;
        let form = view.form.as_ref().filter(|f| f.field < 2 && !view.busy)?;
        let field = form.field;
        Some(Field::new(
            format!("grant:{field}"),
            super::grant_form_text(form),
            move |v| {
                Action::CommunityContext(CommunityContextAction::GrantInput { field, value: v })
            },
        ))
    }

    /// The focused field's cursor: kept while the same field holds the same
    /// text it held after the last edit, else at its end.
    pub(crate) fn field_cursor(&self, field: &Field) -> usize {
        let end = field.value.chars().count();
        match &self.field_cursor {
            Some((id, value, at)) if *id == field.id && *value == field.value => (*at).min(end),
            _ => end,
        }
    }

    /// Apply an editing key to the focused field. `true` when the field took
    /// the key.
    pub(crate) fn edit_focused_field(&mut self, key: &KeyEvent) -> bool {
        let Some(field) = self.focused_field() else {
            return false;
        };
        if !is_edit_key(key) {
            return false;
        }
        let cursor = self.field_cursor(&field);
        let Some((value, at)) = apply(&field.value, cursor, key) else {
            return false;
        };
        if value == field.value && at == cursor {
            // Nothing to do at this edge (→ at the end, Backspace at the
            // start): the field still took the key — unless the form has a
            // use for Backspace in its empty field.
            return !(field.form_backspace
                && field.value.is_empty()
                && key.code == crossterm::event::KeyCode::Backspace);
        }
        if value != field.value {
            let _ = self.action_tx.send(field.set(value.clone()));
        }
        self.field_cursor = Some((field.id, value, at));
        true
    }

    /// Insert a paste at the focused field's cursor. `true` when a field
    /// took it.
    pub(crate) fn paste_into_focused_field(&mut self, text: &str) -> bool {
        let Some(field) = self.focused_field() else {
            return false;
        };
        if !field.paste {
            return true;
        }
        let cursor = self.field_cursor(&field);
        let split = field
            .value
            .char_indices()
            .nth(cursor)
            .map_or(field.value.len(), |(i, _)| i);
        let pasted: String = text.chars().filter(|c| !c.is_control()).collect();
        let mut value = field.value.clone();
        value.insert_str(split, &pasted);
        let at = cursor + pasted.chars().count();
        let _ = self.action_tx.send(field.set(value.clone()));
        self.field_cursor = Some((field.id, value, at));
        true
    }
}

/// The Repos view's focused text field.
fn repos_field(view: &crate::state_handler::main_page::repos::ReposView) -> Option<Field> {
    use crate::state_handler::main_page::repos::{ReposScreen, WorkspaceForm};
    use ReposAction as R;
    use WorkspaceAction as W;
    if view.confirm.is_some() || view.workspace.confirm.is_some() {
        return None;
    }
    match &view.workspace.form {
        Some(WorkspaceForm::Settings { root, .. }) => {
            return Some(Field::new("repos-root", root, |v| {
                Action::Repos(R::Workspace(W::SettingsInput(v)))
            }));
        }
        Some(WorkspaceForm::UsePath { path, .. }) => {
            return Some(Field::new("repos-use", path, |v| {
                Action::Repos(R::Workspace(W::UseInput(v)))
            }));
        }
        Some(WorkspaceForm::Account(form)) => {
            return form.typing().then(|| {
                Field::new("repos-account", &form.path, |v| {
                    Action::Repos(R::Workspace(W::AccountInput(v)))
                })
            });
        }
        None => {}
    }
    if let Some(form) = &view.add {
        let field = form.field;
        return match field {
            0 => Some(Field::new("repos-add:0", &form.query, |v| {
                Action::Repos(R::AddInput { field: 0, value: v })
            })),
            3 => Some(Field::new("repos-add:3", &form.reason, |v| {
                Action::Repos(R::AddInput { field: 3, value: v })
            })),
            _ => None,
        };
    }
    if let ReposScreen::NewRepo(form) = &view.screen {
        return match form.field {
            1 => Some(Field::new("repos-new:1", &form.name, |v| {
                Action::Repos(R::NewInput { field: 1, value: v })
            })),
            3 => Some(Field::new("repos-new:3", &form.description, |v| {
                Action::Repos(R::NewInput { field: 3, value: v })
            })),
            4 => Some(
                Field::new("repos-new:4", &form.owner_query, |v| {
                    Action::Repos(R::NewOwnerQuery(v))
                })
                .form_backspace(),
            ),
            _ => None,
        };
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    #[test]
    fn typing_inserts_at_the_cursor() {
        assert_eq!(
            apply("did:example", 4, &key(KeyCode::Char('X'))),
            Some(("did:Xexample".into(), 5))
        );
    }

    #[test]
    fn arrows_move_within_the_field() {
        assert_eq!(
            apply("abc", 3, &key(KeyCode::Left)),
            Some(("abc".into(), 2))
        );
        assert_eq!(
            apply("abc", 0, &key(KeyCode::Right)),
            Some(("abc".into(), 1))
        );
        assert_eq!(
            apply("abc", 2, &key(KeyCode::Home)),
            Some(("abc".into(), 0))
        );
        assert_eq!(apply("abc", 0, &key(KeyCode::End)), Some(("abc".into(), 3)));
    }

    #[test]
    fn deletes_either_side_of_the_cursor() {
        assert_eq!(
            apply("abc", 1, &key(KeyCode::Backspace)),
            Some(("bc".into(), 0))
        );
        assert_eq!(
            apply("abc", 1, &key(KeyCode::Delete)),
            Some(("ac".into(), 1))
        );
    }

    /// Ctrl chords edit; they never type their letter.
    #[test]
    fn ctrl_chords_edit_and_never_insert_a_letter() {
        assert_eq!(
            apply("hello world", 11, &ctrl('w')),
            Some(("hello ".into(), 6))
        );
        assert_eq!(
            apply("hello", 5, &ctrl('u')).map(|(v, _)| v),
            Some(String::new())
        );
        assert_eq!(apply("hello", 5, &ctrl('a')), Some(("hello".into(), 0)));
        assert_eq!(apply("hello", 0, &ctrl('e')), Some(("hello".into(), 5)));
        for c in ['t', 'v', 'x', 'z'] {
            let edited = apply("hello", 5, &ctrl(c));
            assert!(
                edited.is_none_or(|(v, _)| v == "hello"),
                "Ctrl+{c} must not insert"
            );
        }
    }

    #[test]
    fn non_ascii_text_is_edited_by_character() {
        assert_eq!(
            apply("héllo", 2, &key(KeyCode::Backspace)),
            Some(("hllo".into(), 1))
        );
    }

    #[test]
    fn the_cursor_is_drawn_where_it_is() {
        set_cursor(Some(2));
        let spans = cursor_spans("abcd", true, Style::default());
        let drawn: String = spans.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(drawn, "ab▏cd");
        let unfocused: String = cursor_spans("abcd", false, Style::default())
            .iter()
            .map(|s| s.content.as_ref())
            .collect();
        assert_eq!(unfocused, "abcd");
        set_cursor(None);
    }
}
