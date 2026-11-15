//! The main page's key map: one table per view, drawn as that view's footer and
//! listed by the `?` help overlay (#580).
//!
//! A view says which keys it takes by building a list of [`Binding`]s and
//! drawing it with [`footer`]. Drawing also *advertises* the list for the frame
//! ([`take_advertised`]), and that advertised list is what `?` shows and what
//! decides whether an unhandled key earns a "nothing here" hint. The footer and
//! the help overlay are therefore the same table, and the key-handler tests
//! check each view's handler against it — a handled key cannot be
//! unadvertised, nor an advertised key unhandled.
//!
//! Key labels use one vocabulary on every panel (`Enter`, `Esc`, `Tab`,
//! `Shift+Tab`, `↑/↓`, `←/→`, `Space`, `Del`, `Ctrl+X`, single characters),
//! parsed into the [`KeyCode`]s they stand for by [`codes`], so the label shown
//! and the key matched cannot disagree.

use std::cell::RefCell;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    style::Style,
    text::{Line, Span},
};

use crate::colors::{COLOR_DARK_GRAY, COLOR_TEXT_DEFAULT};

/// One key (or set of keys) a view takes, and what it does there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Binding {
    /// The keys as shown, e.g. `"↑/↓"`, `"Enter"`, `"d/Del"`, `"Ctrl+A"`.
    pub key: &'static str,
    /// What the keys do here, in a few words.
    pub does: String,
}

/// Shorthand for a [`Binding`].
pub(crate) fn k(key: &'static str, does: impl Into<String>) -> Binding {
    debug_assert!(
        key == TYPE || !codes(key).is_empty(),
        "unknown key label {key:?}"
    );
    Binding {
        key,
        does: does.into(),
    }
}

/// The label of the binding that says a text field takes typing: every
/// printable character, Backspace/Del, ←/→ and Home/End edit the field.
pub(crate) const TYPE: &str = "type";

impl Binding {
    /// The keys this binding stands for.
    pub(crate) fn codes(&self) -> Vec<(KeyCode, KeyModifiers)> {
        codes(self.key)
    }

    /// Whether this binding is a text field taking typing.
    pub(crate) fn is_typing(&self) -> bool {
        self.key == TYPE
    }

    /// Whether `key` is one of this binding's keys.
    pub(crate) fn matches(&self, key: &KeyEvent) -> bool {
        if self.is_typing() {
            return is_text_edit(key);
        }
        let mods = key.modifiers & (KeyModifiers::CONTROL | KeyModifiers::ALT);
        self.codes()
            .iter()
            .any(|(code, m)| *code == key.code && *m == mods)
    }
}

/// Whether `key` is a keystroke a text field takes: a character, Backspace/Del,
/// ←/→, Home/End, or an editing chord (see `text_input`).
pub(crate) fn is_text_edit(key: &KeyEvent) -> bool {
    super::text_input::is_edit_key(key)
}

/// Parse a key label into the keys it stands for. Alternatives are separated
/// by `/` (`"↑/↓"`, `"d/Del"`) or `" or "`; an unknown token parses to nothing,
/// which [`k`] rejects in debug builds and the tests reject always.
pub(crate) fn codes(label: &str) -> Vec<(KeyCode, KeyModifiers)> {
    let mut out = Vec::new();
    for part in label.split(" or ") {
        // "↑/↓" splits on '/', but "/" alone is the slash key.
        let tokens: Vec<&str> = if part == "/" {
            vec!["/"]
        } else {
            part.split('/').collect()
        };
        for token in tokens {
            match token_code(token.trim()) {
                Some(code) => out.push(code),
                None => return Vec::new(),
            }
        }
    }
    out
}

fn token_code(token: &str) -> Option<(KeyCode, KeyModifiers)> {
    let none = KeyModifiers::NONE;
    if let Some(rest) = token.strip_prefix("Ctrl+") {
        let mut chars = rest.chars();
        let c = chars.next()?;
        if chars.next().is_some() {
            return None;
        }
        return Some((KeyCode::Char(c.to_ascii_lowercase()), KeyModifiers::CONTROL));
    }
    let code = match token {
        "Enter" => KeyCode::Enter,
        "Esc" => KeyCode::Esc,
        "Tab" => KeyCode::Tab,
        "Shift+Tab" => KeyCode::BackTab,
        "↑" => KeyCode::Up,
        "↓" => KeyCode::Down,
        "←" => KeyCode::Left,
        "→" => KeyCode::Right,
        "Space" => KeyCode::Char(' '),
        "Del" => KeyCode::Delete,
        "Backspace" => KeyCode::Backspace,
        "PgUp" => KeyCode::PageUp,
        "PgDn" => KeyCode::PageDown,
        "Home" => KeyCode::Home,
        "End" => KeyCode::End,
        "F10" => KeyCode::F(10),
        t => {
            let mut chars = t.chars();
            let c = chars.next()?;
            if chars.next().is_some() || !c.is_ascii_graphic() {
                return None;
            }
            KeyCode::Char(c)
        }
    };
    Some((code, none))
}

thread_local! {
    /// The bindings advertised by the footers drawn so far this frame.
    ///
    /// Carried like the status wrap width (see `components::status`): panels
    /// render to `Vec<Line>` without a handle on the page, the render path is
    /// single-threaded, and the page clears it at the top of every frame.
    static ADVERTISED: RefCell<Vec<Binding>> = const { RefCell::new(Vec::new()) };

    /// A confirmation prompt was drawn this frame: it owns the keyboard, so
    /// its keys are the only ones advertised whatever else was drawn.
    static CONFIRMING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Start a frame: nothing is advertised yet.
pub(crate) fn begin_frame() {
    ADVERTISED.with(|a| a.borrow_mut().clear());
    CONFIRMING.set(false);
}

/// Everything advertised since [`begin_frame`], leaving it empty.
pub(crate) fn take_advertised() -> Vec<Binding> {
    let advertised = ADVERTISED.with(|a| std::mem::take(&mut *a.borrow_mut()));
    if CONFIRMING.replace(false) {
        return vec![
            k("y", "confirm"),
            k("Esc", "cancel (so does any other key)"),
        ];
    }
    advertised
}

/// A confirmation prompt is on screen (see `confirm::prompt`).
pub(crate) fn confirming() {
    CONFIRMING.set(true);
}

/// Advertise `bindings` without drawing them (a view whose keys are shown some
/// other way, such as a prompt that names its keys in its own words).
pub(crate) fn advertise(bindings: &[Binding]) {
    ADVERTISED.with(|a| a.borrow_mut().extend_from_slice(bindings));
}

/// One footer line: `key: does · key: does`, dim, prefixed with `indent`.
pub(crate) fn line(indent: &'static str, bindings: &[Binding]) -> Line<'static> {
    let mut spans = vec![Span::raw(indent)];
    for (i, b) in bindings.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" · ", Style::new().fg(COLOR_DARK_GRAY)));
        }
        spans.push(Span::styled(b.key, Style::new().fg(COLOR_TEXT_DEFAULT)));
        spans.push(Span::styled(
            format!(": {}", b.does),
            Style::new().fg(COLOR_DARK_GRAY),
        ));
    }
    Line::from(spans)
}

/// One footer line for an overlay, advertised for the frame. An overlay owns
/// the keyboard while it is open, so its keys replace the panel's.
pub(crate) fn overlay_line(bindings: &[Binding]) -> Line<'static> {
    advertise(bindings);
    line("", bindings)
}

/// Draw `bindings` as a footer and advertise them for `?`.
///
/// A footer wider than the panel wraps onto further lines at a binding
/// boundary rather than being clipped (#576).
pub(crate) fn footer(lines: &mut Vec<Line<'static>>, indent: &'static str, bindings: &[Binding]) {
    advertise(bindings);
    let width = super::components::status::content_width();
    let mut row: Vec<Binding> = Vec::new();
    let mut used = indent.chars().count();
    for b in bindings {
        let w = b.key.chars().count() + 2 + b.does.chars().count();
        let sep = if row.is_empty() { 0 } else { 3 };
        if !row.is_empty() && used + sep + w > width {
            lines.push(line(indent, &row));
            row.clear();
            used = indent.chars().count();
        }
        used += if row.is_empty() { w } else { 3 + w };
        row.push(b.clone());
    }
    if !row.is_empty() {
        lines.push(line(indent, &row));
    }
}

/// The keys that work on every view of the main page.
pub(crate) fn global() -> Vec<Binding> {
    vec![
        k("F10", "quit"),
        k("?", "keys"),
        k("Tab", "switch panel"),
        k("Ctrl+K", "switch community"),
        k("PgUp/PgDn", "scroll"),
        k("Home/End", "top / bottom"),
    ]
}

/// The menu's own keys, while it has the focus.
pub(crate) fn menu() -> Vec<Binding> {
    vec![
        k("↑/↓", "choose"),
        k("Enter/→", "open"),
        k("j/k", "down / up"),
    ]
}

/// A short name for a key, for "that key does nothing here".
pub(crate) fn describe(key: &KeyEvent) -> String {
    let base = match key.code {
        KeyCode::Char(' ') => "Space".to_string(),
        KeyCode::Char(c) => c.to_string(),
        KeyCode::Enter => "Enter".into(),
        KeyCode::Esc => "Esc".into(),
        KeyCode::Tab => "Tab".into(),
        KeyCode::BackTab => "Shift+Tab".into(),
        KeyCode::Up => "↑".into(),
        KeyCode::Down => "↓".into(),
        KeyCode::Left => "←".into(),
        KeyCode::Right => "→".into(),
        KeyCode::Backspace => "Backspace".into(),
        KeyCode::Delete => "Del".into(),
        KeyCode::F(n) => format!("F{n}"),
        other => format!("{other:?}"),
    };
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        format!("Ctrl+{base}")
    } else if key.modifiers.contains(KeyModifiers::ALT) {
        format!("Alt+{base}")
    } else {
        base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_parse_to_the_keys_they_name() {
        assert_eq!(
            codes("↑/↓"),
            vec![
                (KeyCode::Up, KeyModifiers::NONE),
                (KeyCode::Down, KeyModifiers::NONE)
            ]
        );
        assert_eq!(
            codes("d/Del"),
            vec![
                (KeyCode::Char('d'), KeyModifiers::NONE),
                (KeyCode::Delete, KeyModifiers::NONE)
            ]
        );
        assert_eq!(
            codes("Ctrl+K"),
            vec![(KeyCode::Char('k'), KeyModifiers::CONTROL)]
        );
        assert_eq!(
            codes("Esc or Enter"),
            vec![
                (KeyCode::Esc, KeyModifiers::NONE),
                (KeyCode::Enter, KeyModifiers::NONE)
            ]
        );
        assert_eq!(codes("?"), vec![(KeyCode::Char('?'), KeyModifiers::NONE)]);
        assert!(codes("⏎").is_empty(), "one vocabulary: Enter, not ⏎");
        assert!(codes("Return").is_empty());
    }

    #[test]
    fn every_global_and_menu_label_parses() {
        for b in global().iter().chain(menu().iter()) {
            assert!(!b.codes().is_empty(), "{}", b.key);
        }
    }

    #[test]
    fn a_footer_wraps_rather_than_clipping() {
        super::super::components::status::set_wrap_width(30);
        let mut lines = Vec::new();
        footer(
            &mut lines,
            "",
            &[
                k("↑/↓", "move"),
                k("Enter", "open"),
                k("d", "dismiss"),
                k("c", "clear all"),
                k("Esc", "back"),
            ],
        );
        assert!(lines.len() > 1);
        for l in &lines {
            assert!(l.width() <= 30, "{l:?}");
        }
        let advertised = take_advertised();
        assert_eq!(advertised.len(), 5);
    }

    #[test]
    fn typing_matches_text_keys_only() {
        let t = k(TYPE, "edit");
        assert!(t.matches(&KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE)));
        assert!(t.matches(&KeyEvent::new(KeyCode::Char('A'), KeyModifiers::SHIFT)));
        assert!(t.matches(&KeyEvent::new(KeyCode::Left, KeyModifiers::NONE)));
        assert!(!t.matches(&KeyEvent::new(KeyCode::Char('t'), KeyModifiers::CONTROL)));
        assert!(!t.matches(&KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)));
    }
}
