//! The one confirmation rule for the main page (#579).
//!
//! A destructive or outward-facing action — one that removes something, or
//! sends something to someone else — is armed by its key and committed only by
//! `y`. Every other key cancels, Enter included: Enter is the key that opened
//! the view a moment earlier, so a key held a moment too long must never also
//! commit. Irreversible wipes (WIPE, RESET) keep their typed word instead.
//!
//! Every prompt ends with [`KEYS`], so it says exactly which keys do what.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// What every confirmation prompt says about its keys.
pub(crate) const KEYS: &str = "y: confirm · any other key: cancel";

/// Whether `key` commits a pending confirmation: a plain `y`, and nothing else.
#[must_use]
pub(crate) fn is_yes(key: &KeyEvent) -> bool {
    key.code == KeyCode::Char('y')
        && !key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
}

/// A confirmation prompt: the question, then [`KEYS`].
#[must_use]
pub(crate) fn prompt(question: &str) -> String {
    super::keymap::confirming();
    format!("{question}   {KEYS}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn only_a_plain_y_confirms() {
        assert!(is_yes(&key(KeyCode::Char('y'))));
        for code in [
            KeyCode::Enter,
            KeyCode::Char('Y'),
            KeyCode::Char('n'),
            KeyCode::Char(' '),
            KeyCode::Esc,
        ] {
            assert!(!is_yes(&key(code)), "{code:?}");
        }
        assert!(!is_yes(&KeyEvent::new(
            KeyCode::Char('y'),
            KeyModifiers::CONTROL
        )));
    }

    #[test]
    fn a_prompt_says_which_keys_do_what() {
        assert_eq!(
            prompt("Remove this?"),
            "Remove this?   y: confirm · any other key: cancel"
        );
    }
}
