//! Shared helpers for rendering status messages in main-page panels.
//!
//! The content `Paragraph` does not wrap, so long status messages (typically
//! multi-cause error chains) must be word-wrapped manually before being
//! pushed as `Line`s or they get clipped at the panel width.

use crate::colors::{
    COLOR_ORANGE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT, COLOR_WARNING_ACCESSIBLE_RED,
};
pub use crate::state_handler::main_page::status::{Severity, Status};
use ratatui::{
    style::{Modifier, Style},
    text::{Line, Span},
};

/// Fallback wrap width, used only before the first frame has recorded a real
/// one. Matches the width the logs-panel detail view has always assumed.
const DEFAULT_STATUS_WRAP_WIDTH: usize = 76;

/// Narrowest width worth wrapping to. Below this a "wrapped" message is one
/// word per line, which is less readable than letting it run.
const MIN_STATUS_WRAP_WIDTH: usize = 24;

/// Fallback content height, used only before the first frame has recorded a
/// real one. A conservative 24-row terminal minus the surrounding chrome.
const DEFAULT_CONTENT_HEIGHT: usize = 16;

thread_local! {
    /// Visible width of the content panel, recorded by [`set_wrap_width`] at the
    /// top of each frame.
    ///
    /// The `Panel` trait renders to `Vec<Line>` without being told its area; a
    /// hardcoded width would wrap every status message at less than half the
    /// available width on a wide terminal. Threading
    /// the width through every panel signature would touch all of them for one
    /// consumer; the render path is single-threaded and strictly
    /// set-then-render within a frame, so a thread-local carries it instead.
    static WRAP_WIDTH: std::cell::Cell<usize> =
        const { std::cell::Cell::new(DEFAULT_STATUS_WRAP_WIDTH) };

    /// Visible height of the content panel, recorded by [`set_content_height`]
    /// alongside the width. Carried the same way and for the same reason.
    static CONTENT_HEIGHT: std::cell::Cell<usize> =
        const { std::cell::Cell::new(DEFAULT_CONTENT_HEIGHT) };
}

/// Record the content panel's visible width for this frame. Called by the
/// content panel before it renders, so `push_status` wraps to the real width.
pub fn set_wrap_width(width: usize) {
    WRAP_WIDTH.set(width.max(MIN_STATUS_WRAP_WIDTH));
}

/// The width [`push_status`] wraps to.
fn wrap_width() -> usize {
    WRAP_WIDTH.get()
}

/// The content panel's usable width this frame, for a panel that has to fit
/// something that cannot wrap — a QR code.
pub fn content_width() -> usize {
    WRAP_WIDTH.get()
}

/// Record the content panel's visible height for this frame, the companion to
/// [`set_wrap_width`].
///
/// Only one thing needs it, and it is the one thing that cannot be scrolled
/// into view: a QR code has to be whole on the screen to be scanned at all.
pub fn set_content_height(height: usize) {
    CONTENT_HEIGHT.set(height);
}

/// The content panel's usable height this frame, in text rows.
pub fn content_height() -> usize {
    CONTENT_HEIGHT.get()
}

/// Push a status line as one or more wrapped lines (no trailing blank).
///
/// Its colour comes from the [`Severity`] the producer set (see
/// [`severity_style`]), never from the wording of the text (#577). Each
/// wrapped line is prefixed with `indent` so callers can indent inside a
/// panel.
pub fn push_status(lines: &mut Vec<Line<'static>>, status: &Status, indent: &'static str) {
    push_wrapped(lines, &status.text, indent, severity_style(status.severity));
}

/// Push a failure the producer stored as an error (a form's `error` field):
/// [`push_status`] at [`Severity::Error`] without building a [`Status`].
pub fn push_error(lines: &mut Vec<Line<'static>>, msg: &str, indent: &'static str) {
    push_wrapped(lines, msg, indent, severity_style(Severity::Error));
}

/// [`push_status`] in a style the caller chooses, for a message whose severity
/// its wording does not carry.
pub fn push_wrapped(lines: &mut Vec<Line<'static>>, msg: &str, indent: &'static str, style: Style) {
    let width = wrap_width().saturating_sub(indent.len()).max(1);
    for wrapped in wrap_text(msg, width) {
        lines.push(Line::from(vec![Span::styled(
            format!("{}{}", indent, wrapped),
            style,
        )]));
    }
}

/// The one style a status line of each severity is drawn in, on every panel.
///
/// Errors are bold as well as red, so they stay distinguishable where colour
/// is not (a colour-blind theme, a monochrome terminal).
#[must_use]
pub fn severity_style(severity: Severity) -> Style {
    match severity {
        Severity::Info | Severity::Progress => Style::new().fg(COLOR_TEXT_DEFAULT),
        Severity::Success => Style::new().fg(COLOR_SUCCESS),
        Severity::Warning => Style::new().fg(COLOR_ORANGE),
        Severity::Error => Style::new()
            .fg(COLOR_WARNING_ACCESSIBLE_RED)
            .add_modifier(Modifier::BOLD),
    }
}

/// Word-wrap `text` into lines no longer than `width` characters. Embedded
/// newlines are honored so pre-formatted multi-line messages keep structure.
pub fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let mut result: Vec<String> = Vec::new();
    for paragraph in text.split('\n') {
        let mut current = String::new();
        let mut pushed_any = false;
        for word in paragraph.split_whitespace() {
            if current.is_empty() {
                current = word.to_string();
            } else if current.len() + 1 + word.len() <= width {
                current.push(' ');
                current.push_str(word);
            } else {
                result.push(std::mem::take(&mut current));
                pushed_any = true;
                current = word.to_string();
            }
        }
        if !current.is_empty() {
            result.push(current);
        } else if !pushed_any {
            // Preserve blank paragraph separators from embedded newlines.
            result.push(String::new());
        }
    }
    if result.is_empty() {
        result.push(String::new());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_text_breaks_on_word_boundaries() {
        let out = wrap_text("hello world how are you today", 11);
        assert_eq!(out, vec!["hello world", "how are you", "today"]);
    }

    #[test]
    fn wrap_text_preserves_embedded_newlines() {
        let out = wrap_text("line one\nline two", 80);
        assert_eq!(out, vec!["line one", "line two"]);
    }

    #[test]
    fn wrap_text_handles_oversize_word() {
        let long = "a".repeat(40);
        let out = wrap_text(&long, 10);
        assert_eq!(out, vec![long]);
    }

    #[test]
    fn wrap_text_empty_input_yields_one_blank() {
        assert_eq!(wrap_text("", 80), vec![String::new()]);
    }

    /// The colour follows the severity the producer set, not the wording:
    /// a failure worded without "failed" is red because it is an error (#577),
    /// and a success worded with "failed" in it is still a success.
    #[test]
    fn colour_follows_severity_not_wording() {
        for msg in [
            "Messaging unavailable — cannot leave right now.",
            "Couldn't archive: timeout",
            "Witnessing is not available until messaging and the VTA are connected.",
        ] {
            let mut lines = Vec::new();
            push_status(&mut lines, &Status::error(msg), "");
            assert_eq!(
                lines[0].spans[0].style.fg,
                Some(COLOR_WARNING_ACCESSIBLE_RED),
                "{msg}"
            );
        }
        let mut lines = Vec::new();
        push_status(&mut lines, &Status::success("Retried the failed send"), "");
        assert_eq!(lines[0].spans[0].style.fg, Some(COLOR_SUCCESS));
        let mut lines = Vec::new();
        push_status(&mut lines, &Status::warning("Nothing to dismiss"), "");
        assert_eq!(lines[0].spans[0].style.fg, Some(COLOR_ORANGE));
    }

    #[test]
    fn every_severity_has_a_distinct_style() {
        let styles = [
            Severity::Info,
            Severity::Success,
            Severity::Warning,
            Severity::Error,
        ]
        .map(severity_style);
        for (i, a) in styles.iter().enumerate() {
            for b in &styles[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }
}
