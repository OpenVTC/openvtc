//! Themes for the TUI.
//!
//! Every panel draws with seven colour **roles** — the `COLOR_*` constants in
//! [`crate::colors`]: accent (borders, headings), success, warning, danger,
//! text, muted and highlight. Panels keep naming those roles. After each frame
//! is drawn, [`paint`] swaps every role for the active theme's colour and, when
//! the theme has a background, paints it behind everything else. The default
//! theme maps every role to itself, so an unthemed OpenVTC looks exactly as it
//! always has.
//!
//! Doing the swap on the finished frame, rather than threading a palette
//! through every `Style`, keeps theming out of the panels entirely: a panel
//! written today is themed without knowing themes exist.
//!
//! Where themes come from:
//! - [`builtin`] — a handful of well-known open palettes, plus OpenVTC's own;
//! - the user's themes directory — OpenVTC theme files, written by hand, copied
//!   from another theme, or produced by [`import`];
//! - Omarchy's themes, read in place, including whichever is current;
//! - [`import`] converts base16/base24 schemes, Omarchy themes, Alacritty and
//!   Kitty colour files, and [`nvim`] reads any colorscheme Neovim can load.
//!
//! [`catalog`] lists and loads all of them, and remembers the one chosen.

pub mod builtin;
pub mod catalog;
pub mod import;
pub mod nvim;

use std::sync::{PoisonError, RwLock};

use ratatui::buffer::Buffer;
use ratatui::style::Color;

use crate::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS,
    COLOR_TEXT_DEFAULT, COLOR_WARNING_ACCESSIBLE_RED,
};

/// Whether a theme is meant for a dark or a light background.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    #[default]
    Dark,
    Light,
}

impl Mode {
    /// The word a theme file uses.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Dark => "dark",
            Mode::Light => "light",
        }
    }

    /// Read `dark` / `light`; anything else is dark.
    #[must_use]
    pub fn parse(value: &str) -> Self {
        if value.trim().eq_ignore_ascii_case("light") {
            Mode::Light
        } else {
            Mode::Dark
        }
    }
}

/// The colour each role is drawn in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Palette {
    /// Borders, headings, key hints.
    pub accent: Color,
    /// Selection, completed and valid things.
    pub success: Color,
    /// Cautions and things in progress.
    pub warning: Color,
    /// Errors and destructive actions.
    pub danger: Color,
    /// Ordinary text.
    pub text: Color,
    /// Secondary text and hints.
    pub muted: Color,
    /// Values and special actions.
    pub highlight: Color,
    /// Painted behind everything. `None` keeps the terminal's own background.
    pub background: Option<Color>,
}

impl Palette {
    /// OpenVTC's own colours: every role as itself, on the terminal's background.
    pub const DEFAULT: Palette = Palette {
        accent: COLOR_BORDER,
        success: COLOR_SUCCESS,
        warning: COLOR_ORANGE,
        danger: COLOR_WARNING_ACCESSIBLE_RED,
        text: COLOR_TEXT_DEFAULT,
        muted: COLOR_DARK_GRAY,
        highlight: COLOR_SOFT_PURPLE,
        background: None,
    };

    /// The colour role `color` stands for, or `color` itself when it is not a role.
    #[must_use]
    fn role(&self, color: Color) -> Color {
        if color == COLOR_BORDER {
            self.accent
        } else if color == COLOR_SUCCESS {
            self.success
        } else if color == COLOR_ORANGE {
            self.warning
        } else if color == COLOR_WARNING_ACCESSIBLE_RED {
            self.danger
        } else if color == COLOR_TEXT_DEFAULT {
            self.text
        } else if color == COLOR_DARK_GRAY {
            self.muted
        } else if color == COLOR_SOFT_PURPLE {
            self.highlight
        } else {
            color
        }
    }
}

/// A theme: a palette with a name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Theme {
    /// How [`catalog`] finds it again: `catppuccin-mocha`, `user/mine`,
    /// `omarchy/tokyo-night`, `omarchy/current`.
    pub id: String,
    pub name: String,
    pub mode: Mode,
    pub palette: Palette,
}

impl Theme {
    /// OpenVTC's own theme.
    #[must_use]
    pub fn default_theme() -> Self {
        Theme {
            id: builtin::DEFAULT_ID.to_string(),
            name: "OpenVTC".to_string(),
            mode: Mode::Dark,
            palette: Palette::DEFAULT,
        }
    }
}

/// The theme being drawn with, as a name and a palette.
struct Active {
    id: String,
    name: String,
    palette: Palette,
}

static ACTIVE: RwLock<Option<Active>> = RwLock::new(None);

/// Draw with `theme` from the next frame on.
pub fn set_active(theme: &Theme) {
    *ACTIVE.write().unwrap_or_else(PoisonError::into_inner) = Some(Active {
        id: theme.id.clone(),
        name: theme.name.clone(),
        palette: theme.palette,
    });
}

/// The palette being drawn with.
#[must_use]
pub fn active_palette() -> Palette {
    ACTIVE
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
        .map_or(Palette::DEFAULT, |a| a.palette)
}

/// The id and name of the theme being drawn with.
#[must_use]
pub fn active_theme() -> (String, String) {
    ACTIVE
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
        .map_or_else(
            || (builtin::DEFAULT_ID.to_string(), "OpenVTC".to_string()),
            |a| (a.id.clone(), a.name.clone()),
        )
}

/// Theme a finished frame: call at the end of every `Terminal::draw`.
pub fn paint(buffer: &mut Buffer) {
    paint_with(buffer, &active_palette());
}

/// [`paint`] with an explicit palette.
pub fn paint_with(buffer: &mut Buffer, palette: &Palette) {
    if *palette == Palette::DEFAULT {
        return;
    }
    for cell in &mut buffer.content {
        let fg = cell.fg;
        let bg = cell.bg;
        cell.fg = match (fg, palette.background) {
            // Unstyled text on a painted background takes the theme's text
            // colour, or a light theme's background would swallow it.
            (Color::Reset, Some(_)) => palette.text,
            (color, _) => palette.role(color),
        };
        cell.bg = match (bg, palette.background) {
            (Color::Reset, Some(background)) => background,
            (color, _) => palette.role(color),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::layout::Rect;
    use ratatui::style::Style;

    fn palette() -> Palette {
        Palette {
            accent: Color::Rgb(1, 1, 1),
            success: Color::Rgb(2, 2, 2),
            warning: Color::Rgb(3, 3, 3),
            danger: Color::Rgb(4, 4, 4),
            text: Color::Rgb(5, 5, 5),
            muted: Color::Rgb(6, 6, 6),
            highlight: Color::Rgb(7, 7, 7),
            background: Some(Color::Rgb(9, 9, 9)),
        }
    }

    /// Every role is swapped for the theme's colour; anything that is not a
    /// role is left alone.
    #[test]
    fn a_frame_is_drawn_in_the_theme() {
        let mut buffer = Buffer::empty(Rect::new(0, 0, 4, 1));
        buffer.set_string(0, 0, "a", Style::new().fg(COLOR_BORDER));
        buffer.set_string(
            1,
            0,
            "b",
            Style::new().fg(COLOR_TEXT_DEFAULT).bg(COLOR_SUCCESS),
        );
        buffer.set_string(2, 0, "c", Style::new().fg(Color::Rgb(200, 1, 2)));
        paint_with(&mut buffer, &palette());

        assert_eq!(buffer[(0, 0)].fg, Color::Rgb(1, 1, 1));
        assert_eq!(buffer[(1, 0)].fg, Color::Rgb(5, 5, 5));
        assert_eq!(buffer[(1, 0)].bg, Color::Rgb(2, 2, 2));
        assert_eq!(buffer[(2, 0)].fg, Color::Rgb(200, 1, 2));
        // An untouched cell gets the background, and text that can be read on it.
        assert_eq!(buffer[(3, 0)].bg, Color::Rgb(9, 9, 9));
        assert_eq!(buffer[(3, 0)].fg, Color::Rgb(5, 5, 5));
    }

    /// Without a background of its own a theme leaves the terminal's in place.
    #[test]
    fn a_theme_without_a_background_keeps_the_terminals() {
        let mut buffer = Buffer::empty(Rect::new(0, 0, 1, 1));
        let palette = Palette {
            background: None,
            ..palette()
        };
        paint_with(&mut buffer, &palette);
        assert_eq!(buffer[(0, 0)].bg, Color::Reset);
        assert_eq!(buffer[(0, 0)].fg, Color::Reset);
    }

    #[test]
    fn the_default_theme_changes_nothing() {
        let mut buffer = Buffer::empty(Rect::new(0, 0, 2, 1));
        buffer.set_string(0, 0, "a", Style::new().fg(COLOR_SOFT_PURPLE));
        let before = buffer.clone();
        paint_with(&mut buffer, &Palette::DEFAULT);
        assert_eq!(buffer, before);
    }
}
