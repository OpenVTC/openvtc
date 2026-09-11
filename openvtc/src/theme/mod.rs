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
//! - [`builtin`] — a handful of well-known open palettes, OpenVTC's own, and
//!   high-contrast and colourblind-safe ones;
//! - the user's themes directory — OpenVTC theme files, written by hand, copied
//!   from another theme, or produced by [`import`];
//! - Omarchy's themes, read in place, including whichever is current;
//! - [`import`] converts base16/base24 schemes, Omarchy themes, Alacritty and
//!   Kitty colour files, and [`nvim`] reads any colorscheme Neovim can load.
//!
//! [`catalog`] lists and loads all of them, remembers the one chosen, and
//! resolves `auto` with what [`terminal`] learns of the terminal's background.
//! [`live`] notices a theme changing while the TUI runs, and [`export`] writes a
//! theme out for other tools.
//!
//! With `NO_COLOR` set, [`paint`] draws in the terminal's own colours and keeps
//! the roles apart with bold, underline and the like instead.

pub mod builtin;
pub mod catalog;
pub mod export;
pub mod import;
pub mod live;
pub mod nvim;
pub mod terminal;

use std::sync::{OnceLock, PoisonError, RwLock};

use ratatui::buffer::Buffer;
use ratatui::style::{Color, Modifier};

use crate::colors::{
    CLI_CAUTION, COLOR_BORDER, COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS,
    COLOR_TEXT_DEFAULT, COLOR_WARNING_ACCESSIBLE_RED, Themed,
};
use catalog::Roots;

/// Environment variable that chooses a theme for one session, over `tui.toml`.
pub const OVERRIDE_ENV: &str = "OPENVTC_THEME";

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

    /// Light when `background` is; dark when it is dark or unknown.
    #[must_use]
    pub fn of_background(background: Option<Color>) -> Self {
        match background.and_then(rgb) {
            Some((r, g, b))
                if 0.2126 * f64::from(r) + 0.7152 * f64::from(g) + 0.0722 * f64::from(b)
                    > 140.0 =>
            {
                Mode::Light
            }
            _ => Mode::Dark,
        }
    }
}

/// One of the seven colour roles panels draw with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Accent,
    Success,
    Warning,
    Danger,
    Text,
    Muted,
    Highlight,
}

impl Role {
    /// The role OpenVTC's own colour `color` stands for, if it stands for one.
    #[must_use]
    fn of(color: Color) -> Option<Role> {
        [
            (COLOR_BORDER, Role::Accent),
            (COLOR_SUCCESS, Role::Success),
            (COLOR_ORANGE, Role::Warning),
            (COLOR_WARNING_ACCESSIBLE_RED, Role::Danger),
            (COLOR_TEXT_DEFAULT, Role::Text),
            (COLOR_DARK_GRAY, Role::Muted),
            (COLOR_SOFT_PURPLE, Role::Highlight),
        ]
        .into_iter()
        .find_map(|(own, role)| (own == color).then_some(role))
    }

    /// How the role stands apart when drawn without colour. Success is what
    /// selected rows are drawn in, so it is reversed, as a selection bar.
    #[must_use]
    fn without_colour(self) -> Modifier {
        match self {
            Role::Accent => Modifier::BOLD,
            Role::Success => Modifier::REVERSED,
            Role::Warning => Modifier::UNDERLINED,
            Role::Danger => Modifier::BOLD | Modifier::UNDERLINED,
            Role::Text => Modifier::empty(),
            Role::Muted => Modifier::DIM,
            Role::Highlight => Modifier::ITALIC,
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

    /// The colour `role` is drawn in.
    #[must_use]
    pub fn get(&self, role: Role) -> Color {
        match role {
            Role::Accent => self.accent,
            Role::Success => self.success,
            Role::Warning => self.warning,
            Role::Danger => self.danger,
            Role::Text => self.text,
            Role::Muted => self.muted,
            Role::Highlight => self.highlight,
        }
    }

    /// The colour role `color` stands for, or `color` itself when it is not a role.
    #[must_use]
    fn role(&self, color: Color) -> Color {
        Role::of(color).map_or(color, |role| self.get(role))
    }
}

/// A theme: a palette with a name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Theme {
    /// How [`catalog`] finds it again: `catppuccin-mocha`, `user/mine`,
    /// `omarchy/tokyo-night`, `omarchy/current`, `auto`.
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

/// The red, green and blue `color` is drawn in, taking named and indexed
/// colours as xterm draws them by default. `None` for `Reset`, which is
/// whatever the terminal's own colour is.
#[must_use]
pub fn rgb(color: Color) -> Option<(u8, u8, u8)> {
    const ANSI: [(u8, u8, u8); 16] = [
        (0, 0, 0),
        (205, 0, 0),
        (0, 205, 0),
        (205, 205, 0),
        (0, 0, 238),
        (205, 0, 205),
        (0, 205, 205),
        (229, 229, 229),
        (127, 127, 127),
        (255, 0, 0),
        (0, 255, 0),
        (255, 255, 0),
        (92, 92, 255),
        (255, 0, 255),
        (0, 255, 255),
        (255, 255, 255),
    ];
    let index = match color {
        Color::Reset => return None,
        Color::Rgb(r, g, b) => return Some((r, g, b)),
        Color::Indexed(n) => n,
        named => ansi_index(named)?,
    };
    Some(match index {
        0..=15 => ANSI[usize::from(index)],
        16..=231 => {
            let n = index - 16;
            let level = |v: u8| if v == 0 { 0 } else { 55 + v * 40 };
            (level(n / 36), level(n / 6 % 6), level(n % 6))
        }
        _ => {
            let grey = 8 + (index - 232) * 10;
            (grey, grey, grey)
        }
    })
}

/// The ANSI colour number (0–15) of a named colour.
#[must_use]
pub fn ansi_index(color: Color) -> Option<u8> {
    Some(match color {
        Color::Black => 0,
        Color::Red => 1,
        Color::Green => 2,
        Color::Yellow => 3,
        Color::Blue => 4,
        Color::Magenta => 5,
        Color::Cyan => 6,
        Color::Gray => 7,
        Color::DarkGray => 8,
        Color::LightRed => 9,
        Color::LightGreen => 10,
        Color::LightYellow => 11,
        Color::LightBlue => 12,
        Color::LightMagenta => 13,
        Color::LightCyan => 14,
        Color::White => 15,
        _ => return None,
    })
}

/// The WCAG contrast ratio of two colours: 1 for none, 21 for black on white.
/// Body text wants at least 4.5.
#[must_use]
pub fn contrast(a: (u8, u8, u8), b: (u8, u8, u8)) -> f64 {
    fn luminance((r, g, b): (u8, u8, u8)) -> f64 {
        let channel = |c: u8| {
            let c = f64::from(c) / 255.0;
            if c <= 0.040_45 {
                c / 12.92
            } else {
                ((c + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)
    }
    let (a, b) = (luminance(a), luminance(b));
    (a.max(b) + 0.05) / (a.min(b) + 0.05)
}

/// Whether to draw without colour: `NO_COLOR` is set and not empty
/// (<https://no-color.org>). Read once; it cannot change under a running TUI.
#[must_use]
pub fn no_color() -> bool {
    static NO_COLOR: OnceLock<bool> = OnceLock::new();
    *NO_COLOR.get_or_init(|| std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()))
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

/// How a theme is named on screen: `auto` shows the theme it picked.
#[must_use]
pub fn display_name(id: &str, name: &str) -> String {
    if id == catalog::AUTO_ID {
        format!("Auto — {name}")
    } else {
        name.to_string()
    }
}

/// Choose this process's theme, before anything is printed: the one
/// `OPENVTC_THEME` names, else the one chosen in `tui.toml`, else OpenVTC's
/// own. Returns the id of the theme in use, for [`live::Watcher`] to follow.
///
/// Under `auto` this asks the terminal for its background, so it must run
/// before the TUI takes the terminal over.
pub fn init(roots: &Roots) -> String {
    if no_color() {
        // Prompts and messages printed through `console` and `dialoguer` too.
        console::set_colors_enabled(false);
        console::set_colors_enabled_stderr(false);
    }
    let chosen = catalog::choice(roots).theme;
    let requested = std::env::var(OVERRIDE_ENV)
        .ok()
        .map(|id| id.trim().to_string())
        .filter(|id| !id.is_empty());
    if let Some(id) = requested {
        match load_for_session(roots, &id) {
            Ok(theme) => {
                set_active(&theme);
                return theme.id;
            }
            Err(e) => {
                let theme = load_or_default(roots, &chosen);
                set_active(&theme);
                eprintln!(
                    "{}",
                    console::style(format!(
                        "{OVERRIDE_ENV}={id} was ignored ({e:#}); using {}.",
                        display_name(&theme.id, &theme.name)
                    ))
                    .themed(CLI_CAUTION)
                );
                return theme.id;
            }
        }
    }
    let theme = load_or_default(roots, &chosen);
    set_active(&theme);
    theme.id
}

/// Load `id`, asking the terminal for its background first when `id` is `auto`.
fn load_for_session(roots: &Roots, id: &str) -> anyhow::Result<Theme> {
    if id == catalog::AUTO_ID && !no_color() {
        terminal::detect();
    }
    catalog::load(roots, id)
}

/// Theme `id`, or OpenVTC's own when it cannot be loaded.
fn load_or_default(roots: &Roots, id: &str) -> Theme {
    load_for_session(roots, id).unwrap_or_else(|e| {
        tracing::warn!(theme = %id, error = %e, "chosen theme could not be loaded; using the default");
        Theme::default_theme()
    })
}

/// Theme a finished frame: call at the end of every `Terminal::draw`.
pub fn paint(buffer: &mut Buffer) {
    if no_color() {
        paint_without_colour(buffer);
    } else {
        paint_with(buffer, &active_palette());
    }
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

/// [`paint`] for `NO_COLOR`: every colour becomes the terminal's own, and each
/// role keeps a modifier of its own so it still reads as that role. A role used
/// as a background marks a selection, so it is reversed.
pub fn paint_without_colour(buffer: &mut Buffer) {
    for cell in &mut buffer.content {
        if let Some(role) = Role::of(cell.fg) {
            cell.modifier |= role.without_colour();
        }
        if Role::of(cell.bg).is_some() {
            cell.modifier |= Modifier::REVERSED;
        }
        cell.fg = Color::Reset;
        cell.bg = Color::Reset;
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

    /// Without colour, nothing is coloured, and the roles stay apart.
    #[test]
    fn without_colour_roles_are_told_apart_by_modifiers() {
        let mut buffer = Buffer::empty(Rect::new(0, 0, 6, 1));
        buffer.set_string(0, 0, "a", Style::new().fg(COLOR_BORDER));
        buffer.set_string(1, 0, "d", Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED));
        buffer.set_string(2, 0, "m", Style::new().fg(COLOR_DARK_GRAY));
        buffer.set_string(
            3,
            0,
            "s",
            Style::new().fg(COLOR_TEXT_DEFAULT).bg(COLOR_BORDER),
        );
        buffer.set_string(4, 0, "x", Style::new().fg(Color::Rgb(1, 2, 3)).bold());
        paint_without_colour(&mut buffer);

        for x in 0..6 {
            assert_eq!(buffer[(x, 0)].fg, Color::Reset);
            assert_eq!(buffer[(x, 0)].bg, Color::Reset);
        }
        assert_eq!(buffer[(0, 0)].modifier, Modifier::BOLD);
        assert_eq!(
            buffer[(1, 0)].modifier,
            Modifier::BOLD | Modifier::UNDERLINED
        );
        assert_eq!(buffer[(2, 0)].modifier, Modifier::DIM);
        assert_eq!(buffer[(3, 0)].modifier, Modifier::REVERSED, "a selection");
        assert_eq!(
            buffer[(4, 0)].modifier,
            Modifier::BOLD,
            "a panel's own modifiers stay"
        );
        assert_eq!(buffer[(5, 0)].modifier, Modifier::empty());
    }

    #[test]
    fn named_and_indexed_colours_have_rgb() {
        assert_eq!(rgb(Color::White), Some((255, 255, 255)));
        assert_eq!(rgb(Color::Indexed(16)), Some((0, 0, 0)));
        assert_eq!(rgb(Color::Indexed(69)), Some((95, 135, 255)));
        assert_eq!(rgb(Color::Indexed(244)), Some((128, 128, 128)));
        assert_eq!(rgb(Color::Reset), None);
    }

    /// The figures WCAG publishes.
    #[test]
    fn contrast_is_measured_as_wcag_does() {
        assert!((contrast((0, 0, 0), (255, 255, 255)) - 21.0).abs() < 1e-9);
        assert!((contrast((255, 255, 255), (255, 255, 255)) - 1.0).abs() < 1e-9);
        let grey = contrast((0x76, 0x76, 0x76), (255, 255, 255));
        assert!((4.5..4.6).contains(&grey), "#767676 on white is 4.54:1");
    }

    #[test]
    fn a_background_sets_the_mode() {
        assert_eq!(
            Mode::of_background(Some(Color::Rgb(0xef, 0xf1, 0xf5))),
            Mode::Light
        );
        assert_eq!(
            Mode::of_background(Some(Color::Rgb(0x1a, 0x1b, 0x26))),
            Mode::Dark
        );
        assert_eq!(Mode::of_background(Some(Color::White)), Mode::Light);
        assert_eq!(Mode::of_background(None), Mode::Dark);
    }
}
