//! Themes that ship with OpenVTC.
//!
//! OpenVTC's own colours, and a few widely used open palettes mapped onto
//! OpenVTC's roles. The colour values are those the palettes publish; their
//! projects are credited by name.

use ratatui::style::Color;

use super::{Mode, Palette, Theme};

/// The id of OpenVTC's own theme.
pub const DEFAULT_ID: &str = "openvtc";

const fn rgb(hex: u32) -> Color {
    Color::Rgb((hex >> 16) as u8, (hex >> 8) as u8, hex as u8)
}

#[allow(clippy::too_many_arguments)]
fn theme(
    id: &str,
    name: &str,
    mode: Mode,
    [
        accent,
        success,
        warning,
        danger,
        text,
        muted,
        highlight,
        background,
    ]: [u32; 8],
) -> Theme {
    Theme {
        id: id.to_string(),
        name: name.to_string(),
        mode,
        palette: Palette {
            accent: rgb(accent),
            success: rgb(success),
            warning: rgb(warning),
            danger: rgb(danger),
            text: rgb(text),
            muted: rgb(muted),
            highlight: rgb(highlight),
            background: Some(rgb(background)),
        },
    }
}

/// Every built-in theme, OpenVTC's own first.
#[must_use]
pub fn all() -> Vec<Theme> {
    //                       accent    success   warning   danger    text      muted     highlight background
    vec![
        Theme::default_theme(),
        theme(
            "catppuccin-mocha",
            "Catppuccin Mocha",
            Mode::Dark,
            [
                0x89b4fa, 0xa6e3a1, 0xfab387, 0xf38ba8, 0xcdd6f4, 0x7f849c, 0xcba6f7, 0x1e1e2e,
            ],
        ),
        theme(
            "catppuccin-latte",
            "Catppuccin Latte",
            Mode::Light,
            [
                0x1e66f5, 0x40a02b, 0xfe640b, 0xd20f39, 0x4c4f69, 0x8c8fa1, 0x8839ef, 0xeff1f5,
            ],
        ),
        theme(
            "dracula",
            "Dracula",
            Mode::Dark,
            [
                0xbd93f9, 0x50fa7b, 0xffb86c, 0xff5555, 0xf8f8f2, 0x6272a4, 0xff79c6, 0x282a36,
            ],
        ),
        theme(
            "gruvbox-dark",
            "Gruvbox Dark",
            Mode::Dark,
            [
                0x83a598, 0xb8bb26, 0xfe8019, 0xfb4934, 0xebdbb2, 0x928374, 0xd3869b, 0x282828,
            ],
        ),
        theme(
            "nord",
            "Nord",
            Mode::Dark,
            [
                0x88c0d0, 0xa3be8c, 0xd08770, 0xbf616a, 0xd8dee9, 0x616e88, 0xb48ead, 0x2e3440,
            ],
        ),
        theme(
            "tokyo-night",
            "Tokyo Night",
            Mode::Dark,
            [
                0x7aa2f7, 0x9ece6a, 0xff9e64, 0xf7768e, 0xc0caf5, 0x565f89, 0xbb9af7, 0x1a1b26,
            ],
        ),
    ]
}

/// The built-in theme with `id`.
#[must_use]
pub fn find(id: &str) -> Option<Theme> {
    all().into_iter().find(|t| t.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_the_default_comes_first() {
        let themes = all();
        assert_eq!(themes[0].id, DEFAULT_ID);
        let mut ids: Vec<_> = themes.iter().map(|t| t.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), themes.len());
    }

    #[test]
    fn hex_values_are_read_as_rgb() {
        assert_eq!(rgb(0x1e66f5), Color::Rgb(0x1e, 0x66, 0xf5));
    }
}
