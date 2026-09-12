//! Themes that ship with OpenVTC.
//!
//! OpenVTC's own colours, a few widely used open palettes mapped onto OpenVTC's
//! roles, and four made for accessibility. The open palettes' colour values are
//! those they publish; their projects are credited by name.
//!
//! The accessibility themes:
//! - **High contrast**, dark and light: every role at least 7:1 against the
//!   background (WCAG AAA for body text).
//! - **Colourblind safe**, dark and light: roles in the hues of the Okabe–Ito
//!   palette, which stay distinct under the common colour-vision deficiencies.
//!   The dark theme uses Okabe–Ito's own colours; on white those are too pale to
//!   read, so the light theme darkens each hue until it reaches 4.5:1.

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
        theme(
            "high-contrast-dark",
            "High Contrast Dark",
            Mode::Dark,
            [
                0x00d7ff, 0x00ff87, 0xffd700, 0xff6b6b, 0xffffff, 0xc6c6c6, 0xff87ff, 0x000000,
            ],
        ),
        theme(
            "high-contrast-light",
            "High Contrast Light",
            Mode::Light,
            [
                0x0033b3, 0x005c1a, 0x8a4600, 0xb3001b, 0x000000, 0x3d3d3d, 0x7a1fa2, 0xffffff,
            ],
        ),
        // Okabe–Ito: sky blue, bluish green, yellow, vermillion, reddish purple.
        theme(
            "colourblind-dark",
            "Colourblind Safe Dark",
            Mode::Dark,
            [
                0x56b4e9, 0x009e73, 0xf0e442, 0xd55e00, 0xf0f0f0, 0xb0b0b0, 0xcc79a7, 0x101010,
            ],
        ),
        // Okabe–Ito's blue, then its bluish green, yellow, vermillion and
        // reddish purple darkened to read on white.
        theme(
            "colourblind-light",
            "Colourblind Safe Light",
            Mode::Light,
            [
                0x0072b2, 0x007a5a, 0x736b00, 0xb34e00, 0x000000, 0x595959, 0xa6497f, 0xffffff,
            ],
        ),
    ]
}

/// The ids of the themes made for accessibility, and the contrast every one
/// of their roles reaches against the background.
#[cfg(test)]
const ACCESSIBLE: [(&str, f64); 4] = [
    ("high-contrast-dark", 7.0),
    ("high-contrast-light", 7.0),
    ("colourblind-dark", 4.5),
    ("colourblind-light", 4.5),
];

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

    /// Every built-in theme's text reads on its background (4.5:1, WCAG AA),
    /// and the accessibility themes hold every role to their own bar. A theme
    /// drawn on the terminal's background is measured on black or white.
    #[test]
    fn text_is_readable_on_every_built_in_background() {
        use crate::theme::{Role, contrast, rgb};

        let roles = [
            Role::Accent,
            Role::Success,
            Role::Warning,
            Role::Danger,
            Role::Text,
            Role::Muted,
            Role::Highlight,
        ];
        let themes = all();
        for theme in &themes {
            let background = theme
                .palette
                .background
                .and_then(rgb)
                .unwrap_or(match theme.mode {
                    Mode::Dark => (0, 0, 0),
                    Mode::Light => (255, 255, 255),
                });
            let ratio = |role: Role| {
                let colour = rgb(theme.palette.get(role)).expect("a solid colour");
                contrast(colour, background)
            };
            assert!(
                ratio(Role::Text) >= 4.5,
                "{}: text is {:.2}:1 on its background",
                theme.id,
                ratio(Role::Text)
            );
            let bar = ACCESSIBLE
                .iter()
                .find_map(|(id, bar)| (*id == theme.id).then_some(*bar));
            if let Some(bar) = bar {
                for role in roles {
                    assert!(
                        ratio(role) >= bar,
                        "{}: {role:?} is {:.2}:1, under {bar}:1",
                        theme.id,
                        ratio(role)
                    );
                }
            }
        }
        for (id, _) in ACCESSIBLE {
            assert!(themes.iter().any(|t| t.id == id), "{id} is built in");
        }
    }

    #[test]
    fn hex_values_are_read_as_rgb() {
        assert_eq!(rgb(0x1e66f5), Color::Rgb(0x1e, 0x66, 0xf5));
    }
}
