//! Writing a theme out for other tools, so a theme made in OpenVTC can colour
//! them too.
//!
//! Each format carries OpenVTC's seven roles and background where
//! [`super::import`] reads them back, so an exported theme imports as the same
//! theme. What else a format expects is derived from the roles:
//!
//! | Format            | Derived                                                                |
//! |-------------------|------------------------------------------------------------------------|
//! | base16            | `base01`/`base02`/`base04` blend background and text; `base06`/`base07` run past the text; `base0A` is the warning colour, `base0C` blends accent and success, `base0F` danger and warning |
//! | Omarchy           | the background and foreground shades, `selection`, `cyan`, `brown` and the `bright_*` colours |
//! | Alacritty, Kitty  | black and white from background and text, cyan, and the bright colours |
//!
//! A theme drawn on the terminal's own background is exported on black (dark)
//! or white (light), and named terminal colours as xterm draws them.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ratatui::style::Color;

use super::{Mode, Theme, import, rgb};

type Rgb = (u8, u8, u8);

const BLACK: Rgb = (0, 0, 0);
const WHITE: Rgb = (255, 255, 255);

/// A format a theme can be written in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// An OpenVTC theme file.
    Openvtc,
    /// A base16 scheme (YAML).
    Base16,
    /// An Omarchy `colors.toml`, or a theme directory holding one.
    Omarchy,
    /// An Alacritty colour file (TOML).
    Alacritty,
    /// A Kitty colour file.
    Kitty,
}

impl Format {
    /// Every format's name, as `--format` takes it.
    pub const NAMES: [&'static str; 5] = ["openvtc", "base16", "omarchy", "alacritty", "kitty"];

    /// The format named `name`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "openvtc" => Format::Openvtc,
            "base16" => Format::Base16,
            "omarchy" => Format::Omarchy,
            "alacritty" => Format::Alacritty,
            "kitty" => Format::Kitty,
            _ => return None,
        })
    }
}

/// `theme` in `format`.
#[must_use]
pub fn render(theme: &Theme, format: Format) -> String {
    match format {
        Format::Openvtc => import::to_toml(theme),
        Format::Base16 => base16(theme),
        Format::Omarchy => omarchy(theme),
        Format::Alacritty => alacritty(theme),
        Format::Kitty => kitty(theme),
    }
}

/// Write `theme` to `output` in `format`, and return the file written.
///
/// An Omarchy export to a path not ending in `.toml` makes a theme directory
/// Omarchy can use: `colors.toml`, and `light.mode` for a light theme.
///
/// # Errors
///
/// A path that cannot be written.
pub fn write(theme: &Theme, format: Format, output: &Path) -> Result<PathBuf> {
    let file = if format == Format::Omarchy && output.extension().is_none_or(|e| e != "toml") {
        fs::create_dir_all(output)
            .with_context(|| format!("could not create {}", output.display()))?;
        let light = output.join("light.mode");
        match theme.mode {
            Mode::Light => fs::write(&light, "")?,
            Mode::Dark if light.exists() => fs::remove_file(&light)?,
            Mode::Dark => {}
        }
        output.join("colors.toml")
    } else {
        if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)
                .with_context(|| format!("could not create {}", parent.display()))?;
        }
        output.to_path_buf()
    };
    fs::write(&file, render(theme, format))
        .with_context(|| format!("could not write {}", file.display()))?;
    Ok(file)
}

/// A theme's colours, every one of them a definite colour.
struct Solid {
    name: String,
    mode: Mode,
    background: Rgb,
    text: Rgb,
    muted: Rgb,
    accent: Rgb,
    success: Rgb,
    warning: Rgb,
    danger: Rgb,
    highlight: Rgb,
}

impl Solid {
    fn of(theme: &Theme) -> Self {
        let p = &theme.palette;
        let (dark, light) = match theme.mode {
            Mode::Dark => (BLACK, WHITE),
            Mode::Light => (WHITE, BLACK),
        };
        let text = rgb(p.text).unwrap_or(light);
        let solid = |color: Color| rgb(color).unwrap_or(text);
        Solid {
            // Names end up inside quotes and comments.
            name: theme
                .name
                .chars()
                .map(|c| match c {
                    '"' | '\\' => '\'',
                    c if c.is_control() => ' ',
                    c => c,
                })
                .collect(),
            mode: theme.mode,
            background: p.background.and_then(rgb).unwrap_or(dark),
            text,
            muted: solid(p.muted),
            accent: solid(p.accent),
            success: solid(p.success),
            warning: solid(p.warning),
            danger: solid(p.danger),
            highlight: solid(p.highlight),
        }
    }

    /// From the background toward the text, by `t`.
    fn shade(&self, t: f64) -> Rgb {
        mix(self.background, self.text, t)
    }

    /// Past the text, further from the background, by `t`.
    fn beyond_text(&self, t: f64) -> Rgb {
        let far = match self.mode {
            Mode::Dark => WHITE,
            Mode::Light => BLACK,
        };
        mix(self.text, far, t)
    }

    fn cyan(&self) -> Rgb {
        mix(self.accent, self.success, 0.5)
    }

    fn selection(&self) -> Rgb {
        mix(self.background, self.accent, 0.3)
    }

    /// A colour's bright variant: a step toward the text.
    fn bright(&self, color: Rgb) -> Rgb {
        mix(color, self.text, 0.25)
    }

    /// The sixteen terminal colours, black to bright white.
    fn ansi(&self) -> [Rgb; 16] {
        let (black, white, bright_white) = match self.mode {
            Mode::Dark => (self.shade(0.15), self.text, self.beyond_text(0.5)),
            Mode::Light => (
                self.text,
                self.shade(0.15),
                mix(self.background, WHITE, 0.5),
            ),
        };
        let cyan = self.cyan();
        [
            black,
            self.danger,
            self.success,
            self.warning,
            self.accent,
            self.highlight,
            cyan,
            white,
            self.muted,
            self.bright(self.danger),
            self.bright(self.success),
            self.bright(self.warning),
            self.bright(self.accent),
            self.bright(self.highlight),
            self.bright(cyan),
            bright_white,
        ]
    }

    fn header(&self) -> String {
        format!("# {}, exported from OpenVTC\n", self.name)
    }
}

fn mix(from: Rgb, to: Rgb, t: f64) -> Rgb {
    let channel = |a: u8, b: u8| {
        (f64::from(a) + (f64::from(b) - f64::from(a)) * t)
            .round()
            .clamp(0.0, 255.0) as u8
    };
    (
        channel(from.0, to.0),
        channel(from.1, to.1),
        channel(from.2, to.2),
    )
}

fn hex((r, g, b): Rgb) -> String {
    format!("#{r:02x}{g:02x}{b:02x}")
}

fn base16(theme: &Theme) -> String {
    let c = Solid::of(theme);
    let colours = [
        c.background,
        c.shade(0.08),
        c.shade(0.16),
        c.muted,
        mix(c.muted, c.text, 0.5),
        c.text,
        c.beyond_text(0.35),
        c.beyond_text(0.7),
        c.danger,
        c.warning,
        c.warning,
        c.success,
        c.cyan(),
        c.accent,
        c.highlight,
        mix(c.danger, c.warning, 0.5),
    ];
    let mut out = c.header();
    out.push_str(&format!(
        "system: \"base16\"\nname: \"{}\"\nauthor: \"OpenVTC\"\nvariant: \"{}\"\npalette:\n",
        c.name,
        c.mode.as_str()
    ));
    for (i, colour) in colours.iter().enumerate() {
        out.push_str(&format!("  base{i:02X}: \"{}\"\n", hex(*colour)));
    }
    out
}

fn omarchy(theme: &Theme) -> String {
    let c = Solid::of(theme);
    let cyan = c.cyan();
    let groups: [&[(&str, Rgb)]; 5] = [
        &[
            ("accent", c.accent),
            ("selection", c.selection()),
            ("muted", c.muted),
        ],
        &[
            ("background", c.background),
            ("dark_background", mix(c.background, BLACK, 0.25)),
            ("darker_background", mix(c.background, BLACK, 0.45)),
            ("lighter_background", mix(c.background, WHITE, 0.08)),
        ],
        &[
            ("foreground", c.text),
            ("dark_foreground", c.muted),
            ("light_foreground", c.beyond_text(0.2)),
            ("bright_foreground", c.beyond_text(0.4)),
        ],
        &[
            ("red", c.danger),
            ("yellow", c.warning),
            ("orange", c.warning),
            ("green", c.success),
            ("cyan", cyan),
            ("blue", c.accent),
            ("magenta", c.highlight),
            ("brown", mix(c.danger, c.background, 0.45)),
        ],
        &[
            ("bright_red", c.bright(c.danger)),
            ("bright_yellow", c.bright(c.warning)),
            ("bright_green", c.bright(c.success)),
            ("bright_cyan", c.bright(cyan)),
            ("bright_blue", c.bright(c.accent)),
            ("bright_magenta", c.bright(c.highlight)),
        ],
    ];
    let mut out = c.header();
    out.push_str(&format!("mode = \"{}\"\n", c.mode.as_str()));
    for group in groups {
        out.push('\n');
        for (key, colour) in group {
            out.push_str(&format!("{key} = \"{}\"\n", hex(*colour)));
        }
    }
    out
}

const ANSI_NAMES: [&str; 8] = [
    "black", "red", "green", "yellow", "blue", "magenta", "cyan", "white",
];

fn alacritty(theme: &Theme) -> String {
    let c = Solid::of(theme);
    let ansi = c.ansi();
    let mut out = c.header();
    out.push_str(&format!(
        "\n[colors.primary]\nbackground = \"{}\"\nforeground = \"{}\"\n\
         \n[colors.cursor]\ntext = \"{}\"\ncursor = \"{}\"\n\
         \n[colors.selection]\ntext = \"{}\"\nbackground = \"{}\"\n",
        hex(c.background),
        hex(c.text),
        hex(c.background),
        hex(c.accent),
        hex(c.text),
        hex(c.selection()),
    ));
    for (table, colours) in [("normal", &ansi[..8]), ("bright", &ansi[8..])] {
        out.push_str(&format!("\n[colors.{table}]\n"));
        for (name, colour) in ANSI_NAMES.iter().zip(colours) {
            out.push_str(&format!("{name} = \"{}\"\n", hex(*colour)));
        }
    }
    out
}

fn kitty(theme: &Theme) -> String {
    let c = Solid::of(theme);
    let mut out = c.header();
    for (key, colour) in [
        ("foreground", c.text),
        ("background", c.background),
        ("selection_foreground", c.text),
        ("selection_background", c.selection()),
        ("cursor", c.accent),
        ("cursor_text_color", c.background),
        ("url_color", c.accent),
        ("active_border_color", c.accent),
        ("inactive_border_color", c.muted),
    ] {
        out.push_str(&format!("{key} {}\n", hex(colour)));
    }
    for (n, colour) in c.ansi().iter().enumerate() {
        out.push_str(&format!("color{n} {}\n", hex(*colour)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme::builtin;

    fn same(exported: &Theme, back: &Theme, format: &str) {
        assert_eq!(
            back.palette, exported.palette,
            "{} through {format}",
            exported.id
        );
        assert_eq!(back.mode, exported.mode, "{} through {format}", exported.id);
    }

    /// Every built-in theme written out in every format imports as itself.
    #[test]
    fn every_format_reads_back_as_the_same_theme() {
        for theme in builtin::all()
            .into_iter()
            .filter(|t| t.palette.background.is_some())
        {
            let back = import::from_toml(&render(&theme, Format::Openvtc), "x").unwrap();
            same(&theme, &back, "openvtc");
            assert_eq!(back.name, theme.name);

            let back = import::from_base16(&render(&theme, Format::Base16), "x").unwrap();
            same(&theme, &back, "base16");
            assert_eq!(back.name, theme.name);

            let text = render(&theme, Format::Omarchy);
            same(
                &theme,
                &import::from_omarchy_colors(&text, "x", None).unwrap(),
                "omarchy",
            );
            let text = render(&theme, Format::Alacritty);
            same(
                &theme,
                &import::from_alacritty(&text, "x", None).unwrap(),
                "alacritty",
            );
            let text = render(&theme, Format::Kitty);
            same(
                &theme,
                &import::from_kitty(&text, "x", None).unwrap(),
                "kitty",
            );
        }
    }

    /// Written to disk, each export is recognised by what it is, and an
    /// Omarchy export is a theme directory Omarchy — and OpenVTC — can read.
    #[test]
    fn exports_written_to_disk_are_recognised() {
        let dir = std::env::temp_dir().join(format!("openvtc-export-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let latte = builtin::find("catppuccin-latte").unwrap();
        for (format, name) in [
            (Format::Openvtc, "latte.toml"),
            (Format::Base16, "latte.yaml"),
            (Format::Alacritty, "alacritty.toml"),
            (Format::Kitty, "latte.conf"),
            (Format::Omarchy, "latte-export"),
        ] {
            let file = write(&latte, format, &dir.join(name)).unwrap();
            let back = import::from_path(&dir.join(name)).unwrap();
            same(&latte, &back, name);
            assert!(file.is_file());
        }
        let omarchy = dir.join("latte-export");
        assert!(omarchy.join("colors.toml").is_file());
        assert!(omarchy.join("light.mode").is_file());
        assert_eq!(import::from_path(&omarchy).unwrap().name, "Latte Export");

        // Exporting a dark theme over it leaves no light.mode behind.
        let nord = builtin::find("nord").unwrap();
        write(&nord, Format::Omarchy, &omarchy).unwrap();
        assert!(!omarchy.join("light.mode").exists());
        assert_eq!(import::from_path(&omarchy).unwrap().mode, Mode::Dark);
        let _ = fs::remove_dir_all(&dir);
    }

    /// OpenVTC's own theme names terminal colours and has no background; it is
    /// exported in the colours xterm draws, on black.
    #[test]
    fn a_theme_on_the_terminals_background_exports_on_black() {
        let theme = Theme::default_theme();
        let back = import::from_base16(&render(&theme, Format::Base16), "x").unwrap();
        assert_eq!(back.palette.background, Some(Color::Rgb(0, 0, 0)));
        assert_eq!(back.palette.text, Color::Rgb(255, 255, 255));
        assert_eq!(back.palette.accent, theme.palette.accent);
    }

    #[test]
    fn format_names_parse() {
        for name in Format::NAMES {
            assert!(Format::parse(name).is_some(), "{name}");
        }
        assert_eq!(Format::parse("vim"), None);
    }
}
