//! Reading other tools' themes, and reading and writing OpenVTC's own.
//!
//! Each format is mapped onto OpenVTC's seven roles. A role a format does not
//! define keeps OpenVTC's own colour, so a theme file may be as short as it
//! likes.
//!
//! | Role      | OpenVTC `[colors]` | base16/base24 | Omarchy `colors.toml` | Alacritty / Kitty / Ghostty |
//! |-----------|--------------------|---------------|-----------------------|-----------------------------|
//! | accent    | `accent`           | `base0D`      | `accent`, else `blue` | blue (4)                    |
//! | success   | `success`          | `base0B`      | `green`               | green (2)                   |
//! | warning   | `warning`          | `base09`      | `yellow`, else `orange` | yellow (3)                |
//! | danger    | `danger`           | `base08`      | `red`                 | red (1)                     |
//! | text      | `text`             | `base05`      | `foreground`          | foreground                  |
//! | muted     | `muted`            | `base03`      | `dark_foreground`     | bright black (8)            |
//! | highlight | `highlight`        | `base0E`      | `magenta`             | magenta (5)                 |
//! | background| `background`       | `base00`      | `background`          | background                  |

use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result, anyhow, bail};
use ratatui::style::Color;

use super::{Mode, Palette, Theme};

/// A colour as theme files write them: `#rgb`, `#rrggbb`, `rrggbb`,
/// `0xrrggbb`, `#rrggbbaa` (alpha ignored), or a terminal colour name
/// (`white`, `darkgray`).
#[must_use]
pub fn parse_color(value: &str) -> Option<Color> {
    let value = value.trim().trim_matches(|c| c == '"' || c == '\'');
    let digits = value
        .strip_prefix('#')
        .or_else(|| value.strip_prefix("0x"))
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if digits.chars().all(|c| c.is_ascii_hexdigit()) {
        let six = match digits.len() {
            3 => digits.chars().flat_map(|c| [c, c]).collect(),
            6 => digits.to_string(),
            8 => digits[..6].to_string(),
            _ => String::new(),
        };
        if let Ok(n) = u32::from_str_radix(&six, 16) {
            return Some(Color::Rgb((n >> 16) as u8, (n >> 8) as u8, n as u8));
        }
    }
    // Only a bare word may be a name: `#zzz` is a broken hex, not a colour.
    if value.starts_with('#') || value.is_empty() {
        return None;
    }
    Color::from_str(value).ok()
}

/// A name as a theme id segment: lowercase letters, digits and dashes.
#[must_use]
pub fn slug(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
    }
    let out = out.trim_end_matches('-').to_string();
    if out.is_empty() {
        "theme".to_string()
    } else {
        out
    }
}

/// A directory name as a display name: `tokyo-night` → `Tokyo Night`.
#[must_use]
pub fn title(name: &str) -> String {
    name.split(['-', '_', ' '])
        .filter(|w| !w.is_empty())
        .map(|w| {
            let mut chars = w.chars();
            chars.next().map_or_else(String::new, |first| {
                first.to_uppercase().chain(chars).collect()
            })
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Roles as a format supplies them; missing ones keep OpenVTC's colour.
#[derive(Default)]
struct Roles {
    accent: Option<Color>,
    success: Option<Color>,
    warning: Option<Color>,
    danger: Option<Color>,
    text: Option<Color>,
    muted: Option<Color>,
    highlight: Option<Color>,
    background: Option<Color>,
}

impl Roles {
    fn is_empty(&self) -> bool {
        [
            self.accent,
            self.success,
            self.warning,
            self.danger,
            self.text,
            self.muted,
            self.highlight,
            self.background,
        ]
        .iter()
        .all(Option::is_none)
    }

    fn theme(self, name: &str, mode: Option<Mode>) -> Result<Theme> {
        if self.is_empty() {
            bail!("no colours found");
        }
        let mode = mode.unwrap_or_else(|| Mode::of_background(self.background));
        let default = Palette::DEFAULT;
        // Text a theme did not set must still be readable on the background it did.
        let text = self.text.unwrap_or(match (self.background, mode) {
            (Some(_), Mode::Light) => Color::Black,
            _ => default.text,
        });
        Ok(Theme {
            id: slug(name),
            name: name.trim().to_string(),
            mode,
            palette: Palette {
                accent: self.accent.unwrap_or(default.accent),
                success: self.success.unwrap_or(default.success),
                warning: self.warning.unwrap_or(default.warning),
                danger: self.danger.unwrap_or(default.danger),
                text,
                muted: self.muted.unwrap_or(default.muted),
                highlight: self.highlight.unwrap_or(default.highlight),
                background: self.background,
            },
        })
    }
}

fn color_at(table: &toml::Table, key: &str) -> Result<Option<Color>> {
    match table.get(key) {
        None => Ok(None),
        Some(toml::Value::String(s)) => parse_color(s)
            .map(Some)
            .ok_or_else(|| anyhow!("`{key}` is not a colour: {s}")),
        Some(other) => bail!(
            "`{key}` should be a colour string, not {}",
            other.type_str()
        ),
    }
}

fn sub_table<'a>(table: &'a toml::Table, key: &str) -> Option<&'a toml::Table> {
    table.get(key).and_then(toml::Value::as_table)
}

// ----------------------------------------------------------------------------
// OpenVTC's own format
// ----------------------------------------------------------------------------

/// Whether TOML text is an OpenVTC theme: a `[colors]` table naming roles.
fn is_native(table: &toml::Table) -> bool {
    sub_table(table, "colors").is_some_and(|c| {
        [
            "accent",
            "success",
            "warning",
            "danger",
            "text",
            "muted",
            "highlight",
        ]
        .iter()
        .any(|k| c.contains_key(*k))
    })
}

/// An OpenVTC theme file. `fallback_name` names it when the file does not.
///
/// # Errors
///
/// Text that is not TOML, has no `[colors]`, or holds something other than a
/// colour.
pub fn from_toml(text: &str, fallback_name: &str) -> Result<Theme> {
    let table: toml::Table = toml::from_str(text).context("not valid TOML")?;
    let colors = sub_table(&table, "colors").ok_or_else(|| anyhow!("no [colors] table"))?;
    let name = table
        .get("name")
        .and_then(toml::Value::as_str)
        .unwrap_or(fallback_name);
    let mode = table
        .get("mode")
        .and_then(toml::Value::as_str)
        .map(Mode::parse);
    let background = match colors.get("background").and_then(toml::Value::as_str) {
        Some(s) if ["none", "terminal"].contains(&s.trim().to_ascii_lowercase().as_str()) => None,
        _ => color_at(colors, "background")?,
    };
    let roles = Roles {
        accent: color_at(colors, "accent")?,
        success: color_at(colors, "success")?,
        warning: color_at(colors, "warning")?,
        danger: color_at(colors, "danger")?,
        text: color_at(colors, "text")?,
        muted: color_at(colors, "muted")?,
        highlight: color_at(colors, "highlight")?,
        background,
    };
    roles.theme(name, mode)
}

/// `theme` as an OpenVTC theme file, commented so it can be edited by hand.
#[must_use]
pub fn to_toml(theme: &Theme) -> String {
    let p = &theme.palette;
    let name = toml::Value::String(theme.name.clone()).to_string();
    let line = |key: &str, color: Color, what: &str| {
        format!("{key:<10} = {:<10} # {what}\n", format!("\"{color}\""))
    };
    let mut out = String::from(
        "# An OpenVTC theme. Edit any colour, save, and pick it under Settings → Theme\n\
         # (press r there to reload after an edit). Colours are #rrggbb or a terminal\n\
         # colour name. A role left out keeps OpenVTC's own colour.\n\n",
    );
    out.push_str(&format!(
        "name = {name}\nmode = \"{}\"\n\n[colors]\n",
        theme.mode.as_str()
    ));
    out.push_str(&line("accent", p.accent, "borders, headings and key hints"));
    out.push_str(&line(
        "success",
        p.success,
        "selection, completed and valid things",
    ));
    out.push_str(&line("warning", p.warning, "cautions and work in progress"));
    out.push_str(&line("danger", p.danger, "errors and destructive actions"));
    out.push_str(&line("text", p.text, "ordinary text"));
    out.push_str(&line("muted", p.muted, "secondary text and hints"));
    out.push_str(&line(
        "highlight",
        p.highlight,
        "values and special actions",
    ));
    match p.background {
        Some(background) => out.push_str(&line(
            "background",
            background,
            "\"none\" keeps your terminal's own",
        )),
        None => {
            out.push_str("background = \"none\"     # or a colour, painted behind everything\n")
        }
    }
    out
}

// ----------------------------------------------------------------------------
// base16 / base24 schemes (tinted-theming)
// ----------------------------------------------------------------------------

/// A base16 or base24 scheme, in the current (`palette:`) or legacy (flat)
/// YAML layout. Only the flat `key: value` lines schemes use are read.
///
/// # Errors
///
/// A scheme missing the base colours.
pub fn from_base16(text: &str, fallback_name: &str) -> Result<Theme> {
    let mut values: HashMap<String, String> = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().trim_matches('"').to_ascii_lowercase();
        let value = value.trim();
        let value = if let Some(quoted) = value.strip_prefix('"') {
            quoted.split('"').next().unwrap_or_default()
        } else if let Some(quoted) = value.strip_prefix('\'') {
            quoted.split('\'').next().unwrap_or_default()
        } else {
            value.split_whitespace().next().unwrap_or_default()
        };
        values.insert(key, value.to_string());
    }
    let color = |key: &str| values.get(key).and_then(|v| parse_color(v));
    for required in ["base00", "base05", "base08", "base0b", "base0d"] {
        if color(required).is_none() {
            bail!("not a base16 scheme: no `{required}`");
        }
    }
    let name = values
        .get("name")
        .or_else(|| values.get("scheme"))
        .map_or(fallback_name, String::as_str);
    let mode = values.get("variant").map(|v| Mode::parse(v));
    Roles {
        accent: color("base0d"),
        success: color("base0b"),
        warning: color("base09"),
        danger: color("base08"),
        text: color("base05"),
        muted: color("base03"),
        highlight: color("base0e"),
        background: color("base00"),
    }
    .theme(name, mode)
}

// ----------------------------------------------------------------------------
// Omarchy
// ----------------------------------------------------------------------------

/// An Omarchy theme's `colors.toml`.
///
/// # Errors
///
/// Text that is not TOML, or holds no colours.
pub fn from_omarchy_colors(text: &str, name: &str, mode: Option<Mode>) -> Result<Theme> {
    let table: toml::Table = toml::from_str(text).context("not valid TOML")?;
    let mode = mode.or_else(|| {
        table
            .get("mode")
            .and_then(toml::Value::as_str)
            .map(Mode::parse)
    });
    let either = |a: &str, b: &str| -> Result<Option<Color>> {
        Ok(color_at(&table, a)?.or(color_at(&table, b)?))
    };
    Roles {
        accent: either("accent", "blue")?,
        success: color_at(&table, "green")?,
        warning: either("yellow", "orange")?,
        danger: color_at(&table, "red")?,
        text: either("foreground", "bright_foreground")?,
        muted: either("dark_foreground", "muted")?,
        highlight: either("magenta", "bright_magenta")?,
        background: color_at(&table, "background")?,
    }
    .theme(name, mode)
}

// ----------------------------------------------------------------------------
// Terminal colour files
// ----------------------------------------------------------------------------

/// An Alacritty colour file (TOML): `[colors.primary]`, `[colors.normal]`,
/// `[colors.bright]`.
///
/// # Errors
///
/// Text that is not TOML, or has no `[colors]`.
pub fn from_alacritty(text: &str, name: &str, mode: Option<Mode>) -> Result<Theme> {
    let table: toml::Table = toml::from_str(text).context("not valid TOML")?;
    let colors = sub_table(&table, "colors").ok_or_else(|| anyhow!("no [colors] table"))?;
    let empty = toml::Table::new();
    let primary = sub_table(colors, "primary").unwrap_or(&empty);
    let normal = sub_table(colors, "normal").unwrap_or(&empty);
    let bright = sub_table(colors, "bright").unwrap_or(&empty);
    Roles {
        accent: color_at(normal, "blue")?,
        success: color_at(normal, "green")?,
        warning: color_at(normal, "yellow")?,
        danger: color_at(normal, "red")?,
        text: color_at(primary, "foreground")?,
        muted: color_at(bright, "black")?,
        highlight: color_at(normal, "magenta")?,
        background: color_at(primary, "background")?,
    }
    .theme(name, mode)
}

/// ANSI palette entries and the primary colours, however a format names them.
#[derive(Default)]
struct Terminal {
    palette: HashMap<u8, Color>,
    foreground: Option<Color>,
    background: Option<Color>,
}

impl Terminal {
    fn theme(self, name: &str, mode: Option<Mode>) -> Result<Theme> {
        let ansi = |n: u8| self.palette.get(&n).copied();
        Roles {
            accent: ansi(4),
            success: ansi(2),
            warning: ansi(3),
            danger: ansi(1),
            text: self.foreground,
            muted: ansi(8),
            highlight: ansi(5),
            background: self.background,
        }
        .theme(name, mode)
    }
}

/// A Kitty colour file: `foreground #…`, `background #…`, `color0 #…`.
///
/// # Errors
///
/// A file with no colours.
pub fn from_kitty(text: &str, name: &str, mode: Option<Mode>) -> Result<Theme> {
    let mut terminal = Terminal::default();
    for line in text.lines().map(str::trim).filter(|l| !l.starts_with('#')) {
        let mut parts = line.split_whitespace();
        let (Some(key), Some(value)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Some(color) = parse_color(value) else {
            continue;
        };
        match key {
            "foreground" => terminal.foreground = Some(color),
            "background" => terminal.background = Some(color),
            _ => {
                if let Some(n) = key.strip_prefix("color").and_then(|n| n.parse().ok()) {
                    terminal.palette.insert(n, color);
                }
            }
        }
    }
    terminal.theme(name, mode)
}

/// A Ghostty theme: `palette = 1=#…`, `foreground = #…`, `background = #…`.
///
/// # Errors
///
/// A file with no colours.
pub fn from_ghostty(text: &str, name: &str, mode: Option<Mode>) -> Result<Theme> {
    let mut terminal = Terminal::default();
    for line in text.lines().map(str::trim).filter(|l| !l.starts_with('#')) {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim() {
            "foreground" => terminal.foreground = parse_color(value),
            "background" => terminal.background = parse_color(value),
            "palette" => {
                if let Some((n, color)) = value.split_once('=')
                    && let (Ok(n), Some(color)) = (n.trim().parse(), parse_color(color))
                {
                    terminal.palette.insert(n, color);
                }
            }
            _ => {}
        }
    }
    terminal.theme(name, mode)
}

// ----------------------------------------------------------------------------
// Whatever is at a path
// ----------------------------------------------------------------------------

/// Read a theme from `path`: an Omarchy theme directory, a base16/base24 YAML
/// scheme, an OpenVTC or Alacritty TOML file, or a Kitty or Ghostty colour
/// file.
///
/// # Errors
///
/// A path that cannot be read, or holds nothing recognisable.
pub fn from_path(path: &Path) -> Result<Theme> {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .map_or_else(|| "Imported".to_string(), title);
    if path.is_dir() {
        return from_theme_dir(path, &stem);
    }
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("could not read {}", path.display()))?;
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let result = match ext.as_str() {
        "yaml" | "yml" => from_base16(&text, &stem),
        "toml" => {
            let table: toml::Table = toml::from_str(&text).context("not valid TOML")?;
            if is_native(&table) {
                from_toml(&text, &stem)
            } else if sub_table(&table, "colors").is_some_and(|c| c.contains_key("primary")) {
                from_alacritty(&text, &stem, None)
            } else if table.contains_key("foreground") || table.contains_key("accent") {
                from_omarchy_colors(&text, &stem, None)
            } else {
                bail!("a TOML file, but not an OpenVTC, Omarchy or Alacritty theme")
            }
        }
        _ if text.lines().any(|l| l.trim_start().starts_with("palette")) => {
            from_ghostty(&text, &stem, None)
        }
        _ => from_kitty(&text, &stem, None),
    };
    result.with_context(|| format!("could not read a theme from {}", path.display()))
}

/// An Omarchy theme directory: `colors.toml`, or the `alacritty.toml` older
/// themes carry instead, with `light.mode` marking a light theme.
fn from_theme_dir(dir: &Path, name: &str) -> Result<Theme> {
    let mode = dir.join("light.mode").exists().then_some(Mode::Light);
    let read = |file: &str| std::fs::read_to_string(dir.join(file));
    if let Ok(text) = read("colors.toml") {
        return from_omarchy_colors(&text, name, mode)
            .with_context(|| format!("could not read {}/colors.toml", dir.display()));
    }
    if let Ok(text) = read("alacritty.toml") {
        return from_alacritty(&text, name, mode)
            .with_context(|| format!("could not read {}/alacritty.toml", dir.display()));
    }
    if let Ok(text) = read("kitty.conf") {
        return from_kitty(&text, name, mode);
    }
    bail!(
        "{} has no colors.toml, alacritty.toml or kitty.conf",
        dir.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colours_are_read_in_every_form_files_use() {
        let blue = Some(Color::Rgb(0x7a, 0xa2, 0xf7));
        assert_eq!(parse_color("#7aa2f7"), blue);
        assert_eq!(parse_color("\"7aa2f7\""), blue);
        assert_eq!(parse_color("0x7aa2f7"), blue);
        assert_eq!(parse_color("#7aa2f7ff"), blue);
        assert_eq!(parse_color("#fff"), Some(Color::Rgb(255, 255, 255)));
        assert_eq!(parse_color("white"), Some(Color::White));
        assert_eq!(parse_color("#zzz"), None);
        assert_eq!(parse_color(""), None);
    }

    #[test]
    fn names_become_ids_and_titles() {
        assert_eq!(slug("Tokyo Night (Storm)"), "tokyo-night-storm");
        assert_eq!(slug("…"), "theme");
        assert_eq!(title("tokyo-night"), "Tokyo Night");
    }

    /// A theme written out reads back the same, so "copy and edit" starts from
    /// exactly what was on screen.
    #[test]
    fn an_openvtc_theme_round_trips() {
        let theme = crate::theme::builtin::find("catppuccin-latte").unwrap();
        let back = from_toml(&to_toml(&theme), "x").unwrap();
        assert_eq!(back.name, theme.name);
        assert_eq!(back.mode, Mode::Light);
        assert_eq!(back.palette, theme.palette);

        let default = Theme::default_theme();
        let back = from_toml(&to_toml(&default), "x").unwrap();
        assert_eq!(back.palette, default.palette);
    }

    /// A short theme file sets what it names and keeps OpenVTC's colours for
    /// the rest.
    #[test]
    fn a_partial_theme_keeps_openvtc_colours() {
        let theme = from_toml("[colors]\naccent = \"#ff0000\"\n", "Red Borders").unwrap();
        assert_eq!(theme.name, "Red Borders");
        assert_eq!(theme.palette.accent, Color::Rgb(255, 0, 0));
        assert_eq!(theme.palette.text, Palette::DEFAULT.text);
        assert_eq!(theme.palette.background, None);
        assert!(from_toml("[colors]\naccent = \"blueish\"\n", "x").is_err());
    }

    #[test]
    fn a_base16_scheme_in_either_layout() {
        let current = "system: \"base16\"\nname: \"Sample\"\nvariant: \"light\"\npalette:\n  \
                       base00: \"#fafafa\"\n  base03: \"#a0a1a7\"\n  base05: \"#383a42\"\n  \
                       base08: \"#e45649\" # red\n  base09: \"#986801\"\n  base0B: \"#50a14f\"\n  \
                       base0D: \"#4078f2\"\n  base0E: \"#a626a4\"\n";
        let theme = from_base16(current, "fallback").unwrap();
        assert_eq!(theme.name, "Sample");
        assert_eq!(theme.mode, Mode::Light);
        assert_eq!(theme.palette.danger, Color::Rgb(0xe4, 0x56, 0x49));
        assert_eq!(theme.palette.accent, Color::Rgb(0x40, 0x78, 0xf2));

        let legacy = "scheme: \"Legacy\"\nbase00: \"1d1f21\"\nbase05: \"c5c8c6\"\n\
                      base08: \"cc6666\"\nbase0B: \"b5bd68\"\nbase0D: \"81a2be\"\n";
        let theme = from_base16(legacy, "fallback").unwrap();
        assert_eq!(theme.name, "Legacy");
        assert_eq!(theme.mode, Mode::Dark);
        assert_eq!(theme.palette.muted, Palette::DEFAULT.muted);
        assert!(from_base16("name: nothing\n", "x").is_err());
    }

    #[test]
    fn an_omarchy_colors_file() {
        let text = "mode = \"dark\"\naccent = \"#7aa2f7\"\nbackground = \"#1a1b26\"\n\
                    foreground = \"#a9b1d6\"\ndark_foreground = \"#565f89\"\nred = \"#f7768e\"\n\
                    yellow = \"#e0af68\"\ngreen = \"#9ece6a\"\nmagenta = \"#ad8ee6\"\n";
        let theme = from_omarchy_colors(text, "Tokyo Night", None).unwrap();
        assert_eq!(theme.palette.warning, Color::Rgb(0xe0, 0xaf, 0x68));
        assert_eq!(theme.palette.muted, Color::Rgb(0x56, 0x5f, 0x89));
        assert_eq!(theme.palette.background, Some(Color::Rgb(0x1a, 0x1b, 0x26)));
    }

    #[test]
    fn terminal_colour_files() {
        let alacritty = "[colors.primary]\nbackground = \"0x282828\"\nforeground = \"0xebdbb2\"\n\
                         [colors.normal]\nred = \"0xcc241d\"\nblue = \"0x458588\"\n\
                         [colors.bright]\nblack = \"0x928374\"\n";
        let theme = from_alacritty(alacritty, "Gruvbox", None).unwrap();
        assert_eq!(theme.palette.accent, Color::Rgb(0x45, 0x85, 0x88));
        assert_eq!(theme.palette.muted, Color::Rgb(0x92, 0x83, 0x74));

        let kitty =
            "# a comment\nforeground #c0caf5\nbackground #1a1b26\ncolor1 #f7768e\ncolor8 #414868\n";
        let theme = from_kitty(kitty, "Kitty", None).unwrap();
        assert_eq!(theme.palette.danger, Color::Rgb(0xf7, 0x76, 0x8e));
        assert_eq!(theme.palette.muted, Color::Rgb(0x41, 0x48, 0x68));

        let ghostty = "palette = 4=#89b4fa\nbackground = #eff1f5\nforeground = #4c4f69\n";
        let theme = from_ghostty(ghostty, "Ghostty", None).unwrap();
        assert_eq!(theme.palette.accent, Color::Rgb(0x89, 0xb4, 0xfa));
        assert_eq!(
            theme.mode,
            Mode::Light,
            "a light background makes a light theme"
        );
    }

    /// An Omarchy theme directory is read from colors.toml, falling back to the
    /// alacritty.toml older themes carry, with light.mode marking a light one.
    #[test]
    fn an_omarchy_theme_directory() {
        let dir = std::env::temp_dir().join(format!("openvtc-theme-dir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let theme_dir = dir.join("paper-white");
        std::fs::create_dir_all(&theme_dir).unwrap();
        std::fs::write(
            theme_dir.join("alacritty.toml"),
            "[colors.primary]\nbackground = \"#ffffff\"\nforeground = \"#222222\"\n",
        )
        .unwrap();
        std::fs::write(theme_dir.join("light.mode"), "").unwrap();
        let theme = from_path(&theme_dir).unwrap();
        assert_eq!(theme.name, "Paper White");
        assert_eq!(theme.mode, Mode::Light);
        assert_eq!(theme.palette.text, Color::Rgb(0x22, 0x22, 0x22));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
