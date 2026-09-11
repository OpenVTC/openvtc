//! Themes from Neovim colorschemes.
//!
//! Rather than parse colorscheme plugins — Lua, Vimscript, generated or
//! hand-written — OpenVTC asks Neovim. It runs `nvim --headless`, loads the
//! colorscheme with the person's own configuration (so plugin-managed themes
//! are available), and reads back the highlight groups every colorscheme
//! defines. Whatever Neovim can show, OpenVTC can import.
//!
//! | Role      | Highlight group (first one that has a colour) |
//! |-----------|-----------------------------------------------|
//! | accent    | `Function`, `Directory`, `Title`              |
//! | success   | `DiagnosticOk`, `String`                      |
//! | warning   | `DiagnosticWarn`, `WarningMsg`                |
//! | danger    | `DiagnosticError`, `ErrorMsg`                 |
//! | text      | `Normal` foreground                           |
//! | muted     | `Comment`                                     |
//! | highlight | `Keyword`, `Statement`, `Special`             |
//! | background| `Normal` background                           |

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use ratatui::style::Color;
use serde_json::Value;

use super::import::title;
use super::{Mode, Palette, Theme};

const MARKER: &str = "OPENVTC_THEME_JSON:";
const TIMEOUT: Duration = Duration::from_secs(30);
const GROUPS: &[&str] = &[
    "Normal",
    "Comment",
    "Function",
    "Directory",
    "Title",
    "DiagnosticOk",
    "String",
    "DiagnosticWarn",
    "WarningMsg",
    "DiagnosticError",
    "ErrorMsg",
    "Keyword",
    "Statement",
    "Special",
];

/// The Lua run inside Neovim once the colorscheme is loaded.
fn script() -> String {
    let groups = GROUPS
        .iter()
        .map(|g| format!("'{g}'"))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "local out = {{ name = vim.g.colors_name or '', background = vim.o.background, groups = {{}} }}; \
         for _, g in ipairs({{{groups}}}) do \
           local hl = vim.api.nvim_get_hl(0, {{ name = g, link = false }}); \
           out.groups[g] = {{ fg = hl.fg, bg = hl.bg }} \
         end; \
         io.stdout:write('{MARKER}' .. vim.json.encode(out) .. '\\n')"
    )
}

/// Import the Neovim colorscheme `colorscheme`. With `clean`, Neovim skips the
/// person's configuration and only its bundled colorschemes are available.
///
/// # Errors
///
/// A name that is not a colorscheme name, Neovim missing or too slow, or a
/// colorscheme Neovim cannot load.
pub fn import(colorscheme: &str, clean: bool) -> Result<Theme> {
    if colorscheme.is_empty()
        || !colorscheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("`{colorscheme}` is not a colorscheme name");
    }
    let nvim = std::env::var_os("OPENVTC_NVIM").unwrap_or_else(|| "nvim".into());
    let mut command = Command::new(&nvim);
    command.args(["--headless", "-i", "NONE", "-n"]);
    if clean {
        command.arg("--clean");
    }
    command
        .arg("-c")
        .arg(format!("silent! colorscheme {colorscheme}"))
        .arg("-c")
        .arg(format!("lua {}", script()))
        .arg("-c")
        .arg("qa!")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn().map_err(|e| {
        anyhow!(
            "could not run Neovim ({}): {e} — is it installed and on PATH? \
             Set OPENVTC_NVIM to point at it.",
            nvim.to_string_lossy()
        )
    })?;
    let mut stdout = child
        .stdout
        .take()
        .context("Neovim's output was not captured")?;
    let reader = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stdout.read_to_string(&mut text);
        text
    });
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!(
                "Neovim did not finish within {}s — try again with --clean to skip your configuration",
                TIMEOUT.as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let output = reader.join().unwrap_or_default();
    let json = output
        .lines()
        .find_map(|line| line.split_once(MARKER).map(|(_, json)| json))
        .ok_or_else(|| anyhow!("Neovim did not report the colorscheme's colours"))?;
    from_highlights(json, colorscheme)
}

/// The theme for the highlight groups Neovim reported for `requested`.
///
/// # Errors
///
/// Output that is not the report, or a colorscheme Neovim did not load.
pub fn from_highlights(json: &str, requested: &str) -> Result<Theme> {
    let report: Value = serde_json::from_str(json).context("Neovim's report is not JSON")?;
    let loaded = report
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !loaded.eq_ignore_ascii_case(requested) {
        bail!("Neovim has no colorscheme named `{requested}`");
    }
    let mode = Mode::parse(
        report
            .get("background")
            .and_then(Value::as_str)
            .unwrap_or("dark"),
    );
    let channel = |group: &str, which: &str| {
        report
            .pointer(&format!("/groups/{group}/{which}"))
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .map(|n| Color::Rgb((n >> 16) as u8, (n >> 8) as u8, n as u8))
    };
    let first = |groups: &[&str]| groups.iter().find_map(|g| channel(g, "fg"));
    let default = Palette::DEFAULT;
    let background = channel("Normal", "bg");
    let text = channel("Normal", "fg").unwrap_or(match mode {
        Mode::Light => Color::Black,
        Mode::Dark => default.text,
    });
    Ok(Theme {
        id: super::import::slug(requested),
        name: title(requested),
        mode,
        palette: Palette {
            accent: first(&["Function", "Directory", "Title"]).unwrap_or(default.accent),
            success: first(&["DiagnosticOk", "String"]).unwrap_or(default.success),
            warning: first(&["DiagnosticWarn", "WarningMsg"]).unwrap_or(default.warning),
            danger: first(&["DiagnosticError", "ErrorMsg"]).unwrap_or(default.danger),
            text,
            muted: first(&["Comment"]).unwrap_or(default.muted),
            highlight: first(&["Keyword", "Statement", "Special"]).unwrap_or(default.highlight),
            background,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The report maps onto roles, taking the first group with a colour.
    #[test]
    fn a_report_becomes_a_theme() {
        let json = r#"{"name":"sample","background":"dark","groups":{
            "Normal":{"fg":13421772,"bg":1973790},
            "Comment":{"fg":8421504},
            "Function":[],"Directory":{"fg":255},
            "DiagnosticError":{"fg":16711680},
            "Keyword":{"fg":11141290}}}"#;
        let theme = from_highlights(json, "sample").unwrap();
        assert_eq!(theme.name, "Sample");
        assert_eq!(theme.palette.text, Color::Rgb(0xcc, 0xcc, 0xcc));
        assert_eq!(theme.palette.background, Some(Color::Rgb(0x1e, 0x1e, 0x1e)));
        assert_eq!(
            theme.palette.accent,
            Color::Rgb(0, 0, 255),
            "Function is empty, so Directory"
        );
        assert_eq!(theme.palette.danger, Color::Rgb(255, 0, 0));
        assert_eq!(theme.palette.success, Palette::DEFAULT.success);
    }

    /// `:colorscheme` fails silently in the script, so a name Neovim does not
    /// know shows up as a different (or no) loaded scheme.
    #[test]
    fn an_unknown_colorscheme_is_refused() {
        let json = r#"{"name":"default","background":"dark","groups":{}}"#;
        assert!(from_highlights(json, "nosuchtheme").is_err());
        assert!(import("bad name; !rm", true).is_err());
    }

    /// Against a real Neovim, with a colorscheme every Neovim release bundles.
    ///
    /// Skips itself when Neovim is not on `PATH`, rather than being `#[ignore]`d:
    /// the coverage job runs ignored tests too, and CI machines need not have
    /// Neovim.
    #[test]
    fn a_bundled_colorscheme_imports() {
        if std::process::Command::new("nvim")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("skipped: nvim is not on PATH");
            return;
        }
        let theme = import("desert", true).unwrap();
        assert_eq!(theme.name, "Desert");
        assert!(theme.palette.background.is_some());
    }
}
