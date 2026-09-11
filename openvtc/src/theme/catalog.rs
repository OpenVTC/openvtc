//! Finding, loading and remembering themes.
//!
//! | Id                  | Where it comes from                                         |
//! |---------------------|-------------------------------------------------------------|
//! | `auto`              | follows the terminal's background: `auto_dark` or `auto_light` |
//! | `openvtc`, `nord`…  | built in ([`super::builtin`])                               |
//! | `user/<name>`       | `<config>/themes/<name>.toml`, an OpenVTC theme file        |
//! | `omarchy/current`   | whichever Omarchy theme is current, followed as it changes  |
//! | `omarchy/<name>`    | an Omarchy theme directory, read in place                   |
//!
//! `<config>` is `OPENVTC_CONFIG_PATH`, else `~/.config/openvtc` (the
//! platform's config directory on Windows). The choice is kept in
//! `<config>/tui.toml`, shared by every profile: how the TUI looks is the
//! person's, not the account's.
//!
//! ```toml
//! theme = "auto"
//! auto_dark = "openvtc"            # under auto, on a dark terminal
//! auto_light = "catppuccin-latte"  # and on a light one
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};

use super::{Mode, Theme, builtin, import, terminal};

/// The id that follows the terminal's background.
pub const AUTO_ID: &str = "auto";

/// Under `auto`, the theme for a light terminal when `tui.toml` names none.
const AUTO_LIGHT_DEFAULT: &str = "catppuccin-latte";

/// Where current Omarchy releases record the current theme's name, under home.
const OMARCHY_CURRENT_NAME: &str = ".local/state/omarchy/current/theme.name";

/// Where earlier Omarchy releases linked the current theme's directory.
const OMARCHY_CURRENT_LINK: &str = ".config/omarchy/current/theme";

/// The files an Omarchy theme directory is read from.
const OMARCHY_THEME_FILES: [&str; 4] =
    ["colors.toml", "alacritty.toml", "kitty.conf", "light.mode"];

/// Where a listed theme comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// Follows the terminal, between these two ids.
    Auto {
        dark: String,
        light: String,
    },
    Builtin,
    User(PathBuf),
    Omarchy(PathBuf),
    OmarchyCurrent,
}

impl Source {
    /// A few words for a list.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Source::Auto { dark, light } => {
                format!("{dark} on a dark terminal, {light} on a light one")
            }
            Source::Builtin => "built in".to_string(),
            Source::User(_) => "yours".to_string(),
            Source::Omarchy(_) => "Omarchy".to_string(),
            Source::OmarchyCurrent => "Omarchy, follows the current theme".to_string(),
        }
    }
}

/// A theme that can be chosen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub id: String,
    pub name: String,
    pub source: Source,
}

/// What `tui.toml` says to draw with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Choice {
    /// The theme chosen: an id, or `auto`.
    pub theme: String,
    /// Under `auto`, the theme for a dark terminal.
    pub auto_dark: String,
    /// Under `auto`, the theme for a light terminal.
    pub auto_light: String,
}

impl Default for Choice {
    fn default() -> Self {
        Choice {
            theme: builtin::DEFAULT_ID.to_string(),
            auto_dark: builtin::DEFAULT_ID.to_string(),
            auto_light: AUTO_LIGHT_DEFAULT.to_string(),
        }
    }
}

impl Choice {
    /// The theme `auto` draws with on a terminal in `mode`.
    #[must_use]
    pub fn for_mode(&self, mode: Mode) -> &str {
        match mode {
            Mode::Dark => &self.auto_dark,
            Mode::Light => &self.auto_light,
        }
    }
}

/// The places themes live.
#[derive(Clone, Debug, Default)]
pub struct Roots {
    /// OpenVTC's configuration directory.
    pub config: Option<PathBuf>,
    /// The home directory, where Omarchy keeps its themes and current choice.
    pub home: Option<PathBuf>,
    /// Omarchy's system-wide themes.
    pub system_omarchy: Option<PathBuf>,
}

impl Roots {
    /// The real locations for this user.
    #[must_use]
    pub fn from_env() -> Self {
        let home = dirs::home_dir();
        let config = std::env::var_os("OPENVTC_CONFIG_PATH")
            .map(PathBuf::from)
            .or_else(|| {
                #[cfg(windows)]
                {
                    dirs::config_dir().map(|p| p.join("openvtc"))
                }
                #[cfg(not(windows))]
                {
                    home.as_ref().map(|h| h.join(".config").join("openvtc"))
                }
            });
        Roots {
            config,
            home,
            system_omarchy: Some(PathBuf::from("/usr/share/omarchy/themes")),
        }
    }

    /// Where the person's own theme files live.
    #[must_use]
    pub fn themes_dir(&self) -> Option<PathBuf> {
        self.config.as_ref().map(|c| c.join("themes"))
    }

    /// `tui.toml`, where the choice is kept.
    #[must_use]
    pub fn settings_file(&self) -> Option<PathBuf> {
        self.config.as_ref().map(|c| c.join("tui.toml"))
    }

    /// Omarchy's theme directories, the person's own first.
    fn omarchy_dirs(&self) -> Vec<PathBuf> {
        let mut dirs = Vec::new();
        if let Some(home) = &self.home {
            dirs.push(home.join(".config/omarchy/themes"));
            dirs.push(home.join(".local/share/omarchy/themes"));
        }
        dirs.extend(self.system_omarchy.clone());
        dirs
    }

    /// The Omarchy theme directory named `name`.
    fn omarchy_theme(&self, name: &str) -> Option<PathBuf> {
        self.omarchy_dirs()
            .into_iter()
            .map(|d| d.join(name))
            .find(|d| is_omarchy_theme(d))
    }

    /// The current Omarchy theme's directory.
    fn omarchy_current(&self) -> Option<PathBuf> {
        let home = self.home.as_ref()?;
        // Current releases record the theme's name.
        if let Ok(name) = fs::read_to_string(home.join(OMARCHY_CURRENT_NAME))
            && let Some(dir) = self.omarchy_theme(name.trim())
        {
            return Some(dir);
        }
        // Earlier ones link to its directory.
        fs::canonicalize(home.join(OMARCHY_CURRENT_LINK))
            .ok()
            .filter(|d| is_omarchy_theme(d))
    }
}

fn is_omarchy_theme(dir: &Path) -> bool {
    dir.join("colors.toml").is_file() || dir.join("alacritty.toml").is_file()
}

/// A theme id segment that is safe as a file name.
fn valid_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && !segment.starts_with('.')
}

/// Every theme that can be chosen: auto, built in, the person's own, then
/// Omarchy's.
#[must_use]
pub fn list(roots: &Roots) -> Vec<Entry> {
    let choice = choice(roots);
    let mut entries = vec![Entry {
        id: AUTO_ID.to_string(),
        name: "Auto (follow terminal)".to_string(),
        source: Source::Auto {
            dark: choice.auto_dark,
            light: choice.auto_light,
        },
    }];
    entries.extend(builtin::all().into_iter().map(|t| Entry {
        id: t.id,
        name: t.name,
        source: Source::Builtin,
    }));

    if let Some(dir) = roots.themes_dir()
        && let Ok(files) = fs::read_dir(&dir)
    {
        let mut user: Vec<Entry> = files
            .flatten()
            .map(|f| f.path())
            .filter(|p| p.extension().is_some_and(|e| e == "toml"))
            .filter_map(|path| {
                let stem = path.file_stem()?.to_str()?.to_string();
                if !valid_segment(&stem) {
                    return None;
                }
                let theme = fs::read_to_string(&path)
                    .ok()
                    .and_then(|text| import::from_toml(&text, &import::title(&stem)).ok())?;
                Some(Entry {
                    id: format!("user/{stem}"),
                    name: theme.name,
                    source: Source::User(path),
                })
            })
            .collect();
        user.sort_by(|a, b| a.name.cmp(&b.name));
        entries.extend(user);
    }

    if let Some(current) = roots.omarchy_current() {
        let name = current
            .file_name()
            .and_then(|n| n.to_str())
            .map(import::title)
            .unwrap_or_default();
        entries.push(Entry {
            id: "omarchy/current".to_string(),
            name: format!("Omarchy current ({name})"),
            source: Source::OmarchyCurrent,
        });
    }
    let mut seen = std::collections::HashSet::new();
    let mut omarchy = Vec::new();
    for dir in roots.omarchy_dirs() {
        let Ok(children) = fs::read_dir(&dir) else {
            continue;
        };
        for child in children.flatten() {
            let path = child.path();
            let Some(name) = path
                .file_name()
                .and_then(|n| n.to_str())
                .map(str::to_string)
            else {
                continue;
            };
            if valid_segment(&name) && is_omarchy_theme(&path) && seen.insert(name.clone()) {
                omarchy.push(Entry {
                    id: format!("omarchy/{name}"),
                    name: import::title(&name),
                    source: Source::Omarchy(path),
                });
            }
        }
    }
    omarchy.sort_by(|a, b| a.name.cmp(&b.name));
    entries.extend(omarchy);
    entries
}

/// The theme with `id`. `auto` loads the theme for the terminal's background,
/// keeping `auto` as its id.
///
/// # Errors
///
/// An unknown id, or a theme file that cannot be read.
pub fn load(roots: &Roots, id: &str) -> Result<Theme> {
    if id == AUTO_ID {
        let target = resolve(roots, id);
        let mut theme = load(roots, &target)
            .with_context(|| format!("auto's theme for this terminal, `{target}`"))?;
        theme.id = AUTO_ID.to_string();
        return Ok(theme);
    }
    let mut theme = if let Some(theme) = builtin::find(id) {
        theme
    } else if let Some(name) = id.strip_prefix("user/") {
        if !valid_segment(name) {
            bail!("`{id}` is not a theme id");
        }
        let dir = roots
            .themes_dir()
            .ok_or_else(|| anyhow!("no configuration directory for themes"))?;
        let path = dir.join(format!("{name}.toml"));
        let text = fs::read_to_string(&path)
            .with_context(|| format!("no theme file at {}", path.display()))?;
        import::from_toml(&text, &import::title(name))
            .with_context(|| format!("could not read {}", path.display()))?
    } else if id == "omarchy/current" {
        let dir = roots
            .omarchy_current()
            .ok_or_else(|| anyhow!("no current Omarchy theme found"))?;
        import::from_path(&dir)?
    } else if let Some(name) = id.strip_prefix("omarchy/") {
        if !valid_segment(name) {
            bail!("`{id}` is not a theme id");
        }
        let dir = roots
            .omarchy_theme(name)
            .ok_or_else(|| anyhow!("no Omarchy theme named `{name}`"))?;
        import::from_path(&dir)?
    } else {
        bail!("no theme `{id}` — `openvtc theme list` shows them all");
    };
    theme.id = id.to_string();
    Ok(theme)
}

/// The id of the theme `id` draws with: under `auto`, the one for the
/// terminal's background as [`terminal::mode`] knows it; any other id is itself.
#[must_use]
pub fn resolve(roots: &Roots, id: &str) -> String {
    if id == AUTO_ID {
        choice(roots).for_mode(terminal::mode().0).to_string()
    } else {
        id.to_string()
    }
}

/// The files theme `id` is read from, whether or not they exist yet, so a
/// change to any of them can be noticed. Built-in themes have none; `auto` is
/// resolved by the caller, which knows the choice it is following.
#[must_use]
pub fn sources(roots: &Roots, id: &str) -> Vec<PathBuf> {
    let theme_files = |dir: PathBuf| OMARCHY_THEME_FILES.map(|f| dir.join(f)).to_vec();
    if let Some(name) = id.strip_prefix("user/") {
        return roots
            .themes_dir()
            .filter(|_| valid_segment(name))
            .map(|dir| vec![dir.join(format!("{name}.toml"))])
            .unwrap_or_default();
    }
    if id == "omarchy/current" {
        let mut files = Vec::new();
        if let Some(home) = &roots.home {
            files.push(home.join(OMARCHY_CURRENT_NAME));
            files.push(home.join(OMARCHY_CURRENT_LINK));
        }
        files.extend(roots.omarchy_current().map(theme_files).unwrap_or_default());
        return files;
    }
    if let Some(name) = id.strip_prefix("omarchy/")
        && valid_segment(name)
        && let Some(dir) = roots.omarchy_theme(name)
    {
        return theme_files(dir);
    }
    Vec::new()
}

/// `tui.toml` as a table: empty when there is none, `None` when it is there but
/// is not TOML.
fn settings(roots: &Roots) -> Option<toml::Table> {
    let Some(text) = roots
        .settings_file()
        .and_then(|path| fs::read_to_string(path).ok())
    else {
        return Some(toml::Table::new());
    };
    toml::from_str(&text).ok()
}

/// What `tui.toml` says to draw with, or `None` while it cannot be read as TOML
/// — half-written, or mid-edit.
#[must_use]
pub fn read_choice(roots: &Roots) -> Option<Choice> {
    let table = settings(roots)?;
    let default = Choice::default();
    let id = |key: &str, fallback: String, auto_allowed: bool| {
        table
            .get(key)
            .and_then(toml::Value::as_str)
            .map(str::trim)
            .filter(|id| !id.is_empty() && (auto_allowed || *id != AUTO_ID))
            .map_or(fallback, str::to_string)
    };
    Some(Choice {
        theme: id("theme", default.theme, true),
        // `auto` cannot pick itself.
        auto_dark: id("auto_dark", default.auto_dark, false),
        auto_light: id("auto_light", default.auto_light, false),
    })
}

/// What `tui.toml` says to draw with, OpenVTC's own theme when it says nothing.
#[must_use]
pub fn choice(roots: &Roots) -> Choice {
    read_choice(roots).unwrap_or_default()
}

/// Remember `id` as the chosen theme, keeping anything else `tui.toml` holds.
///
/// # Errors
///
/// A configuration directory that cannot be written.
pub fn remember(roots: &Roots, id: &str) -> Result<()> {
    store(roots, &[("theme", id)])
}

/// Choose `auto`, and with `dark` or `light`, the theme it draws with on a dark
/// or light terminal.
///
/// # Errors
///
/// A configuration directory that cannot be written.
pub fn remember_auto(roots: &Roots, dark: Option<&str>, light: Option<&str>) -> Result<()> {
    let mut entries = vec![("theme", AUTO_ID)];
    entries.extend(dark.map(|id| ("auto_dark", id)));
    entries.extend(light.map(|id| ("auto_light", id)));
    store(roots, &entries)
}

/// Set `entries` in `tui.toml`. Written to a temporary file and renamed into
/// place, so a running TUI never reads it half-written.
fn store(roots: &Roots, entries: &[(&str, &str)]) -> Result<()> {
    let path = roots
        .settings_file()
        .ok_or_else(|| anyhow!("no configuration directory to remember the theme in"))?;
    let mut table = settings(roots).unwrap_or_default();
    for (key, value) in entries {
        table.insert(
            (*key).to_string(),
            toml::Value::String((*value).to_string()),
        );
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let partial = path.with_extension("toml.partial");
    fs::write(&partial, toml::to_string(&table)?)
        .and_then(|()| fs::rename(&partial, &path))
        .with_context(|| format!("could not write {}", path.display()))
}

/// Write `theme` into the person's themes directory, under a file name no
/// other theme uses. Returns its id and path.
///
/// # Errors
///
/// A themes directory that cannot be written.
pub fn install(roots: &Roots, theme: &Theme) -> Result<(String, PathBuf)> {
    let dir = roots
        .themes_dir()
        .ok_or_else(|| anyhow!("no configuration directory for themes"))?;
    fs::create_dir_all(&dir).with_context(|| format!("could not create {}", dir.display()))?;
    let base = import::slug(&theme.name);
    let mut stem = base.clone();
    let mut n = 2;
    while dir.join(format!("{stem}.toml")).exists() {
        stem = format!("{base}-{n}");
        n += 1;
    }
    let path = dir.join(format!("{stem}.toml"));
    fs::write(&path, import::to_toml(theme))
        .with_context(|| format!("could not write {}", path.display()))?;
    Ok((format!("user/{stem}"), path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme::{Mode, builtin};

    fn roots(tag: &str) -> (PathBuf, Roots) {
        let base =
            std::env::temp_dir().join(format!("openvtc-themes-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let roots = Roots {
            config: Some(base.join("config")),
            home: Some(base.join("home")),
            system_omarchy: Some(base.join("system")),
        };
        (base, roots)
    }

    fn omarchy_theme(dir: &Path, name: &str, background: &str) {
        let theme = dir.join(name);
        fs::create_dir_all(&theme).unwrap();
        fs::write(
            theme.join("colors.toml"),
            format!("background = \"{background}\"\nforeground = \"#dddddd\"\n"),
        )
        .unwrap();
    }

    /// A theme copied in, chosen, and loaded back is the theme that was copied.
    #[test]
    fn an_installed_theme_can_be_chosen_and_loaded() {
        let (base, roots) = roots("install");
        let mut theme = builtin::find("nord").unwrap();
        theme.name = "My Nord".into();
        let (id, path) = install(&roots, &theme).unwrap();
        assert_eq!(id, "user/my-nord");
        assert!(path.ends_with("themes/my-nord.toml"));
        let (second, _) = install(&roots, &theme).unwrap();
        assert_eq!(
            second, "user/my-nord-2",
            "an existing file is never overwritten"
        );

        remember(&roots, &id).unwrap();
        let chosen = load(&roots, &choice(&roots).theme).unwrap();
        assert_eq!(chosen.id, "user/my-nord");
        assert_eq!(chosen.palette, theme.palette);
        assert!(list(&roots).iter().any(|e| e.id == "user/my-nord"));
        assert_eq!(
            sources(&roots, &id),
            [roots.themes_dir().unwrap().join("my-nord.toml")]
        );
        let _ = fs::remove_dir_all(base);
    }

    /// Omarchy's themes are read in place, the person's own shadowing the
    /// system's, and the current one is followed by name.
    #[test]
    fn omarchy_themes_are_listed_and_the_current_one_followed() {
        let (base, roots) = roots("omarchy");
        let home = roots.home.clone().unwrap();
        omarchy_theme(
            &home.join(".config/omarchy/themes"),
            "tokyo-night",
            "#1a1b26",
        );
        omarchy_theme(
            roots.system_omarchy.as_ref().unwrap(),
            "tokyo-night",
            "#000000",
        );
        omarchy_theme(roots.system_omarchy.as_ref().unwrap(), "white", "#ffffff");
        let state = home.join(".local/state/omarchy/current");
        fs::create_dir_all(&state).unwrap();
        fs::write(state.join("theme.name"), "white\n").unwrap();

        let entries = list(&roots);
        let omarchy: Vec<_> = entries
            .iter()
            .filter(|e| e.id.starts_with("omarchy/"))
            .map(|e| e.id.as_str())
            .collect();
        assert_eq!(
            omarchy,
            ["omarchy/current", "omarchy/tokyo-night", "omarchy/white"]
        );

        let tokyo = load(&roots, "omarchy/tokyo-night").unwrap();
        assert_eq!(
            tokyo.palette.background,
            Some(ratatui::style::Color::Rgb(0x1a, 0x1b, 0x26)),
            "the person's own copy wins"
        );
        let current = load(&roots, "omarchy/current").unwrap();
        assert_eq!(current.id, "omarchy/current");
        assert_eq!(current.mode, Mode::Light);

        let watched = sources(&roots, "omarchy/current");
        assert!(watched.contains(&state.join("theme.name")));
        assert!(watched.contains(&roots.system_omarchy.unwrap().join("white/colors.toml")));
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn nothing_chosen_or_something_unreadable() {
        let (base, roots) = roots("fallback");
        assert_eq!(choice(&roots), Choice::default());
        remember(&roots, "user/missing").unwrap();
        assert_eq!(choice(&roots).theme, "user/missing");
        assert!(load(&roots, "user/missing").is_err());
        assert!(load(&roots, "user/../../etc/passwd").is_err());
        assert!(load(&roots, "omarchy/../x").is_err());
        assert!(sources(&roots, "user/../x").is_empty());

        fs::write(roots.settings_file().unwrap(), "theme = \"nord").unwrap();
        assert_eq!(read_choice(&roots), None, "half-written is not a choice");
        assert_eq!(choice(&roots), Choice::default());
        let _ = fs::remove_dir_all(base);
    }

    /// `auto` keeps its own id, draws with the theme for the terminal, and can
    /// never be told to pick itself.
    #[test]
    fn auto_picks_between_two_themes() {
        let (base, roots) = roots("auto");
        let entries = list(&roots);
        assert_eq!(entries[0].id, AUTO_ID, "auto comes first");

        remember(&roots, "dracula").unwrap();
        remember_auto(&roots, Some("nord"), None).unwrap();
        let chosen = choice(&roots);
        assert_eq!(chosen.theme, AUTO_ID);
        assert_eq!(chosen.for_mode(Mode::Dark), "nord");
        assert_eq!(chosen.for_mode(Mode::Light), AUTO_LIGHT_DEFAULT);

        let theme = load(&roots, AUTO_ID).unwrap();
        assert_eq!(theme.id, AUTO_ID);
        let expected = builtin::find(chosen.for_mode(terminal::mode().0)).unwrap();
        assert_eq!(theme.palette, expected.palette);
        assert_eq!(theme.name, expected.name);

        fs::write(
            roots.settings_file().unwrap(),
            "theme = \"auto\"\nauto_dark = \"auto\"\nauto_light = \"auto\"\n",
        )
        .unwrap();
        assert_eq!(choice(&roots).auto_dark, builtin::DEFAULT_ID);
        assert!(load(&roots, AUTO_ID).is_ok());
        let _ = fs::remove_dir_all(base);
    }
}
