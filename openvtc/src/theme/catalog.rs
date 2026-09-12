//! Finding, loading and remembering themes.
//!
//! | Id                  | Where it comes from                                         |
//! |---------------------|-------------------------------------------------------------|
//! | `openvtc`, `nord`…  | built in ([`super::builtin`])                               |
//! | `user/<name>`       | `<config>/themes/<name>.toml`, an OpenVTC theme file        |
//! | `omarchy/current`   | whichever Omarchy theme is current, followed as it changes  |
//! | `omarchy/<name>`    | an Omarchy theme directory, read in place                   |
//!
//! `<config>` is `OPENVTC_CONFIG_PATH`, else `~/.config/openvtc` (the
//! platform's config directory on Windows). The chosen id is kept in
//! `<config>/tui.toml`, shared by every profile: how the TUI looks is the
//! person's, not the account's.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};

use super::{Theme, builtin, import};

/// Where a listed theme comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    Builtin,
    User(PathBuf),
    Omarchy(PathBuf),
    OmarchyCurrent,
}

impl Source {
    /// A word for a list.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Source::Builtin => "built in",
            Source::User(_) => "yours",
            Source::Omarchy(_) => "Omarchy",
            Source::OmarchyCurrent => "Omarchy, follows the current theme",
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

    fn settings_file(&self) -> Option<PathBuf> {
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
        if let Ok(name) = fs::read_to_string(home.join(".local/state/omarchy/current/theme.name"))
            && let Some(dir) = self.omarchy_theme(name.trim())
        {
            return Some(dir);
        }
        // Earlier ones link to its directory.
        fs::canonicalize(home.join(".config/omarchy/current/theme"))
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

/// Every theme that can be chosen: built in, the person's own, then Omarchy's.
#[must_use]
pub fn list(roots: &Roots) -> Vec<Entry> {
    let mut entries: Vec<Entry> = builtin::all()
        .into_iter()
        .map(|t| Entry {
            id: t.id,
            name: t.name,
            source: Source::Builtin,
        })
        .collect();

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

/// The theme with `id`.
///
/// # Errors
///
/// An unknown id, or a theme file that cannot be read.
pub fn load(roots: &Roots, id: &str) -> Result<Theme> {
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

/// The id of the chosen theme, if one was chosen.
#[must_use]
pub fn selected(roots: &Roots) -> Option<String> {
    let text = fs::read_to_string(roots.settings_file()?).ok()?;
    let table: toml::Table = toml::from_str(&text).ok()?;
    table
        .get("theme")
        .and_then(toml::Value::as_str)
        .map(str::to_string)
}

/// Remember `id` as the chosen theme, keeping anything else `tui.toml` holds.
///
/// # Errors
///
/// A configuration directory that cannot be written.
pub fn remember(roots: &Roots, id: &str) -> Result<()> {
    let path = roots
        .settings_file()
        .ok_or_else(|| anyhow!("no configuration directory to remember the theme in"))?;
    let mut table: toml::Table = fs::read_to_string(&path)
        .ok()
        .and_then(|text| toml::from_str(&text).ok())
        .unwrap_or_default();
    table.insert("theme".to_string(), toml::Value::String(id.to_string()));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, toml::to_string(&table)?)
        .with_context(|| format!("could not write {}", path.display()))
}

/// The chosen theme, or OpenVTC's own when none was chosen or it cannot be read.
#[must_use]
pub fn load_selected(roots: &Roots) -> Theme {
    selected(roots)
        .and_then(|id| match load(roots, &id) {
            Ok(theme) => Some(theme),
            Err(e) => {
                tracing::warn!(theme = %id, error = %e, "chosen theme could not be loaded; using the default");
                None
            }
        })
        .unwrap_or_else(Theme::default_theme)
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
        let chosen = load_selected(&roots);
        assert_eq!(chosen.id, "user/my-nord");
        assert_eq!(chosen.palette, theme.palette);
        assert!(list(&roots).iter().any(|e| e.id == "user/my-nord"));
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
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn nothing_chosen_or_something_unreadable_falls_back_to_openvtc() {
        let (base, roots) = roots("fallback");
        assert_eq!(load_selected(&roots).id, builtin::DEFAULT_ID);
        remember(&roots, "user/missing").unwrap();
        assert_eq!(load_selected(&roots).id, builtin::DEFAULT_ID);
        assert!(load(&roots, "user/../../etc/passwd").is_err());
        assert!(load(&roots, "omarchy/../x").is_err());
        let _ = fs::remove_dir_all(base);
    }
}
