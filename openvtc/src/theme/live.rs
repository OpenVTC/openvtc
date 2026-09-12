//! Following theme changes while the TUI runs.
//!
//! A theme can change under a running TUI in two ways: another theme is chosen
//! (`openvtc theme set` in another terminal rewrites `tui.toml`), or the theme
//! in use changes where it is read from (a theme file is edited, Omarchy
//! switches its current theme, an Omarchy theme's colours are edited).
//!
//! [`Watcher::check`] looks for both by comparing modification times, sizes and
//! link targets of a handful of files — cheap enough to do every second, and
//! the same on every platform, without a file-watching dependency. It changes
//! nothing itself: the UI loop runs it off the render thread and decides
//! whether to take what it found, so a theme being previewed in the picker is
//! never replaced from under the person previewing it.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use super::catalog::{self, AUTO_ID, Choice, Roots};
use super::{Theme, terminal};

/// How often the UI loop checks.
pub const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// What a file looked like when last checked.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Stamp {
    path: PathBuf,
    modified: Option<SystemTime>,
    len: Option<u64>,
    /// Where it links to, when it is a link.
    target: Option<PathBuf>,
}

impl Stamp {
    fn of(path: &Path) -> Self {
        let metadata = fs::metadata(path).ok();
        Stamp {
            path: path.to_path_buf(),
            modified: metadata.as_ref().and_then(|m| m.modified().ok()),
            len: metadata.map(|m| m.len()),
            target: fs::read_link(path).ok(),
        }
    }
}

/// Follows the theme in use and `tui.toml` for changes.
#[derive(Clone, Debug)]
pub struct Watcher {
    roots: Roots,
    settings: Option<Stamp>,
    choice: Choice,
    /// The id of the theme being drawn with, which may not be `tui.toml`'s
    /// choice: `OPENVTC_THEME` can choose another for the session.
    following: String,
    sources: Vec<Stamp>,
}

/// What [`Watcher::check`] found: the watcher as it would be once it has seen
/// the change, and the theme to draw with, if that changed.
#[derive(Debug)]
pub struct Update {
    watcher: Watcher,
    theme: Option<Theme>,
}

impl Watcher {
    /// Follow the theme `following`, the one being drawn with now.
    #[must_use]
    pub fn new(roots: Roots, following: &str) -> Self {
        let mut watcher = Watcher {
            settings: roots.settings_file().map(|p| Stamp::of(&p)),
            choice: catalog::choice(&roots),
            following: following.to_string(),
            sources: Vec::new(),
            roots,
        };
        watcher.sources = watcher.stamp_sources();
        watcher
    }

    /// The files the followed theme is read from, as they are now.
    fn stamp_sources(&self) -> Vec<Stamp> {
        let id = if self.following == AUTO_ID {
            self.choice.for_mode(terminal::mode().0)
        } else {
            &self.following
        };
        catalog::sources(&self.roots, id)
            .iter()
            .map(|path| Stamp::of(path))
            .collect()
    }

    /// Look for a change since this watcher last saw one. `None` when nothing
    /// has changed. Touches the file system, so keep it off the render thread.
    #[must_use]
    pub fn check(&self) -> Option<Update> {
        let mut next = self.clone();
        let mut reload = false;
        next.settings = self.roots.settings_file().map(|p| Stamp::of(&p));
        if next.settings != self.settings
            && let Some(choice) = catalog::read_choice(&self.roots)
        {
            if choice.theme != self.choice.theme {
                // A theme chosen while the TUI runs — here or with `openvtc
                // theme set` — replaces the one in use, even one
                // OPENVTC_THEME chose for the session.
                next.following.clone_from(&choice.theme);
                reload = true;
            } else if choice != self.choice && self.following == AUTO_ID {
                reload = true;
            }
            next.choice = choice;
        }
        next.sources = next.stamp_sources();
        reload |= next.sources != self.sources;

        if !reload {
            return (next.settings != self.settings).then_some(Update {
                watcher: next,
                theme: None,
            });
        }
        let theme = match catalog::load(&self.roots, &next.following) {
            Ok(theme) => Some(theme),
            Err(e) => {
                // Most likely a file caught mid-edit; the next save is checked again.
                tracing::warn!(theme = %next.following, error = %e, "changed theme could not be loaded; keeping the one in use");
                None
            }
        };
        Some(Update {
            watcher: next,
            theme,
        })
    }

    /// Take `update` as seen. Returns the theme to draw with now, if it changed.
    pub fn accept(&mut self, update: Update) -> Option<Theme> {
        *self = update.watcher;
        update.theme
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::style::Color;

    fn roots(tag: &str) -> (PathBuf, Roots) {
        let base = std::env::temp_dir().join(format!("openvtc-live-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("config/themes")).unwrap();
        let roots = Roots {
            config: Some(base.join("config")),
            home: Some(base.join("home")),
            system_omarchy: None,
        };
        (base, roots)
    }

    fn omarchy_theme(roots: &Roots, name: &str, background: &str) -> PathBuf {
        let dir = roots
            .home
            .as_ref()
            .unwrap()
            .join(".config/omarchy/themes")
            .join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("colors.toml"),
            format!("background = \"{background}\"\nforeground = \"#dddddd\"\n"),
        )
        .unwrap();
        dir
    }

    /// Run a check and take what it found, as the UI loop does.
    fn step(watcher: &mut Watcher) -> Option<Option<Theme>> {
        let update = watcher.check()?;
        Some(watcher.accept(update))
    }

    #[test]
    fn an_edited_theme_file_is_redrawn() {
        let (base, roots) = roots("edit");
        let file = roots.themes_dir().unwrap().join("mine.toml");
        fs::write(&file, "[colors]\naccent = \"#ff0000\"\n").unwrap();
        let mut watcher = Watcher::new(roots, "user/mine");
        assert!(watcher.check().is_none(), "nothing has changed");

        fs::write(
            &file,
            "[colors]\naccent = \"#00ff00\"\ntext = \"#ffffff\"\n",
        )
        .unwrap();
        let theme = step(&mut watcher).flatten().expect("the edit is drawn");
        assert_eq!(theme.id, "user/mine");
        assert_eq!(theme.palette.accent, Color::Rgb(0, 255, 0));
        assert!(watcher.check().is_none(), "and seen once");

        // A file caught half-written keeps the theme in use, and is seen
        // again when it is saved whole.
        fs::write(&file, "[colors]\naccent = \"#00").unwrap();
        assert_eq!(step(&mut watcher), Some(None));
        fs::write(&file, "[colors]\naccent = \"#0000ff\"\n").unwrap();
        let theme = step(&mut watcher).flatten().unwrap();
        assert_eq!(theme.palette.accent, Color::Rgb(0, 0, 255));
        let _ = fs::remove_dir_all(base);
    }

    /// A theme chosen elsewhere replaces the one in use, even one chosen for
    /// the session; other changes to `tui.toml` redraw nothing.
    #[test]
    fn a_theme_chosen_elsewhere_is_drawn() {
        let (base, roots) = roots("chosen");
        catalog::remember(&roots, "nord").unwrap();
        // As if OPENVTC_THEME=dracula.
        let mut watcher = Watcher::new(roots.clone(), "dracula");
        assert!(watcher.check().is_none());

        let settings = roots.settings_file().unwrap();
        fs::write(&settings, "theme = \"nord\"\nsomething_else = \"x\"\n").unwrap();
        assert_eq!(
            step(&mut watcher),
            Some(None),
            "still nord: nothing to draw"
        );

        catalog::remember(&roots, "gruvbox-dark").unwrap();
        let theme = step(&mut watcher).flatten().expect("the new choice");
        assert_eq!(theme.id, "gruvbox-dark");
        assert!(watcher.check().is_none());
        let _ = fs::remove_dir_all(base);
    }

    /// Under `auto`, changing the theme it picks for this terminal redraws.
    #[test]
    fn auto_follows_its_own_themes() {
        let (base, roots) = roots("auto");
        catalog::remember_auto(&roots, Some("nord"), Some("nord")).unwrap();
        let mut watcher = Watcher::new(roots.clone(), AUTO_ID);
        catalog::remember_auto(&roots, Some("dracula"), Some("dracula")).unwrap();
        let theme = step(&mut watcher).flatten().expect("auto's theme changed");
        assert_eq!(theme.id, AUTO_ID);
        assert_eq!(theme.name, "Dracula");
        let _ = fs::remove_dir_all(base);
    }

    /// Omarchy switching its current theme, and an edit to the current theme's
    /// colours, are both followed.
    #[test]
    fn omarchy_switching_themes_is_followed() {
        let (base, roots) = roots("omarchy");
        omarchy_theme(&roots, "one", "#111111");
        let two = omarchy_theme(&roots, "two", "#222222");
        let state = roots
            .home
            .as_ref()
            .unwrap()
            .join(".local/state/omarchy/current");
        fs::create_dir_all(&state).unwrap();
        fs::write(state.join("theme.name"), "one\n").unwrap();
        let mut watcher = Watcher::new(roots, "omarchy/current");
        assert!(watcher.check().is_none());

        fs::write(state.join("theme.name"), "two\n").unwrap();
        let theme = step(&mut watcher).flatten().expect("the switch");
        assert_eq!(theme.id, "omarchy/current");
        assert_eq!(theme.palette.background, Some(Color::Rgb(0x22, 0x22, 0x22)));

        fs::write(
            two.join("colors.toml"),
            "background = \"#333333\"\nforeground = \"#eeeeee\"\n",
        )
        .unwrap();
        let theme = step(&mut watcher).flatten().expect("the edit");
        assert_eq!(theme.palette.background, Some(Color::Rgb(0x33, 0x33, 0x33)));
        let _ = fs::remove_dir_all(base);
    }

    /// Earlier Omarchy releases switch by repointing a link.
    #[cfg(unix)]
    #[test]
    fn the_older_omarchy_link_is_followed() {
        let (base, roots) = roots("link");
        let one = omarchy_theme(&roots, "one", "#111111");
        let two = omarchy_theme(&roots, "two", "#222222");
        let current = roots.home.as_ref().unwrap().join(".config/omarchy/current");
        fs::create_dir_all(&current).unwrap();
        std::os::unix::fs::symlink(&one, current.join("theme")).unwrap();
        let mut watcher = Watcher::new(roots, "omarchy/current");
        assert!(watcher.check().is_none());

        fs::remove_file(current.join("theme")).unwrap();
        std::os::unix::fs::symlink(&two, current.join("theme")).unwrap();
        let theme = step(&mut watcher).flatten().expect("the new link");
        assert_eq!(theme.palette.background, Some(Color::Rgb(0x22, 0x22, 0x22)));
        let _ = fs::remove_dir_all(base);
    }
}
