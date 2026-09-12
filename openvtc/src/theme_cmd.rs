//! `openvtc theme`: list, choose, import, create and export themes for the TUI.
//!
//! Runs before any profile is opened: how the TUI looks belongs to the person,
//! not to an account, so no unlock is needed to change it.

use std::path::Path;

use anyhow::{Context, Result, bail};
use clap::{Arg, ArgAction, ArgMatches, Command, builder::PossibleValuesParser};
use console::style;

use crate::colors::{CLI_CAUTION, CLI_EXAMPLE, CLI_INFO, Themed};
use crate::theme::catalog::{self, AUTO_ID, Roots};
use crate::theme::export::{self, Format};
use crate::theme::{OVERRIDE_ENV, Theme, contrast, import, nvim, rgb};

/// The `theme` subcommand's definition.
pub fn command() -> Command {
    Command::new("theme")
        .about("List, choose, import, create and export themes for the TUI")
        .long_about(
            "Themes colour the TUI. Choose one here or under Settings → Theme, where \
             moving through the list previews each one. A running TUI picks up a new \
             choice, or an edit to the theme in use, within a second.\n\n\
             Themes come from four places: those built in; your own OpenVTC theme files; \
             Omarchy's themes, read in place (omarchy/current follows whichever is \
             current); and anything you import — a base16 or base24 scheme, an Omarchy \
             theme directory, an Alacritty, Kitty or Ghostty colour file, or a Neovim \
             colorscheme (nvim:<name>). `auto` follows your terminal's background.\n\n\
             OPENVTC_THEME=<id> chooses a theme for one session, and NO_COLOR draws \
             without colour.",
        )
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(Command::new("list").about("List the themes you can choose"))
        .subcommand(
            Command::new("set")
                .about("Choose the theme the TUI uses")
                .long_about(
                    "Choose the theme the TUI uses.\n\n\
                     `auto` follows your terminal's background: OpenVTC asks the terminal \
                     when it starts, and draws with one theme on a dark background and \
                     another on a light one. --dark and --light choose those two.",
                )
                .args([
                    Arg::new("id")
                        .required(true)
                        .help("A theme id from `openvtc theme list`, or auto"),
                    Arg::new("dark")
                        .long("dark")
                        .value_name("ID")
                        .help("With auto, the theme for a dark terminal (default: openvtc)"),
                    Arg::new("light")
                        .long("light")
                        .value_name("ID")
                        .help("With auto, the theme for a light terminal (default: catppuccin-latte)"),
                ]),
        )
        .subcommand(
            Command::new("import")
                .about("Import a theme from another tool into your themes")
                .long_about(
                    "Import a theme into your themes directory as an OpenVTC theme file, \
                     which you can then edit.\n\n\
                     SOURCE is one of:\n  \
                     a base16/base24 scheme (.yaml)\n  \
                     an Omarchy theme directory\n  \
                     an Alacritty (.toml), Kitty (.conf) or Ghostty colour file\n  \
                     nvim:<colorscheme> — any colorscheme your Neovim can load",
                )
                .args([
                    Arg::new("source")
                        .required(true)
                        .value_name("SOURCE")
                        .help("A theme file or directory, or nvim:<colorscheme>"),
                    Arg::new("name")
                        .long("name")
                        .value_name("NAME")
                        .help("Name the imported theme"),
                    Arg::new("use")
                        .long("use")
                        .action(ArgAction::SetTrue)
                        .help("Also choose it"),
                    Arg::new("clean")
                        .long("clean")
                        .action(ArgAction::SetTrue)
                        .help("With nvim:, skip your Neovim configuration (bundled colorschemes only)"),
                ]),
        )
        .subcommand(
            Command::new("new")
                .about("Start your own theme from an existing one")
                .args([
                    Arg::new("name").required(true).help("Your theme's name"),
                    Arg::new("from")
                        .long("from")
                        .value_name("ID")
                        .help("The theme to start from (default: the one chosen)"),
                ]),
        )
        .subcommand(
            Command::new("export")
                .about("Write a theme out for another tool")
                .long_about(
                    "Write a theme out in another tool's format, so a theme made in OpenVTC \
                     can colour your terminal, editor or desktop too. Prints it unless \
                     --output is given.\n\n\
                     FORMAT is one of:\n  \
                     openvtc    an OpenVTC theme file\n  \
                     base16     a base16 scheme (.yaml)\n  \
                     omarchy    an Omarchy theme: with --output, a theme directory \
                     (colors.toml, and light.mode for a light theme), unless the path ends \
                     in .toml\n  \
                     alacritty  an Alacritty colour file (.toml)\n  \
                     kitty      a Kitty colour file (.conf)",
                )
                .args([
                    Arg::new("id")
                        .required(true)
                        .help("A theme id from `openvtc theme list`"),
                    Arg::new("format")
                        .long("format")
                        .value_name("FORMAT")
                        .value_parser(PossibleValuesParser::new(Format::NAMES))
                        .default_value("openvtc")
                        .help("The format to write"),
                    Arg::new("output")
                        .long("output")
                        .short('o')
                        .value_name("PATH")
                        .help("Write to PATH instead of printing"),
                ]),
        )
}

/// Run `openvtc theme …`.
///
/// # Errors
///
/// A theme that cannot be found, read, imported or written.
pub fn run(matches: &ArgMatches) -> Result<()> {
    let roots = Roots::from_env();
    match matches.subcommand() {
        Some(("list", _)) => {
            list(&roots);
            Ok(())
        }
        Some(("set", args)) => set(&roots, args),
        Some(("import", args)) => import_theme(&roots, args),
        Some(("new", args)) => new_theme(&roots, args),
        Some(("export", args)) => export_theme(&roots, args),
        _ => bail!("choose one of: list, set, import, new, export"),
    }
}

/// `OPENVTC_THEME` as set in this shell, if it is.
fn session_override() -> Option<String> {
    std::env::var(OVERRIDE_ENV)
        .ok()
        .filter(|id| !id.trim().is_empty())
}

/// Tell the person when this shell's `OPENVTC_THEME` will outrank their choice.
fn note_override() {
    if let Some(id) = session_override() {
        println!(
            "{}",
            style(format!(
                "{OVERRIDE_ENV}={id} is set in this shell, so a TUI started from it uses that \
                 theme instead."
            ))
            .themed(CLI_CAUTION)
        );
    }
}

fn set(roots: &Roots, args: &ArgMatches) -> Result<()> {
    let id = args.get_one::<String>("id").map_or("", String::as_str);
    let dark = args.get_one::<String>("dark").map(String::as_str);
    let light = args.get_one::<String>("light").map(String::as_str);
    if id != AUTO_ID {
        if dark.is_some() || light.is_some() {
            bail!(
                "--dark and --light choose the themes auto picks between: \
                 `openvtc theme set auto --dark <id> --light <id>`"
            );
        }
        let theme = catalog::load(roots, id)?;
        catalog::remember(roots, &theme.id)?;
        println!(
            "{} {}",
            style("The TUI now uses").themed(CLI_INFO),
            style(&theme.name).themed(CLI_EXAMPLE)
        );
        note_override();
        return Ok(());
    }

    for (flag, chosen) in [("--dark", dark), ("--light", light)] {
        if let Some(chosen) = chosen {
            if chosen == AUTO_ID {
                bail!("{flag} needs a theme of its own, not auto");
            }
            catalog::load(roots, chosen).with_context(|| format!("{flag} {chosen}"))?;
        }
    }
    catalog::remember_auto(roots, dark, light)?;
    let choice = catalog::choice(roots);
    let name = |id: &str| catalog::load(roots, id).map_or_else(|_| id.to_string(), |t| t.name);
    println!(
        "{} {} {} {} {}",
        style("The TUI now follows your terminal:").themed(CLI_INFO),
        style(name(&choice.auto_dark)).themed(CLI_EXAMPLE),
        style("on a dark background,").themed(CLI_INFO),
        style(name(&choice.auto_light)).themed(CLI_EXAMPLE),
        style("on a light one.").themed(CLI_INFO)
    );
    note_override();
    Ok(())
}

fn list(roots: &Roots) {
    let in_use = catalog::choice(roots).theme;
    println!(
        "{}",
        style("Themes — choose with `openvtc theme set <id>` or under Settings → Theme")
            .themed(CLI_INFO)
    );
    for entry in catalog::list(roots) {
        let mark = if entry.id == in_use { "✓" } else { " " };
        println!(
            "  {mark} {:<28} {:<34} {}",
            style(&entry.id).themed(CLI_EXAMPLE),
            entry.name,
            style(entry.source.label()).dim()
        );
    }
    if let Some(dir) = roots.themes_dir() {
        println!(
            "{} {}",
            style("Your themes live in").themed(CLI_INFO),
            dir.display()
        );
    }
    note_override();
}

/// A warning for a theme whose text is hard to read on its own background.
fn readability(theme: &Theme) -> Option<String> {
    let background = rgb(theme.palette.background?)?;
    let ratio = contrast(rgb(theme.palette.text)?, background);
    (ratio < 4.5).then(|| {
        format!(
            "Its text is {ratio:.1}:1 against its background, under the 4.5:1 that reads \
             comfortably; consider a lighter or darker text colour."
        )
    })
}

fn import_theme(roots: &Roots, args: &ArgMatches) -> Result<()> {
    let source = args.get_one::<String>("source").map_or("", String::as_str);
    let mut theme = match source.strip_prefix("nvim:") {
        Some(colorscheme) => nvim::import(colorscheme, args.get_flag("clean"))?,
        None => import::from_path(Path::new(source))?,
    };
    if let Some(name) = args.get_one::<String>("name") {
        theme.name.clone_from(name);
    }
    let (id, path) = catalog::install(roots, &theme)?;
    println!(
        "{} {} {} {}",
        style("Imported").themed(CLI_INFO),
        style(&theme.name).themed(CLI_EXAMPLE),
        style("as").themed(CLI_INFO),
        style(&id).themed(CLI_EXAMPLE)
    );
    println!("  {}", path.display());
    if let Some(warning) = readability(&theme) {
        println!("{}", style(warning).themed(CLI_CAUTION));
    }
    if args.get_flag("use") {
        catalog::remember(roots, &id)?;
        println!("{}", style("and chose it for the TUI.").themed(CLI_INFO));
        note_override();
    } else {
        println!(
            "{}",
            style(format!(
                "Edit the file to adjust it, and choose it with `openvtc theme set {id}`."
            ))
            .themed(CLI_CAUTION)
        );
    }
    Ok(())
}

fn new_theme(roots: &Roots, args: &ArgMatches) -> Result<()> {
    let name = args.get_one::<String>("name").map_or("", String::as_str);
    let from = args
        .get_one::<String>("from")
        .cloned()
        .unwrap_or_else(|| catalog::choice(roots).theme);
    let mut theme = catalog::load(roots, &from)?;
    theme.name = name.to_string();
    let (id, path) = catalog::install(roots, &theme)?;
    println!(
        "{} {} {}",
        style("Started").themed(CLI_INFO),
        style(&id).themed(CLI_EXAMPLE),
        style(format!("from {from}:")).themed(CLI_INFO)
    );
    println!("  {}", path.display());
    println!(
        "{}",
        style(format!(
            "Edit its colours, then choose it with `openvtc theme set {id}` — or under \
             Settings → Theme, where r reloads after an edit."
        ))
        .themed(CLI_CAUTION)
    );
    Ok(())
}

fn export_theme(roots: &Roots, args: &ArgMatches) -> Result<()> {
    let id = args.get_one::<String>("id").map_or("", String::as_str);
    let format = args
        .get_one::<String>("format")
        .and_then(|name| Format::parse(name))
        .unwrap_or(Format::Openvtc);
    let theme = catalog::load(roots, id)?;
    match args.get_one::<String>("output") {
        // Printed bare, so it can be piped or redirected as it is.
        None => print!("{}", export::render(&theme, format)),
        Some(output) => {
            let file = export::write(&theme, format, Path::new(output))?;
            println!(
                "{} {} {} {}",
                style("Exported").themed(CLI_INFO),
                style(&theme.name).themed(CLI_EXAMPLE),
                style("to").themed(CLI_INFO),
                file.display()
            );
        }
    }
    Ok(())
}
