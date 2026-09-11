//! `openvtc theme`: list, choose, import and create themes for the TUI.
//!
//! Runs before any profile is opened: how the TUI looks belongs to the person,
//! not to an account, so no unlock is needed to change it.

use std::path::Path;

use anyhow::{Result, bail};
use clap::{Arg, ArgAction, ArgMatches, Command};
use console::style;

use crate::colors::{CLI_BLUE, CLI_ORANGE, CLI_PURPLE};
use crate::theme::catalog::{self, Roots};
use crate::theme::{builtin, import, nvim};

/// The `theme` subcommand's definition.
pub fn command() -> Command {
    Command::new("theme")
        .about("List, choose, import and create themes for the TUI")
        .long_about(
            "Themes colour the TUI. Choose one here or under Settings → Theme, where \
             moving through the list previews each one.\n\n\
             Themes come from four places: those built in; your own OpenVTC theme files; \
             Omarchy's themes, read in place (omarchy/current follows whichever is \
             current); and anything you import — a base16 or base24 scheme, an Omarchy \
             theme directory, an Alacritty, Kitty or Ghostty colour file, or a Neovim \
             colorscheme (nvim:<name>).",
        )
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(Command::new("list").about("List the themes you can choose"))
        .subcommand(
            Command::new("set")
                .about("Choose the theme the TUI uses")
                .arg(
                    Arg::new("id")
                        .required(true)
                        .help("A theme id from `openvtc theme list`"),
                ),
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
                        .help("The theme to start from (default: the one in use)"),
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
        Some(("set", args)) => {
            let id = args.get_one::<String>("id").map_or("", String::as_str);
            let theme = catalog::load(&roots, id)?;
            catalog::remember(&roots, &theme.id)?;
            println!(
                "{} {}",
                style("The TUI now uses").color256(CLI_BLUE),
                style(&theme.name).color256(CLI_PURPLE)
            );
            Ok(())
        }
        Some(("import", args)) => import_theme(&roots, args),
        Some(("new", args)) => new_theme(&roots, args),
        _ => bail!("choose one of: list, set, import, new"),
    }
}

fn list(roots: &Roots) {
    let in_use = catalog::selected(roots).unwrap_or_else(|| builtin::DEFAULT_ID.to_string());
    println!(
        "{}",
        style("Themes — choose with `openvtc theme set <id>` or under Settings → Theme")
            .color256(CLI_BLUE)
    );
    for entry in catalog::list(roots) {
        let mark = if entry.id == in_use { "✓" } else { " " };
        println!(
            "  {mark} {:<28} {:<34} {}",
            style(&entry.id).color256(CLI_PURPLE),
            entry.name,
            style(entry.source.label()).dim()
        );
    }
    if let Some(dir) = roots.themes_dir() {
        println!(
            "{} {}",
            style("Your themes live in").color256(CLI_BLUE),
            dir.display()
        );
    }
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
        style("Imported").color256(CLI_BLUE),
        style(&theme.name).color256(CLI_PURPLE),
        style("as").color256(CLI_BLUE),
        style(&id).color256(CLI_PURPLE)
    );
    println!("  {}", path.display());
    if args.get_flag("use") {
        catalog::remember(roots, &id)?;
        println!("{}", style("and chose it for the TUI.").color256(CLI_BLUE));
    } else {
        println!(
            "{}",
            style(format!(
                "Edit the file to adjust it, and choose it with `openvtc theme set {id}`."
            ))
            .color256(CLI_ORANGE)
        );
    }
    Ok(())
}

fn new_theme(roots: &Roots, args: &ArgMatches) -> Result<()> {
    let name = args.get_one::<String>("name").map_or("", String::as_str);
    let from = args
        .get_one::<String>("from")
        .cloned()
        .or_else(|| catalog::selected(roots))
        .unwrap_or_else(|| builtin::DEFAULT_ID.to_string());
    let mut theme = catalog::load(roots, &from)?;
    theme.name = name.to_string();
    let (id, path) = catalog::install(roots, &theme)?;
    println!(
        "{} {} {}",
        style("Started").color256(CLI_BLUE),
        style(&id).color256(CLI_PURPLE),
        style(format!("from {from}:")).color256(CLI_BLUE)
    );
    println!("  {}", path.display());
    println!(
        "{}",
        style(format!(
            "Edit its colours, then choose it with `openvtc theme set {id}` — or under \
             Settings → Theme, where r reloads after an edit."
        ))
        .color256(CLI_ORANGE)
    );
    Ok(())
}
