/*! Command Line Interface configuration
*/

use anyhow::Context;
use clap::{Arg, Command};
#[cfg(feature = "openpgp-card")]
use dialoguer::{Password, theme::ColorfulTheme};
#[cfg(feature = "openpgp-card")]
use secrecy::SecretString;

pub fn cli() -> Command {
    // Full CLI Set
    Command::new("openvtc")
        .about("Open Verifiable Trust Communities")
        .version(env!("CARGO_PKG_VERSION"))
        .subcommand_required(false)
        .arg_required_else_help(false)
        .args([
            Arg::new("unlock-code").short('u').long("unlock-code").help(
                "DEPRECATED: use --unlock-code-file instead. Unlock passphrase \
                     for the encrypted config. WARNING: command-line arguments \
                     are visible to other local users via the process list \
                     (`ps`, /proc); prefer --unlock-code-file or the \
                     interactive prompt on shared systems.",
            ),
            Arg::new("unlock-code-file")
                .long("unlock-code-file")
                .value_name("PATH")
                // One passphrase, one source. Taking both and silently
                // preferring one is how the wrong one gets used quietly.
                .conflicts_with("unlock-code")
                .help(
                    "Read the unlock passphrase from the first line of PATH, or \
                     from standard input when PATH is `-`. Unlike --unlock-code \
                     this keeps the passphrase out of the process list.",
                ),
            Arg::new("profile")
                .short('p')
                .long("profile")
                .help("Config profile to use")
                .default_value("default"),
            Arg::new("invitation")
                .long("invitation")
                .value_name("FILE")
                .help(
                    "Path to a Verifiable Invitation Credential (VIC) JSON file \
                     to present when joining a community. The community verifies \
                     it and auto-admits on a valid, trusted, unconsumed invitation.",
                ),
        ])
        .subcommand(Command::new("setup").about("Initial configuration of the openvtc tool"))
        .subcommand(
            Command::new("health")
                .about(
                    "Resolve the messaging chain (personas, VTA, mediators, VTCs) and \
                     report what each DID advertises, which transport each pair would \
                     negotiate, and whether the hosts answer",
                )
                .long_about(
                    "Map the messaging path between this client and a community.\n\n\
                     For every DID involved — each persona, the VTA, every mediator, and \
                     each VTC — this resolves the DID document, prints its service \
                     definitions verbatim, and probes any public HTTPS transport URLs \
                     (plaintext and non-public ones are listed, not dialled; redirects \
                     are not followed). It then runs \
                     the same TSP > DIDComm > REST negotiation a real send performs, so \
                     the reported transport is the one that would actually be used.\n\n\
                     Parties may sit behind different mediators; that is supported and \
                     is reported rather than assumed away.\n\n\
                     Read-only: nothing is sent, so it is safe to run against a live \
                     deployment while a join is stuck. Exits non-zero if any DID fails \
                     to resolve or any pair shares no transport.",
                )
                .args([
                    Arg::new("vtc")
                        .long("vtc")
                        .value_name("DID")
                        .action(clap::ArgAction::Append)
                        .help(
                            "A community VTC DID to include. Repeatable. Communities \
                             already in the account are included automatically; use this \
                             to check one before joining, or when the account cannot be \
                             loaded.",
                        ),
                    Arg::new("json")
                        .long("json")
                        .action(clap::ArgAction::SetTrue)
                        .help("Emit the report as JSON instead of a rendered map"),
                    Arg::new("recoverable")
                        .long("recoverable")
                        .action(clap::ArgAction::SetTrue)
                        .help(
                            "Also report whether this account could be rebuilt from its \
                             Trust Context if this machine were lost. Read-only.",
                        ),
                    Arg::new("allow-private-probes")
                        .long("allow-private-probes")
                        .action(clap::ArgAction::SetTrue)
                        .help(
                            "Also probe transport URLs that are plaintext or that point at \
                             loopback, private or link-local addresses. By default those are \
                             listed but not dialled, because the URLs come from DID documents \
                             anyone can publish. For local development stacks only.",
                        ),
                ]),
        )
        .subcommand(crate::theme_cmd::command())
}

/// Read an unlock passphrase from `path`, or from standard input when `path` is
/// `-`.
///
/// Only the first line is taken, and it is trimmed. A trailing newline is what
/// every editor and every `echo` leaves behind, and a passphrase whose ends are
/// whitespace cannot be told from one whose ends are not by the person typing it
/// at the prompt — so both ends go, and anything after the first line is not
/// part of the passphrase.
///
/// An empty first line is an error rather than an empty passphrase: it almost
/// always means the file was not written, or was written somewhere else.
pub fn read_unlock_code_file(path: &str) -> anyhow::Result<String> {
    use std::io::BufRead;

    let mut first_line = String::new();
    if path == "-" {
        std::io::stdin()
            .lock()
            .read_line(&mut first_line)
            .context("failed to read the unlock passphrase from standard input")?;
    } else {
        let file = std::fs::File::open(path)
            .with_context(|| format!("failed to open unlock passphrase file `{path}`"))?;
        std::io::BufReader::new(file)
            .read_line(&mut first_line)
            .with_context(|| format!("failed to read unlock passphrase file `{path}`"))?;
    }

    let passphrase = first_line.trim().to_string();
    if passphrase.is_empty() {
        anyhow::bail!("no unlock passphrase on the first line of `{path}`");
    }
    Ok(passphrase)
}

#[cfg(feature = "openpgp-card")]
pub fn get_user_pin() -> anyhow::Result<SecretString> {
    let user_pin = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Please enter Token User PIN")
        .allow_empty_password(false)
        .interact()?;
    if user_pin.is_empty() {
        Ok(SecretString::new("123456".into()))
    } else {
        Ok(SecretString::new(user_pin.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_definition_is_valid() {
        // Catches malformed arg/subcommand configuration at test time.
        cli().debug_assert();
    }

    #[test]
    fn unknown_subcommand_is_rejected() {
        // `allow_external_subcommands` is intentionally NOT set: an unknown
        // subcommand must produce a clap error (with a `--help` suggestion)
        // rather than silently falling through to the TUI.
        let err = cli()
            .try_get_matches_from(["openvtc", "status"])
            .expect_err("unknown subcommand `status` should be rejected");
        assert_eq!(
            err.kind(),
            clap::error::ErrorKind::InvalidSubcommand,
            "expected an InvalidSubcommand error, got: {err}"
        );
    }

    #[test]
    fn version_flag_succeeds() {
        let err = cli()
            .try_get_matches_from(["openvtc", "--version"])
            .expect_err("--version short-circuits parsing");
        // `--version` is reported by clap as a (successful) DisplayVersion error.
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
        assert!(
            err.to_string().contains(env!("CARGO_PKG_VERSION")),
            "version output should contain the package version"
        );
    }

    #[test]
    fn setup_subcommand_is_accepted() {
        let matches = cli()
            .try_get_matches_from(["openvtc", "setup"])
            .expect("`setup` is a valid subcommand");
        assert_eq!(matches.subcommand_name(), Some("setup"));
    }

    #[test]
    fn theme_subcommands_are_accepted() {
        let matches = cli()
            .try_get_matches_from(["openvtc", "theme", "import", "nvim:tokyonight", "--use"])
            .expect("`theme import` is a valid subcommand");
        let (_, theme) = matches.subcommand().expect("theme");
        let (sub, import) = theme.subcommand().expect("import");
        assert_eq!(sub, "import");
        assert!(import.get_flag("use"));
        assert!(
            cli()
                .try_get_matches_from(["openvtc", "theme", "set"])
                .is_err(),
            "`set` needs a theme id"
        );
    }

    #[test]
    fn theme_set_auto_and_export_are_accepted() {
        let matches = cli()
            .try_get_matches_from([
                "openvtc", "theme", "set", "auto", "--dark", "nord", "--light", "dracula",
            ])
            .expect("`theme set auto --dark --light` is valid");
        let (_, theme) = matches.subcommand().expect("theme");
        let (_, set) = theme.subcommand().expect("set");
        assert_eq!(
            set.get_one::<String>("dark").map(String::as_str),
            Some("nord")
        );
        assert_eq!(
            set.get_one::<String>("light").map(String::as_str),
            Some("dracula")
        );

        let matches = cli()
            .try_get_matches_from([
                "openvtc",
                "theme",
                "export",
                "nord",
                "--format",
                "kitty",
                "-o",
                "nord.conf",
            ])
            .expect("`theme export` is valid");
        let (_, theme) = matches.subcommand().expect("theme");
        let (_, export) = theme.subcommand().expect("export");
        assert_eq!(
            export.get_one::<String>("format").map(String::as_str),
            Some("kitty")
        );
        assert_eq!(
            export.get_one::<String>("output").map(String::as_str),
            Some("nord.conf")
        );

        let matches = cli()
            .try_get_matches_from(["openvtc", "theme", "export", "nord"])
            .expect("the format defaults");
        let (_, theme) = matches.subcommand().expect("theme");
        let (_, export) = theme.subcommand().expect("export");
        assert_eq!(
            export.get_one::<String>("format").map(String::as_str),
            Some("openvtc")
        );
        assert!(
            cli()
                .try_get_matches_from(["openvtc", "theme", "export", "nord", "--format", "vim"])
                .is_err(),
            "an unknown format is refused"
        );
    }

    #[test]
    fn unlock_code_file_accepts_stdin() {
        let matches = cli()
            .try_get_matches_from(["openvtc", "--unlock-code-file", "-"])
            .expect("`--unlock-code-file -` is valid");
        assert_eq!(
            matches
                .get_one::<String>("unlock-code-file")
                .map(String::as_str),
            Some("-"),
            "`-` reaches the reader as-is, which is how it means standard input"
        );
    }

    #[test]
    fn unlock_code_and_unlock_code_file_conflict() {
        let err = cli()
            .try_get_matches_from([
                "openvtc",
                "--unlock-code",
                "from-argv",
                "--unlock-code-file",
                "-",
            ])
            .expect_err("two sources for one passphrase must be refused");
        assert_eq!(
            err.kind(),
            clap::error::ErrorKind::ArgumentConflict,
            "expected an ArgumentConflict, got: {err}"
        );
    }

    #[test]
    fn unlock_code_file_reads_the_first_line_trimmed() {
        let dir = std::env::temp_dir().join(format!("openvtc-unlockfile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create the test directory");

        let path = dir.join("passphrase");
        // The trailing newline an editor leaves, surrounding whitespace, and a
        // second line that is not part of the passphrase.
        std::fs::write(&path, b"  correct horse battery staple  \nignored\n")
            .expect("write the passphrase file");
        assert_eq!(
            read_unlock_code_file(&path.to_string_lossy()).expect("the file reads"),
            "correct horse battery staple"
        );

        let empty = dir.join("empty");
        std::fs::write(&empty, b"\n").expect("write the empty file");
        assert!(
            read_unlock_code_file(&empty.to_string_lossy()).is_err(),
            "an empty first line is an error, not an empty passphrase"
        );

        assert!(
            read_unlock_code_file(&dir.join("missing").to_string_lossy()).is_err(),
            "a path that does not exist is an error"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_subcommand_is_accepted() {
        // Bare `openvtc` (launch the TUI) must still parse cleanly.
        cli()
            .try_get_matches_from(["openvtc"])
            .expect("bare invocation should parse");
    }
}
