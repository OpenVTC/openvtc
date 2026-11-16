//! Command Line Interface configuration

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
                // Global, so `openvtc health --profile work` works as well as
                // `openvtc --profile work health` — the diagnostics print the
                // former.
                .global(true)
                .help("Config profile to use")
                .default_value("default"),
            Arg::new("monochrome")
                .long("monochrome")
                .global(true)
                .action(clap::ArgAction::SetTrue)
                .help(
                    "Draw without colour, keeping roles apart with bold and underline — \
                     for terminals whose colours wash out or clash. Same as setting \
                     NO_COLOR.",
                ),
            Arg::new("invitation")
                .long("invitation")
                .value_name("FILE")
                .global(true)
                .help(
                    "Path to a Verifiable Invitation Credential (VIC) JSON file \
                     to present when joining a community. The community verifies \
                     it, and on a valid, trusted, unconsumed invitation admits you or \
                     refers the request for review, as its join criteria say.",
                ),
        ])
        .subcommand(
            Command::new("setup")
                .about("Initial configuration of the openvtc tool")
                .args(crate::setup_cmd::args()),
        )
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
                            "A community's DID to include. Repeatable. Communities \
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
        .subcommand(
            Command::new("community")
                .about("The Communities panel without the TUI: join a community")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(crate::state_handler::join_cmd::command()),
        )
        .subcommand(crate::repos_cmd::command())
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
pub fn read_unlock_code_file(path: &str) -> anyhow::Result<zeroize::Zeroizing<String>> {
    use std::io::BufRead;

    // Both buffers are wiped when dropped: this is the unlock passphrase.
    let mut first_line = zeroize::Zeroizing::new(String::new());
    if path == "-" {
        std::io::stdin()
            .lock()
            .read_line(&mut first_line)
            .context("failed to read the unlock code from standard input")?;
    } else {
        let file = std::fs::File::open(path)
            .with_context(|| format!("failed to open unlock code file `{path}`"))?;
        std::io::BufReader::new(file)
            .read_line(&mut first_line)
            .with_context(|| format!("failed to read unlock code file `{path}`"))?;
    }

    let passphrase = zeroize::Zeroizing::new(first_line.trim().to_string());
    if passphrase.is_empty() {
        anyhow::bail!("no unlock code on the first line of `{path}`");
    }
    Ok(passphrase)
}

#[cfg(feature = "openpgp-card")]
pub fn get_user_pin() -> anyhow::Result<SecretString> {
    let user_pin = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Please enter Token User PIN")
        .allow_empty_password(false)
        .interact()?;
    // `allow_empty_password(false)` above means this cannot be empty, so no
    // factory-PIN fallback is needed.
    Ok(SecretString::new(user_pin.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `openvtc …` command the startup diagnostics tell a user to run
    /// must be one this CLI accepts. They are read when something is already
    /// broken; a hint that clap rejects sends the user further astray.
    #[test]
    fn every_command_the_diagnostics_suggest_parses() {
        use openvtc_core::{
            diagnostics::{DiagnosisContext, diagnose},
            errors::{OpenVTCError, SecureStoreFault},
        };

        let store = |fault| OpenVTCError::SecureStore {
            fault,
            profile: "work".into(),
            detail: "x".into(),
        };
        let errors = [
            store(SecureStoreFault::Missing),
            store(SecureStoreFault::Unavailable),
            store(SecureStoreFault::Ambiguous),
            store(SecureStoreFault::Corrupt),
            store(SecureStoreFault::Rejected),
            OpenVTCError::Decrypt("x".into()),
            OpenVTCError::ConfigNotFound("x".into(), std::io::Error::other("x")),
            OpenVTCError::ConfigVersionUnsupported {
                found: 1,
                expected: 2,
            },
            OpenVTCError::Vta("x".into()),
            OpenVTCError::Auth("x".into()),
            OpenVTCError::remote(
                openvtc_core::errors::RemoteService::Vta,
                openvtc_core::errors::RemoteKind::AuthRejected,
                "x",
            ),
            OpenVTCError::remote(
                openvtc_core::errors::RemoteService::Vta,
                openvtc_core::errors::RemoteKind::Timeout,
                "x",
            ),
            OpenVTCError::Resolver("x".into()),
            OpenVTCError::Config("x".into()),
        ];

        let mut commands = Vec::new();
        for err in &errors {
            let d = diagnose(err, &DiagnosisContext::new("work"));
            commands.extend(
                d.checks
                    .iter()
                    .filter(|c| c.starts_with("openvtc "))
                    .cloned(),
            );
            for text in d.remedies.iter().chain([&d.cause, &d.headline]) {
                // Backticked spans: every odd-numbered piece.
                for span in text.split('`').skip(1).step_by(2) {
                    if span == "openvtc" || span.starts_with("openvtc ") {
                        commands.push(span.to_string());
                    }
                }
            }
        }
        assert!(!commands.is_empty(), "no commands found to check");
        for command in commands {
            // Drop a trailing shell comment, then split on whitespace (no
            // quoting is used in these hints).
            let words: Vec<&str> = command
                .split('#')
                .next()
                .unwrap()
                .split_whitespace()
                .collect();
            assert!(
                cli().try_get_matches_from(&words).is_ok(),
                "diagnostics suggest `{command}`, which the CLI rejects"
            );
        }
    }

    #[test]
    fn profile_is_accepted_before_or_after_a_subcommand() {
        for args in [
            &["openvtc", "--profile", "work", "health"][..],
            &["openvtc", "health", "--profile", "work"][..],
        ] {
            // `resolve_profile` reads the top-level matches.
            let m = cli().try_get_matches_from(args).unwrap();
            assert_eq!(m.get_one::<String>("profile").unwrap(), "work");
        }
    }

    /// `--monochrome` is a global switch: accepted before or after a
    /// subcommand, and off unless given.
    #[test]
    fn monochrome_is_a_global_switch() {
        assert!(
            !super::cli()
                .try_get_matches_from(["openvtc"])
                .unwrap()
                .get_flag("monochrome")
        );
        assert!(
            super::cli()
                .try_get_matches_from(["openvtc", "--monochrome"])
                .unwrap()
                .get_flag("monochrome")
        );
        let m = super::cli()
            .try_get_matches_from(["openvtc", "setup", "--monochrome"])
            .unwrap();
        assert!(m.get_flag("monochrome"));
    }

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
            read_unlock_code_file(&path.to_string_lossy())
                .expect("the file reads")
                .as_str(),
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
