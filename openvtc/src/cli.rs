/*! Command Line Interface configuration
*/

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
                "Unlock passphrase for the encrypted config. \
                     WARNING: command-line arguments are visible to other \
                     local users via the process list (`ps`, /proc); prefer \
                     the interactive prompt on shared systems.",
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
    fn no_subcommand_is_accepted() {
        // Bare `openvtc` (launch the TUI) must still parse cleanly.
        cli()
            .try_get_matches_from(["openvtc"])
            .expect("bare invocation should parse");
    }
}
