# OpenVTC Command Reference

Command reference for the `openvtc` CLI. The definitions live in
`openvtc/src/cli.rs` and the `*_cmd.rs` files beside it; `openvtc --help` and
`openvtc <command> --help` print the same information from the build you have.

Running `openvtc` with no subcommand launches the terminal UI (TUI). Most work
happens there. The subcommands below cover setup, diagnostics, themes, and a
headless form of joining a community and working with its repositories.

## Contents

- [Quick reference](#quick-reference)
- [Global options](#global-options)
- [Environment variables](#environment-variables)
- [openvtc (no subcommand)](#openvtc-no-subcommand)
- [openvtc setup](#openvtc-setup)
- [openvtc health](#openvtc-health)
- [openvtc theme](#openvtc-theme)
- [openvtc community join](#openvtc-community-join)
- [openvtc repo](#openvtc-repo)
- [Profiles](#profiles)

## Quick reference

| Command | Description |
| --- | --- |
| `openvtc` | Launch the TUI. Starts the setup wizard if the profile has no config. |
| `openvtc setup` | Run the setup wizard, or set up headless with `--vta-did`. |
| `openvtc health` | Report on the messaging chain: personas, VTA, mediators, communities. Read-only. |
| `openvtc theme list\|set\|import\|new\|export` | Manage TUI themes. |
| `openvtc community join <COMMUNITY_DID>` | Join a community without the TUI and wait for the verdict. |
| `openvtc repo list\|clone\|sign` | The Repos view without the TUI. |
| `openvtc --help` | Print help. |
| `openvtc --version` | Print the version. |

## Global options

| Option | Description |
| --- | --- |
| `-p, --profile <NAME>` | Config profile to use (default: `default`). Accepted before or after the subcommand. |
| `--unlock-code-file <PATH>` | Read the unlock passphrase from the first line of `PATH`, or from standard input when `PATH` is `-`. Keeps the passphrase out of the process list. |
| `-u, --unlock-code <CODE>` | **Deprecated.** Use `--unlock-code-file`. The passphrase is visible to other local users in the process list (`ps`, `/proc`). Cannot be combined with `--unlock-code-file`. |
| `--monochrome` | Draw without colour, keeping roles apart with bold and underline. Same as setting `NO_COLOR`. |
| `--invitation <FILE>` | A Verifiable Invitation Credential (VIC) JSON file to present when joining a community. Checked before anything else runs. |
| `-h, --help` | Print help. |
| `-V, --version` | Print the version. |

With neither unlock option, OpenVTC prompts for the passphrase when the profile
needs one.

## Environment variables

None of these appear in `--help`.

| Variable | Effect |
| --- | --- |
| `OPENVTC_CONFIG_PROFILE` | Profile to use. If `--profile` names a different, non-default profile, the flag wins and a warning is printed. |
| `OPENVTC_CONFIG_PATH` | Directory that holds config files. See [Profiles](#profiles). |
| `OPENVTC_SECURE_STORE` | Credential store. Unset uses the OS store; `file` selects the encrypted file store (Linux). See the [`openvtc` README](../openvtc/README.md#secure-storage). |
| `OPENVTC_THEME` | Theme for one session. |
| `OPENVTC_NVIM` | Path to Neovim for `theme import nvim:<name>`, if `nvim` is not on `PATH`. |
| `NO_COLOR` | Draw without colour. |
| `OPENVTC_DEBUG_LOG` | Write debug logs to this file (appended; moved to `<path>.1` at startup once over 50 MiB). |
| `OPENVTC_FRIENDLY_NAME` | Display name override. |
| `OPENVTC_VTA_URL`, `OPENVTC_VTA_DID`, `OPENVTC_MEDIATOR_DID` | Honoured only by builds with the `dev-overrides` feature. Release builds ignore them. |

There are no shell completions.

## openvtc (no subcommand)

Launches the TUI. If the selected profile has no config, the TUI opens the
setup wizard.

The main menu holds: Communities, Inbox, My Relationships, My Credentials,
Vetting, My Identity, Settings, VTA Service, TSP Relationships, Logs and
Help / Status. A community's repositories are in its Repos view (`r` on a
community).

```bash
openvtc
openvtc -p profile-1
openvtc --unlock-code-file ~/.config/openvtc/passphrase
```

## openvtc setup

Runs the setup wizard. It offers two routes:

- **New profile.** Connect to your Verifiable Trust Agent (VTA), authorise
  OpenVTC from your Personal Network Manager (PNM), optionally set up a
  hardware token, and set an unlock code. No DID is created yet; a persona is
  created when you join your first community.
- **Recover from backup.** Restore a profile from a file made with Settings →
  Export Config. See [Backup and Restore](./backup-restore.md).

There is no `setup import` subcommand.

### Headless setup

`--vta-did` runs the new-profile route without the wizard. It prints the PNM
command for the VTA administrator to run, waits for the grant, then saves the
account. It needs `--unlock-code-file`.

| Option | Description |
| --- | --- |
| `--vta-did <DID>` | Create a new account on this VTA. |
| `--unlock-code-file <PATH>` | The new unlock passphrase, from the first line of `PATH` (or standard input for `-`). At least 8 characters. |
| `--context <ID>` | The VTA Trust Context to provision into. |
| `--wait <DURATION>` | How long to wait for the grant, e.g. `90s`, `30m`, `1h` (default `30m`). The grant itself lasts one hour. |

```bash
openvtc setup
openvtc -p profile-1 setup
openvtc setup --vta-did did:webvh:... --unlock-code-file ./passphrase
```

## openvtc health

Maps the messaging path between this client and a community. For every DID
involved (each persona, the VTA, every mediator and each community VTC) it
resolves the DID document, prints its service definitions, and probes public
HTTPS transport URLs. It then runs the same TSP > DIDComm > REST negotiation a
real send performs and reports the transport that would be used. It also
reports which credential store is in use.

Nothing is sent, and it does not take the profile lock, so it is safe to run
while a TUI is open. It exits non-zero if any DID fails to resolve or any pair
shares no transport.

| Option | Description |
| --- | --- |
| `--vtc <DID>` | A community VTC DID to include. Repeatable. Communities already in the account are included automatically. |
| `--json` | Print the report as JSON. |
| `--recoverable` | Also report whether the account could be rebuilt from its VTA Trust Context if this machine were lost. |
| `--allow-private-probes` | Also probe plaintext URLs and ones that point at loopback, private or link-local addresses. For local development only. |

## openvtc theme

Lists, chooses, imports, creates and exports TUI themes. See
[Themes](./themes.md) for the full guide.

| Command | Description |
| --- | --- |
| `theme list` | List the themes you can choose. |
| `theme set <ID> [--dark <ID>] [--light <ID>]` | Choose a theme. `auto` follows the terminal background; `--dark` and `--light` pick the two themes. |
| `theme import <SOURCE> [--name <NAME>] [--use] [--clean]` | Import a base16/base24 scheme, Omarchy theme directory, Alacritty, Kitty or Ghostty colour file, or `nvim:<colorscheme>`. |
| `theme new <NAME> [--from <ID>]` | Start your own theme from an existing one. |
| `theme export <ID> [--format <FORMAT>] [-o, --output <PATH>]` | Write a theme for another tool: `openvtc`, `base16`, `omarchy`, `alacritty` or `kitty`. |

## openvtc community join

Sends a join request to a community and waits, without the TUI, for the
verdict. On admission the membership credentials are stored and the account is
saved. It exits non-zero on rejection, timeout or any failure.

```bash
openvtc community join <COMMUNITY_DID> [options]
```

| Option | Description |
| --- | --- |
| `--persona <NAME>` | Join as this persona: its DID, label or agent name. |
| `--new-persona <NAME>` | Create a new persona with this label and join as it. |
| `--accept-directory <DIGEST>` | Accept the community's member-directory statement with this digest. The statement and digest are printed when the community needs it. |
| `--wait <DURATION>` | How long to wait for the verdict, e.g. `90s`, `30m`, `2h` (default `30m`). |

Without `--persona` or `--new-persona`, the only persona in the account is used;
with none, a new one is created. Pass `--invitation <FILE>` (before or after
`join`) to present an invitation; without one this is an open request that the
community's moderators decide.

## openvtc repo

The Repos view without the TUI. `--community` takes a VTC DID or name, and is
optional when the account holds exactly one active membership.

| Command | Description |
| --- | --- |
| `repo list [--community <DID-OR-NAME>]` | List the repositories you hold a right on, with that right. |
| `repo clone <RESOURCE> [--dir <PATH>] [--community <DID-OR-NAME>]` | Clone one repository, e.g. `gitlab.com/group/repo`. Signing is not set up. |
| `repo sign [REPO_PATH] [--persona <NAME>]` | Make a checkout sign commits as your persona (default path: the current directory). Same as `e` in the TUI's Repos view. |

`repo sign` needs the `did-git-sign` binary on `PATH` and the VTA reachable.
Install the signer with `cargo install did-git-sign`; it is developed in
[verifiable-git-infrastructure](https://github.com/OpenVTC/verifiable-git-infrastructure).

## Profiles

A profile is a separate identity with its own config and secrets.

- Select one with `-p, --profile <NAME>` or `OPENVTC_CONFIG_PROFILE`.
- Names may contain only `[A-Za-z0-9._-]` and must not contain `..`.
- Config files are `config.json` for the default profile and
  `config-<NAME>.json` for others, in `~/.config/openvtc/` on Linux and macOS
  and `%APPDATA%\openvtc\` on Windows. `OPENVTC_CONFIG_PATH` overrides the
  directory.

```bash
openvtc -p profile-1
export OPENVTC_CONFIG_PROFILE=profile-1
openvtc
```
