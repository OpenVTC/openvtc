# openvtc

A terminal user interface (TUI) for managing OpenVTC identities, relationships,
and verifiable credentials. Built with [ratatui](https://ratatui.rs/).

## Overview

`openvtc` is the OpenVTC client, providing a rich TUI experience with:

- **Setup wizard** — Guided multi-step setup flow with real-time feedback
- **Main dashboard** — View relationships, contacts, tasks, and VRCs at a glance
- **DIDComm messaging** — Live WebSocket-based message handling with visual status
- **Keyboard-driven navigation** — Fast interaction without leaving the terminal

## Architecture

The application follows an actor model with unidirectional data flow:

```
┌──────────┐  Actions   ┌──────────────┐  State   ┌───────────┐
│ UI Layer ├───────────→│ StateHandler ├─────────→│ UI Layer  │
│ (render) │            │  (business)  │          │ (render)  │
└──────────┘            └──────────────┘          └───────────┘
```

- **`UiManager`** renders state and captures key events as `Action` variants
- **`StateHandler`** processes actions, performs DID/DIDComm operations, emits `State` updates
- **Graceful shutdown** via broadcast channels and OS signal handling

## Installation

```bash
cargo install --path openvtc
```

Or build without hardware token support:

```bash
cargo install --path openvtc --no-default-features
```

## Usage

```bash
# Start with default profile (auto-detects setup vs main mode)
openvtc

# Force setup wizard
openvtc setup

# Use a named profile
openvtc -p my-profile
```

## Configuration

- Default location: `~/.config/openvtc/`
- Override: `OPENVTC_CONFIG_PATH` and `OPENVTC_CONFIG_PROFILE` environment variables

### Secure Storage

A profile lives in two halves: a **config file** on disk
(`~/.config/openvtc/config.json`) and its **secret key material** — the BIP32
seed or VTA credential bundle — in an OS credential store. Both are needed.
Copying one without the other produces `No matching credential found` at
startup; `openvtc health` says so explicitly.

| Platform | Store | Durable? |
|----------|-------|----------|
| macOS | Keychain | Yes |
| Windows | Credential Manager | Yes |
| Linux | Secret Service — GNOME Keyring / KWallet / KeePassXC | Yes |

This is the same registration `pnm` and every other tool on `vta-sdk` uses
(`vta_sdk::keyring_init::install_default_store`), so a given OS keeps every
tool's secrets in the same place.

#### OpenVTC fails closed

**If the credential store cannot be opened, OpenVTC exits and explains why.**
It does not quietly write your keys somewhere else. A tool that silently
downgrades its own storage teaches you the secure backend is optional, and the
moment it matters you discover your secrets were somewhere you never agreed to.

Every store OpenVTC will select is durable. Nothing it writes is lost by a
reboot.

#### Headless machines — choosing file storage

On a server, container or CI runner with no keyring daemon, select durable file
storage **deliberately**:

```bash
OPENVTC_SECURE_STORE=file openvtc
```

Secrets then live in `~/.config/openvtc/secrets/` at mode `0600`. This store
**refuses to hold an unencrypted profile** — set a passphrase (Settings →
Protection) or use a hardware token first, so key material is never written to
disk in the clear.

| `OPENVTC_SECURE_STORE` | Effect |
|---|---|
| *unset* (supported default) | The OS credential store. Fails closed if unavailable. |
| `file` | Durable encrypted file. Requires a passphrase or token. Linux only. |
| `keyutils` | **Deprecated, migration only.** The Linux kernel keyring is RAM-only and loses your keys on reboot. It exists solely so a profile written by an older OpenVTC can be started once and exported. Warns loudly on every launch. |

#### When the secure store fails

`openvtc health` reports which store is in use, whether this profile's
credential is present, and how long it will survive — and it runs even when the
profile cannot be decrypted, which is when you need it. On a startup failure,
OpenVTC also writes the full diagnosis to
`~/.config/openvtc/last-startup-failure.txt`; attach that to a bug report.

To look at the entry yourself:

```bash
# macOS
security find-generic-password -s openvtc -a default
# Linux (Secret Service)
secret-tool search service openvtc username default
# Linux (encrypted file)
ls -l ~/.config/openvtc/secrets/
# Windows
cmdkey /list | findstr openvtc
```


## Feature Flags

| Flag            | Description                                                        | Default  |
|-----------------|--------------------------------------------------------------------|----------|
| `openpgp-card`  | OpenPGP-compatible hardware token support                          | Enabled  |
| `dev-overrides` | Honour trust-anchor environment overrides (development builds only) | Disabled |

### Developer trust-anchor overrides

`OPENVTC_VTA_URL`, `OPENVTC_VTA_DID` and `OPENVTC_MEDIATOR_DID` change which VTA
and mediator this client authenticates to. Builds without the `dev-overrides`
feature, which includes every release build, **ignore them**. Each one that is
set is reported on stderr before the TUI starts and again in the Activity Log.

To point a local build at a development VTA or mediator, compile the feature in:

```bash
OPENVTC_VTA_URL=http://127.0.0.1:8080 cargo run -p openvtc --features dev-overrides
```

In a `dev-overrides` build:

| Variable | Effect |
|---|---|
| `OPENVTC_VTA_URL` | Must be an `http://` or `https://` URL with a host. The setup wizard uses it as the VTA REST endpoint and skips DID resolution; a loaded profile uses it for this run. |
| `OPENVTC_VTA_DID` | Must parse as a DID. Replaces the profile's VTA DID for this run. |
| `OPENVTC_MEDIATOR_DID` | Must parse as a DID. Replaces the active persona's mediator for this run. |

An override applies to the running process only. Saves and exports keep writing
the stored values, so the override is gone as soon as the variable is unset. A
value that fails validation is ignored and logged. While an override is active,
the bottom bar shows a red `DEV OVERRIDE` badge naming it.

`OPENVTC_FRIENDLY_NAME` only changes the display name, and every build honours it.

## Troubleshooting

### Debug Logging

The TUI captures stdout/stderr for rendering, so standard `RUST_LOG` output
is not visible. To enable file-based debug logging, set `OPENVTC_DEBUG_LOG`
to a file path:

```bash
OPENVTC_DEBUG_LOG=/tmp/openvtc.log openvtc
```

This writes timestamped tracing output at `debug` level to the specified file.
For finer control, combine with `RUST_LOG`:

```bash
# Only log openvtc and DIDComm service at debug, everything else at warn
OPENVTC_DEBUG_LOG=/tmp/openvtc.log \
  RUST_LOG="warn,openvtc=debug,openvtc_core=debug,affinidi_messaging_didcomm_service=debug" \
  openvtc
```

Useful patterns to look for in the logs:
- `built listener configs` — shows how many DIDComm listeners were created at startup
- `registered listener` — shows each listener's ID and state
- `rapid disconnect cycling detected` — indicates a WebSocket reconnect loop
- `sending DIDComm message` — tracks outbound message routing

### Common Issues

**WebSocket reconnect loop** — If the activity log shows repeated
"Listener 'persona' disconnected / restarting" messages, check:
1. Only one instance of openvtc is running for this profile (`ps aux | grep openvtc`)
2. Network connectivity to the mediator is stable
3. Debug logs for duplicate listener registration

**Configuration not found** — Ensure `~/.config/openvtc/` exists or set
`OPENVTC_CONFIG_PATH`. Run `openvtc setup` to create initial configuration.

## Documentation

- [Command Reference](../docs/openvtc-tool-commands.md)
- [Relationships and VRCs Guide](../docs/relationships-vrcs.md)
