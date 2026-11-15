# Open Verifiable Trust Community (OpenVTC) with First Person Protocol

[![Rust](https://img.shields.io/badge/rust-1.95.0%2B-blue.svg?maxAge=3600)](https://github.com/OpenVTC/openvtc)

A CLI tool for establishing verifiable trust relationships within developer
communities using Decentralised Identifiers (DIDs) and Verifiable Credentials
(VCs).

OpenVTC implements open standards and protocols to enable _"Know Your Developer"_
capabilities, following the [First Person Project white paper](https://www.firstperson.network/white-paper)
for establishing and verifying **first-person trust relationships** using
Personhood Credentials (PHCs) and Verifiable Relationship Credentials (VRCs).

## Workspace Crates

| Crate | Description |
|-------|-------------|
| [`openvtc`](./openvtc/) | The OpenVTC client: a terminal UI (TUI) plus headless subcommands |
| [`openvtc-core`](./openvtc-core/) | Shared library for configuration, DID management, messaging and crypto |

The verifiable trust infrastructure that OpenVTC talks to (the VTA, key
management, credential protocols and DIDComm services) lives in
[verifiable-trust-infrastructure](https://github.com/OpenVTC/verifiable-trust-infrastructure).
The `did-git-sign` commit signer lives in
[verifiable-git-infrastructure](https://github.com/OpenVTC/verifiable-git-infrastructure).

## Table of Contents

- [Quickstart](#quickstart)
- [Core Concepts](#core-concepts)
- [Glossary](#glossary)
- [Decentralised Identity](#decentralised-identity)
- [Decentralised Communication](#decentralised-communication)
- [Profiles and Configurations](#profiles-and-configurations)
- [Prerequisites](#prerequisites)
- [Feature Flags](#feature-flags)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [DID Git Signing](#did-git-signing)
- [Contributing](#contributing)
- [Additional Resources](#additional-resources)

## Quickstart

Install from crates.io.

```bash
cargo install openvtc
```

Run the setup wizard.

```bash
openvtc setup
```

Launch the TUI.

```bash
openvtc
```

View the available commands.

```bash
openvtc --help
```

## Core Concepts

- **Decentralised Identifiers (DIDs)** - A globally unique identifier that enables secure digital interactions. The DID is the cornerstone of Self-Sovereign Identity (SSI), a concept that aims to put individuals or entities in control of their digital identities. DID is usually associated with a cryptographic key pair and represented with different DID methods, each with its own benefits.

- **Verifiable Credentials (VCs)** - A digital representation of a claim attested by a trusted issuer about the subject (e.g., Individual or Organisation). VC is cryptographically signed and verifiable using cryptographic keys associated with the DID of the issuer.

- **Personhood Credentials (PHCs)** – A type of verifiable credential issued by any ecosystem (any qualified entity such as a company, university, nonprofit community, government, etc.) that can attest to the credential holder being a real, unique person within that ecosystem. Part of PHC issuance is providing a verified identity verifiable credential issued by a trusted issuer. [Read more](https://docs.google.com/document/d/1RtS86BqyVn3i3mXm48VhC-SRaYvW2W_MvR4w6x9KQWY/edit?tab=t.0#heading=h.i544xd6ocqhm).

- **Verifiable Relationship Credentials (VRCs)** - A type of verifiable credential issued peer-to-peer between holders of personhood credentials to attest to verifiable first-person trust relationships. The verifiable relationship credential validates your personhood credential. [Read more](https://docs.google.com/document/d/1RtS86BqyVn3i3mXm48VhC-SRaYvW2W_MvR4w6x9KQWY/edit?tab=t.0#heading=h.siks62ntn9c5).

- **Verifiable Trust Agent (VTA)** - The service that holds your keys and creates your DIDs. OpenVTC connects to a VTA during setup; you authorise it from your Personal Network Manager (PNM).

- **DIDComm Messaging Protocol** - An open standard for decentralised communication. Built on the foundation of Decentralised Identifiers (DIDs), it enables parties to exchange verifiable data such as credentials and establishes secure communication channels between parties without relying on centralised servers.

## Glossary

The TUI uses one name for each of these:

- **Persona** — an identity you hold: a DID your VTA keeps the keys for. The
  *My Identity* panel manages your personas (and their attributes, faces and
  worlds).
- **Community** — a Verifiable Trust Community (VTC) you belong to or are
  joining. The UI says *community*; *VTC* names the service behind it.
- **Unlock code** — the secret that protects your profile on this machine
  (`--unlock-code`; *Settings → Protection*). An export file's *passphrase*
  is a different secret, chosen per export.
- **Inbox** — requests and credentials sent to you, waiting for an answer
  (the docs' *tasks*).
- **Help / Status** — connection status, your DIDs and the keyboard
  shortcuts; `?` on any panel lists that panel's keys.

## Decentralised Identity

OpenVTC uses `did:webvh` for your **persona DID**. It enhances the existing `did:web` method, providing:

- Portability with a self-certifying identifier (SCID), allowing you to move to a different domain.

- Robust security by introducing a pre-rotation key and witness proof that approves changes to the DID.

You do not host the DID yourself. A persona DID is created through your VTA,
which publishes it on its WebVH hosting service, when you join your first
community (or create a persona in **My Identity**). One account can hold
several personas.

_Sample did:webvh identifier:_

![Sample WebVH DID Method](./docs/assets/didwebvh-sample.png)

## Decentralised Communication

OpenVTC uses DIDComm-compatible mediators for secure, private communication using your **persona DID** or a per-relationship **relationship DID**. The mediator comes from your VTA's DID document; OpenVTC has no built-in default mediator.

DIDComm mediators handle message routing and storage while preserving privacy through end-to-end encryption. Messages are structured in multiple "envelope" layers providing:

- Confidentiality
- Sender authenticity
- Non-repudiation
- Sender anonymity

_Sample DIDComm message envelopes._

![Sample DIDComm Message Envelopes](./docs/assets/didcomm-envelopes.png)

## Profiles and Configurations

OpenVTC supports multiple profiles, allowing you to represent different identities across various contexts. Choose one with `-p/--profile <NAME>` or the `OPENVTC_CONFIG_PROFILE` environment variable:

```bash
openvtc -p profile-1
export OPENVTC_CONFIG_PROFILE=profile-1   # bash/zsh
$env:OPENVTC_CONFIG_PROFILE = "profile-1" # PowerShell
```

Each profile has three layers of configuration. See
[Config Data Structure](./docs/openvtc-config-data-structure.md) for detail.

- **Public configuration** — a JSON file on disk with non-secret settings,
  the protection mode, and the encrypted protected configuration.
- **Protected configuration** — encrypted, stored inside the public file. It
  holds your account (personas and community memberships), contacts,
  relationships, credentials and the activity log.
- **Secured configuration** — key material in the OS credential store: macOS
  Keychain, Linux Secret Service or Windows Credential Manager. On a headless
  Linux machine you can choose an encrypted file store instead with
  `OPENVTC_SECURE_STORE=file`. See the
  [`openvtc` README](./openvtc/README.md#secure-storage) and
  [Secured Configuration Management](./docs/secured-configuration-management.md).

Config files live in:

- `~/.config/openvtc/` on Linux and macOS
- `%APPDATA%\openvtc\` on Windows (from `dirs::config_dir()`)

The default profile uses `config.json`; a named profile uses
`config-<PROFILE_NAME>.json`. Set `OPENVTC_CONFIG_PATH` to use another
directory; OpenVTC creates it if it does not exist.

## Prerequisites

1. Rust 1.95.0 or later, to build from source ([install Rust](https://rust-lang.org/learn/get-started/)).
2. Access to a Verifiable Trust Agent (VTA), and its DID.
3. A Personal Network Manager (`pnm`) that can grant OpenVTC access to the VTA,
   or a VTA administrator who will run the grant for you.

## Feature Flags

| Flag            | Description                                                         | Default  |
| --------------- | ------------------------------------------------------------------- | -------- |
| `openpgp-card`  | OpenPGP-compatible hardware token support                           | Enabled  |
| `dev-overrides` | Honour VTA and mediator overrides from the environment (development builds only) | Disabled |

`--no-default-features` is a Cargo flag applied at build or install time, not a
flag on the `openvtc` binary. To install without hardware token support:

```bash
cargo install openvtc --no-default-features
```

## Getting Started

1. Install OpenVTC.

   ```bash
   cargo install openvtc
   ```

   To install from a checkout instead, run `cargo install --path openvtc`.

2. Run the setup wizard.

   ```bash
   openvtc setup
   ```

   To set up a named profile instead of **default**, add `-p/--profile`:

   ```bash
   openvtc -p profile-1 setup
   ```

   The wizard walks you through:

   - Connecting to your VTA: enter the VTA's DID.
   - Authorising OpenVTC from your PNM: the wizard shows the `pnm` command to
     run. The grant lasts one hour.
   - Optionally setting up a hardware token.
   - Setting an unlock code to protect the profile.

   No DID is created during setup. The wizard can also restore a profile from
   a backup; see [Backup and Restore](./docs/backup-restore.md).

   On a machine without a terminal UI, run setup headless:

   ```bash
   openvtc setup --vta-did <VTA_DID> --unlock-code-file <PATH>
   ```

   It prints the PNM command for the VTA administrator, waits for the grant,
   then saves the account.

3. Join a community. In the TUI, open **Communities**. Or, headless:

   ```bash
   openvtc community join <COMMUNITY_DID>
   ```

   Your first join creates your persona DID through the VTA. Add
   `--invitation <FILE>` to present an invitation credential.

4. Check the setup at any time:

   ```bash
   openvtc health
   ```

   It resolves your personas, the VTA, the mediators and each community, and
   reports which transport each pair would use. It is read-only.

## Usage

Run `openvtc` with no subcommand to launch the TUI. Its main menu holds
Communities, Inbox, My Relationships, My Credentials, Vetting, My Identity,
Settings, VTA Service, TSP Relationships, Logs and Help / Status.

The CLI also has these subcommands:

| Command | Description |
| --- | --- |
| `openvtc setup` | Set up a profile (wizard or headless). |
| `openvtc health` | Report on the messaging chain. Read-only. |
| `openvtc theme …` | List, choose, import, create and export themes. See [Themes](./docs/themes.md). |
| `openvtc community join …` | Join a community without the TUI. |
| `openvtc repo list\|clone\|sign` | Work with a community's repositories without the TUI. |

See the [command reference](./docs/openvtc-tool-commands.md) for every
subcommand, flag and environment variable.

## DID Git Signing

OpenVTC can make a repository checkout sign commits as your persona. Set it up
from a community's Repos view in the TUI (`e`), or with `openvtc repo sign`.
Both need the `did-git-sign` binary on your `PATH`:

```bash
cargo install did-git-sign
```

`did-git-sign` is developed in
[verifiable-git-infrastructure](https://github.com/OpenVTC/verifiable-git-infrastructure).

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for building, testing, commit
sign-off (DCO) and the pull request process, and [RELEASES.md](./RELEASES.md)
for how releases are made.

## Additional Resources

Additional resources to learn more about the Open Verifiable Trust Community (OpenVTC) Tool.

- [First Person Project White Paper](https://www.firstperson.network/white-paper)
- [Command Reference](./docs/openvtc-tool-commands.md)
- [Relationships and VRCs Guide](./docs/relationships-vrcs.md)
- [Community Rooms](./docs/community-rooms.md)
- [Forge Accounts](./docs/forge-accounts.md)
- [Themes](./docs/themes.md)
- [Secure Key Management](./docs/secure-key-management.md)
- [Secured Configuration Management](./docs/secured-configuration-management.md)
- [Backup and Restore](./docs/backup-restore.md)
- [Config Data Structure](./docs/openvtc-config-data-structure.md)
