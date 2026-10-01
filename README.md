# Open Verifiable Trust Community (OpenVTC) with First Person Protocol

[![Rust](https://img.shields.io/badge/rust-1.94.0%2B-blue.svg?maxAge=3600)](https://github.com/OpenVTC/openvtc)

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
| `openvtc` | TUI-based CLI with ratatui interface |
| `openvtc-core` | Shared library for configuration, DID management, and crypto |
| `did-git-sign` | [Git commit signing proxy](./did-git-sign/) using DID Ed25519 keys via VTA |

## Table of Contents

- [Quickstart](#quickstart)
- [Core Concepts](#core-concepts)
- [Decentralised Identity](#decentralised-identity)
- [Decentralised Communication](#decentralised-communication)
- [Profiles and Configurations](#profiles-and-configurations)
  - [Public Configuration](#public-configuration)
  - [Private Configuration](#private-configuration)
  - [Secured Configuration](#secured-configuration)
- [Prerequisites](#prerequisites)
- [Feature Flags](#feature-flags)
- [Getting Started](#getting-started)
  - [Initial Setup](#initial-setup)
  - [Host Your DID Document](#host-your-did-document)
- [Check Setup Status](#check-setup-status)
- [Usage](#usage)
- [Planned Commands](#planned-commands)
- [DID Git Signing](#did-git-signing)
- [Additional Resources](#additional-resources)

## Quickstart

Install from source.

```bash
cargo install --path openvtc
```

Run setup wizard.

```bash
openvtc setup
```

Launch the TUI (review status, contacts, relationships, and credentials).

```bash
openvtc
```

View available commands.

```bash
openvtc --help
```

Print the version.

```bash
openvtc --version
```

## Core Concepts

- **Decentralised Identifiers (DIDs)** - A globally unique identifier that enables secure digital interactions. The DID is the cornerstone of Self-Sovereign Identity (SSI), a concept that aims to put individuals or entities in control of their digital identities. DID is usually associated with a cryptographic key pair and represented with different DID methods, each with its own benefits.

- **Verifiable Credentials (VCs)** - A digital representation of a claim attested by a trusted issuer about the subject (e.g., Individual or Organisation). VC is cryptographically signed and verifiable using cryptographic keys associated with the DID of the issuer.

- **Personhood Credentials (PHCs)** – A type of verifiable credential issued by any ecosystem (any qualified entity such as a company, university, nonprofit community, government, etc.) that can attest to the credential holder being a real, unique person within that ecosystem. Part of PHC issuance is providing a verified identity verifiable credential issued by a trusted issuer. [Read more](https://docs.google.com/document/d/1RtS86BqyVn3i3mXm48VhC-SRaYvW2W_MvR4w6x9KQWY/edit?tab=t.0#heading=h.i544xd6ocqhm).

- **Verifiable Relationship Credentials (VRCs)** - A type of verifiable credential issued peer-to-peer between holders of personhood credentials to attest to verifiable first-person trust relationships. The verifiable relationship credential validates your personhood credential. [Read more](https://docs.google.com/document/d/1RtS86BqyVn3i3mXm48VhC-SRaYvW2W_MvR4w6x9KQWY/edit?tab=t.0#heading=h.siks62ntn9c5).

- **DIDComm Messaging Protocol** - An open standard for decentralised communication. Built on the foundation of Decentralised Identifiers (DIDs), it enables parties to exchange verifiable data such as credentials and establishes secure communication channels between parties without relying on centralised servers.

## Decentralised Identity

The OpenVTC tool uses the `did:webvh` to create your **persona DID**. It enhances the existing `did:web` method, providing:

- Portability with a self-certifying identifier (SCID), allowing you to move to a different domain.

- Robust security by introducing a pre-rotation key and witness proof that approves changes to the DID.

**Requirements:** A publicly accessible domain to host DID log entries (`did.jsonl`) for successful DID resolution and public key/service endpoint retrieval.

_Sample did:webvh identifier:_

![Sample WebVH DID Method](./docs/assets/didwebvh-sample.png)

## Decentralised Communication

OpenVTC seamlessly integrates with DIDComm-compatible mediators for secure, private communication using your **persona DID** or a per-relationship **relationship DID**.

DIDComm mediators handle message routing and storage while preserving privacy through end-to-end encryption. Messages are structured in multiple "envelope" layers providing:

- Confidentiality
- Sender authenticity
- Non-repudiation
- Sender anonymity

_Sample DIDComm message envelopes._

![Sample DIDComm Message Envelopes](./docs/assets/didcomm-envelopes.png)

## Profiles and Configurations

OpenVTC supports multiple profiles, allowing you to represent different identities across various contexts.

To use a specific profile when running the tool, set the environment variable `OPENVTC_CONFIG_PROFILE` with the name of your profile. For example:

**Linux/macOS (bash/zsh):**

```bash
export OPENVTC_CONFIG_PROFILE=profile-1 
```
> Add to `~/.zshrc` or `~/.bashrc` to persist across sessions.

**Windows (PowerShell):**

```powershell
$env:OPENVTC_CONFIG_PROFILE = "profile-1"
```
> On Windows, to keep this setting permanently, add it to your PowerShell profile or go to System Properties and set it under Environment Variables.

Each profile manages two types of configurations:

### Public Configuration

Stored in JSON format, the public configuration contains environment-specific details such as:

- Persona DID.
- Mediator DID.
- Security mode (e.g., Unlock Codes or Hardware Token).
- Encrypted private data containing known contacts, relationships, and VRCs.

Config file location:

**Default location (all platforms unless `OPENVTC_CONFIG_PATH` is set):**

- Default profile: `~/.config/openvtc/config.json`
- Named profiles: `~/.config/openvtc/config-<PROFILE_NAME>.json`

On Windows this resolves to:

```
C:\Users\<YourUser>\.config\openvtc\config.json
```

> Path is built from `dirs::home_dir()` plus `.config/openvtc/`.



You can change the default location where the public configuration is saved by setting the environment variable `OPENVTC_CONFIG_PATH` with the new path. For example:

**Linux/macOS (bash/zsh):**

```bash
export OPENVTC_CONFIG_PATH=~/.config/openvtc-tool
```
**Windows (PowerShell):**

```powershell
$env:OPENVTC_CONFIG_PATH = "C:\custom\path\openvtc"
```
> Ensure the value is a directory path. OpenVTC will create it if it does not exist.


### Private Configuration

An encrypted configuration stored inside the public configuration file, containing sensitive information about:

- List of known contacts with their Persona DIDs and Alias.
- List of known relationships with their:
  - Remote and local relationship DIDs
  - Remote and local persona DIDs
  - Relationship aliases
- Verifiable Relationship Credentials (VRCs)

The private configuration uses the same encryption method as the [secured configuration](#secured-configuration).

### Secured Configuration

Sensitive information is stored in the operating system's secure storage through the project's `keyring` integration:

- **macOS** — Keychain
- **Linux** — Secret Service keyring
- **Windows** — Windows Credential Manager

The secured configuration includes:

- Private key materials.
- Encrypted Session Key (ESK), if using a hardware token.

For more details, refer to the [Secured Configuration Management](./docs/secured-configuration-management.md).

## Prerequisites

1. Rust version 1.94.0 or higher (Install [Rust](https://rust-lang.org/learn/get-started/))
2. Publicly accessible domain to host your DID document.
3. **Optional:** DIDComm mediator to send messages. OpenVTC provides a default DIDComm mediator.
4. **Optional:** Set environment variables.
   - `OPENVTC_CONFIG_PATH`: Path to openvtc configuration files (default:
     `~/.config/openvtc/config.json`).
   - `OPENVTC_CONFIG_PROFILE`: Set a specific configuration profile (defaults to `default`).

## Feature Flags

OpenVTC currently supports `openpgp-card` as an option to perform cryptographic operations, such as signing and authentication.

| Flag           | Description                               | Default |
| -------------- | ----------------------------------------- | ------- |
| `openpgp-card` | OpenPGP-compatible hardware token support | Enabled |

`--no-default-features` is a Cargo flag applied at build/install time (not a
flag on the `openvtc` binary itself). To build or install without the
OpenPGP-card feature:

```bash
cargo install --path openvtc --no-default-features
```

## Getting Started

### Workspace Layout

This repository is a Cargo workspace. The root `Cargo.toml` defines the following crates:

| Crate | Role |
|---|---|
| `openvtc-core` | Core library — config, storage, cryptography, DID logic |
| `openvtc` | Terminal UI (TUI) interface |
| `did-git-sign` | Git commit signing proxy using DID Ed25519 keys |

### Building

From the repo root:

```bash
cargo build
```

To build without the OpenPGP card feature:

```bash
cargo build --no-default-features
```

### Testing

```bash
cargo test
```

For a specific crate:

```bash
cargo test -p openvtc-core
```

### PR Guidelines

- Use conventional commits where possible (e.g. `docs: expand CONTRIBUTING.md`)
- Sign the CLA — GitHub will guide you through this when you open a PR
- Reference the issue your PR addresses (e.g. `Closes #13`)
- If platform-specific behaviour is uncertain, write `> **Note:** TBD — help wanted` rather than documenting incorrect information

### Initial Setup

1. Install locally from the source.

   ```bash
   cargo install --path openvtc
   ```

   > **Note:** This will change once the tool is published.

2. Run the setup wizard.

   ```bash
   openvtc setup
   ```

   To set up a named profile instead of **default**, set the `-p/--profile` option.

   ```bash
   openvtc -p profile-1 setup
   ```

Follow the prompts to:

- Create the configuration.
- Generate cryptographic keys.
- Generate Persona DID.
- Connect to DIDComm mediator server.

### Host Your DID Document

After setup, OpenVTC generates a `did.jsonl` file for your Persona DID. The file must be hosted at a specific URL matching your configured DID.

The `did:webvh` method resolves your DID by fetching the DID document from a well-known location on the web. If the document is not hosted at the correct URL, the DID cannot be resolved or used.

**For example:**

- If your configured URL is `https://mydomain.com`, you must host the file at:

  ```
  https://mydomain.com/.well-known/did.jsonl
  ```

- If your configured URL is `https://mydomain.com/profile1`, you must host the file at:

  ```text
  https://mydomain.com/profile1/did.jsonl
  ```

> **Important:** The URL must be publicly accessible for DID resolution.

To set up multiple profiles for the same domain, see the [Multiple DIDs on Same Domain](./docs/multiple-didweb-same-domain.md).

## Check Setup Status

OpenVTC configures your environment to ensure your setup is safe, secure, and private when running the tool.

Once setup is complete, launch the TUI to review the status and health of your current environment:

```bash
openvtc
```

To launch with a specific profile:

```bash
openvtc -p profile-1
```

The TUI surfaces, among other things:

- Tool version.
- Your Persona DIDs, and whether your Persona DID is resolvable.
- Configured keys for authentication, encryption, and signing.
- List of requested and established relationships.
- DIDComm mediator connectivity.

## Usage

OpenVTC today is a terminal UI (TUI) plus a `setup` subcommand. Launch the
TUI from the installed binary:

```bash
openvtc
```

Or from the source checkout:

```bash
cargo run -p openvtc
```

The only non-TUI subcommand currently implemented is `setup`. Refer to the
complete [command reference](./docs/openvtc-tool-commands.md) for the full
list of flags and the roadmap of planned commands.

## Planned Commands

A number of standalone subcommands (`status`, `logs`, `contacts`,
`relationships`, `tasks`, `vrcs`, and config `export`/`import`) are planned but
not yet implemented as CLI commands — those capabilities are currently reached
through the TUI. See the
[command reference](./docs/openvtc-tool-commands.md#planned-commands-not-yet-implemented)
for details.

## DID Git Signing

The workspace includes [`did-git-sign`](./did-git-sign/), a standalone tool that
signs git commits using your DID's Ed25519 key managed by a VTA. It integrates
with git's SSH signing mechanism as a signing proxy — no private key material
ever touches disk.

```bash
# Install
cargo install --path did-git-sign

# Configure for the current repo
did-git-sign init \
  --credential "eyJkaWQiOi..." \
  --key-id "your-vta-key-id" \
  --did-key-id "did:webvh:abc123:example.com#key-0" \
  --name "Your Name"

# Commits are now automatically signed with your DID
git commit -m "signed with my DID"
```

See the [did-git-sign README](./did-git-sign/README.md) for full documentation.

## Additional Resources

Additional resources to learn more about the Open Verifiable Trust Community (OpenVTC) Tool.

- [First Person Project White Paper](https://www.firstperson.network/white-paper)
- [Relationships and VRCs Guide](./docs/relationships-vrcs.md)
- [Secure Key Management](./docs/secure-key-management.md)
- [Secured Configuration Management](./docs/secured-configuration-management.md)
- [Backup and Restore](./docs/backup-restore.md)
- [Multiple Profiles Setup](./docs/multiple-didweb-same-domain.md)
- [Config Data Structure](./docs/openvtc-config-data-structure.md)
