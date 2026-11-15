# Contribution Guidelines

Thank you for contributing! Before you contribute, we ask some things of you:

- Please follow our Code of Conduct, the Contributor Covenant. You can find a copy [in this repository](CODE_OF_CONDUCT.md) or under https://www.contributor-covenant.org/
- Every commit must carry a [Developer Certificate of Origin](https://developercert.org/) sign-off (`git commit -s`). The DCO check fails a PR with an unsigned commit. There is no CLA.

## Start with a Discussion

Before opening an issue or pull request, please start a conversation in [GitHub Discussions](https://github.com/OpenVTC/openvtc/discussions). This gives maintainers and the community a chance to provide early feedback, avoid duplicate effort, and help shape the direction of proposed changes.

- **Bug reports** — confirm the behavior and get initial triage before filing an issue.
- **Feature ideas** — discuss the use case and approach before writing code.
- **Questions** — ask in Discussions rather than opening an issue.

Once there is agreement on the approach, you can proceed with an issue or PR and link back to the discussion for context.

## Development Setup

1. Install Rust via [rustup](https://rustup.rs/). The minimum version is
   `rust-version` in the root `Cargo.toml` (currently 1.95.0)
2. Clone the repository:
   ```bash
   git clone https://github.com/OpenVTC/openvtc.git
   cd openvtc
   ```
3. Build the workspace:
   ```bash
   cargo build
   ```
4. Run the test suite:
   ```bash
   cargo test --workspace
   ```

### Optional: Hardware Token Support

To build without OpenPGP card support (avoids PC/SC dependencies):

```bash
cargo build --no-default-features
```

## Code Standards

### Formatting and Linting

All code must pass formatting and linting checks before merge:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
```

### Commit Messages

- Use [Conventional Commits](https://www.conventionalcommits.org/) style: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`
- Keep the subject line under 72 characters
- All commits must be DCO-signed (`git commit -s`)

### Branch Naming

- `feat/<short-description>` — New features
- `fix/<short-description>` — Bug fixes
- `docs/<short-description>` — Documentation only
- `refactor/<short-description>` — Code refactoring

## Pull Request Process

1. **Fork and branch** from `main`. Every change lands on `main` first, fixes
   included; a fix a release needs reaches its `release/<major.minor>` branch
   by backport (see [RELEASES.md](RELEASES.md)). Add a `## [Unreleased]` entry
   to CHANGELOG.md, and never edit a version: the release tooling owns them
2. **Write tests** for new functionality — PRs that decrease test coverage will be flagged
3. **Run the full check suite** locally before submitting:
   ```bash
   cargo fmt --all --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   ```
4. **Open the PR** with a clear title and description summarizing the change
5. **Link related issues** using `Closes #123` or `Fixes #123` in the PR body
6. **Respond to review feedback** promptly

If platform-specific behaviour is uncertain in documentation, write
`> **Note:** TBD — help wanted` rather than documenting something incorrect.

### Changelog entries

CHANGELOG.md follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
A release's section becomes its GitHub Release notes, so keep entries short:

- Put each entry under one of `### Added`, `### Changed`, `### Deprecated`,
  `### Removed`, `### Fixed` or `### Security` in `## [Unreleased]`. Mark a
  breaking change with **Breaking** at the start of the entry.
- Keep an entry to two or three lines, and end it with the PR or issue number,
  e.g. `(#123)`. Put longer explanation in the PR description.

## Architecture Overview

The workspace is organized as a layered architecture:

- **`openvtc-core`** — Core library: cryptography, DID management, configuration, protocol logic. No UI dependencies.
- **`openvtc`** — TUI binary that consumes `openvtc-core`

The `did-git-sign` commit signer is not part of this workspace. It is developed
in [verifiable-git-infrastructure](https://github.com/OpenVTC/verifiable-git-infrastructure)
and consumed from crates.io.

Key design principles:
- Crypto and protocol logic stays in `openvtc-core` — binary crates are pure consumers
- Secrets are handled with `secrecy`/`zeroize` — never log, serialize, or expose key material
- Error handling uses `thiserror` in the library and `anyhow` in binaries

## Security

If you discover a security vulnerability, please follow the [Security Policy](SECURITY.md). Do **not** open a public issue.

When writing code that handles sensitive data:
- Use `SecretString` / `SecretVec` for secret values
- Ensure secrets are zeroized on drop
- Never include secret material in error messages or logs
- Use `OsRng` (not `thread_rng()`) for cryptographic randomness
