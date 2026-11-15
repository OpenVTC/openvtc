# OpenVTC Core Library

[![Rust](https://img.shields.io/badge/rust-1.95.0%2B-blue.svg?maxAge=3600)](https://github.com/OpenVTC/openvtc)
[![docs.rs](https://img.shields.io/docsrs/openvtc-core)](https://docs.rs/openvtc-core)

Core library for [OpenVTC](https://github.com/OpenVTC/openvtc) (Open
Verifiable Trust Communities), a client for joining and taking part in
verifiable trust communities with Decentralised Identifiers (DIDs) and
Verifiable Credentials.

## Overview

`openvtc-core` is the shared foundation of the
[`openvtc`](https://crates.io/crates/openvtc) client. It holds the
configuration model (account, personas, community memberships), encrypted
storage, the connection to a Verifiable Trust Agent (VTA), DIDComm and TSP
messaging, relationships and Verifiable Relationship Credentials (VRCs),
community joining, and peer identity vetting. It has no UI dependencies.

The crate is built for the `openvtc` client and its API changes with each
release. See [docs.rs/openvtc-core](https://docs.rs/openvtc-core) for the
modules and their documentation.

## Usage

```toml
[dependencies]
openvtc-core = "0.8"
```

```rust
use openvtc_core::config::public_config::{profile_dir, validate_profile_name};

fn main() -> Result<(), openvtc_core::errors::OpenVTCError> {
    validate_profile_name("work")?;
    // ~/.config/openvtc on Linux and macOS, %APPDATA%\openvtc on Windows,
    // or OPENVTC_CONFIG_PATH when it is set.
    println!("{}", profile_dir("work")?.display());
    Ok(())
}
```

## Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `openpgp-card` | **yes** | OpenPGP smart-card support via `openpgp-card`, `card-backend-pcsc` and `openpgp-card-rpgp`. Disable with `default-features = false` on platforms without PC/SC. |
| `arbitrary` | no | Derives `Arbitrary` on parse-surface types for the fuzz harnesses. |

## Security

- **Encryption at rest** — The protected configuration is encrypted with
  AES-256-GCM.
- **Credential store** — Local secret material (the VTA credential bundle,
  and a seed for legacy BIP32 profiles) is kept in the operating system's
  credential store, or in an encrypted file store the operator chooses.
- **Zeroisation** — Sensitive values are zeroised on drop via the `zeroize`
  and `secrecy` crates.
- **Hardware tokens** — With the `openpgp-card` feature, the secured
  configuration can be protected by an OpenPGP smart card.

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `OPENVTC_CONFIG_PATH` | Directory that holds profile config files. |
| `OPENVTC_MEDIATOR_DID` | Not read by this crate. The `openvtc` binary honours it only when built with the `dev-overrides` feature (runtime-only, never saved); release builds ignore it. |

## License

Licensed under [Apache-2.0](https://github.com/OpenVTC/openvtc/blob/main/LICENSE).
