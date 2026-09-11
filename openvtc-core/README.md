# OpenVTC Core Library

[![Rust](https://img.shields.io/badge/rust-1.94.0%2B-blue.svg?maxAge=3600)](https://github.com/OpenVTC/openvtc)

Core library for the OpenVTC ecosystem. Provides configuration management,
DID-based identity operations, encrypted storage, peer-to-peer relationship
handling, Verifiable Relationship Credentials (VRCs), and DIDComm messaging
types used by the CLI and related tools.

## Overview

`openvtc-core` is the shared foundation crate that the OpenVTC binaries
(`openvtc` and `did-git-sign`) depend on. It defines the data structures,
cryptographic routines, and protocol constants needed to operate within
the Linux Foundation's decentralized trust infrastructure.

## Modules

| Module | Description |
|--------|-------------|
| `config` | Multi-layer configuration system split into **public** (plaintext on disk), **protected** (AES-256-GCM encrypted on disk), and **secured** (OS keyring) layers. Manages DID documents, TDK profiles, and key material. |
| `relationships` | Peer-to-peer trust relationship lifecycle — request, accept, reject, and finalize flows over DIDComm. |
| `vrc` | Verifiable Relationship Credentials — request, issue, and verify VRCs that attest to established relationships. |
| `tasks` | Async task tracker for long-running DIDComm operations (message send/receive, credential issuance). |
| `vetting` | Peer identity vetting: tickets, applications, the vetter desk, and the peer Trust Tasks between them. |
| `bip32` | BIP32 hierarchical key derivation from a seed, with helpers to derive Ed25519 signing keys and X25519 encryption keys. |
| `openpgp_card` | Hardware token (OpenPGP smart card) support for key storage and signing. Feature-gated behind `openpgp-card`. |
| `errors` | Unified error type (`OpenVTCError`) used across the library. |
| `logs` | Structured logging utilities. |

## Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `openpgp-card` | **yes** | Enables OpenPGP smart-card support via `openpgp-card`, `card-backend-pcsc`, and `openpgp-card-rpgp`. Disable with `default-features = false` on platforms without PC/SC. |

## DIDComm Message Types

The library defines a `MessageType` enum and corresponding `protocol_urls`
constants for the OpenVTC messaging protocol, covering relationship
requests, trust pings, VRC issuance, and maintainer list exchange.

## Security

- **Encryption at rest** — Protected configuration is encrypted with
  AES-256-GCM using keys derived via HKDF-SHA256.
- **OS keyring storage** — Secret key material (seeds, unlock codes) is
  stored in the operating system's native credential store through the
  `keyring` crate.
- **Zeroization** — Sensitive values are zeroized on drop via the
  `zeroize` and `secrecy` crates to limit exposure in memory.
- **Hardware tokens** — When the `openpgp-card` feature is enabled,
  private keys can remain on a smart card and never touch disk.

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `OPENVTC_MEDIATOR_DID` | Override the default Linux Foundation public mediator DID. |
| `OPENVTC_ORG_DID` | Override the default Linux Foundation organisation DID. |

## License

Licensed under [Apache-2.0](../LICENSE).
