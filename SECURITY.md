# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.7.x   | :white_check_mark: |
| < 0.7   | :x:                |

The newest two GA releases are supported; see [RELEASES.md](RELEASES.md#support)
for the policy and the current schedule.

## Reporting a Vulnerability

If you discover a security vulnerability in OpenVTC, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: **security@firstperson.network**

Include the following in your report:

- Description of the vulnerability
- Steps to reproduce
- Affected component(s) and version(s)
- Potential impact assessment
- Any suggested mitigations (optional)

## Response Timeline

- **Acknowledgement:** Within 48 hours of receipt
- **Initial assessment:** Within 5 business days
- **Fix timeline:** Depends on severity; critical issues targeted within 14 days

## Scope

The following are in scope:

- All crates in the `openvtc` workspace (`openvtc-core`, `openvtc`, `did-git-sign`)
- Cryptographic operations (key derivation, encryption, signing)
- Secret handling and memory management
- DIDComm protocol implementation
- Configuration storage and protection
- Hardware token (OpenPGP card) integration

## Security Design

OpenVTC employs defense-in-depth for secret protection:

1. **Secured Config** — Private key material stored in OS keyring (macOS Keychain, Linux Secret Service, Windows Credential Manager) or hardware tokens
2. **Protected Config** — Relationship and contact data encrypted at rest with AES-256-GCM
3. **Public Config** — Only non-sensitive metadata stored in plaintext

Cryptographic primitives used:

- **AES-256-GCM** for authenticated encryption
- **HKDF-SHA256** for key derivation with domain separation
- **Argon2id** for passphrase-based key derivation
- **Ed25519** for digital signatures
- **X25519** for key agreement
- Memory zeroization via `secrecy` and `zeroize` crates

## Disclosure Policy

We follow coordinated disclosure. After a fix is available, we will:

1. Release a patched version
2. Publish a security advisory via GitHub
3. Credit the reporter (unless anonymity is requested)
