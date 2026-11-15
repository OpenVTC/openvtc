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

- All crates in the `openvtc` workspace (`openvtc-core`, `openvtc`)
- Cryptographic operations (key derivation, encryption, signing)
- Secret handling and memory management
- DIDComm and TSP messaging as implemented in this repository
- Configuration storage and protection
- Hardware token (OpenPGP card) integration

Out of scope here, but reportable to the same address:

- The `did-git-sign` commit signer, developed in
  [verifiable-git-infrastructure](https://github.com/OpenVTC/verifiable-git-infrastructure).
- The VTA, VTC and other services, developed in
  [verifiable-trust-infrastructure](https://github.com/OpenVTC/verifiable-trust-infrastructure).

## Security Design

OpenVTC employs defense-in-depth for secret protection:

1. **Key backend** — By default, persona keys are managed by the VTA and
   fetched when needed. OpenVTC stores a VTA credential bundle, which it uses
   to authenticate to the VTA. Older profiles may use the legacy BIP32 backend,
   which derives keys from a locally stored seed.
2. **Secured Config** — Local secret material (the VTA credential bundle, a
   legacy BIP32 seed, and the key for the protected config) is kept in the OS
   credential store (macOS Keychain, Linux Secret Service, Windows Credential
   Manager). On Linux, `OPENVTC_SECURE_STORE=file` selects an encrypted file
   store instead; it refuses to hold a profile that has no passphrase or
   hardware token. The secured config is encrypted under the unlock code or an
   OpenPGP hardware token, unless the user chooses plaintext protection after
   a warning. Under an unlock code the key is derived with Argon2id and a
   random salt of the profile's own, and the profile's name is bound to the
   ciphertext as associated data.
3. **Protected Config** — The account, contacts, relationships, credentials
   and the activity log, encrypted at rest with AES-256-GCM and bound to the
   profile's name as associated data.
4. **Public Config** — Plaintext: the config version, the protection type (and
   a hardware token's id), the friendly name, and the encrypted Protected
   Config. The activity log, which names contacts and DIDs, is no longer here;
   a config written by an earlier release has its log moved into the Protected
   Config the next time it is opened.

`config.json`, exports and startup-failure reports are written owner-only
(`0600` on Unix) from the moment they are created, and atomically: a crash
mid-save leaves the previous file, not a truncated one.

Cryptographic primitives used:

- **AES-256-GCM** for authenticated encryption
- **HKDF-SHA256** for key derivation, with a separate label per kind of encrypted blob
- **Argon2id** for passphrase-based key derivation
- **Ed25519** for digital signatures
- **X25519** for key agreement
- Memory zeroization via `secrecy` and `zeroize` crates

## Disclosure Policy

We follow coordinated disclosure. After a fix is available, we will:

1. Release a patched version
2. Publish a security advisory via GitHub
3. Credit the reporter (unless anonymity is requested)
