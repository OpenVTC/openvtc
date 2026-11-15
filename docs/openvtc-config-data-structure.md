# OpenVTC Config Data Structure

An OpenVTC profile is stored in three layers. This page says what lives in
each layer and how each is protected. It does not list fields: those change
often, and the rustdoc is the reference for them.

- **Field-level detail:** [openvtc-core on docs.rs](https://docs.rs/openvtc-core)
  (module `openvtc_core::config`).
- **Source:** `openvtc-core/src/config/` — `public_config.rs`,
  `protected_config.rs`, `secured_config.rs`, `account.rs` and `mod.rs`.

## The three layers

| Layer | Type | Where it is stored | Protection |
| ----- | ---- | ------------------ | ---------- |
| Public config | `PublicConfig` | `config.json` (or `config-{profile}.json`) in the profile directory | Plaintext JSON, file mode `0600` on Unix |
| Protected config | `ProtectedConfig` | Inside the public config, in its `private` field | Always encrypted (AES-256-GCM) |
| Secured config | `SecuredConfig` | OS credential store, or the encrypted file store | Unlock code, hardware token, or none |

The profile directory is `~/.config/openvtc/` on macOS and Linux, and
`%APPDATA%\openvtc` on Windows. `OPENVTC_CONFIG_PATH` overrides it. See
[Profiles and Configurations](../README.md#profiles-and-configurations).

At run time the three layers are combined into one `Config` value. On save,
the secured config is written to the secure store first, then the public
config (with the protected config encrypted inside it) is written to disk.

### Public config

Plaintext JSON on disk. It holds:

- the config format version (`config_version`);
- how the secured config is protected (`protection`: `Encrypted`, `Token`
  with the token ID, or `Plaintext`);
- the profile's friendly name;
- the encrypted protected config (`private`).

Configs written by earlier releases also kept the activity log (`logs`) here,
in plaintext. It is read and moved into the protected config the next time the
profile is opened, and is no longer written to this layer.

### Protected config

Encrypted, and stored as a base64url string in the public config's `private`
field. It holds everything about the account that is sensitive but is not
key material.

Its centre is the **account** (`Account`, in `account.rs`):

- `Account` records the VTA the account is provisioned against and the
  top-level VTA context it administers.
- `Account.personas` holds the account's personas (`PersonaRecord`). Each is
  a `did:webvh` or `did:scid:vh:1` identity. Its keys are held by the VTA; the
  record keeps only non-secret key references (`KeyRef`).
- `Account.communities` holds community memberships (`CommunityRecord`),
  grouped by the community's VTC DID. Each membership names the persona it
  presents, its lifecycle status, its relationships and VRCs within that
  community, and the credentials the community issued.

Alongside the account, the protected config holds:

- `contacts` — known DIDs and their aliases;
- `relationships` — DIDComm relationships;
- `tsp_relationships` — TSP relationship state, kept separate from the
  DIDComm relationships;
- `tasks` — pending and completed tasks;
- `vrcs_issued` and `vrcs_received` — verifiable relationship credentials;
- `agent_names` — a cache of verified agent names, keyed by DID (only
  verified names are stored; see `openvtc-core/src/agent_name.rs`);
- `vetting` — peer identity vetting;
- `seen_documents` — operational documents already acted on, so a replay is
  refused across restarts;
- `deferred_inbound` — inbound messages set aside for a check, kept across a
  restart;
- `vta_sync` — sync state with the VTA's application-state store;
- `witnessings` — witnessings completed through the VTA;
- `logs` — the activity log. Its entries can name contacts and DIDs, which is
  why it is encrypted here. Entries belong to a `LogFamily`: `Relationship`,
  `Contact`, `Task`, `Config` or `Community`. Each message is stripped of
  control, bidi and zero-width characters and capped at 1024 characters as it
  is added, since many quote text a peer sent.

The payload carries a `schema_version`. Fields written by a newer build are
kept in `extra` so an older build does not drop them on save.

### Secured config

Stored in the OS credential store (macOS Keychain, Windows Credential
Manager, or Secret Service on Linux), under service `openvtc` with the
profile name as the account. On Linux, `OPENVTC_SECURE_STORE=file` selects an
encrypted file store under the profile directory's `secrets/` folder instead.
The file store refuses a profile that has no unlock code or hardware token.
See [Handling Secured Configuration](./secured-configuration-management.md)
and the Secure Storage section of [`openvtc/README.md`](../openvtc/README.md).

It holds:

- for the VTA key backend: the VTA credential bundle (`credential_bundle`),
  the VTA's DID (`vta_did`), its URL (`vta_url`, absent for DIDComm-only
  VTAs) and its DIDComm mediator DID (`mediator_did`);
- for legacy BIP32-based configs only: the BIP32 seed (`bip32_seed`);
- the key that encrypts the protected config (`protected_key`);
- `key_info` — for each key ID, where the key came from (BIP32 path,
  imported, or VTA-managed), when it was created, and its purpose
  (`KeyTypes`).

When a hardware token protects the secured config, the stored envelope also
carries the encrypted session key (ESK) that the token decrypts.

## Key backends

`KeyBackend` (in `mod.rs`) decides where keys live:

- `KeyBackend::Vta` — keys are created and held by the VTA. OpenVTC stores
  the credential bundle it uses to authenticate to the VTA, and non-secret
  key references. Setup creates this backend.
- `KeyBackend::Bip32` — legacy. Keys are derived locally from a BIP32 seed
  held in the secured config. Existing BIP32-based configs still load.

## How the protected config is encrypted

- The key is `protected_key`: 32 random bytes from the OS random number
  generator, created on first save and stored in the secured config.
- Each save uses a fresh random 12-byte nonce. An AES-256-GCM key is derived
  from `protected_key` with HKDF-SHA256 (nonce as salt, info
  `openvtc/protected-config/v2`). The stored blob is
  `"OPC2" | nonce | ciphertext + tag`, with
  `openvtc/protected-config/v2\0profile\0{profile}` as associated data, so it
  opens only as the profile it was written for. In an export the associated
  data names `export` instead, so the export imports into any profile.
- Blobs written before that format (no `OPC2` prefix, info `openvtc-key-v2`,
  no associated data) are still read, and rewritten by the next save.
- Because the key is stored, not derived from the VTA credential, the
  credential can be rotated without losing access to the protected config.
- Configs written before `protected_key` existed were encrypted with a key
  derived from the key backend: BIP32 path `m/0'/0'/0'`, or HKDF-SHA256 over
  the VTA credential's private key. These are still read, and are re-encrypted
  under a new `protected_key` on the next save.

## Further reading

- [Handling Secured Configuration](./secured-configuration-management.md)
- [Secure Key Management](./secure-key-management.md)
- [Relationships and VRCs](./relationships-vrcs.md)
- [Backup and restore](./backup-restore.md)
