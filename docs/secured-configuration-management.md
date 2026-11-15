# Handling Secured Configuration

The OpenVTC CLI tool keeps its most sensitive configuration, the
`SecuredConfig`, in a secure store on your device. The stored value is a
single-line JSON envelope whose payloads are base64url-encoded (see
[Storage format](#storage-format-and-why-it-is-one-line)).

## Where it is stored

By default OpenVTC uses the OS credential store, under service `openvtc` with
the profile name as the account:

- macOS: the system Keychain.
- Windows: Windows Credential Manager.
- Linux: the Secret Service (for example GNOME Keyring, KWallet or KeePassXC).

If the OS credential store cannot be opened, OpenVTC exits with an
explanation. It does not fall back to another store on its own.

On a Linux machine with no keyring daemon, you can choose an encrypted file
store instead:

```bash
OPENVTC_SECURE_STORE=file openvtc
```

The secret is then written to the `secrets/` folder in the profile directory
(`~/.config/openvtc/secrets/` by default), with file mode `0600`. The file
store refuses a profile that has no unlock code or hardware token, so key
material is never written to disk unencrypted.

`OPENVTC_SECURE_STORE=keyutils` (the Linux kernel keyring) is deprecated and
exists only to migrate a profile written by an older OpenVTC. The kernel
keyring is held in memory and is lost on reboot. Any other value is an error.
See the Secure Storage section of [`openvtc/README.md`](../openvtc/README.md).

## What it contains

- **VTA key backend (the normal case):** the VTA credential bundle OpenVTC
  uses to authenticate to the VTA, the VTA's DID, its URL (absent for
  DIDComm-only VTAs) and its DIDComm mediator DID. Persona and relationship
  keys are held by the VTA, not on this device.
- **Legacy BIP32 backend:** the BIP32 seed from which keys are derived. It is
  present only in BIP32-based configs; setup no longer creates them.
- The key that encrypts the protected config (`protected_key`).
- Key info: for each key ID, where the key came from (a BIP32 derivation
  path, an imported multi-encoded private key, or a VTA key ID), when it was
  created, and its purpose.

OpenVTC protects this configuration in one of three ways.

## Hardware Token

During setup, the tool can use a hardware token that implements the OpenPGP
card standard.

To save the configuration, the tool:

1. Generates a random 32-byte session key.

2. Encrypts the configuration with AES-256-GCM, using a key derived from the
   session key with HKDF-SHA256.

3. Encrypts the session key with the public key in the token's decryption
   slot, producing an Encrypted Session Key (ESK).

The ESK and the encrypted configuration are stored together in the secure
store.

To read the configuration later, the tool:

1. Asks the token to decrypt the ESK with its private key. The token must be
   present, and its user PIN is required.

2. Uses the recovered session key to decrypt the configuration with
   AES-256-GCM.

## Unlock Code

If you do not use a hardware token, you can set an unlock code to protect the
configuration. It must be at least 8 characters.

The unlock code is not stored. To save the configuration, the tool:

1. Derives a 32-byte key from the unlock code with Argon2id (128 MiB of
   memory, 4 iterations, 1 lane), salted with 16 random bytes drawn for this
   profile when the code is set. The salt is stored beside the ciphertext, so
   two profiles with the same code have unrelated keys.

2. Generates a random 12-byte nonce and derives an AES-256-GCM key from the
   Argon2id key with HKDF-SHA256 (nonce as salt, info
   `openvtc/secured-config/v2`).

3. Encrypts the configuration with AES-256-GCM, with
   `openvtc/secured-config/v2\0profile\0{profile}` as associated data, and
   stores it as `{"format":"PasswordSealed","salt":…,"sealed":…}`. The blob
   opens only as the profile it was written for.

To read the configuration later, the tool asks for the unlock code, derives
the same Argon2id key, and decrypts. A wrong unlock code fails the AES-GCM
authentication check. The tool checks the code at the prompt, so a wrong code
can be entered again.

Exported config files use the `OPV3` format: a random 16-byte Argon2id salt
per export stored in the file, the export label in the HKDF step, and the
header bound as associated data (`passphrase_encrypt`). Imports still accept
the `OPV2` and older fixed-salt export formats.

### Format versions and migration

| `format` | Written by | Key | Associated data |
| --- | --- | --- | --- |
| `PasswordSealed` | current releases | Argon2id, per-profile random salt | `openvtc/secured-config/v2\0profile\0{profile}` |
| `PasswordEncrypted` | earlier releases (read only) | Argon2id, one fixed salt for every install | none |

A profile still in `PasswordEncrypted` is rewritten as `PasswordSealed` the
first time it is unlocked. That is one store write replacing one entry: the
new envelope is decrypted in memory before it is written and read back after,
and the original is put back if the read-back fails. Either version opens with
the same unlock code, so a crash at any point leaves a profile that opens.
Once migrated, a profile cannot be opened by a release that predates
`PasswordSealed`; that release reports the stored blob as unrecognised.

Because the profile name is bound into the blob, renaming a profile by hand
(moving its keyring entry or `config-{profile}.json`) makes it unopenable
under the new name. Move a profile with export and import instead.

## Plaintext

The plaintext option stores the configuration unencrypted in the secure store,
protected only by the store itself. Setup offers it only after a warning, and
it can also be chosen later by removing the passphrase in Settings. The file
store refuses plaintext profiles.

On load, the tool checks that the stored format matches the protection the
profile expects. A plaintext blob found where an encrypted one is expected is
refused.

## Storage format (and why it is one line)

Whichever of the three protections is in use, the value handed to the OS
credential store is the same shape: a single-line, compact JSON envelope whose
payloads are all BASE64URL. `openvtc-core/src/config/secured_config.rs`
(`encode_blob`) is the only place that writes it, and it refuses to emit a
secret containing a line break, a control character, a backslash, or any
non-ASCII byte.

That is a hard requirement, not a style preference. gnome-keyring writes an
item's secret into `~/.local/share/keyrings/*.keyring` verbatim, but reads it
back through `GKeyFile` *unescaping*. A secret with a raw newline in it
therefore comes back as extra lines of the keyring file, and the daemon fails
to parse the file at all:

```text
keyring was in an invalid or unrecognized format: .../Default_keyring.keyring
```

The blast radius is the whole collection, not just the OpenVTC item — every
other secret in the user's login keyring becomes unreadable too.

### Recovering a keyring OpenVTC has already corrupted

Releases before this fix stored the envelope pretty-printed, so on a Secret
Service backend the first save would break the login keyring. The data is
orphaned, not destroyed. To recover:

1. Stop the daemon so it cannot rewrite anything under you:
   `systemctl --user stop gnome-keyring-daemon.service` (or log out).
2. Copy the whole `~/.local/share/keyrings/` directory somewhere safe before
   touching it.
3. Look at the `default` file — a small pointer naming the active keyring. If
   the unlock prompt was answered at some point after the breakage, the answer
   created a *new* empty keyring and repointed `default` at it; note the
   original name so you can point it back.
4. In the original `.keyring` file, find the OpenVTC item's secret: it is the
   value that spills across several lines instead of one. Either join it back
   into a single line or delete that item's block entirely — the rest of the
   file parses again either way.
5. Point `default` back at the original keyring, restart the daemon, and
   confirm with `secret-tool search --all service openvtc`.

If the OpenVTC item itself cannot be salvaged, the profile's secret half is
gone and the config file alone will not start it — see
[backup-restore.md](backup-restore.md) for what that costs and what can be
recovered from the VTA.
