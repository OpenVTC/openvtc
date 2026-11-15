# Backup and Restore

A profile has two halves: the config file on disk and its secrets in the
credential store (see the [`openvtc` README](../openvtc/README.md#secure-storage)).
A backup holds both, so it can move a profile to another machine or bring one
back after a loss.

There are no `export` or `import` subcommands. Backup and restore happen in the
TUI.

## Back up a profile

1. Launch the TUI: `openvtc` (or `openvtc -p <profile>`).
2. Open **Settings** and choose **Export Config**.
3. Enter a file path and a passphrase, then confirm.

The backup holds the public config (with the encrypted protected config inside
it) and the secured config, including the key material from the credential
store. It is encrypted with AES-256-GCM under a key derived from the passphrase
with Argon2id, using a fresh random salt for each export. On Unix the file is
written with mode `0600` from the moment it is created, and a symlink at the
chosen path is refused rather than followed. The backup is not tied to the
profile it came from, so it can be restored under any profile name.

Keep the backup and its passphrase somewhere safe. Anyone with both has the
profile's secrets.

## Restore a profile

1. Run `openvtc setup` (add `-p <profile>` to restore into a named profile).
2. Choose **Recover from backup**.
3. Enter the backup file path, the backup passphrase (blank if it had none),
   and a new unlock code for this profile (blank for none).
4. Exit and start OpenVTC again to load the restored profile.

Settings has no import action. Importing into a running profile is not
supported; use the setup wizard.

## Recover from the VTA

Without a backup, part of an account can be rebuilt from its VTA Trust Context.

- `openvtc health --recoverable` reports, read-only, whether this account could
  be rebuilt from its Trust Context if this machine were lost.
- During `openvtc setup`, if the Trust Context you are setting up into already
  holds an account, the wizard offers **[R] Recover this account**. It lists
  what will be restored (identities and memberships) and, at the same weight,
  what will not. Nothing is written until you confirm.

The rebuild itself does not restore community names and flags, relationships,
contacts or activity history. Copies of the first three that were synced to the
VTA return on first launch; anything never synced, and the activity history, is
lost. Make a backup if you need it.
