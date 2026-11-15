//! A durable, file-backed [`keyring_core`] credential store.
//!
//! # Why this exists
//!
//! Linux has no OS-provided durable secret store that works without a desktop
//! session. The kernel keyring (`linux-keyutils-keyring-store`) — which OpenVTC
//! used unconditionally on Linux — documents itself as RAM-only: *"completely
//! in-memory and will not persist across reboots. Consider the keyring a secure
//! cache."* We were keeping the **only** copy of a profile's BIP32 seed /
//! VTA credential bundle there, so every headless Linux user lost their account
//! on reboot, surfacing as `No matching credential found` at startup.
//!
//! This store is what an operator selects deliberately on such a machine
//! (`OPENVTC_SECURE_STORE=file`): the secret goes to a `0600` file under the
//! profile's config directory, which survives reboots the way the rest of the
//! config already does. It is never chosen automatically — OpenVTC fails
//! closed rather than downgrading its own storage behind the user's back.
//!
//! # The plaintext guard
//!
//! Even when chosen deliberately, this store will not hold a raw seed. A
//! [`SecretPolicy`] callback vets every secret before it is written; OpenVTC
//! supplies one that refuses an unencrypted `SecuredConfig` blob. A profile
//! with no passphrase or token is therefore refused with an explanation
//! naming the fix, rather than having its seed written out in the clear.

use keyring_core::{
    Entry, Error, Result,
    api::{CredentialApi, CredentialPersistence, CredentialStoreApi},
    attributes::parse_attributes,
};
use std::{
    any::Any,
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

/// Vets a secret before it is written to disk.
///
/// Returns `Err(reason)` to refuse the write; `reason` is surfaced to the user
/// verbatim, so it should say what to do, not just what happened.
pub type SecretPolicy = fn(&[u8]) -> std::result::Result<(), String>;

/// Extension used for every secret file this store writes.
const SECRET_EXT: &str = "secret";

/// File-backed credential store rooted at a single directory.
pub struct Store {
    /// Directory holding one file per credential.
    dir: PathBuf,
    /// Optional write-time guard (see the module docs).
    policy: Option<SecretPolicy>,
    /// Instance id, per the keyring-core contract.
    id: String,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileStore")
            .field("dir", &self.dir)
            .field("policy", &self.policy.is_some())
            .finish()
    }
}

impl Store {
    /// Create a store rooted at `dir`, vetting writes with `policy`.
    ///
    /// The directory is created on first write, not here — merely describing
    /// the store (for `openvtc health`, or for a diagnosis of some unrelated
    /// failure) must not have the side effect of creating it.
    #[must_use]
    pub fn new(dir: PathBuf, policy: Option<SecretPolicy>) -> Arc<Self> {
        Arc::new(Store {
            id: format!("openvtc file store at {}", dir.display()),
            dir,
            policy,
        })
    }

    /// The directory this store keeps its secrets in.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

/// Encode one path component so that arbitrary service/user strings map to a
/// single, unambiguous filename.
///
/// Anything outside `[A-Za-z0-9._-]` becomes `%XX`, and `%` itself is escaped,
/// so the mapping is injective — two different credentials can never collide on
/// one file. (OpenVTC's own profile names are already restricted to that set;
/// the encoding is here because the keyring-core API allows any string.)
fn encode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// One credential = one file.
struct Cred {
    path: PathBuf,
    service: String,
    user: String,
    policy: Option<SecretPolicy>,
}

impl std::fmt::Debug for Cred {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileCred")
            .field("path", &self.path)
            .field("service", &self.service)
            .field("user", &self.user)
            .finish()
    }
}

/// Tighten permissions on a path to `mode`, on platforms that have them.
#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

/// Map an io error to the keyring-core error model.
fn io_err(e: std::io::Error) -> Error {
    Error::PlatformFailure(Box::new(e))
}

impl CredentialApi for Cred {
    fn set_secret(&self, secret: &[u8]) -> Result<()> {
        if let Some(policy) = self.policy
            && let Err(reason) = policy(secret)
        {
            return Err(Error::NotSupportedByStore(reason));
        }

        let dir = self
            .path
            .parent()
            .ok_or_else(|| Error::Invalid("path".to_string(), "no parent directory".to_string()))?;
        fs::create_dir_all(dir).map_err(io_err)?;
        // Best-effort: an existing directory with looser permissions is
        // tightened too, so an upgrade from a hand-created directory doesn't
        // leave the secrets world-readable.
        let _ = set_mode(dir, 0o700);

        // Write-then-rename so a crash mid-write cannot truncate a good secret
        // into an unreadable one — the failure mode this whole change exists to
        // stop. The shared routine creates the temporary file 0600 in the same
        // directory, syncs it, and renames it over the secret.
        crate::private_file::atomic_write_private(&self.path, secret).map_err(io_err)
    }

    fn get_secret(&self) -> Result<Vec<u8>> {
        match fs::read(&self.path) {
            Ok(bytes) => Ok(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Error::NoEntry),
            Err(e) => Err(io_err(e)),
        }
    }

    fn get_attributes(&self) -> Result<HashMap<String, String>> {
        // Errors in the same cases as get_secret, per the trait contract.
        self.get_secret()?;
        Ok(HashMap::from([
            (
                crate::secure_store::BACKEND_ATTR.to_string(),
                crate::secure_store::BACKEND_FILE.to_string(),
            ),
            ("path".to_string(), self.path.display().to_string()),
        ]))
    }

    fn delete_credential(&self) -> Result<()> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Error::NoEntry),
            Err(e) => Err(io_err(e)),
        }
    }

    fn get_credential(&self) -> Result<Option<Arc<keyring_core::api::Credential>>> {
        if self.path.exists() {
            Ok(None)
        } else {
            Err(Error::NoEntry)
        }
    }

    fn get_specifiers(&self) -> Option<(String, String)> {
        Some((self.service.clone(), self.user.clone()))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl CredentialStoreApi for Store {
    fn vendor(&self) -> String {
        "OpenVTC encrypted file store".to_string()
    }

    fn id(&self) -> String {
        self.id.clone()
    }

    fn build(
        &self,
        service: &str,
        user: &str,
        modifiers: Option<&HashMap<&str, &str>>,
    ) -> Result<Entry> {
        // No modifiers are supported; parse_attributes rejects any that are
        // passed rather than silently ignoring them.
        parse_attributes(&[], modifiers)?;
        let name = format!(
            "{}.{}.{SECRET_EXT}",
            encode_component(service),
            encode_component(user)
        );
        Ok(Entry::new_with_credential(Arc::new(Cred {
            path: self.dir.join(name),
            service: service.to_string(),
            user: user.to_string(),
            policy: self.policy,
        })))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn persistence(&self) -> CredentialPersistence {
        CredentialPersistence::UntilDelete
    }

    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyring_core::api::CredentialStoreApi;

    /// A policy that refuses anything starting with `plain:`, standing in for
    /// the real "is this blob encrypted?" check.
    fn refuse_plain(secret: &[u8]) -> std::result::Result<(), String> {
        if secret.starts_with(b"plain:") {
            Err("unencrypted".to_string())
        } else {
            Ok(())
        }
    }

    fn tmpdir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("openvtc-filestore-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn round_trips_a_secret() {
        let dir = tmpdir("roundtrip");
        let store = Store::new(dir.clone(), None);
        let entry = store.build("openvtc", "default", None).unwrap();
        entry.set_secret(b"hello").unwrap();
        assert_eq!(entry.get_secret().unwrap(), b"hello");
        // Overwriting replaces rather than appends.
        entry.set_secret(b"bye").unwrap();
        assert_eq!(entry.get_secret().unwrap(), b"bye");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_credential_reports_no_entry() {
        let dir = tmpdir("missing");
        let store = Store::new(dir.clone(), None);
        let entry = store.build("openvtc", "nope", None).unwrap();
        assert!(matches!(entry.get_secret(), Err(Error::NoEntry)));
        assert!(matches!(entry.delete_credential(), Err(Error::NoEntry)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_removes_the_file() {
        let dir = tmpdir("delete");
        let store = Store::new(dir.clone(), None);
        let entry = store.build("openvtc", "default", None).unwrap();
        entry.set_secret(b"x").unwrap();
        entry.delete_credential().unwrap();
        assert!(matches!(entry.get_secret(), Err(Error::NoEntry)));
        let _ = fs::remove_dir_all(&dir);
    }

    /// The guard that keeps a bare seed off the disk. A refusal must be
    /// `NotSupportedByStore` specifically — the composite store routes on it.
    #[test]
    fn policy_refusal_is_distinguishable_and_writes_nothing() {
        let dir = tmpdir("policy");
        let store = Store::new(dir.clone(), Some(refuse_plain));
        let entry = store.build("openvtc", "default", None).unwrap();
        match entry.set_secret(b"plain:seed") {
            Err(Error::NotSupportedByStore(msg)) => assert_eq!(msg, "unencrypted"),
            other => panic!("expected a policy refusal, got {other:?}"),
        }
        assert!(matches!(entry.get_secret(), Err(Error::NoEntry)));
        entry.set_secret(b"sealed").unwrap();
        assert_eq!(entry.get_secret().unwrap(), b"sealed");
        let _ = fs::remove_dir_all(&dir);
    }

    /// Different credentials must never share a file, whatever characters the
    /// service/user contain.
    #[test]
    fn credential_names_do_not_collide() {
        let dir = tmpdir("collide");
        let store = Store::new(dir.clone(), None);
        // Without escaping, "a.b"/"c" and "a"/"b.c" would both flatten to the
        // same "a.b.c.secret".
        let a = store.build("a.b", "c", None).unwrap();
        let b = store.build("a", "b.c", None).unwrap();
        a.set_secret(b"first").unwrap();
        b.set_secret(b"second").unwrap();
        assert_eq!(a.get_secret().unwrap(), b"first");
        assert_eq!(b.get_secret().unwrap(), b"second");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn secret_file_and_directory_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("perms");
        let store = Store::new(dir.clone(), None);
        let entry = store.build("openvtc", "default", None).unwrap();
        entry.set_secret(b"secret").unwrap();

        let dir_mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            dir_mode, 0o700,
            "secrets dir must not be group/world readable"
        );

        let file = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|e| e == SECRET_EXT))
            .expect("secret file written");
        let mode = fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "secret file must be owner-only");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn store_reports_itself_durable() {
        let store = Store::new(tmpdir("persist"), None);
        assert!(matches!(
            store.persistence(),
            CredentialPersistence::UntilDelete
        ));
    }

    /// Describing a store must not create anything — `openvtc health` calls it
    /// on profiles that may not exist.
    #[test]
    fn constructing_a_store_touches_no_disk() {
        let dir = tmpdir("notouch");
        let store = Store::new(dir.clone(), None);
        let _ = store.build("openvtc", "default", None).unwrap();
        assert!(
            !dir.exists(),
            "building a store must not create its directory"
        );
    }
}
