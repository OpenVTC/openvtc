//!  Public [crate::config::Config] information that is stored in plaintext on disk

use crate::{
    config::{
        Config, ConfigProtectionType,
        protected_config::{ProtectedBinding, ProtectedConfig},
    },
    errors::OpenVTCError,
    logs::Logs,
};
use secrecy::SecretBox;
use serde::{Deserialize, Serialize};
use std::{env, fs, path::PathBuf};
use tracing::warn;

/// Current config format version. Increment when the format changes.
///
/// v2 (T1): the multi-community `account` model is the persisted source of
/// truth. There is no in-place v1→v2 migration — a pre-v2 config triggers a
/// breaking reset (D13 / R-RST): the CLI warns, deletes it, and re-runs setup.
pub const CONFIG_VERSION: u32 = 2;

/// Result of [`PublicConfig::delete_profile`]. Mostly informational —
/// callers render `warnings` when surfacing partial-state issues. None of
/// the fields represent fatal errors.
#[derive(Debug, Default)]
pub struct DeleteProfileSummary {
    /// Path of the JSON config that was deleted (if any).
    pub removed_config_file: Option<String>,
    /// True when the openvtc keyring entry was deleted.
    pub removed_keyring_entry: bool,
    /// Best-effort warnings — used for display, not error propagation.
    pub warnings: Vec<String>,
}

/// Primary structure used for storing [crate::config::Config] data that is not sensitive
#[derive(Clone, Serialize, Deserialize, Debug, Default)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct PublicConfig {
    /// Config format version for migration support.
    /// Absent in pre-0.2.0 configs (treated as version 0).
    #[serde(default)]
    pub config_version: u32,

    /// How is the configuration protected?
    pub protection: ConfigProtectionType,

    /// Human friendly name to use when referring to ourself
    pub friendly_name: String,

    /// The activity log as older configs stored it, in clear (#568).
    ///
    /// Read, never written: the log lives in the encrypted
    /// [`ProtectedConfig::logs`]. [`PublicConfig::migrate_logs_into`] moves
    /// what an older config carried there, and the next save leaves this key
    /// out of the file.
    #[serde(rename = "logs", default, skip_serializing)]
    pub legacy_logs: Logs,

    /// The [`ProtectedConfig`] sealed by [`ProtectedConfig::save`], `None` before one
    /// has been written.
    #[serde(default)]
    pub private: Option<String>,
}

impl From<&Config> for PublicConfig {
    /// Extracts public information from the full Config
    fn from(cfg: &Config) -> Self {
        cfg.public.clone()
    }
}

/// Validates that a profile name contains only safe characters.
///
/// Trims leading/trailing whitespace before validating so that
/// `" default "` is treated as `"default"`. Rejects whitespace-only
/// inputs explicitly with a clear error rather than letting them fall
/// through the alphanumeric check (which would emit a confusing
/// "Invalid profile name '   '" message). The empty/whitespace check
/// runs first so an empty string can't reach the character check.
pub fn validate_profile_name(profile: &str) -> Result<(), OpenVTCError> {
    let trimmed = profile.trim();

    if trimmed.is_empty() {
        return Err(OpenVTCError::Config(
            "Profile name cannot be empty or contain only whitespace".to_string(),
        ));
    }

    if trimmed != "default"
        && !trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(OpenVTCError::Config(format!(
            "Invalid profile name '{trimmed}'. Only alphanumeric characters, hyphens, and underscores are allowed."
        )));
    }
    Ok(())
}

/// Resolve the directory that holds OpenVTC profile data — config files,
/// the did.jsonl log, etc. Honours `OPENVTC_CONFIG_PATH`. Falls back to
/// `~/.config/openvtc/` on Unix/macOS, and to the platform's AppData
/// location (`%APPDATA%\openvtc`, via `dirs::config_dir()`) on Windows.
/// Validates the profile name as a side effect.
pub fn profile_dir(profile: &str) -> Result<PathBuf, OpenVTCError> {
    validate_profile_name(profile)?;
    if let Ok(config_path) = env::var("OPENVTC_CONFIG_PATH") {
        return Ok(PathBuf::from(config_path));
    }
    #[cfg(windows)]
    {
        dirs::config_dir()
            .map(|p| p.join("openvtc"))
            .ok_or_else(|| {
                OpenVTCError::Config("Couldn't determine configuration directory".to_string())
            })
    }
    #[cfg(not(windows))]
    {
        dirs::home_dir()
            .map(|p| p.join(".config").join("openvtc"))
            .ok_or_else(|| OpenVTCError::Config("Couldn't determine Home directory".to_string()))
    }
}

/// Private helper to determine where the config file is located.
/// Returns a `PathBuf` so callers don't have to round-trip through a
/// (potentially non-UTF-8) string.
fn get_config_path(profile: &str) -> Result<PathBuf, OpenVTCError> {
    let mut path = profile_dir(profile)?;
    if profile == "default" {
        path.push("config.json");
    } else {
        path.push(format!("config-{profile}.json"));
    }
    Ok(path)
}

impl PublicConfig {
    /// Move the activity log an older config kept in this plaintext tier into
    /// the encrypted `private` tier, leaving none here. Returns how many
    /// entries moved.
    ///
    /// Crash-safe because both tiers are in the one file: the save that
    /// follows writes the moved entries (inside `private`) and drops them from
    /// the plaintext part in a single atomic write. Until then the file is
    /// unchanged and the move is simply repeated on the next load.
    pub fn migrate_logs_into(&mut self, private: &mut ProtectedConfig) -> usize {
        let moved = self.legacy_logs.messages.len();
        if moved > 0 {
            private.logs.absorb(std::mem::take(&mut self.legacy_logs));
        }
        moved
    }

    /// Saves to disk the public configuration information
    /// Uses the default CONFIG_PATH const or ENV Variable OPENVTC_CONFIG_PATH
    ///
    /// `private` is encrypted under `private_seed` and bound to `profile`
    /// ([`ProtectedBinding::Profile`]). The file is replaced atomically and is
    /// owner-only from creation (`0600` on Unix); a missing profile directory
    /// is created `0700`. A `config.json` that is a symlink is written where
    /// it points, so a profile kept in another directory on purpose still
    /// saves.
    pub fn save(
        &self,
        profile: &str,
        private: &ProtectedConfig,
        private_seed: &SecretBox<Vec<u8>>,
    ) -> Result<(), OpenVTCError> {
        let mut path = get_config_path(profile)?;

        if let Some(parent_path) = path.parent() {
            crate::private_file::create_private_dir(parent_path).map_err(|e| {
                OpenVTCError::Config(format!(
                    "Couldn't create parent directory ({}): {e}",
                    parent_path.to_string_lossy()
                ))
            })?;
        }
        if fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
            path = fs::canonicalize(&path).map_err(|e| {
                OpenVTCError::Config(format!(
                    "Couldn't resolve the config file link ({}): {e}",
                    path.to_string_lossy()
                ))
            })?;
        }

        let public = PublicConfig {
            config_version: CONFIG_VERSION,
            private: Some(private.save(private_seed, ProtectedBinding::Profile(profile))?),
            ..self.clone()
        };
        crate::private_file::atomic_write_private(
            &path,
            serde_json::to_string_pretty(&public)?.as_bytes(),
        )
        .map_err(|e| {
            OpenVTCError::Config(format!(
                "Couldn't write public config to file ({}): {e}",
                path.to_string_lossy()
            ))
        })?;

        Ok(())
    }

    ///
    /// Removes the public config JSON file under the resolved config path
    /// and (best-effort) deletes the matching `SecuredConfig` keyring
    /// entry. Each step is idempotent — both succeed when the artifact is
    /// already gone, so the function is safe to run against a partial /
    /// already-clean install.
    ///
    /// Caller is expected to coordinate other cleanup (e.g.
    /// `did_git_sign::init::uninstall`) themselves; this function only
    /// owns openvtc's own state.
    /// Tear down the on-disk + OS-keyring footprint of a profile.
    ///
    /// Removes the public config JSON file under the resolved config path
    /// and (best-effort) deletes the matching `SecuredConfig` keyring
    /// entry. Each step is idempotent — both succeed when the artifact is
    /// already gone, so the function is safe to run against a partial /
    /// already-clean install.
    ///
    /// Caller is expected to coordinate other cleanup (e.g.
    /// `did_git_sign::init::uninstall`) themselves; this function only
    /// owns openvtc's own state.
    pub fn delete_profile(profile: &str) -> Result<DeleteProfileSummary, OpenVTCError> {
        validate_profile_name(profile)?;
        let mut summary = DeleteProfileSummary::default();

        let path = get_config_path(profile)?;
        if path.exists() {
            fs::remove_file(&path).map_err(|e| {
                OpenVTCError::Config(format!(
                    "Couldn't remove public config file ({}): {e}",
                    path.to_string_lossy()
                ))
            })?;
            summary.removed_config_file = Some(path.to_string_lossy().into_owned());
        }

        // Whatever happens below, the next save to this profile must write.
        crate::config::secured_config::forget_written(profile);

        // Drop the SecuredConfig keyring entry if present. `delete_credential`
        // returns `NoEntry` when nothing is stored — swallow that case.
        match keyring_core::Entry::new(crate::config::secured_config::service_name(), profile) {
            Ok(entry) => match entry.delete_credential() {
                Ok(()) => summary.removed_keyring_entry = true,
                Err(keyring_core::Error::NoEntry) => {}
                Err(e) => {
                    summary
                        .warnings
                        .push(format!("could not remove keyring entry: {e}"));
                }
            },
            Err(e) => {
                summary
                    .warnings
                    .push(format!("could not access keyring entry: {e}"));
            }
        }

        Ok(summary)
    }

    /// Loads from disk the public information for OpenVTC to unlock it's secrets from the OS Secure
    /// Store
    pub fn load(profile: &str) -> Result<Self, OpenVTCError> {
        let path = get_config_path(profile)?;

        let file = fs::File::open(&path)
            .map_err(|e| OpenVTCError::ConfigNotFound(path.to_string_lossy().into_owned(), e))?;

        let config: Self = match serde_json::from_reader(file) {
            Ok(s) => s,
            Err(e) => {
                warn!("Couldn't Deserialize PublicConfig. Reason: {e}");
                return Err(e.into());
            }
        };

        // Breaking reset (D13 / R-RST-1): a pre-v2 config cannot be migrated in
        // place. Detect it here — on the plaintext public config, before any
        // decryption that assumes the v2 shape — and surface a typed error the
        // CLI maps to a "warn → delete → fresh setup" flow.
        if config.config_version < CONFIG_VERSION {
            warn!(
                from = config.config_version,
                to = CONFIG_VERSION,
                "incompatible config version — breaking reset required"
            );
            return Err(OpenVTCError::ConfigVersionUnsupported {
                found: config.config_version,
                expected: CONFIG_VERSION,
            });
        }

        Ok(config)
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Guards tests that mutate the OPENVTC_CONFIG_PATH env var so they
    /// don't race against each other.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_get_config_path_default_profile() {
        let _guard = ENV_LOCK.lock().unwrap();
        let base = if cfg!(windows) {
            "C:\\tmp\\openvtc-test"
        } else {
            "/tmp/openvtc-test"
        };
        unsafe { env::set_var("OPENVTC_CONFIG_PATH", base) };
        let path = get_config_path("default").unwrap();
        let mut expected = PathBuf::from(base);
        expected.push("config.json");
        assert_eq!(path, expected);
        unsafe { env::remove_var("OPENVTC_CONFIG_PATH") };
    }

    #[test]
    fn test_get_config_path_named_profile() {
        let _guard = ENV_LOCK.lock().unwrap();
        let base = if cfg!(windows) {
            "C:\\tmp\\openvtc-test"
        } else {
            "/tmp/openvtc-test"
        };
        unsafe { env::set_var("OPENVTC_CONFIG_PATH", base) };
        let path = get_config_path("work").unwrap();
        let mut expected = PathBuf::from(base);
        expected.push("config-work.json");
        assert_eq!(path, expected);
        unsafe { env::remove_var("OPENVTC_CONFIG_PATH") };
    }

    #[test]
    fn test_get_config_path_trailing_slash_normalization() {
        let _guard = ENV_LOCK.lock().unwrap();
        let (base_with, base_without) = if cfg!(windows) {
            ("C:\\tmp\\cfg\\", "C:\\tmp\\cfg")
        } else {
            ("/tmp/cfg/", "/tmp/cfg")
        };
        unsafe { env::set_var("OPENVTC_CONFIG_PATH", base_with) };
        let path_with = get_config_path("default").unwrap();
        unsafe { env::set_var("OPENVTC_CONFIG_PATH", base_without) };
        let path_without = get_config_path("default").unwrap();
        assert_eq!(
            path_with, path_without,
            "trailing slash should not affect the resolved path"
        );
        unsafe { env::remove_var("OPENVTC_CONFIG_PATH") };
    }

    #[test]
    fn test_get_config_path_fallback() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe { env::remove_var("OPENVTC_CONFIG_PATH") };
        let path = get_config_path("default").unwrap();
        let mut expected_suffix = PathBuf::new();
        expected_suffix.push("openvtc");
        expected_suffix.push("config.json");
        assert!(
            path.ends_with(&expected_suffix),
            "fallback path should end with openvtc/config.json: {}",
            path.display()
        );
    }

    #[test]
    fn test_load_pre_v2_config_triggers_breaking_reset() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join("openvtc-reset-test");
        let _ = fs::create_dir_all(&dir);
        unsafe { env::set_var("OPENVTC_CONFIG_PATH", &dir) };

        // Write a v1-shaped config (config_version = 1) to disk.
        let old = PublicConfig {
            config_version: 1,
            ..PublicConfig::default()
        };
        fs::write(
            dir.join("config.json"),
            serde_json::to_string_pretty(&old).unwrap(),
        )
        .unwrap();

        let err = PublicConfig::load("default").unwrap_err();
        assert!(
            matches!(
                err,
                OpenVTCError::ConfigVersionUnsupported {
                    found: 1,
                    expected: CONFIG_VERSION
                }
            ),
            "pre-v2 config must surface ConfigVersionUnsupported, got: {err:?}"
        );

        let _ = fs::remove_file(dir.join("config.json"));
        unsafe { env::remove_var("OPENVTC_CONFIG_PATH") };
    }

    /// An older config's plaintext log is read, moved into the protected tier,
    /// and never written back out in clear (#568).
    #[test]
    fn plaintext_logs_move_to_the_protected_tier() {
        let old = r#"{
            "config_version": 2,
            "protection": "Plaintext",
            "friendly_name": "me",
            "logs": {"messages": [
                {"created": "2026-01-01T00:00:00Z", "type_": "Contact",
                 "message": "Added contact (did:example:bob) alias(bob)"}
            ]},
            "private": null
        }"#;
        let mut pc: PublicConfig = serde_json::from_str(old).unwrap();
        assert_eq!(pc.legacy_logs.messages.len(), 1);

        let mut private = ProtectedConfig::default();
        assert_eq!(pc.migrate_logs_into(&mut private), 1);
        assert!(pc.legacy_logs.is_empty());
        assert_eq!(
            private.logs.messages[0].message,
            "Added contact (did:example:bob) alias(bob)"
        );

        // Even a stale in-memory copy never writes the log in clear.
        pc.legacy_logs = private.logs.clone();
        let json = serde_json::to_string(&pc).unwrap();
        assert!(!json.contains("did:example:bob"), "{json}");
        assert!(!json.contains("\"logs\""), "{json}");
    }

    #[cfg(unix)]
    #[test]
    fn save_writes_an_owner_only_file_atomically() {
        use std::os::unix::fs::PermissionsExt;
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!(
            "openvtc-save-test-{}-{:x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let profile_dir = dir.join("nested");
        unsafe { env::set_var("OPENVTC_CONFIG_PATH", &profile_dir) };

        let seed = SecretBox::new(Box::new(vec![5u8; 32]));
        let mut private = ProtectedConfig::default();
        private
            .logs
            .insert(crate::logs::LogFamily::Contact, "did:example:carol".into());
        let pc = PublicConfig {
            config_version: CONFIG_VERSION,
            protection: ConfigProtectionType::Plaintext,
            ..PublicConfig::default()
        };
        let saved = pc.save("savetest", &private, &seed);
        unsafe { env::remove_var("OPENVTC_CONFIG_PATH") };
        saved.unwrap();

        let file = profile_dir.join("config-savetest.json");
        let mode = fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let dir_mode = fs::metadata(&profile_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);

        let text = fs::read_to_string(&file).unwrap();
        assert!(!text.contains("did:example:carol"), "log is encrypted");
        let back: PublicConfig = serde_json::from_str(&text).unwrap();
        let reopened = ProtectedConfig::load(
            &seed,
            back.private.as_deref().unwrap(),
            ProtectedBinding::Profile("savetest"),
        )
        .unwrap();
        assert_eq!(reopened.logs.messages.len(), 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_public_config_default() {
        let pc = PublicConfig::default();
        assert!(pc.friendly_name.is_empty());
        assert!(pc.private.is_none());
        assert_eq!(pc.config_version, 0);
    }

    /// Smoke-test the `arbitrary` fuzz seam (issue #124): a `PublicConfig`
    /// must be constructible from raw bytes via `Arbitrary` and the result
    /// must round-trip through serde, so structure-aware fuzz harnesses can
    /// generate inputs and feed them straight at the deserializer.
    #[cfg(feature = "arbitrary")]
    #[test]
    fn test_public_config_arbitrary_roundtrips() {
        use arbitrary::{Arbitrary, Unstructured};

        let raw: Vec<u8> = (0..=255u8).cycle().take(512).collect();
        let mut u = Unstructured::new(&raw);
        let pc = PublicConfig::arbitrary(&mut u).expect("construct from bytes");
        let json = serde_json::to_string(&pc).expect("serialize arbitrary config");
        serde_json::from_str::<PublicConfig>(&json).expect("re-parse serialized config");
    }
}
