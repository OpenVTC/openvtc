//! Single-instance enforcement via lock files.
//!
//! Detects and prevents duplicate instances of the application running
//! against the same profile.
//!
//! # Usage
//!
//! ```no_run
//! use openvtc_core::process_lock::{check_duplicate_instance, remove_lock_file};
//!
//! let lock_path = check_duplicate_instance("default").expect("already running");
//! // … run application …
//! remove_lock_file(&lock_path);
//! ```

use crate::errors::OpenVTCError;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process,
    str::FromStr,
};
use sysinfo::{Pid, ProcessRefreshKind, RefreshKind, System};

/// Checks whether another instance of openvtc is already running for `profile`.
///
/// Uses atomic `create_new(true)` to avoid TOCTOU race conditions — if two
/// processes start simultaneously, only one will successfully create the lock
/// file; the other will see `AlreadyExists` and check the existing PID.
///
/// If no duplicate is found a lock file containing the current PID is created
/// and its path is returned so the caller can [`remove_lock_file`] it on exit.
///
/// # Errors
///
/// - [`OpenVTCError::DuplicateInstance`] — another live process holds the lock.
/// - [`OpenVTCError::LockFile`] — the lock file could not be read or created.
pub fn check_duplicate_instance(profile: &str) -> Result<PathBuf, OpenVTCError> {
    let lock_file = get_lock_file(profile)?;

    // Ensure parent directory exists
    if let Some(parent) = lock_file.parent()
        && !parent.exists()
    {
        fs::create_dir_all(parent)
            .map_err(|e| OpenVTCError::LockFile(format!("couldn't create lock directory: {e}")))?;
    }

    // Attempt atomic lock file creation — avoids TOCTOU race
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_file)
    {
        Ok(mut file) => {
            // We won the race — write our PID
            file.write_all(process::id().to_string().as_bytes())
                .map_err(|e| {
                    OpenVTCError::LockFile(format!("couldn't write PID to lock file: {e}"))
                })?;
            return Ok(lock_file);
        }
        Err(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Lock file exists — check if the owning process is still alive
        }
        Err(e) => {
            return Err(OpenVTCError::LockFile(format!(
                "couldn't create lock file: {e}"
            )));
        }
    }

    // Lock file already exists — read and validate the PID
    let pid_str = fs::read_to_string(&lock_file)
        .map_err(|e| OpenVTCError::LockFile(format!("couldn't read lock file: {e}")))?;
    let pid_str = pid_str.trim_end();

    let system = System::new_with_specifics(
        RefreshKind::nothing().with_processes(ProcessRefreshKind::nothing()),
    )
    .map_err(|e| OpenVTCError::LockFile(format!("couldn't read the process list: {e}")))?;
    let pid = Pid::from_str(pid_str)
        .map_err(|e| OpenVTCError::LockFile(format!("invalid PID in lock file: {e}")))?;

    if system.process(pid).is_some() {
        return Err(OpenVTCError::DuplicateInstance(profile.to_string()));
    }

    // Stale lock file — overwrite with our PID
    create_lock_file(&lock_file)?;
    Ok(lock_file)
}

/// Returns the canonical path to the lock file for `profile`.
///
/// Honours `OPENVTC_CONFIG_PATH`. Falls back to `~/.config/openvtc/` on
/// Unix/macOS, and to the platform's AppData location
/// (`%APPDATA%\openvtc`, via `dirs::config_dir()`) on Windows.
///
/// # Errors
///
/// Returns [`OpenVTCError::LockFile`] if the configuration directory
/// cannot be determined.
pub(crate) fn get_lock_file(profile: &str) -> Result<PathBuf, OpenVTCError> {
    let mut path = if let Ok(config_path) = std::env::var("OPENVTC_CONFIG_PATH") {
        PathBuf::from(config_path)
    } else {
        #[cfg(windows)]
        {
            dirs::config_dir()
                .map(|p| p.join("openvtc"))
                .ok_or_else(|| {
                    OpenVTCError::LockFile("couldn't determine configuration directory".to_string())
                })?
        }
        #[cfg(not(windows))]
        {
            dirs::home_dir()
                .map(|p| p.join(".config").join("openvtc"))
                .ok_or_else(|| {
                    OpenVTCError::LockFile("couldn't determine home directory".to_string())
                })?
        }
    };

    if profile == "default" {
        path.push("config.lock");
    } else {
        path.push(format!("config-{profile}.lock"));
    }
    Ok(path)
}

/// Writes a lock file at `lock_file` containing the current process PID.
///
/// Parent directories are created if they do not already exist.
///
/// # Errors
///
/// Returns [`OpenVTCError::LockFile`] on any I/O failure.
pub(crate) fn create_lock_file<P: AsRef<Path>>(lock_file: P) -> Result<(), OpenVTCError> {
    let lock_file = lock_file.as_ref();
    if let Some(parent) = lock_file.parent()
        && !parent.exists()
    {
        fs::create_dir_all(parent)
            .map_err(|e| OpenVTCError::LockFile(format!("couldn't create lock directory: {e}")))?;
    }

    fs::write(lock_file, process::id().to_string()).map_err(|e| {
        OpenVTCError::LockFile(format!(
            "couldn't write lock file '{}': {e}",
            lock_file.to_string_lossy()
        ))
    })?;
    Ok(())
}

/// Removes the lock file at `lock_file`, ignoring any errors.
///
/// Errors are silently discarded because this is always called during
/// application shutdown, where there is no meaningful recovery path.
pub fn remove_lock_file<P: AsRef<Path>>(lock_file: P) {
    let _ = fs::remove_file(lock_file);
}
