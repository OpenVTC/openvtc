//! Writing owner-only files atomically.
//!
//! One routine for every file OpenVTC writes that holds profile data: the
//! config file, exports, the file-backed secret store and startup-failure
//! reports. Before it existed each wrote in place (truncate, then write, then
//! `chmod`), so a crash mid-save left `config.json` truncated — and that file
//! carries the whole encrypted protected tier — and every new file briefly
//! existed at the umask default.

use std::{
    fs,
    io::{self, Write},
    path::Path,
};

/// Write `bytes` to `path` so that `path` holds either its old content or all
/// of the new content — never a prefix — and is never readable by anyone but
/// the owner.
///
/// 1. A temporary file is created *new* (never opening an existing file or
///    link) in the same directory, so the final rename is atomic rather than a
///    cross-filesystem copy. On Unix it is created `0600`, before any byte
///    lands.
/// 2. The bytes are written and `fsync`ed.
/// 3. The temporary file is renamed over `path`, and on Unix the directory is
///    `fsync`ed so the rename itself survives a crash.
///
/// If anything fails before the rename, the temporary file is removed and
/// `path` is untouched.
///
/// A symlink at `path` is refused rather than followed or replaced: a link
/// left where a private file is about to be written is how such a file ends
/// up somewhere its owner did not choose (a synced or shared directory).
/// Callers that deliberately support a symlinked target resolve it first.
///
/// The parent directory must exist; this does not create it.
///
/// # Errors
///
/// Any I/O error, or [`io::ErrorKind::InvalidInput`] for a symlink at `path`
/// or a path with no parent directory.
pub fn atomic_write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("refusing to write through a symlink: {}", path.display()),
            ));
        }
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    let dir = match path.parent() {
        Some(p) if p.as_os_str().is_empty() => Path::new("."),
        Some(p) => p,
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} has no parent directory", path.display()),
            ));
        }
    };
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} has no file name", path.display()),
        )
    })?;

    let (tmp, mut file) = create_temp(dir, file_name)?;
    let written = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .and_then(|()| {
            drop(file);
            fs::rename(&tmp, path)
        });
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    sync_dir(dir);
    Ok(())
}

/// Create a fresh temporary file beside the target, owner-only from birth.
fn create_temp(
    dir: &Path,
    file_name: &std::ffi::OsStr,
) -> io::Result<(std::path::PathBuf, fs::File)> {
    use rand::RngCore;
    let mut last = None;
    for _ in 0..8 {
        let mut name = std::ffi::OsString::from(".");
        name.push(file_name);
        name.push(format!(".{:016x}.tmp", rand::rngs::OsRng.next_u64()));
        let tmp = dir.join(name);

        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&tmp) {
            Ok(file) => {
                // `mode` is filtered by the umask; it can only tighten 0600,
                // but set it outright so the result does not depend on that.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Err(e) = file.set_permissions(fs::Permissions::from_mode(0o600)) {
                        drop(file);
                        let _ = fs::remove_file(&tmp);
                        return Err(e);
                    }
                }
                return Ok((tmp, file));
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other("could not create a temporary file")))
}

/// Make a completed rename durable. Best-effort: not every filesystem lets a
/// directory be opened and synced, and the data itself is already synced.
fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Create `dir` (and its parents) if missing, the last component owner-only
/// (`0700`) on Unix. An existing directory is left as it is: it may be one the
/// user chose (`OPENVTC_CONFIG_PATH`) and shares on purpose.
///
/// # Errors
///
/// Any I/O error from creating the directory.
pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "openvtc-private-file-{name}-{}-{:x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn writes_and_replaces_content() {
        let dir = scratch("replace");
        let path = dir.join("config.json");
        atomic_write_private(&path, b"first").unwrap();
        atomic_write_private(&path, b"second").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");
        // No temporary files left behind.
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_owner_only_even_over_a_looser_one() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("mode");
        let path = dir.join("export.enc");
        fs::write(&path, b"old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        atomic_write_private(&path, b"new").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        fs::remove_dir_all(dir).unwrap();
    }

    /// A write that fails after the temporary file was fully written — at the
    /// rename, the last step — leaves the target as it was and no temporary
    /// file behind. The target here is a non-empty directory, which a file
    /// cannot be renamed over.
    #[test]
    fn a_failed_rename_leaves_the_target_intact_and_cleans_up() {
        let dir = scratch("fail");
        let target = dir.join("occupied");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("keep"), b"precious").unwrap();

        assert!(atomic_write_private(&target, b"x").is_err());

        assert_eq!(fs::read(target.join("keep")).unwrap(), b"precious");
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temporary file cleaned up");
        fs::remove_dir_all(dir).unwrap();
    }

    /// A write that cannot even start (no room for the temporary file — here a
    /// read-only directory) leaves the old file exactly as it was. The
    /// in-place `fs::write` this replaced truncated it first.
    #[cfg(unix)]
    #[test]
    fn a_failed_write_leaves_the_old_file_intact() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("readonly");
        let path = dir.join("config.json");
        fs::write(&path, b"precious").unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();

        let result = atomic_write_private(&path, b"replacement");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        // Root ignores directory permissions; nothing to check there.
        if result.is_err() {
            assert_eq!(fs::read(&path).unwrap(), b"precious");
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_target_is_refused_and_not_followed() {
        let dir = scratch("symlink");
        let elsewhere = dir.join("elsewhere");
        fs::write(&elsewhere, b"untouched").unwrap();
        let link = dir.join("export.enc");
        std::os::unix::fs::symlink(&elsewhere, &link).unwrap();

        let err = atomic_write_private(&link, b"secret").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(fs::read(&elsewhere).unwrap(), b"untouched");
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_created_directory_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("dir");
        let profile = dir.join("a").join("openvtc");
        create_private_dir(&profile).unwrap();
        let mode = fs::metadata(&profile).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        fs::remove_dir_all(dir).unwrap();
    }
}
