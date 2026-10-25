//! Crash-safe edits of launcher-owned files.
//!
//! `launcher_profiles.json` holds every profile the operator has, and an
//! `instance.cfg` holds an instance's whole configuration. Writing either in
//! place means a crash or a full disk mid-write destroys it, so edits go to a
//! temporary file beside the original, are flushed to disk, and replace it with
//! one rename. A one-time backup is kept from before `MineBurp` first touched
//! the file, and an edit is refused if the launcher changed the file between
//! `MineBurp` reading and replacing it.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write as _},
    path::{Path, PathBuf},
    time::SystemTime,
};

use crate::LaunchError;

/// A file's contents together with what identified its version on disk.
#[derive(Debug, Clone)]
pub(crate) struct Snapshot {
    pub text: String,
    modified: Option<SystemTime>,
    length: u64,
}

pub(crate) fn read_snapshot(path: &Path) -> io::Result<Snapshot> {
    let metadata = fs::metadata(path)?;
    let text = fs::read_to_string(path)?;
    Ok(Snapshot {
        text,
        modified: metadata.modified().ok(),
        length: metadata.len(),
    })
}

/// The path of the backup kept for `path`.
pub(crate) fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".mineburp.bak");
    path.with_file_name(name)
}

/// Copies `path` to its backup unless a backup already exists, so the backup
/// is always the file as it was before `MineBurp`'s first edit.
pub(crate) fn backup_once(path: &Path) -> io::Result<()> {
    let backup = backup_path(path);
    if backup.exists() {
        return Ok(());
    }
    fs::copy(path, &backup)?;
    Ok(())
}

/// Replaces `path` with `contents` atomically.
///
/// With `expected`, the replacement is refused when the file on disk is no
/// longer the version that was read — a running launcher saved it meanwhile,
/// and overwriting would silently discard its change.
pub(crate) fn write_atomic(
    path: &Path,
    contents: &[u8],
    expected: Option<&Snapshot>,
) -> Result<(), LaunchError> {
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path.file_name().ok_or_else(|| {
        LaunchError::InvalidMetadata(format!("{} has no file name", path.display()))
    })?;
    let mut temporary_name = std::ffi::OsString::from(".");
    temporary_name.push(name);
    temporary_name.push(format!(".mineburp-{}.tmp", uuid::Uuid::new_v4().simple()));
    let temporary = directory.join(temporary_name);

    let result = (|| -> Result<(), LaunchError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        if let Ok(metadata) = fs::metadata(path) {
            let _ = fs::set_permissions(&temporary, metadata.permissions());
        }
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        if let Some(expected) = expected {
            let current = fs::metadata(path)?;
            if current.modified().ok() != expected.modified || current.len() != expected.length {
                return Err(LaunchError::AgentConfiguration(format!(
                    "{} changed while MineBurp was editing it; close the launcher and try again",
                    path.display()
                )));
            }
        }
        fs::rename(&temporary, path)?;
        // Make the rename itself durable. Directories cannot be opened this
        // way everywhere; where they cannot, the rename is still atomic.
        if let Ok(directory) = File::open(directory) {
            let _ = directory.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_contents_and_keeps_one_backup() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("profiles.json");
        fs::write(&path, "original").unwrap();
        backup_once(&path).unwrap();
        let snapshot = read_snapshot(&path).unwrap();
        write_atomic(&path, b"first edit", Some(&snapshot)).unwrap();
        backup_once(&path).unwrap();
        write_atomic(&path, b"second edit", None).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "second edit");
        assert_eq!(fs::read_to_string(backup_path(&path)).unwrap(), "original");
        // No temporary files are left behind.
        let leftovers = fs::read_dir(directory.path())
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")
            })
            .count();
        assert_eq!(leftovers, 0);
    }

    #[test]
    fn refuses_to_overwrite_a_concurrent_change() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("instance.cfg");
        fs::write(&path, "a=1\n").unwrap();
        let snapshot = read_snapshot(&path).unwrap();
        // The launcher saves meanwhile (a different length is enough to tell,
        // even on filesystems with coarse timestamps).
        fs::write(&path, "a=1\nb=2\n").unwrap();
        assert!(write_atomic(&path, b"a=mineburp\n", Some(&snapshot)).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "a=1\nb=2\n");
    }
}
