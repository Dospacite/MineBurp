//! Validation for file paths the webview hands to commands.
//!
//! The webview is the least trusted part of the application: anything that
//! can run script in it can call commands. A path argument is therefore held
//! to what the command is for — a project is a `.mineburp` file, an export is
//! a `.json` or `.pcapng` file — so a compromised page cannot use "export" to
//! truncate an arbitrary file, or "save as" to overwrite one, and no export
//! can overwrite the project it is reading from.

use std::{
    ffi::OsString,
    path::{Component, Path, PathBuf},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathPurpose {
    /// A project file that must not exist yet.
    NewProject,
    /// A project file that must exist.
    ExistingProject,
    /// A JSON export, created or replaced.
    ExportJson,
    /// A pcapng export, created or replaced.
    ExportPcap,
    /// A pcap or pcapng file to read.
    ImportCapture,
}

impl PathPurpose {
    fn extensions(self) -> &'static [&'static str] {
        match self {
            Self::NewProject | Self::ExistingProject => &["mineburp"],
            Self::ExportJson => &["json"],
            Self::ExportPcap => &["pcapng"],
            Self::ImportCapture => &["pcap", "pcapng", "cap", "dmp"],
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::NewProject | Self::ExistingProject => "a MineBurp project (.mineburp)",
            Self::ExportJson => "a JSON file (.json)",
            Self::ExportPcap => "a pcapng file (.pcapng)",
            Self::ImportCapture => "a capture file (.pcap or .pcapng)",
        }
    }
}

/// Checks `path` for `purpose`; `protected` lists files no write may touch
/// (the open project). Returns the path to use.
pub fn validate_path(
    path: &Path,
    purpose: PathPurpose,
    protected: &[&Path],
) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("the path must be absolute".into());
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err("the path must not contain `..`".into());
    }
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    if !purpose.extensions().contains(&extension.as_str()) {
        return Err(format!("the file must be {}", purpose.label()));
    }
    match purpose {
        PathPurpose::ExistingProject | PathPurpose::ImportCapture => {
            if !path.is_file() {
                return Err(format!("{} is not a file", path.display()));
            }
        }
        PathPurpose::NewProject | PathPurpose::ExportJson | PathPurpose::ExportPcap => {
            let parent = path
                .parent()
                .filter(|parent| parent.is_dir())
                .ok_or_else(|| "the destination folder does not exist".to_owned())?;
            if std::fs::symlink_metadata(path)
                .is_ok_and(|metadata| metadata.file_type().is_symlink())
            {
                return Err("destination must not be a symbolic link".into());
            }
            if path.is_dir() {
                return Err(format!("{} is a folder", path.display()));
            }
            if purpose == PathPurpose::NewProject && path.exists() {
                return Err(format!("{} already exists", path.display()));
            }
            if is_protected(parent, path, protected) {
                return Err("an export cannot replace the open project".into());
            }
        }
    }
    Ok(path.to_path_buf())
}

/// Whether `path` resolves to one of `protected` or one of its `SQLite`
/// sidecar files.
fn is_protected(parent: &Path, path: &Path, protected: &[&Path]) -> bool {
    // Resolve through the parent so a not-yet-existing target still compares
    // by its real location, and a link to the project is caught.
    let resolved = path.canonicalize().ok().or_else(|| {
        parent
            .canonicalize()
            .ok()
            .and_then(|parent| path.file_name().map(|name| parent.join(name)))
    });
    let Some(resolved) = resolved else {
        return false;
    };
    protected.iter().any(|project| {
        let Ok(project) = project.canonicalize() else {
            return false;
        };
        let sidecar = |suffix: &str| {
            let mut name = OsString::from(project.as_os_str());
            name.push(suffix);
            PathBuf::from(name)
        };
        resolved == project || resolved == sidecar("-wal") || resolved == sidecar("-shm")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holds_each_path_to_its_purpose() {
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("work.mineburp");
        std::fs::write(&project, b"db").unwrap();
        let protected = [project.as_path()];

        assert!(validate_path(&project, PathPurpose::ExistingProject, &protected).is_ok());
        assert!(
            validate_path(&project, PathPurpose::NewProject, &protected).is_err(),
            "exists"
        );
        assert!(
            validate_path(
                &directory.path().join("new.mineburp"),
                PathPurpose::NewProject,
                &protected
            )
            .is_ok()
        );
        // Wrong extension, relative, traversal, missing folder.
        assert!(
            validate_path(
                &directory.path().join(".bashrc"),
                PathPurpose::ExportJson,
                &protected
            )
            .is_err()
        );
        assert!(validate_path(Path::new("x.json"), PathPurpose::ExportJson, &protected).is_err());
        assert!(
            validate_path(
                &directory.path().join("a/../b.json"),
                PathPurpose::ExportJson,
                &protected
            )
            .is_err()
        );
        assert!(
            validate_path(
                &directory.path().join("missing/b.json"),
                PathPurpose::ExportJson,
                &protected
            )
            .is_err()
        );
        assert!(
            validate_path(
                &directory.path().join("out.JSON"),
                PathPurpose::ExportJson,
                &protected
            )
            .is_ok()
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_export_cannot_reach_the_open_project_through_a_link() {
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("work.mineburp");
        std::fs::write(&project, b"db").unwrap();
        let link = directory.path().join("innocent.json");
        std::os::unix::fs::symlink(&project, &link).unwrap();
        let protected = [project.as_path()];
        assert!(validate_path(&link, PathPurpose::ExportJson, &protected).is_err());
        let wal_link = directory.path().join("wal.pcapng");
        let mut wal = project.as_os_str().to_owned();
        wal.push("-wal");
        std::fs::write(&wal, b"w").unwrap();
        std::os::unix::fs::symlink(PathBuf::from(wal), &wal_link).unwrap();
        assert!(validate_path(&wal_link, PathPurpose::ExportPcap, &protected).is_err());
    }
}
