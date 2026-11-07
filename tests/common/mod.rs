// Shared fixtures for the integration tests. One copy here, so every test
// builds the same fixture; a helper duplicated across test files drifts,
// and each drift is a flake.
//
// Not every test file uses every helper, and each file is its own crate.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use tempfile::TempDir;

/// A scratch directory that is deleted when the fixture is dropped,
/// whether the test passed or panicked. The `TempDir` field is what ties
/// cleanup to the struct; `tempfile::tempdir()?.path()` in one expression
/// is a path to a directory that was deleted at the end of the statement.
pub struct Workspace {
    _tmp: TempDir,
    root: PathBuf,
}

impl Workspace {
    pub fn new() -> Self {
        let tmp = tempfile::tempdir().expect("create a temp dir");
        let root = tmp.path().to_path_buf();
        Self { _tmp: tmp, root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Write `contents` to `name` under the workspace and return its path.
    /// `name` is relative and stays inside the workspace, or the cleanup
    /// guarantee is void: an absolute or `..` path would be written for
    /// real and left behind.
    pub fn write(&self, name: &str, contents: &str) -> PathBuf {
        let rel = Path::new(name);
        assert!(
            rel.is_relative()
                && !rel
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir)),
            "fixture path must stay inside the workspace; got {name}"
        );
        let path = self.root.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent dirs");
        }
        fs::write(&path, contents).expect("write fixture file");
        path
    }
}

/// A finished process as a failed assertion should show it: the exit code,
/// then stdout and stderr.
pub fn shown(out: &Output) -> String {
    format!(
        "exit {:?}\n--- stdout\n{}--- stderr\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}
