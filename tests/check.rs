// `cargo-lockpatrol check` end to end: the real binary, a real git
// repository, and a stub `cargo` that plays back cargo-deny JSON captured
// from cargo-deny 0.20.2 (tests/fixtures/deny). The repository tracks a
// root and two nested lockfiles, one under a non-ASCII name; an untracked
// one stands in for a stray build tree, and `oldCargo.lock` for a fixture
// whose name only ends in Cargo.lock. No check should read either. A
// `deny.toml` sits at the root and under `fuzz/`, where the configs point.
//
// The stub is a shell script, so these run on Unix only; the decisions
// they wire together are unit-tested in src/ on every platform.
#![cfg(unix)]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

use common::{Workspace, shown};

const STUB: &str = r#"#!/usr/bin/env bash
printf '%s\n' "$*" >> "$STUB_LOG"
cat > /dev/null
pick=$STUB_NESTED
prev=
for arg in "$@"; do
    if [ "$prev" = --manifest-path ] && [ "$arg" = Cargo.toml ]; then pick=$STUB_ROOT; fi
    prev=$arg
done
cat "$STUB_FIXTURES/${pick%%:*}.jsonl" >&2
exit "${pick##*:}"
"#;

const TRACKED: [&str; 3] = ["Cargo.lock", "fuzz/Cargo.lock", "naïve/Cargo.lock"];

/// A git repository with three tracked lockfiles and two that no check
/// should read, plus the stub `cargo`.
struct Repo {
    ws: Workspace,
    /// The repository's path as git reports it: on macOS the temp dir is
    /// under `/var` or `/tmp`, symlinks git resolves.
    root: PathBuf,
}

impl Repo {
    fn new() -> Self {
        let ws = Workspace::new();
        for file in TRACKED.iter().chain(&[
            "fuzz/oldCargo.lock",
            "scratch/Cargo.lock",
            "deny.toml",
            "fuzz/deny.toml",
        ]) {
            ws.write(&format!("repo/{file}"), "");
        }
        let stub = ws.write("bin/cargo", STUB);
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755))
            .expect("make the stub executable");
        let root =
            std::fs::canonicalize(ws.root().join("repo")).expect("canonicalize the repo path");
        git(&root, &["init", "-q"]);
        let mut add = vec!["add", "fuzz/oldCargo.lock"];
        add.extend(TRACKED);
        git(&root, &add);
        Repo { ws, root }
    }

    /// Runs `cargo-lockpatrol check` from `dir` with the stub playing
    /// `root` for the root manifest and `nested` for every other, each as
    /// `<fixture>:<exit code>`.
    fn check_from(&self, dir: &Path, root: &str, nested: &str, extra: &[&str]) -> Run {
        let log = self.ws.write("calls", "");
        let out = lockpatrol(dir)
            .args(extra)
            .env("CARGO", self.ws.root().join("bin/cargo"))
            .env("STUB_LOG", &log)
            .env(
                "STUB_FIXTURES",
                Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/deny"),
            )
            .env("STUB_ROOT", root)
            .env("STUB_NESTED", nested)
            .output()
            .expect("run cargo-lockpatrol");
        let calls = std::fs::read_to_string(&log).expect("read the call log");
        Run::new(out, calls)
    }

    fn check(&self, root: &str, nested: &str) -> Run {
        self.check_from(&self.root, root, nested, &[])
    }
}

/// Runs git in `dir` and asserts it succeeded.
fn git(dir: &Path, args: &[&str]) {
    let out = clean_git_env(Command::new("git").args(args).current_dir(dir))
        .output()
        .expect("run git");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// `cargo-lockpatrol check`, to be run from `dir`.
fn lockpatrol(dir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cargo-lockpatrol"));
    cmd.arg("check").current_dir(dir);
    clean_git_env(&mut cmd);
    cmd
}

/// Clears the variables that point git at a repository. A pre-commit hook
/// hands its git environment (`GIT_INDEX_FILE` and the rest) to the tests
/// it runs, and git would then read or write the commit being made instead
/// of the scratch repository.
fn clean_git_env(cmd: &mut Command) -> &mut Command {
    static VARS: OnceLock<Vec<String>> = OnceLock::new();
    let vars = VARS.get_or_init(|| {
        let out = Command::new("git")
            .args(["rev-parse", "--local-env-vars"])
            .output()
            .expect("run git");
        // The `GIT_CONFIG*` ones carry configuration, not a repository,
        // and can hold what git needs to reach the network (a proxy),
        // which the live test's advisory-db fetch uses.
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|v| !v.starts_with("GIT_CONFIG"))
            .map(str::to_string)
            .collect()
    });
    for var in vars {
        cmd.env_remove(var);
    }
    cmd
}

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
    calls: Vec<String>,
}

impl Run {
    fn new(out: Output, calls: String) -> Self {
        Run {
            code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            calls: calls.lines().map(str::to_string).collect(),
        }
    }

    /// The value each cargo deny call gave `flag`, in call order.
    fn values_of(&self, flag: &str) -> Vec<&str> {
        self.calls
            .iter()
            .map(|c| {
                let after = c
                    .split(&format!(" {flag} "))
                    .nth(1)
                    .unwrap_or_else(|| panic!("no {flag} in {c}"));
                after.split(' ').next().unwrap_or("")
            })
            .collect()
    }

    /// The manifest each cargo deny call was pointed at, in call order.
    fn manifests(&self) -> Vec<&str> {
        self.values_of("--manifest-path")
    }

    /// The manifests of the calls that ran with `--locked`.
    fn locked_manifests(&self) -> Vec<&str> {
        self.calls
            .iter()
            .zip(self.manifests())
            .filter(|(c, _)| c.split(' ').any(|a| a == "--locked"))
            .map(|(_, m)| m)
            .collect()
    }
}

impl std::fmt::Debug for Run {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "exit {:?}\n--- stdout\n{}--- stderr\n{}--- calls\n{}",
            self.code,
            self.stdout,
            self.stderr,
            self.calls.join("\n")
        )
    }
}

#[test]
fn every_tree_clean_exits_zero_with_an_empty_report() {
    let run = Repo::new().check("clean:0", "clean:0");
    assert_eq!((run.code, run.stdout.as_str()), (Some(0), ""), "{run:?}");
}

#[test]
fn each_tracked_lockfile_is_checked_once_by_its_name_on_disk() {
    let run = Repo::new().check("clean:0", "clean:0");
    let mut manifests = run.manifests();
    manifests.sort();
    assert_eq!(
        manifests,
        ["Cargo.toml", "fuzz/Cargo.toml", "naïve/Cargo.toml"],
        "{run:?}"
    );
}

#[test]
fn every_tree_is_checked_against_the_root_deny_toml() {
    let repo = Repo::new();
    let run = repo.check("clean:0", "clean:0");
    let want = format!("{}/deny.toml", repo.root.display());
    assert_eq!(run.values_of("--config"), [want.as_str(); 3], "{run:?}");
}

#[test]
fn an_advisory_in_the_root_tree_exits_one_with_a_report_under_the_root_lockfile() {
    let run = Repo::new().check("unmaintained:1", "clean:0");
    let section = run.stdout.split("## ").nth(1).unwrap_or_default();
    let under_root = section.starts_with("cargo deny check advisories (Cargo.lock)\n");
    let id_shown = section.contains("├ ID: RUSTSEC-2025-0141");
    assert_eq!(
        (run.code, under_root, id_shown),
        (Some(1), true, true),
        "{run:?}"
    );
}

#[test]
fn an_advisory_in_a_nested_tree_is_reported_under_that_lockfile() {
    let run = Repo::new().check("clean:0", "vulnerability:1");
    let heading = |lockfile: &str| {
        run.stdout
            .contains(&format!("## cargo deny check advisories ({lockfile})\n"))
    };
    assert_eq!(
        (
            run.code,
            heading("fuzz/Cargo.lock"),
            heading("naïve/Cargo.lock")
        ),
        (Some(1), true, true),
        "{run:?}"
    );
}

#[test]
fn a_yanked_crate_is_reported_by_its_headline() {
    let run = Repo::new().check("yanked:1", "clean:0");
    let headline = run
        .stdout
        .contains("error[yanked]: detected yanked crate (try `cargo update -p smallvec`)");
    assert_eq!((run.code, headline), (Some(1), true), "{run:?}");
}

#[test]
fn a_tree_that_broke_exits_two_with_an_empty_report_and_says_which_tree() {
    let run = Repo::new().check("config-error:1", "clean:0");
    let names_tree = run.stderr.starts_with("cargo deny on Cargo.lock ");
    assert_eq!(
        (run.code, run.stdout.as_str(), names_tree),
        (Some(2), "", true),
        "{run:?}"
    );
}

#[test]
fn a_tree_that_stopped_with_only_an_error_log_exits_two_with_an_empty_report() {
    let run = Repo::new().check("missing-manifest:1", "clean:0");
    assert_eq!((run.code, run.stdout.as_str()), (Some(2), ""), "{run:?}");
}

#[test]
fn a_stale_ignore_entry_is_broken_not_an_advisory() {
    let run = Repo::new().check("unused-ignore:1", "clean:0");
    assert_eq!((run.code, run.stdout.as_str()), (Some(2), ""), "{run:?}");
}

#[test]
fn an_advisory_beside_a_broken_tree_exits_three_and_is_still_reported() {
    let run = Repo::new().check("unmaintained:1", "missing-manifest:1");
    let reported = run.stdout.contains("RUSTSEC-2025-0141");
    assert_eq!((run.code, reported), (Some(3), true), "{run:?}");
}

#[test]
fn no_tracked_lockfile_exits_two() {
    let repo = Repo::new();
    let mut rm = vec!["rm", "-q", "--cached"];
    rm.extend(TRACKED);
    git(&repo.root, &rm);
    let run = repo.check("clean:0", "clean:0");
    assert_eq!((run.code, run.calls.len()), (Some(2), 0), "{run:?}");
}

#[test]
fn by_default_only_the_root_tree_runs_locked() {
    let run = Repo::new().check("clean:0", "clean:0");
    assert_eq!(run.locked_manifests(), ["Cargo.toml"], "{run:?}");
}

#[test]
fn locked_all_runs_every_tree_locked() {
    let repo = Repo::new();
    let run = repo.check_from(&repo.root, "clean:0", "clean:0", &["--locked", "all"]);
    assert_eq!(run.locked_manifests().len(), 3, "{run:?}");
}

#[test]
fn a_run_from_a_subdirectory_checks_the_whole_repository() {
    let repo = Repo::new();
    let run = repo.check_from(&repo.root.join("fuzz"), "clean:0", "clean:0", &[]);
    assert_eq!((run.code, run.calls.len()), (Some(0), 3), "{run:?}");
}

#[test]
fn a_relative_config_is_read_from_where_the_command_runs() {
    let repo = Repo::new();
    let run = repo.check_from(
        &repo.root.join("fuzz"),
        "clean:0",
        "clean:0",
        &["--config", "deny.toml"],
    );
    let want = format!("{}/fuzz/deny.toml", repo.root.display());
    assert_eq!(run.values_of("--config"), [want.as_str(); 3], "{run:?}");
}

#[test]
fn a_run_from_a_subdirectory_still_reads_the_root_deny_toml() {
    let repo = Repo::new();
    let run = repo.check_from(&repo.root.join("fuzz"), "clean:0", "clean:0", &[]);
    let want = format!("{}/deny.toml", repo.root.display());
    assert_eq!(run.values_of("--config"), [want.as_str(); 3], "{run:?}");
}

#[test]
fn a_config_that_is_not_a_file_is_broken_before_any_tree_runs() {
    // cargo deny would quietly check with its defaults.
    let repo = Repo::new();
    let run = repo.check_from(&repo.root, "clean:0", "clean:0", &["--config", "deny.tmol"]);
    let names_it = run.stderr.contains("deny.tmol");
    assert_eq!(
        (run.code, run.calls.len(), names_it),
        (Some(2), 0, true),
        "{run:?}"
    );
}

#[test]
fn a_cargo_that_cannot_be_run_is_broken() {
    let repo = Repo::new();
    std::fs::remove_file(repo.ws.root().join("bin/cargo")).expect("remove the stub");
    let run = repo.check("clean:0", "clean:0");
    let stub = repo.ws.root().join("bin/cargo");
    let names_stub = run.stderr.contains(&*stub.to_string_lossy());
    assert_eq!(
        (run.code, names_stub),
        (Some(2), true),
        "stderr should name {stub:?}; {run:?}"
    );
}

#[test]
fn outside_a_git_repository_is_broken() {
    let ws = Workspace::new();
    let out = lockpatrol(ws.root())
        .env("GIT_CEILING_DIRECTORIES", ws.root())
        .output()
        .expect("run cargo-lockpatrol");
    let stderr = String::from_utf8_lossy(&out.stderr);
    // The git command that failed, not a later step: `ls-files` would
    // fail here too, and so would running a missing cargo.
    let names_step = stderr.contains("git rev-parse --show-toplevel failed");
    assert_eq!(
        (out.status.code(), names_step),
        (Some(2), true),
        "stderr: {stderr}"
    );
}

#[test]
fn a_usage_error_exits_two() {
    let out = lockpatrol(Path::new(env!("CARGO_MANIFEST_DIR")))
        .args(["--locked", "sometimes"])
        .output()
        .expect("run cargo-lockpatrol");
    assert_eq!(
        out.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// The stub pins the format these tests were written against; these pin
// that the real cargo-deny still writes it. They need cargo-deny on PATH,
// the RustSec database (a network fetch on a cold cache), and for the
// tree with a dependency, crates.io.

/// A committed crate named `live` with `dependencies` (TOML lines) and a
/// lockfile, and the outcome of `cargo-lockpatrol check` on it.
fn live_check(dependencies: &str) -> Output {
    let ws = Workspace::new();
    ws.write(
        "repo/Cargo.toml",
        &format!(
            "[package]\nname = \"live\"\nversion = \"0.1.0\"\nedition = \"2021\"\npublish = false\n\n[dependencies]\n{dependencies}"
        ),
    );
    ws.write("repo/src/lib.rs", "");
    ws.write("repo/deny.toml", "[advisories]\nversion = 2\n");
    let root = ws.root().join("repo");
    let lock = Command::new(env!("CARGO"))
        .arg("generate-lockfile")
        .current_dir(&root)
        .output()
        .expect("run cargo");
    assert!(
        lock.status.success(),
        "{}",
        String::from_utf8_lossy(&lock.stderr)
    );
    git(&root, &["init", "-q"]);
    git(
        &root,
        &["add", "Cargo.toml", "Cargo.lock", "src/lib.rs", "deny.toml"],
    );
    lockpatrol(&root)
        .env("CARGO", env!("CARGO"))
        .output()
        .expect("run cargo-lockpatrol")
}

#[test]
#[ignore = "needs cargo-deny and the advisory database; CI runs it in security.yml's deny job; locally: cargo nextest run --run-ignored only -E 'test(/^live_/)'"]
fn live_a_tree_with_no_dependencies_is_clean_under_the_real_cargo_deny() {
    let out = live_check("");
    assert_eq!(out.status.code(), Some(0), "{}", shown(&out));
}

// The JSON's diagnostics, not only its summary line: a cargo-deny that
// moved the advisory id or renamed a code would turn every finding into a
// broken check, and the clean tree above would not notice.
#[test]
#[ignore = "needs cargo-deny, the advisory database and crates.io; CI runs it in security.yml's deny job; locally: cargo nextest run --run-ignored only -E 'test(/^live_/)'"]
fn live_a_known_vulnerability_is_a_finding_under_the_real_cargo_deny() {
    let out = live_check("smallvec = \"=1.6.0\"\n");
    let reported = String::from_utf8_lossy(&out.stdout).contains("├ ID: RUSTSEC-2021-0003");
    assert_eq!(
        (out.status.code(), reported),
        (Some(1), true),
        "{}",
        shown(&out)
    );
}
