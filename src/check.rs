//! `cargo lockpatrol check`: every tracked `Cargo.lock`, one root
//! `deny.toml`, one exit code.
//!
//! Every tree, not just the root: a crate excluded from the workspace (a
//! wasm site, an e2e crate, a cargo-fuzz dir) keeps its own `Cargo.lock`,
//! which a root `cargo deny` never opens. The list comes from git, so a
//! new one is covered the commit it lands, and every run reads the same
//! `deny.toml`, so it is the one ignore list for all of them, even beside
//! a tree that ships its own.

use std::ffi::OsString;
use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::str::FromStr;

use crate::deny::{self, Broken, BrokenKind, TreeResult};

/// Every tree clean.
pub const EXIT_CLEAN: u8 = 0;
/// An advisory in some tree.
pub const EXIT_FOUND: u8 = 1;
/// A check failed without reporting an advisory, or there was nothing to
/// check. There is nothing to triage, and an issue about a network error
/// would bury the next real one.
pub const EXIT_BROKEN: u8 = 2;
/// Both: one tree found an advisory and another broke. The finding still
/// gets filed, and the job still fails, so a dead check cannot hide
/// behind a live one.
pub const EXIT_FOUND_AND_BROKEN: u8 = 3;

/// Which trees get `--locked`, which fails a run whose `Cargo.lock`
/// disagrees with its manifests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Locked {
    /// Only the root lockfile. Without `--locked`, `cargo metadata`
    /// quietly rewrites a root lock that disagrees with its manifests and
    /// cargo-deny checks the rewritten graph, not the one committed; with
    /// it, the run breaks and says so. A nested tree is exempt because one
    /// that path-depends on the root crate goes stale on every root
    /// version bump that refreshes only the root lock, and `--locked`
    /// would turn each one into a red check.
    #[default]
    Root,
    None,
    All,
}

impl Locked {
    /// Whether the tree whose lockfile is `lockfile` (relative to the repo
    /// root) runs with `--locked`.
    pub fn applies_to(self, lockfile: &Path) -> bool {
        match self {
            Locked::Root => lockfile == Path::new("Cargo.lock"),
            Locked::None => false,
            Locked::All => true,
        }
    }
}

/// A `--locked` value that is not `root`, `none` or `all`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownLocked(pub String);

impl fmt::Display for UnknownLocked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "--locked takes root, none or all, not {:?}", self.0)
    }
}

impl std::error::Error for UnknownLocked {}

impl FromStr for Locked {
    type Err = UnknownLocked;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "root" => Ok(Locked::Root),
            "none" => Ok(Locked::None),
            "all" => Ok(Locked::All),
            other => Err(UnknownLocked(other.to_string())),
        }
    }
}

/// The program to run as `cargo`: `$CARGO`, which cargo sets for the
/// subcommands it starts, or `cargo` from `PATH`. Read through `env` so a
/// test can point it at a stub.
pub fn cargo_program(env: impl Fn(&str) -> Option<OsString>) -> OsString {
    env("CARGO")
        .filter(|c| !c.is_empty())
        .unwrap_or_else(|| "cargo".into())
}

/// The arguments after `cargo` for one tree.
///
/// `--format json` because the JSON tells a finding from a broken run and
/// the human report does not. `--log-level error` drops warn-level
/// advisories, which do not fail the check. `--config` because cargo deny
/// otherwise prefers a `deny.toml` next to the manifest. `--workspace`
/// graphs every member, not just the root package and what it depends on.
fn deny_args(lockfile: &Path, config: &Path, locked: bool) -> Vec<OsString> {
    let mut args: Vec<OsString> = [
        "deny",
        "--format",
        "json",
        "--log-level",
        "error",
        "--color",
        "never",
        "--workspace",
    ]
    .map(OsString::from)
    .into();
    if locked {
        args.push("--locked".into());
    }
    args.extend([
        "--config".into(),
        config.into(),
        "--manifest-path".into(),
        lockfile.with_file_name("Cargo.toml").into(),
        "check".into(),
        "advisories".into(),
    ]);
    args
}

/// The paths in `git ls-files -z` output. `-z` because git C-quotes a
/// path holding a quote or a non-ASCII character, and a manifest path
/// built from the quoted form does not exist.
fn split_nul(listing: &[u8]) -> Vec<PathBuf> {
    listing
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .map(path_from_bytes)
        .collect()
}

/// A path from git's bytes: exact on Unix, where a path is bytes, and
/// lossy elsewhere, where git writes UTF-8.
fn path_from_bytes(bytes: &[u8]) -> PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        PathBuf::from(std::ffi::OsStr::from_bytes(bytes))
    }
    #[cfg(not(unix))]
    {
        PathBuf::from(String::from_utf8_lossy(bytes).into_owned())
    }
}

/// The exit code for what every tree came to: found plus twice broken.
/// An empty list would pass every tree by checking none of them, so it is
/// broken.
fn exit_code(results: &[(PathBuf, TreeResult)]) -> u8 {
    let found = results
        .iter()
        .any(|(_, r)| matches!(r, TreeResult::Found { .. }));
    let broken = results.is_empty()
        || results
            .iter()
            .any(|(_, r)| matches!(r, TreeResult::Broken(_)));
    match (found, broken) {
        (false, false) => EXIT_CLEAN,
        (true, false) => EXIT_FOUND,
        (false, true) => EXIT_BROKEN,
        (true, true) => EXIT_FOUND_AND_BROKEN,
    }
}

/// What `check` needs to know.
#[derive(Debug, Clone)]
pub struct Options {
    /// The repository's top level; every lockfile path is relative to it.
    pub root: PathBuf,
    /// The `deny.toml` every tree is checked against.
    pub config: PathBuf,
    pub locked: Locked,
    /// The program run as `cargo`.
    pub cargo: OsString,
}

/// Run git in `dir` and return its stdout.
fn git(dir: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("could not run git: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(out.stdout)
}

/// The working tree's top level, as git reports it for `dir`.
pub fn repo_root(dir: &Path) -> Result<PathBuf, String> {
    let listing = git(dir, &["rev-parse", "--show-toplevel"])?;
    Ok(path_from_bytes(
        listing.strip_suffix(b"\n").unwrap_or(&listing),
    ))
}

/// Files named exactly `Cargo.lock`, at the root or below, that git
/// tracks. A bare `*Cargo.lock` would also match a fixture such as
/// `oldCargo.lock`.
fn tracked_lockfiles(root: &Path) -> Result<Vec<PathBuf>, String> {
    git(root, &["ls-files", "-z", "--", ":(glob)**/Cargo.lock"]).map(|l| split_nul(&l))
}

/// Run the check over every tracked lockfile. The report of each tree
/// that found something goes to `out`; why a tree broke goes to `err`.
/// Returns the exit code.
pub fn run(opts: &Options, out: &mut impl Write, err: &mut impl Write) -> io::Result<u8> {
    let lockfiles = match tracked_lockfiles(&opts.root) {
        Ok(l) => l,
        Err(e) => {
            writeln!(err, "{e}")?;
            return Ok(EXIT_BROKEN);
        }
    };
    let deny = |lockfile: &Path| {
        // stdin is null so nothing cargo deny starts (a git fetch for a
        // git dependency) can wait on a terminal.
        let o = Command::new(&opts.cargo)
            .args(deny_args(
                lockfile,
                &opts.config,
                opts.locked.applies_to(lockfile),
            ))
            .current_dir(&opts.root)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("could not run {}: {e}", opts.cargo.to_string_lossy()))?;
        let mut text = String::from_utf8_lossy(&o.stderr).into_owned();
        text.push('\n');
        text.push_str(&String::from_utf8_lossy(&o.stdout));
        Ok((o.status.code(), text))
    };
    let results = check_trees(&lockfiles, deny);
    write_report(&results, out, err)?;
    Ok(exit_code(&results))
}

/// Each of `lockfiles` with what its run came to, in order. `deny` runs
/// cargo deny on one tree and returns its exit code and output, or why it
/// could not start.
fn check_trees(
    lockfiles: &[PathBuf],
    mut deny: impl FnMut(&Path) -> Result<(Option<i32>, String), String>,
) -> Vec<(PathBuf, TreeResult)> {
    lockfiles
        .iter()
        .map(|lockfile| {
            let result = match deny(lockfile) {
                Ok((exit, output)) => deny::classify(exit, &output),
                Err(why) => TreeResult::Broken(Broken {
                    kind: BrokenKind::NotRun,
                    exit: None,
                    messages: vec![why],
                }),
            };
            (lockfile.clone(), result)
        })
        .collect()
}

/// Write each tree's section of the report to `out`, and to `err` why a
/// tree broke and any other error a tree with findings reported.
fn write_report(
    results: &[(PathBuf, TreeResult)],
    out: &mut impl Write,
    err: &mut impl Write,
) -> io::Result<()> {
    if results.is_empty() {
        writeln!(err, "no tracked Cargo.lock to check")?;
    }
    for (lockfile, result) in results {
        let name = lockfile.to_string_lossy();
        match result {
            TreeResult::Clean => {}
            TreeResult::Found { findings, messages } => {
                writeln!(out, "{}", deny::section(&name, findings))?;
                if !messages.is_empty() {
                    writeln!(err, "cargo deny on {name} also reported:")?;
                    for m in messages {
                        writeln!(err, "    {m}")?;
                    }
                }
            }
            TreeResult::Broken(b) => {
                writeln!(err, "{}", describe(&name, b))?;
                for m in &b.messages {
                    writeln!(err, "    {m}")?;
                }
            }
        }
    }
    Ok(())
}

/// The line that says which tree broke, how, and with what exit code. A
/// run that never started has no exit code to report, and `exit: None`
/// on any other run means a signal ended it.
fn describe(lockfile: &str, broken: &Broken) -> String {
    let what = match broken.kind {
        BrokenKind::NotRun => "could not start",
        BrokenKind::NoSummary => "stopped before it checked anything",
        BrokenKind::NoFinding => "failed without reporting an advisory",
    };
    let exit = match (broken.kind, broken.exit) {
        (BrokenKind::NotRun, _) => String::new(),
        (_, Some(c)) => format!(" (exit {c})"),
        (_, None) => " (killed by a signal)".to_string(),
    };
    format!("cargo deny on {lockfile} {what}{exit}:")
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::*;
    use crate::deny::Finding;
    use crate::fixtures::{CONFIG_ERROR, UNMAINTAINED, UNUSED_IGNORE};

    fn finding() -> TreeResult {
        TreeResult::Found {
            findings: vec![Finding {
                code: "unmaintained".into(),
                id: Some("RUSTSEC-2025-0141".into()),
                message: "Bincode is unmaintained".into(),
                notes: vec!["ID: RUSTSEC-2025-0141".into()],
                graph: vec![],
            }],
            messages: vec![],
        }
    }

    fn broken(kind: BrokenKind, exit: Option<i32>, messages: &[&str]) -> Broken {
        Broken {
            kind,
            exit,
            messages: messages.iter().map(|m| m.to_string()).collect(),
        }
    }

    fn results(list: Vec<(&str, TreeResult)>) -> Vec<(PathBuf, TreeResult)> {
        list.into_iter()
            .map(|(l, r)| (PathBuf::from(l), r))
            .collect()
    }

    /// What `write_report` wrote for `results`.
    struct Written {
        out: String,
        err: String,
    }

    fn written(results: &[(PathBuf, TreeResult)]) -> Written {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        write_report(results, &mut out, &mut err).expect("write to a Vec");
        Written {
            out: String::from_utf8(out).expect("utf-8 report"),
            err: String::from_utf8(err).expect("utf-8 reasons"),
        }
    }

    /// The value that follows `flag` in `args`.
    fn value_after<'a>(args: &'a [OsString], flag: &str) -> Option<&'a OsStr> {
        args.windows(2)
            .find(|w| w[0] == flag)
            .map(|w| w[1].as_os_str())
    }

    // Deciding: each tree's result, and the exit code they add up to.

    #[test]
    fn a_run_that_could_not_start_is_broken_with_no_exit_code_and_its_reason() {
        let got = check_trees(&[PathBuf::from("Cargo.lock")], |_| {
            Err("could not run /no/cargo: not found".to_string())
        });
        assert_eq!(
            got,
            results(vec![(
                "Cargo.lock",
                TreeResult::Broken(broken(
                    BrokenKind::NotRun,
                    None,
                    &["could not run /no/cargo: not found"]
                ))
            )])
        );
    }

    #[test]
    fn each_tree_is_classified_from_its_own_run_and_kept_in_order() {
        let got = check_trees(
            &[
                PathBuf::from("Cargo.lock"),
                PathBuf::from("fuzz/Cargo.lock"),
            ],
            |lockfile| {
                let output = if lockfile == Path::new("Cargo.lock") {
                    UNMAINTAINED
                } else {
                    CONFIG_ERROR
                };
                Ok((Some(1), output.to_string()))
            },
        );
        assert_eq!(
            got,
            vec![
                (
                    PathBuf::from("Cargo.lock"),
                    deny::classify(Some(1), UNMAINTAINED)
                ),
                (
                    PathBuf::from("fuzz/Cargo.lock"),
                    deny::classify(Some(1), CONFIG_ERROR)
                ),
            ]
        );
    }

    #[test]
    fn clean_trees_exit_zero() {
        let r = results(vec![
            ("Cargo.lock", TreeResult::Clean),
            ("fuzz/Cargo.lock", TreeResult::Clean),
        ]);
        assert_eq!(exit_code(&r), EXIT_CLEAN);
    }

    #[test]
    fn a_finding_exits_one() {
        let r = results(vec![
            ("Cargo.lock", TreeResult::Clean),
            ("fuzz/Cargo.lock", finding()),
        ]);
        assert_eq!(exit_code(&r), EXIT_FOUND);
    }

    #[test]
    fn a_broken_tree_exits_two() {
        let r = results(vec![
            ("Cargo.lock", TreeResult::Clean),
            (
                "fuzz/Cargo.lock",
                TreeResult::Broken(broken(BrokenKind::NoSummary, Some(1), &[])),
            ),
        ]);
        assert_eq!(exit_code(&r), EXIT_BROKEN);
    }

    #[test]
    fn a_finding_beside_a_broken_tree_exits_three() {
        let r = results(vec![
            ("Cargo.lock", finding()),
            (
                "fuzz/Cargo.lock",
                TreeResult::Broken(broken(BrokenKind::NoSummary, Some(1), &[])),
            ),
        ]);
        assert_eq!(exit_code(&r), EXIT_FOUND_AND_BROKEN);
    }

    #[test]
    fn no_tree_checked_exits_two() {
        assert_eq!(exit_code(&[]), EXIT_BROKEN);
    }

    // Writing: what goes to the report and what goes to the reasons.

    #[test]
    fn a_clean_tree_writes_nothing() {
        let w = written(&results(vec![("Cargo.lock", TreeResult::Clean)]));
        assert_eq!((w.out.as_str(), w.err.as_str()), ("", ""));
    }

    #[test]
    fn a_finding_goes_to_the_report_as_its_trees_section() {
        let r = results(vec![("fuzz/Cargo.lock", finding())]);
        let TreeResult::Found { findings, .. } = &r[0].1 else {
            unreachable!("finding() is Found")
        };
        let w = written(&r);
        // Routing only: what a section holds is pinned in deny.rs.
        assert_eq!(
            w.out,
            format!("{}\n", deny::section("fuzz/Cargo.lock", findings))
        );
    }

    #[test]
    fn the_other_errors_of_a_tree_with_findings_go_to_the_reasons() {
        let stale = UNUSED_IGNORE.lines().next().unwrap_or("");
        let r = results(vec![(
            "Cargo.lock",
            deny::classify(Some(1), &format!("{stale}\n{UNMAINTAINED}")),
        )]);
        let w = written(&r);
        assert!(
            w.err
                .contains("error[advisory-not-detected]: advisory was not encountered"),
            "got:\n{}",
            w.err
        );
    }

    #[test]
    fn a_broken_tree_goes_to_the_reasons_with_each_message_and_not_to_the_report() {
        let r = results(vec![(
            "fuzz/Cargo.lock",
            TreeResult::Broken(broken(BrokenKind::NoSummary, Some(1), &["first", "second"])),
        )]);
        let w = written(&r);
        let reasons: Vec<&str> = w.err.lines().map(str::trim).collect();
        assert_eq!(
            (w.out.as_str(), &reasons[1..]),
            ("", &["first", "second"][..])
        );
    }

    #[test]
    fn no_tree_checked_says_so_in_the_reasons() {
        let w = written(&[]);
        assert!(w.err.contains("Cargo.lock"), "got:\n{}", w.err);
    }

    #[test]
    fn a_broken_tree_is_described_by_its_lockfile() {
        let line = describe(
            "naïve/Cargo.lock",
            &broken(BrokenKind::NoSummary, Some(1), &[]),
        );
        assert!(line.contains("naïve/Cargo.lock"), "got: {line}");
    }

    #[test]
    fn a_run_that_exited_is_described_with_its_exit_code() {
        let line = describe("Cargo.lock", &broken(BrokenKind::NoFinding, Some(101), &[]));
        assert!(line.contains("101"), "got: {line}");
    }

    #[test]
    fn a_run_with_no_exit_code_is_described_as_ended_by_a_signal() {
        let line = describe("Cargo.lock", &broken(BrokenKind::NoSummary, None, &[]));
        assert!(line.contains("signal"), "got: {line}");
    }

    #[test]
    fn a_run_that_never_started_claims_neither_an_exit_code_nor_a_signal() {
        // A missing cargo once read "exit on a signal", which is wrong on
        // both counts.
        let line = describe("Cargo.lock", &broken(BrokenKind::NotRun, None, &[]));
        assert!(
            !line.contains("exit") && !line.contains("signal"),
            "got: {line}"
        );
    }

    #[test]
    fn each_broken_kind_is_described_differently() {
        let lines = [
            BrokenKind::NotRun,
            BrokenKind::NoSummary,
            BrokenKind::NoFinding,
        ]
        .map(|k| describe("Cargo.lock", &broken(k, Some(1), &[])));
        assert!(
            lines[0] != lines[1] && lines[1] != lines[2] && lines[0] != lines[2],
            "got: {lines:?}"
        );
    }

    // Choosing what to run.

    #[test]
    fn root_locks_the_root_lockfile_and_no_other() {
        assert_eq!(
            [
                Locked::Root.applies_to(Path::new("Cargo.lock")),
                Locked::Root.applies_to(Path::new("fuzz/Cargo.lock"))
            ],
            [true, false]
        );
    }

    #[test]
    fn all_locks_a_nested_lockfile() {
        assert!(Locked::All.applies_to(Path::new("fuzz/Cargo.lock")));
    }

    #[test]
    fn none_does_not_lock_the_root() {
        assert!(!Locked::None.applies_to(Path::new("Cargo.lock")));
    }

    #[test]
    fn locked_parses_its_three_values() {
        assert_eq!(
            ["root", "none", "all"].map(|s| s.parse::<Locked>()),
            [Ok(Locked::Root), Ok(Locked::None), Ok(Locked::All)]
        );
    }

    #[test]
    fn locked_refuses_any_other_value_and_carries_it() {
        assert_eq!("Root".parse::<Locked>(), Err(UnknownLocked("Root".into())));
    }

    #[test]
    fn a_nested_lockfile_is_checked_through_the_manifest_beside_it() {
        let args = deny_args(
            Path::new("fuzz/Cargo.lock"),
            Path::new("/repo/deny.toml"),
            false,
        );
        assert_eq!(
            value_after(&args, "--manifest-path"),
            Some(OsStr::new("fuzz/Cargo.toml"))
        );
    }

    #[test]
    fn the_config_flag_carries_the_given_path() {
        let args = deny_args(Path::new("Cargo.lock"), Path::new("/repo/deny.toml"), false);
        assert_eq!(
            value_after(&args, "--config"),
            Some(OsStr::new("/repo/deny.toml"))
        );
    }

    #[test]
    fn every_run_asks_for_json_at_error_level_over_the_whole_workspace() {
        let args = deny_args(Path::new("Cargo.lock"), Path::new("deny.toml"), false);
        assert_eq!(
            (
                value_after(&args, "--format"),
                value_after(&args, "--log-level"),
                args.iter().any(|a| a == "--workspace")
            ),
            (Some(OsStr::new("json")), Some(OsStr::new("error")), true),
            "got {args:?}"
        );
    }

    #[test]
    fn check_advisories_comes_after_every_global_flag() {
        // cargo-deny reads `--config`, `--manifest-path` and the rest only
        // before the subcommand.
        let args = deny_args(Path::new("Cargo.lock"), Path::new("deny.toml"), true);
        assert_eq!(
            &args[args.len() - 2..],
            ["check", "advisories"],
            "got {args:?}"
        );
    }

    #[test]
    fn locked_is_passed_only_when_asked() {
        let with = deny_args(Path::new("Cargo.lock"), Path::new("deny.toml"), true);
        let without = deny_args(Path::new("Cargo.lock"), Path::new("deny.toml"), false);
        assert_eq!(
            (
                with.iter().any(|a| a == "--locked"),
                without.iter().any(|a| a == "--locked")
            ),
            (true, false)
        );
    }

    #[test]
    fn cargo_comes_from_the_cargo_variable_when_set() {
        let env = |k: &str| (k == "CARGO").then(|| OsString::from("/opt/cargo"));
        assert_eq!(cargo_program(env), OsString::from("/opt/cargo"));
    }

    #[test]
    fn an_unset_or_empty_cargo_variable_means_cargo_on_path() {
        assert_eq!(
            [
                cargo_program(|_| None),
                cargo_program(|_| Some(OsString::new()))
            ],
            [OsString::from("cargo"), OsString::from("cargo")]
        );
    }

    #[test]
    fn a_nul_separated_listing_splits_into_paths_and_drops_the_trailing_empty_one() {
        assert_eq!(
            split_nul(b"Cargo.lock\0fuzz/Cargo.lock\0"),
            [
                PathBuf::from("Cargo.lock"),
                PathBuf::from("fuzz/Cargo.lock")
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_path_that_is_not_utf8_survives_the_split() {
        use std::os::unix::ffi::OsStrExt;
        let raw = b"na\xefve/Cargo.lock";
        let mut listing = raw.to_vec();
        listing.push(0);
        assert_eq!(split_nul(&listing), [PathBuf::from(OsStr::from_bytes(raw))]);
    }
}
