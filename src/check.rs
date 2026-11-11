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

use crate::deny::{self, Broken, BrokenKind, TreeResult, UnusedIgnore};

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
/// Added to [`EXIT_CLEAN`] or [`EXIT_FOUND`], so 4 or 5: `deny.toml` denies
/// unused ignore entries and one matches nothing in any tree. It is its
/// own bit because the report is still whole: a caller can file or close
/// on the findings and then fail on the entry. Never beside a broken tree,
/// which may be the one that needs the entry.
pub const EXIT_STALE_IGNORE: u8 = 4;

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
/// the human report does not. `--log-level warn` because an unused ignore
/// entry is a warning at cargo-deny's default; a warning-level advisory
/// it lets through is not a finding. `--config` because cargo deny
/// otherwise prefers a `deny.toml` next to the manifest. `--workspace`
/// graphs every member, not just the root package and what it depends on.
fn deny_args(lockfile: &Path, config: &Path, locked: bool) -> Vec<OsString> {
    let mut args: Vec<OsString> = [
        "deny",
        "--format",
        "json",
        "--log-level",
        "warn",
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

/// One tree's run: its lockfile, what it came to, and the ignore entries
/// it matched nothing with.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Tree {
    pub lockfile: PathBuf,
    pub result: TreeResult,
    pub unused: Vec<UnusedIgnore>,
}

/// The ignore entries that every tree whose check ran matched nothing
/// with, each once, in the order the first of those trees reported them,
/// and whether every tree's check ran. A broken tree may have needed an
/// entry the others did not, so beside one the entries are candidates, not
/// known to be stale.
fn stale_ignores(trees: &[Tree]) -> (Vec<UnusedIgnore>, bool) {
    let ran: Vec<&Tree> = trees
        .iter()
        .filter(|t| !matches!(t.result, TreeResult::Broken(_)))
        .collect();
    let mut stale: Vec<UnusedIgnore> = Vec::new();
    for u in ran.first().map_or(&[][..], |t| &t.unused) {
        if !stale.contains(u) && ran.iter().all(|t| t.unused.contains(u)) {
            stale.push(u.clone());
        }
    }
    (stale, ran.len() == trees.len())
}

/// The exit code for what every tree came to: found, plus twice broken,
/// plus [`EXIT_STALE_IGNORE`] for a denied stale ignore entry. An empty
/// list would pass every tree by checking none of them, so it is broken.
fn exit_code(trees: &[Tree], denied_stale: bool) -> u8 {
    let found = trees
        .iter()
        .any(|t| matches!(t.result, TreeResult::Found { .. }));
    let broken = trees.is_empty()
        || trees
            .iter()
            .any(|t| matches!(t.result, TreeResult::Broken(_)));
    let trees = match (found, broken) {
        (false, false) => EXIT_CLEAN,
        (true, false) => EXIT_FOUND,
        (false, true) => EXIT_BROKEN,
        (true, true) => EXIT_FOUND_AND_BROKEN,
    };
    trees + if denied_stale { EXIT_STALE_IGNORE } else { 0 }
}

/// What `check` needs to know.
#[derive(Debug, Clone)]
pub struct Options {
    /// The repository's top level; every lockfile path is relative to it.
    pub root: PathBuf,
    /// The `deny.toml` every tree is checked against. It has to exist:
    /// cargo deny warns about a missing one and uses its defaults.
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
/// A config that is not a file is broken before any tree runs. Returns
/// the exit code.
pub fn run(opts: &Options, out: &mut impl Write, err: &mut impl Write) -> io::Result<u8> {
    if !opts.config.is_file() {
        writeln!(
            err,
            "no deny.toml at {}: cargo deny would check with its defaults instead",
            opts.config.display()
        )?;
        return Ok(EXIT_BROKEN);
    }
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
    let trees = check_trees(&lockfiles, deny, out, err)?;
    let (stale, every_tree_ran) = stale_ignores(&trees);
    write_stale(&stale, every_tree_ran, &opts.config, err)?;
    // Beside a broken tree the entries are candidates, which fail nothing.
    let denied_stale = every_tree_ran && stale.iter().any(|u| u.denied);
    Ok(exit_code(&trees, denied_stale))
}

/// Each of `lockfiles` with what its run came to, in order. `deny` runs
/// cargo deny on one tree and returns its exit code and output, or why it
/// could not start. Each tree's lines are written as its run ends, after a
/// line naming it as the run starts, so a CI log shows a run that hangs.
pub(crate) fn check_trees(
    lockfiles: &[PathBuf],
    mut deny: impl FnMut(&Path) -> Result<(Option<i32>, String), String>,
    out: &mut impl Write,
    err: &mut impl Write,
) -> io::Result<Vec<Tree>> {
    if lockfiles.is_empty() {
        writeln!(err, "no tracked Cargo.lock to check")?;
    }
    lockfiles
        .iter()
        .map(|lockfile| {
            writeln!(err, "checking {}", lockfile.to_string_lossy())?;
            let (result, unused) = match deny(lockfile) {
                Ok((exit, output)) => deny::read(exit, &output),
                Err(why) => (
                    TreeResult::Broken(Broken {
                        kind: BrokenKind::NotRun,
                        exit: None,
                        messages: vec![why],
                    }),
                    Vec::new(),
                ),
            };
            let tree = Tree {
                lockfile: lockfile.clone(),
                result,
                unused,
            };
            write_tree(&tree, out, err)?;
            Ok(tree)
        })
        .collect()
}

/// Write a tree's section of the report to `out` if it found something,
/// and to `err` that it is clean, why it broke, or any other error it
/// reported beside its findings. The clean line is for a CI log, which
/// otherwise shows nothing of a passing run; the report stays empty.
fn write_tree(t: &Tree, out: &mut impl Write, err: &mut impl Write) -> io::Result<()> {
    let name = t.lockfile.to_string_lossy();
    match &t.result {
        TreeResult::Clean => writeln!(err, "{name}: clean")?,
        TreeResult::Found { findings, messages } => {
            writeln!(out, "{}", deny::section(&name, findings))?;
            if !messages.is_empty() {
                writeln!(err, "cargo deny on {name} also reported:")?;
                for m in messages {
                    writeln!(err, "{}", indented(m))?;
                }
            }
        }
        TreeResult::Broken(b) => {
            writeln!(err, "{}", describe(&name, b))?;
            for m in &b.messages {
                writeln!(err, "{}", indented(m))?;
            }
        }
    }
    Ok(())
}

/// `message` with each of its lines indented. A message from cargo may
/// run to several lines, and at column 0 a `warning: ` or `error: ` line
/// is one of this crate's own (scripts/annotate.sh reads them there).
fn indented(message: &str) -> String {
    message
        .lines()
        .map(|line| format!("    {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Write to `err` a line for each stale ignore entry, naming the config it
/// is in: an error if the config denies unused entries, else a warning.
/// When a tree broke, the entries are candidates, each a warning that says
/// which trees it speaks for.
fn write_stale(
    stale: &[UnusedIgnore],
    every_tree_ran: bool,
    config: &Path,
    err: &mut impl Write,
) -> io::Result<()> {
    let trees = if every_tree_ran {
        "any tracked Cargo.lock"
    } else {
        "any Cargo.lock whose check ran"
    };
    for u in stale {
        let level = if u.denied && every_tree_ran {
            "error"
        } else {
            "warning"
        };
        writeln!(
            err,
            "{level}: {} ignores {}, which matches nothing in {trees}",
            config.display(),
            u.entry
        )?;
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
    use crate::fixtures::{CLEAN, CONFIG_ERROR, STALE_LOCK, UNMAINTAINED, UNUSED_DENY, ignore};

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

    fn tree(lockfile: &str, result: TreeResult, unused: &[(&str, bool)]) -> Tree {
        Tree {
            lockfile: PathBuf::from(lockfile),
            result,
            unused: unused
                .iter()
                .map(|&(entry, denied)| ignore(entry, denied))
                .collect(),
        }
    }

    fn results(list: Vec<(&str, TreeResult)>) -> Vec<Tree> {
        list.into_iter().map(|(l, r)| tree(l, r, &[])).collect()
    }

    /// The trees `check_trees` returns, its writing thrown away.
    fn checked(
        lockfiles: &[PathBuf],
        deny: impl FnMut(&Path) -> Result<(Option<i32>, String), String>,
    ) -> Vec<Tree> {
        check_trees(lockfiles, deny, &mut io::sink(), &mut io::sink()).expect("write to a sink")
    }

    /// A writer whose bytes the test can read while another holds it.
    #[derive(Clone, Default)]
    struct Shared(std::rc::Rc<std::cell::RefCell<Vec<u8>>>);

    impl Write for Shared {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.borrow_mut().write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Shared {
        fn text(&self) -> String {
            String::from_utf8(self.0.borrow().clone()).expect("utf-8")
        }
    }

    // A run that hangs shows in a CI log as the last tree named, and the
    // trees before it as done.
    #[test]
    fn each_tree_is_named_as_its_run_starts_and_its_lines_written_as_it_ends() {
        let err = Shared::default();
        let mut seen = Vec::new();
        let lockfiles = [
            PathBuf::from("Cargo.lock"),
            PathBuf::from("fuzz/Cargo.lock"),
        ];
        let watch = err.clone();
        check_trees(
            &lockfiles,
            |_| {
                seen.push(watch.text());
                Ok((Some(0), CLEAN.to_string()))
            },
            &mut io::sink(),
            &mut err.clone(),
        )
        .expect("write to a Shared buffer");
        assert_eq!(
            seen,
            [
                "checking Cargo.lock\n",
                "checking Cargo.lock\nCargo.lock: clean\nchecking fuzz/Cargo.lock\n"
            ]
        );
    }

    /// What `write_tree` wrote for each of `results`.
    struct Written {
        out: String,
        err: String,
    }

    fn written(results: &[Tree]) -> Written {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        for t in results {
            write_tree(t, &mut out, &mut err).expect("write to a Vec");
        }
        Written {
            out: String::from_utf8(out).expect("utf-8 report"),
            err: String::from_utf8(err).expect("utf-8 reasons"),
        }
    }

    // cargo's own `error: ` line, which follows a newline inside one
    // message of this fixture, must not read as one of this crate's.
    #[test]
    fn every_line_of_a_message_that_runs_to_several_is_indented() {
        let w = written(&results(vec![(
            "Cargo.lock",
            deny::classify(Some(1), STALE_LOCK),
        )]));
        let own: Vec<&str> = w.err.lines().filter(|l| !l.starts_with("    ")).collect();
        assert_eq!(
            own,
            ["cargo deny on Cargo.lock stopped before it checked anything (exit 1):"],
            "got:\n{}",
            w.err
        );
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
        let got = checked(&[PathBuf::from("Cargo.lock")], |_| {
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
        let got = checked(
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
            results(vec![
                ("Cargo.lock", deny::classify(Some(1), UNMAINTAINED)),
                ("fuzz/Cargo.lock", deny::classify(Some(1), CONFIG_ERROR)),
            ])
        );
    }

    #[test]
    fn each_tree_carries_the_unused_ignores_of_its_own_run() {
        let got = checked(
            &[
                PathBuf::from("Cargo.lock"),
                PathBuf::from("fuzz/Cargo.lock"),
            ],
            |lockfile| {
                Ok(if lockfile == Path::new("Cargo.lock") {
                    (Some(1), UNUSED_DENY.to_string())
                } else {
                    (Some(0), CLEAN.to_string())
                })
            },
        );
        let unused: Vec<_> = got.iter().map(|t| t.unused.clone()).collect();
        assert_eq!(
            unused,
            [
                vec![
                    ignore("RUSTSEC-2020-0001", true),
                    ignore("smallvec@1.4.0", true)
                ],
                vec![]
            ]
        );
    }

    #[test]
    fn an_entry_every_tree_left_unused_is_stale() {
        let trees = [
            tree(
                "Cargo.lock",
                TreeResult::Clean,
                &[("RUSTSEC-2020-0001", false)],
            ),
            tree(
                "fuzz/Cargo.lock",
                finding(),
                &[("RUSTSEC-2020-0001", false)],
            ),
        ];
        assert_eq!(stale_ignores(&trees), (stale(false).to_vec(), true));
    }

    #[test]
    fn an_entry_one_tree_used_is_not_stale() {
        // The shape the multi-lockfile repos have: an ignore only the
        // site's tree needs.
        let trees = [
            tree(
                "Cargo.lock",
                TreeResult::Clean,
                &[("RUSTSEC-2025-0141", true)],
            ),
            tree("site/Cargo.lock", TreeResult::Clean, &[]),
            tree(
                "fuzz/Cargo.lock",
                TreeResult::Clean,
                &[("RUSTSEC-2025-0141", true)],
            ),
        ];
        assert_eq!(stale_ignores(&trees).0, []);
    }

    #[test]
    fn stale_entries_keep_the_first_trees_order() {
        let both = [("RUSTSEC-2020-0002", false), ("RUSTSEC-2020-0001", false)];
        let reversed = [("RUSTSEC-2020-0001", false), ("RUSTSEC-2020-0002", false)];
        let trees = [
            tree("Cargo.lock", TreeResult::Clean, &both),
            tree("fuzz/Cargo.lock", TreeResult::Clean, &reversed),
        ];
        let entries: Vec<_> = stale_ignores(&trees)
            .0
            .into_iter()
            .map(|u| u.entry)
            .collect();
        assert_eq!(entries, ["RUSTSEC-2020-0002", "RUSTSEC-2020-0001"]);
    }

    #[test]
    fn an_entry_deny_toml_lists_twice_is_stale_once() {
        // `ignore = ["RUSTSEC-2020-0001", { id = "RUSTSEC-2020-0001", reason = "..." }]`
        // gets one diagnostic per listing.
        let twice = [("RUSTSEC-2020-0001", false), ("RUSTSEC-2020-0001", false)];
        let trees = [tree("Cargo.lock", TreeResult::Clean, &twice)];
        assert_eq!(stale_ignores(&trees).0, stale(false));
    }

    #[test]
    fn beside_a_broken_tree_what_the_other_trees_left_unused_is_only_a_candidate() {
        // The broken tree never said which entries it uses, and its own
        // list is not read: it may have stopped part way.
        let trees = [
            tree(
                "Cargo.lock",
                TreeResult::Clean,
                &[("RUSTSEC-2020-0001", true)],
            ),
            tree(
                "fuzz/Cargo.lock",
                TreeResult::Broken(broken(BrokenKind::NoFinding, Some(1), &[])),
                &[],
            ),
        ];
        assert_eq!(stale_ignores(&trees), (stale(true).to_vec(), false));
    }

    #[test]
    fn when_every_tree_broke_there_is_no_candidate() {
        let trees = [tree(
            "Cargo.lock",
            TreeResult::Broken(broken(BrokenKind::NoFinding, Some(1), &[])),
            &[("RUSTSEC-2020-0001", true)],
        )];
        assert_eq!(stale_ignores(&trees), (vec![], false));
    }

    #[test]
    fn no_tree_means_no_stale_entry() {
        assert_eq!(stale_ignores(&[]), (vec![], true));
    }

    #[test]
    fn clean_trees_exit_zero() {
        let r = results(vec![
            ("Cargo.lock", TreeResult::Clean),
            ("fuzz/Cargo.lock", TreeResult::Clean),
        ]);
        assert_eq!(exit_code(&r, false), EXIT_CLEAN);
    }

    #[test]
    fn a_finding_exits_one() {
        let r = results(vec![
            ("Cargo.lock", TreeResult::Clean),
            ("fuzz/Cargo.lock", finding()),
        ]);
        assert_eq!(exit_code(&r, false), EXIT_FOUND);
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
        assert_eq!(exit_code(&r, false), EXIT_BROKEN);
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
        assert_eq!(exit_code(&r, false), EXIT_FOUND_AND_BROKEN);
    }

    fn stale(denied: bool) -> [UnusedIgnore; 1] {
        [ignore("RUSTSEC-2020-0001", denied)]
    }

    #[test]
    fn a_denied_stale_entry_on_clean_trees_exits_four() {
        let r = results(vec![("Cargo.lock", TreeResult::Clean)]);
        assert_eq!(exit_code(&r, true), 4);
    }

    #[test]
    fn a_denied_stale_entry_beside_a_finding_exits_five() {
        // Not three, which tells the monitor some tree's findings are
        // missing and freezes the issue; a stale entry hides none.
        let r = results(vec![("Cargo.lock", finding())]);
        assert_eq!(exit_code(&r, true), 5);
    }

    #[test]
    fn no_tree_checked_exits_two() {
        assert_eq!(exit_code(&[], false), EXIT_BROKEN);
    }

    // Writing: what goes to the report and what goes to the reasons.

    #[test]
    fn a_clean_tree_is_named_in_the_reasons_and_not_in_the_report() {
        let w = written(&results(vec![("Cargo.lock", TreeResult::Clean)]));
        assert_eq!(
            (w.out.as_str(), w.err.as_str()),
            ("", "Cargo.lock: clean\n")
        );
    }

    #[test]
    fn a_finding_goes_to_the_report_as_its_trees_section() {
        let r = results(vec![("fuzz/Cargo.lock", finding())]);
        let TreeResult::Found { findings, .. } = &r[0].result else {
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
        let TreeResult::Found { findings, .. } = finding() else {
            unreachable!("finding() is Found")
        };
        let messages = vec!["error[unexpected-keys]: one".to_string()];
        let r = results(vec![(
            "Cargo.lock",
            TreeResult::Found { findings, messages },
        )]);
        let w = written(&r);
        assert_eq!(
            w.err.lines().last().map(str::trim),
            Some("error[unexpected-keys]: one"),
            "got:\n{}",
            w.err
        );
    }

    /// What `write_stale` wrote for `stale` in `ci/deny.toml`.
    fn stale_written(stale: &[UnusedIgnore], every_tree_ran: bool) -> String {
        let mut err = Vec::new();
        write_stale(stale, every_tree_ran, Path::new("ci/deny.toml"), &mut err)
            .expect("write to a Vec");
        String::from_utf8(err).expect("utf-8 reasons")
    }

    #[test]
    fn a_stale_entry_is_written_with_its_config_and_entry() {
        let line = stale_written(&stale(false), true);
        assert!(
            line.contains("ci/deny.toml") && line.contains("RUSTSEC-2020-0001"),
            "got: {line}"
        );
    }

    // action.yml turns a line into an annotation by these two prefixes.
    #[test]
    fn a_stale_entry_is_a_warning_unless_denied() {
        let [warned, denied] = [false, true].map(|d| stale_written(&stale(d), true));
        assert_eq!(
            (
                warned.starts_with("warning: "),
                denied.starts_with("error: ")
            ),
            (true, true),
            "got: {warned:?} and {denied:?}"
        );
    }

    #[test]
    fn a_denied_candidate_is_a_warning() {
        let line = stale_written(&stale(true), false);
        assert!(line.starts_with("warning: "), "got: {line}");
    }

    #[test]
    fn only_a_candidate_says_it_speaks_for_the_trees_whose_check_ran() {
        // The token is the claim: a broken tree may yet need the entry.
        let [candidate, settled] =
            [false, true].map(|ran| stale_written(&stale(false), ran).contains("whose check ran"));
        assert_eq!((candidate, settled), (true, false));
    }

    #[test]
    fn each_stale_entry_gets_its_own_line() {
        let two = [stale(false), stale(true)].concat();
        assert_eq!(stale_written(&two, true).lines().count(), 2);
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
        let err = Shared::default();
        check_trees(
            &[],
            |_| unreachable!("no tree to run"),
            &mut io::sink(),
            &mut err.clone(),
        )
        .expect("write to a Shared buffer");
        assert_eq!(err.text(), "no tracked Cargo.lock to check\n");
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
            value_after(&args, "--manifest-path").map(Path::new),
            Some(Path::new("fuzz/Cargo.toml"))
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
    fn every_run_asks_for_json_at_warn_level_over_the_whole_workspace() {
        let args = deny_args(Path::new("Cargo.lock"), Path::new("deny.toml"), false);
        assert_eq!(
            (
                value_after(&args, "--format"),
                value_after(&args, "--log-level"),
                args.iter().any(|a| a == "--workspace")
            ),
            (Some(OsStr::new("json")), Some(OsStr::new("warn")), true),
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
