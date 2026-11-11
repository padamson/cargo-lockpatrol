//! Reading one `cargo deny --format json check advisories` run.
//!
//! cargo-deny exits 1 both for a finding and for a run that never got as
//! far as checking (a bad `deny.toml`, an advisory-db fetch, `cargo
//! metadata`), so the exit code alone cannot tell them apart. The JSON can:
//! a run that finished writes a `{"type":"summary"}` line last, and a
//! finding is a diagnostic whose code is one of [`FINDING_CODES`].

use serde_json::Value;

/// The diagnostic codes that are advisories against a crate in the tree.
/// [`read`] takes an ignore entry the run matched nothing with apart from
/// the rest; every other code that fails a run
/// (`unexpected-keys` from a bad config) is a broken check: there is
/// nothing in the dependency tree to triage.
pub const FINDING_CODES: [&str; 5] = [
    "vulnerability",
    "unmaintained",
    "unsound",
    "notice",
    "yanked",
];

/// The diagnostic codes for an `[advisories].ignore` entry that matched
/// nothing in the tree: an advisory id, or a yanked crate.
const UNUSED_CODES: [&str; 2] = ["advisory-not-detected", YANKED_NOT_DETECTED];
const YANKED_NOT_DETECTED: &str = "yanked-not-detected";

/// The warning for a crate whose registry cargo-deny could not ask whether
/// it is yanked. A yanked-crate ignore for it then reads as unused
/// (`check` in cargo-deny 0.20.2's src/advisories.rs).
const INDEX_FAILURE_CODE: &str = "index-failure";

/// An `[advisories].ignore` entry that one run matched nothing with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnusedIgnore {
    /// The entry as `deny.toml` spells it: a `RUSTSEC-` id, or a yanked
    /// crate such as `smallvec@1.4.0`.
    pub entry: String,
    /// Whether the run counted it as an error, as it does under
    /// `unused-ignored-advisory = "deny"`. cargo-deny's default is a
    /// warning.
    pub denied: bool,
}

/// One advisory cargo-deny reported against one crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The diagnostic code, one of [`FINDING_CODES`].
    pub code: String,
    /// The `RUSTSEC-` id. A yanked crate has none.
    pub id: Option<String>,
    /// cargo-deny's one-line message: the advisory's title, or for a
    /// yanked crate the suggestion to update it.
    pub message: String,
    /// cargo-deny's notes: the id, the advisory URL, the description and
    /// the solution, in its order. A note may span several lines.
    pub notes: Vec<String>,
    /// The inverted dependency tree from the affected crate up to the
    /// workspace, one line per crate, already indented.
    pub graph: Vec<String>,
}

/// What one tree's run came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeResult {
    Clean,
    /// Advisories, and any other errors the same run reported (a second
    /// error beside a real finding), which a caller should still show: the
    /// gate is red on both. From [`classify`] a denied unused ignore entry
    /// is one of them; [`read`] returns those apart.
    Found {
        findings: Vec<Finding>,
        messages: Vec<String>,
    },
    Broken(Broken),
}

/// A run that counts as broken: why, its exit code (`None` for a signal),
/// and the error lines cargo-deny wrote, so the caller can say what went
/// wrong without the raw JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Broken {
    pub kind: BrokenKind,
    pub exit: Option<i32>,
    pub messages: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokenKind {
    /// cargo deny could not be started at all.
    NotRun,
    /// No summary line: cargo-deny stopped before it checked anything.
    NoSummary,
    /// The run finished and failed, but on nothing in [`FINDING_CODES`]
    /// (nor, from [`read`], only on unused ignore entries).
    NoFinding,
}

/// Classify one run from its exit code and its output (stderr, where
/// cargo-deny writes its JSON, with stdout appended; a line that is not
/// JSON is kept as an error message).
///
/// A run with no summary is broken whatever its exit code, so a change to
/// cargo-deny's JSON that drops or renames the summary fails loudly
/// instead of passing every tree.
///
/// This reads the run alone: an ignore entry it matched nothing with is
/// an error like any other when `deny.toml` denies it. [`read`] reads the
/// run as one tree of several.
///
/// ```
/// use cargo_lockpatrol::deny::{classify, TreeResult};
///
/// let clean = r#"{"fields":{"advisories":{"errors":0,"helps":0,"notes":0,"warnings":0}},"type":"summary"}"#;
/// assert_eq!(classify(Some(0), clean), TreeResult::Clean);
/// assert!(matches!(classify(Some(0), ""), TreeResult::Broken(_)));
/// ```
pub fn classify(exit: Option<i32>, output: &str) -> TreeResult {
    let run = parse(output);
    let messages = run
        .lines
        .into_iter()
        .filter_map(|line| match line {
            Line::Error(m) | Line::NotJson(m) => Some(m),
            Line::Unused {
                ignore, headline, ..
            } => ignore.denied.then_some(headline),
        })
        .collect();
    conclude(exit, run.summary, run.findings, messages, false)
}

/// One tree's run in a repository whose trees share a `deny.toml`: what it
/// came to, and the ignore entries it matched nothing with, at either
/// severity: the advisory ids, then the yanked crates, each in the order
/// cargo-deny reported them.
///
/// Most entries of a shared `deny.toml` are unused in most trees, so
/// whether one is stale is the caller's to decide across every tree, and a
/// run that failed only on unused entries is clean here. A yanked-crate
/// entry is left out when the run could not ask a registry about some
/// crate, since the entry may be for that crate. cargo-deny reports unused
/// entries only at `--log-level warn` or below unless `deny.toml` denies
/// them.
pub fn read(exit: Option<i32>, output: &str) -> (TreeResult, Vec<UnusedIgnore>) {
    let run = parse(output);
    let mut messages = Vec::new();
    let mut unused = Vec::new();
    let mut yanked = Vec::new();
    // Whether cargo-deny reported an error other than an unused entry. A
    // line that is not JSON is not one: cargo and rustup write plain
    // notices to stderr on runs that pass.
    let mut other_error = false;
    for line in run.lines {
        match line {
            Line::Error(m) => {
                other_error = true;
                messages.push(m);
            }
            Line::NotJson(m) => messages.push(m),
            Line::Unused {
                ignore,
                yanked: true,
                ..
            } => yanked.push(ignore),
            Line::Unused { ignore, .. } => unused.push(ignore),
        }
    }
    let unverified = run.index_failed && yanked.iter().any(|u| u.denied);
    if !run.index_failed {
        unused.append(&mut yanked);
    }
    let excused =
        exit == Some(1) && !other_error && (unverified || unused.iter().any(|u| u.denied));
    (
        conclude(exit, run.summary, run.findings, messages, excused),
        unused,
    )
}

/// A line of a run's output that is neither its summary nor a finding.
enum Line {
    /// An error diagnostic with no finding code, or an `ERROR` log record.
    Error(String),
    /// Not JSON, so not cargo-deny's.
    NotJson(String),
    /// An ignore entry the run matched nothing with: whether it is for a
    /// yanked crate, and the diagnostic as [`Line::Error`] would hold it.
    Unused {
        ignore: UnusedIgnore,
        yanked: bool,
        headline: String,
    },
}

/// A run's output, read once for [`classify`] and [`read`] to weigh.
struct Run {
    summary: bool,
    findings: Vec<Finding>,
    lines: Vec<Line>,
    /// Whether cargo-deny could not ask a registry about some crate.
    index_failed: bool,
}

fn parse(output: &str) -> Run {
    let mut run = Run {
        summary: false,
        findings: Vec::new(),
        lines: Vec::new(),
        index_failed: false,
    };
    for line in output.lines().filter(|l| !l.trim().is_empty()) {
        let Ok(record) = serde_json::from_str::<Value>(line) else {
            run.lines.push(Line::NotJson(line.to_string()));
            continue;
        };
        let fields = &record["fields"];
        match record["type"].as_str() {
            Some("summary") => run.summary = true,
            Some("diagnostic") => {
                let error = fields["severity"] == "error";
                let code = text(&fields["code"]);
                let headline = || headline(code, text(&fields["message"]));
                run.index_failed |= code == INDEX_FAILURE_CODE;
                if let Some(entry) = unused_entry(fields) {
                    run.lines.push(Line::Unused {
                        ignore: UnusedIgnore {
                            entry,
                            denied: error,
                        },
                        yanked: code == YANKED_NOT_DETECTED,
                        headline: headline(),
                    });
                } else if let Some(f) = finding(fields).filter(|_| error) {
                    run.findings.push(f);
                } else if error {
                    run.lines.push(Line::Error(headline()));
                }
            }
            Some("log") if fields["level"] == "ERROR" => run
                .lines
                .push(Line::Error(format!("[ERROR] {}", text(&fields["message"])))),
            _ => {}
        }
    }
    run
}

/// What a run came to. `excused` is whether its failure is accounted for
/// by something that is not this tree's to fail on.
fn conclude(
    exit: Option<i32>,
    summary: bool,
    findings: Vec<Finding>,
    messages: Vec<String>,
    excused: bool,
) -> TreeResult {
    let kind = if !summary {
        BrokenKind::NoSummary
    } else if exit == Some(0) {
        return TreeResult::Clean;
    } else if !findings.is_empty() {
        return TreeResult::Found { findings, messages };
    } else if excused {
        return TreeResult::Clean;
    } else {
        BrokenKind::NoFinding
    };
    TreeResult::Broken(Broken {
        kind,
        exit,
        messages,
    })
}

/// The entry an unused-ignore diagnostic names: its first label's span,
/// the entry's text in `deny.toml`. One without a span names nothing, so
/// it is read as any other diagnostic is.
fn unused_entry(fields: &Value) -> Option<String> {
    if !UNUSED_CODES.contains(&text(&fields["code"])) {
        return None;
    }
    fields["labels"][0]["span"].as_str().map(str::to_string)
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap_or("")
}

fn finding(fields: &Value) -> Option<Finding> {
    let code = text(&fields["code"]);
    if !FINDING_CODES.contains(&code) {
        return None;
    }
    let notes = fields["notes"]
        .as_array()
        .map(|notes| notes.iter().map(|n| text(n).to_string()).collect())
        .unwrap_or_default();
    let mut graph = Vec::new();
    for root in fields["graphs"].as_array().into_iter().flatten() {
        graph_lines(root, &mut Vec::new(), &mut graph);
    }
    Some(Finding {
        code: code.to_string(),
        id: fields["advisory"]["id"].as_str().map(str::to_string),
        message: text(&fields["message"]).to_string(),
        notes,
        graph,
    })
}

/// One line per node of cargo-deny's inverted graph, drawn as its human
/// output draws it (`write_graph_as_text` in cargo-deny 0.20): the
/// affected crate behind `├ `, then each crate that depends on it, one
/// level deeper per step towards the workspace. `levels` holds, for each
/// level above this node, whether a sibling still follows there.
fn graph_lines(node: &Value, levels: &mut Vec<bool>, out: &mut Vec<String>) {
    let repeat = if node["repeat"] == true { " (*)" } else { "" };
    let name = if let Some(krate) = node.get("Krate") {
        let kind = krate["kind"]
            .as_str()
            .map(|k| format!("({k}) "))
            .unwrap_or_default();
        format!(
            "{kind}{} v{}{repeat}",
            text(&krate["name"]),
            text(&krate["version"])
        )
    } else if let Some(feature) = node.get("Feature") {
        format!(
            "{} feature '{}'{repeat}",
            text(&feature["crate_name"]),
            text(&feature["name"])
        )
    } else {
        return;
    };
    let mut line = String::from(if levels.is_empty() { "├ " } else { "  " });
    if let Some((&last_continues, above)) = levels.split_last() {
        for &continues in above {
            line.push_str(if continues { "│   " } else { "    " });
        }
        line.push_str(if last_continues {
            "├── "
        } else {
            "└── "
        });
    }
    line.push_str(&name);
    out.push(line);
    let parents = node["parents"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    for (i, parent) in parents.iter().enumerate() {
        levels.push(i + 1 < parents.len());
        graph_lines(parent, levels, out);
        levels.pop();
    }
}

const HEADING: &str = "## cargo deny check advisories (";

/// The heading of a tree's section in the report. The renderer keys each
/// finding on the lockfile named here (read back by [`lockfile_of`]), so
/// the wording is part of the format, not prose.
pub fn heading(lockfile: &str) -> String {
    format!("{HEADING}{lockfile})")
}

/// The lockfile a [`heading`] names, or `None` for any other line.
pub fn lockfile_of(line: &str) -> Option<&str> {
    line.strip_prefix(HEADING)?.strip_suffix(')')
}

/// A diagnostic's first line, as cargo-deny's human output starts it. The
/// renderer reads a finding from it, so it is part of the format too.
pub fn headline(code: &str, message: &str) -> String {
    format!("error[{code}]: {message}")
}

impl Finding {
    /// This finding's [`headline`].
    pub fn headline(&self) -> String {
        headline(&self.code, &self.message)
    }
}

/// A tree's section of the report: its heading, then each finding as
/// cargo-deny's human output lays it out (a headline naming the code, the
/// notes, then the graph). The diagnostic's labels are left out: their
/// line numbers point into a lockfile cargo-deny synthesizes, not the one
/// on disk.
///
/// The headline and the `├ ID:` note line are what the issue renderer
/// reads a finding from, and they match what the shell checker this
/// replaces printed, so a tracking issue it wrote reads back as the same
/// findings. A note's later lines are drawn behind `│`, so a description
/// line that holds nothing but another advisory's id cannot pass for an
/// id line.
pub fn section(lockfile: &str, findings: &[Finding]) -> String {
    use std::fmt::Write;

    // Writing to a String cannot fail.
    let mut out = heading(lockfile);
    out.push('\n');
    for f in findings {
        let _ = writeln!(out, "\n{}", f.headline());
        for note in &f.notes {
            let mut lines = note.lines();
            let _ = writeln!(out, "   ├ {}", lines.next().unwrap_or(""));
            for line in lines {
                let _ = if line.trim().is_empty() {
                    writeln!(out, "   │")
                } else {
                    writeln!(out, "   │ {}", line.trim_end())
                };
            }
        }
        for line in &f.graph {
            let _ = writeln!(out, "   {line}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::fixtures::*;

    fn found(result: TreeResult) -> Vec<Finding> {
        match result {
            TreeResult::Found { findings, .. } => findings,
            other => panic!("expected Found, got {other:?}"),
        }
    }

    fn broken(result: TreeResult) -> Broken {
        match result {
            TreeResult::Broken(b) => b,
            other => panic!("expected Broken, got {other:?}"),
        }
    }

    fn ids(findings: &[Finding]) -> Vec<(&str, Option<&str>)> {
        findings
            .iter()
            .map(|f| (f.code.as_str(), f.id.as_deref()))
            .collect()
    }

    #[test]
    fn a_summary_with_exit_zero_is_clean() {
        assert_eq!(classify(Some(0), CLEAN), TreeResult::Clean);
    }

    #[test]
    fn an_unmaintained_advisory_is_a_finding_with_its_id() {
        let f = found(classify(Some(1), UNMAINTAINED));
        assert_eq!(ids(&f), [("unmaintained", Some("RUSTSEC-2025-0141"))]);
    }

    #[test]
    fn a_vulnerability_is_a_finding_with_its_id() {
        let f = found(classify(Some(1), VULNERABILITY));
        assert_eq!(ids(&f), [("vulnerability", Some("RUSTSEC-2021-0003"))]);
    }

    #[test]
    fn unsound_and_notice_advisories_are_findings() {
        // No fixture has either code, and cargo-mutants does not mutate the
        // literals in FINDING_CODES, so a misspelt one would turn those
        // advisories into a broken check (exit 2, no issue filed) unseen.
        for code in ["unsound", "notice"] {
            let run =
                UNMAINTAINED.replace(r#""code":"unmaintained""#, &format!(r#""code":"{code}""#));
            assert_eq!(
                ids(&found(classify(Some(1), &run))),
                [(code, Some("RUSTSEC-2025-0141"))],
                "code {code}"
            );
        }
    }

    #[test]
    fn every_advisory_in_a_run_is_kept_in_order() {
        let f = found(classify(Some(1), TWO));
        assert_eq!(
            ids(&f),
            [
                ("unmaintained", Some("RUSTSEC-2025-0141")),
                ("vulnerability", Some("RUSTSEC-2021-0003"))
            ]
        );
    }

    #[test]
    fn a_yanked_crate_is_a_finding_without_an_id() {
        let f = found(classify(Some(1), YANKED));
        assert_eq!(ids(&f), [("yanked", None)]);
    }

    #[test]
    fn a_yanked_crate_is_named_in_its_message() {
        let f = found(classify(Some(1), YANKED));
        assert_eq!(
            f[0].message,
            "detected yanked crate (try `cargo update -p smallvec`)"
        );
    }

    #[test]
    fn a_finding_carries_the_advisory_title() {
        let f = &found(classify(Some(1), UNMAINTAINED))[0];
        assert_eq!(f.message, "Bincode is unmaintained");
    }

    #[test]
    fn a_finding_carries_the_notes_in_cargo_denys_order() {
        let f = &found(classify(Some(1), UNMAINTAINED))[0];
        let firsts: Vec<&str> = f
            .notes
            .iter()
            .map(|n| n.lines().next().unwrap_or(""))
            .collect();
        assert_eq!(firsts.first(), Some(&"ID: RUSTSEC-2025-0141"));
        assert_eq!(
            firsts.last(),
            Some(&"Solution: No safe upgrade is available!")
        );
    }

    #[test]
    fn a_finding_carries_the_path_from_the_crate_to_the_workspace() {
        let f = &found(classify(Some(1), UNMAINTAINED))[0];
        assert_eq!(f.graph, ["├ bincode v1.3.3", "  └── fx v0.1.0"]);
    }

    /// The ignore entries `output` reports unused, read as `check` reads
    /// them.
    fn unused_in(output: &str) -> Vec<UnusedIgnore> {
        read(Some(0), output).1
    }

    const ADVISORY_NOT_DETECTED: &str =
        "error[advisory-not-detected]: advisory was not encountered";

    #[test]
    fn a_finding_keeps_the_other_errors_its_run_reported() {
        // A stale ignore entry beside a real advisory: the gate is red on
        // both, so the stale entry must not vanish behind the finding.
        let run = format!("{}\n{UNMAINTAINED}", first(UNUSED_DENY));
        match classify(Some(1), &run) {
            TreeResult::Found { messages, .. } => assert_eq!(messages, [ADVISORY_NOT_DETECTED]),
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[test]
    fn a_run_classified_alone_is_broken_by_its_denied_unused_ignores() {
        let b = broken(classify(Some(1), UNUSED_DENY));
        assert_eq!(
            (b.kind, b.messages),
            (
                BrokenKind::NoFinding,
                vec![
                    ADVISORY_NOT_DETECTED.to_string(),
                    "error[yanked-not-detected]: yanked crate was not encountered".to_string()
                ]
            )
        );
    }

    #[test]
    fn an_unused_ignore_beside_a_finding_is_read_as_unused_not_as_a_message() {
        // An entry this tree does not use may be what another tree needs.
        let run = format!("{}\n{UNMAINTAINED}", first(UNUSED_DENY));
        match read(Some(1), &run) {
            (TreeResult::Found { messages, .. }, unused) => assert_eq!(
                (messages, unused),
                (vec![], vec![ignore("RUSTSEC-2020-0001", true)])
            ),
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[test]
    fn a_failed_run_whose_only_errors_are_unused_ignores_reads_as_clean() {
        assert_eq!(read(Some(1), UNUSED_DENY).0, TreeResult::Clean);
    }

    #[test]
    fn a_line_that_is_not_cargo_denys_does_not_break_a_run_failed_by_unused_ignores() {
        let run = format!("info: syncing channel updates\n{UNUSED_DENY}");
        assert_eq!(read(Some(1), &run).0, TreeResult::Clean);
    }

    #[test]
    fn a_failed_run_with_unused_ignores_only_at_warning_level_reads_as_broken() {
        // The warnings did not fail it, so something else did.
        assert_eq!(
            broken(read(Some(1), UNUSED_WARN).0).kind,
            BrokenKind::NoFinding
        );
    }

    #[test]
    fn unused_ignores_beside_another_error_read_as_broken() {
        let run = format!("{}\n{UNUSED_DENY}", first(CONFIG_ERROR));
        assert_eq!(broken(read(Some(1), &run).0).kind, BrokenKind::NoFinding);
    }

    #[test]
    fn unused_ignores_under_an_exit_code_other_than_one_read_as_broken() {
        // cargo-deny exits 1 for errors it reported; anything else failed
        // in a way the JSON does not say.
        assert_eq!(
            broken(read(Some(101), UNUSED_DENY).0).kind,
            BrokenKind::NoFinding
        );
    }

    #[test]
    fn a_yanked_ignore_is_not_read_as_unused_when_a_registry_could_not_be_asked() {
        // The entry may be for the crate cargo-deny could not look up.
        let run = format!("{}\n{UNUSED_DENY}", first(INDEX_FAILURE));
        assert_eq!(read(Some(1), &run).1, [ignore("RUSTSEC-2020-0001", true)]);
    }

    #[test]
    fn a_registry_that_could_not_be_asked_does_not_excuse_a_failed_run() {
        // The yanked entry is unused at warning level, which fails no run,
        // so something else did.
        let denied = r#""message":"yanked crate was not encountered","severity":"error""#;
        assert!(INDEX_FAILURE.contains(denied), "got: {INDEX_FAILURE}");
        let run = INDEX_FAILURE.replace(denied, &denied.replace("error", "warning"));
        assert_eq!(broken(read(Some(1), &run).0).kind, BrokenKind::NoFinding);
    }

    #[test]
    fn a_run_failed_only_by_a_yanked_ignore_it_could_not_check_reads_as_clean() {
        assert_eq!(read(Some(1), INDEX_FAILURE), (TreeResult::Clean, vec![]));
    }

    #[test]
    fn unused_ignores_at_warning_level_are_read_with_their_entries() {
        assert_eq!(
            unused_in(UNUSED_WARN),
            [
                ignore("RUSTSEC-2020-0001", false),
                ignore("RUSTSEC-2021-0003", false),
            ]
        );
    }

    #[test]
    fn denied_unused_ignores_are_read_with_an_advisory_id_and_a_yanked_crate() {
        assert_eq!(
            unused_in(UNUSED_DENY),
            [
                ignore("RUSTSEC-2020-0001", true),
                ignore("smallvec@1.4.0", true),
            ]
        );
    }

    #[test]
    fn an_unused_ignore_diagnostic_without_a_span_is_a_message() {
        let bare = first(UNUSED_DENY).replace(r#""span":"RUSTSEC-2020-0001""#, r#""x":1"#);
        let summary = UNUSED_DENY.lines().last().expect("fixture has a summary");
        let (result, unused) = read(Some(1), &format!("{bare}\n{summary}"));
        assert_eq!(
            (broken(result).messages, unused),
            (vec![ADVISORY_NOT_DETECTED.to_string()], vec![])
        );
    }

    #[test]
    fn a_run_with_no_unused_ignores_reads_none() {
        assert_eq!(unused_in(TWO), []);
    }

    #[test]
    fn a_config_error_is_broken_without_a_summary() {
        let b = broken(classify(Some(1), CONFIG_ERROR));
        assert_eq!((b.kind, b.exit), (BrokenKind::NoSummary, Some(1)));
    }

    #[test]
    fn a_config_error_names_the_misspelt_key_diagnostic_and_the_file() {
        // The fixture's config was `bad.toml` (tests/fixtures/deny/README.md).
        let b = broken(classify(Some(1), CONFIG_ERROR));
        assert!(
            b.messages[0].starts_with("error[unexpected-keys]: found 1 unexpected keys"),
            "got {:?}",
            b.messages
        );
        assert!(
            b.messages[1].ends_with("/bad.toml'"),
            "got {:?}",
            b.messages
        );
    }

    #[test]
    fn a_stale_lock_under_locked_is_broken_and_says_why() {
        let b = broken(classify(Some(1), STALE_LOCK));
        let says_locked = b
            .messages
            .iter()
            .any(|m| m.contains("because --locked was passed"));
        assert_eq!(
            (b.kind, says_locked),
            (BrokenKind::NoSummary, true),
            "got {:?}",
            b.messages
        );
    }

    #[test]
    fn a_bad_manifest_path_is_broken_without_a_summary() {
        let b = broken(classify(Some(1), MISSING_MANIFEST));
        assert_eq!(b.kind, BrokenKind::NoSummary);
    }

    #[test]
    fn a_run_that_exits_zero_without_a_summary_is_broken_not_clean() {
        // A cargo-deny that renamed or dropped its summary line would
        // otherwise pass every tree.
        let b = broken(classify(Some(0), ""));
        assert_eq!((b.kind, b.exit), (BrokenKind::NoSummary, Some(0)));
    }

    #[test]
    fn findings_without_a_summary_are_broken() {
        // A run killed part way has reported some of its advisories and
        // not others, so its findings are not the whole answer.
        let truncated: String = TWO.lines().take(1).collect();
        let b = broken(classify(None, &truncated));
        assert_eq!((b.kind, b.exit), (BrokenKind::NoSummary, None));
    }

    #[test]
    fn a_line_that_is_not_json_is_kept_as_a_message() {
        let usage = "error: unexpected argument '--db-path' found";
        assert_eq!(broken(classify(Some(2), usage)).messages, [usage]);
    }

    #[test]
    fn only_error_level_log_lines_are_kept_as_messages() {
        let warn = r#"{"fields":{"level":"WARN","message":"advisory database is stale","timestamp":"t"},"type":"log"}"#;
        let output = format!("{warn}\n{MISSING_MANIFEST}");
        assert_eq!(
            broken(classify(Some(1), &output)).messages,
            ["[ERROR] --manifest-path must point to a Cargo.toml file"]
        );
    }

    #[test]
    fn a_warning_level_diagnostic_is_not_a_finding() {
        // At the default `yanked = "warn"`, cargo-deny still reports the
        // crate. Exit 1 here stands for some other error failing the run.
        let warned = YANKED.replace(r#""severity":"error""#, r#""severity":"warning""#);
        assert_eq!(
            broken(classify(Some(1), &warned)).kind,
            BrokenKind::NoFinding
        );
    }

    fn drawn(graph: &str) -> Vec<String> {
        let mut out = Vec::new();
        graph_lines(
            &serde_json::from_str(graph).unwrap(),
            &mut Vec::new(),
            &mut out,
        );
        out
    }

    // The expected drawings follow `write_graph_as_text` in cargo-deny
    // 0.20.2's src/diag/grapher.rs, as its human output prints a graph
    // note (first line behind `├ `, later lines indented two).

    #[test]
    fn a_crate_with_two_dependents_draws_a_tee_then_an_ell_with_a_rule_between() {
        let graph = r#"{"Krate":{"name":"x","version":"1.0.0"},"parents":[
            {"Krate":{"name":"a","version":"1.0.0"},"parents":[{"Krate":{"name":"w","version":"0.1.0"}}]},
            {"Krate":{"name":"b","version":"1.0.0"}}]}"#;
        assert_eq!(
            drawn(graph),
            [
                "├ x v1.0.0",
                "  ├── a v1.0.0",
                "  │   └── w v0.1.0",
                "  └── b v1.0.0"
            ]
        );
    }

    #[test]
    fn a_feature_node_a_dependency_kind_and_a_repeat_are_drawn_as_cargo_deny_draws_them() {
        let graph = r#"{"Krate":{"name":"a","version":"1.0.0"},"parents":[
            {"Feature":{"crate_name":"b","name":"std"},"parents":[{"Krate":{"name":"c","version":"2.0.0","kind":"dev"},"repeat":true}]}]}"#;
        assert_eq!(
            drawn(graph),
            [
                "├ a v1.0.0",
                "  └── b feature 'std'",
                "      └── (dev) c v2.0.0 (*)"
            ]
        );
    }

    #[test]
    fn a_section_starts_with_the_heading_naming_the_lockfile() {
        let text = section("fuzz/Cargo.lock", &found(classify(Some(1), TWO)));
        assert_eq!(
            text.lines().next(),
            Some("## cargo deny check advisories (fuzz/Cargo.lock)")
        );
    }

    #[test]
    fn a_heading_reads_back_to_its_lockfile_and_no_other_line_does() {
        assert_eq!(
            [
                lockfile_of(&heading("naïve (old)/Cargo.lock")),
                lockfile_of("## Alternatives to consider"),
                lockfile_of("## cargo deny check advisories (Cargo.lock"),
            ],
            [Some("naïve (old)/Cargo.lock"), None, None]
        );
    }

    #[test]
    fn a_section_shows_each_finding_by_headline_and_id_line() {
        let text = section("fuzz/Cargo.lock", &found(classify(Some(1), TWO)));
        let lines: Vec<&str> = text.lines().collect();
        for want in [
            "error[unmaintained]: Bincode is unmaintained",
            "   ├ ID: RUSTSEC-2025-0141",
            "error[vulnerability]: Buffer overflow in SmallVec::insert_many",
            "   ├ ID: RUSTSEC-2021-0003",
            "   ├ smallvec v1.6.0",
        ] {
            assert!(lines.contains(&want), "missing line {want:?} in:\n{text}");
        }
    }

    fn noted(note: &str) -> String {
        section(
            "Cargo.lock",
            &[Finding {
                code: "unmaintained".into(),
                id: Some("RUSTSEC-2025-0141".into()),
                message: "t".into(),
                notes: vec![note.into()],
                graph: vec![],
            }],
        )
    }

    #[test]
    fn a_later_line_of_a_note_cannot_pass_for_an_id_line() {
        let text = noted("It supersedes\nRUSTSEC-2020-0071");
        assert!(text.contains("\n   │ RUSTSEC-2020-0071\n"), "got:\n{text}");
    }

    #[test]
    fn a_blank_line_inside_a_note_keeps_its_rule_without_trailing_space() {
        let text = noted("one\n\ntwo");
        assert!(text.contains("\n   │\n"), "got:\n{text}");
    }
}
