//! Turns an open tracking issue's body and a fresh `check` report into the
//! new body, and says whether watchers need telling.
//!
//! The body is rewritten whole on every run, so triage notes go in
//! comments. Findings are compared by identity, not text, so a finding
//! reported in different words (a retitled advisory, a new solution line)
//! only refreshes the body, and only a finding that came or went posts a
//! comment.
//!
//! ```
//! use cargo_lockpatrol::render::{render, Status};
//!
//! let report = "\
//! ## cargo deny check advisories (Cargo.lock)
//!
//! error[unmaintained]: Bincode is unmaintained
//!    ├ ID: RUSTSEC-2025-0141
//! ";
//! let opened = render("", report);
//! assert_eq!(opened.status, Status::Changed);
//! assert_eq!(render(&opened.body, report).status, Status::Unchanged);
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::deny;

const INTRO: &str = "\
An advisory that is not in `deny.toml`'s `[advisories].ignore` affects
one of this repository's tracked `Cargo.lock` files, so the next
`cargo lockpatrol check` will fail.

Triage each one:
- **Fix available**: bump the crate (`cargo update -p <crate>`, plus
  `--manifest-path` when the report names a lockfile outside the root),
  or bump the parent that pins it.
- **No fix, or blocked upstream**: accept the risk and add the
  `RUSTSEC-…` id to `deny.toml`'s ignore list, with a rationale. Every
  lockfile is checked against that one list.

This description is rewritten on every run, so an edit to it is lost.
Put triage notes in comments.

";

const FOOTER: &str =
    "\n\n_Maintained by [cargo-lockpatrol](https://github.com/padamson/cargo-lockpatrol)._\n";

/// GitHub refuses a body or comment over 65536 characters. This leaves
/// room for the fence and the run-log line.
const LIMIT: usize = 60000;

const CUT: &str = "(Cut to fit GitHub's size limit; the run log has the full report.)";

/// What makes two findings the same finding across runs: the lockfile
/// it is reported under, and its RustSec id, or its headline when it has
/// none (a yanked crate). An advisory retitled upstream is still the same
/// finding; one that newly affects a second lockfile is a new one.
///
/// `tree` is the lockfile its section's heading names. It is `None` for a
/// finding above any heading, as in a body written before reports named
/// their lockfiles.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    pub tree: Option<String>,
    pub id: String,
}

/// What an open issue needs after a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The findings changed: edit the body and post the comment.
    Changed,
    /// The same findings, reported differently: edit the body only.
    Refreshed,
    /// The body already carries this report: leave the issue alone.
    Unchanged,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Status::Changed => "changed",
            Status::Refreshed => "refreshed",
            Status::Unchanged => "unchanged",
        })
    }
}

/// The outcome of [`render`]: the new body, the findings that went away
/// and the findings that are new since the old body, each mapped to its
/// headline, and what the issue needs.
#[derive(Debug, PartialEq, Eq)]
pub struct Rendered {
    pub body: String,
    pub resolved: BTreeMap<Key, String>,
    pub new: BTreeMap<Key, String>,
    pub status: Status,
}

/// A diagnostic's first line, as `deny::section` writes it:
/// `error[code]: message`.
fn is_headline(line: &str) -> bool {
    line.strip_prefix("error[")
        .and_then(|rest| rest.split_once("]: "))
        .is_some_and(|(code, _)| {
            !code.is_empty() && code.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
        })
}

/// The RustSec id on an `├ ID:` line, or on a line that is the id alone
/// at the margin (as [`compact`] writes it). A line of a note's
/// description is indented, behind `│` in a report `check` wrote and
/// behind spaces in one the shell script wrote, so an id it names is never
/// read as the finding's.
fn id_line(line: &str) -> Option<&str> {
    let id = line.trim_start().strip_prefix("├ ID: ").unwrap_or(line);
    let b = id.as_bytes();
    let digits = |r: std::ops::Range<usize>| b[r].iter().all(u8::is_ascii_digit);
    (b.len() == 17
        && id.starts_with("RUSTSEC-")
        && digits(8..12)
        && b[12] == b'-'
        && digits(13..17))
    .then_some(id)
}

/// Each finding in `text` with its headline, in report order, the first
/// headline kept when a key repeats.
pub fn findings(text: &str) -> Vec<(Key, String)> {
    let mut diagnostics: Vec<(Option<&str>, Option<&str>, &str)> = Vec::new();
    let mut tree = None;
    for line in text.lines() {
        if let Some(lockfile) = deny::lockfile_of(line) {
            tree = Some(lockfile);
        } else if is_headline(line) {
            diagnostics.push((tree, None, line));
        } else if let (Some(last), Some(id)) = (diagnostics.last_mut(), id_line(line)) {
            last.1 = Some(id);
        }
    }
    let mut seen = BTreeSet::new();
    diagnostics
        .into_iter()
        .filter_map(|(tree, id, headline)| {
            let key = Key {
                tree: tree.map(str::to_owned),
                id: id.unwrap_or(headline).to_owned(),
            };
            seen.insert(key.clone()).then(|| (key, headline.to_owned()))
        })
        .collect()
}

/// The report inside a body this module wrote: its first fenced block.
/// [`fenced`] makes the fence longer than any backtick run inside, so the
/// first line that repeats it closes the block.
fn written_report(body: &str) -> Option<String> {
    let lines: Vec<&str> = body.split('\n').collect();
    lines.iter().enumerate().find_map(|(i, fence)| {
        if fence.len() < 3 || !fence.bytes().all(|b| b == b'`') {
            return None;
        }
        (i + 2..lines.len())
            .find(|&j| lines[j] == *fence)
            .map(|j| lines[i + 1..j].join("\n"))
    })
}

/// The headline to show beside a finding's id, or `None` when the
/// headline is the key (a yanked crate) and the id already shows it.
fn beside_id<'a>(key: &Key, headline: &'a str) -> Option<&'a str> {
    (key.id != headline).then_some(headline)
}

/// A shorter report holding only the findings, under their lockfile
/// headings, that [`findings`] reads back to the same keys. Each finding
/// is one item (a blank line, then its lines), so [`fit`] keeps or drops a
/// finding whole and never separates a headline from its id.
fn compact(report: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut tree: Option<String> = None;
    for (key, headline) in findings(report) {
        if key.tree != tree {
            tree = key.tree.clone();
            if let Some(lockfile) = &tree {
                let heading = deny::heading(lockfile);
                items.push(if items.is_empty() {
                    heading
                } else {
                    format!("\n{heading}")
                });
            }
        }
        items.push(match beside_id(&key, &headline) {
            Some(headline) => format!("\n{headline}\n{}", key.id),
            None => format!("\n{}", key.id),
        });
    }
    items
}

/// The leading items that fit in `room` characters, each counted with the
/// newline that will join it.
fn fit(items: &[String], room: usize) -> &[String] {
    let mut size = 0;
    let kept = items
        .iter()
        .take_while(|item| {
            size += item.chars().count() + 1;
            size <= room
        })
        .count();
    &items[..kept]
}

/// `text` in a code fence longer than any backtick run inside it.
/// Advisory text is community-authored, and a title that closed the fence
/// would render as markdown, @-mentions and all.
fn fenced(text: &str) -> String {
    let longest = text.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    let fence = "`".repeat((longest + 1).max(3));
    format!("{fence}\n{text}\n{fence}")
}

/// The fenced report in at most `room` characters. Past that, only the
/// findings are kept, so each one can still be matched next run.
fn section(report: &str, room: usize) -> String {
    let report = report.trim_end_matches('\n');
    if report.chars().count() <= room {
        return fenced(report);
    }
    let items = compact(report);
    let mut kept: Vec<&str> = fit(&items, room.saturating_sub(CUT.chars().count() + 2))
        .iter()
        .map(String::as_str)
        .collect();
    kept.extend(["", CUT]);
    fenced(&kept.join("\n"))
}

fn by_id(found: BTreeMap<Key, String>) -> BTreeMap<Key, String> {
    found
        .into_iter()
        .map(|(key, headline)| (Key { tree: None, ..key }, headline))
        .collect()
}

/// The new body for `report`, and how it differs from `old`, the open
/// issue's body (empty when there is none).
pub fn render(old: &str, report: &str) -> Rendered {
    // A body saved from GitHub's web editor has CRLF endings, and an
    // untouched report must still compare equal.
    let lf = |text: &str| text.replace("\r\n", "\n").replace('\r', "\n");
    let (old, report) = (lf(old), lf(report));
    let report = report.as_str();
    let room = LIMIT - INTRO.chars().count() - FOOTER.chars().count();
    let report_section = section(report, room);
    let body = format!("{INTRO}{report_section}{FOOTER}");
    // Text outside the old report's fence, such as a note someone added,
    // is not read for findings. A body with no fence has none.
    let mut was: BTreeMap<_, _> = findings(&written_report(&old).unwrap_or_default())
        .into_iter()
        .collect();
    let mut shown: BTreeMap<_, _> = findings(&report_section).into_iter().collect();
    let mut live: BTreeMap<_, _> = findings(report).into_iter().collect();
    // A body written before reports had lockfile headings has no lockfile
    // in its keys. Compare it by id alone, or the first run after it posts
    // a comment listing every finding as both new and resolved.
    if !was.is_empty() && was.keys().all(|k| k.tree.is_none()) {
        shown = by_id(shown);
        live = by_id(live);
    }
    // A finding is resolved only when it is gone from the full report, not
    // when the size cut left it out of the body. A finding is new when the
    // body shows it and the old body did not; one left out by the cut is
    // not counted, since nothing says whether the old body had it.
    let new: BTreeMap<_, _> = shown
        .into_iter()
        .filter(|(key, _)| !was.contains_key(key))
        .collect();
    was.retain(|key, _| !live.contains_key(key));
    let resolved = was;
    // An unchanged body has nothing new or resolved either: its report
    // reads back as the findings it shows, all of them live. Whitespace at
    // the very end is not compared, so a host that stores the body without
    // its last newline does not get it rewritten on every run.
    let status = if body.trim_end() == old.trim_end() {
        Status::Unchanged
    } else if resolved.is_empty() && new.is_empty() {
        Status::Refreshed
    } else {
        Status::Changed
    };
    Rendered {
        body,
        resolved,
        new,
        status,
    }
}

fn label(key: &Key, headline: &str) -> String {
    let text = match beside_id(key, headline) {
        Some(headline) => format!("{} ({headline})", key.id),
        None => key.id.clone(),
    };
    match &key.tree {
        Some(tree) => format!("{tree}: {text}"),
        None => text,
    }
}

fn listing(heading: &str, items: &BTreeMap<Key, String>) -> Vec<String> {
    if items.is_empty() {
        return Vec::new();
    }
    let lines: Vec<String> = items.iter().map(|(k, h)| label(k, h)).collect();
    let mut kept = fit(&lines, LIMIT / 2).to_vec();
    let left_out = lines.len() - kept.len();
    if left_out > 0 {
        kept.push(String::new());
        kept.push(format!("({left_out} more not shown)"));
    }
    vec![
        format!("{heading}:"),
        fenced(&kept.join("\n")),
        String::new(),
    ]
}

/// The comment for a [`Status::Changed`] issue: the findings that came and
/// went, and a link to the run log when `run_url` is given. It names the
/// findings themselves, since a run log expires after 90 days.
pub fn comment(
    resolved: &BTreeMap<Key, String>,
    new: &BTreeMap<Key, String>,
    run_url: Option<&str>,
) -> String {
    let mut lines = vec!["The advisory findings changed.".to_string(), String::new()];
    lines.extend(listing("New", new));
    lines.extend(listing("Resolved", resolved));
    lines.push(run_url.map_or_else(String::new, |url| {
        format!("The issue body has the new report, and [the run log]({url}) has it in full.")
    }));
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::deny::{Finding, TreeResult};
    use crate::fixtures::{TWO, UNMAINTAINED, YANKED};

    const VULNERABILITY_ID: &str = "RUSTSEC-2021-0003";
    const UNMAINTAINED_ID: &str = "RUSTSEC-2025-0141";

    /// The report `check` writes for these trees, each a lockfile and the
    /// cargo-deny run captured for it.
    fn report(trees: &[(&str, &str)]) -> String {
        let results: Vec<_> = trees
            .iter()
            .map(|(lockfile, run)| (PathBuf::from(lockfile), deny::classify(Some(1), run)))
            .collect();
        let mut out = Vec::new();
        crate::check::write_report(&results, &mut out, &mut std::io::sink())
            .expect("write to a Vec");
        String::from_utf8(out).expect("the report is UTF-8")
    }

    fn key(lockfile: &str, id: &str) -> Key {
        Key {
            tree: Some(lockfile.to_owned()),
            id: id.to_owned(),
        }
    }

    fn keys(found: &BTreeMap<Key, String>) -> Vec<Key> {
        found.keys().cloned().collect()
    }

    fn keys_of(text: &str) -> BTreeSet<Key> {
        findings(text).into_iter().map(|(k, _)| k).collect()
    }

    fn opened(report: &str) -> String {
        render("", report).body
    }

    const SCRIPT_REPORT: &str = include_str!("../tests/fixtures/render/script-report.txt");
    const SCRIPT_BODY: &str = include_str!("../tests/fixtures/render/script-body.md");

    /// `n` findings of one advisory, each under its own lockfile, as a
    /// comment listing takes them.
    fn many_new(n: usize) -> BTreeMap<Key, String> {
        (0..n)
            .map(|i| {
                (
                    key(&format!("crates/c{i}/Cargo.lock"), UNMAINTAINED_ID),
                    String::new(),
                )
            })
            .collect()
    }

    /// `report` without its lockfile headings, as reports were before they
    /// named their lockfiles.
    fn headless(report: &str) -> String {
        report
            .lines()
            .filter(|l| deny::lockfile_of(l).is_none())
            .map(|l| format!("{l}\n"))
            .collect()
    }

    /// A body cut to fit, then a report with a new tree ahead of the rest,
    /// which pushes the last findings the body showed past the cut.
    fn new_finding_ahead_of_a_cut() -> Rendered {
        let enormous = many(2000);
        let more = format!("{}{enormous}", report(&[("crates/c0/Cargo.lock", TWO)]));
        render(&opened(&enormous), &more)
    }

    /// `n` trees with one finding each, under crates/c1/Cargo.lock onward.
    fn many(n: usize) -> String {
        let lockfiles: Vec<String> = (1..=n).map(|i| format!("crates/c{i}/Cargo.lock")).collect();
        let trees: Vec<_> = lockfiles
            .iter()
            .map(|l| (l.as_str(), UNMAINTAINED))
            .collect();
        report(&trees)
    }

    #[test]
    fn every_finding_check_writes_reads_back_under_its_lockfile_by_id_or_headline() {
        let r = report(&[("Cargo.lock", TWO), ("fuzz/Cargo.lock", YANKED)]);
        let yanked = match deny::classify(Some(1), YANKED) {
            TreeResult::Found { findings, .. } => findings[0].headline(),
            other => panic!("expected a finding, got {other:?}"),
        };
        assert_eq!(
            keys_of(&r),
            BTreeSet::from([
                key("Cargo.lock", UNMAINTAINED_ID),
                key("Cargo.lock", VULNERABILITY_ID),
                key("fuzz/Cargo.lock", &yanked),
            ])
        );
    }

    #[test]
    fn the_shell_scripts_report_reads_as_the_findings_check_reports() {
        assert_eq!(
            keys_of(SCRIPT_REPORT),
            keys_of(&report(&[("Cargo.lock", TWO)]))
        );
    }

    #[test]
    fn the_report_in_a_body_the_shell_script_wrote_reads_as_its_findings() {
        let written = written_report(SCRIPT_BODY).expect("the body holds a fenced report");
        assert_eq!(keys_of(&written), keys_of(SCRIPT_REPORT));
    }

    #[test]
    fn a_body_the_shell_script_wrote_refreshes_on_the_same_findings() {
        let rendered = render(SCRIPT_BODY, &report(&[("Cargo.lock", TWO)]));
        assert_eq!(rendered.status, Status::Refreshed, "{rendered:?}");
    }

    #[test]
    fn a_first_report_lists_every_finding_as_new() {
        let rendered = render("", &report(&[("Cargo.lock", TWO)]));
        assert_eq!(
            (
                rendered.status,
                keys(&rendered.new),
                keys(&rendered.resolved)
            ),
            (
                Status::Changed,
                vec![
                    key("Cargo.lock", VULNERABILITY_ID),
                    key("Cargo.lock", UNMAINTAINED_ID)
                ],
                vec![]
            )
        );
    }

    #[test]
    fn the_body_opens_with_the_triage_steps() {
        let body = opened(&report(&[("Cargo.lock", UNMAINTAINED)]));
        assert!(body.starts_with(INTRO), "{body}");
    }

    #[test]
    fn the_report_reads_back_whole_from_the_body() {
        let r = report(&[("Cargo.lock", UNMAINTAINED)]);
        assert_eq!(written_report(&opened(&r)), Some(r.trim_end().to_owned()));
    }

    #[test]
    fn the_same_report_leaves_the_issue_alone() {
        let r = report(&[("Cargo.lock", UNMAINTAINED)]);
        let old = opened(&r);
        assert_eq!(
            render(&old, &r),
            Rendered {
                body: old,
                resolved: BTreeMap::new(),
                new: BTreeMap::new(),
                status: Status::Unchanged
            }
        );
    }

    #[test]
    fn a_body_saved_with_crlf_endings_is_still_unchanged() {
        let r = report(&[("Cargo.lock", UNMAINTAINED)]);
        let old = opened(&r).replace('\n', "\r\n");
        assert_eq!(render(&old, &r).status, Status::Unchanged);
    }

    #[test]
    fn a_report_with_crlf_endings_reads_like_one_without() {
        let r = report(&[("Cargo.lock", UNMAINTAINED)]);
        assert_eq!(
            render(&opened(&r), &r.replace('\n', "\r\n")).status,
            Status::Unchanged
        );
    }

    #[test]
    fn a_body_that_differs_only_in_trailing_whitespace_is_still_unchanged() {
        let r = report(&[("Cargo.lock", UNMAINTAINED)]);
        let body = opened(&r);
        assert_eq!(
            [body.trim_end().to_owned(), format!("{body}\n \n")].map(|old| render(&old, &r).status),
            [Status::Unchanged; 2]
        );
    }

    #[test]
    fn a_finding_reported_in_other_words_refreshes_without_a_comment() {
        let r = report(&[("Cargo.lock", UNMAINTAINED)]);
        let reworded = r.replace("No safe upgrade is available!", "Use wincode.");
        assert_ne!(reworded, r);
        let rendered = render(&opened(&r), &reworded);
        assert_eq!(
            (rendered.status, rendered.body.contains("Use wincode.")),
            (Status::Refreshed, true)
        );
    }

    #[test]
    fn a_retitled_advisory_refreshes_without_a_comment() {
        let r = report(&[("Cargo.lock", UNMAINTAINED)]);
        let retitled = r.replace("Bincode is unmaintained", "Bincode is no longer maintained");
        assert_ne!(retitled, r);
        let rendered = render(&opened(&r), &retitled);
        assert_eq!(
            (
                rendered.status,
                rendered.body.contains("Bincode is no longer maintained")
            ),
            (Status::Refreshed, true)
        );
    }

    #[test]
    fn an_id_alone_on_a_description_line_is_not_the_findings_id() {
        let finding = Finding {
            code: "unmaintained".into(),
            id: Some(UNMAINTAINED_ID.into()),
            message: "Bincode is unmaintained".into(),
            notes: vec![
                format!("ID: {UNMAINTAINED_ID}"),
                "It is superseded by\nRUSTSEC-2020-0071".into(),
            ],
            graph: vec![],
        };
        let section = deny::section("Cargo.lock", &[finding]);
        assert_eq!(
            keys_of(&section),
            BTreeSet::from([key("Cargo.lock", UNMAINTAINED_ID)]),
            "{section}"
        );
    }

    #[test]
    fn a_fixed_yanked_crate_is_resolved_by_its_headline() {
        let yanked = report(&[("Cargo.lock", YANKED)]);
        let rendered = render(&opened(&yanked), &report(&[("Cargo.lock", UNMAINTAINED)]));
        assert_eq!(
            (rendered.status, keys(&rendered.resolved)),
            (
                Status::Changed,
                keys_of(&yanked).into_iter().collect::<Vec<_>>()
            )
        );
    }

    #[test]
    fn a_new_finding_is_new() {
        let old = opened(&report(&[("Cargo.lock", UNMAINTAINED)]));
        let rendered = render(&old, &report(&[("Cargo.lock", TWO)]));
        assert_eq!(
            (
                rendered.status,
                keys(&rendered.new),
                keys(&rendered.resolved)
            ),
            (
                Status::Changed,
                vec![key("Cargo.lock", VULNERABILITY_ID)],
                vec![]
            )
        );
    }

    #[test]
    fn a_finding_that_went_away_is_resolved() {
        let old = opened(&report(&[("Cargo.lock", TWO)]));
        let rendered = render(&old, &report(&[("Cargo.lock", UNMAINTAINED)]));
        assert_eq!(
            (
                rendered.status,
                keys(&rendered.resolved),
                keys(&rendered.new)
            ),
            (
                Status::Changed,
                vec![key("Cargo.lock", VULNERABILITY_ID)],
                vec![]
            )
        );
    }

    #[test]
    fn a_known_advisory_reaching_another_lockfile_is_new_there() {
        let old = opened(&report(&[("Cargo.lock", TWO)]));
        let spread = report(&[("Cargo.lock", TWO), ("fuzz/Cargo.lock", TWO)]);
        let rendered = render(&old, &spread);
        assert_eq!(
            keys(&rendered.new),
            [
                key("fuzz/Cargo.lock", VULNERABILITY_ID),
                key("fuzz/Cargo.lock", UNMAINTAINED_ID)
            ]
        );
    }

    fn fenced_title() -> String {
        report(&[("Cargo.lock", UNMAINTAINED)])
            .replace("Bincode is unmaintained", "Bincode ``` is unmaintained")
    }

    #[test]
    fn a_fence_in_an_advisory_title_gets_a_longer_fence_around_the_report() {
        let body = opened(&fenced_title());
        assert_eq!(body.lines().find(|l| l.starts_with("```")), Some("````"));
    }

    #[test]
    fn a_report_holding_a_fence_reads_back_whole() {
        let r = fenced_title();
        assert_eq!(written_report(&opened(&r)), Some(r.trim_end().to_owned()));
    }

    #[test]
    fn a_body_from_before_lockfile_headings_with_the_same_findings_refreshes() {
        let r = report(&[("Cargo.lock", TWO)]);
        let rendered = render(&opened(&headless(&r)), &r);
        assert_eq!(rendered.status, Status::Refreshed, "{rendered:?}");
    }

    #[test]
    fn a_body_from_before_lockfile_headings_still_sees_a_new_finding() {
        let unmaintained = headless(&report(&[("Cargo.lock", UNMAINTAINED)]));
        let rendered = render(&opened(&unmaintained), &report(&[("Cargo.lock", TWO)]));
        assert_eq!(
            keys(&rendered.new),
            [Key {
                tree: None,
                id: VULNERABILITY_ID.into()
            }]
        );
    }

    #[test]
    fn an_oversized_report_keeps_every_finding_under_its_lockfile() {
        let huge = many(400);
        let body = opened(&huge);
        assert_eq!(
            (body.contains(CUT), keys_of(&body)),
            (true, keys_of(&huge)),
            "{} characters",
            huge.len()
        );
    }

    #[test]
    fn an_oversized_report_with_the_same_findings_leaves_the_issue_alone() {
        let huge = many(400);
        let reworded = huge.replace("No safe upgrade is available!", "Use wincode.");
        assert_ne!(reworded, huge);
        assert_eq!(render(&opened(&huge), &reworded).status, Status::Unchanged);
    }

    #[test]
    fn a_body_edited_by_hand_is_rewritten_whole() {
        let r = report(&[("Cargo.lock", UNMAINTAINED)]);
        let noted = format!("{}\nA note.\n", opened(&r));
        assert_eq!(render(&noted, &r).body, opened(&r));
    }

    #[test]
    fn a_finding_pasted_below_the_report_is_not_read() {
        let r = report(&[("Cargo.lock", UNMAINTAINED)]);
        let pasted = report(&[("Cargo.lock", TWO)]);
        let noted = format!("{}\nPasted from the log:\n{pasted}", opened(&r));
        assert_eq!(render(&noted, &r).status, Status::Refreshed);
    }

    #[test]
    fn a_body_with_no_report_gains_one_with_every_finding_new() {
        let r = report(&[("Cargo.lock", UNMAINTAINED)]);
        let rendered = render("Hand-written body with no report.\n", &r);
        assert_eq!(
            (rendered.status, keys(&rendered.new)),
            (Status::Changed, vec![key("Cargo.lock", UNMAINTAINED_ID)])
        );
    }

    #[test]
    fn findings_past_the_limit_are_cut_and_the_cut_says_so() {
        assert!(opened(&many(2000)).contains(CUT));
    }

    // The budget is LIMIT for the intro, the report and the footer; the
    // two three-backtick fences and their newlines add 8. GitHub's own
    // limit, 65536, is further off still.
    #[test]
    fn a_cut_body_stays_within_its_budget() {
        let size = opened(&many(2000)).chars().count();
        assert!(size <= LIMIT + 8, "{size} characters");
    }

    #[test]
    fn fit_keeps_the_items_whose_lengths_and_newlines_fit() {
        let items = ["ab".to_owned(), "cd".to_owned()];
        assert_eq!((fit(&items, 6).len(), fit(&items, 5).len()), (2, 1));
    }

    #[test]
    fn a_cut_keeps_every_finding_that_fits_beside_the_notice_and_no_more() {
        let r = report(&[("Cargo.lock", TWO), ("fuzz/Cargo.lock", TWO)]);
        let items = compact(&r);
        let all: usize = items.iter().map(|i| i.chars().count() + 1).sum();
        let room = all + CUT.chars().count() + 2;
        let kept = |room| keys_of(&section(&r, room)).len();
        assert_eq!((kept(room), kept(room - 1)), (4, 3));
    }

    #[test]
    fn a_new_finding_ahead_of_the_cut_is_new() {
        let rendered = new_finding_ahead_of_a_cut();
        assert_eq!(
            keys(&rendered.new),
            [
                key("crates/c0/Cargo.lock", VULNERABILITY_ID),
                key("crates/c0/Cargo.lock", UNMAINTAINED_ID)
            ]
        );
    }

    #[test]
    fn findings_pushed_past_the_cut_are_not_resolved() {
        let rendered = new_finding_ahead_of_a_cut();
        assert_eq!(keys(&rendered.resolved), vec![]);
    }

    // Wherever the size cut falls, it keeps or drops each finding whole
    // (headline and id together): a headline kept without its id reads as
    // a new finding and posts a comment.
    #[test]
    fn no_cut_point_shows_a_finding_the_full_report_lacks() {
        for r in [
            report(&[("Cargo.lock", TWO), ("fuzz/Cargo.lock", TWO)]),
            report(&[("Cargo.lock", YANKED)]),
        ] {
            let live = keys_of(&r);
            let bad: Vec<usize> = (0..r.chars().count())
                .filter(|&room| !keys_of(&section(&r, room)).is_subset(&live))
                .collect();
            assert_eq!(
                bad,
                Vec::<usize>::new(),
                "rooms that split a finding in\n{r}"
            );
        }
    }

    #[test]
    fn a_fence_is_one_longer_than_the_longest_backtick_run_and_at_least_three() {
        assert_eq!(
            (fenced("a ```` b"), fenced("a ` b")),
            (
                "`````\na ```` b\n`````".to_owned(),
                "```\na ` b\n```".to_owned()
            )
        );
    }

    #[test]
    fn a_headline_names_a_lowercase_code_in_brackets() {
        assert_eq!(
            [
                "error[vulnerability]: x",
                "error[unused-ignore]: x",
                "error[]: x",
                "error[Vuln]: x",
                "error[vulnerability] x",
                " error[vulnerability]: x",
            ]
            .map(is_headline),
            [true, true, false, false, false, false]
        );
    }

    #[test]
    fn an_id_line_is_the_id_alone_or_after_the_id_note() {
        assert_eq!(
            [
                "   ├ ID: RUSTSEC-2021-0003",
                "RUSTSEC-2021-0003",
                "    RUSTSEC-2021-0003",
                "   │ RUSTSEC-2021-0003",
                "   ├ ID: RUSTSEC-2021-0003 (withdrawn)",
                "   ├ ID: RUSTSEC-2021-003",
                "   ├ ID: RUSTSEC-2021_0003",
                "   ├ ID: RUSTSEC-202a-0003",
                "   ├ ID: RUSTSEC-2021-000a",
                "   ├ ID: RUSTSEX-2021-0003",
            ]
            .map(id_line),
            [
                Some("RUSTSEC-2021-0003"),
                Some("RUSTSEC-2021-0003"),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None
            ]
        );
    }

    #[test]
    fn the_report_in_a_body_closes_at_the_first_line_repeating_its_fence() {
        assert_eq!(
            written_report("intro\n````\n```\nin\n````\nafter\n````\n"),
            Some("```\nin".to_owned())
        );
    }

    #[test]
    fn a_body_with_an_unclosed_fence_has_no_report() {
        assert_eq!(written_report("intro\n```\nnever closed\n"), None);
    }

    #[test]
    fn the_comment_lists_each_finding_by_lockfile_and_id_under_new_or_resolved() {
        let new = BTreeMap::from([(
            key("fuzz/Cargo.lock", VULNERABILITY_ID),
            "error[vulnerability]: Buffer overflow".to_owned(),
        )]);
        let yanked = "error[yanked]: detected yanked crate".to_owned();
        let resolved = BTreeMap::from([(key("Cargo.lock", &yanked), yanked.clone())]);
        let c = comment(&resolved, &new, None);
        let listed =
            |heading: &str, label: &str| c.contains(&format!("{heading}:\n```\n{label}\n```\n"));
        assert_eq!(
            (
                listed(
                    "New",
                    "fuzz/Cargo.lock: RUSTSEC-2021-0003 \
                     (error[vulnerability]: Buffer overflow)"
                ),
                listed(
                    "Resolved",
                    "Cargo.lock: error[yanked]: detected yanked crate"
                ),
            ),
            (true, true),
            "{c}"
        );
    }

    #[test]
    fn the_comment_links_the_run_log_when_given_one() {
        let c = comment(
            &BTreeMap::new(),
            &BTreeMap::new(),
            Some("https://example.invalid/run"),
        );
        assert!(
            c.ends_with("[the run log](https://example.invalid/run) has it in full."),
            "{c}"
        );
    }

    #[test]
    fn a_long_listing_says_how_many_it_left_out() {
        let c = comment(&BTreeMap::new(), &many_new(2000), None);
        let shown = c.lines().filter(|l| l.contains(UNMAINTAINED_ID)).count();
        let note = format!("({} more not shown)", 2000 - shown);
        assert_eq!((shown > 0, c.contains(&note)), (true, true), "{note}\n{c}");
    }

    #[test]
    fn a_long_listing_fills_half_the_limit_and_no_more() {
        let new = many_new(2000);
        let longest = new
            .iter()
            .map(|(k, h)| label(k, h).chars().count() + 1)
            .max()
            .unwrap_or(0);
        let listed =
            written_report(&comment(&BTreeMap::new(), &new, None)).expect("a fenced listing");
        let size: usize = listed
            .lines()
            .filter(|l| l.contains(UNMAINTAINED_ID))
            .map(|l| l.chars().count() + 1)
            .sum();
        assert!(
            LIMIT / 2 - longest < size && size <= LIMIT / 2,
            "{size} characters listed"
        );
    }

    #[test]
    fn a_comment_lists_new_before_resolved_each_in_lockfile_order() {
        let entry = |lockfile: &str, id: &str| (key(lockfile, id), id.to_owned());
        let new = BTreeMap::from([
            entry("fuzz/Cargo.lock", VULNERABILITY_ID),
            entry("Cargo.lock", VULNERABILITY_ID),
        ]);
        let resolved = BTreeMap::from([entry("Cargo.lock", UNMAINTAINED_ID)]);
        let c = comment(&resolved, &new, None);
        let order: Vec<&str> = c
            .lines()
            .filter(|l| l.contains("RUSTSEC-") || l.ends_with(':'))
            .collect();
        assert_eq!(
            order,
            [
                "New:",
                "Cargo.lock: RUSTSEC-2021-0003",
                "fuzz/Cargo.lock: RUSTSEC-2021-0003",
                "Resolved:",
                "Cargo.lock: RUSTSEC-2025-0141",
            ]
        );
    }
}
