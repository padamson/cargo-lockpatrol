// `cargo-lockpatrol render` end to end: files in, files out, the status on
// stdout. What the body and comment say is unit-tested in src/render.rs;
// these pin the wiring the action relies on.

mod common;

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use common::{Workspace, shown};

const REPORT: &str = "## cargo deny check advisories (Cargo.lock)

error[unmaintained]: Bincode is unmaintained
   ├ ID: RUSTSEC-2025-0141
";

const RUN_URL: &str = "https://example.invalid/run";

/// `cargo-lockpatrol render` on `old`, the path of the old body, and
/// [`REPORT`], writing into `ws`, with any `extra` arguments.
fn render_in(ws: &Workspace, old: &Path, extra: &[&str]) -> Output {
    let report = ws.write("report.txt", REPORT);
    Command::new(env!("CARGO_BIN_EXE_cargo-lockpatrol"))
        .arg("render")
        .args([
            old,
            &report,
            &ws.root().join("body.md"),
            &ws.root().join("comment.md"),
        ])
        .args(extra)
        .output()
        .expect("run cargo-lockpatrol")
}

/// [`render_in`] a fresh workspace, with `old` as the old body.
fn render(old: &str, extra: &[&str]) -> (Output, Workspace) {
    let ws = Workspace::new();
    let old = ws.write("old.md", old);
    (render_in(&ws, &old, extra), ws)
}

fn read(ws: &Workspace, name: &str) -> String {
    fs::read_to_string(ws.root().join(name)).unwrap_or_else(|e| format!("<{name}: {e}>"))
}

#[test]
fn a_first_report_prints_changed_and_writes_a_body_holding_it() {
    let (out, ws) = render("", &[]);
    let body = read(&ws, "body.md");
    assert_eq!(
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).as_ref(),
            body.contains("├ ID: RUSTSEC-2025-0141")
        ),
        (Some(0), "changed\n", true),
        "{}\n--- body\n{body}",
        shown(&out)
    );
}

#[test]
fn the_body_written_reads_back_as_unchanged() {
    let (_, first) = render("", &[]);
    let (out, _) = render(&read(&first, "body.md"), &[]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "unchanged\n",
        "{}",
        shown(&out)
    );
}

#[test]
fn the_run_url_reaches_the_comment() {
    let (out, ws) = render("", &["--run-url", RUN_URL]);
    let comment = read(&ws, "comment.md");
    assert!(
        comment.contains(&format!("({RUN_URL})")),
        "{}\n--- comment\n{comment}",
        shown(&out)
    );
}

#[test]
fn a_missing_old_body_is_broken_and_named() {
    let ws = Workspace::new();
    let missing = ws.root().join("nope.md");
    let out = render_in(&ws, &missing, &[]);
    let names_it = String::from_utf8_lossy(&out.stderr).contains(&*missing.to_string_lossy());
    assert_eq!(
        (out.status.code(), names_it),
        (Some(2), true),
        "{}",
        shown(&out)
    );
}
