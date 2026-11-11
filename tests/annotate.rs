// scripts/annotate.sh, which action.yml runs over `check`'s stderr. The
// tests run it with whatever `bash` is on PATH, so they run on Unix only.
#![cfg(unix)]

mod common;

use std::process::Command;

use common::Workspace;

/// What the script prints for a file holding `stderr`.
fn annotated(stderr: &str) -> String {
    let ws = Workspace::new();
    let file = ws.write("reasons.txt", stderr);
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/annotate.sh");
    let out = Command::new("bash")
        .arg(script)
        .arg(&file)
        .output()
        .expect("run bash");
    assert!(out.status.success(), "annotate.sh failed: {out:?}");
    String::from_utf8(out.stdout).expect("utf-8 output")
}

#[test]
fn a_warning_line_and_an_error_line_each_become_an_annotation() {
    assert_eq!(
        annotated("warning: deny.toml ignores A\nerror: deny.toml ignores B\n"),
        "::warning::deny.toml ignores A\n::error::deny.toml ignores B\n"
    );
}

#[test]
fn a_line_with_neither_prefix_is_not_annotated() {
    assert_eq!(
        annotated("{\"type\":\"summary\"}\n  warning: indented\nWarning: x\n"),
        ""
    );
}

#[test]
fn a_last_line_without_a_newline_is_annotated() {
    assert_eq!(annotated("warning: last"), "::warning::last\n");
}

#[test]
fn a_command_in_the_message_stays_in_the_message() {
    assert_eq!(
        annotated("warning: ::set-output name=x::y\n"),
        "::warning::::set-output name=x::y\n"
    );
}

// A runner that ends a line at a bare carriage return would read what
// follows it as a line of its own.
#[test]
fn a_carriage_return_cannot_start_a_second_line() {
    assert_eq!(
        annotated("warning: a\r::error::forged\n"),
        "::warning::a::error::forged\n"
    );
}
