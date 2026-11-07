// Template placeholder. Replace with integration tests for your crate.
//
// Integration tests live in `tests/` and exercise your crate as an
// external consumer would: only `pub` items are accessible. Each file
// here is compiled as a separate binary. Shared fixtures go in
// `tests/common/mod.rs`, once.

mod common;

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use common::{PollError, Workspace, poll_until};
use my_project::{DEFAULT_LARGE_THRESHOLD, Size, classify};

#[test]
fn a_file_with_enough_lines_classifies_as_large() {
    let ws = Workspace::new();
    let lines = "x\n".repeat(DEFAULT_LARGE_THRESHOLD as usize);
    let path = ws.write("items.txt", &lines);

    let count = std::fs::read_to_string(&path).unwrap().lines().count() as i64;

    assert_eq!(
        classify(count),
        Ok(Size::Large),
        "counted {count} lines in {}",
        path.display()
    );
}

#[test]
fn a_poll_stops_at_its_deadline_and_says_what_it_waited_for() {
    let result: Result<(), PollError<()>> = poll_until(
        "a value that never arrives",
        Duration::from_millis(60),
        || Ok(None),
    );

    match result {
        Err(PollError::Deadline { what, waited }) => {
            assert_eq!(what, "a value that never arrives");
            assert!(
                waited >= Duration::from_millis(60),
                "gave up early after {waited:?}"
            );
        }
        other => panic!("expected Deadline, got {other:?}"),
    }
}

#[test]
fn a_probe_error_fails_the_poll_immediately() {
    let result: Result<(), PollError<&str>> =
        poll_until("anything", Duration::from_secs(5), || {
            Err("driver went away")
        });

    assert!(
        matches!(result, Err(PollError::Probe("driver went away"))),
        "got {result:?}"
    );
}

// The shape for a test that needs something a fresh clone may not have
// (a tool, a service, real time). It is gated, never skipped: a missing
// precondition is a reason string on the attribute, and the lane that has
// the precondition runs it with `--run-ignored only`. A test that
// `return`s when the tool is missing reports a pass it did not earn.
#[test]
#[ignore = "waits on real time; run with: cargo nextest run --run-ignored only -E 'test(/^live_/)'"]
fn live_poll_sees_a_value_produced_on_another_thread() {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(50));
        tx.send(7).unwrap();
    });

    // `Empty` is "not yet"; `Disconnected` means the producer died and the
    // poll must fail now rather than wait out the deadline.
    let got = poll_until(
        "a value from the producer thread",
        Duration::from_secs(2),
        || match rx.try_recv() {
            Ok(v) => Ok(Some(v)),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(e @ mpsc::TryRecvError::Disconnected) => Err(e),
        },
    );

    assert!(matches!(got, Ok(7)), "got {got:?}");
}
