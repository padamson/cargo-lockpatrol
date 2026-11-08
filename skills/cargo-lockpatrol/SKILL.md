---
name: cargo-lockpatrol
description: Use when a repo checks RustSec advisories with cargo-deny through cargo-lockpatrol, or is replacing copied scripts/check-advisories.sh and advisory-monitor.yml with its GitHub Action and pre-commit hook; covers the check exit codes, pinning the action and hook by SHA, and the tracking issue.
license: MIT OR Apache-2.0
metadata:
  version: "1.0.1"
---

# cargo-lockpatrol

`cargo lockpatrol check` runs `cargo deny check advisories` on every
`Cargo.lock` git tracks (the root and any nested tree, such as `fuzz/`),
all against the root `deny.toml`, and exits 0 clean, 1 an advisory, 2 the
check itself broke (an advisory-database fetch, a missing or bad
`deny.toml`, a lock that disagrees with its manifests), or 3 both.
cargo-deny must be on `PATH`; cargo-lockpatrol never installs it, and a
version older than the 0.20.2 its tests pin reads as broken, never as clean.

It reaches a repo three ways, all released under one tag:

- **The GitHub Action**, as a gate (the step fails on 1, 2 or 3) or, with
  `issue: "true"`, as a scheduled monitor that keeps one tracking issue
  current and fails only on a broken check.
- **The prek or pre-commit hook**, `cargo-lockpatrol` (builds the binary at
  the pinned rev) or `cargo-lockpatrol-system` (runs one on `PATH`).
- **The binary**, `cargo install cargo-lockpatrol` or `cargo binstall
  cargo-lockpatrol`.

## Doing it right

- **Pin a release tag's commit by SHA, with the tag as a comment**: `uses:
  padamson/cargo-lockpatrol@<sha>  # vX.Y.Z` and `rev: <sha>  # frozen:
  vX.Y.Z`. The action runs the release named in its own `Cargo.toml` at
  that commit. A commit between releases names the previous release, so
  its `action.yml` can pass that older binary a flag it does not know, and
  the check reports broken.
- **Run the monitor on `schedule` and `workflow_dispatch` only**, with a
  `concurrency` group and `cancel-in-progress: false`. Never trigger it
  from `issues` or `issue_comment`: every issue event would run a full
  check, and with a PAT or App token as `github-token` its own edits would
  start it again.
- **Ignore an advisory in `deny.toml`**, `[advisories].ignore`, with a
  `reason`. It is the one list for every tree, the gate, the hook and the
  monitor.
- **Read exit 2 as broken, not as an advisory.** The reason is on stderr
  (the step log in CI), not in the report: a network failure or a stale
  `Cargo.lock` is fixed differently from a vulnerable dependency.
- **Put triage in issue comments.** The monitor rewrites the issue body on
  every run that changes it.

## Replacing the template's copied scripts

A repo made from `rust-project-template` carries
`scripts/check-advisories.sh`, `scripts/advisory-issue-body.py`,
`scripts/test-check-advisories.sh`, `advisory-monitor.yml` and two advisory
hooks. The scripts never passed `--locked`; cargo-lockpatrol defaults to
`root`, so a root `Cargo.lock` that disagrees with its manifests becomes a
broken check (exit 2). Commit a refreshed lock first, or pass `locked:
none` (`args: [--locked, none]` for the hook) to keep the old behavior.
Then switch in one change:

1. In `advisory-monitor.yml`, keep the checkout and the Rust and
   cargo-deny installs, and replace every step after them (check, find,
   update, close, and "Fail on a broken check") with the action and
   `issue: "true"`. Drop the job's `GH_TOKEN`, `ISSUE_TITLE` and
   `ISSUE_LABEL` env; keep `issues: write`, the schedule and the
   concurrency group. The default `issue-title` and `issue-label` match
   the script's, so the open issue is found, and its body is read as the
   same findings: the first run only refreshes it.
2. In the Security workflow, replace `scripts/check-advisories.sh` with the
   action as a gate, after the same cargo-deny install.
3. In `.pre-commit-config.yaml`, replace the `cargo-deny-advisories` and
   `advisory-checker-classifies-output` hooks with the `cargo-lockpatrol`
   hook from `https://github.com/padamson/cargo-lockpatrol`.
4. In the Test workflow, remove the step that runs
   `scripts/test-check-advisories.sh`.
5. Delete the three scripts.

Inputs, outputs, flags and the hook ids are in
[`references/usage.md`](references/usage.md).
