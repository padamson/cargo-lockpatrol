# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

## [0.2.0] - 2026-11-11

### Added
- `check` names each `[advisories].ignore` entry that matches nothing in any tracked `Cargo.lock`: a warning by default, or an error that adds 4 to the exit code (4, or 5 beside a finding) when `deny.toml` sets `unused-ignored-advisory = "deny"`. When a tree broke, an entry the other trees leave unused is a warning only
- The action annotates the run with each stale entry, and has a `stale-ignore` output. As a monitor it files or closes its issue before it fails on a denied stale entry
- `check` writes `checking <lockfile>` to stderr as each tree's run starts, and that tree's lines as it ends, among them one for a clean tree such as `Cargo.lock: clean`. A passing run's log shows which lockfiles were checked, and a run that hangs shows which one it is on. The report on stdout stays empty
- The action shows `check`'s stderr as it comes, where it used to show it once the run ended
- `deny::read`, which reads a run as one tree of several: it returns the ignore entries the run matched nothing with beside its result, and a run that failed only on those is clean. `deny::classify` reads a run alone, as before

### Changed
- Under `unused-ignored-advisory = "deny"`, `check` no longer breaks on an entry that one tree leaves unused and another needs; only an entry that no tree uses fails it, with exit 4 or 5 where it was exit 2. Before, a shared entry failed every tree that did not need it. Before turning `deny` on, narrow every plain `cargo deny check` (a CI step, a hook, a dev command in a README or CLAUDE.md) to `cargo deny check bans licenses sources`: cargo-deny on its own reads one tree, and fails with `advisory-not-detected` on each ignore entry that tree does not use
- A line on cargo-deny's stderr that is not JSON no longer breaks a run that failed only on unused ignore entries
- Every line of a cargo-deny message that runs to several lines is indented on stderr, so cargo's own `error:` lines are not annotated by the action
- `check` runs cargo-deny at `--log-level warn`, the level at which cargo-deny reports an unused ignore by default

## [0.1.1] - 2026-11-09

### Fixed
- An issue body from the template's older scripts, which kept the report between `<!-- advisory-report -->` markers, is read from between the markers, so a code block in a triage note above them no longer reads as the report and announces every finding as new
- Triage notes kept beside the report in such a body move into a comment on the first run instead of being dropped with the old body
- A report too large for the issue body is no longer misread at its cut: the body now lists every finding's key in a hidden comment, so a finding that a resolution brings into view is no longer announced as new, and a new finding beyond the cut is announced. Past roughly 700 findings the list itself no longer fits, and the body is cut as before
- The monitor posts its comment before it edits the issue body, so a comment that fails is posted on the next run instead of never

## [0.1.0] - 2026-11-08

### Added
- `cargo lockpatrol check`, the advisory gate for every tracked `Cargo.lock`
- `cargo lockpatrol render`, which keeps a tracking issue's body current with `check`'s report
- A GitHub Action that runs `check` as a gate or as a monitor that keeps one tracking issue current, using a release binary it verifies first
- Hooks for prek and pre-commit
- An agent skill: `npx skills add padamson/cargo-lockpatrol`
- Release archives for Linux (x86_64, aarch64; static, so any glibc), macOS (x86_64, aarch64) and Windows (x86_64), with build provenance, named so `cargo binstall` finds them

[Unreleased]: https://github.com/padamson/cargo-lockpatrol/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/padamson/cargo-lockpatrol/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/padamson/cargo-lockpatrol/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/padamson/cargo-lockpatrol/releases/tag/v0.1.0
