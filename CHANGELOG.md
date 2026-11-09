# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Fixed
- An issue body from the template's older scripts, which kept the report between `<!-- advisory-report -->` markers, is read from between the markers, so a code block in a triage note above them no longer reads as the report and announces every finding as new
- Triage notes kept beside the report in such a body move into a comment on the first run instead of being dropped with the old body
- A report too large for the issue body is no longer misread at its cut: the body now lists every finding's key in a hidden comment, so a finding that a resolution brings into view is no longer announced as new, and a new finding beyond the cut is announced. Past roughly 700 findings the list itself no longer fits, and the body is cut as before

## [0.1.0] - 2026-11-08

### Added
- `cargo lockpatrol check`, the advisory gate for every tracked `Cargo.lock`
- `cargo lockpatrol render`, which keeps a tracking issue's body current with `check`'s report
- A GitHub Action that runs `check` as a gate or as a monitor that keeps one tracking issue current, using a release binary it verifies first
- Hooks for prek and pre-commit
- An agent skill: `npx skills add padamson/cargo-lockpatrol`
- Release archives for Linux (x86_64, aarch64; static, so any glibc), macOS (x86_64, aarch64) and Windows (x86_64), with build provenance, named so `cargo binstall` finds them

[Unreleased]: https://github.com/padamson/cargo-lockpatrol/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/padamson/cargo-lockpatrol/releases/tag/v0.1.0
