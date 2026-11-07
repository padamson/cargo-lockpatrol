# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- Crate `cargo-lockpatrol`, created from `rust-project-template`
- `cargo lockpatrol check`: runs `cargo deny --format json check advisories` on every git-tracked `Cargo.lock` against one `deny.toml`, prints each finding under its lockfile, and exits 0 (clean), 1 (an advisory), 2 (a check broke, or no `Cargo.lock` is tracked), or 3 (both). A run with no summary line counts as broken, so a failed advisory-db fetch or a bad `deny.toml` is never read as a finding or as clean. `--locked root|none|all` (default `root`) picks which trees must match their lockfile
- `cargo lockpatrol render OLD REPORT OUT COMMENT [--run-url URL]`: turns a tracking issue's body and a `check` report into the new body and a comment, and prints `changed` (findings came or went: edit the body and post the comment), `refreshed` (the same findings in other words: edit the body only) or `unchanged`. Findings are matched by lockfile and RustSec id (a yanked crate by its headline), the report is fenced so advisory text cannot render as markdown, and a report too large for GitHub is cut to its findings. A body written by `scripts/advisory-issue-body.py` reads back as the same findings
- Agent skill scaffold renamed to `skills/cargo-lockpatrol`, still hidden from installers until the first release

[Unreleased]: https://github.com/padamson/cargo-lockpatrol/commits/main
