# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- Crate `cargo-lockpatrol`, created from `rust-project-template`
- `cargo lockpatrol check`: runs `cargo deny --format json check advisories` on every git-tracked `Cargo.lock` against one `deny.toml`, prints each finding under its lockfile, and exits 0 (clean), 1 (an advisory), 2 (a check broke, or no `Cargo.lock` is tracked), or 3 (both). A run with no summary line counts as broken, so a failed advisory-db fetch or a bad `deny.toml` is never read as a finding or as clean. `--locked root|none|all` (default `root`) picks which trees must match their lockfile
- Agent skill scaffold renamed to `skills/cargo-lockpatrol`, still hidden from installers until the first release

[Unreleased]: https://github.com/padamson/cargo-lockpatrol/commits/main
