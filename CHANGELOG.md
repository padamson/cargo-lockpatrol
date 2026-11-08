# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

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
