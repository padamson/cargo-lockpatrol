# cargo-lockpatrol

Check every tracked `Cargo.lock` in a repository for RustSec advisories
with `cargo-deny`, and keep one GitHub issue current with what it finds.

## What it does

- Runs `cargo deny check advisories` against every `Cargo.lock` that git
  tracks (the root lock and any nested tree outside the workspace), all
  with the root `deny.toml`.
- Tells a finding from a broken run. `check` exits 0 when every tree is
  clean, 1 for a finding, 2 when the check itself broke (an
  advisory-database fetch, a bad `deny.toml`, a `cargo metadata` failure),
  and 3 for both, so a network error never reads as an advisory and a
  broken tree cannot hide behind a clean one.
- Keeps one tracking issue. Each run rewrites the body, a comment is added
  only when the set of advisory ids changes (naming what came and what
  went), and the issue closes when every tree is clean. Triage goes in the
  comments.

The same binary backs a composite GitHub Action (for the CI gate and the
scheduled monitor) and a pre-commit hook, released from this repository
under one tag. Pinning that tag pins all three callers to the same
checker, so the monitor never reports something the gates pass.

## Motivation

`cargo deny check advisories` exits 1 for a finding and for a crash alike,
and it reads one manifest per run. Repositories made from
[rust-project-template](https://github.com/padamson/rust-project-template)
work around both with three copied scripts (about 700 lines of shell and
Python, plus a 150-line workflow), and every fix to them is one port per
repository. A released tool turns that into a Dependabot bump.

## Installation

```bash
cargo install cargo-lockpatrol    # or: cargo binstall cargo-lockpatrol
```

## Usage

```bash
cargo lockpatrol check    # the gate: exit 0, 1, 2 or 3 as above
cargo lockpatrol render OLD REPORT OUT COMMENT [--run-url URL]
                          # the issue: prints changed, refreshed or unchanged
```

Every caller needs cargo-deny on `PATH`; cargo-lockpatrol does not install
it, so you pick its version.

### GitHub Action

Pin the action by commit SHA. The action runs the release whose version is
in `Cargo.toml` at that commit, and checks the archive's build provenance
before running it, so the pin covers the binary too.

As a gate, the step fails on a finding or a broken check:

```yaml
- uses: taiki-e/install-action@<sha>  # cargo-deny
  with:
    tool: cargo-deny
- uses: padamson/cargo-lockpatrol@<sha>  # vX.Y.Z
```

As a monitor, a finding opens or updates one tracking issue, a clean check
closes it, and the step fails only on a broken check:

```yaml
on:
  schedule:
    - cron: "0 7 * * *"
  workflow_dispatch:

concurrency:
  group: advisory-monitor
  cancel-in-progress: false

jobs:
  advisories:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: write
    steps:
      - uses: actions/checkout@<sha>  # v7
      - uses: taiki-e/install-action@<sha>  # cargo-deny
        with:
          tool: cargo-deny
      - uses: padamson/cargo-lockpatrol@<sha>  # vX.Y.Z
        with:
          issue: "true"
```

Keep the monitor on a schedule, never on `issues` or `issue_comment`
events, and keep the concurrency group: two runs at once would each find
no issue and each open one. A run that finds what the issue already says
does not touch it.

Inputs: `deny-config` (default `deny.toml` at the root), `locked` (`root`,
`none` or `all`), `working-directory` (a directory inside the repository
to run from; `deny-config` is relative to it), `issue`, `issue-title`,
`issue-label` and `github-token`.
Outputs: `result` (`clean`, `finding`, `broken` or `both`) and `report`,
the path of the report.

### pre-commit and prek

```yaml
- repo: https://github.com/padamson/cargo-lockpatrol
  rev: <sha>  # frozen: vX.Y.Z
  hooks:
    - id: cargo-lockpatrol         # builds the binary at the pinned rev
    # - id: cargo-lockpatrol-system  # or runs one already on PATH
```

## Agent skill

[![skills.sh](https://skills.sh/b/padamson/cargo-lockpatrol)](https://skills.sh/padamson/cargo-lockpatrol)

```bash
npx skills add padamson/cargo-lockpatrol
```

Works with [Claude Code](https://claude.ai/code),
[Codex](https://openai.com/codex/), [Cursor](https://cursor.com), and any
other [compatible agent](https://agentskills.io/clients). The install copies
the skill into your repo and records its source in `skills-lock.json`.

## Development

See [CLAUDE.md](CLAUDE.md) for development commands.

### Prerequisites

- [Rust toolchain](https://rustup.rs/) (MSRV: 1.88)
- [prek](https://github.com/j178/prek) for pre-commit hooks: `cargo install prek && prek install`

### Build and test

```bash
cargo build
cargo nextest run
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)

at your option.
