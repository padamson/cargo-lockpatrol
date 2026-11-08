# cargo-lockpatrol usage

## `cargo lockpatrol check`

```
cargo lockpatrol check [--config <PATH>] [--locked <root|none|all>]
```

Writes the report to stdout, one section per lockfile with findings, and
why any tree broke to stderr. Exit 0 clean, 1 an advisory, 2 broken, 3
both.

- `--config`: the `deny.toml` every tree is checked against, relative to
  the current directory. Default: `deny.toml` at the repository root, even
  for a nested tree that has its own.
- `--locked`: which trees must match their `Cargo.lock`. `root` (the
  default) fails a root lock that disagrees with its manifests instead of
  checking a quietly rewritten graph; nested trees are exempt because one
  that path-depends on the root crate goes stale on every version bump.
  `all` and `none` do what they say.

A repository with no tracked `Cargo.lock` is broken (exit 2), not clean.

## `cargo lockpatrol render`

```
cargo lockpatrol render <OLD> <REPORT> <OUT> <COMMENT> [--run-url <URL>]
```

The monitor's step, rarely run by hand. Reads the issue's old body (an
empty file when there is none) and a `check` report, writes the new body
and a comment, and prints `changed` (findings came or went: edit the body
and post the comment), `refreshed` (the same findings in other words: edit
the body only) or `unchanged` (touch nothing).

## The GitHub Action

| Input | Default | |
|---|---|---|
| `deny-config` | `deny.toml` at the root | `--config`, relative to `working-directory` |
| `locked` | `root` | `--locked` |
| `working-directory` | `.` | a directory inside the repository to run from; every tracked lockfile is still checked |
| `issue` | `"false"` | `"true"` for the monitor |
| `issue-title` | `Security: new dependency advisory detected` | the monitor finds its issue by title and label |
| `issue-label` | `security-advisory` | created on the first finding if missing |
| `github-token` | `github.token` | downloads the release, manages the issue |

Outputs: `result` (`clean`, `finding`, `broken` or `both`) and `report`
(the report's path).

The monitor needs `permissions: issues: write`. It opens the issue on a
finding, edits the body when the findings or their wording change,
comments only when findings come or go, closes the issue when every tree
is clean, and leaves an open issue alone when a tree is broken (the
report is partial). The step fails on `broken` and `both`.

## Hooks

| id | language | runs |
|---|---|---|
| `cargo-lockpatrol` | `rust` | the binary built at the pinned rev |
| `cargo-lockpatrol-system` | `system` | `cargo-lockpatrol` on `PATH` |

Both run when a `Cargo.toml`, `Cargo.lock` or `deny.toml` is committed and
check every tracked lockfile. Pass `args: [--locked, all]` or `args:
[--config, path/deny.toml]` to change what they check.
