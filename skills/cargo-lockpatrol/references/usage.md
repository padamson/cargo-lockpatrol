# cargo-lockpatrol usage

## `cargo lockpatrol check`

```
cargo lockpatrol check [--config <PATH>] [--locked <root|none|all>]
```

Writes the report to stdout, one section per lockfile with findings. On
stderr, each lockfile gets `checking <lockfile>` as its run starts, and
as it ends `<lockfile>: clean`, why it broke, or, for a lockfile with
findings, nothing unless cargo-deny said more (then `cargo deny on
<lockfile> also reported:` and its messages). Exit 0 clean, 1 an
advisory, 2 broken, 3 both; 4 or 5 is 0 or 1 with a denied stale ignore
entry (below).

- `--config`: the `deny.toml` every tree is checked against, relative to
  the current directory. Default: `deny.toml` at the repository root, even
  for a nested tree that has its own. A path that is not a file is a
  broken check (exit 2): cargo-deny would otherwise fall back to its
  built-in config, with only a warning the check does not show.
- `--locked`: which trees must match their `Cargo.lock`. `root` (the
  default) fails a root lock that disagrees with its manifests instead of
  checking a quietly rewritten graph; nested trees are exempt because one
  that path-depends on the root crate goes stale on every version bump.
  `all` and `none` do what they say.

An `[advisories].ignore` entry that matches nothing in any tracked
lockfile is stale, and `check` names it on stderr: as a warning at
cargo-deny's default, or as an error that adds 4 to the exit code when
`deny.toml` sets `unused-ignored-advisory = "deny"`: 4 on clean trees, 5
beside a finding. The report is complete either way, so the monitor files
or closes its issue first and then fails. An entry that some tree
uses is never reported, however many trees leave it unused. When a tree
broke, an entry the other trees leave unused is a warning that says so,
since the broken tree may be the one that needs it. A yanked-crate entry
is not counted unused in a tree where cargo-deny could not reach the
registry.

Only `check` reads the trees together. A plain `cargo deny check
advisories` with `unused-ignored-advisory = "deny"` fails on every entry
its one tree does not use.

A repository with no tracked `Cargo.lock` is broken (exit 2), not clean.

## `cargo lockpatrol render`

```
cargo lockpatrol render <OLD> <REPORT> <OUT> <COMMENT> [--run-url <URL>]
```

The monitor's step, rarely run by hand. Reads the issue's old body (an
empty file when there is none) and a `check` report, writes the new body
and a comment, and prints `changed` (findings came or went, or the old
body kept notes beside its report, which the comment carries: edit the
body and post the comment), `refreshed` (the same findings in other words: edit
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

Outputs: `result` (`clean`, `finding`, `broken` or `both`), `stale-ignore`
(`true` when a denied ignore entry matches nothing in any tree) and `report`
(the report's path).

The monitor needs `permissions: issues: write`. It opens the issue on a
finding, edits the body when the findings or their wording change,
comments only when findings come or go or notes leave the body, closes
the issue when every tree is clean, and leaves an open issue alone when
a tree is broken (the report is partial). The step fails on `broken` and
`both`.

## Hooks

| id | language | runs |
|---|---|---|
| `cargo-lockpatrol` | `rust` | the binary built at the pinned rev |
| `cargo-lockpatrol-system` | `system` | `cargo-lockpatrol` on `PATH` |

Both run when a `Cargo.toml`, `Cargo.lock` or `deny.toml` is committed and
check every tracked lockfile. Pass `args: [--locked, all]` or `args:
[--config, path/deny.toml]` to change what they check.
