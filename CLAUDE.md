# Project Name

<!-- Replace with a one-line description of what this project does -->

## Development

```bash
cargo build              # build
cargo nextest run        # run tests
cargo test --doc         # doc tests
cargo clippy             # lint
cargo fmt                # format
cargo deny check         # advisories (root lockfile only), licenses, bans, sources (one ignore list: deny.toml)
./scripts/check-advisories.sh  # advisories in every tracked Cargo.lock, the way CI gates them
cargo vet                # supply chain review
```

## Claude Code sandbox

The sandbox is on in user settings for every repo, and a session never
writes outside its own working tree. There is no per-repo sandbox file
to look for.

## Pre-commit hooks

```bash
cargo install prek
prek install --overwrite   # --overwrite replaces any legacy pre-commit hook
```

Hooks mirror CI checks: fmt, clippy, check, nextest, doctest, deny, vet,
and the skill version guard.

## Watching CI

```bash
./scripts/ci-watch.sh            # stream job results for HEAD until they finish
./scripts/ci-watch.sh <sha>      # for a specific commit
./scripts/ci-watch.sh --poll 15 --timeout 600   # poll every 15s, give up after 10 minutes
```

One line per job as it reaches a terminal state, then an exit code:
0 all green, 1 something failed, 2 timed out or a usage error. A `gh`
call inside a shell loop is not matched by the sandbox's command
exclusion, so this script is excluded as a whole in
`.claude/settings.json`. Pass `--poll` and `--timeout` as flags: an
env-var prefix (`POLL=15 ./scripts/ci-watch.sh`) is not the excluded
command, so the script runs sandboxed and every `gh` call fails.

## Manual checks

What a session cannot check and the person reviewing the work can. A
hand-off before a commit names each one that applies, as its command and
what a pass looks like; CI is the backstop, not the plan.

**From a plain terminal** (the sandbox blocks these):

- A change to `.claude/settings.json`: the sandbox denies writes to it,
  so apply the edit by hand, then run `/sandbox` in a new session. A pass
  is the resolved config showing the change.
- A new consumed skill: `npx skills add <owner>/<repo>` (Agent skills,
  below). A pass is one entry per skill in `ls -l .claude/skills/`.
- A new public API's rustdoc: `cargo doc --open`, since `open` is blocked
  in the sandbox.

**Not from a session at all**, changed on github.com or crates.io: the
`main` branch protection and its required checks, the `release tags`
ruleset, Allow auto-merge and automatic head-branch deletion, the merge
App and its two Dependabot secrets, Dependabot alerts and security
updates, and the crate's Trusted Publisher (SETUP.md has each).

**By eye:**

- Prose a reader will act on: the CHANGELOG entry, README, SETUP.md
  steps, and the shipped skill under `skills/`. The skill version guard
  checks the bump, not that the prose is still true.
- A workflow change: the first run of the changed job on GitHub, since
  nothing local runs it. A job that only fires on a tag, a schedule or a
  Dependabot PR waits for that event, or a `workflow_dispatch` where it
  has one.

## Agent skills

`skills/my-project/` is the skill this crate ships to consumers (see
SETUP.md "Agent skill" to ship or delete it). Edits to it must bump
`metadata.version` in its `SKILL.md`; the pre-commit hook and the
`Skill version guard` CI job both enforce that.

Skills of tools this crate depends on are managed installs, not vendored:
`skills-lock.json` (tracked) records each source and a content hash, and
`npx skills add <owner>/<repo>` fetches the content into `.agents/` and
links it from `.claude/skills/`. Both paths are gitignored, so run the
installs once after cloning, from a plain terminal (the sandbox denies
writes under `.claude/skills/`). Verify with `ls -l .claude/skills/`: one
entry per installed skill. Refresh with `npx skills update -p`: without
`-p` it prompts for a scope and defaults to Global. The refresh runs fine
inside the sandbox, since the real files live under `.agents/`; only
`add`, which creates the `.claude/skills/` symlink, needs a plain
terminal. Confirm by reading `metadata.version` out of the installed
`SKILL.md`.

## Mutation testing

```bash
./scripts/mutants.sh                 # diff HEAD~1..HEAD (default)
./scripts/mutants.sh main            # diff main..HEAD
./scripts/mutants.sh --working       # diff uncommitted edits against HEAD
./scripts/mutants.sh -- --jobs 4     # pass extra cargo-mutants args
```

`scripts/mutants.sh` wraps `cargo mutants --in-diff`, scoping mutation
testing to just the lines a commit touched. A full-codebase run grows
linearly with codebase size and routinely takes hours; `--in-diff`
keeps the loop fast enough to use while the test is still warm. Use
`--working` to gate edits before committing them (new files need
`git add -N <file>` first to show up in the diff). Don't reach for
`cargo mutants -f <file>` as the fast path: with `examine_globs` set it
ignores the filter and sweeps everything in scope.

Run one mutation job at a time; every run writes `mutants.out/`. A
stray run is stopped with `pkill -f cargo-mutants` (hyphen; the binary
is `cargo-mutants`).

CI runs the per-diff variant on every push and PR (`mutation-testing-diff`
in `security.yml`). The full-codebase job (`mutation-testing`) is
manual-only via `workflow_dispatch` — use it for occasional audits or
big refactors, never on a schedule.

Scope the baseline with `.cargo/mutants.toml`, which ships live (a
`.mutants.toml` at the repo root is ignored silently); `--in-diff`
narrows from there.

## Tests

A test is a claim about behavior, named as the claim, one claim per
test, asserting the value (`assert_eq!` on an enum, `matches!` on the
error variant and what it names) rather than prose. The seed crate shows
the shapes: a decision returned as a value, an error that carries the
offending input, an environment read through an injected lookup, a
`TempDir`-owning fixture and a bounded poll in `tests/common/mod.rs`,
and one `#[ignore = "reason; run with ..."]` test as the gate for
anything a fresh clone may lack. Never `return` from a test because a
precondition is missing.

`.config/nextest.toml` bounds every test with a slow-timeout; the hook
runs the default profile (no retries) and CI runs `--profile ci` (one
retry, reported FLAKY). nextest does not run doctests, so `cargo test
--doc` is its own step, and the crate keeps at least one doctest so that
step is not a no-op.

## Release process

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md`
3. Commit: `git commit -m "Release vX.Y.Z"`
4. Tag: `git tag vX.Y.Z`
5. Push: `git push origin main --tags`

The tag triggers CI, which checks each crate's semver against its latest
crates.io release, then builds, tests, creates a GitHub Release, and
publishes to crates.io. A crate not yet on crates.io skips the semver
check, and a version already there skips the publish; any other answer
from crates.io fails the run, and so does a tag that no publishable
crate's version matches. A crate's first version is published by hand
(SETUP.md, "crates.io Trusted Publishing"); its tag then finds that
version on crates.io and skips the publish.

After a crate's first publish (the first release, or a crate new to the
workspace), add `[policy.<crate>] audit-as-crates-io = false` to
`supply-chain/config.toml`. Until it is there, `cargo vet` matches the
path crate to its crates.io version and fails every push.

<!-- Add custom skills under .claude/skills/ as needed -->
