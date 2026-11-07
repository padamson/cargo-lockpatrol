# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- `dependabot.yml`: a commented `directories:` example on the cargo entry, for repos whose excluded crates commit their own `Cargo.lock` (Dependabot reads only the root lock otherwise)
- `.config/nextest.toml`: slow-timeout and leak-timeout in every profile, retries only under `[profile.ci]` (which CI now runs), a commented test-group example; every CI job carries `timeout-minutes`
- `.cargo/mutants.toml` ships live instead of as an `.example`, so a fresh clone never runs mutation testing unscoped under `cargo test`
- Seed crate rewritten as claim-shaped tests: `classify` returns a `Size` enum with a boundary at the threshold and a `SizeError::Negative` variant carrying the count; the threshold reads the environment through an injected lookup; `tests/common/mod.rs` ships a `TempDir`-owning `Workspace` fixture and a bounded `poll_until`; one `#[ignore = "..."]` test shows the gate for anything a fresh clone may lack. `tempfile` as a dev-dependency
- Doctest policy: `cargo test --doc` always runs, and the crate keeps at least one doctest so the step is honest
- CLAUDE.md "Tests" section with the shapes and the runner policy
- `scripts/mutants.sh` creates its scratch diff under `$TMPDIR` with a full template; `mktemp -t` ignores `$TMPDIR` on macOS and fails under the Claude Code sandbox
- `release.yml` gates the release on `cargo semver-checks check-release`: a job the build and the publish both wait on, comparing each publishable crate with its latest crates.io release and skipping a crate crates.io answers 404 for (any other answer fails the run). Crates without a library target are listed and passed over. A tag no publishable crate's version matches fails first. The publish skips a version already on crates.io, so the first tag after the hand-published first version goes green
- `release.yml` publishes to crates.io with Trusted Publishing (OIDC via `rust-lang/crates-io-auth-action`); the token-missing skip and the `continue-on-error` on the publish step are gone, since both made a failed publish look green. SETUP.md walks through the crates.io publisher entry, and SETUP.md and CLAUDE.md give the `audit-as-crates-io = false` cargo-vet policy each crate needs after its first publish
- `advisory-monitor.yml`: daily `cargo deny check advisories`, opening one tracking issue on a new advisory and closing it when the tree is clean; the report reaches the issue body through an env var, not string interpolation
- `cargo audit` removed from CI and the hooks: `cargo deny check` reads the same advisory database, so `deny.toml`'s `[advisories] ignore` is the single list and nothing mirrors it. `Security Audit` leaves the required checks
- Every action in every workflow pinned to a commit SHA with the version in a trailing comment (Dependabot keeps them current); workflow permissions default to `contents: read` and each writing job names what it writes
- `.github/actions/diff-base`: one composite action giving the mutation and skill-guard jobs the PR base branch's current tip, the push's previous tip, or nothing on a first push
- Agent skill scaffold: `skills/my-project/` with `references/`, hidden from installers by `metadata.internal: true` until shipped; `scripts/check-skill-version-bumped.sh` as a pre-commit hook and a `Skill version guard` CI job; the `npx skills add` block plus skills.sh badge in README.md. SETUP.md says how to ship it (with the in-repo symlink as an opt-in for crates that use themselves) or remove it
- Consumed agent skills: `.agents/` and `.claude/skills/` gitignored, and a CLAUDE.md section on `npx skills add` installs (from a plain terminal) and `npx skills update -p` refreshes (fine inside the sandbox)
- Tracked `.claude/settings.json` with the Claude Code sandbox block (loopback network, configd Mach lookup, excluded commands for git, gh, nextest, cargo run, prek, the mutants and ci-watch scripts)
- `scripts/ci-watch.sh` streams job results for a commit until every run finishes, with a CLAUDE.md section
- CLAUDE.md states the sandbox is on for every repo and cross-repo writes are not allowed; SETUP.md says `prek install` writes `.git/hooks` and is run by hand once per clone
- Dual license, `MIT OR Apache-2.0`: `LICENSE-MIT` and `LICENSE-APACHE`, `Cargo.toml` and README updated
- SETUP.md: keeping `target/` under control (a `find` that lists Cargo-made `target/` directories idle 30 days, since cargo-sweep is unmaintained; turning incremental off, build-script assets outside `OUT_DIR` with their own CI cache), converting to a workspace, and a `build.rs` recipe so `--version` reports the build commit off a release tag
- Pre-commit: a comment by the nextest hook stating that the hook's feature set must equal the union of CI's, and a commented `exclude:` for byte-exact fixture directories on the whitespace hooks
- `security.yml`: a commented resolve-then-`--rev` recipe for installing a tool from a git branch
- `scripts/check-advisories.sh` points every tree at the root `deny.toml` (a nested one no longer wins), keeps cargo deny off the stdin that carries the lockfile list, and reads git's list NUL-separated so a path git would quote still resolves
- Advisory tracking issue: the monitor owns the body and rewrites it whole on every run, and the body asks for triage notes in comments. Past GitHub's size limit the report is cut to its findings, each kept or dropped whole, with a notice saying so. The report is fenced longer than any run of backticks in advisory text. When the findings change, a comment lists the new and resolved ones by id and title, so the record outlives the run log; a finding the cut left out is not called resolved. Findings are matched by the RUSTSEC id on their `ID:` line (a yanked crate by its first line), so an advisory retitled upstream, or a moved lockfile line, updates the body without a comment, and an advisory named in another's description is not a finding. A body from before reports had lockfile headings is compared by id alone
- `scripts/ci-watch.sh` counts a failed run with no failed job, finds a commit's runs on the server by SHA, recomputes its counts each poll so a re-run that goes green reads green, leaves out scheduled runs that landed on the same commit, takes `--poll` and `--timeout` flags, and exits 2 on a usage error
- `dependabot-auto-merge.yml` leaves a Dependabot PR that edits the workflow itself for a hand merge, read from the event's base and head SHAs, so a bumped token action never runs with the App's key before review. The check is a job of its own that the merge job needs, since the runner runs an action's `pre:` hook before a job's first step; it holds a compare at its 300-file limit and matches a renamed file under its old name. `dependabot.yml` keeps `create-github-app-token` out of the actions group, so its bump is held from its first push and holds no other bump
- `security.yml`: a `Semver preview` job on pushes and PRs, not required, comparing each publishable library crate with its latest crates.io release ahead of the tag-time gate; it passes over a crate whose manifest still names the placeholder repository
- SETUP.md: a `release tags` ruleset, admin bypass only, so a leaked merge-App key cannot push a release tag; vet fixes for a Dependabot PR land on `main` and reach the PR through `@dependabot rebase`
- `Cargo.toml`: a `[lints]` table with `unsafe_code = "deny"` and an empty clippy table
- `.claude/settings.json`: `com.apple.trustd.agent` beside `configd` in `allowMachLookup`, so a tool that verifies TLS through the macOS platform verifier (`cargo audit` 0.22) can fetch its database in-session
- CLAUDE.md: a `## Manual checks` section listing what a session cannot check (plain-terminal gates, GitHub and crates.io settings, what to read by eye)
- `scripts/mutants.sh` diffs a root commit against git's empty tree, so `Mutation Testing (diff)` tests the initial scaffold instead of failing with exit 128 on a repo's first push; a user-supplied base ref that does not resolve is now a hard error rather than a silent pass
- `scripts/mutants.sh --working` diffs uncommitted edits against `HEAD` (or a given ref), for gating a change before it is committed
- `scripts/mutants.sh` passes `--no-renames` to `git diff`, so a `git mv` produces a mutable diff instead of a green gate over unmutated code
- Pre-commit `cargo vet` hook: `files` regex now matches paths under `supply-chain/` (the end-anchored pattern matched nothing), and the hook skips until `cargo vet init` has run, mirroring the CI job
- `deny.toml`: `allow-wildcard-paths = true`, so versionless path deps of `publish = false` workspace members and dev-dependencies do not trip `wildcards = "deny"`
- CLAUDE.md: `--working` usage, the `-f <file>` trap, and the one-run-at-a-time rule for `mutants.out/`
- `Supply Chain Review` job checks for `supply-chain/audits.toml` before installing cargo-vet, so an uninitialized repo skips in seconds instead of building the tool first; it builds cargo-vet from crates.io with `--locked`, since the newest release with binaries (0.10.0, all `install-action` can fetch) cannot parse `trusted-publisher` entries
- `dependabot-auto-merge.yml`: enables squash auto-merge on every Dependabot PR (authored by Dependabot and pushed by it) behind the required status checks, using a GitHub App's token so each merge starts a push run on `main` (a `GITHUB_TOKEN` merge starts none). SETUP.md walks through the App, its two Dependabot secrets, and the Allow auto-merge and delete-head-branch settings
- Dependabot `cooldown` (7/14/7/3 days for cargo, 7 for actions) so bumps arrive after the cargo-vet import sets have audited them
- Dependabot groups for majors and for actions, plus a commented git-dependencies slot that must come first, so the weekly run opens at most four PRs and the auto-merge cascade (N PRs, O(N^2) CI runs) cannot start
- SETUP.md: require every PR-triggered job including `Mutation Testing (diff)`, and leave "require branches to be up to date" off, with the reasoning for both
- Initial project scaffold
- `.cargo/mutants.toml` with scoping guidance to keep `cargo mutants` runs tractable on real downstreams: `.cargo/` is the one path cargo-mutants reads (a root `.mutants.toml` is ignored silently) and the header says how to verify the config is live; `test_workspace = true` and no `--lib`, which skipped `tests/` integration targets and let cross-target kills survive; a commented nextest filterset as the speed lever and a commented `exclude_globs` for codegen output
- `test.yml` split: ubuntu-only `Lint` job covers fmt, clippy, doctest, and `cargo doc`; the cross-platform matrix (ubuntu/macos/windows) runs only `cargo build` + `cargo nextest run`
- Comments in `security.yml`, `.pre-commit-config.yaml`, and `deny.toml` documenting the `cargo audit --ignore` pattern keyed off `deny.toml`'s `[advisories] ignore` as source of truth
- CLAUDE.md / SETUP.md note on `prek install --overwrite` to avoid double-firing legacy pre-commit hooks
- MSRV-job comment on stubbing `include_bytes!` build artifacts via `touch` for downstreams that embed generated files
- Expanded `cargo vet import` list in SETUP.md to the seven well-known trusted orgs (bytecode-alliance, embark-studios, fermyon, google, isrg, mozilla, zcash), using the named-import form
- Per-PR workflow documentation in SETUP.md for handling Supply Chain Review failures on Dependabot PRs (never auto-regenerate exemptions in CI; certify vs. regenerate vs. reject)
- `cargo vet trust` section in SETUP.md covering transitive trust of publishers already certified by imported orgs (seanmonstar, BurntSushi, epage, kennykerr, Lokathor), including `--allow-multiple-publishers` guidance for flagship multi-maintainer packages
- `scripts/mutants.sh` wrapper for `cargo mutants --in-diff`, with project-specific pre-setup placeholder, defaulting to `HEAD~1..HEAD`
- Two-job mutation-testing setup in `security.yml`: a per-push/PR `mutation-testing-diff` job using `cargo mutants --in-diff` (typical runtime seconds-to-minutes), with `fetch-depth: 0` and PR/push base resolution; and a `mutation-testing` (full) job available via manual `workflow_dispatch` only — full-codebase runs don't scale to be scheduled
- `## Mutation testing` section in CLAUDE.md covering the local script + CI shape
- `/mutants.out/` and `/mutants.out.old/` added to `.gitignore`
- All Cargo cache steps in `test.yml`, `release.yml`, and `security.yml` switched from `actions/cache@v5` + manual key composition to `Swatinem/rust-cache@v2` + `shared-key`. Auto-derived key includes the rustc version (catches stale-binary panics across toolchain bumps), and pre-save cleanup keeps cache size in check. Release-job `shared-key` includes `matrix.target` so the two macOS cross-targets don't clobber each other.

[Unreleased]: https://github.com/OWNER/REPO/commits/main
