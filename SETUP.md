# Setup Checklist

After creating a repo from this template, complete these steps.

## Automated (already in the template)

- [x] GitHub Actions CI: test, security, release workflows, a daily advisory monitor
- [x] Dependabot: weekly cargo and GitHub Actions updates, auto-merged behind the required checks
- [x] Pre-commit hooks via prek
- [x] cargo-deny configuration (the one advisory ignore list)
- [x] Tracked Claude Code sandbox settings (`.claude/settings.json`)
- [x] An agent skill scaffold under `skills/` (hidden from installers until you ship it), with its version guard
- [x] CHANGELOG scaffold
- [x] CLAUDE.md with development commands

## Search and replace

- [ ] Replace `my-project` with your project name in `Cargo.toml`, `README.md`, and `CLAUDE.md`
- [ ] Replace `OWNER/REPO` with your GitHub path in `Cargo.toml` and `CHANGELOG.md`
- [ ] Replace `Your Name` with your name in `Cargo.toml`, and `Paul Adamson` in `LICENSE-MIT`
- [ ] Decide about `skills/my-project`: ship it under your crate's name, or delete it (see "Agent skill" below)
- [ ] Update `description`, `categories`, and `keywords` in `Cargo.toml`
- [ ] Update `README.md` with your project description and usage
- [ ] Update `CLAUDE.md` with project-specific context
- [ ] Strip `<!-- Template users: ... -->` and similar meta-comments from `README.md` and `CLAUDE.md` after the placeholder substitutions

## GitHub Settings (manual)

These settings cannot be configured via code and must be set in the GitHub UI.

### Repository settings

- [ ] **Settings > General > Features:** Enable "Issues" and "Projects" if not already
- [ ] **Settings > Branches > Branch protection:** Add rule for `main`.

  **Apply protection only after the first PR has merged** — otherwise the rules block the very PR that first makes the required checks real.

  **Require every PR-triggered job.** The required checks are the entire
  merge gate for Dependabot: `dependabot-auto-merge.yml` enables auto-merge
  on every Dependabot PR, and it merges the moment these are green. The
  push run on `main` afterwards tests the merged tree but cannot stop the
  merge. A job left off this list (Supply Chain Review is the classic
  omission) means a bump merges with that job red.

  - `MSRV Check` — cheap; catches accidental use of post-MSRV features
  - `Lint` — fmt, clippy, doctest, cargo doc (ubuntu-only)
  - `Test on ubuntu-latest`, `Test on macos-latest`, `Test on windows-latest`
  - `License & Dependency Check`, `Supply Chain Review`
  - `Mutation Testing (diff)`, `Skill version guard`

  Leave `Semver preview` off the list. It is the early warning for the
  release's semver gate, and on 0.x a deliberate breaking change turns it
  red until the release that bumps the version, which would block every
  merge in between. Leave off `dependabot-auto-merge.yml`'s two jobs,
  `Hold a PR that edits this workflow` and `Enable auto-merge`, too: they
  are the merge machinery, not checks on the change, and the hold's red is
  what marks a PR you merge by hand (Dependabot auto-merge, below).

  **Leave "require branches to be up to date" off** (`strict: false`).
  With it on, the second green Dependabot PR of the week is stale the moment
  the first merges, auto-merge never updates branches, and Dependabot only
  rebases on a conflict, so PRs sit blocked until someone clicks "update
  branch" and every rebase re-runs CI. Off, each green PR merges once. The
  residual risk (two green PRs that conflict semantically without
  conflicting in git) is negligible for Dependabot: cargo PRs always collide
  on `Cargo.lock` and get rebased and re-tested, and an actions bump beside
  a cargo bump touches disjoint files.

  Either click through the UI, or apply via `gh api` (requires `admin:repo` scope — run `gh auth refresh -s admin:repo` first if needed):

  ```bash
  gh api -X PUT repos/OWNER/REPO/branches/main/protection \
    --input - <<'JSON'
  {
    "required_status_checks": {
      "strict": false,
      "checks": [
        {"context": "MSRV Check"},
        {"context": "Lint"},
        {"context": "Test on ubuntu-latest"},
        {"context": "Test on macos-latest"},
        {"context": "Test on windows-latest"},
        {"context": "License & Dependency Check"},
        {"context": "Supply Chain Review"},
        {"context": "Mutation Testing (diff)"},
        {"context": "Skill version guard"}
      ]
    },
    "enforce_admins": false,
    "required_pull_request_reviews": null,
    "restrictions": null,
    "required_linear_history": false,
    "allow_force_pushes": false,
    "allow_deletions": false,
    "required_conversation_resolution": true
  }
  JSON
  ```

- [ ] **Settings > Rules > Rulesets > New tag ruleset:** restrict
  creation, update and deletion of release tags, with the Repository admin
  role as the only bypass. The merge App's token can push a tag, a tag
  pushed with it starts `release.yml` (one pushed with `GITHUB_TOKEN`
  would not), and the release publishes through Trusted Publishing, so
  without the ruleset a leaked App key could release any commit. Cover
  every pattern under `on.push.tags` in `release.yml`: `v*` here, plus
  any per-crate prefix you add after converting to a workspace.

  ```bash
  gh api -X POST repos/OWNER/REPO/rulesets --input - <<'JSON'
  {
    "name": "release tags",
    "target": "tag",
    "enforcement": "active",
    "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
    "rules": [{"type": "creation"}, {"type": "update"}, {"type": "deletion"}],
    "bypass_actors": [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}]
  }
  JSON
  ```

  Your own `git push origin main --tags` still works through the admin
  bypass.

### Dependabot auto-merge

`dependabot-auto-merge.yml` enables auto-merge with a GitHub App's token.
A merge made with the default `GITHUB_TOKEN` starts no workflows, so
`main` would never get a push run for a Dependabot merge: nothing would
test the tree two sibling bumps leave behind, and push-only jobs would not
run. Until the App and its secrets exist, minting the token fails, so
every Dependabot PR shows a red **Enable auto-merge** check and waits for
you to merge it by hand. That check is not required, so the red is a
reminder, not a block. A Dependabot PR that edits
`dependabot-auto-merge.yml` itself shows a red **Hold a PR that edits this
workflow** check instead, and **Enable auto-merge** is skipped: a bump of
the token action would otherwise run with the App's key before review.
Read the bump and merge it by hand. `dependabot.yml` keeps that action out
of the weekly actions group, so its bump arrives as a PR of its own and
the rest of the week's action bumps still merge on their own.

- [ ] **Settings > General > Pull Requests:** turn on "Allow auto-merge"
  and "Automatically delete head branches". With auto-merge off, the
  workflow's `gh pr merge --auto` fails and nothing merges.

  ```bash
  gh api -X PATCH repos/OWNER/REPO \
    -F allow_auto_merge=true -F delete_branch_on_merge=true
  ```

- [ ] **Create the App** (one App serves every repo you own; skip to the
  install if you have it). **Settings > Developer settings > GitHub Apps >
  New GitHub App**: any name and homepage URL, webhook off, and repository
  permissions **Contents**, **Pull requests** and **Workflows** set to
  read and write. Workflows is there because Dependabot's actions bumps
  edit files under `.github/workflows/`. Note the **Client ID**, then
  generate a private key and save the `.pem`.
- [ ] **Install the App** on this repo: the App's page > **Install App** >
  your account > **Only select repositories**.
- [ ] **Add the two secrets as Dependabot secrets**, not Actions secrets.
  A Dependabot-triggered run can read only Dependabot secrets.

  ```bash
  gh secret set AUTOMERGE_APP_CLIENT_ID --app dependabot --body <client-id>
  gh secret set AUTOMERGE_APP_PRIVATE_KEY --app dependabot < <app>.private-key.pem
  ```

  The private key mints tokens for every repo the App is installed on, so
  install it only where everyone with write access could be trusted with
  all of them; a repo with outside collaborators gets its own App. Delete
  the local `.pem` once the secret is set. If the key is needed again,
  generate a new one on the App's page and delete the old one there.

- [ ] **Never add the App to the branch protection bypass list.** Its
  merges would then skip the required checks.
- [ ] **Prove it.** With Dependabot security updates on (Code security,
  below) and an advisory open, a PR arrives right away, since security
  updates ignore the cooldown; otherwise wait for the weekly run. The
  merged PR's `merged_by` should be the App's bot, and its merge commit
  should have the full set of push runs on `main`.

### Code security

- [ ] **Settings > Code security and analysis** (`/settings/security_analysis`): Enable:
  - Private vulnerability reporting
  - Dependabot alerts
  - Dependabot security updates
  - Dependabot malware alerts
  - Code scanning (CodeQL) via default setup
  - Secret scanning
  - Push protection

### crates.io Trusted Publishing

The release workflow publishes with a short-lived token minted from
GitHub's OIDC identity for this repo and this workflow. There is no
`CARGO_REGISTRY_TOKEN` secret to create, leak, or rotate.

- [ ] On crates.io, for your crate: **Settings > Trusted Publishing > Add a GitHub publisher** with owner `OWNER`, repository `REPO`, workflow `release.yml`, and no environment (unless you add one below).

  A crate that has never been published has no settings page yet. Publish
  the first version from your machine with a token scoped to
  `publish-new`, then add the trusted publisher and revoke the token; every
  later release goes through the workflow.

  If the publisher is missing or misnamed, the `Authenticate to crates.io`
  step fails and the run is red. That is the intended signal. The workflow
  has no "skip if not configured" path and no `continue-on-error` on the
  publish, because both turn a broken release into a green run with no
  crate.

- [ ] Once the crate is on crates.io, tell cargo-vet it is this repo's own
  code. From the first publish on, `cargo vet` matches the path crate to
  the published version and fails every push ("non-crates.io-fetched
  packages match published crates.io versions") until the crate has a
  policy. Add to `supply-chain/config.toml`, once per published crate:

  ```toml
  [policy.<crate>]
  audit-as-crates-io = false
  ```

### Environments (optional)

- [ ] Create `release` environment with required reviewers if you want manual approval before publishing

## Local setup

### Install tools

```bash
cargo install cargo-nextest cargo-deny cargo-vet cargo-mutants cargo-semver-checks prek
```

If any `cargo install` fails with a rustc version mismatch (`requires rustc X.Y.Z or newer, while the currently active rustc version is ...`), run `rustup update stable` — or run `cargo install` from outside any directory containing a `rust-toolchain.toml` override. `cargo install` uses the *active* toolchain, which is directory-scoped when a toolchain file is present in the working tree.

### Enable pre-commit hooks

```bash
prek install --overwrite
```

`--overwrite` replaces any pre-existing `.git/hooks/pre-commit` from the
legacy Python `pre-commit`. Without it, prek keeps the old hook at
`.git/hooks/pre-commit.legacy` and runs both — every check fires twice.

Run this by hand once per clone. It writes into `.git/hooks`, which the
Claude Code sandbox protects, so a session can't do it for you.

### Verify everything works

```bash
cargo build
cargo nextest run
cargo deny check
```

### Initialize cargo-vet

See the cargo-vet section below.

## cargo-vet initialization

Until `cargo vet init` has run, both the pre-commit `cargo vet` hook and
the CI `Supply Chain Review` job print a skip message and pass, so the
first commit and push of a new repo are not blocked on this section.

After your first `cargo build`, initialize supply chain auditing:

```bash
cargo vet init
cargo vet import bytecode-alliance
cargo vet import embark-studios
cargo vet import fermyon
cargo vet import google
cargo vet import isrg
cargo vet import mozilla
cargo vet import zcash
```

`cargo vet import <name>` resolves the canonical URL for each known
trusted org — no need to pin a URL. Together, these seven imports
absorb the bulk of common transitive dependencies (in one dogfooding
run on a real project they converted 142 exemptions into real audits
without any maintainer work).

If your crate has no third-party dependencies yet, `cargo vet` passes immediately with nothing to audit. The imports above pre-seed trusted audit sets so that when you add your first dependency, the audits are already in place — you can safely defer the `cargo vet import ...` commands until then.

### Transitively trust publishers your imported orgs trust

Bigger leverage on top of imports. The orgs you've imported have
already certified specific *individual* publishers. `cargo vet trust`
extends those certifications to your tree — no first-hand audit work.

Run `cargo vet suggest` to see candidates — it surfaces publishers
already trusted by 2+ of your imported orgs. High-leverage names to
apply by default (broadly endorsed, ship widely-used crates):

```bash
cargo vet trust --all seanmonstar    # hyper, reqwest, mime_guess, ...
cargo vet trust --all BurntSushi     # regex, regex-syntax, csv, ...
cargo vet trust --all epage          # clap, toml, anstream, ...
cargo vet trust --all kennykerr      # windows-rs, windows-targets, ...
cargo vet trust --all Lokathor       # bytemuck, ...
```

For multi-maintainer flagship packages (clap, tower, windows-*), add
`--allow-multiple-publishers` so a release by any of the maintainers
counts (not just the trusted one):

```bash
cargo vet trust --all epage --allow-multiple-publishers
cargo vet trust --all seanmonstar --allow-multiple-publishers
cargo vet trust --all kennykerr --allow-multiple-publishers
```

In dogfooding on a real project, this took **304 → 237 exemptions**
(a further 22% reduction on top of imports) with zero audit work.

Then exempt any remaining unaudited dependencies:

```bash
cargo vet
# Follow the prompts to exempt crates
```

### Per-PR workflow for unvetted entries

**Never auto-regenerate exemptions in CI.** A Supply Chain Review
failure on a Dependabot PR is the *signal* that new unvetted code is
arriving — pause and decide before merging. Auto-regenerating
rubber-stamps every upstream change and defeats the point of
`cargo vet`.

The fix lands on `main`, not on the PR branch. Dependabot's rebase is a
force-push that drops any commit added to its branch, and a human push
makes the auto-merge job skip the PR, so it would need a hand merge
anyway. For each unvetted entry in a failing PR, on `main`:

- **`cargo vet certify <crate> <version>`** — gold standard. Read the
  diff (`diff -ru` of the two versions under `~/.cargo/registry/src/`),
  then attest.
- **An exemption for the new version** — bronze standard. Acceptable
  for patch bumps from known publishers; not for new transitives or
  majors. Add it by hand to `supply-chain/config.toml`, beside the old
  version's entry rather than in place of it, so `main` stays green
  until the PR merges. (`cargo vet regenerate exemptions` on `main`
  never sees the PR's version.)
- **Reject** if the diff looks sketchy.

Push, comment `@dependabot rebase` on the PR so its next run picks up
the audits, and run `cargo vet prune` once it merges.

## Agent skill

`skills/my-project/` is the shape of the skill this crate would ship:
the directory `npx skills add OWNER/REPO` installs into a consumer's
repo, so an agent there knows how to use the crate. As scaffolded it is
hidden from installers (`metadata.internal: true`) and nothing loads it.
Decide now:

- [ ] **Ship it.** Rename the directory to your crate name, remove the
  `internal` line from `SKILL.md`, write it for an agent that has never
  seen the crate, and fill `references/`. Every later content edit bumps
  `metadata.version`; the pre-commit hook and the `Skill version guard`
  CI job refuse one that doesn't. Keep the "Agent skill" block in
  `README.md`.

  Only if this repo uses its own crate (examples, an e2e suite, docs that
  exercise it) is it worth auto-loading the skill in-repo too. Claude
  Code discovers project skills at `.claude/skills/` alone, so add one
  tracked symlink and un-ignore it:

  ```bash
  ln -s ../../skills/<name> .claude/skills/<name>
  echo '!/.claude/skills/<name>' >> .gitignore
  ```

- [ ] **Don't ship one.** Delete `skills/`,
  `scripts/check-skill-version-bumped.sh`, the `skill-version-bumped`
  hook in `.pre-commit-config.yaml`, the `skill-version` job in
  `test.yml`, and the "Agent skill" block in `README.md`, and drop
  `Skill version guard` from the required checks.

Skills of the tools this crate depends on are the other direction, and
CLAUDE.md covers them: `npx skills add <owner>/<repo>` once per clone,
content gitignored, pin tracked in `skills-lock.json`.

## Keeping `target/` under control

A project that builds many permutations (default, `--all-features`,
per-target, mutation testing, fuzzing) accumulates tens of gigabytes
under `target/`, most of it incremental-compilation cache with no
payoff outside a single edit-rebuild loop.

- **Sweep periodically.** `cargo-sweep` is unmaintained, so use a
  plain `find` (or `cargo-clean-all`, which is maintained). This lists
  every `target/` under `~/src` that Cargo made (its `CACHEDIR.TAG` says
  so) and in which nothing was modified in 30 days. A build that compiles
  anything counts as use, but a no-op build writes nothing, so a repo you
  only build or run, with no pull, lockfile change or toolchain update in
  that time, is listed too. Read the list, then add `&& rm -rf "$1"`
  inside the quotes:

  ```bash
  find ~/src -type d -name target -prune -exec sh -c \
    'grep -qs "created by cargo" "$1/CACHEDIR.TAG" && [ -z "$(find "$1" -mtime -30 -print -quit)" ] && echo "$1"' _ {} \;
  ```
- **Consider turning incremental off** once the permutation count grows:
  `[build] incremental = false` in `.cargo/config.toml`. CI already has
  it off (`Swatinem/rust-cache` sets `CARGO_INCREMENTAL=0`).
- **Build scripts that download large assets** (drivers, models,
  fixtures) must not write them into `OUT_DIR`: its path carries a
  per-toolchain, per-feature hash, so every permutation re-downloads and
  keeps its own copy. Write to a stable, version-keyed path outside
  `target/` (env-selectable, defaulting to `OUT_DIR` for zero-config
  local use), give the script a skip-download env var for compile-only
  jobs like MSRV, and cache that path in CI with its own `actions/cache`
  keyed on the asset version. `Swatinem/rust-cache` deliberately does not
  cache workspace crates' build-script output.

## Converting to a workspace

The template ships a single crate on purpose: one `Cargo.toml`, one
`src/lib.rs`, every CI invocation already carrying `--workspace` so
nothing needs to change when a second crate appears. Convert when a
second crate has a reason to exist (a `-core` library behind a CLI,
a proc-macro crate, a separate binary), not before.

1. `mkdir -p crates/<name>` and `git mv src tests crates/<name>/`.
2. Turn the root `Cargo.toml` into a virtual manifest:
   `[workspace] members = ["crates/*"]`, `resolver = "3"`, a
   `[workspace.package]` block holding `edition`, `rust-version`,
   `license`, `repository`, `authors`, and a `[workspace.dependencies]`
   table. Move the crate's own `[package]` to `crates/<name>/Cargo.toml`
   with `edition.workspace = true` and friends.
3. `.cargo/mutants.toml`: `examine_globs = ["crates/*/src/**/*.rs"]`.
   `deny.toml` already allows versionless path deps between private
   workspace members.
4. `release.yml` semver-checks and publishes every crate whose `publish`
   is not `false`, each at its own version, skipping a version already on
   crates.io. If one crate depends on another, replace the publish step's
   `cargo metadata` list with the crates in dependency order, since cargo
   resolves each from crates.io. Each published crate needs its own
   trusted-publisher entry and its own `audit-as-crates-io = false`
   policy. A `v*` tag releases every publishable crate whose version is
   not yet on crates.io; the tag's version has to match at least one of
   them, and it names the archives and picks the CHANGELOG section for the
   release notes. A crate new to the workspace is published by hand once,
   like the first, before its trusted publisher can exist.
5. Run `cargo nextest run --workspace`, `cargo clippy --all-targets
   --all-features -- -D warnings`, `cargo deny check`, and
   `./scripts/mutants.sh --working --list` before committing; the last
   one confirms the mutants config still resolves files.

## Reporting the build commit from `--version`

For a binary people install from source (`cargo install --git`, or
`--path`), make `--version` say which commit it was built from when it
is not a tagged release. Three cases: no git available (a crates.io
install) prints the bare crate version; HEAD exactly at the tag
`v<version>` prints the bare version, since that is the release; anything
else prints `<version> (<short sha>)`. No dirty-tree marker: nothing
re-runs the build script on an uncommitted edit, so it would be wrong as
often as right.

Add a `build.rs`:

```rust
fn main() {
    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let build_id = match git_short_sha() {
        Some(sha) if !at_release_tag(&version) => format!("{version} ({sha})"),
        _ => version,
    };
    println!("cargo:rustc-env=CRATE_VERSION_WITH_BUILD={build_id}");

    // Freshness: `.git/HEAD` covers checkouts and branch switches; the
    // branch's ref file covers commits. Use `../../.git` from a workspace
    // member.
    let git_dir = std::path::Path::new(".git");
    if !git_dir.exists() {
        return;
    }
    println!("cargo:rerun-if-changed=.git/HEAD");
    if let Ok(head) = std::fs::read_to_string(git_dir.join("HEAD"))
        && let Some(reference) = head.strip_prefix("ref: ")
        && git_dir.join(reference.trim()).exists()
    {
        println!("cargo:rerun-if-changed=.git/{}", reference.trim());
    }
}

fn git_short_sha() -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let sha = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (!sha.is_empty()).then_some(sha)
}

fn at_release_tag(version: &str) -> bool {
    std::process::Command::new("git")
        .args(["describe", "--exact-match", "--tags", "HEAD"])
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .is_some_and(|tag| tag.trim() == format!("v{version}"))
}
```

With clap derive: `#[command(version = env!("CRATE_VERSION_WITH_BUILD"))]`.

Test the shape, not the environment, so the same test passes in a dev
checkout and in a tagged release build: the output starts with
`CARGO_PKG_VERSION`, and any suffix matches exactly ` (<7+ hex digits>)`.

## Release ceremony (final step — cut vX.Y.Z)

Only run this after every box above is checked and your first feature PR has merged.

1. Promote `## [Unreleased]` in `CHANGELOG.md` to `## [X.Y.Z] - YYYY-MM-DD` (use today's date); leave a fresh `## [Unreleased]` above it for future work.
2. Update the compare links at the bottom of `CHANGELOG.md`:
   - Change `[Unreleased]` to `https://github.com/OWNER/REPO/compare/vX.Y.Z...HEAD`.
   - Add `[X.Y.Z]: https://github.com/OWNER/REPO/releases/tag/vX.Y.Z`.
3. Update the version in `Cargo.toml` to `X.Y.Z`.
4. Remove this file — you won't need it again: `git rm SETUP.md`.
5. Commit, tag, push:
   ```bash
   git add Cargo.toml CHANGELOG.md
   git commit -m "Release vX.Y.Z"
   git tag vX.Y.Z
   git push origin main --tags
   ```
6. Watch the Release workflow. On success, verify end-to-end:
   ```bash
   cargo install <crate> && <crate> --version
   ```
