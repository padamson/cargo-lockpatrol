An advisory that is not in an ignore list is affecting a tree one of
the Security & Quality gates checks, so the next push or scheduled run
will go red.

Triage each one:
- **Fix available**: bump the crate (`cargo update -p <crate>`, plus
  `--manifest-path` for `crates/site`, `crates/site-e2e` or
  `crates/playwright/fuzz`), or bump the parent that pins it.
- **No fix / upstream-blocked**: accept the risk and add the
  `RUSTSEC-…` id, with a rationale, to the ignore list of each gate
  that reports it: `deny.toml` `[advisories].ignore` for
  `cargo deny`, and `.cargo/audit.toml` `[advisories].ignore` (create
  it if absent) for `scripts/audit-lockfiles.sh`. A vulnerability in
  the workspace tree is reported by both.
