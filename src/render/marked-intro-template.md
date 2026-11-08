An advisory that is not in `deny.toml`'s `[advisories].ignore` is
affecting a tree the Security & Quality gate checks, so the next push or
scheduled run will go red.

Triage each one:
- **Fix available**: bump the crate (`cargo update -p <crate>`, plus
  `--manifest-path` when the report names a lockfile outside the root),
  or bump the parent that pins it.
- **No fix / upstream-blocked**: accept the risk and add the
  `RUSTSEC-…` id to `deny.toml`'s ignore list, with a rationale. That
  list is the only one; CI, the pre-commit hook and this monitor all
  read it, for every lockfile.
