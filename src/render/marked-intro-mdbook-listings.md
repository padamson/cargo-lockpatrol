An advisory that is not in `deny.toml`'s `[advisories].ignore` is
affecting a tree the Security & Quality gate checks, so the next push or
scheduled run will go red.

Triage each one:
- **Fix available**: bump the crate (`cargo update -p <crate>`, plus
  `--manifest-path` when the report names a lockfile outside the root),
  or bump the parent that pins it.
- **No fix / upstream-blocked**: accept the risk and add the
  `RUSTSEC-…` id, with a rationale, to **both** ignore lists: `deny.toml`
  `[advisories].ignore`, which this monitor and the `cargo deny` gates
  read, and `.cargo/audit.toml`, which the `cargo audit` gate and hook
  read. One without the other leaves a gate red.
