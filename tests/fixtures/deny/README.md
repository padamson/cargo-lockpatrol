# cargo-deny JSON fixtures

What `cargo deny --format json --log-level warn --color never --workspace
--config <deny.toml> --manifest-path Cargo.toml check advisories` writes to
stderr, captured from cargo-deny 0.20.2. `check` runs at `--log-level warn`
because an unused ignore is a warning at cargo-deny's default level. The
files dated 2026-11-07 were captured at `--log-level error`; on 2026-11-11
each scenario was run again at both levels, and each wrote the same JSON at
both, equal to its file here but for the timestamps and paths. cargo-deny
promises no stability for its JSON, so these files are what notice a format
change: regenerate them with a new cargo-deny and see which tests fail.

Each comes from a scratch binary crate `fx`. Absolute paths were rewritten
to `/home/runner/work/my-project/my-project`.

| File | Dependencies | deny.toml `[advisories]` | Exit |
|---|---|---|---|
| `clean.jsonl` | none | `version = 2` | 0 |
| `unmaintained.jsonl` | `bincode = "=1.3.3"` | `version = 2` | 1 |
| `vulnerability.jsonl` | `smallvec = "=1.6.0"` | `version = 2` | 1 |
| `two-advisories.jsonl` | both of the above | `version = 2` | 1 |
| `yanked.jsonl` | `smallvec` at 1.4.0 (`cargo update --precise`) | `yanked = "deny"`, `ignore = ["RUSTSEC-2021-0003"]` | 1 |
| `unused-ignores-warn.jsonl` | none | `ignore = ["RUSTSEC-2020-0001", { id = "RUSTSEC-2021-0003", reason = "x" }]`, run at `--log-level warn` | 0 |
| `unused-ignores-deny.jsonl` | none | `unused-ignored-advisory = "deny"`, `ignore = ["RUSTSEC-2020-0001", { crate = "smallvec@1.4.0", reason = "y" }]`, run at `--log-level warn` | 1 |
| `index-failure.jsonl` | `smallvec` at 1.4.0 | `yanked = "deny"`, `unused-ignored-advisory = "deny"`, `ignore = ["RUSTSEC-2021-0003", { crate = "smallvec@1.4.0", reason = "y" }]`, with no registry index to read (below) | 1 |
| `config-error.jsonl` | both | a misspelt key, `ignroe = []`, in a file named `bad.toml` | 1 |
| `missing-manifest.jsonl` | none | `--manifest-path nope/Cargo.toml` | 1 |
| `stale-lock.jsonl` | `smallvec = "=1.6.0"` added after the lock was generated | `version = 2`, run with `--locked` | 1 |

`unmaintained.jsonl` and `vulnerability.jsonl` are the two diagnostics of
`two-advisories.jsonl`, each with the summary's error count set to 1.

`index-failure.jsonl` is a run that could not ask the registry whether a
crate is yanked. cargo-deny reads the index from the cache under
`$CARGO_HOME`, so the run had `CARGO_HOME` set to a directory holding only a
copy of `advisory-dbs` and an empty `.package-cache`, `--offline`, and
`CARGO` set to a script that runs the real cargo with the real `CARGO_HOME`,
so that `cargo metadata` still worked.
