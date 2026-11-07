# cargo-deny JSON fixtures

What `cargo deny --format json --log-level error --color never --workspace
--config <deny.toml> --manifest-path Cargo.toml check advisories` writes to
stderr, captured from cargo-deny 0.20.2 on 2026-11-07. cargo-deny promises
no stability for its JSON, so these files are what notice a format change:
regenerate them with a new cargo-deny and see which tests fail.

Each comes from a scratch binary crate `fx`. Absolute paths were rewritten
to `/home/runner/work/my-project/my-project`.

| File | Dependencies | deny.toml `[advisories]` | Exit |
|---|---|---|---|
| `clean.jsonl` | none | `version = 2` | 0 |
| `unmaintained.jsonl` | `bincode = "=1.3.3"` | `version = 2` | 1 |
| `vulnerability.jsonl` | `smallvec = "=1.6.0"` | `version = 2` | 1 |
| `two-advisories.jsonl` | both of the above | `version = 2` | 1 |
| `yanked.jsonl` | `smallvec` at 1.4.0 (`cargo update --precise`) | `yanked = "deny"`, `ignore = ["RUSTSEC-2021-0003"]` | 1 |
| `unused-ignore.jsonl` | `smallvec` at 1.4.0 | `ignore` adds `RUSTSEC-2020-0001`, `unused-ignored-advisory = "deny"` | 1 |
| `config-error.jsonl` | both | a misspelt key, `ignroe = []`, in a file named `bad.toml` | 1 |
| `missing-manifest.jsonl` | none | `--manifest-path nope/Cargo.toml` | 1 |

`unmaintained.jsonl` and `vulnerability.jsonl` are the two diagnostics of
`two-advisories.jsonl`, each with the summary's error count set to 1.
