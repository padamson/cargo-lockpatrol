# Renderer fixtures

A tracking-issue body in the format of `rust-project-template`'s advisory
monitor, and the report it holds. Repositories made from the template have
open issues in this format, so `render` must read this body as the same
findings: a repository that switches to cargo-lockpatrol then sees its
issue refreshed rather than every finding announced as new.

| File | What it is |
|---|---|
| `template-report.txt` | the report on the scratch crate `fx` with `bincode = "=1.3.3"` and `smallvec = "=1.6.0"` (the tree behind `../deny/two-advisories.jsonl`), from cargo-deny 0.20.2 |
| `template-body.md` | the issue body for that report |

Absolute paths are rewritten to `/home/runner/work/my-project/my-project`.
Both files are the format's exact bytes, so edit neither;
`.gitattributes` keeps them that way on every checkout.
