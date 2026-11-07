# Renderer fixtures

What the shell gate this crate replaces wrote, frozen so `render` keeps
reading a tracking issue it opened.

| File | What it is |
|---|---|
| `script-report.txt` | `scripts/check-advisories.sh`'s report on the scratch crate `fx` with `bincode = "=1.3.3"` and `smallvec = "=1.6.0"` (the tree behind `../deny/two-advisories.jsonl`), captured with cargo-deny 0.20.2 on 2026-11-07 |
| `script-body.md` | `scripts/advisory-issue-body.py` on an empty old body and that report: the body such an issue carries |

Absolute paths were rewritten to `/home/runner/work/my-project/my-project`.
The script and the Python renderer are deleted once this repo runs its own
action, so these cannot be regenerated after that; they record a format
that stopped changing.
