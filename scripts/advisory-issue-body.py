#!/usr/bin/env python3
"""Renders the advisory monitor's tracking-issue body.

Usage: advisory-issue-body.py OLD_BODY REPORT OUT COMMENT

OLD_BODY is the open issue's body (an empty file when there is none) and
REPORT is check-advisories.sh's output. Writes the new body to OUT and
prints what an open issue needs:

  changed    the findings changed; edit the body and post COMMENT, which
             lists the findings that came and went and links the run log
             named by $RUN_URL, so watchers are told
  refreshed  the same findings, reported differently; edit the body only
  unchanged  leave the issue alone

With no open issue, the caller opens one with OUT whatever this prints.

The workflow owns the body and rewrites it whole on every run, so triage
notes go in comments. Findings are compared by identity, not text: cargo
deny quotes Cargo.lock line numbers, which move with every dependency
bump, and a comment for each would notify watchers about nothing.
"""

import os
import re
import sys

INTRO = """An advisory that is not in `deny.toml`'s `[advisories].ignore` is
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

The monitor rewrites this description on every run, so an edit to it is
lost. Put triage notes in comments.

"""

FOOTER = "\n\n_Maintained automatically by the Security Advisory Monitor workflow._\n"

# GitHub refuses a body or comment over 65536 characters. This leaves
# room for the fence and the run-log line.
LIMIT = 60000
CUT = "(Cut to fit GitHub's size limit; the run log has the full report.)"

# The report has one section per lockfile, headed `## <lockfile>`, and a
# finding is one cargo deny diagnostic in it. The diagnostic's first line,
# its headline, names the check and the crate or advisory title, such as
# `error[unmaintained]: Bincode is unmaintained` (cargo deny runs at
# `--log-level error`, so every diagnostic is an error). Its id is read
# only from its `├ ID:` line, or from a line that is the id alone (as
# `compact()` writes it), since the description cargo deny prints below
# can name other advisories.
TREE = re.compile(r"^## (.*)$")
HEADLINE = re.compile(r"^error\[[a-z-]+\]: .*$")
ID = re.compile(r"^\s*(?:├ ID: )?(RUSTSEC-\d{4}-\d{4})$")

# The report in a body the renderer wrote is its first fenced block.
# `fenced()` makes the fence longer than any run of backticks inside, so
# the first line that repeats it closes the block.
REPORT = re.compile(r"^(`{3,})\n(.*?)\n\1$", re.M | re.S)


def findings(text):
    """Map each finding in `text` to its headline, in report order.

    The key is (lockfile, RUSTSEC id), so an advisory retitled upstream is
    still the same finding, and one that newly affects a second lockfile
    is a new one. A yanked crate has no id and is keyed by its headline
    instead."""
    diagnostics, tree = [], None
    for line in text.splitlines():
        if heading := TREE.match(line):
            tree = heading.group(1)
        elif HEADLINE.match(line):
            diagnostics.append([tree, None, line])
        elif diagnostics and (match := ID.match(line)):
            diagnostics[-1][1] = match.group(1)
    found = {}
    for tree, ident, headline in diagnostics:
        found.setdefault((tree, ident or headline), headline)
    return found


def parts(ident, headline):
    """The lines that show a finding: its headline and its id, or the
    headline alone when it is also the key."""
    return [ident] if ident == headline else [headline, ident]


def compact(report):
    """A shorter report holding only the findings, under their lockfile
    headings, that `findings()` parses back to the same keys. Each finding
    is one item of the list (a blank line, then its lines), so `fit()`
    keeps or drops a finding whole and never separates a headline from its
    id."""
    lines, tree = [], None
    for (entry_tree, ident), headline in findings(report).items():
        if entry_tree != tree:
            tree = entry_tree
            lines.append(f"\n## {tree}" if lines else f"## {tree}")
        lines.append("\n" + "\n".join(parts(ident, headline)))
    return lines


def fit(lines, room):
    """The leading items of `lines` that fit in `room` characters. An item
    may hold several lines."""
    kept, size = [], 0
    for item in lines:
        size += len(item) + 1
        if size > room:
            break
        kept.append(item)
    return kept


def fenced(text):
    """`text` in a code fence longer than any backtick run inside it.
    Advisory text is community-authored, and a title that closed the
    fence would render as markdown, @-mentions and all."""
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}\n{text}\n{fence}"


def section(report, room):
    """The fenced report in at most `room` characters. Past that, only
    the findings are kept, so each one can still be matched next run."""
    report = report.rstrip("\n")
    if len(report) > room:
        report = "\n".join(fit(compact(report), room - len(CUT) - 2) + ["", CUT])
    return fenced(report)


def by_id(found):
    """`found` with the lockfile left out of each key."""
    return {(None, ident): headline for (_, ident), headline in found.items()}


def render(old, report):
    """The new body, the findings resolved since `old`, the findings new
    since `old` (each a dict from key to headline), and the status word."""
    report_section = section(report, LIMIT - len(INTRO) - len(FOOTER))
    new = INTRO + report_section + FOOTER
    if new == old:
        return old, {}, {}, "unchanged"
    # Text outside the old report's fence, such as a note someone added,
    # is not read for findings. A body with no fence has none.
    written = REPORT.search(old)
    was = findings(written.group(2) if written else "")
    shown, live = findings(report_section), findings(report)
    # A body written before the report had lockfile headings has no
    # lockfile in its keys. Compare it by id alone, or the first run on the
    # new renderer posts a comment listing every finding as both new and
    # resolved.
    if was and all(tree is None for tree, _ in was):
        shown, live = by_id(shown), by_id(live)
    # A finding is resolved only when it is gone from the full report, not
    # when the size cut left it out of the body. A finding is new when the
    # body shows it and the old body did not; one left out by the cut is
    # not counted, since nothing says whether the old body had it.
    resolved = {key: was[key] for key in was.keys() - live.keys()}
    found = {key: shown[key] for key in shown.keys() - was.keys()}
    return new, resolved, found, "changed" if resolved or found else "refreshed"


def comment(resolved, new, run_url):
    def label(tree, ident, headline):
        text = ident if ident == headline else f"{ident} ({headline})"
        return f"{tree}: {text}" if tree else text

    def listing(heading, items):
        if not items:
            return []
        lines = [label(*key, items[key]) for key in sorted(items, key=str)]
        kept = fit(lines, LIMIT // 2)
        if len(kept) < len(lines):
            kept += ["", f"({len(lines) - len(kept)} more not shown)"]
        return [f"{heading}:", fenced("\n".join(kept)), ""]

    log = f"The issue body has the new report, and [the run log]({run_url}) has it in full." if run_url else ""
    return "\n".join(["The advisory findings changed.", "", *listing("New", new), *listing("Resolved", resolved), log])


def main(old_path, report_path, out_path, comment_path):
    # Text mode turns the CRLF endings of a body saved from GitHub's web
    # editor into LF, so an untouched report still compares equal.
    with open(old_path) as f:
        old = f.read()
    with open(report_path) as f:
        report = f.read()
    body, resolved, new, status = render(old, report)
    with open(out_path, "w") as f:
        f.write(body)
    with open(comment_path, "w") as f:
        f.write(comment(resolved, new, os.environ.get("RUN_URL", "")))
    print(status)


if __name__ == "__main__":
    main(*sys.argv[1:5])
