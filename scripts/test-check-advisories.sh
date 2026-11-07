#!/usr/bin/env bash
#
# Self-test for check-advisories.sh and advisory-issue-body.py, the two
# halves of advisory-monitor.yml.
#
# The monitor runs on a schedule nobody watches, so a classifier that calls
# a hit "broken" fails one job and files nothing, and one that calls a
# fetch error a hit files an issue about the network. A stub `cargo` on
# PATH replays real cargo-deny 0.20 output, and that output is what pins
# the classifier to the format it was written against. The checker runs
# from a scratch repo with a root and two nested lockfiles, so the tree
# list is tested as well. The renderer cases pin when watchers get a
# comment, and that the body always fits on GitHub.

set -euo pipefail

# A pre-commit hook inherits GIT_INDEX_FILE and friends from the commit
# that runs it, and the git calls below would then write the scratch
# repo's files into that commit's index.
# shellcheck disable=SC2046
unset $(git rev-parse --local-env-vars)

here=$(cd "$(dirname "$0")" && pwd)
renderer="$here/advisory-issue-body.py"
# An explicit template: BSD mktemp does not take TMPDIR into account for a
# bare `-d`, so leaving it out puts the fixtures somewhere macOS may refuse.
work=$(mktemp -d "${TMPDIR:-/tmp}/check-advisories-test.XXXXXX")
trap 'rm -rf "$work"' EXIT
mkdir "$work/bin" "$work/fx"

# The checker resolves the repo from its own path, so it runs as a copy
# inside a repo whose tracked lockfiles the test controls. The untracked
# one stands in for a stray build tree, and oldCargo.lock for a fixture
# whose name only ends in Cargo.lock; no gate should read either. git
# quotes a non-ASCII path unless asked not to, so one tree has such a name.
repo="$work/repo"
mkdir -p "$repo/scripts" "$repo/fuzz" "$repo/naïve" "$repo/scratch"
# As the checker's own `cd` spells it: a TMPDIR with a trailing slash
# leaves a `//` in "$work" that `cd` drops.
repo=$(cd "$repo" && pwd)
cp "$here/check-advisories.sh" "$repo/scripts/"
checker="$repo/scripts/check-advisories.sh"
touch "$repo/Cargo.lock" "$repo/fuzz/Cargo.lock" "$repo/fuzz/oldCargo.lock" "$repo/naïve/Cargo.lock" "$repo/scratch/Cargo.lock"
git -C "$repo" init -q
git -C "$repo" add Cargo.lock fuzz/Cargo.lock fuzz/oldCargo.lock naïve/Cargo.lock

# Replays the root fixture for the root manifest and the nested fixture
# for any other. It reads stdin dry, as a git fetch for a git dependency
# can, so a checker that shares its lockfile list with cargo deny's stdin
# checks one tree and drops the rest.
cat > "$work/bin/cargo" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "$STUB_DIR/calls"
cat > /dev/null
[ "$1" = deny ] || { echo "stub cargo: unexpected subcommand: $*" >&2; exit 99; }
fx=$STUB_NESTED
while [ $# -gt 0 ]; do
    if [ "$1" = --manifest-path ] && [ "$2" = Cargo.toml ]; then fx=$STUB_ROOT; fi
    shift
done
cat "$STUB_DIR/fx/$fx.out"
exit "$(cat "$STUB_DIR/fx/$fx.code")"
STUB
chmod +x "$work/bin/cargo"

fixture() {
    printf '%s\n' "$2" > "$work/fx/$1.code"
    cat > "$work/fx/$1.out"
}

fixture clean 0 <<'OUT'
advisories ok
OUT

fixture hit 1 <<'OUT'
error[unmaintained]: Bincode is unmaintained
   ┌─ /home/runner/work/my-project/my-project/Cargo.lock:13:1
   │
13 │ bincode 1.3.3 registry+https://github.com/rust-lang/crates.io-index
   │ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ unmaintained advisory detected
   │
   ├ ID: RUSTSEC-2025-0141
   ├ Advisory: https://rustsec.org/advisories/RUSTSEC-2025-0141
   ├ Solution: No safe upgrade is available!
   ├ bincode v1.3.3
     └── syntect v5.3.0

advisories FAILED
OUT

fixture vulnerability 1 <<'OUT'
error[vulnerability]: Buffer overflow in SmallVec::insert_many
   ┌─ /home/runner/work/my-project/my-project/fuzz/Cargo.lock:20:1
   │
20 │ smallvec 1.6.0 registry+https://github.com/rust-lang/crates.io-index
   │ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ security vulnerability detected
   │
   ├ ID: RUSTSEC-2021-0003
   ├ Advisory: https://rustsec.org/advisories/RUSTSEC-2021-0003
   ├ Solution: Upgrade to >=0.6.14, <1.0.0 OR >=1.6.1 (try `cargo update -p smallvec`)
   ├ smallvec v1.6.0
     └── my-project-fuzz v0.0.0

advisories FAILED
OUT

cat "$work/fx/hit.out" "$work/fx/vulnerability.out" | fixture both 1

# A yanked crate's diagnostic, which has no RUSTSEC id, followed by an
# advisory's diagnostic, which has one.
cat - "$work/fx/hit.out" <<'OUT' | fixture yanked 1
error[yanked]: detected yanked crate (try `cargo update -p foo`)
   ┌─ /home/runner/work/my-project/my-project/Cargo.lock:9:1
   │
 9 │ foo 0.1.0 registry+https://github.com/rust-lang/crates.io-index
   │ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ yanked version
   │
   ├ foo v0.1.0
     └── my-project v0.1.0

OUT

# An advisory's description, as cargo deny prints it below the `ID:`
# line, with a paragraph break and another advisory named.
awk '{ print } /├ ID: RUSTSEC-2025-0141/ {
        print "   ├ Development has ceased."
        print "    "
        print "    It supersedes RUSTSEC-2020-0071 for this crate." }' "$work/fx/hit.out" | fixture described 1

fixture broken 1 <<'OUT'
2026-10-10 14:12:54 [ERROR] failed to acquire advisory database lock: failed to obtain lock file '/nonexistent/advisory-dbs': failed to create parent directories for lock path
OUT

# A typo in deny.toml: same diagnostic shape as a finding, but no advisory.
fixture config-error 1 <<'OUT'
error[unexpected-keys]: found 1 unexpected keys, expected: ["version", "db-path", "db-urls", "vulnerability", "notice", "unmaintained", "unsound", "yanked", "ignore", "severity-threshold", "git-fetch-with-cli", "disable-yank-checking", "maximum-db-staleness", "unused-ignored-advisory"]
  ┌─ /home/runner/work/my-project/my-project/deny.toml:2:1
  │
2 │ ignroe = []
  │ ──────

2026-10-10 14:28:34 [ERROR] failed to deserialize config from '/home/runner/work/my-project/my-project/deny.toml'
OUT

failures=0

# fail NAME [CONTEXT_FILE]: report a failed check, indenting the context.
fail() {
    echo "FAIL: $1"
    if [ -n "${2:-}" ]; then sed 's/^/    /' "$2" | head -n 20; fi
    failures=$((failures + 1))
}

# run ROOT NESTED, then expect NAME STATUS TEXT against its result. An
# empty TEXT asserts the report is empty.
run() {
    : > "$work/calls"
    status=0
    PATH="$work/bin:$PATH" STUB_DIR="$work" STUB_ROOT="$1" STUB_NESTED="$2" \
        "$checker" > "$work/out" 2> "$work/stderr" < /dev/null || status=$?
}

expect() {
    local name="$1" status_want="$2" text="$3"
    if [ "$status" -ne "$status_want" ]; then
        cat "$work/out" "$work/stderr" > "$work/context"
        fail "$name: exit $status, expected $status_want" "$work/context"
    elif [ -z "$text" ] && [ -s "$work/out" ]; then
        fail "$name: expected an empty report" "$work/out"
    elif [ -n "$text" ] && ! grep -qF -- "$text" "$work/out"; then
        fail "$name: report did not contain '$text'" "$work/out"
    else
        echo "ok: $name"
    fi
}

run clean clean
expect "every tree clean is clean" 0 ""
if [ "$(grep -cF -- "--log-level error --color never --workspace --config $repo/deny.toml --manifest-path " "$work/calls")" -eq 3 ]; then
    echo "ok: every call is quiet, whole-workspace, and reads the root deny.toml"
else
    fail "a call was missing the quiet, workspace or root-config flags" "$work/calls"
fi
if [ "$(wc -l < "$work/calls")" -eq 3 ] &&
    grep -qx -- '.*--manifest-path Cargo.toml .*' "$work/calls" &&
    grep -qx -- '.*--manifest-path fuzz/Cargo.toml .*' "$work/calls" &&
    grep -qx -- '.*--manifest-path naïve/Cargo.toml .*' "$work/calls" &&
    ! grep -qE 'scratch|oldCargo' "$work/calls"; then
    echo "ok: one cargo deny per tracked Cargo.lock, named as it is on disk, and none for an untracked or merely similar one"
else
    fail "expected one cargo deny per tracked lockfile" "$work/calls"
fi

run hit clean
expect "a root diagnostic is a hit" 1 "RUSTSEC-2025-0141"
expect "and the report names the lockfile" 1 "## cargo deny check advisories (Cargo.lock)"
# The renderer cases below read the checker's own reports, so a change to
# its format reaches them.
cp "$work/out" "$work/report.txt"

run clean vulnerability
expect "a nested lockfile's diagnostic is a hit" 1 "RUSTSEC-2021-0003"
expect "and the report names that lockfile" 1 "## cargo deny check advisories (fuzz/Cargo.lock)"

run broken clean
expect "a failure without a diagnostic is broken, with no report" 2 ""

run config-error clean
expect "a deny.toml error is broken, not an advisory" 2 ""

run hit broken
expect "a hit beside a broken tree is still filed, and the job told" 3 "RUSTSEC-2025-0141"

run hit vulnerability
cp "$work/out" "$work/more.txt"
run both both
cp "$work/out" "$work/spread.txt"

run yanked clean
expect "a yanked crate is a hit" 1 "error[yanked]: detected yanked crate"
cp "$work/out" "$work/yanked.txt"

run described clean
cp "$work/out" "$work/described.txt"

git -C "$repo" rm -q --cached Cargo.lock fuzz/Cargo.lock naïve/Cargo.lock
run clean clean
expect "no tracked Cargo.lock is broken, not clean" 2 ""

# render OLD_BODY_FILE REPORT_FILE, then rendered NAME STATUS TEXT. TEXT
# is a line the new body must contain.
render() {
    status_out=$(RUN_URL=https://example.invalid/run "$renderer" "$1" "$2" "$work/body.txt" "$work/comment.txt")
}

# commented NAME TEXT...: each TEXT is a line the comment must contain.
commented() {
    local name="$1" text
    shift
    for text in "$@"; do
        if ! grep -qF -- "$text" "$work/comment.txt"; then
            fail "$name: comment did not contain '$text'" "$work/comment.txt"
            return
        fi
    done
    echo "ok: $name"
}

# lacks NAME FILE TEXT: passes when FILE exists and does not contain
# TEXT. `grep -q` exits non-zero both for no match and for a missing file,
# so the file's existence is checked first.
lacks() {
    if [ ! -f "$2" ]; then
        fail "$1: $(basename "$2") was not written"
    elif grep -qF -- "$3" "$2"; then
        fail "$1: $(basename "$2") contained '$3'" "$2"
    else
        echo "ok: $1"
    fi
}

# fits NAME: the body is under GitHub's 65536-character limit.
fits() {
    local size
    size=$(wc -m < "$work/body.txt")
    if [ "$size" -lt 65536 ]; then
        echo "ok: $1"
    else
        fail "$1: body is $size characters"
    fi
}

# trees N: the one-finding report repeated N times, copy i under
# crates/ci/Cargo.lock. One awk, not N seds.
trees() {
    awk -v n="$1" '{ line[NR] = $0 }
        END { for (i = 1; i <= n; i++) for (j = 1; j <= NR; j++) {
            l = line[j]; sub(/\(Cargo\.lock\)/, "(crates/c" i "/Cargo.lock)", l); print l } }' "$work/report.txt"
}

rendered() {
    local name="$1" want="$2" text="$3"
    if [ "$status_out" != "$want" ]; then
        fail "$name: rendered as '$status_out', expected '$want'"
    elif ! grep -qF -- "$text" "$work/body.txt"; then
        fail "$name: body did not contain '$text'" "$work/body.txt"
    else
        echo "ok: $name"
    fi
}

: > "$work/empty.txt"
render "$work/empty.txt" "$work/report.txt"
rendered "a first report carries the triage steps" changed "Triage each one:"
cp "$work/body.txt" "$work/opened.txt"

render "$work/opened.txt" "$work/report.txt"
rendered "the same report leaves the issue alone" unchanged "RUSTSEC-2025-0141"

sed 's/$/\r/' "$work/opened.txt" > "$work/crlf.txt"
render "$work/crlf.txt" "$work/report.txt"
rendered "a body saved with CRLF endings is still unchanged" unchanged "RUSTSEC-2025-0141"

sed 's/Cargo\.lock:13:1/Cargo.lock:17:1/; s/^13 │/17 │/' "$work/report.txt" > "$work/moved.txt"
render "$work/opened.txt" "$work/moved.txt"
rendered "a finding whose lockfile line moved refreshes without a comment" refreshed "Cargo.lock:17:1"

# Upstream can retitle an advisory. Findings are matched by RUSTSEC id,
# so a new title alone only refreshes the body.
sed 's/Bincode is unmaintained/Bincode is no longer maintained/' "$work/report.txt" > "$work/retitled.txt"
render "$work/opened.txt" "$work/retitled.txt"
rendered "a retitled advisory refreshes without a comment" refreshed "Bincode is no longer maintained"

# cargo deny prints each advisory's description below its `ID:` line,
# with whitespace-only lines between paragraphs, and the text can name
# other advisories. Only the `ID:` line names the finding.
render "$work/opened.txt" "$work/described.txt"
rendered "an advisory's description is not a finding" refreshed "It supersedes RUSTSEC-2020-0071"

# A yanked crate has no id, so it is matched by its headline.
render "$work/empty.txt" "$work/yanked.txt"
cp "$work/body.txt" "$work/yanked-opened.txt"
render "$work/yanked-opened.txt" "$work/report.txt"
rendered "a yanked crate that is fixed is a change" changed "RUSTSEC-2025-0141"
commented "and the comment names it as resolved by its headline" "Resolved:" "error[yanked]: detected yanked crate"

render "$work/opened.txt" "$work/more.txt"
rendered "a new finding is a change" changed "RUSTSEC-2021-0003"
commented "and the comment names it by id and title, and links the run log" \
    "New:" "cargo deny check advisories (fuzz/Cargo.lock): RUSTSEC-2021-0003 (error[vulnerability]: Buffer overflow in SmallVec::insert_many)" \
    "(https://example.invalid/run)"
cp "$work/body.txt" "$work/more-opened.txt"

render "$work/more-opened.txt" "$work/report.txt"
rendered "a finding that went away is a change" changed "RUSTSEC-2025-0141"
commented "and the comment names it as resolved" \
    "Resolved:" "cargo deny check advisories (fuzz/Cargo.lock): RUSTSEC-2021-0003"

# Every heading, title and id in spread.txt is already in more.txt, only
# now each advisory is in both trees.
cp "$work/body.txt" "$work/two-trees.txt"
render "$work/two-trees.txt" "$work/spread.txt"
rendered "a known advisory reaching another lockfile is a change" changed "RUSTSEC-2021-0003"

# An advisory title is community-authored; one holding a fence must not
# close the report's and render the rest as markdown.
sed 's/Bincode is unmaintained/Bincode ``` is unmaintained/' "$work/report.txt" > "$work/backticks.txt"
render "$work/empty.txt" "$work/backticks.txt"
rendered "a fence in an advisory title gets a longer fence around it" changed '````'
cp "$work/body.txt" "$work/backticks-opened.txt"
render "$work/backticks-opened.txt" "$work/backticks.txt"
rendered "and that body reads back unchanged" unchanged "Bincode \`\`\` is unmaintained"

# A body from before reports named their lockfiles: the same findings,
# with no tree to pair them with.
{ printf '<!-- advisory-report -->\n```\n'; cat "$work/fx/hit.out"; printf '```\n<!-- /advisory-report -->\n'; } > "$work/pre-port.txt"
render "$work/pre-port.txt" "$work/report.txt"
rendered "a body from before lockfile headings, with the same findings, refreshes without a comment" refreshed "## cargo deny check advisories (Cargo.lock)"

trees 400 > "$work/huge.txt"
render "$work/empty.txt" "$work/huge.txt"
rendered "an oversized report keeps its findings and drops the graphs" changed "Cut to fit GitHub's size limit"
fits "and it fits"
rendered "with every lockfile named" changed "## cargo deny check advisories (crates/c400/Cargo.lock)"
cp "$work/body.txt" "$work/huge-opened.txt"
sed 's/Cargo\.lock:13:1/Cargo.lock:17:1/' "$work/huge.txt" > "$work/huge-moved.txt"
render "$work/huge-opened.txt" "$work/huge-moved.txt"
rendered "an oversized report with the same findings leaves the issue alone" unchanged "crates/c1/Cargo.lock"

# The workflow owns the body. A note someone added to it is gone at the
# next update. Findings are read only from the report's fence, so a
# diagnostic pasted from the run log below it is not a finding, and with
# the same findings that update is only a refresh.
{ cat "$work/opened.txt"; printf '\nPasted from the log:\n'; sed -n '/^error\[vulnerability\]/,/├ ID:/p' "$work/fx/vulnerability.out"; } > "$work/noted.txt"
render "$work/noted.txt" "$work/report.txt"
rendered "a body edited by hand is rewritten whole" refreshed "RUSTSEC-2025-0141"
lacks "and the edit is gone" "$work/body.txt" "Pasted from the log:"

printf 'Hand-written body with no report.\n' > "$work/bare.txt"
render "$work/bare.txt" "$work/report.txt"
rendered "a body with no report gains one" changed "RUSTSEC-2025-0141"
commented "and the comment lists its findings as new" "New:" "RUSTSEC-2025-0141"

# Even the findings alone can outgrow the limit; the cut must keep its
# notice and whole lines.
trees 2000 > "$work/enormous.txt"
render "$work/empty.txt" "$work/enormous.txt"
rendered "findings past the limit are cut, and the cut says so" changed "Cut to fit GitHub's size limit"
fits "and it fits"
cp "$work/body.txt" "$work/enormous-opened.txt"

# A new finding at the front pushes the last ones past the cut; they are
# still live, so nothing is announced as resolved.
{ sed 's|(fuzz/Cargo.lock)|(crates/c0/Cargo.lock)|' "$work/more.txt" | sed -n '/(crates\/c0\/Cargo.lock)/,/advisories FAILED/p'
  printf '\n'; cat "$work/enormous.txt"; } > "$work/enormous-more.txt"
render "$work/enormous-opened.txt" "$work/enormous-more.txt"
rendered "a new finding in a cut report is a change" changed "RUSTSEC-2021-0003"
commented "and the comment names it" "crates/c0/Cargo.lock): RUSTSEC-2021-0003"
lacks "and findings pushed past the cut are not called resolved" "$work/comment.txt" "Resolved:"

# Wherever the size cut falls, it keeps or drops each finding whole
# (headline and id together): a headline kept without its id reads as a
# new finding and posts a comment. Every room from 0 to the report's full
# length is tried, in one Python process, since starting one per room is
# slow. -B keeps Python from writing a __pycache__ beside the renderer.
split_at=$(python3 -I -B - "$renderer" "$work/spread.txt" "$work/yanked.txt" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("renderer", sys.argv[1])
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)
for path in sys.argv[2:]:
    report = open(path).read()
    live = renderer.findings(report).keys()
    bad = [room for room in range(len(report)) if not renderer.findings(renderer.section(report, room)).keys() <= live]
    if bad:
        print(path, *bad[:5])
PY
)
if [ -z "$split_at" ]; then
    echo "ok: no cut point shows a finding the full report lacks"
else
    fail "a cut showed a finding the full report lacks (report, then rooms): $split_at"
fi

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed"
    exit 1
fi
echo "all checks passed"
