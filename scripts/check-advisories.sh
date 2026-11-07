#!/usr/bin/env bash
#
# Runs `cargo deny check advisories` against every tracked Cargo.lock and
# says whether a failure is a finding or a broken tool. It is the advisory
# gate: Security & Quality and the pre-commit hook run it beside `cargo
# deny check bans licenses sources`, and advisory-monitor.yml files an
# issue from its report, so the monitor never reports something no gate
# fails on.
#
# Every tree, not just the root: a crate excluded from the workspace (a
# wasm site, an e2e crate, a cargo-fuzz dir) keeps its own Cargo.lock,
# which a root `cargo deny` never opens. The list comes from git, so a new
# one is covered the commit it lands. Every run is pointed at the root
# deny.toml, so it is the one ignore list for all of them, even beside a
# tree that ships its own.
#
# Prints the report of each tree that found something.
#   0  every tree clean
#   1  an advisory in some tree
#   2  a check failed without reporting one: an advisory-db fetch, cargo
#      metadata, a bad deny.toml. There is nothing to triage, and an
#      issue about a network error would bury the next real one.
#   3  both: one tree found an advisory and another broke. The finding
#      still gets filed, and the job still fails, so a dead check cannot
#      hide behind a live one.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

found=0
broken=0
checked=0

# Files named exactly Cargo.lock, at the root or below; a bare
# '*Cargo.lock' would also match a fixture such as oldCargo.lock. `-z`
# because git C-quotes a path holding a quote or a non-ASCII character,
# and the manifest path built from the quoted form does not exist. The
# list comes in on fd 3, not stdin, so nothing in the loop (cargo deny,
# or a git fetch it starts) can read it dry.
while IFS= read -r -d '' lock <&3; do
    checked=$((checked + 1))
    manifest="${lock%Cargo.lock}Cargo.toml"
    # `--config` because cargo deny otherwise prefers a deny.toml next to
    # the manifest. No `--locked`: a nested tree that path-depends on the
    # root crate goes stale on every root version bump or raised
    # requirement that refreshes only the root lock, and it would turn
    # each one into a red required check. `--workspace` graphs every
    # member, not just the root package and what it depends on.
    # `--log-level error` keeps the advisory-db fetch chatter out of the
    # report (and warn-level advisories with it, which do not fail the
    # check), and `--color never` keeps ANSI codes away from the anchored
    # grep. Only the codes below are findings: a bad
    # deny.toml reports in the same shape (`error[unexpected-keys]`) and
    # is a broken check.
    report=$(cargo deny --log-level error --color never --workspace \
        --config "$PWD/deny.toml" --manifest-path "$manifest" check advisories 2>&1)
    code=$?
    [ "$code" -eq 0 ] && continue
    if grep -qE '^error\[(vulnerability|unmaintained|unsound|notice|yanked)\]' <<<"$report"; then
        found=1
        printf '## cargo deny check advisories (%s)\n\n%s\n\n' "$lock" "$report"
    else
        broken=1
        printf 'cargo deny exited %s on %s without reporting an advisory:\n%s\n' "$code" "$lock" "$report" >&2
    fi
done 3< <(git ls-files -z ':(glob)**/Cargo.lock')

# An empty list would pass every tree by checking none of them.
if [ "$checked" -eq 0 ]; then
    echo "no tracked Cargo.lock to check" >&2
    exit 2
fi

exit $((found + 2 * broken))
