//! Runs `cargo deny check advisories` over every git-tracked `Cargo.lock`
//! against one `deny.toml`, and tells a finding from a broken check.
//!
//! The binary is `cargo-lockpatrol`, run as `cargo lockpatrol check`. Its
//! exit code is the contract a CI gate, a pre-commit hook and a scheduled
//! monitor all read:
//!
//! | Exit | Meaning |
//! |---|---|
//! | 0 | every tree clean |
//! | 1 | an advisory in some tree |
//! | 2 | a check broke without reporting one, no `Cargo.lock` is tracked, or the `deny.toml` is missing |
//! | 3 | both: one tree found an advisory and another broke |
//! | 4, 5 | 0 or 1, and `deny.toml` denies unused ignore entries, one of which matches nothing in any tree |
//!
//! [`deny`] reads one cargo-deny run; [`check`] finds the trees and runs
//! cargo-deny on each; [`render`] turns a report and a tracking issue's
//! old body into its new body and a comment.

pub mod check;
pub mod deny;
pub mod render;

/// The cargo-deny JSON captured in tests/fixtures/deny, shared by the unit
/// tests of both modules.
#[cfg(test)]
mod fixtures {
    pub const CLEAN: &str = include_str!("../tests/fixtures/deny/clean.jsonl");
    pub const UNMAINTAINED: &str = include_str!("../tests/fixtures/deny/unmaintained.jsonl");
    pub const VULNERABILITY: &str = include_str!("../tests/fixtures/deny/vulnerability.jsonl");
    pub const TWO: &str = include_str!("../tests/fixtures/deny/two-advisories.jsonl");
    pub const YANKED: &str = include_str!("../tests/fixtures/deny/yanked.jsonl");
    pub const UNUSED_WARN: &str = include_str!("../tests/fixtures/deny/unused-ignores-warn.jsonl");
    pub const UNUSED_DENY: &str = include_str!("../tests/fixtures/deny/unused-ignores-deny.jsonl");
    pub const INDEX_FAILURE: &str = include_str!("../tests/fixtures/deny/index-failure.jsonl");
    pub const CONFIG_ERROR: &str = include_str!("../tests/fixtures/deny/config-error.jsonl");
    pub const MISSING_MANIFEST: &str =
        include_str!("../tests/fixtures/deny/missing-manifest.jsonl");
    pub const STALE_LOCK: &str = include_str!("../tests/fixtures/deny/stale-lock.jsonl");

    /// The first line of `fixture`, a diagnostic in each that this is
    /// called with.
    pub fn first(fixture: &str) -> &str {
        fixture.lines().next().expect("fixture has a first line")
    }

    pub fn ignore(entry: &str, denied: bool) -> crate::deny::UnusedIgnore {
        crate::deny::UnusedIgnore {
            entry: entry.into(),
            denied,
        }
    }
}
