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
//! | 2 | a check broke without reporting one, or no `Cargo.lock` is tracked |
//! | 3 | both: one tree found an advisory and another broke |
//!
//! [`deny`] reads one cargo-deny run; [`check`] finds the trees and runs
//! cargo-deny on each.

pub mod check;
pub mod deny;

/// The cargo-deny JSON captured in tests/fixtures/deny, shared by the unit
/// tests of both modules.
#[cfg(test)]
mod fixtures {
    pub const CLEAN: &str = include_str!("../tests/fixtures/deny/clean.jsonl");
    pub const UNMAINTAINED: &str = include_str!("../tests/fixtures/deny/unmaintained.jsonl");
    pub const VULNERABILITY: &str = include_str!("../tests/fixtures/deny/vulnerability.jsonl");
    pub const TWO: &str = include_str!("../tests/fixtures/deny/two-advisories.jsonl");
    pub const YANKED: &str = include_str!("../tests/fixtures/deny/yanked.jsonl");
    pub const UNUSED_IGNORE: &str = include_str!("../tests/fixtures/deny/unused-ignore.jsonl");
    pub const CONFIG_ERROR: &str = include_str!("../tests/fixtures/deny/config-error.jsonl");
    pub const MISSING_MANIFEST: &str =
        include_str!("../tests/fixtures/deny/missing-manifest.jsonl");
}
