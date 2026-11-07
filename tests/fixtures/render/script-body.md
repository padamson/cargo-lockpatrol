An advisory that is not in `deny.toml`'s `[advisories].ignore` is
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

```
## cargo deny check advisories (Cargo.lock)

error[unmaintained]: Bincode is unmaintained
  ┌─ /home/runner/work/my-project/my-project/Cargo.lock:1:1
  │
1 │ bincode 1.3.3 registry+https://github.com/rust-lang/crates.io-index
  │ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ unmaintained advisory detected
  │
  ├ ID: RUSTSEC-2025-0141
  ├ Advisory: https://rustsec.org/advisories/RUSTSEC-2025-0141
  ├ Due to a doxxing and harassment incident, the bincode team has taken the decision to cease development permanently.
    
    The team considers version 1.3.3 a complete version of bincode that is not in need of any updates.
    
    ## Alternatives to consider
    
    * [wincode](https://crates.io/crates/wincode)
    * [postcard](https://crates.io/crates/postcard)
    * [bitcode](https://crates.io/crates/bitcode)
    * [rkyv](https://crates.io/crates/rkyv)
  ├ Announcement: https://git.sr.ht/~stygianentity/bincode/tree/v3.0/item/README.md
  ├ Solution: No safe upgrade is available!
  ├ bincode v1.3.3
    └── fx v0.1.0

error[vulnerability]: Buffer overflow in SmallVec::insert_many
  ┌─ /home/runner/work/my-project/my-project/Cargo.lock:5:1
  │
5 │ smallvec 1.6.0 registry+https://github.com/rust-lang/crates.io-index
  │ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ security vulnerability detected
  │
  ├ ID: RUSTSEC-2021-0003
  ├ Advisory: https://rustsec.org/advisories/RUSTSEC-2021-0003
  ├ A bug in the `SmallVec::insert_many` method caused it to allocate a buffer that was smaller than needed.  It then wrote past the end of the buffer, causing a buffer overflow and memory corruption on the heap.
    
    This bug was only triggered if the iterator passed to `insert_many` yielded more items than the lower bound returned from its `size_hint` method.
     
    The flaw was corrected in smallvec 0.6.14 and 1.6.1, by ensuring that additional space is always reserved for each item inserted.  The fix also simplified the implementation of `insert_many` to use less unsafe code, so it is easier to verify its correctness.
    
    Thank you to Yechan Bae ([@Qwaz](https://github.com/Qwaz)) and the Rust group at Georgia Tech’s SSLab for finding and reporting this bug.
  ├ Announcement: https://github.com/servo/rust-smallvec/issues/252
  ├ Solution: Upgrade to >=0.6.14, <1.0.0 OR >=1.6.1 (try `cargo update -p smallvec`)
  ├ smallvec v1.6.0
    └── fx v0.1.0

advisories FAILED
```

_Maintained automatically by the Security Advisory Monitor workflow._
