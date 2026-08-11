//! `air_test_harness` -- exercises the real, unmodified `title_air` crate
//! (from `../../air`, the actual production AIR) against the real
//! `winterfell` 0.13.1 crate. Trace-building, full-honest-trace, tamper,
//! and fuzz checks live here as ordinary `#[test]`s so `cargo test` covers
//! them; `src/bin/{e2e_harness,fuzz_harness}.rs` are thin, human-readable
//! wrappers around the same functions.
//!
//! This crate used to depend on a hand-written `facade` crate that
//! reimplemented a slice of winterfell's public API (real `f128` field
//! arithmetic, but hand-rolled `Air`/`AirContext`/etc. scaffolding) so it
//! could build without network access or a modern-enough toolchain. That
//! shim is gone: with a real toolchain (edition2024-capable) and crates.io
//! access, there's no reason to test against a reimplementation when the
//! genuine crate is one `cargo build` away -- a shim can only prove the
//! AIR is compatible with someone's understanding of winterfell's API, not
//! with winterfell itself.

pub use title_air::*;

pub mod e2e_support;
pub mod fuzz_support;
