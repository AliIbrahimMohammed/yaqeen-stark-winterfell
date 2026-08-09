# Reproducible test harness

Reproduces the "real end-to-end AIR behavioral test" section of the test
report. Requires only rustc/cargo (any recent version, tested here on the
Ubuntu-24.04 system rustc 1.75.0 -- no nightly features used).

    cargo run --bin e2e_harness    # merkle-root cross-check, constraint check,
                                    # assertion check, tamper check, hash() check
    cargo run --bin fuzz_harness   # 256 arbitrary-data row-transitions, panic/OOB check
    cargo test -p title_air --lib  # the crate's own unit tests

`air_test/src/lib.rs` is a byte-for-byte, unmodified copy of the shipped
`air/src/lib.rs` from `yaqeen-stark-patched.zip` -- diffed against it in
this session to confirm.

`facade/src/lib.rs` is NOT the real `winterfell` crate. It's a minimal
re-implementation of only the parts of the winterfell 0.13.1 public API
that `air/src/lib.rs` actually calls (the `Air` trait, `AirContext`,
`Assertion`, `EvaluationFrame`, `TraceInfo`, `TransitionConstraintDegree`,
and the `FieldElement`/`BaseElement` field arithmetic), built by reading
the real winter-air/winter-math 0.13.1 source (downloaded from
static.crates.io in this session) so the signatures and field arithmetic
match the genuine crate, not guesswork. It does not implement FRI, LDE,
or Merkle commitments, so it cannot generate or verify an actual STARK
proof -- see "What this does NOT prove" in the main report.
