# Reproducible test harness

Reproduces the "real end-to-end AIR behavioral test" section of the test
report -- now built against the **real** `winterfell` 0.13.1 crate and the
**real, unmodified** `title_air` crate (`../air`), not a hand-written
stand-in for either.

## Requirements

Unlike earlier versions of this harness, this now needs:

- **Network access to crates.io** (to pull the real `winterfell` 0.13.1
  dependency tree: `winter-air`, `winter-math`, `winter-crypto`,
  `winter-fri`, `winter-prover`, `winter-verifier`, `blake3`, etc.)
- **A modern-enough Rust toolchain.** `winter-crypto`'s `blake3` dependency
  pulls in `cpufeatures 0.3`, which requires the `edition2024` Cargo
  feature -- stabilized in **Rust 1.85** (Feb 2025). Ubuntu 24.04's default
  `apt` `cargo`/`rustc` is 1.75 and is too old; install a newer one, e.g.:

      apt-get install -y rust-1.91-all   # or any rust-1.85+ package apt offers

  and put its `cargo`/`rustc` ahead of the default on `PATH`.

## Running

    cargo test                     # everything below, via plain `cargo test`
    cargo run --bin e2e_harness    # human-readable narrative version of the
                                    # same checks: merkle-root cross-check,
                                    # constraint check, assertion check,
                                    # tamper checks, hash() round-count check
    cargo run --bin fuzz_harness   # longer fuzz pass + a soundness-oriented
                                    # boolean-constraint fuzz check

## Layout

- **`air_test/Cargo.toml`** depends directly on `title_air = { path =
  "../../air" }` (the real, unmodified production AIR crate) and
  `winterfell = "0.13.1"` (the real crate from crates.io -- the exact same
  version `air/Cargo.toml`, `prover/Cargo.toml`, and `canister/Cargo.toml`
  pin). The harness package itself is named `air_test_harness`, not
  `title_air`, so it can't be confused with the real crate it depends on.
- **`air_test/src/lib.rs`** just re-exports `title_air::*` and declares the
  two support modules below -- there is no copy, no `#[path]` trick, no
  facade. `cargo update` in this workspace pulls the same `winterfell`
  release the production crates use.
- **`air_test/src/e2e_support.rs`** -- trace-building support (`SparseTree`,
  `build_trace`, `to_bits_le`, `eval_all_constraints`, `demo_proof_options`),
  each with its own `#[test]`s: an honest trace satisfies every transition
  constraint and every assertion; tampering a public-input-adjacent cell
  breaks its assertion; tampering a mid-permutation row (not just a
  boundary) breaks a transition constraint, which is the property that
  actually matters for soundness.
- **`air_test/src/fuzz_support.rs`** -- a small xorshift64* PRNG plus two
  fuzz checks: `fuzz_no_panics` (robustness: garbage input must not panic
  or index out of bounds) and `fuzz_boolean_violations_are_caught`
  (soundness: a random non-boolean value written into a boolean-constrained
  column must actually produce a nonzero constraint, not just "not panic").
- **`air_test/src/bin/{e2e_harness,fuzz_harness}.rs`** -- thin binaries that
  call the library functions above and print a human-readable pass/fail
  report. Every check they print has a matching `#[test]`; they exist for
  a readable narrative, not as the only place these properties are checked.

## What changed from the earlier `facade`-based version

This harness used to depend on a hand-written `facade` crate (deleted) that
reimplemented a slice of winterfell's public API -- real `f128` field
arithmetic, but hand-rolled `Air`/`AirContext`/`ProofOptions`/`Assertion`/
etc. scaffolding -- so it could build without network access or a
modern-enough toolchain. That shim is gone. A facade can only prove the AIR
is compatible with someone's *understanding* of winterfell's API; it can't
prove compatibility with winterfell itself, and it duplicates a second copy
of nontrivial field arithmetic that then also needs its own test coverage
just to be trustworthy as ground truth. With a real toolchain and crates.io
access, there's no reason to accept that weaker guarantee.

Swapping in the real crate surfaced real API differences the facade had
been hiding (all fixed, all covered by the tests above):

- Real `BaseElement::ZERO`/`::ONE` come from the `FieldElement` trait, not
  inherent consts on `BaseElement` -- every call site needs
  `use winterfell::math::FieldElement;` in scope.
- Real `ProofOptions` is a full STARK-parameter struct (`num_queries`,
  `blowup_factor`, `grinding_factor`, FRI folding/remainder degree,
  constraint/DEEP batching method) constructed via `ProofOptions::new(..)`,
  not a unit struct. See `e2e_support::demo_proof_options()`.
- Real `Assertion` has private fields with `.column()`/`.first_step()`/
  `.values()` accessor methods (and supports multi-value/strided
  assertions via `.values()` returning a slice), not public
  `.column`/`.first_step`/`.value` fields.

## Known findings from this pass

- **Facade division-by-zero (moot now -- the facade is gone).** The old
  `facade`'s `BaseElement::inv(0)` used to return `0` silently instead of
  erroring. Not applicable anymore since real `winterfell`'s field
  arithmetic is used directly, but noted here for history.
- **`hash()` has no length domain separation (documented, not changed).**
  `hash(&[1])` and `hash(&[1, 0])` collide, because unused lanes are
  zero-padded with no length tag. This is safe today only because every
  call site uses a fixed, hard-coded arity per domain tag -- see the
  extended doc comment on `hash()` in `air/src/lib.rs` for why a length
  tag can't simply be added (it would break byte-identity with the AIR's
  own in-circuit job-boundary logic). Pinned down as a regression test
  (`hash_implicitly_pads_and_does_not_length_separate`, in `air/src/lib.rs`
  itself) so this becomes a deliberate, reviewed change if it's ever
  touched, not an accidental one.

## Confirmed against the real production workspace

With the same modern toolchain, the actual `air`, `prover`, and `canister`
crates in `../` (not this harness) also build and test cleanly against
real `winterfell` 0.13.1:

    cd .. && cargo test --workspace --lib
    # title_air:      18 passed
    # title_verifier: 63 passed
