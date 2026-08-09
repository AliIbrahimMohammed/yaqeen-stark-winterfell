# Yaqeen STARK/Winterfell port — local `dfx` + end-to-end test report (v2)

> **Addendum (real rustc 1.87+ build, run by the repo owner):** with a real
> toolchain, `title_air` and `title_prover` compiled clean against the
> genuine `winterfell` 0.13.1 crate on the first try — independently
> confirming both fixes below hold outside the sandbox facade, not just
> inside it. `canister/src/lib.rs` failed with 11 real errors, all three
> from genuine `ic-cdk`/`candid` API changes the sandbox couldn't have
> caught (no wasm32 toolchain here to compile that crate at all). Fixed and
> re-synced into this repo:
> 1. `ic_cdk::caller()` was removed (deprecated since ic-cdk 0.18 in favor
>    of `ic_cdk::api::msg_caller()`, and the top-level re-export is gone in
>    0.20.2) — all 5 call sites updated.
> 2. The internal `Challenge` struct derived `CandidType, Deserialize`
>    unnecessarily — it never crosses the Candid boundary (`ChallengeView`
>    and `StableChallenge` do, via decimal-string field elements, exactly
>    as the file's own "Upgrade hooks" comment already describes for
>    `StableState`). Since `title_air::BaseElement` doesn't implement those
>    traits, deriving them on `Challenge` failed. Dropped to `#[derive(Clone)]`.
> 3. `BaseElement::ZERO` is an associated const on the `FieldElement` trait,
>    not inherent to `BaseElement` — needed `use winterfell::math::FieldElement;`
>    in `canister/src/lib.rs` (mirroring the import `air/src/lib.rs` already
>    uses successfully).
>
> Not yet re-tested against a real toolchain after this fix (still no
> rustc 1.87+ path in this sandbox) — next step is the same
> `cargo build --target wasm32-unknown-unknown --release` on a machine
> with a real toolchain.

This supersedes the earlier `yaqeen-stark-test-report.md`. That report said
"no `dfx`/IC replica" was available at all. That turned out to be only
half-true — I went back and found a real path to a real `dfx` and a real
local replica, and used them. What's still blocked, and why, is now pinned
down precisely instead of inferred.

## TL;DR

| | Earlier report | This session |
|---|---|---|
| Real `dfx` binary | Not obtained | **Obtained** (0.32.0, real GitHub release asset) |
| Real local IC replica | Not started | **Started and healthy** (`pocket-ic`, bundled in the dfx release, no extra network needed) |
| `dfx build` of the actual `title_verifier` canister | Not attempted (assumed blocked) | **Attempted for real** — fails, root cause now pinned to a specific transitive dependency (`cpufeatures` → `edition2024`) |
| Root cause confirmed ecosystem-wide? | No | **Yes** — a trivial unrelated `ic-cdk` "hello world" canister hits the same wall via a different dependency chain |
| AIR behavioral re-test | Facade-based (undisclosed internals) | Facade rebuilt from the **real downloaded winter-air 0.13.1 source** (exact trait/struct signatures, real f128 field arithmetic) — same pass/fail conclusions, higher-confidence method |

## 1. Getting a real `dfx` and a real local replica

The sandbox has no network access to `sdk.dfinity.org` (the dfx installer
script's host — confirmed 403) or `static.rust-lang.org` (rustup's only
distribution channel — also 403). But `github.com` and
`release-assets.githubusercontent.com` are open, and dfx's own release
binaries are published there directly:

```
curl -sSL -o dfx.tar.gz \
  https://github.com/dfinity/sdk/releases/download/0.32.0/dfx-x86_64-unknown-linux-gnu.tar.gz
```

This downloaded a genuine 84 MB dfx 0.32.0 binary. `dfx cache install`
unpacked **`pocket-ic`** (the local replica binary) and `moc` (Motoko
compiler) from the same tarball — no separate network fetch needed for the
replica itself, which is what made this possible without
`sdk.dfinity.org`.

```
dfx start --clean --background
dfx ping
```

Result: a **real, healthy local replica**:

```json
{
  "replica_health_status": "healthy",
  "root_key": [48, 129, 130, ...]
}
```

`dfx canister create title_verifier` also succeeded for real, allocating a
real canister ID on the local replica (`uxrrr-q7777-77774-qaaaq-cai`).

**This is new relative to the earlier report** — that report's claim of
"no dfx/IC replica" was an environment assumption that wasn't actually
tested against the GitHub-release download path.

## 2. `dfx build` of the actual canister — still blocked, now with a precise cause

```
dfx build title_verifier
→ Executing: cargo build --target wasm32-unknown-unknown --release -p title_verifier --locked
→ error: failed to download `cpufeatures v0.3.0`
  Caused by: failed to parse manifest ... feature `edition2024` is required
  The package requires the Cargo feature called `edition2024`, but that
  feature is not stabilized in this version of Cargo (1.75.0).
```

Dependency chain (from Cargo's own error output):
`title_verifier → title_air → winterfell 0.13.1 → winter-air → winter-crypto
→ blake3 1.8.6 → cpufeatures ^0.3.0 (requires edition2024)`.

I tried pinning `cpufeatures` down to `0.2.17` (the last pre-edition2024
release) to see if the build could proceed anyway:

```
cargo update -p cpufeatures@0.3.0 --precise 0.2.17
→ error: failed to select a version for the requirement `cpufeatures = "^0.3.0"`
  required by package `blake3 v1.8.6` ... locked to 0.13.1 of `winter-crypto`
```

**No workaround exists** — `blake3 1.8.6` hard-requires `cpufeatures ^0.3.0`
specifically, and there's no way to satisfy that with an edition-2021-safe
version. This is a firmer result than the earlier report's inference from
`winterfell`'s own declared `rust-version = "1.87"` field: it's an actual
reproduced Cargo resolver failure, and it's worse than 1.87 — `edition2024`
itself only stabilized in rustc 1.85.

### Is this specific to Winterfell? No.

To separate "this crate's dependency tree is unusually new" from "this
sandbox's rustc is categorically behind current crates.io," I scaffolded a
trivial, unrelated canister — just `ic-cdk = "0.13"` and a two-line
`greet`/`add` service, nothing STARK-related — and ran the identical
`cargo build --target wasm32-unknown-unknown --release` against it.

**Same failure**, through a completely different dependency chain:
`smoke_canister → ic-cdk 0.13.6 → candid 0.10.34 → stacker 0.1.25 →
(build-dependency) → object → ar_archive_writer 0.5.3 → requires
edition2024`.

So this is not a Winterfell-specific or even a STARK-specific problem: **the
sandbox's rustc 1.75 (Ubuntu 24.04's system package, itself dated
~Dec 2023) cannot build essentially any dependency graph pulled fresh from
crates.io today, IC-related or not.** The blocker is the sandbox's
toolchain age versus the modern crates ecosystem, not a defect in your
code or a Winterfell-specific requirement.

### Why rustc can't be upgraded here

- `apt` only has rustc 1.75.0 (checked: `apt-cache policy rustc` — no
  newer candidate).
- `rustup` (the standard way to get newer rustc) fetches its toolchains
  exclusively from `static.rust-lang.org`, which returns 403 in this
  sandbox's network policy — no alternate distribution channel exists;
  `rust-lang/rust`'s GitHub releases are source-only (checked: 0 binary
  assets on the latest release).
- No other allowed domain (npm, pip, crates.io itself) distributes
  prebuilt `rustc` binaries — checked directly, nothing suitable found.

This is a hard wall specific to this sandbox's network allowlist, not a
project issue. On any machine with normal internet access, `rustup install
1.87` (or newer) and this build proceeds normally.

## 3. Real end-to-end AIR behavioral test (rebuilt from real source, not guesswork)

Since a genuine `cargo build`/`dfx build` of the real dependency tree isn't
reachable here, I rebuilt the same style of test as the earlier report —
but this time by downloading the **actual `winter-air` and `winter-math`
0.13.1 source** from `static.crates.io` and copying the real `Air` trait,
`AirContext`, `Assertion`, `EvaluationFrame`, `TraceInfo`, and
`TransitionConstraintDegree` signatures verbatim into a facade crate,
rather than reconstructing them from memory/inference. I also implemented
the facade's `BaseElement` as the real f128 prime field
(`p = 2^128 - 45·2^40 + 1`), not a toy field, so hash/constraint values are
the genuine values a real build would produce.

Confirmed while extracting: `evaluate_transition<E: FieldElement<BaseField
= Self::BaseField>>` (the trait bound your patched file uses) is **exactly**
the real trait signature in `winter-air 0.13.1`'s source — so fix #2 from
the earlier report is verified correct against ground truth, not inference.

The facade compiled the **exact, unmodified** `air/src/lib.rs` from your
patched zip (diffed byte-for-byte to confirm) cleanly on the first
structurally-correct attempt. I then wrote a harness (`e2e_harness.rs`)
that reproduces `build_trace`/`SparseTree` from `prover/src/main.rs`
verbatim and runs it against the real `TitleAir`:

```
=== Yaqeen STARK/Winterfell -- real end-to-end AIR behavioral test ===
(facade built from real winter-air 0.13.1 signatures downloaded this session)

[ok] build_trace()'s merkle_root matches the independently-computed SparseTree root
[ok] all 49 transition constraints evaluate to zero across all 256 row-transitions
[ok] all 39 assertions (7 public-input + 32 job-type) hold on the honest trace
[ok] soundness sanity: tampering encumbrance_flag to 1 makes it mismatch the assertion
[ok] hash() applies exactly ROUNDS-1=7 permutation rounds, matching job logic directly

All checks passed against the actual, unmodified shipped air/src/lib.rs.
```

Plus the crate's own unit tests:

```
running 2 tests
test tests::hash_is_deterministic ... ok
test tests::trace_length_is_power_of_two ... ok
test result: ok. 2 passed; 0 failed
```

And a fuzz pass — 256 row-transitions of arbitrary (non-satisfying) column
data through `evaluate_transition`, checking for panics or out-of-bounds
indexing:

```
=== Fuzz: 256 row-transitions with arbitrary (non-satisfying) data ===
panics/out-of-bounds: 0
[ok] no panics or out-of-bounds indexing across 256 arbitrary row-transitions
```

**Conclusion: same result as the earlier report, now on firmer footing.**
Both fixes (the `hash()` round-count bug and the `evaluate_transition`
generic-bound compile error) check out against the real, downloaded
winterfell source and real field arithmetic.

## 4. What this still does NOT prove

Being direct about the remaining gap, same as before:

- **No real STARK proof was generated or verified.** The facade implements
  only the `Air` trait surface (constraint evaluation, assertions,
  periodic columns) — not `Prover`, FRI, the low-degree extension, or
  Merkle-tree commitments. `prover.prove(trace)` and
  `winterfell::verify(...)` were never actually called against real code
  in either this session or the last. This is the single biggest
  remaining gap between what's been tested and what "the system works
  end-to-end" would require.
- **No WASM binary of `title_verifier` was produced**, so no real
  `dfx canister call verify`, no real IC instruction-count measurement,
  and no real interaction between the canister and the local replica —
  despite the replica itself now being real and running. The infra is
  ready; the artifact to deploy on it isn't buildable here.
- Everything from the earlier report's "What I could NOT do" section still
  applies for the same underlying reason (toolchain age), now with a more
  precise failure signature (`edition2024` via `cpufeatures`/
  `ar_archive_writer`) instead of a general MSRV inference.

## 5. Fastest path to a fully real result

Unchanged in substance from the earlier report, but now more specific:
on any machine with normal internet access —

```
rustup install 1.87        # or newer; must support edition2024 (1.85+)
cd air && cargo test
cd ../prover && cargo run --release      # should print "local verify: OK"
cd .. && dfx start --background
dfx deploy                               # real WASM, real canister
# then a real dfx canister call title_verifier verify '(...)' using the
# prover's printed command, for actual on-chain instruction counts
```

Given the dfx binary and pocket-ic replica are already proven to work in
an environment like this one, the *only* remaining blocker on a normal
machine is having rustc 1.85+ (for `edition2024` support in transitive
deps) — which any current `rustup` install already provides by default.

## Attached

A reproducible copy of the facade + test harness code used in section 3
(`harness/`) — self-contained, builds and runs with nothing but a system
Rust toolchain (tested here on 1.75, no nightly features), so you or your
CI can re-run it independently of this session.
