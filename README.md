# Yaqeen on ICP — Winterfell STARK Edition

A zero-knowledge **title-verification system** for the [Internet Computer](https://internetcomputer.org) (ICP), implemented as a Rust canister that verifies **Winterfell STARK proofs** natively on-chain. This is a re-architecture of Yaqeen's original Groth16/Motoko design: the proven statement is unchanged, but the proof system now has **no trusted setup**, and on-chain verification is ~1,000× cheaper.

The prover proves ownership of a property title, that it is unencumbered, that its license is valid and unexpired, and that it is a genuine member of the registry's Merkle tree — **without ever revealing the property, the owner's secret, or any private record data** to the canister or observers.

## Highlights

- **Transparent proof system.** STARKs (FRI-based) require no trusted-setup ceremony — the single biggest outstanding risk of the original Groth16 design (`ceremony/`) is eliminated entirely.
- **Native on-chain verification.** `winterfell::verify()` (a published Rust crate) runs directly inside the canister. No vendored BLS12-381 pairing library to maintain.
- **~1,057× cheaper verification.** A full end-to-end `verify` call measures **19,779,043 instructions** (~19.8M) vs. ~20.9 billion for the Groth16 verifier it replaces — comfortably inside a single execution round instead of ~3 DTS rounds.
- **Panic-hardened.** `verify` is wrapped in `std::panic::catch_unwind` (with `panic = "unwind"` in the release profile); a structurally malformed proof returns `Err(..)` instead of trapping the call, and a legitimate retry afterward still succeeds.
- **Privacy-preserving by construction.** The canister never sees `owner_secret` or the property being proven; replay is prevented via single-use challenges and nullifiers.

## Repository layout

```
├── air/                  title_air crate — the AIR + shared hash/permutation;
│                         linked unmodified by both the canister and the prover
├── canister/             title_verifier crate — the Rust IC canister, with a
│                         catch_unwind-hardened verify()
├── prover/               Off-chain proving library + CLI: builds the registry
│                         Merkle tree, witness, and trace; generates the proof
├── test-harness/         Reproducible test harness (e2e + fuzz) built against
│                         the real winterfell 0.13.1 crate
├── run_full_cycle.sh     Automated build → deploy → golden-path verify →
│                         panic-hardening test
├── dfx.json
└── Cargo.toml            Workspace root (panic = "unwind" in [profile.release])
```

| Crate | Role | Runs on |
|---|---|---|
| `title_air` | The AIR definition: trace shape, constraints, assertions, hash | IC canister + off-chain prover |
| `title_verifier` | The canister: registry, challenges, nullifiers, on-chain `verify` | IC (wasm32) |
| `title_prover` | Trace building + STARK proof generation (CLI wrapper over a reusable library) | Owner's device / proving service |

## How it works

```
 admin / back-office        property owner's device            canister (on-chain)
 ────────────────────       ──────────────────────────         ────────────────────
 1. submit_record ──────────────────────────────────────────▶   updates registry
    (public fields,                                              Merkle tree + root
     NOT owner_secret)

                            2. request_challenge ◀───────────   issues challenge_id,
                               (purpose)              ───────▶   merkle_root, nonce,
                                                                  timestamp (5 min TTL)

                            3. build witness + trace,
                               generate STARK proof
                               (off-chain, private)

                            4. verify ───────────────────────▶   checks public inputs
                               (challenge_id, proof_bytes,        match the challenge,
                                public_inputs)                    runs winterfell::verify
                                                                   inside catch_unwind,
                                                     ◀──────────   returns Ok(nullifier)
                                                                   or Err(reason)
```

1. **Record submission** (admin-only). An admin calls `submit_record` with a property's public fields: `property_id`, `owner_commitment` (a hash computed off-canister from `owner_secret` + `property_id` — never the secret itself), `encumbrance_flag`, `license_status`, `license_expiry`. The canister inserts the leaf into its depth-25 sparse Merkle tree and returns the new root.
2. **Challenge request.** Anyone calls `request_challenge(purpose)`. The canister returns a `ChallengeView`: `challenge_id`, the registry's current `merkle_root`, `registry_id`, `purpose`, a fresh `request_nonce`, the real `current_timestamp`, and `expires_at` — valid for 5 minutes (`CHALLENGE_TTL_NS`).
3. **Proof generation** (off-chain). The prover combines the owner's private witness with the challenge's exact `current_timestamp`/`request_nonce`, builds a 256-row × 50-column execution trace satisfying the AIR, and produces a STARK proof plus public inputs. It also self-verifies the proof locally before anything is submitted.
4. **Verification** (on-chain). `verify(challenge_id, proof_bytes, public_inputs)` runs in three phases: cheap state checks (challenge lookup, expiry, public-input match, nullifier-spent) → cryptographic work (`Proof::from_bytes` + `winterfell::verify`, inside `catch_unwind`, outside any state borrow) → commit (mark challenge consumed, nullifier spent). Returns `Ok(VerifyOk { nullifier })` or a specific `Err(reason)`.
5. **Read access.** `get_record` and `get_merkle_proof` are certified `query` calls for inspecting stored fields or fetching Merkle siblings.

## Canister interface

Full interface in [`canister/title_verifier.did`](canister/title_verifier.did). Field elements (hash outputs) cross the Candid boundary as base-10 decimal strings; small integers use `nat64`.

| Method | Kind | Inputs | Output |
|---|---|---|---|
| `bootstrap_admin` | update | `principal` | `Ok` / `Err` — succeeds once, while there are zero admins |
| `add_admin` / `remove_admin` | update | `principal` | `Ok` / `Err` — admin-only |
| `submit_record` | update | `property_id`, `owner_commitment`, `encumbrance_flag`, `license_status`, `license_expiry` | `Ok(merkle_root)` / `Err` — admin-only |
| `request_challenge` | update | `purpose` | `Ok(ChallengeView)` / `Err` — rate-limited per caller |
| `get_record` | query | `property_id` | `opt Record` |
| `get_merkle_proof` | query | `property_id` | `opt MerkleProof` |
| `verify` | update | `challenge_id`, `proof_bytes`, `VerifyPublicInputs` | `Ok(VerifyOk { nullifier })` / `Err` — panic-guarded |
| `health` | query | — | `text` status |

`VerifyPublicInputs` — every field must exactly match the challenge at issuance:

```candid
type VerifyPublicInputs = record {
  registry_id     : nat64;  // registry this proof is against
  merkle_root     : text;   // decimal field element
  purpose         : nat64;
  request_nonce   : nat64;
  current_timestamp : nat64;
  nullifier       : text;   // decimal field element; must not already be spent
};
```

Deliberately **not** present anywhere: `owner_secret` and the `property_id` being proven.

## The AIR in brief

See `air/src/lib.rs` for full documentation. The statement — owner commitment → leaf → 25-level Merkle inclusion → nullifier, plus encumbrance/license/expiry checks — is expressed as a **fixed-shape 256-row × 50-column trace**: 32 "jobs" of 8 rows each (28 real hash invocations + 4 padding jobs), where each job runs an 8-round permutation and boundary rows wire outputs into the next job's inputs via one-hot selector columns.

- `TREE_DEPTH = 25` is a compile-time constant baked into the trace shape (no dynamic AIR loading — one `Air` implementation per computation).
- The AIR defines its own sponge-like permutation ("RPO-lite") over Winterfell's `f128` field, used consistently in the AIR, the prover, and the canister's Merkle bookkeeping — **see [Security notes](#security-notes)**.
- A full trace satisfies all 49 transition constraints and 39 assertions — confirmed by the prover's in-process `local verify: OK` and by on-chain verification.

## Getting started

### Prerequisites

- Rust **1.87+** (edition 2024 support requires 1.85+), with the `wasm32-unknown-unknown` target
- [DFINITY SDK](https://github.com/dfinity/sdk) **0.25.1+** (`dfx`)
- `candid-extractor` (for regenerating the `.did` from the built WASM)

### Build & deploy

```bash
rustup default stable
rustup target add wasm32-unknown-unknown
cargo install candid-extractor
export PATH="$HOME/.cargo/bin:$PATH"

# 1. Does the AIR compile and pass its own unit tests?
cargo test -p title_air

# 2. Build and deploy the canister.
dfx start --clean --background
dfx deploy

# The committed canister/title_verifier.did is a hand-written stand-in;
# regenerate the authoritative one from the real WASM and redeploy:
candid-extractor target/wasm32-unknown-unknown/release/title_verifier.wasm \
  > canister/title_verifier.did
dfx deploy

# 3. Bootstrap admin and submit a record. license_expiry must be comfortably
#    in the future relative to the replica's real clock — it is NOT derived
#    from any later timestamp; it is fixed here.
dfx canister call title_verifier bootstrap_admin \
  "(principal \"$(dfx identity get-principal)\")"

dfx canister call title_verifier submit_record \
  '(42:nat64, "<owner_commitment>", 0:nat64, 1:nat64, <license_expiry>:nat64)'

# 4. Request a challenge and move through the remaining steps immediately —
#    challenges expire (5 minutes).
dfx canister call title_verifier request_challenge '(1:nat64)'
# -> note the real challenge_id, request_nonce, and current_timestamp

# 5. Prove against that exact challenge — real values, not placeholders.
cargo run --release -p title_prover -- <current_timestamp> <request_nonce> <license_expiry>
#    -> prints public inputs, "local verify: OK", proof size/time, and writes
#       verify_args.candid with a {challengeId} placeholder (the proof blob is
#       too large for a single shell command line)

# 6. Patch in the real challenge_id and verify.
sed -i "s/{challengeId}/<real_challenge_id>/" verify_args.candid
time dfx canister call title_verifier verify --argument-file verify_args.candid
```

A successful call returns `variant { Ok = record { nullifier = "..." } }` and logs the real on-chain verification cost:

```
[Canister ...] verify: proof_bytes=46346B instructions=19779043
```

> **Important:** the prover assumes its record lands at leaf index 0 of a fresh tree. If other records were submitted first, the canister's real Merkle root will differ and `verify` will (correctly) reject with `merkle_root mismatch`.

### Automated end-to-end test

[`run_full_cycle.sh`](run_full_cycle.sh) automates the full cycle — toolchain sanity, `cargo test -p title_air`, canister build, clean replica + deploy + `.did` regeneration, admin bootstrap, golden-path `request_challenge → prove → verify`, and a dedicated panic-hardening test:

1. Requests a fresh challenge and proof, then flips 24 random bytes inside the proof blob to corrupt it structurally.
2. Asserts `verify` with the corrupted proof returns `Err = ` — confirming `catch_unwind` + `panic = "unwind"` are effective in the deployed WASM, not just in source.
3. Asserts `verify` with the original proof for the *same* challenge still returns `Ok = ` — confirming the caught panic left canister state untouched.

```bash
bash run_full_cycle.sh
```

## Cost analysis

All figures are measured — off-chain on a real toolchain, on-chain against the deployed canister on a real local replica.

### Off-chain (proving)

- `trace_length = 256`, `trace_width = 50`, `blowup_factor = 8` → LDE domain of 2,048 rows (tiny by STARK standards).
- **Proving time: 46–75 ms**; **proof size: ~45–47 KB**, consistently across runs.

### On-chain (verification)

| Metric | Groth16 (original) | Winterfell STARK (this port) |
|---|---|---|
| Instructions per `verify` | ~20.9 billion | **19,779,043 (~19.8M)** |
| Execution rounds | ~3 DTS rounds (multi-second) | **Single round** |
| Proof size | 192 bytes | ~46 KB (~240× larger) |
| Trusted setup | Required | **None** |

- ~19.8M instructions is **~0.28%** of the 7B single-round ceiling and **~0.05%** of the 40B update-call ceiling — and ~1,057× cheaper than the Groth16 call it replaces.
- Corrupted-proof rejection is cheaper still (~6.1–8.1M instructions; it fails during FRI/constraint checking), and returns `Err(..)` cleanly.
- For reference, `ic-winterfell-verifier`'s much smaller `WorkAir` (1 column, 1 constraint) measured ~19M–48M instructions depending on trace length — confirming that domain size, not column/constraint count, dominates cost at this scale.
- Wall-clock round trip (`time dfx canister call ... verify`) is ~2.5–4.3 s on a local replica, dominated by `dfx`/replica overhead.

## Testing

```
cargo test --workspace
```

| Suite | Scope |
|---|---|
| `air` (title_air) | 17–18 tests — hash determinism, trace shape, regression for hash length-separation |
| `canister` (title_verifier) | 64 tests, fully offline — every `_impl` function is a plain Rust function taking `caller`/`now_ns` as parameters, so the exact production logic runs under `cargo test`, including `verify_crypto_accepts_a_genuine_proof_from_the_real_prover` (a genuine proof generated by the real prover library is verified by the real `verify_crypto_impl`) |
| `test-harness` | 32 tests — e2e constraint/assertion checks, tamper checks, and fuzz robustness/soundness passes against the real `winterfell` 0.13.1 crate |

The `dev` profile sets `debug-assertions = false` intentionally: winterfell's prover has an internal debug-only check requiring a trace's *actual* per-constraint polynomial degree to exactly equal the AIR's conservative declared bound. A small demo trace legitimately falls under that bound for some constraints; without this setting the assert trips under `cargo test` even though the identical proof verifies in release mode and on-chain. This does not weaken any of the workspace's own (unconditional) test assertions.

See [`TESTING.md`](TESTING.md) for the full test history and [`test-harness/README.md`](test-harness/README.md) for the harness details.

## Design decisions

- **Why STARKs?** Groth16's 192-byte proofs are bought by a trusted-setup ceremony; Yaqeen's multi-party ceremony never actually ran — the top item on its own risk list. STARKs are transparent, removing that entire risk category, at the cost of larger proofs and a new, unaudited hash function. See [Security notes](#security-notes).
- **Why Rust for the canister?** Winterfell is a Rust library; a Rust canister verifies proofs natively via `winterfell::verify()` with no vendored cryptography.
- **Why decimal strings?** Field elements cross Candid as decimal strings due to uneven `int128`/`nat128` tooling support.
- **Challenge binding.** `request_challenge` is public and unauthenticated; `verify` is scoped to the principal who requested the challenge, closing a third-party race where a bogus `verify` could consume a legitimate challenge before the real prover's proof lands.

## Security notes

This is a **prototype/scaffolding system**, and the following must be addressed before any real value depends on it:

- **The hash permutation ("RPO-lite") is unaudited.** It was designed from scratch to fit Winterfell's `f128` field because no pairing-free hash existed for it (Yaqeen's Poseidon is over BLS12-381's scalar field). It needs review and replacement with a properly-analyzed construction (Rescue-Prime, a tuned Poseidon2 instance, etc.). This is the single biggest new risk this port introduces.
- **The linear "mix" layer is not a verified MDS matrix**; rounds, S-box degree, and mixing parameters are scaffolding choices, not the output of a security analysis.
- **`catch_unwind` hardening depends on two invariants** that are easy to lose in future edits and are covered by `run_full_cycle.sh` step 6:
  - `[profile.release]` must stay `panic = "unwind"` — under `panic = "abort"` (a common wasm size optimization) `catch_unwind` silently becomes a no-op and a malformed proof traps the call.
  - The `catch_unwind` closure in `verify` must keep touching no `RefCell`/canister state — that is what makes catching the panic safe (nothing is left half-mutated).
- **Stable-memory upgrades use the legacy `stable_save`/`stable_restore` pair** — fine for prototype state sizes, but worth migrating to `ic-stable-structures` for a large registry.
- **`hash()` does no length domain separation** (`hash(&[1])` and `hash(&[1, 0])` collide); safe today only because every call site uses fixed arity per domain tag. Pinned as a regression test.
- **Challenge TTL is short (5 min)** and easy to exceed during manual testing — treat request → prove → verify as one atomic unit (`run_full_cycle.sh` automates this).
- **`dfx deploy`'s `cargo audit` step can fail with `error loading advisory database: parse error: duplicate advisory ID`** on some machines — this is a corrupted local RustSec advisory clone (`~/.cargo/advisory-db/`), not a vulnerability finding; clear it with `rm -rf ~/.cargo/advisory-db && cargo install cargo-audit --force`.

## See also

- [`TESTING.md`](TESTING.md) — full testing history, including the journey from a sandboxed facade to real-toolchain validation
- [`test-harness/README.md`](test-harness/README.md) — the reproducible e2e/fuzz harness
- [`run_full_cycle.sh`](run_full_cycle.sh) — automated end-to-end + panic-hardening test
- [`air/src/lib.rs`](air/src/lib.rs) — the AIR, trace layout, and constraint documentation
