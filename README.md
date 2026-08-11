# Yaqeen on ICP — Winterfell STARK Edition

A privacy-preserving title-verification system on the Internet Computer. A
property owner proves — via a zero-knowledge STARK proof generated on their
own device — that they own a specific title, that it is unencumbered, that
its license is currently valid, and that it belongs to the registry's
Merkle tree, **without revealing which property it is or their private
`owner_secret`**.

This is a re-architecture of Yaqeen's original Groth16/Motoko verifier to
use transparent STARK proofs (via [Winterfell](https://github.com/facebook/winterfell))
instead of a pairing-based SNARK, removing the need for a trusted-setup
ceremony. The statement being proven is unchanged; what changed is how it's
expressed and checked. See ["What changed, and why"](#what-changed-and-why)
for the full comparison.

> **Status.** Builds, tests, and deploys cleanly against `winterfell` 0.13.1
> (rustc 1.87+). Verified end-to-end against a local `dfx` replica: record
> submission → challenge → proof → on-chain verification, including a
> deliberately corrupted proof to confirm the panic-hardened failure path.
> See [Known limitations](#known-limitations) before relying on this for
> anything beyond a prototype — several placeholder cryptographic
> parameters have **not** received a security review.

---

## Table of contents

- [Architecture](#architecture)
- [How it works](#how-it-works)
- [Canister interface](#canister-interface)
- [Generating a proof](#generating-a-proof)
- [Security model](#security-model)
- [Known limitations](#known-limitations)
- [Performance](#performance)
- [What changed, and why](#what-changed-and-why)
- [Build & deploy](#build--deploy)
- [Testing](#testing)
- [Design notes / engineering log](#design-notes--engineering-log)

---

## Architecture

```
yaqeen-stark/
├── air/                title_air: the AIR (arithmetic circuit) and the
│                        shared hash/permutation, linked unmodified by
│                        both the canister and the off-chain prover
├── canister/            title_verifier: the IC canister (Rust), including
│                        registry bookkeeping, challenge issuance, and a
│                        panic-hardened verify()
├── prover/              off-chain binary + library: builds the Merkle
│                        tree, the witness, the execution trace, and a
│                        real STARK proof
├── test-harness/        integration/e2e/fuzz test harness against the
│                        real winterfell crate
├── run_full_cycle.sh    scripted build → deploy → verify → hardening test
├── dfx.json
└── Cargo.toml           workspace root
```

Three crates share one invariant: the canister's registry hashing, the
prover's witness construction, and the AIR's in-circuit hash must all use
the byte-identical permutation in `air/src/lib.rs`. A STARK proof only
attests that *some* trace satisfies the AIR — correctness depends entirely
on prover and verifier agreeing on that AIR.

## How it works

```
 admin / back office          property owner's device            canister (on-chain)
 ────────────────────         ─────────────────────────           ────────────────────
 1. submit_record  ──────────────────────────────────────────────▶  updates registry's
    (public fields only,                                            Merkle tree + root
     never owner_secret)

                               2. request_challenge  ◀─────────────  issues challenge_id,
                                  (purpose)               ─────────▶ merkle_root, nonce,
                                                                      timestamp (5 min TTL)

                               3. build witness + trace,
                                  generate STARK proof
                                  (off-chain, private)

                               4. verify  ───────────────────────▶  checks public inputs
                                  (challenge_id, proof_bytes,        against the challenge,
                                   public_inputs)                    runs winterfell::verify
                                                        ◀─────────── inside catch_unwind
                                                                    returns Ok(nullifier)
                                                                    or Err(reason)
```

1. **`submit_record`** (admin-only). An admin submits a property's public
   fields — `property_id`, an `owner_commitment` (a hash computed
   off-canister from `owner_secret` + `property_id`; the canister never
   sees the secret itself), `encumbrance_flag`, `license_status`, and
   `license_expiry`. The canister hashes these into a leaf and updates its
   Merkle tree, returning the new root.

2. **`request_challenge`**. The prospective prover requests a challenge
   with a `purpose` code (e.g. "sale", "lease"). The canister returns a
   `ChallengeView`: a `challenge_id`, the registry's *current*
   `merkle_root`, a fresh `request_nonce`, the replica's real
   `current_timestamp`, and an `expires_at` five minutes out.

3. **Proof generation** (off-chain, on the owner's device). The prover
   combines the private witness (`owner_secret`, `property_id`, Merkle
   siblings) with the exact `current_timestamp` and `request_nonce` from
   the challenge, builds a trace satisfying the AIR, and produces a STARK
   proof plus its matching public inputs.

4. **`verify`**. Anyone holding the proof calls `verify` with the
   `challenge_id`, `proof_bytes`, and `public_inputs`. The canister runs
   this in three phases:
   - **Precheck** — cheap, state-dependent checks: challenge lookup,
     caller-binding, expiry, exact match against the challenge's original
     public inputs, and a nullifier-not-yet-spent check.
   - **Crypto** — `Proof::from_bytes` + `winterfell::verify`, run outside
     any state borrow and wrapped in `catch_unwind` so a structurally
     malformed proof returns `Err(..)` instead of trapping the call.
   - **Commit** — only on success: marks the challenge consumed and the
     nullifier spent.

   Returns `Ok({ nullifier })` or a specific `Err(text)` describing which
   check failed.

5. **Read access.** `get_record` and `get_merkle_proof` are public `query`
   calls for inspecting a property's stored fields or fetching the sibling
   path needed to build a proof for it.

Nothing in this interface ever takes `owner_secret` or the `property_id`
being proven as an input to `verify` — that's the entire point of proving
membership rather than disclosing the record.

## Canister interface

| Method | Kind | Access | Inputs | Output |
|---|---|---|---|---|
| `bootstrap_admin` | update | public, once only | `principal` | `Ok` / `Err` — succeeds only while the canister has zero admins |
| `add_admin` / `remove_admin` | update | admin-only | `principal` | `Ok` / `Err` |
| `submit_record` | update | admin-only | `property_id`, `owner_commitment`, `encumbrance_flag`, `license_status`, `license_expiry` | `Ok(text)` new Merkle root, or `Err` |
| `request_challenge` | update | rate-limited per caller | `purpose : nat64` | `Ok(ChallengeView)` or `Err` |
| `verify` | update | rate-limited, caller-bound to the challenge | `challenge_id`, `proof_bytes`, `public_inputs` | `Ok({ nullifier })` or `Err`; panic-guarded internally |
| `get_record` | query | public | `property_id` | `opt Record` |
| `get_merkle_proof` | query | public | `property_id` | `opt MerkleProof` |
| `health` | query | public | — | status string |

`VerifyPublicInputs`:

```candid
type VerifyPublicInputs = record {
  registry_id       : nat64;  // which registry this proof is against
  merkle_root        : text;  // decimal field element; must match the
                               // challenge's merkle_root at issuance
  purpose             : nat64; // must match the challenge's purpose
  request_nonce       : nat64; // must match the challenge's request_nonce
  current_timestamp   : nat64; // must match the challenge's timestamp
  nullifier            : text; // decimal field element; must not be spent
};
```

`verify` checks these in order — `registry_id` → `merkle_root` → `purpose`
→ `request_nonce` → `current_timestamp` → nullifier-not-spent — before any
cryptographic work runs, then decodes the proof and calls
`winterfell::verify` inside `catch_unwind`.

Field elements that can be arbitrary 128-bit hash outputs (owner
commitments, tree nodes, nullifiers) cross the Candid boundary as
decimal-string text, not native integers, due to uneven `int128`/`nat128`
tooling support — the same approach `ic-winterfell-verifier` uses. Small
bounded integers use plain `nat64`.

## Generating a proof

`prover/src/main.rs` runs entirely off-chain (typically on the owner's own
device) and never talks to the canister directly.

```bash
cargo run --release -p title_prover -- <current_timestamp> <request_nonce> <license_expiry>
```

| Argument | Source |
|---|---|
| `current_timestamp` | must exactly equal the value the live `request_challenge` call returned |
| `request_nonce` | must exactly equal the value the live `request_challenge` call returned |
| `license_expiry` | must exactly equal the value originally passed to `submit_record` for this property — it is *not* derived from `current_timestamp` |

`owner_secret`, `property_id`, `registry_id`, and `purpose` are demo
constants hardcoded in `main()`; in a real deployment these come from the
owner's own records, never from the canister.

Output: the public inputs and a local self-check (`winterfell::verify` run
in-process, printing `local verify: OK` before anything is submitted
anywhere), plus a `verify_args.candid` file containing the full
`dfx canister call` argument tuple — written to disk rather than printed
inline, since the proof blob is too large for a shell command line.

```bash
sed -i "s/{challengeId}/<real_challenge_id>/" verify_args.candid
dfx canister call title_verifier verify --argument-file verify_args.candid
```

One caveat: the prover currently assumes its record sits at Merkle leaf
index 0, which only holds if `submit_record` was the first record ever
submitted to that registry. Submitting other records first shifts the
canister's real root away from what the proof assumes, and `verify`
correctly rejects with `merkle_root mismatch`.

## Security model

What the system is designed to guarantee, and where those guarantees
currently stand:

- **Admin authorization.** `submit_record`, `add_admin`, and `remove_admin`
  all check `is_admin`. `bootstrap_admin` is intentionally public but only
  succeeds once, while the admin list is empty — a race for the *first*
  bootstrap call exists by design (whoever deploys must call it in the
  same session, before the canister ID is shared) but every call after
  that is properly gated. `remove_admin` refuses to remove the last
  remaining admin, preventing an accidental admin lockout.

- **Replay and front-running protection.** `verify` is bound to the
  principal that originally called `request_challenge` for that challenge
  — without this, `request_challenge` being public and unauthenticated
  would let a third party watching consensus race a bogus `verify` call
  against someone else's freshly issued challenge. Spent nullifiers and
  consumed challenges are tracked separately and both checked before any
  cryptographic work runs.

- **Panic containment.** `winterfell::verify` and `Proof::from_bytes` are
  not guaranteed panic-free against adversarial byte input — an internal
  `assert_eq!` inside Winterfell can fire on a structurally malformed (not
  merely cryptographically invalid) proof. The crypto phase runs inside
  `std::panic::catch_unwind`, converting that into an ordinary `Err(..)`
  instead of trapping the whole update call. This depends on two things
  staying true, both easy to lose in a future edit:
  - `[profile.release]` must keep `panic = "unwind"`. Under the common
    wasm size-optimization default of `panic = "abort"`, `catch_unwind`
    silently becomes a no-op and a malformed proof traps the call again.
  - The `catch_unwind`-wrapped closure must never touch canister state
    (`RefCell`s), which is what makes catching the panic safe — nothing is
    left half-mutated if it unwinds.

  This is exercised by both an offline fuzz test (`verify_crypto_fuzz_never_panics_on_random_proof_bytes`,
  several thousand random byte buffers through the real decode path) and
  a live end-to-end test against the deployed canister (see
  [Testing](#testing)).

- **Rate limiting.** Both `request_challenge` and `verify` enforce a
  minimum interval per calling principal and reject the anonymous
  principal outright, independently per caller.

- **DoS-bounded pruning.** The `heartbeat` that expires stale challenges
  processes at most `MAX_PRUNE_PER_HEARTBEAT` (50) per tick, so a caller
  spamming `request_challenge` can't make a single heartbeat do unbounded
  work.

- **State integrity on failure.** If the crypto phase fails — ordinary
  rejection or a caught panic — neither the challenge nor the nullifier is
  marked consumed, confirmed by a dedicated test asserting a legitimate
  retry against the same challenge still succeeds afterward.

- **Private witness data never crosses the Candid boundary.** `owner_secret`
  and the `property_id` being proven appear nowhere in any canister method
  signature.

## Known limitations

These are the items worth resolving before any real value depends on this
system, roughly in order of severity:

1. **The in-circuit hash permutation ("RPO-lite") is an unaudited,
   scaffolding-only construction.** Its linear mixing layer (`MIX` /
   `mix()`) has not been verified to have the MDS property, its round
   count (8) and S-box degree were not derived from cryptanalysis, and its
   round constants come from a small hand-written PRNG expansion rather
   than a documented, reviewed generation process. This is the single
   biggest open risk in the project — treat it exactly like the upstream
   Yaqeen project's own `poseidon_config()` disclaimer. Before any real
   value depends on this, replace it with a reviewed STARK-friendly
   permutation (Rescue-Prime, or a properly analyzed Poseidon2 instance
   for this field).

2. **`request_challenge` has no caller-bound commitment beyond the
   principal check added to `verify`.** The current binding (only the
   original requester's principal can consume a challenge) closes the
   most direct front-running path, but a caller identity alone is a
   weaker binding than a cryptographic commitment scoped to the specific
   proof. Worth revisiting if the threat model includes a sophisticated
   on-chain adversary.

3. **Stable-memory upgrade persistence uses the legacy
   `ic_cdk::storage::stable_save`/`stable_restore` pair** with an
   unbounded `Vec`-based encode/decode on every upgrade. Adequate for a
   prototype's state size; migrate to `ic-stable-structures` before
   deploying with a registry large enough for this to matter.

4. **Challenge TTL is short (5 minutes)** and easy to exceed during manual
   testing — any pause between requesting a challenge and calling `verify`
   can burn the window, surfacing as `unknown or expired challenge`. The
   reliable pattern is to treat request → prove → verify as one atomic
   sequence (see `run_full_cycle.sh`'s `prove_against_fresh_challenge`).

5. **The workspace's `[profile.dev]` sets `debug-assertions = false`**,
   which is necessary to avoid a Winterfell-internal debug-only sanity
   check tripping on small demo traces (see the comment in the root
   `Cargo.toml`), but it also disables Rust's own integer-overflow checks
   for `cargo test`/`cargo build`'s default profile. This doesn't weaken
   any of this workspace's own test assertions, but it does mean `cargo
   test` alone won't catch an integer overflow introduced elsewhere in
   the codebase — run `cargo test --release` periodically, or CI with
   overflow checks explicitly re-enabled, as a supplement.

6. **The committed `canister/title_verifier.did` should always be
   regenerated from the built WASM** (`candid-extractor`) rather than
   hand-maintained, to guarantee it can never silently drift from the
   real interface. `run_full_cycle.sh` does this automatically; a
   pre-commit or CI check enforcing it would close the gap for
   manually-triggered deploys.

7. **`dfx deploy`'s built-in `cargo audit` step can fail** with a
   "duplicate advisory ID" parse error on some machines — this is a
   stale local clone of the RustSec advisory database
   (`~/.cargo/advisory-db/`), not a real vulnerability finding. Clear it
   with `rm -rf ~/.cargo/advisory-db && cargo install cargo-audit --force`.

## Performance

Every number below is measured against a real toolchain and a real local
replica, not estimated.

**Off-chain (proving).** `trace_length = 256`, `trace_width = 50`,
`blowup_factor = 8` → a 2,048-row low-degree-extension domain, small by
STARK standards. Proving consistently took **46–75 ms** and produced a
proof of **~45–47 KB**, self-verifying in-process before submission.

**On-chain (verification).** A real `verify` call against a real challenge
and a real proof logged:

```
verify: proof_bytes=46346B instructions=19779043
```

**~19.8M instructions** — about **0.28%** of the IC's 7B-instruction
single-round ceiling and **0.05%** of the 40B-instruction update-call
ceiling, comfortably within a single execution round. A corrupted proof
rejected inside `catch_unwind` for roughly **6–8M instructions** (it fails
during FRI/constraint checking, before completing the full protocol).
Full round-trip wall-clock time (`dfx canister call ... verify`, including
network/consensus overhead) measured **~2.5–4.3 s**.

**Proof size vs. the Groth16 original.** Groth16 proofs are a fixed 192
bytes regardless of circuit size — the reason pairing-based SNARKs are so
attractive for on-chain verification and calldata cost. This STARK port's
~46 KB proof is roughly **240x larger**, still small relative to IC
message-size limits, but a real ongoing bandwidth/storage cost the
original architecture didn't have — the direct price of removing the
trusted-setup requirement.

## What changed, and why

| | Original (Groth16) | This port (Winterfell STARK) |
|---|---|---|
| Proof system | Groth16 (pairing-based SNARK) | STARK (FRI-based, transparent) |
| Field | BLS12-381 scalar field | Winterfell's native `f128` |
| Circuit model | R1CS (arkworks) | AIR — fixed-shape trace + transition constraints |
| Hash function | Poseidon over BLS12-381 `Fr` | Purpose-built sponge permutation over `f128` (unaudited — see [Known limitations](#known-limitations)) |
| Trusted setup | Required; the ceremony had never actually run | None — STARKs are transparent |
| On-chain verifier | Vendored ~4,000-line BLS12-381 pairing library in Motoko | `winterfell::verify()`, a published crate, called inside `catch_unwind` |
| Canister language | Motoko | Rust (`ic-cdk`) |
| Proof size | 192 bytes | ~46 KB |
| Measured on-chain cost | ~20.9B instructions, ~3 DTS rounds | ~19.8M instructions, single round |

The trade is not strictly one-directional: removing the trusted-setup
ceremony (the original project's own top risk item) comes at the cost of a
~240x larger proof and a new, unaudited hash function replacing a Poseidon
instance that was at least parameterized by a standard script. Whether
that trade is worth it depends on the deployment's actual threat model and
volume.

## Build & deploy

Requires rustc 1.87+ (edition2024 support, 1.85+) and `dfx` 0.25.1+.

```bash
rustup default stable
rustup target add wasm32-unknown-unknown
cargo install candid-extractor
export PATH="$HOME/.cargo/bin:$PATH"

# 1. AIR unit tests
cargo test -p title_air

# 2. Build and deploy the canister
dfx start --clean --background
dfx deploy

# Regenerate the authoritative .did from the real WASM so it can never
# silently drift from the built interface:
candid-extractor target/wasm32-unknown-unknown/release/title_verifier.wasm \
  > canister/title_verifier.did
dfx deploy

# 3. Bootstrap the deployer as admin and submit a demo record
dfx canister call title_verifier bootstrap_admin \
  "(principal \"$(dfx identity get-principal)\")"
dfx canister call title_verifier submit_record \
  '(42:nat64, "<owner_commitment>", 0:nat64, 1:nat64, <license_expiry>:nat64)'

# 4. Request a challenge and move through the remaining steps immediately
#    (challenges expire after 5 minutes)
dfx canister call title_verifier request_challenge '(1:nat64)'

# 5. Prove against that exact challenge
cargo run --release -p title_prover -- <current_timestamp> <request_nonce> <license_expiry>

# 6. Patch in the real challenge_id and verify
sed -i "s/{challengeId}/<real_challenge_id>/" verify_args.candid
dfx canister call title_verifier verify --argument-file verify_args.candid
```

## Testing

```bash
cargo test --workspace
```

Covers `air` (unit tests for the permutation and trace-layout invariants),
`canister` (business-logic tests for every public method, organized by
function plus a dedicated attack-scenario section: unauthorized access,
replay, nullifier double-spend, cross-challenge input mixing, anonymous
impersonation, rate-limit bypass, admin lockout, and fuzzed malformed proof
bytes against the `catch_unwind` boundary), and `test-harness` (integration
tests against the real `winterfell` crate). All of it runs offline — no
`dfx`/replica needed for logic correctness.

[`run_full_cycle.sh`](./run_full_cycle.sh) automates the real end-to-end
path against a live local replica: toolchain checks, build, a clean
deploy, `.did` regeneration, admin bootstrap, a golden-path
request → prove → verify cycle, and a hardening test that corrupts 24
bytes inside a real proof and asserts the call returns `Err(..)` (not a
trap) followed by a successful retry with the original proof, confirming
the caught panic left canister state untouched.

```bash
bash run_full_cycle.sh
```

See [`TESTING.md`](./TESTING.md) for the fuller test history.

## Design notes / engineering log

A few AIR-specific constraints worth knowing before modifying `air/src/lib.rs`:

- **Fixed trace shape.** An `Air`'s trace length is fixed by `TraceInfo` at
  construction, not chosen per-witness the way an R1CS witness size can
  vary. `TREE_DEPTH` and the hash job count are compile-time constants
  baked into `TRACE_LENGTH`; the job count is padded (28 → 32) purely so
  `JOB_COUNT * ROUNDS` lands on a power of two, which Winterfell's
  periodic columns and FFT-based low-degree extension require. Changing
  `TREE_DEPTH` means recomputing every row constant, not adjusting a
  circuit-size parameter.

- **No native if/then.** Selecting "chain the previous job's output" vs.
  "start fresh," and selecting a Merkle direction bit, are both built from
  the selector-column + boolean-constraint + one-hot-sum + assertion
  pattern standard in hand-rolled STARK circuits — there's no R1CS gadget
  to translate from directly.

- **Range checks are hand-rolled bit decomposition.** The
  `license_expiry > current_timestamp` check uses 32 extra trace columns
  and a selector-gated weighted-sum constraint, active only at the leaf
  job's row. `license_expiry` is fixed at `submit_record` time and is
  independent of `current_timestamp` — deriving one from the other
  silently changes the leaf being proven against and surfaces later as a
  confusing `merkle_root mismatch`.

- **Public inputs are pinned to specific `(column, step)` cells** via
  `Assertion`s, not passed as free-floating wires — the trace's row layout
  is effectively part of the protocol's public interface.

- **Transition-constraint degree accounting is exact-match, not an upper
  bound**, and depends on the combination of periodic-column cycles and
  trace-column multiplications in each constraint. A mismatch either
  panics at proof/verify time or, worse, silently produces an invalid
  proof — double-check this after any constraint change.
