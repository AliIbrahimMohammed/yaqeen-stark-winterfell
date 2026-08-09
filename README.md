> **Status: builds, tests, deploys, and verifies for real, end to end.**
> `title_air`, `title_prover`, and `title_verifier` all compile clean
> against the genuine `winterfell` 0.13.1 crate (rustc 1.87+, `cargo build
> --target wasm32-unknown-unknown --release`). `air`'s unit tests pass. The
> off-chain prover generates a real STARK proof and self-verifies it
> (`local verify: OK`). The canister has been deployed to a real local
> replica (`dfx deploy`) and driven end-to-end through `bootstrap_admin` ->
> `submit_record` -> `request_challenge` -> `prove` -> **`verify`**, all
> against the live canister, with the canister returning a genuine
> `Ok(nullifier)` and logging a real on-chain instruction count. See
> ["Cost analysis"](#cost-analysis) for the measured numbers and
> [`TESTING.md`](./TESTING.md) for the fuller test history (including an
> earlier sandboxed dry run) and [`test-harness/`](./test-harness) for a
> standalone AIR-behavior harness.

# Yaqeen on ICP -- Winterfell STARK edition

This is Yaqeen's title-verification canister re-architected to match
[`ic-winterfell-verifier`](../ic-winterfell-verifier): proofs are
**Winterfell STARK proofs, generated off-chain**, and verified natively
on-chain by a Rust canister, instead of Groth16 proofs verified by a
vendored Motoko BLS12-381 pairing library.

The **statement being proven is unchanged** from the original Yaqeen/Groth16
version: the prover still proves ownership of a title, non-encumbrance, a
valid non-expired license, and Merkle-tree membership, without revealing
`owner_secret` or any private record data. What changed is *how* that
statement is expressed and checked.

```
yaqeen-stark/
├── air/        title_air crate: the AIR + shared hash/permutation,
│               linked unmodified by both the canister and the prover
├── canister/   title_verifier crate: the actual IC canister (Rust)
├── prover/     off-chain binary: builds the registry Merkle tree, the
│               witness, the trace, and generates a real proof
├── dfx.json
└── Cargo.toml  workspace root
```

Everything below has now been run against a real toolchain (rustc 1.87+),
a real `dfx` (0.32.0+), and a real local replica, including the full
`verify` call against a live challenge -- not reasoned through by hand
against documentation.

---

## Table of contents

- [System overview](#system-overview)
  - [The five-step workflow](#the-five-step-workflow)
  - [Canister interface: inputs & outputs](#canister-interface-inputs--outputs)
  - [Proof generation: prover inputs & outputs](#proof-generation-prover-inputs--outputs)
- [What changed, and why](#what-changed-and-why)
- [The AIR, in brief](#the-air-in-brief)
- [Cost analysis](#cost-analysis)
  - [Off-chain (proving)](#off-chain-proving)
  - [On-chain (verification)](#on-chain-verification)
  - [Proof size and the Groth16 trade-off](#proof-size-and-the-groth16-trade-off)
- [Challenges encountered](#challenges-encountered)
- [Build & deploy](#build--deploy)
- [Known limitations / the most likely bugs](#known-limitations--the-most-likely-bugs)

---

## System overview

At a high level, this project lets a title registry (the canister) issue
short-lived, single-use **challenges**, and lets a property owner (running
the prover on their own device) answer a challenge with a **zero-knowledge
proof** that they own a specific title, the title is unencumbered, its
license is currently valid, and it's genuinely a member of the registry's
Merkle tree -- all **without ever revealing which property it is or the
owner's private secret** to the canister or to anyone watching the chain.
The only things that become public are: the registry's current Merkle
root, the purpose of the check, a nonce and timestamp binding the proof to
one specific challenge, and a **nullifier** -- a one-time-use value that
lets the canister detect a replayed proof without learning which property
produced it.

### The five-step workflow

```
 admin/back-office              property owner's device            canister (on-chain)
 ──────────────────             ─────────────────────────           ────────────────────
 1. submit_record  ───────────────────────────────────────────────▶  updates registry's
    (property fields,                                                Merkle tree + root
     NOT owner_secret)

                                 2. request_challenge  ◀──────────────  issues challenge_id,
                                    (purpose)               ─────────▶  merkle_root, nonce,
                                                                        timestamp (5 min TTL)

                                 3. build witness + trace,
                                    generate STARK proof
                                    (off-chain, private)

                                 4. verify  ─────────────────────────▶  checks public inputs
                                    (challenge_id, proof_bytes,          match the challenge,
                                     public_inputs)                      runs winterfell::verify,
                                                          ◀───────────  returns Ok(nullifier)
                                                                        or Err(reason)
```

1. **Record submission** (admin-only, off the critical path for any single
   proof). An admin calls `submit_record` with a property's public fields
   -- `property_id`, an `owner_commitment` (a hash computed off-canister
   from `owner_secret` + `property_id`, never the secret itself),
   `encumbrance_flag`, `license_status`, and `license_expiry`. The
   canister hashes these into a leaf, inserts or updates that leaf in its
   Merkle tree, and returns the tree's new root. **Output:** the updated
   Merkle root (a decimal-string field element).

2. **Challenge request.** Anyone (typically the prospective prover) calls
   `request_challenge` with a `purpose` code (e.g. "sale", "lease").
   **Input:** `purpose : nat64`. **Output:** a `ChallengeView` containing
   `challenge_id`, the registry's *current* `merkle_root`, `registry_id`,
   `purpose` (echoed back), a fresh `request_nonce`, the replica's real
   `current_timestamp`, and `expires_at` -- the challenge is valid for
   5 minutes (`CHALLENGE_TTL_NS`) from issuance.

3. **Proof generation** (off-chain, on the owner's own device -- see
   [below](#proof-generation-prover-inputs--outputs) for the full
   input/output contract). The prover combines the owner's private
   witness with the exact `current_timestamp` and `request_nonce` the
   challenge just returned, builds an execution trace satisfying the
   AIR's constraints, and produces a STARK proof plus the matching public
   inputs.

4. **Verification.** The prover (or anyone holding the proof) calls
   `verify` with `challenge_id`, the raw `proof_bytes`, and the
   `public_inputs` the prover printed. The canister checks the public
   inputs against the stored challenge, then calls `winterfell::verify`
   against the AIR. **Output:** `Ok(VerifyOk { nullifier })` on success,
   or `Err(String)` describing exactly which check failed. On success the
   challenge is marked consumed and the nullifier marked spent, so the
   same proof (or the same challenge) cannot be replayed.

5. **(Optional) read access.** `get_record` and `get_merkle_proof` are
   `query` calls anyone can use to inspect a property's stored public
   fields or fetch the sibling path needed to build a proof for it,
   without needing prover access to the owner's own machine.

### Canister interface: inputs & outputs

The full Candid interface (`canister/title_verifier.did`):

| Method | Kind | Inputs | Output |
|---|---|---|---|
| `bootstrap_admin` | update | `principal` | `Ok` / `Err(text)` -- succeeds once, only while the canister has zero admins |
| `add_admin` / `remove_admin` | update | `principal` | `Ok` / `Err(text)` -- admin-only |
| `submit_record` | update | `property_id : nat64`, `owner_commitment : text`, `encumbrance_flag : nat64`, `license_status : nat64`, `license_expiry : nat64` | `Ok(text)` -- the registry's new Merkle root -- or `Err(text)`; admin-only |
| `request_challenge` | update | `purpose : nat64` | `Ok(ChallengeView)` or `Err(text)`; rate-limited per caller |
| `get_record` | query | `property_id : nat64` | `opt Record` -- the property's stored public fields, or `null` |
| `get_merkle_proof` | query | `property_id : nat64` | `opt MerkleProof` -- `root`, `leaf_index`, `path_bits`, `siblings`, or `null` |
| `verify` | update | `challenge_id : nat64`, `proof_bytes : blob`, `public_inputs : VerifyPublicInputs` | `Ok(VerifyOk { nullifier : text })` or `Err(text)` |
| `health` | query | -- | `text` status string |

`VerifyPublicInputs`, the third argument to `verify`, is:

```candid
type VerifyPublicInputs = record {
  registry_id       : nat64;  // which registry this proof is against
  merkle_root        : text;  // decimal field element -- must equal the
                               // challenge's merkle_root at issuance time
  purpose             : nat64; // must equal the challenge's purpose
  request_nonce       : nat64; // must equal the challenge's request_nonce
  current_timestamp   : nat64; // must equal the challenge's current_timestamp
  nullifier            : text; // decimal field element -- must not already
                               // be spent
};
```

`verify` checks these fields **before** doing any cryptographic work, in
this exact order: `registry_id` match -> `merkle_root` match -> `purpose`
match -> `request_nonce` match -> `current_timestamp` match -> nullifier
not already spent -> proof bytes decode -> `winterfell::verify(...)`
against the AIR. Any mismatch short-circuits with a specific `Err(text)`
(e.g. `"merkle_root mismatch"`, `"unknown or expired challenge"`,
`"challenge already consumed"`, `"nullifier already spent"`, `"invalid
proof: ..."`) before the expensive verification step runs, which is also
why a rejected call at this stage logs a very small instruction count --
see "Challenges" for how that can be mistaken for a cryptographic
failure when it's actually a stale-challenge or copy/paste issue.

Note what is deliberately **not** an input anywhere in this interface:
`owner_secret`, or which `property_id` the proof is about. The canister
never sees either -- that's the entire point of proving membership rather
than submitting the record directly.

### Proof generation: prover inputs & outputs

`prover/src/main.rs` is a standalone binary that runs entirely off-chain,
typically on the property owner's own device. It never talks to the
canister directly (there is no network call in the prover) -- it takes
plain values as CLI arguments and file/console output, and the resulting
proof is submitted to the canister separately via `dfx canister call`.

**Inputs** (some hardcoded as demo/scaffolding values inside `main()`,
some real CLI arguments):

| Input | Source | Notes |
|---|---|---|
| `current_timestamp` | CLI arg 1 | must exactly equal the `current_timestamp` the live `request_challenge` call returned |
| `request_nonce` | CLI arg 2 | must exactly equal the `request_nonce` the live `request_challenge` call returned |
| `license_expiry` | CLI arg 3 | must exactly equal the value originally passed to `submit_record` for this property -- it is **not** derived from `current_timestamp` (see "Challenges" #4) |
| `owner_secret`, `property_id` | hardcoded demo constants in `main()` | private witness values; in a real deployment these come from the owner's own records, never from the canister |
| `registry_id`, `purpose` | hardcoded demo constants | must match the values used when the corresponding `submit_record`/`request_challenge` calls were made |
| Merkle siblings/path | computed in-process by the prover's own `SparseTree`, from the same witness values | must correspond to the property's actual leaf position in the canister's real tree (leaf index 0, i.e. the first record ever submitted to that registry, in this scaffolding's current form) |

**Outputs**, printed to the console and written to `verify_args.candid`:

- The public inputs, printed individually: `registry_id`, `merkle_root`,
  `purpose`, `request_nonce`, `current_timestamp`, `nullifier` -- these
  are exactly the fields the `verify` call's `VerifyPublicInputs`
  argument needs.
- **Proof size and proving time** -- e.g. `proof size: 46346 bytes`,
  `proving time: 0.075s (74 ms)`.
- A local self-check: `winterfell::verify` run against the same AIR and
  proof, in-process, printing `local verify: OK` before anything is
  sent anywhere. This catches a broken witness/trace before spending a
  canister call on it.
- `verify_args.candid`: a file containing the full ready-to-run
  `dfx canister call title_verifier verify --argument-file
  verify_args.candid` argument tuple -- `({challengeId}, blob "...",
  record { ... })` -- with the real proof bytes and public inputs
  embedded, and a literal `{challengeId}` placeholder to be replaced
  with the real `challenge_id` from `request_challenge`'s response (the
  arguments are written to a file, not printed inline, because the
  proof blob is too large for a single shell command line -- see
  "Challenges" and "Build & deploy").

In short: the prover's inputs are one private witness (never leaves the
owner's device) plus a handful of public values that must exactly match a
live, unexpired challenge; its output is a proof blob plus a matching
public-inputs record, packaged as a ready-to-submit Candid argument file.

---

## What changed, and why

| | Yaqeen (Groth16, original) | Yaqeen (Winterfell STARK, this port) |
|---|---|---|
| Proof system | Groth16 (pairing-based SNARK) | STARK (FRI-based, transparent) |
| Curve / field | BLS12-381 scalar field | Winterfell's native `f128` prime field |
| Circuit model | R1CS (arkworks) | AIR -- fixed-shape execution trace + transition constraints |
| Hash function | Poseidon over BLS12-381 `Fr` | A from-scratch sponge-like permutation over `f128` ("RPO-lite", see below) |
| Trusted setup | Required (Groth16 always needs one); `ceremony/`'s whole Phase-2 MPC toolkit exists because of this | **None.** STARKs are transparent -- there is nothing to run a ceremony for, and the entire `ceremony/` risk category (Yaqeen's own README calls it "the highest-stakes open item") disappears |
| On-chain verifier | Vendored BLS12-381 pairing library in Motoko (~4,000 lines, unmodified upstream) | `winterfell::verify()`, a published Rust crate, called directly -- no vendored cryptography to maintain |
| Canister language | Motoko | Rust (`ic-cdk`), matching `ic-winterfell-verifier`'s own choice, since Winterfell is a Rust library |
| Proof size | 192 bytes (Groth16's headline property) | ~46 KB, measured (see [below](#proof-size-and-the-groth16-trade-off)) |
| Measured on-chain cost | ~20.9B instructions, ~3 DTS rounds (measured on a real replica) | **19,779,043 instructions, measured on a real replica** -- see [cost analysis](#on-chain-verification) |

The single biggest reason to make this trade at all: **Groth16's 192-byte
proof is bought entirely by a trusted setup ceremony**, and Yaqeen's own
`ROADMAP.md`/README are explicit that the real multi-party ceremony has
never actually run -- it's the top item on their own risk list. Moving to a
transparent proof system removes that entire category of risk (no ceremony,
no toxic waste, no "was Phase 1 sourced honestly" question) at the cost of
a larger proof and, most importantly, **a completely new, unaudited
cryptographic hash function** replacing a Poseidon instance that was at
least parameterized by a standard script. See
["Challenges"](#challenges-encountered) for the full trade-off discussion --
this is not a strictly-better swap, it trades one category of risk for
another.

## The AIR, in brief

`air/src/lib.rs` documents this in detail; the short version:

- The statement (owner commitment -> leaf -> 25-level Merkle inclusion ->
  nullifier, plus the encumbrance/license/expiry checks) is expressed as a
  **fixed-shape, 256-row, 50-column trace** -- 32 "jobs" of 8 rows each (28
  real hash invocations + 4 padding jobs), where each job runs an 8-round
  permutation and job-to-job "boundary" rows wire outputs into the next
  job's inputs (Merkle sibling/direction selection, public-input pinning,
  etc.) via one-hot job-type selector columns.
- Unlike the R1CS circuit, which can express Poseidon-over-BLS12-381
  directly, this AIR needed its **own hash function** designed to fit
  Winterfell's field and the "everything is a polynomial constraint" model
  -- see `air/src/lib.rs`'s "Why the hash function had to change" section.
  It is explicitly a **scaffolding placeholder**, exactly like Yaqeen's own
  `poseidon_config()` disclaimer, and needs a reviewed replacement (Rescue
  Prime, a properly-analyzed Poseidon2 instance for this field, etc.)
  before any real value depends on it.
- `TREE_DEPTH = 25` is now a **compile-time constant baked into the trace
  shape**, not a circuit parameter -- same limitation
  `ic-winterfell-verifier`'s own README calls out ("no dynamic/generic AIR
  loading... a canister that needs to verify multiple distinct computations
  needs one `Air` implementation per computation").
- `air`'s own unit tests (`hash_is_deterministic`,
  `trace_length_is_power_of_two`) pass under `cargo test -p title_air`, and
  a full 256-row/50-column trace built by `prover/src/main.rs` for a real
  demo record satisfies every one of the AIR's 49 transition constraints
  and 39 assertions end-to-end -- confirmed both by the prover's own
  `winterfell::verify(...)` call printing `local verify: OK`, and,
  ultimately, by the deployed canister's own `winterfell::verify()`
  returning `Ok(...)` on-chain.

## Cost analysis

Every number in this section is now measured, not estimated: off-chain
proving on a real toolchain, and on-chain verification against the
deployed canister on a real local replica, with the instruction count read
directly from the canister's own logged output.

### Off-chain (proving)

Proving cost for a STARK scales roughly with `trace_width * trace_length *
log(trace_length) * blowup_factor` (dominated by low-degree extensions /
FFTs over the whole trace, plus building the Merkle commitments over the
extended domain). Concretely for `title_air`:

- `trace_length = 256`, `trace_width = 50`, `blowup_factor = 8` (as
  configured in `prover/src/main.rs`) -> LDE domain size = 2,048.
- That domain is **tiny** by STARK standards (`ic-winterfell-verifier`'s
  own benchmarks go up to a 2,097,152-row domain for their largest case).
- **Measured**: `cargo run --release -p title_prover` builds the trace,
  proves it, and self-verifies well under a second on a single modern
  core. Across several runs against different challenges, proving time
  consistently landed in the **48-75 ms** range, with proof size
  consistently in the **~44-46 KB** range (46,346 bytes on the run that
  went on to verify successfully on-chain).
- The dominant real-world cost here is **not proving time** -- it's the
  engineering cost of getting the AIR right (see "Challenges" below) and,
  operationally, running the off-chain prover somewhere trustworthy (the
  owner's own device, matching the original security model: "the canister
  never learns `owner_secret`").

### On-chain (verification)

This is the number that matters most for the architecture decision, and
it's where switching away from pairings pays off:

- Yaqeen's Groth16 verifier measured **~20.9 billion instructions per
  call**, spanning **~3 DTS (deterministic time-slicing) rounds** --
  multi-second finality, and uncomfortably close to needing careful
  instruction budgeting (see Yaqeen's own README "Performance" table).
  That cost is dominated by the pairing (Miller loop + final
  exponentiation), which is inherently expensive arithmetic.
- STARK verification has **no pairings at all** -- it's Merkle-path
  checks (cheap hash comparisons) plus FRI folding steps plus evaluating
  the AIR's transition constraints at a handful of random query points.
- **Measured, on the live canister**: a real `verify` call, against a real
  `request_challenge`-issued challenge, with a real proof generated for
  that exact challenge, logged:

  ```
  verify: proof_bytes=46346B instructions=19779043
  ```

  That's **19,779,043 instructions** (~19.8M) for a full end-to-end
  verification -- registry-root check, temporal check, Merkle-path
  verification, FRI folding, and constraint evaluation for all 49
  transition constraints across 50 trace columns.
- Set against the IC's own limits, that's:
  - **~0.28%** of the 7B-instruction single-execution-round ceiling
  - **~0.05%** of the 40B-instruction update-call ceiling
  - roughly **1,057x cheaper** than the 20.9B-instruction Groth16 call it
    replaces, while also moving from ~3 DTS rounds (multi-second
    finality) down to comfortably within a **single** execution round
- For context, `ic-winterfell-verifier`'s own measured numbers for a much
  smaller AIR (`WorkAir`: 1 column, 1 constraint) ranged from ~19M
  instructions (1,024-row trace) to ~48M instructions (262,144-row
  trace). `title_air` is wider (50 columns vs. 1) and has far more
  constraints (49 vs. 1), but its LDE domain (2,048) is far smaller than
  any `WorkAir` benchmark case -- and the measured 19.8M-instruction cost
  landing right at the low end of `WorkAir`'s own range confirms that the
  domain size, not column/constraint count, is the dominant term for a
  circuit this small.
- The full round trip, including network/consensus overhead (`time dfx
  canister call ... verify`), measured **~2.5 seconds wall-clock** on a
  local replica -- most of that is `dfx`/replica request overhead, not
  execution time, since the actual instruction count above corresponds to
  a small fraction of a single execution round.

### Proof size and the Groth16 trade-off

- Groth16: **192 bytes**, always, regardless of circuit size -- the
  property that makes pairing-based SNARKs so attractive for on-chain
  verification cost *and* calldata cost.
- `ic-winterfell-verifier`'s `WorkAir` proofs ranged from **~29.6 KB**
  (1,024-row trace) to **~85.2 KB** (262,144-row trace).
- `title_air`'s proof, **measured directly on the successful on-chain
  run**: **46,346 bytes** (~45.3 KB) -- despite a very different shape
  from `WorkAir` (more columns per query, ~50 field elements opened per
  query instead of 1, pushing size up; a much shallower Merkle-commitment
  tree, 2,048 leaves vs. up to ~2.1M, pushing it back down, since Merkle
  authentication paths dominate STARK proof size), it lands squarely in
  the same range `ic-winterfell-verifier` observed.
- This is a **~241x larger proof** than Yaqeen's Groth16 proof. For an
  update call sending the proof as a `blob` argument, that's still small
  relative to the IC's message size limits, but it is real, ongoing
  bandwidth/storage cost per verification that the original architecture
  didn't have, and is the direct price of removing the trusted-setup
  requirement.

## Challenges encountered

In rough order of how much design effort they took:

1. **No native pairing-free hash existed for this field.** Yaqeen's
   Poseidon instance is defined over BLS12-381's scalar field; Winterfell
   proofs are over its own `f128` field. There is no way to reuse the
   existing hash -- a new one had to be designed from scratch
   (`air/src/lib.rs`'s `apply_round`/`hash`), and **it is unaudited**. This
   is the single biggest new risk this port introduces, and the first
   thing that needs real cryptographic review before any value depends on
   this system.
2. **AIRs don't have a native "if/then" the way R1CS gadgets do.**
   Selecting between "chain the previous job's output" vs. "start fresh"
   (owner_commitment/nullifier vs. leaf/merkle), and selecting Merkle
   left/right by a direction bit, both had to be built from the
   selector-column + boolean-constraint + one-hot-sum + assertion pattern
   that's standard in hand-rolled STARK circuits but has no R1CS
   equivalent to translate from -- it's genuinely new design work, not a
   line-by-line port of `circuit/src/lib.rs`.
3. **Fixed trace shape.** An `Air`'s trace length is fixed by
   `TraceInfo`/`AirContext` at construction, not chosen freely like an
   R1CS witness size. `TREE_DEPTH` and the hash job count had to become
   compile-time constants baked into `TRACE_LENGTH`, and the job count had
   to be padded (28 -> 32) purely so `JOB_COUNT * ROUNDS` lands on a power
   of two, which Winterfell's periodic columns and FFT-based LDE require.
4. **Range checks need hand-rolled bit decomposition, same as R1CS, but
   wired through selector-gated single-row constraints instead of a
   circuit gadget.** The `license_expiry > current_timestamp` check
   (originally a `to_bits_gadget` + comparison trick in
   `circuit/src/lib.rs`) became 32 extra trace columns and a
   selector-gated weighted-sum constraint, active only at the leaf job's
   row. Note that `license_expiry` is a value fixed at `submit_record`
   time and is otherwise independent of `current_timestamp` -- deriving
   one from the other (rather than treating them as separate,
   independently-supplied values) is a mistake that surfaces as a
   `merkle_root mismatch` at verify time, since it silently changes the
   leaf being proven against.
5. **Transition-constraint degree accounting is exact-match, not just an
   upper bound**, and it depends on the *combination* of periodic-column
   cycles and trace-column multiplications in each constraint -- a
   mismatch either panics at proof/verify time or (worse) silently
   produces an invalid proof. This was the leading suspect for the first
   real bug once a toolchain was available, and it turned out to be
   correct on the first `cargo build`/`cargo test` -- no degree mismatch
   surfaced.
6. **Public inputs must be pinned to specific `(column, step)` cells via
   `Assertion`s**, not passed as free-floating circuit wires the way R1CS
   public inputs are. That makes the trace's row *layout* (which job sits
   at which absolute row) effectively part of the protocol's public
   interface -- changing `TREE_DEPTH` later means recomputing every row
   constant in `air/src/lib.rs`, not just a circuit-size parameter.
7. **Proof size vs. trusted setup is a real trade-off, not a strict
   improvement** -- see the cost analysis above. This port trades Yaqeen's
   single biggest outstanding risk (the trusted setup ceremony never
   having actually run) for a new one (an unaudited hash function) plus a
   real, ongoing bandwidth/storage cost increase. Whether that trade is
   worth it depends on the deployment's actual threat model and volume,
   not something this port can decide unilaterally.
8. **Same WASM/canister constraints `ic-winterfell-verifier` already
   documented**: no `concurrent`/`rayon` in the canister (single-threaded
   WASM sandbox), `verify` must be an `update` call (not `query`) for
   consensus certification, and a structurally malformed (not just
   cryptographically invalid) proof can trap the call via an internal
   `assert_eq!` inside Winterfell rather than returning a graceful error --
   `ic-winterfell-verifier`'s README flags this as "a real finding, not a
   hypothetical," and nothing in this port changes that; the same
   `catch_unwind`-based hardening they suggest applies here too and isn't
   implemented yet.
9. **Candid `int128`/`nat128` tooling gaps**, same as
   `ic-winterfell-verifier`: field elements cross the Candid boundary as
   decimal strings rather than native integers, for the same reason
   documented in that project's README.
10. **Challenges expire, and expiry is easy to hit by accident.**
    `request_challenge` issues a short-lived challenge
    (`CHALLENGE_TTL_NS`, 5 minutes in this deployment); any pause between
    requesting the challenge and calling `verify` -- rebuilding the
    prover, patching source, or just working through commands by hand --
    can burn the whole window, surfacing as `unknown or expired
    challenge` with a suspiciously small logged instruction count (the
    canister rejects at the lookup stage, before ever touching the
    proof). The reliable pattern is: request the challenge, immediately
    prove against its exact `current_timestamp`/`request_nonce`, and
    verify right away, treating the whole sequence as one atomic unit
    rather than three independent steps.
11. **Getting from "reasoned by hand" to "actually compiles" surfaced real,
    if minor, `ic-cdk`/`candid` API drift** (see `TESTING.md` for the
    three fixes this needed: `ic_cdk::caller()` removal, an unnecessary
    `CandidType`/`Deserialize` derive on an internal-only struct, and a
    missing `FieldElement` trait import for `BaseElement::ZERO`) -- exactly
    the kind of "minor issues... as usual with hand-written Rust against a
    library that has changed across versions" `ic-winterfell-verifier`'s
    own README warned to expect. None of it touched the AIR's actual
    constraint logic.

## Build & deploy

```bash
rustup default stable   # needs rustc 1.87+ / edition2024 support (1.85+)
rustup target add wasm32-unknown-unknown
cargo install candid-extractor
export PATH="$HOME/.cargo/bin:$PATH"   # candid-extractor lands here

# 1. Does the AIR compile and pass its own unit tests?
cargo test -p title_air

# 2. Build and deploy the canister.
dfx start --clean --background
dfx deploy
#    dfx builds title_verifier itself; the committed canister/title_verifier.did
#    is a hand-written stand-in. Regenerate the authoritative one from the
#    real WASM before deploying (or immediately after, then redeploy):
candid-extractor target/wasm32-unknown-unknown/release/title_verifier.wasm \
  > canister/title_verifier.did

# 3. Bootstrap admin and submit a record. license_expiry must be comfortably
#    in the future relative to the replica's real clock -- it is NOT derived
#    from any timestamp the prover sees later; it's fixed here.
dfx canister call title_verifier bootstrap_admin \
  "(principal \"$(dfx identity get-principal)\")"

dfx canister call title_verifier submit_record \
  '(42:nat64, "<owner_commitment>", 0:nat64, 1:nat64, <license_expiry>:nat64)'

# 4. Request a challenge, and move through the remaining steps immediately --
#    challenges expire (CHALLENGE_TTL_NS, 5 minutes in this deployment).
dfx canister call title_verifier request_challenge '(1:nat64)'
# -> note the real challenge_id, request_nonce, and current_timestamp

# 5. Prove against that exact challenge -- real values, not placeholders.
cargo run --release -p title_prover -- <current_timestamp> <request_nonce> <license_expiry>
#    -> prints public inputs, "local verify: OK", proof size, proving time,
#       and writes verify_args.candid with a {challengeId} placeholder
#       (the args are written to a file, not printed inline, since the
#       proof blob is too large for a single shell command line).

# 6. Patch in the real challenge_id and verify.
sed -i "s/{challengeId}/<real_challenge_id>/" verify_args.candid
time dfx canister call title_verifier verify --argument-file verify_args.candid
```

A successful call returns `variant { Ok = record { nullifier = "..." } }`
and logs a line like:

```
[Canister ...] verify: proof_bytes=46346B instructions=19779043
```

That instruction count is the real on-chain verification cost -- see
["Cost analysis"](#on-chain-verification) for how it compares to the IC's
execution limits and to the original Groth16 verifier.

One thing to watch: the prover builds its own private, single-leaf Merkle
tree assuming its record lands at leaf index 0. That only matches the
canister's actual tree if `submit_record` in step 3 was the *first* record
ever submitted to that `registry_id` -- submitting other records first (or
re-submitting to update a different property first) will shift the
canister's real Merkle root away from what the prover's proof assumes, and
`verify` will (correctly) reject with `merkle_root mismatch`.

## Known limitations / the most likely bugs

- **The linear "mix" layer (`MIX` constant / `mix()` function) is not a
  verified MDS matrix.** For a real deployment this needs to be replaced
  with a matrix that's actually been checked for the MDS property (or the
  whole permutation swapped for an established one) -- see point 1 in
  "Challenges."
- **No `catch_unwind` hardening** around `winterfell::verify` in the
  canister yet -- a structurally malformed proof can trap the whole
  `update` call rather than returning `Err(..)`, same open item
  `ic-winterfell-verifier`'s own network testing surfaced.
- **Stable-memory upgrade persistence uses the legacy
  `ic_cdk::storage::stable_save`/`stable_restore` pair**, adequate for a
  prototype's state size but worth migrating to `ic-stable-structures` for
  a real deployment with a large registry (unbounded `Vec`-based
  encode/decode on every upgrade doesn't scale indefinitely).
- **The permutation, MDS-like mixing layer, and round count (8 rounds) are
  scaffolding choices, not the output of a real security analysis** --
  exactly parallel to Yaqeen's own `poseidon_config()` disclaimer
  ("placeholder parameter generation for scaffolding purposes only").
  Number of rounds, S-box degree, and the mixing matrix all need proper
  cryptanalysis before this protects anything of value.
- **The committed `canister/title_verifier.did` is hand-written**, not
  generated from the real WASM. It matches the real interface (confirmed
  via `candid-extractor` in this session), but should be regenerated and
  committed as the source of truth rather than hand-maintained going
  forward.
- **Challenge TTL is short (5 minutes) and easy to exceed during manual
  testing or debugging** -- see point 10 in "Challenges" for the failure
  mode and the recommended atomic request-prove-verify pattern.
