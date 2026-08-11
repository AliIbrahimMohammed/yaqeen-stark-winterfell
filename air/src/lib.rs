//! `title_air` -- the Algebraic Intermediate Representation (AIR) for
//! Yaqeen's title-verification statement, re-expressed as a fixed-shape
//! STARK circuit instead of a Groth16 R1CS circuit.
//!
//! Just like `ic-winterfell-verifier/air`, this crate is the single most
//! important piece of the whole system: a STARK proof only means "some
//! trace satisfying *this* AIR exists" -- it says nothing about what was
//! computed unless prover and verifier link the byte-identical AIR. So this
//! module is imported unmodified by both `title_prover` (off-chain) and
//! `title_verifier` (the canister).
//!
//! ## The statement (unchanged from Yaqeen's Noir/Groth16 version)
//!
//! The prover knows `owner_secret` such that:
//!   1. `owner_commitment = H(DOMAIN_OWNER_COMMITMENT, owner_secret, property_id)`
//!   2. `leaf = H(DOMAIN_LEAF, registry_id, owner_commitment, encumbrance_flag,
//!               license_status, license_expiry)` sits in the registry's
//!      depth-25 sparse Merkle tree at `merkle_root`
//!   3. `encumbrance_flag == 0`
//!   4. `license_status == 1`
//!   5. `license_expiry > current_timestamp` (32-bit range-checked)
//!   6. `nullifier = H(DOMAIN_NULLIFIER, owner_secret, property_id, purpose,
//!                    request_nonce)`
//!
//! Public inputs (6, same order Yaqeen used): `[registry_id, merkle_root,
//! purpose, request_nonce, current_timestamp, nullifier]`.
//!
//! ## Why the hash function had to change
//!
//! Yaqeen's circuit uses Poseidon over the BLS12-381 scalar field, because
//! that's what a pairing-based Groth16 verifier needs. Winterfell doesn't do
//! pairings at all -- it works over its own STARK-friendly prime field
//! (`winterfell::math::fields::f128`), so a byte-for-byte port of BLS12-381
//! Poseidon is neither meaningful nor necessary. Instead this AIR defines
//! its own small sponge-like permutation ("RPO-lite" below) natively over
//! `f128`, used consistently everywhere a hash is needed: inside the AIR
//! (as arithmetized trace constraints), in the off-chain prover (to build
//! the witness), and in the canister's own Merkle-tree bookkeeping (as a
//! plain, non-AIR Rust function -- see `hash()`), so the registry's
//! `currentRoot` and the AIR's `merkle_root` public input can never drift
//! apart.
//!
//! **This permutation is a scaffolding placeholder, not an audited
//! cryptographic hash function** -- exactly the same caveat Yaqeen's own
//! `poseidon_config()` carries for its BLS12-381 parameters. Swap in a
//! reviewed STARK-friendly permutation (e.g. Rescue-Prime, Poseidon2 tuned
//! for this field, or Winterfell's own `Rp64_256`-style construction) before
//! any real value depends on this.
//!
//! ## Trace layout
//!
//! The whole statement is a *fixed*-shape circuit (unlike the example
//! `WorkAir`, which takes a variable trace length): `TREE_DEPTH` is fixed at
//! 25, so the number of hash invocations, and therefore the trace length,
//! is a compile-time constant (`TRACE_LENGTH = 256`), not something a
//! caller can vary per proof.
//!
//! The trace is laid out as 32 fixed-size "jobs" of `ROUNDS = 8` rows each
//! (28 real hash invocations + 4 padding jobs, padded up so
//! `JOB_COUNT * ROUNDS` is a power of two):
//!
//! | Job index | Rows      | Computes                                   |
//! |----------:|-----------|---------------------------------------------|
//! | 0         | 0..7      | `owner_commitment`                          |
//! | 1         | 8..15     | `leaf` (also carries the range check)       |
//! | 2..26     | 16..215   | the 25 Merkle-path steps, leaf -> root      |
//! | 27        | 216..223  | `nullifier`                                 |
//! | 28..31    | 224..255  | padding (no public meaning)                 |
//!
//! Within a job, row 0 (`IS_FIRST`) carries that job's *own* fresh inputs
//! (in `aux_a..aux_d`, `t_owner..t_nullifier`) and, for chained jobs, reads
//! the *previous* job's digest out of `s0` at the previous job's row 7
//! (`IS_LAST`). Rows 1..7 apply the permutation's round function.
//!
//! Column layout (`TRACE_WIDTH = 50`):
//!
//! | Columns   | Meaning                                                       |
//! |-----------|----------------------------------------------------------------|
//! | 0..7      | permutation state `s0..s7` (`s0` is the digest output lane)   |
//! | 8..11     | `aux_a..aux_d` -- this job's fresh witness/public inputs       |
//! | 12,13     | `held_secret`, `held_pid` -- `owner_secret`/`property_id`, held constant across the *entire* trace so job 0 and job 27 can both read them |
//! | 14..17    | `t_owner,t_leaf,t_merkle,t_nullifier` -- one-hot job-type selector |
//! | 18..49    | `rc_bit_0..31` -- 32-bit decomposition, used only at row 8 to prove `license_expiry > current_timestamp` |

use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{FieldElement, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

// Re-exported so downstream crates (canister, prover) use the exact same
// field type without importing winterfell::math directly themselves.
pub use winterfell::math::fields::f128::BaseElement;


// ---------------------------------------------------------------------
// Hash function used for vector commitments (trace/constraint Merkle
// trees) and the Fiat-Shamir transcript. Unrelated to the in-circuit
// title-verification hash below -- this is Winterfell's own commitment
// scheme, same choice ic-winterfell-verifier made.
// ---------------------------------------------------------------------
pub type HashFn = Blake3_256<BaseElement>;
pub type RandCoin = DefaultRandomCoin<HashFn>;
pub type VC = MerkleTree<HashFn>;

// ---------------------------------------------------------------------
// Domain-separation tags -- identical values to Yaqeen's circuit, kept for
// continuity even though they now live in a different field.
// ---------------------------------------------------------------------
pub const DOMAIN_LEAF: u64 = 1;
pub const DOMAIN_OWNER_COMMITMENT: u64 = 2;
pub const DOMAIN_NULLIFIER: u64 = 3;
pub const DOMAIN_NODE: u64 = 4;

/// Depth of the registry's sparse Merkle tree. Fixed, like Yaqeen's.
pub const TREE_DEPTH: usize = 25;

// ---------------------------------------------------------------------
// Permutation parameters ("RPO-lite")
// ---------------------------------------------------------------------
pub const STATE_WIDTH: usize = 8;
pub const ROUNDS: usize = 8;
/// owner_commitment(1) + leaf(1) + merkle(TREE_DEPTH) + nullifier(1),
/// padded up to the next power of two.
pub const REAL_JOB_COUNT: usize = 3 + TREE_DEPTH;
pub const JOB_COUNT: usize = 32; // REAL_JOB_COUNT (28) padded to 32
pub const TRACE_LENGTH: usize = JOB_COUNT * ROUNDS; // 256

// Job indices.
pub const JOB_OWNER: usize = 0;
pub const JOB_LEAF: usize = 1;
pub const JOB_MERKLE_FIRST: usize = 2;
pub const JOB_MERKLE_LAST: usize = JOB_MERKLE_FIRST + TREE_DEPTH - 1; // 26
pub const JOB_NULLIFIER: usize = JOB_MERKLE_LAST + 1; // 27

pub const fn job_start_row(job: usize) -> usize {
    job * ROUNDS
}
pub const fn job_last_row(job: usize) -> usize {
    job * ROUNDS + ROUNDS - 1
}

/// Which one-hot type column a given job index is pinned to, for the
/// assertions in `get_assertions`. Jobs 0 = owner_commitment, 1 = leaf,
/// 2..=26 = the 25 Merkle steps, 27 = nullifier, 28..=31 = padding
/// (arbitrarily typed as merkle steps -- their output is never asserted).
pub const fn job_type_column(job: usize) -> usize {
    match job {
        JOB_OWNER => T_OWNER,
        JOB_LEAF => T_LEAF,
        JOB_NULLIFIER => T_NULLIFIER,
        j if j >= JOB_MERKLE_FIRST && j <= JOB_MERKLE_LAST => T_MERKLE,
        _ => T_MERKLE, // padding jobs 28..31
    }
}

pub const ROW_LEAF_FIRST: usize = job_start_row(JOB_LEAF); // 8
pub const ROW_MERKLE_LAST_OUTPUT: usize = job_last_row(JOB_MERKLE_LAST); // 215
pub const ROW_NULLIFIER_FIRST: usize = job_start_row(JOB_NULLIFIER); // 216
pub const ROW_NULLIFIER_OUTPUT: usize = job_last_row(JOB_NULLIFIER); // 223

// Column indices.
pub const S0: usize = 0; // .. S7 = 7 (digest/output lane is S0)
pub const AUX_A: usize = 8;
pub const AUX_B: usize = 9;
pub const AUX_C: usize = 10;
pub const AUX_D: usize = 11;
pub const HELD_SECRET: usize = 12;
pub const HELD_PID: usize = 13;
pub const T_OWNER: usize = 14;
pub const T_LEAF: usize = 15;
pub const T_MERKLE: usize = 16;
pub const T_NULLIFIER: usize = 17;
pub const RC_BIT_0: usize = 18; // .. RC_BIT_0 + 31 = 49
pub const RANGE_BITS: usize = 32;
pub const TRACE_WIDTH: usize = RC_BIT_0 + RANGE_BITS; // 50

/// Number of transition constraints returned by `evaluate_transition`:
/// 8 state lanes + held_secret + held_pid + 4 type-column booleans +
/// 1 one-hot-sum + 1 merkle-bit-boolean + 32 range-check bit booleans +
/// 1 range-check weighted-sum = 49.
pub const NUM_TRANSITION_CONSTRAINTS: usize = 8 + 2 + 4 + 1 + 1 + RANGE_BITS + 1;

// ---------------------------------------------------------------------
// Round constants for the permutation. Deterministic pseudo-random
// expansion of a fixed seed -- exactly as ad hoc, and exactly as clearly
// flagged as such, as Yaqeen's own placeholder `poseidon_config()`.
// ---------------------------------------------------------------------
pub fn round_constants() -> [[BaseElement; STATE_WIDTH]; ROUNDS] {
    // A tiny splitmix64-style expansion, seeded so both the prover and the
    // canister (and the AIR itself) derive byte-identical constants just by
    // calling this function -- no shared file to keep in sync, no risk of
    // drift.
    let mut seed: u64 = 0x5441_5145_454e_2d31; // "TAQEEN-1" as bytes-ish
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut out = [[BaseElement::ZERO; STATE_WIDTH]; ROUNDS];
    for r in out.iter_mut() {
        for lane in r.iter_mut() {
            let hi = next() as u128;
            let lo = next() as u128;
            *lane = BaseElement::new((hi << 64) | lo);
        }
    }
    out
}

/// Small fixed (non-audited) linear mixing layer, applied after the S-box
/// each round. A circulant matrix with small coefficients -- cheap to
/// evaluate, degree-1, and (for a real deployment) should be replaced with
/// a matrix that's been checked for the MDS property.
const MIX: [u64; STATE_WIDTH] = [2, 3, 1, 1, 1, 1, 1, 1];

fn mix<E: FieldElement<BaseField = BaseElement>>(state: &[E; STATE_WIDTH]) -> [E; STATE_WIDTH] {
    let coeffs: [E; STATE_WIDTH] = std::array::from_fn(|i| E::from(BaseElement::new(MIX[i] as u128)));
    std::array::from_fn(|i| {
        let mut acc = E::ZERO;
        for j in 0..STATE_WIDTH {
            acc += state[(i + j) % STATE_WIDTH] * coeffs[j];
        }
        acc
    })
}

fn sbox<E: FieldElement>(state: &[E; STATE_WIDTH]) -> [E; STATE_WIDTH] {
    std::array::from_fn(|i| state[i].exp(3u32.into()))
}

/// One round of the permutation: add round constants, S-box, mix.
/// Generic over `E` so the exact same code path is used symbolically
/// inside `evaluate_transition` (`E` = constraint-evaluation field) and
/// concretely inside the prover / canister (`E` = `BaseElement`).
pub fn apply_round<E: FieldElement<BaseField = BaseElement>>(
    state: &[E; STATE_WIDTH],
    round_constants: &[E; STATE_WIDTH],
) -> [E; STATE_WIDTH] {
    let added: [E; STATE_WIDTH] = std::array::from_fn(|i| state[i] + round_constants[i]);
    let boxed = sbox(&added);
    mix(&boxed)
}

/// Plain (non-AIR) hash, used by the canister to maintain its own Merkle
/// tree and by the prover to build witnesses / Merkle proofs. Absorbs up to
/// `STATE_WIDTH` field elements in one shot (all of this statement's hash
/// calls have at most 6 inputs, well under the 8-lane state), applies
/// `ROUNDS` rounds, and returns lane 0 as the digest.
///
/// This is the "job" logic from the trace, factored out so it can run
/// outside of any STARK context at all.
pub fn hash(inputs: &[BaseElement]) -> BaseElement {
    assert!(
        inputs.len() <= STATE_WIDTH,
        "hash() supports at most {STATE_WIDTH} inputs, got {}",
        inputs.len()
    );
    let mut state = [BaseElement::ZERO; STATE_WIDTH];
    state[..inputs.len()].copy_from_slice(inputs);
    let rcs = round_constants();
    // A "job" in the trace is ROUNDS=8 rows: 1 initial row + 7 row-to-row
    // transitions (the 8th row-to-row transition, from a job's last row
    // into the next job's first row, is the boundary/chaining step wired
    // in evaluate_transition, not another permutation round). This plain
    // hash() must apply exactly the same number of rounds as the in-circuit
    // job logic (see run_job in prover/src/main.rs), or values computed
    // off-circuit (Merkle roots, leaves, nullifiers) can never match what
    // any real trace proves.
    for rc in rcs.iter().take(ROUNDS - 1) {
        state = apply_round(&state, rc);
    }
    state[0]
}

// ---------------------------------------------------------------------
// Public inputs
// ---------------------------------------------------------------------
#[derive(Clone, Debug)]
pub struct PublicInputs {
    pub registry_id: BaseElement,
    pub merkle_root: BaseElement,
    pub purpose: BaseElement,
    pub request_nonce: BaseElement,
    pub current_timestamp: BaseElement,
    pub nullifier: BaseElement,
}

impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![
            self.registry_id,
            self.merkle_root,
            self.purpose,
            self.request_nonce,
            self.current_timestamp,
            self.nullifier,
        ]
    }
}

// ---------------------------------------------------------------------
// The AIR
// ---------------------------------------------------------------------
pub struct TitleAir {
    context: AirContext<BaseElement>,
    pub_inputs: PublicInputs,
}

impl Air for TitleAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        assert_eq!(
            TRACE_WIDTH,
            trace_info.width(),
            "trace must have exactly {TRACE_WIDTH} columns"
        );
        assert_eq!(
            TRACE_LENGTH,
            trace_info.length(),
            "trace must have exactly {TRACE_LENGTH} rows -- this AIR proves a fixed-shape \
             statement (TREE_DEPTH = {TREE_DEPTH}), it does not take a variable trace length"
        );

        // Degrees, in the same order evaluate_transition writes `result`.
        // The permutation round (S-box exponent 3) dominates; boundary/
        // selection terms are multiplied by a cycle-8 periodic gate, so we
        // declare them with `with_cycles`. These are conservative (rather
        // than hand-optimized) degree bounds -- tightening them is a
        // legitimate follow-up once this compiles and is benchmarked
        // locally (see README "Known limitations").
        let mut degrees = Vec::with_capacity(NUM_TRANSITION_CONSTRAINTS);
        for _ in 0..STATE_WIDTH {
            degrees.push(TransitionConstraintDegree::with_cycles(3, vec![ROUNDS]));
        }
        degrees.push(TransitionConstraintDegree::new(1)); // held_secret copy
        degrees.push(TransitionConstraintDegree::new(1)); // held_pid copy
        for _ in 0..4 {
            degrees.push(TransitionConstraintDegree::with_cycles(2, vec![ROUNDS])); // t_* boolean
        }
        degrees.push(TransitionConstraintDegree::with_cycles(1, vec![ROUNDS])); // one-hot sum
        degrees.push(TransitionConstraintDegree::with_cycles(3, vec![ROUNDS])); // merkle-bit boolean
        for _ in 0..RANGE_BITS {
            degrees.push(TransitionConstraintDegree::new(2)); // range bits boolean (unconditional)
        }
        degrees.push(TransitionConstraintDegree::with_cycles(2, vec![ROUNDS])); // range weighted-sum

        // Assertions: 7 public-input/constant values (registry_id,
        // encumbrance_flag==0, license_status==1, merkle_root, purpose,
        // request_nonce, nullifier) PLUS one assertion per job (32) pinning
        // that job's one-hot type column to 1. The type-column assertions
        // are what make the job sequence (owner -> leaf -> 25 merkle steps
        // -> nullifier -> padding) a fixed part of the *statement* rather
        // than something a prover could relabel; the boolean + one-hot-sum
        // transition constraints then force the other three type columns
        // to 0 at that row for free.
        let num_assertions = 7 + JOB_COUNT;

        TitleAir {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            pub_inputs,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let cur = frame.current();
        let nxt = frame.next();

        // periodic_values layout: [rc_0..rc_7 (8 cols), is_first, is_last]
        let rc: [E; STATE_WIDTH] = std::array::from_fn(|i| periodic_values[i]);
        let is_first = periodic_values[STATE_WIDTH];
        let is_last = periodic_values[STATE_WIDTH + 1];
        let not_last = E::ONE - is_last;

        // ---- normal round formula (used when !is_last) ----
        let cur_state: [E; STATE_WIDTH] = std::array::from_fn(|i| cur[i]);
        let round_next = apply_round(&cur_state, &rc);

        // ---- boundary formula (used when is_last; reads job-owning data
        // from the NEXT row, since aux/t columns "belong" to the job that's
        // about to start) ----
        let t_owner = nxt[T_OWNER];
        let t_leaf = nxt[T_LEAF];
        let t_merkle = nxt[T_MERKLE];
        let t_nullifier = nxt[T_NULLIFIER];
        let aux_a = nxt[AUX_A];
        let aux_b = nxt[AUX_B];
        let aux_c = nxt[AUX_C];
        let aux_d = nxt[AUX_D];
        let held_secret = cur[HELD_SECRET];
        let held_pid = cur[HELD_PID];
        let prev_out = cur[S0]; // this job's finished digest

        let domain_owner = E::from(BaseElement::new(DOMAIN_OWNER_COMMITMENT as u128));
        let domain_leaf = E::from(BaseElement::new(DOMAIN_LEAF as u128));
        let domain_node = E::from(BaseElement::new(DOMAIN_NODE as u128));
        let domain_nullifier = E::from(BaseElement::new(DOMAIN_NULLIFIER as u128));

        // Merkle left/right selection: {left,right} must be a permutation
        // of {prev_out, sibling(aux_a)}, chosen by bit(aux_b). Written
        // without branching so both witnesses cost the same.
        let left = aux_b * aux_a + (E::ONE - aux_b) * prev_out;
        let right = aux_b * prev_out + (E::ONE - aux_b) * aux_a;

        // Per job type, the 5 meaningful input lanes (s0 = domain tag,
        // s1..s5 = the rest); s6/s7 unused (always 0):
        //   owner:     [domain_owner,     held_secret, held_pid,   0,          0,            0]
        //   leaf:      [domain_leaf,      aux_a(=registry_id), prev_out(=owner_commitment), aux_b(=encumbrance=0), aux_c(=license_status=1), aux_d(=license_expiry)]
        //   merkle:    [domain_node,      left,        right,      0,          0,            0]
        //   nullifier: [domain_nullifier, held_secret, held_pid,   aux_a(=purpose), aux_b(=request_nonce), 0]
        let boundary_s0 = t_owner * domain_owner
            + t_leaf * domain_leaf
            + t_merkle * domain_node
            + t_nullifier * domain_nullifier;
        let boundary_s1 =
            t_owner * held_secret + t_leaf * aux_a + t_merkle * left + t_nullifier * held_secret;
        let boundary_s2 =
            t_owner * held_pid + t_leaf * prev_out + t_merkle * right + t_nullifier * held_pid;
        let boundary_s3 = t_leaf * aux_b + t_nullifier * aux_a;
        let boundary_s4 = t_leaf * aux_c + t_nullifier * aux_b;
        let boundary_s5 = t_leaf * aux_d;
        let boundary = [
            boundary_s0,
            boundary_s1,
            boundary_s2,
            boundary_s3,
            boundary_s4,
            boundary_s5,
            E::ZERO,
            E::ZERO,
        ];

        for i in 0..STATE_WIDTH {
            result[i] = nxt[i] - (not_last * round_next[i] + is_last * boundary[i]);
        }

        // held_secret / held_pid: constant across the whole trace.
        result[8] = nxt[HELD_SECRET] - cur[HELD_SECRET];
        result[9] = nxt[HELD_PID] - cur[HELD_PID];

        // t_* boolean + one-hot, gated to matter only at each job's first
        // row (`is_first`, evaluated on the CURRENT row, since t_* belongs
        // to whichever job owns the current row once it's begun).
        let is_first_cur = {
            // is_first as defined on `periodic_values` is aligned to the
            // current row already (Winterfell aligns periodic values with
            // the frame's current step), so reuse it directly.
            is_first
        };
        result[10] = is_first_cur * (cur[T_OWNER] * cur[T_OWNER] - cur[T_OWNER]);
        result[11] = is_first_cur * (cur[T_LEAF] * cur[T_LEAF] - cur[T_LEAF]);
        result[12] = is_first_cur * (cur[T_MERKLE] * cur[T_MERKLE] - cur[T_MERKLE]);
        result[13] = is_first_cur * (cur[T_NULLIFIER] * cur[T_NULLIFIER] - cur[T_NULLIFIER]);
        result[14] = is_first_cur
            * (cur[T_OWNER] + cur[T_LEAF] + cur[T_MERKLE] + cur[T_NULLIFIER] - E::ONE);

        // merkle direction bit (aux_b) must be boolean, only when this
        // job is a merkle step.
        result[15] = is_first_cur * cur[T_MERKLE] * (cur[AUX_B] * cur[AUX_B] - cur[AUX_B]);

        // range-check bits: unconditionally boolean (harmless where unused
        // -- the honest prover just sets them to 0).
        for i in 0..RANGE_BITS {
            let b = cur[RC_BIT_0 + i];
            result[16 + i] = b * b - b;
        }

        // range-check weighted sum, gated to the leaf job's first row only:
        // sum(bit_i * 2^i) == license_expiry - current_timestamp - 1
        // (the standard "diff doesn't underflow" trick for a>b given both
        // fit comfortably under 2^32).
        let mut weighted = E::ZERO;
        for i in 0..RANGE_BITS {
            weighted += cur[RC_BIT_0 + i] * E::from(BaseElement::new(1u128 << i));
        }
        let current_timestamp = E::from(self.pub_inputs.current_timestamp);
        // Evaluated when `cur` IS the leaf job's own first row (is_first_cur
        // gates on the current row's cycle position, and license_expiry
        // lives in `cur[AUX_D]` on that same row).
        let diff = cur[AUX_D] - current_timestamp - E::ONE;
        result[16 + RANGE_BITS] = is_first_cur * cur[T_LEAF] * (weighted - diff);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut a = vec![
            Assertion::single(AUX_A, ROW_LEAF_FIRST, self.pub_inputs.registry_id),
            Assertion::single(AUX_B, ROW_LEAF_FIRST, BaseElement::ZERO), // encumbrance_flag == 0
            Assertion::single(AUX_C, ROW_LEAF_FIRST, BaseElement::ONE), // license_status == 1
            Assertion::single(S0, ROW_MERKLE_LAST_OUTPUT, self.pub_inputs.merkle_root),
            Assertion::single(AUX_A, ROW_NULLIFIER_FIRST, self.pub_inputs.purpose),
            Assertion::single(AUX_B, ROW_NULLIFIER_FIRST, self.pub_inputs.request_nonce),
            Assertion::single(S0, ROW_NULLIFIER_OUTPUT, self.pub_inputs.nullifier),
        ];
        for job in 0..JOB_COUNT {
            let col = job_type_column(job);
            a.push(Assertion::single(col, job_start_row(job), BaseElement::ONE));
        }
        a
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let rcs = round_constants();
        let mut cols: Vec<Vec<BaseElement>> = (0..STATE_WIDTH)
            .map(|lane| (0..ROUNDS).map(|r| rcs[r][lane]).collect())
            .collect();
        let mut is_first = vec![BaseElement::ZERO; ROUNDS];
        is_first[0] = BaseElement::ONE;
        let mut is_last = vec![BaseElement::ZERO; ROUNDS];
        is_last[ROUNDS - 1] = BaseElement::ONE;
        cols.push(is_first);
        cols.push(is_last);
        cols
    }
}

mod tests {
    #[allow(unused_imports)] // harmless: unused when this file is compiled
    // stand-alone (winterfell) vs. through the test-harness facade (which
    // already re-exports everything via `pub use air_source::*` one level
    // up) -- keeping the import documents the module's real dependency
    // either way instead of leaving it to hidden crate-level re-exports.
    use super::*;

    #[test]
    fn hash_is_deterministic() {
        let a = hash(&[BaseElement::new(1), BaseElement::new(2)]);
        let b = hash(&[BaseElement::new(1), BaseElement::new(2)]);
        assert_eq!(a, b);
        let c = hash(&[BaseElement::new(1), BaseElement::new(3)]);
        assert_ne!(a, c);
    }

    #[test]
    fn trace_length_is_power_of_two() {
        assert!(TRACE_LENGTH.is_power_of_two());
        assert_eq!(TRACE_LENGTH, 256);
    }

    // -----------------------------------------------------------------
    // hash()
    // -----------------------------------------------------------------

    #[test]
    fn hash_is_sensitive_to_input_order() {
        // Domain separation / argument order matters: swapping two inputs
        // must not collide, or the "leaf" and "nullifier" statements could
        // be confused with each other off-chain.
        let a = hash(&[BaseElement::new(1), BaseElement::new(2)]);
        let b = hash(&[BaseElement::new(2), BaseElement::new(1)]);
        assert_ne!(a, b);
    }

    #[test]
    fn hash_zero_pads_and_can_collide_across_lengths() {
        // `hash()` right-pads its input with zeros up to STATE_WIDTH, so
        // `hash(&[1])` and `hash(&[1, 0])` are DEFINED to collide -- this
        // is not a bug, it's the documented contract. This test pins that
        // contract down explicitly so it can't silently change, and so the
        // real safety boundary is visible in one place:
        //
        //   hash() is only safe to call with a FIXED arity per domain,
        //   tagged by a domain constant as the first element (as every
        //   call site in this codebase does -- see DOMAIN_NODE,
        //   DOMAIN_OWNER_COMMITMENT, DOMAIN_LEAF usage in
        //   prover/src/main.rs). It must never be called with untrusted,
        //   variable-length input expecting length to be part of the
        //   digest -- callers that need that must hash the length in
        //   explicitly (e.g. as an extra fixed-position field element).
        let a = hash(&[BaseElement::new(1)]);
        let b = hash(&[BaseElement::new(1), BaseElement::new(0)]);
        assert_eq!(a, b, "hash() zero-pads; this collision is expected");

        // But a genuinely different (non-zero-padding-equivalent) input
        // must still differ.
        let c = hash(&[BaseElement::new(1), BaseElement::new(2)]);
        assert_ne!(a, c);
    }

    #[test]
    fn hash_empty_input_is_deterministic_and_nonzero() {
        let a = hash(&[]);
        let b = hash(&[]);
        assert_eq!(a, b);
        // Sanity: an all-zero state run through real round constants
        // shouldn't land back on zero.
        assert_ne!(a, BaseElement::ZERO);
    }

    #[test]
    fn hash_accepts_full_width_input() {
        // STATE_WIDTH inputs is the documented max; must not panic.
        let inputs = [BaseElement::new(7); STATE_WIDTH];
        let _ = hash(&inputs);
    }

    #[test]
    #[should_panic(expected = "hash() supports at most")]
    fn hash_rejects_too_many_inputs() {
        let inputs = [BaseElement::new(1); STATE_WIDTH + 1];
        let _ = hash(&inputs);
    }

    // -----------------------------------------------------------------
    // round_constants() / apply_round()
    // -----------------------------------------------------------------

    #[test]
    fn round_constants_are_deterministic() {
        let a = round_constants();
        let b = round_constants();
        assert_eq!(a, b);
    }

    #[test]
    fn round_constants_are_not_trivially_zero() {
        // Every round should contribute real mixing; a bug in the splitmix
        // expansion (e.g. reseeding to 0) would silently degrade this.
        for round in round_constants().iter() {
            assert!(round.iter().any(|&c| c != BaseElement::ZERO));
        }
    }

    #[test]
    fn apply_round_is_deterministic() {
        let state = [BaseElement::new(1); STATE_WIDTH];
        let rc = round_constants()[0];
        let a = apply_round(&state, &rc);
        let b = apply_round(&state, &rc);
        assert_eq!(a, b);
    }

    #[test]
    fn apply_round_changes_state() {
        // A permutation round that leaves the state untouched would make
        // every job's digest independent of its inputs.
        let state = [BaseElement::new(1); STATE_WIDTH];
        let rc = round_constants()[0];
        let next = apply_round(&state, &rc);
        assert_ne!(state, next);
    }

    #[test]
    fn apply_round_is_sensitive_to_round_constants() {
        // Using round 0's constants vs round 1's constants on the same
        // input must diverge, or the permutation would effectively use
        // only a single round constant.
        let state = [BaseElement::new(5); STATE_WIDTH];
        let rcs = round_constants();
        let a = apply_round(&state, &rcs[0]);
        let b = apply_round(&state, &rcs[1]);
        assert_ne!(a, b);
    }

    // -----------------------------------------------------------------
    // Trace-layout invariants
    // -----------------------------------------------------------------

    #[test]
    fn job_and_row_layout_matches_docs() {
        assert_eq!(JOB_OWNER, 0);
        assert_eq!(JOB_LEAF, 1);
        assert_eq!(JOB_MERKLE_FIRST, 2);
        assert_eq!(JOB_MERKLE_LAST, 26);
        assert_eq!(JOB_NULLIFIER, 27);
        assert_eq!(REAL_JOB_COUNT, 28);
        assert_eq!(JOB_COUNT, 32);

        assert_eq!(job_start_row(JOB_LEAF), 8);
        assert_eq!(ROW_LEAF_FIRST, 8);
        assert_eq!(job_last_row(JOB_MERKLE_LAST), 215);
        assert_eq!(ROW_MERKLE_LAST_OUTPUT, 215);
        assert_eq!(job_start_row(JOB_NULLIFIER), 216);
        assert_eq!(ROW_NULLIFIER_FIRST, 216);
        assert_eq!(job_last_row(JOB_NULLIFIER), 223);
        assert_eq!(ROW_NULLIFIER_OUTPUT, 223);

        // Every job occupies exactly ROUNDS rows, and jobs tile the trace
        // with no gaps or overlaps.
        assert_eq!(job_last_row(JOB_COUNT - 1), TRACE_LENGTH - 1);
        for job in 0..JOB_COUNT {
            assert_eq!(job_last_row(job) - job_start_row(job) + 1, ROUNDS);
            if job > 0 {
                assert_eq!(job_start_row(job), job_last_row(job - 1) + 1);
            }
        }
    }

    #[test]
    fn job_type_column_covers_every_job_exactly_once_per_type() {
        assert_eq!(job_type_column(JOB_OWNER), T_OWNER);
        assert_eq!(job_type_column(JOB_LEAF), T_LEAF);
        assert_eq!(job_type_column(JOB_NULLIFIER), T_NULLIFIER);
        for job in JOB_MERKLE_FIRST..=JOB_MERKLE_LAST {
            assert_eq!(job_type_column(job), T_MERKLE);
        }
        // Padding jobs (28..=31) are arbitrarily typed as merkle steps,
        // per the doc comment -- pin that down so a future change to the
        // padding convention is a deliberate, visible edit.
        for job in (JOB_NULLIFIER + 1)..JOB_COUNT {
            assert_eq!(job_type_column(job), T_MERKLE);
        }
    }

    #[test]
    fn column_indices_are_within_bounds_and_non_overlapping() {
        // s0..s7, aux_a..d, held_secret/pid, t_owner..t_nullifier, then
        // rc_bit_0..31 must exactly tile TRACE_WIDTH with no gaps.
        let mut seen = vec![false; TRACE_WIDTH];
        let mut mark = |col: usize| {
            assert!(col < TRACE_WIDTH, "column {col} out of bounds");
            assert!(!seen[col], "column {col} used twice");
            seen[col] = true;
        };
        for c in 0..STATE_WIDTH {
            mark(c); // s0..s7
        }
        mark(AUX_A);
        mark(AUX_B);
        mark(AUX_C);
        mark(AUX_D);
        mark(HELD_SECRET);
        mark(HELD_PID);
        mark(T_OWNER);
        mark(T_LEAF);
        mark(T_MERKLE);
        mark(T_NULLIFIER);
        for i in 0..RANGE_BITS {
            mark(RC_BIT_0 + i);
        }
        assert!(seen.iter().all(|&b| b), "not every column is accounted for");
    }

    #[test]
    fn num_transition_constraints_matches_formula() {
        // 8 state lanes + held_secret + held_pid + 4 type-column booleans
        // + 1 one-hot-sum + 1 merkle-bit-boolean + 32 range bits + 1
        // range weighted-sum, per the doc comment above the constant.
        assert_eq!(
            NUM_TRANSITION_CONSTRAINTS,
            STATE_WIDTH + 2 + 4 + 1 + 1 + RANGE_BITS + 1
        );
        assert_eq!(NUM_TRANSITION_CONSTRAINTS, 49);
    }

    #[test]
    fn public_inputs_to_elements_preserves_order() {
        let pi = PublicInputs {
            registry_id: BaseElement::new(1),
            merkle_root: BaseElement::new(2),
            purpose: BaseElement::new(3),
            request_nonce: BaseElement::new(4),
            current_timestamp: BaseElement::new(5),
            nullifier: BaseElement::new(6),
        };
        assert_eq!(
            pi.to_elements(),
            vec![
                BaseElement::new(1),
                BaseElement::new(2),
                BaseElement::new(3),
                BaseElement::new(4),
                BaseElement::new(5),
                BaseElement::new(6),
            ]
        );
    }
}
