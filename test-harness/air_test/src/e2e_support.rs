//! Trace-building and cross-checking support for the "honest prover"
//! behavioral test, factored out of `src/bin/e2e_harness.rs` so every
//! function here has its own `#[test]`s and runs under plain `cargo test`
//! instead of only being exercised by manually running the binary.

use crate::*;
use winterfell::{math::FieldElement, Air, BatchingMethod, EvaluationFrame, FieldExtension, ProofOptions};

/// Reasonable demo `ProofOptions` for these constraint-evaluation tests.
/// Values only affect actual FRI/proof generation (which this harness
/// doesn't do -- see `../README.md`); `TitleAir::context()` just needs
/// *some* valid options to construct an `AirContext`.
pub fn demo_proof_options() -> ProofOptions {
    ProofOptions::new(
        28,                       // num_queries
        8,                        // blowup_factor
        0,                        // grinding_factor
        FieldExtension::None,
        4,                        // fri_folding_factor
        7,                        // fri_remainder_max_degree (2^3 - 1)
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

/// A depth-`TREE_DEPTH` sparse Merkle tree over `BaseElement`, using the
/// same `hash(&[DOMAIN_NODE, left, right])` construction the AIR's merkle
/// jobs use. "Sparse" here means unset leaves default to a precomputed
/// per-level zero-hash instead of being stored explicitly, so the whole
/// depth-25 tree never needs 2^25 real nodes in memory.
pub struct SparseTree {
    zero_hashes: Vec<BaseElement>,
    nodes: std::collections::HashMap<(usize, usize), BaseElement>,
}

impl SparseTree {
    pub fn new() -> Self {
        let mut zero_hashes = vec![BaseElement::ZERO; TREE_DEPTH + 1];
        for level in 1..=TREE_DEPTH {
            let z = zero_hashes[level - 1];
            zero_hashes[level] = hash(&[BaseElement::new(DOMAIN_NODE as u128), z, z]);
        }
        Self {
            zero_hashes,
            nodes: Default::default(),
        }
    }

    pub fn node_at(&self, level: usize, index: usize) -> BaseElement {
        *self
            .nodes
            .get(&(level, index))
            .unwrap_or(&self.zero_hashes[level])
    }

    pub fn insert_leaf(&mut self, index: usize, leaf: BaseElement) {
        assert!(
            index < (1usize << TREE_DEPTH),
            "leaf index {index} out of range for a depth-{TREE_DEPTH} tree"
        );
        self.nodes.insert((0, index), leaf);
        let mut idx = index;
        let mut cur = leaf;
        for level in 0..TREE_DEPTH {
            let pair_base = (idx / 2) * 2;
            let sibling_index = if idx == pair_base {
                pair_base + 1
            } else {
                pair_base
            };
            let sibling = self.node_at(level, sibling_index);
            let (l, r) = if idx % 2 == 0 {
                (cur, sibling)
            } else {
                (sibling, cur)
            };
            cur = hash(&[BaseElement::new(DOMAIN_NODE as u128), l, r]);
            idx /= 2;
            self.nodes.insert((level + 1, idx), cur);
        }
    }

    pub fn root(&self) -> BaseElement {
        self.node_at(TREE_DEPTH, 0)
    }

    /// Returns `(siblings, bits)` for `index`, both ordered leaf-to-root:
    /// `bits[i] == true` means the current node is the *right* child at
    /// level `i` (so `siblings[i]` is its left sibling), matching the same
    /// `{left,right}` selection the AIR's merkle-job constraint uses.
    pub fn proof(&self, index: usize) -> (Vec<BaseElement>, Vec<bool>) {
        assert!(
            index < (1usize << TREE_DEPTH),
            "leaf index {index} out of range for a depth-{TREE_DEPTH} tree"
        );
        let mut siblings = Vec::with_capacity(TREE_DEPTH);
        let mut bits = Vec::with_capacity(TREE_DEPTH);
        let mut idx = index;
        for level in 0..TREE_DEPTH {
            let pair_base = (idx / 2) * 2;
            let sibling_index = if idx == pair_base {
                pair_base + 1
            } else {
                pair_base
            };
            siblings.push(self.node_at(level, sibling_index));
            bits.push(idx % 2 == 1);
            idx /= 2;
        }
        (siblings, bits)
    }

    /// Recomputes a root from a leaf plus a `(siblings, bits)` proof,
    /// independent of any `SparseTree` instance. Used to cross-check that
    /// `proof()`/`root()` are mutually consistent without relying on the
    /// same struct that produced them.
    pub fn recompute_root(leaf: BaseElement, siblings: &[BaseElement], bits: &[bool]) -> BaseElement {
        assert_eq!(siblings.len(), TREE_DEPTH);
        assert_eq!(bits.len(), TREE_DEPTH);
        let mut cur = leaf;
        for level in 0..TREE_DEPTH {
            let (l, r) = if bits[level] {
                (siblings[level], cur)
            } else {
                (cur, siblings[level])
            };
            cur = hash(&[BaseElement::new(DOMAIN_NODE as u128), l, r]);
        }
        cur
    }
}

impl Default for SparseTree {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Witness {
    pub registry_id: BaseElement,
    pub purpose: BaseElement,
    pub request_nonce: BaseElement,
    pub current_timestamp: u64,
    pub owner_secret: BaseElement,
    pub property_id: BaseElement,
    pub license_expiry: u64,
    pub merkle_siblings: Vec<BaseElement>,
    pub merkle_bits: Vec<bool>,
}

/// Little-endian bit decomposition of `v` into `n` field elements (0 or 1).
/// Bits at or above position `n` are silently dropped -- callers must
/// ensure `v < 2^n`, which `build_trace` enforces via `checked_sub`/
/// `expect` before calling this for the range check.
pub fn to_bits_le(v: u64, n: usize) -> Vec<BaseElement> {
    (0..n)
        .map(|i| BaseElement::new(((v >> i) & 1) as u128))
        .collect()
}

/// Runs one "job" (`ROUNDS` rows) of the permutation into `cols`, writing
/// the job's type-selector, aux inputs, and full round-by-round state, and
/// returns the job's digest (final `s0`). Shared by every job in
/// `build_trace` below, so the row-layout logic exists in exactly one
/// place.
fn run_job(
    cols: &mut [Vec<BaseElement>],
    rcs: &[[BaseElement; STATE_WIDTH]; ROUNDS],
    job: usize,
    initial_state: [BaseElement; STATE_WIDTH],
    aux: [BaseElement; 4],
) -> BaseElement {
    let start = job_start_row(job);
    let t_col = job_type_column(job);
    for r in start..start + ROUNDS {
        cols[t_col][r] = BaseElement::ONE;
    }
    cols[AUX_A][start] = aux[0];
    cols[AUX_B][start] = aux[1];
    cols[AUX_C][start] = aux[2];
    cols[AUX_D][start] = aux[3];

    let mut state = initial_state;
    for lane in 0..STATE_WIDTH {
        cols[lane][start] = state[lane];
    }
    for r in 0..ROUNDS - 1 {
        state = apply_round(&state, &rcs[r]);
        for lane in 0..STATE_WIDTH {
            cols[lane][start + r + 1] = state[lane];
        }
    }
    state[0]
}

/// Builds a full honest execution trace (`TRACE_WIDTH` x `TRACE_LENGTH`
/// columns) for `w`, plus the `PublicInputs` it satisfies.
///
/// # Panics
/// Panics if `w.license_expiry <= w.current_timestamp` (the range-check
/// input would underflow) or if `w.merkle_siblings`/`w.merkle_bits` aren't
/// exactly `TREE_DEPTH` long.
pub fn build_trace(w: &Witness) -> (Vec<Vec<BaseElement>>, PublicInputs) {
    assert_eq!(
        w.merkle_siblings.len(),
        TREE_DEPTH,
        "witness must supply exactly TREE_DEPTH merkle siblings"
    );
    assert_eq!(
        w.merkle_bits.len(),
        TREE_DEPTH,
        "witness must supply exactly TREE_DEPTH merkle bits"
    );

    let rcs = round_constants();
    let mut cols: Vec<Vec<BaseElement>> = vec![vec![BaseElement::ZERO; TRACE_LENGTH]; TRACE_WIDTH];

    for r in 0..TRACE_LENGTH {
        cols[HELD_SECRET][r] = w.owner_secret;
        cols[HELD_PID][r] = w.property_id;
    }

    let z = BaseElement::ZERO;
    let one = BaseElement::ONE;
    let dtag = |d: u64| BaseElement::new(d as u128);

    let owner_commitment = run_job(
        &mut cols,
        &rcs,
        JOB_OWNER,
        [
            dtag(DOMAIN_OWNER_COMMITMENT),
            w.owner_secret,
            w.property_id,
            z,
            z,
            z,
            z,
            z,
        ],
        [z, z, z, z],
    );

    let license_expiry_fe = BaseElement::new(w.license_expiry as u128);
    let leaf = run_job(
        &mut cols,
        &rcs,
        JOB_LEAF,
        [
            dtag(DOMAIN_LEAF),
            w.registry_id,
            owner_commitment,
            z,
            one,
            license_expiry_fe,
            z,
            z,
        ],
        [w.registry_id, z, one, license_expiry_fe],
    );

    {
        let diff = w
            .license_expiry
            .checked_sub(w.current_timestamp)
            .and_then(|d| d.checked_sub(1))
            .expect("license_expiry must be > current_timestamp");
        assert!(
            diff < (1u64 << RANGE_BITS),
            "license_expiry - current_timestamp - 1 must fit in {RANGE_BITS} bits"
        );
        let bits = to_bits_le(diff, RANGE_BITS);
        let start = job_start_row(JOB_LEAF);
        for (i, b) in bits.into_iter().enumerate() {
            cols[RC_BIT_0 + i][start] = b;
        }
    }

    let mut current = leaf;
    for level in 0..TREE_DEPTH {
        let job = JOB_MERKLE_FIRST + level;
        let sibling = w.merkle_siblings[level];
        let bit_flag = w.merkle_bits[level];
        let bit = if bit_flag { one } else { z };
        // Must match the AIR's own left/right selection exactly
        // (air/src/lib.rs's evaluate_transition): when bit is set, `current`
        // is the RIGHT child and `sibling` is the LEFT child; when bit is
        // clear, `current` is the LEFT child. Writing `current`/`sibling`
        // straight into s1/s2 regardless of `bit` (as an earlier version of
        // this harness did) silently swaps left/right whenever bit==1,
        // producing a root that doesn't match a real Merkle tree's
        // convention even though every AIR constraint still happily
        // verifies it -- run_job just writes whatever initial_state it's
        // given, it doesn't re-derive left/right from bit itself.
        let (left, right) = if bit_flag { (sibling, current) } else { (current, sibling) };
        current = run_job(
            &mut cols,
            &rcs,
            job,
            [dtag(DOMAIN_NODE), left, right, z, z, z, z, z],
            [sibling, bit, z, z],
        );
    }
    let merkle_root = current;

    let nullifier = run_job(
        &mut cols,
        &rcs,
        JOB_NULLIFIER,
        [
            dtag(DOMAIN_NULLIFIER),
            w.owner_secret,
            w.property_id,
            w.purpose,
            w.request_nonce,
            z,
            z,
            z,
        ],
        [w.purpose, w.request_nonce, z, z],
    );

    let mut pad = nullifier;
    for job in (JOB_NULLIFIER + 1)..JOB_COUNT {
        pad = run_job(
            &mut cols,
            &rcs,
            job,
            [dtag(DOMAIN_NODE), pad, z, z, z, z, z, z],
            [z, z, z, z],
        );
    }

    let pub_inputs = PublicInputs {
        registry_id: w.registry_id,
        merkle_root,
        purpose: w.purpose,
        request_nonce: w.request_nonce,
        current_timestamp: BaseElement::new(w.current_timestamp as u128),
        nullifier,
    };

    (cols, pub_inputs)
}

/// Evaluates every transition constraint at every row of `cols` (wrapping
/// row `TRACE_LENGTH - 1`'s "next" row back to row 0, matching how
/// Winterfell treats the trace as cyclic for transition constraints).
pub fn eval_all_constraints(air: &TitleAir, cols: &[Vec<BaseElement>]) -> Vec<Vec<BaseElement>> {
    let periodic = air.get_periodic_column_values();
    let mut all_results = Vec::with_capacity(TRACE_LENGTH);
    for step in 0..TRACE_LENGTH {
        let next_step = (step + 1) % TRACE_LENGTH;
        let cur: Vec<BaseElement> = cols.iter().map(|c| c[step]).collect();
        let nxt: Vec<BaseElement> = cols.iter().map(|c| c[next_step]).collect();
        let frame = EvaluationFrame::from_rows(cur, nxt);
        let cycle_pos = step % ROUNDS;
        let pv: Vec<BaseElement> = periodic.iter().map(|col| col[cycle_pos % col.len()]).collect();
        let mut result = vec![BaseElement::ZERO; NUM_TRANSITION_CONSTRAINTS];
        air.evaluate_transition::<BaseElement>(&frame, &pv, &mut result);
        all_results.push(result);
    }
    all_results
}

/// Builds a small, deterministic "demo registry" witness: a single leaf
/// inserted at index 0 of an otherwise-empty depth-`TREE_DEPTH` tree, with
/// a one-year license window. Shared by tests and by `bin/e2e_harness.rs`
/// so there's one canonical honest-witness fixture.
pub fn demo_witness() -> (Witness, BaseElement /* independently-computed root */) {
    let registry_id = BaseElement::new(1);
    let owner_secret = BaseElement::new(0xA11CE_u64 as u128);
    let property_id = BaseElement::new(42);
    let owner_commitment = hash(&[
        BaseElement::new(DOMAIN_OWNER_COMMITMENT as u128),
        owner_secret,
        property_id,
    ]);
    let license_status = BaseElement::ONE;
    let encumbrance_flag = BaseElement::ZERO;
    let current_timestamp: u64 = 1_754_000_000;
    let license_expiry: u64 = current_timestamp + 365 * 24 * 3600;
    let leaf = hash(&[
        BaseElement::new(DOMAIN_LEAF as u128),
        registry_id,
        owner_commitment,
        encumbrance_flag,
        license_status,
        BaseElement::new(license_expiry as u128),
    ]);

    let mut tree = SparseTree::new();
    tree.insert_leaf(0, leaf);
    let (siblings, bits) = tree.proof(0);
    let root = tree.root();

    let witness = Witness {
        registry_id,
        purpose: BaseElement::new(1),
        request_nonce: BaseElement::new(7),
        current_timestamp,
        owner_secret,
        property_id,
        license_expiry,
        merkle_siblings: siblings,
        merkle_bits: bits,
    };
    (witness, root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use winterfell::TraceInfo;

    // -----------------------------------------------------------------
    // SparseTree
    // -----------------------------------------------------------------

    #[test]
    fn empty_tree_root_matches_recursive_zero_hash() {
        let tree = SparseTree::new();
        // An empty depth-D tree's root is H(DOMAIN_NODE, H(...), H(...))
        // applied D times starting from BaseElement::ZERO -- exactly what
        // `zero_hashes` computes, so this pins that `root()` actually reads
        // it rather than some other (possibly stale) value.
        let mut z = BaseElement::ZERO;
        for _ in 0..TREE_DEPTH {
            z = hash(&[BaseElement::new(DOMAIN_NODE as u128), z, z]);
        }
        assert_eq!(tree.root(), z);
    }

    #[test]
    fn single_insert_changes_root() {
        let mut tree = SparseTree::new();
        let empty_root = tree.root();
        tree.insert_leaf(0, BaseElement::new(123));
        assert_ne!(tree.root(), empty_root);
    }

    #[test]
    fn proof_recomputes_to_the_actual_root() {
        // Cross-check against an independent recomputation, not just
        // "root() didn't panic" -- this is the property a forged Merkle
        // proof would violate.
        let mut tree = SparseTree::new();
        let leaf = BaseElement::new(999);
        tree.insert_leaf(12345, leaf);
        let (siblings, bits) = tree.proof(12345);
        let recomputed = SparseTree::recompute_root(leaf, &siblings, &bits);
        assert_eq!(recomputed, tree.root());
    }

    #[test]
    fn proof_at_index_zero_and_max_index_both_work() {
        // Index 0 (all-left path) and the maximum valid index (all-right
        // path) exercise both ends of the bit-direction logic.
        let max_index = (1usize << TREE_DEPTH) - 1;
        for &index in &[0usize, max_index] {
            let mut tree = SparseTree::new();
            let leaf = BaseElement::new(index as u128 + 1);
            tree.insert_leaf(index, leaf);
            let (siblings, bits) = tree.proof(index);
            assert_eq!(SparseTree::recompute_root(leaf, &siblings, &bits), tree.root());
        }
    }

    #[test]
    fn two_leaves_both_verify_against_the_same_root() {
        let mut tree = SparseTree::new();
        let leaf_a = BaseElement::new(11);
        let leaf_b = BaseElement::new(22);
        tree.insert_leaf(5, leaf_a);
        tree.insert_leaf(6, leaf_b); // sibling of index 5
        let root = tree.root();

        let (sa, ba) = tree.proof(5);
        assert_eq!(SparseTree::recompute_root(leaf_a, &sa, &ba), root);
        let (sb, bb) = tree.proof(6);
        assert_eq!(SparseTree::recompute_root(leaf_b, &sb, &bb), root);
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn insert_leaf_rejects_out_of_range_index() {
        let mut tree = SparseTree::new();
        tree.insert_leaf(1usize << TREE_DEPTH, BaseElement::new(1));
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn proof_rejects_out_of_range_index() {
        let tree = SparseTree::new();
        let _ = tree.proof(1usize << TREE_DEPTH);
    }

    // -----------------------------------------------------------------
    // to_bits_le
    // -----------------------------------------------------------------

    #[test]
    fn to_bits_le_round_trips_small_values() {
        for v in [0u64, 1, 2, 3, 255, 256, 12345] {
            let bits = to_bits_le(v, 32);
            let mut reconstructed: u64 = 0;
            for (i, b) in bits.iter().enumerate() {
                if *b == BaseElement::ONE {
                    reconstructed |= 1 << i;
                }
            }
            assert_eq!(reconstructed, v, "round-trip failed for {v}");
        }
    }

    #[test]
    fn to_bits_le_has_requested_length() {
        assert_eq!(to_bits_le(1, 32).len(), 32);
        assert_eq!(to_bits_le(1, 0).len(), 0);
    }

    #[test]
    fn to_bits_le_bits_are_boolean() {
        let bits = to_bits_le(u64::MAX, 32);
        assert!(bits.iter().all(|b| *b == BaseElement::ZERO || *b == BaseElement::ONE));
    }

    #[test]
    fn to_bits_le_drops_bits_above_n() {
        // Documented behavior: bit 32 of a value is silently dropped when
        // n=32. Callers (build_trace) are responsible for ensuring the
        // value actually fits -- this test exists so that contract stays
        // visible and deliberate rather than discovered by accident.
        let with_high_bit = 1u64 << 32; // bit 32, outside the requested 32 bits
        let bits = to_bits_le(with_high_bit, 32);
        assert!(bits.iter().all(|b| *b == BaseElement::ZERO));
    }

    // -----------------------------------------------------------------
    // build_trace / demo_witness
    // -----------------------------------------------------------------

    #[test]
    fn build_trace_merkle_root_matches_independent_tree() {
        let (witness, independent_root) = demo_witness();
        let (_cols, pub_inputs) = build_trace(&witness);
        assert_eq!(pub_inputs.merkle_root, independent_root);
    }

    /// Regression test for a real bug found in an earlier version of this
    /// harness: `build_trace`'s merkle loop wrote `[current, sibling]`
    /// straight into `s1`/`s2` without checking `bit`, silently swapping
    /// left/right whenever `bit == 1`. Every AIR constraint still verified
    /// fine (the constraints only check that `{s1,s2}` is *some*
    /// permutation of `{prev_out, aux_a}` consistent with `aux_b`, and a
    /// trace built this way is self-consistent with its own `s1`/`s2`
    /// values) -- so the bug never showed up as a failing constraint or
    /// assertion. It only showed up as a root that didn't match what an
    /// independent, ordinary Merkle-tree implementation (`SparseTree`)
    /// computes for the same leaf/siblings/bits, which is exactly what
    /// this test checks.
    ///
    /// `demo_witness()` alone can't catch this: it always inserts at leaf
    /// index 0, whose proof is all `bit == false`, so the swap path never
    /// triggers there. This test inserts at an *odd* index specifically to
    /// force `bit == true` at level 0 (and exercise a mix of both at
    /// higher levels).
    #[test]
    fn build_trace_merkle_root_matches_independent_tree_with_right_child_bits() {
        let registry_id = BaseElement::new(1);
        let owner_secret = BaseElement::new(0xB0B_u64 as u128);
        let property_id = BaseElement::new(7);
        let owner_commitment = hash(&[
            BaseElement::new(DOMAIN_OWNER_COMMITMENT as u128),
            owner_secret,
            property_id,
        ]);
        let current_timestamp: u64 = 1_754_000_000;
        let license_expiry: u64 = current_timestamp + 1000;
        let leaf = hash(&[
            BaseElement::new(DOMAIN_LEAF as u128),
            registry_id,
            owner_commitment,
            BaseElement::ZERO,
            BaseElement::ONE,
            BaseElement::new(license_expiry as u128),
        ]);

        // A handful of other leaves in the tree so siblings along the path
        // are non-trivial (not just precomputed zero-hashes).
        let mut tree = SparseTree::new();
        for i in [0u64, 2, 3, 5, 9, 17].iter() {
            tree.insert_leaf(*i as usize, hash(&[BaseElement::new(*i as u128)]));
        }
        // Odd index -> bit == true at level 0.
        let index = 1usize;
        tree.insert_leaf(index, leaf);
        let (siblings, bits) = tree.proof(index);
        assert!(bits[0], "index 1's proof must have bit==true at level 0");
        let independent_root = tree.root();
        // Cross-check proof()/root() against the fully independent
        // recompute_root() as well, so this test doesn't just compare
        // build_trace against itself via a single shared code path.
        assert_eq!(
            SparseTree::recompute_root(leaf, &siblings, &bits),
            independent_root
        );

        let witness = Witness {
            registry_id,
            purpose: BaseElement::new(1),
            request_nonce: BaseElement::new(3),
            current_timestamp,
            owner_secret,
            property_id,
            license_expiry,
            merkle_siblings: siblings,
            merkle_bits: bits,
        };
        let (_cols, pub_inputs) = build_trace(&witness);
        assert_eq!(pub_inputs.merkle_root, independent_root);
    }

    #[test]
    fn build_trace_public_inputs_echo_the_witness() {
        let (witness, _root) = demo_witness();
        let (_cols, pub_inputs) = build_trace(&witness);
        assert_eq!(pub_inputs.registry_id, witness.registry_id);
        assert_eq!(pub_inputs.purpose, witness.purpose);
        assert_eq!(pub_inputs.request_nonce, witness.request_nonce);
        assert_eq!(
            pub_inputs.current_timestamp,
            BaseElement::new(witness.current_timestamp as u128)
        );
    }

    #[test]
    fn build_trace_nullifier_matches_plain_hash() {
        let (witness, _root) = demo_witness();
        let (_cols, pub_inputs) = build_trace(&witness);
        let expected = hash(&[
            BaseElement::new(DOMAIN_NULLIFIER as u128),
            witness.owner_secret,
            witness.property_id,
            witness.purpose,
            witness.request_nonce,
        ]);
        assert_eq!(pub_inputs.nullifier, expected);
    }

    #[test]
    fn build_trace_output_has_correct_dimensions() {
        let (witness, _root) = demo_witness();
        let (cols, _pub_inputs) = build_trace(&witness);
        assert_eq!(cols.len(), TRACE_WIDTH);
        assert!(cols.iter().all(|c| c.len() == TRACE_LENGTH));
    }

    #[test]
    #[should_panic(expected = "license_expiry must be > current_timestamp")]
    fn build_trace_rejects_expiry_equal_to_timestamp() {
        // Boundary case: expiry == timestamp must be rejected (statement
        // requires strictly-greater), not silently accepted.
        let (mut witness, _root) = demo_witness();
        witness.license_expiry = witness.current_timestamp;
        let _ = build_trace(&witness);
    }

    #[test]
    #[should_panic(expected = "license_expiry must be > current_timestamp")]
    fn build_trace_rejects_expiry_before_timestamp() {
        let (mut witness, _root) = demo_witness();
        witness.license_expiry = witness.current_timestamp - 1;
        let _ = build_trace(&witness);
    }

    #[test]
    #[should_panic(expected = "exactly TREE_DEPTH merkle siblings")]
    fn build_trace_rejects_wrong_sibling_count() {
        let (mut witness, _root) = demo_witness();
        witness.merkle_siblings.pop();
        let _ = build_trace(&witness);
    }

    #[test]
    #[should_panic(expected = "exactly TREE_DEPTH merkle bits")]
    fn build_trace_rejects_wrong_bit_count() {
        let (mut witness, _root) = demo_witness();
        witness.merkle_bits.pop();
        let _ = build_trace(&witness);
    }

    // -----------------------------------------------------------------
    // eval_all_constraints (full honest-trace + tamper checks)
    // -----------------------------------------------------------------

    fn honest_air_and_trace() -> (TitleAir, Vec<Vec<BaseElement>>) {
        let (witness, _root) = demo_witness();
        let (cols, pub_inputs) = build_trace(&witness);
        let trace_info = TraceInfo::new(TRACE_WIDTH, TRACE_LENGTH);
        let air = TitleAir::new(trace_info, pub_inputs, demo_proof_options());
        (air, cols)
    }

    #[test]
    fn honest_trace_satisfies_every_transition_constraint() {
        let (air, cols) = honest_air_and_trace();
        let results = eval_all_constraints(&air, &cols);
        for (step, r) in results.iter().enumerate() {
            for (i, v) in r.iter().enumerate() {
                assert_eq!(
                    *v,
                    BaseElement::ZERO,
                    "nonzero constraint at step {step}, index {i}: {v}"
                );
            }
        }
    }

    #[test]
    fn honest_trace_satisfies_every_assertion() {
        let (air, cols) = honest_air_and_trace();
        for a in air.get_assertions() {
            assert_eq!(
                cols[a.column()][a.first_step()], a.values()[0],
                "assertion failed: col={} step={}",
                a.column(), a.first_step()
            );
        }
    }

    #[test]
    fn tampering_encumbrance_flag_breaks_its_assertion() {
        // Soundness sanity: flipping encumbrance_flag from 0 to 1 must
        // make the trace mismatch the corresponding assertion, or the
        // "encumbrance_flag == 0" requirement isn't actually enforced.
        let (air, cols) = honest_air_and_trace();
        let leaf_start = job_start_row(JOB_LEAF);
        let mut tampered = cols;
        tampered[AUX_B][leaf_start] = BaseElement::ONE;

        let assertion = air
            .get_assertions()
            .into_iter()
            .find(|a| a.column() == AUX_B && a.first_step() == leaf_start)
            .expect("encumbrance_flag assertion must exist");
        assert_ne!(tampered[AUX_B][leaf_start], assertion.values()[0]);
    }

    #[test]
    fn tampering_merkle_root_breaks_its_assertion() {
        let (air, cols) = honest_air_and_trace();
        let mut tampered = cols;
        let out_row = ROW_MERKLE_LAST_OUTPUT;
        tampered[S0][out_row] += BaseElement::ONE;

        let assertion = air
            .get_assertions()
            .into_iter()
            .find(|a| a.column() == S0 && a.first_step() == out_row)
            .expect("merkle_root assertion must exist");
        assert_ne!(tampered[S0][out_row], assertion.values()[0]);
    }

    #[test]
    fn tampering_a_permutation_row_breaks_a_transition_constraint() {
        // Unlike the assertion-level tamper checks above, this corrupts a
        // mid-permutation row (not a job boundary) and checks the *AIR's
        // own* transition constraints -- not just get_assertions -- catch
        // it. This is the property that actually makes the STARK sound
        // against a forged trace.
        let (air, cols) = honest_air_and_trace();
        let mut tampered = cols;
        tampered[S0][3] += BaseElement::ONE; // mid-round row inside job 0

        let results = eval_all_constraints(&air, &tampered);
        let any_nonzero = results.iter().flatten().any(|v| *v != BaseElement::ZERO);
        assert!(
            any_nonzero,
            "tampering a mid-permutation row produced no nonzero constraint anywhere"
        );
    }

    #[test]
    fn hash_matches_run_job_round_count() {
        // hash() must apply exactly ROUNDS-1 rounds, matching what
        // build_trace's run_job does per job -- otherwise off-circuit
        // values (e.g. the canister's own Merkle bookkeeping) would never
        // match what a real trace proves.
        let (witness, _root) = demo_witness();
        let mut state = [BaseElement::ZERO; STATE_WIDTH];
        state[0] = BaseElement::new(DOMAIN_OWNER_COMMITMENT as u128);
        state[1] = witness.owner_secret;
        state[2] = witness.property_id;
        let rcs = round_constants();
        let mut manual = state;
        for r in 0..ROUNDS - 1 {
            manual = apply_round(&manual, &rcs[r]);
        }
        let via_hash = hash(&[
            BaseElement::new(DOMAIN_OWNER_COMMITMENT as u128),
            witness.owner_secret,
            witness.property_id,
        ]);
        assert_eq!(manual[0], via_hash);
    }
}
