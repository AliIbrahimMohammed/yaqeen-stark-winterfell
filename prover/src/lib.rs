//! Reusable off-chain proving logic for `title_air::TitleAir`.
//!
//! Split out of `src/main.rs` (which is now a thin CLI wrapper around this
//! library) so the same trace-building and proving logic can be reused by
//! `canister`'s own test suite: generating a *genuine* valid STARK proof
//! and feeding it to the canister's real `verify_crypto_impl` closes a gap
//! that was previously only exercised via `run_full_cycle.sh` against a
//! live dfx replica -- the canister's own `#[cfg(test)]` module only ever
//! fed `verify_crypto_impl` garbage/malformed proof bytes, never a real
//! one. With this split, `cargo test -p title_verifier` alone now covers
//! it -- see `canister/src/lib.rs`'s
//! `verify_crypto_accepts_a_genuine_proof_from_the_real_prover` test.
//!
//! This crate plays the role of the owner's device / a proving service in
//! Yaqeen's architecture -- it is the only place `owner_secret` ever
//! exists, exactly as the README's security model requires ("the canister
//! never learns owner_secret").

use title_air::*;
use winterfell::{
    math::FieldElement, matrix::ColMatrix, AuxRandElements, ConstraintCompositionCoefficients,
    CompositionPoly, CompositionPolyTrace, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, PartitionOptions, Prover, StarkDomain, TraceInfo, TracePolyTable, TraceTable,
};
pub use winterfell::{
    crypto::MerkleTree, math::FieldElement as WinterFieldElement, BatchingMethod, FieldExtension,
    Proof, ProofOptions, Prover as WinterProver, Trace,
};

// ---------------------------------------------------------------------
// A minimal off-chain mirror of the canister's sparse Merkle tree, built
// with the exact same `title_air::hash`. In a real deployment this data
// comes from the canister's `getRecord` / `getMerkleProof` query calls
// instead of being reinvented here -- see the canister crate.
// ---------------------------------------------------------------------
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
        self.nodes.insert((0, index), leaf);
        let mut idx = index;
        let mut cur = leaf;
        for level in 0..TREE_DEPTH {
            let pair_base = (idx / 2) * 2;
            let sibling_index = if idx == pair_base { pair_base + 1 } else { pair_base };
            let sibling = self.node_at(level, sibling_index);
            let (l, r) = if idx % 2 == 0 { (cur, sibling) } else { (sibling, cur) };
            cur = hash(&[BaseElement::new(DOMAIN_NODE as u128), l, r]);
            idx /= 2;
            self.nodes.insert((level + 1, idx), cur);
        }
    }

    pub fn root(&self) -> BaseElement {
        self.node_at(TREE_DEPTH, 0)
    }

    /// Returns (siblings, path_bits) from `index` up to the root, same
    /// left/right-bit convention the canister's `getMerkleProof` uses:
    /// `bit == true` means the tracked node is the RIGHT child.
    pub fn proof(&self, index: usize) -> (Vec<BaseElement>, Vec<bool>) {
        let mut siblings = Vec::with_capacity(TREE_DEPTH);
        let mut bits = Vec::with_capacity(TREE_DEPTH);
        let mut idx = index;
        for level in 0..TREE_DEPTH {
            let pair_base = (idx / 2) * 2;
            let sibling_index = if idx == pair_base { pair_base + 1 } else { pair_base };
            siblings.push(self.node_at(level, sibling_index));
            bits.push(idx % 2 == 1);
            idx /= 2;
        }
        (siblings, bits)
    }
}

// ---------------------------------------------------------------------
// Witness
// ---------------------------------------------------------------------
pub struct Witness {
    // public
    pub registry_id: BaseElement,
    pub purpose: BaseElement,
    pub request_nonce: BaseElement,
    pub current_timestamp: u64,
    // private
    pub owner_secret: BaseElement,
    pub property_id: BaseElement,
    pub license_expiry: u64,
    pub merkle_siblings: Vec<BaseElement>, // len TREE_DEPTH
    pub merkle_bits: Vec<bool>,            // len TREE_DEPTH
}

pub fn to_bits_le(v: u64, n: usize) -> Vec<BaseElement> {
    (0..n)
        .map(|i| BaseElement::new(((v >> i) & 1) as u128))
        .collect()
}

/// Builds the full 256-row trace for `w`, following exactly the job
/// layout documented in `title_air`. Returns the trace plus the public
/// inputs it satisfies (so the caller doesn't have to separately recompute
/// owner_commitment / leaf / merkle_root / nullifier by hand).
pub fn build_trace(w: &Witness) -> (TraceTable<BaseElement>, PublicInputs) {
    let rcs = round_constants();
    let mut cols: Vec<Vec<BaseElement>> = vec![vec![BaseElement::ZERO; TRACE_LENGTH]; TRACE_WIDTH];

    for r in 0..TRACE_LENGTH {
        cols[HELD_SECRET][r] = w.owner_secret;
        cols[HELD_PID][r] = w.property_id;
    }

    // Runs one 8-row hash job, writing state/aux/type columns, and returns
    // the digest (s0 at the job's last row). A plain function (not a
    // closure) so the mutable borrow of `cols` doesn't outlive each call --
    // callers interleave direct `cols[..]` writes (e.g. the range-check
    // bits) between job invocations.
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

    let z = BaseElement::ZERO;
    let one = BaseElement::ONE;
    let dtag = |d: u64| BaseElement::new(d as u128);

    // Job 0: owner_commitment = H(DOMAIN_OWNER, owner_secret, property_id)
    let owner_commitment = run_job(
        &mut cols,
        &rcs,
        JOB_OWNER,
        [dtag(DOMAIN_OWNER_COMMITMENT), w.owner_secret, w.property_id, z, z, z, z, z],
        [z, z, z, z],
    );

    // Job 1: leaf = H(DOMAIN_LEAF, registry_id, owner_commitment, 0, 1, license_expiry)
    let license_expiry_fe = BaseElement::new(w.license_expiry as u128);
    let leaf = run_job(
        &mut cols,
        &rcs,
        JOB_LEAF,
        [
            dtag(DOMAIN_LEAF),
            w.registry_id,
            owner_commitment,
            z, // encumbrance_flag == 0
            one, // license_status == 1
            license_expiry_fe,
            z,
            z,
        ],
        [w.registry_id, z, one, license_expiry_fe],
    );

    // Leaf job's range-check bits (license_expiry - current_timestamp - 1),
    // 32-bit decomposition, written at the leaf job's own first row.
    {
        let diff = w
            .license_expiry
            .checked_sub(w.current_timestamp)
            .and_then(|d| d.checked_sub(1))
            .expect("license_expiry must be > current_timestamp");
        let bits = to_bits_le(diff, RANGE_BITS);
        let start = job_start_row(JOB_LEAF);
        for (i, b) in bits.into_iter().enumerate() {
            cols[RC_BIT_0 + i][start] = b;
        }
    }

    // Jobs 2..26: the 25 Merkle steps, leaf -> root.
    let mut current = leaf;
    for level in 0..TREE_DEPTH {
        let job = JOB_MERKLE_FIRST + level;
        let sibling = w.merkle_siblings[level];
        let bit = if w.merkle_bits[level] { one } else { z };
        let left = if w.merkle_bits[level] { sibling } else { current };
        let right = if w.merkle_bits[level] { current } else { sibling };
        current = run_job(
            &mut cols,
            &rcs,
            job,
            [dtag(DOMAIN_NODE), left, right, z, z, z, z, z],
            [sibling, bit, z, z],
        );
    }
    let merkle_root = current;

    // Job 27: nullifier = H(DOMAIN_NULLIFIER, owner_secret, property_id, purpose, request_nonce)
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

    // Jobs 28..31: padding. Just keep hashing forward harmlessly (typed as
    // merkle steps with a zero sibling/bit) so every row has a value
    // satisfying the AIR's uniform round formula; nothing downstream reads
    // these rows.
    let mut pad = nullifier;
    for job in (JOB_NULLIFIER + 1)..JOB_COUNT {
        pad = run_job(&mut cols, &rcs, job, [dtag(DOMAIN_NODE), pad, z, z, z, z, z, z], [z, z, z, z]);
    }

    let pub_inputs = PublicInputs {
        registry_id: w.registry_id,
        merkle_root,
        purpose: w.purpose,
        request_nonce: w.request_nonce,
        current_timestamp: BaseElement::new(w.current_timestamp as u128),
        nullifier,
    };

    (TraceTable::init(cols), pub_inputs)
}

pub struct TitleProver {
    options: ProofOptions,
    pub_inputs: PublicInputs,
}

impl TitleProver {
    pub fn new(options: ProofOptions, pub_inputs: PublicInputs) -> Self {
        Self { options, pub_inputs }
    }
}

impl Prover for TitleProver {
    type BaseField = BaseElement;
    type Air = TitleAir;
    type Trace = TraceTable<Self::BaseField>;
    type HashFn = HashFn;
    type VC = VC;
    type RandomCoin = RandCoin;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> PublicInputs {
        // The trace was built to satisfy exactly this statement (see
        // `build_trace`); rather than re-deriving registry_id / merkle_root
        // / etc. from trace cells here, the caller supplies them directly
        // at construction time so there's exactly one place (`build_trace`)
        // that computes them.
        self.pub_inputs.clone()
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}
