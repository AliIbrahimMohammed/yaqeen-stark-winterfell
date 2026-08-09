//! Off-chain prover for `title_air::TitleAir`.
//!
//! Mirrors `ic-winterfell-verifier/prover_example`: this binary does NOT
//! run on the IC. It plays the role of the owner's device / a proving
//! service in Yaqeen's architecture -- it is the only place `owner_secret`
//! ever exists, exactly as the original README's security model requires
//! ("the canister never learns owner_secret").
//!
//! It (1) builds a tiny in-memory registry + depth-25 sparse Merkle tree
//! using the SAME hash (`title_air::hash`) the canister uses for its own
//! bookkeeping, (2) computes a Merkle witness for one demo record,
//! (3) builds the full 256-row execution trace satisfying `TitleAir`,
//! (4) proves it, and (5) prints a ready-to-paste `dfx canister call`.
//!
//! Run with: `cargo run --release -p title_prover`

use title_air::*;
use winterfell::{
    crypto::MerkleTree, math::FieldElement, matrix::ColMatrix, AuxRandElements, BatchingMethod,
    CompositionPoly, CompositionPolyTrace, ConstraintCompositionCoefficients,
    DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde, FieldExtension,
    PartitionOptions, Proof, ProofOptions, Prover, StarkDomain, Trace, TraceInfo, TracePolyTable,
    TraceTable,
};

// ---------------------------------------------------------------------
// A minimal off-chain mirror of the canister's sparse Merkle tree, built
// with the exact same `title_air::hash`. In a real deployment this data
// comes from the canister's `getRecord` / `getMerkleProof` query calls
// instead of being reinvented here -- see the canister crate.
// ---------------------------------------------------------------------
struct SparseTree {
    zero_hashes: Vec<BaseElement>,
    nodes: std::collections::HashMap<(usize, usize), BaseElement>,
}

impl SparseTree {
    fn new() -> Self {
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

    fn node_at(&self, level: usize, index: usize) -> BaseElement {
        *self
            .nodes
            .get(&(level, index))
            .unwrap_or(&self.zero_hashes[level])
    }

    fn insert_leaf(&mut self, index: usize, leaf: BaseElement) {
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

    fn root(&self) -> BaseElement {
        self.node_at(TREE_DEPTH, 0)
    }

    /// Returns (siblings, path_bits) from `index` up to the root, same
    /// left/right-bit convention the canister's `getMerkleProof` uses:
    /// `bit == true` means the tracked node is the RIGHT child.
    fn proof(&self, index: usize) -> (Vec<BaseElement>, Vec<bool>) {
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
struct Witness {
    // public
    registry_id: BaseElement,
    purpose: BaseElement,
    request_nonce: BaseElement,
    current_timestamp: u64,
    // private
    owner_secret: BaseElement,
    property_id: BaseElement,
    license_expiry: u64,
    merkle_siblings: Vec<BaseElement>, // len TREE_DEPTH
    merkle_bits: Vec<bool>,            // len TREE_DEPTH
}

fn to_bits_le(v: u64, n: usize) -> Vec<BaseElement> {
    (0..n)
        .map(|i| BaseElement::new(((v >> i) & 1) as u128))
        .collect()
}

/// Builds the full 256-row trace for `w`, following exactly the job
/// layout documented in `title_air`. Returns the trace plus the public
/// inputs it satisfies (so the caller doesn't have to separately recompute
/// owner_commitment / leaf / merkle_root / nullifier by hand).
fn build_trace(w: &Witness) -> (TraceTable<BaseElement>, PublicInputs) {
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

struct TitleProver {
    options: ProofOptions,
    pub_inputs: PublicInputs,
}

impl TitleProver {
    fn new(options: ProofOptions, pub_inputs: PublicInputs) -> Self {
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

fn main() {
    // ---- 1. Build a demo registry with one record and the resulting tree ----
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
    // Pass the real `current_timestamp` a live `request_challenge` call
    // returned, e.g.: `cargo run --release -p title_prover -- 1786283167`.
    // The canister's `verify` rejects any proof whose public
    // `current_timestamp` doesn't exactly match the challenge it was
    // issued against, so this can't be a stale hardcoded demo value once
    // you're proving against a real deployed canister.
    let current_timestamp: u64 = std::env::args()
        .nth(1)
        .map(|s| s.parse().expect("current_timestamp arg must be a u64"))
        .unwrap_or(1_754_000_000); // fallback: local self-verify only, not for a real challenge
    // license_expiry must match what was actually written on-chain via
    // submit_record -- it is NOT derived from current_timestamp. Deriving
    // it from current_timestamp silently changes the leaf (and therefore
    // the whole tree's root) every time you pass a different challenge
    // timestamp, which is what caused "merkle_root mismatch": the real
    // on-chain leaf was built with the license_expiry value submitted at
    // registration time, not "now + 1 year". Pass it as the 3rd CLI arg,
    // e.g.: cargo run --release -p title_prover -- <timestamp> <nonce> 1785536000
    let license_expiry: u64 = std::env::args()
        .nth(3)
        .map(|s| s.parse().expect("license_expiry arg must be a u64"))
        .unwrap_or(1_785_536_000); // fallback: matches the submit_record call used in TESTING.md
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
    let merkle_root = tree.root();
    assert_eq!(merkle_root, tree.root());

    // ---- 2. Challenge (in a real flow this comes from `requestChallenge`) ----
    let purpose = BaseElement::new(1); // e.g. "sale"
    // Second CLI arg: the real request_nonce a live `request_challenge`
    // call returned. It's baked into the nullifier (job 27's inputs), so
    // it isn't checked by an equality assertion the way current_timestamp
    // is -- but if it doesn't match, the nullifier this proof commits to
    // won't match what the canister computes for VerifyPublicInputs, and
    // the proof's own binding (nullifier is a public input) means verify
    // will still reject.
    let request_nonce = BaseElement::new(
        std::env::args()
            .nth(2)
            .map(|s| s.parse().expect("request_nonce arg must be a u64"))
            .unwrap_or(7), // fallback: local self-verify only, not for a real challenge
    );

    let witness = Witness {
        registry_id,
        purpose,
        request_nonce,
        current_timestamp,
        owner_secret,
        property_id,
        license_expiry,
        merkle_siblings: siblings,
        merkle_bits: bits,
    };

    // ---- 3. Build the trace + prove ----
    let (trace, pub_inputs) = build_trace(&witness);
    assert_eq!(pub_inputs.merkle_root, merkle_root, "trace's merkle_root must match the tree");

    let options = ProofOptions::new(
        32,  // number of queries
        8,   // blowup factor
        0,   // grinding factor
        FieldExtension::None,
        8,   // FRI folding factor
        31,  // FRI max remainder polynomial degree
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );

    let prover = TitleProver::new(options, pub_inputs.clone());
    let air_pub_inputs = pub_inputs.clone();
    let prove_start = std::time::Instant::now();
    let proof: Proof = prover.prove(trace).expect("proof generation failed");
    let prove_elapsed = prove_start.elapsed();

    let proof_bytes = proof.to_bytes();

    println!("registry_id       = {}", pub_inputs.registry_id);
    println!("merkle_root       = {}", pub_inputs.merkle_root);
    println!("purpose           = {}", pub_inputs.purpose);
    println!("request_nonce     = {}", pub_inputs.request_nonce);
    println!("current_timestamp = {}", pub_inputs.current_timestamp);
    println!("nullifier         = {}", pub_inputs.nullifier);
    println!("proof size: {} bytes", proof_bytes.len());
    println!(
        "proving time: {:.3}s ({} ms)",
        prove_elapsed.as_secs_f64(),
        prove_elapsed.as_millis()
    );
    println!();

    println!("Sanity check against the same AIR, off-chain:");
    let min_opts = winterfell::AcceptableOptions::MinConjecturedSecurity(80);
    match winterfell::verify::<TitleAir, HashFn, RandCoin, MerkleTree<HashFn>>(
        proof.clone(),
        air_pub_inputs,
        &min_opts,
    ) {
        Ok(()) => println!("  local verify: OK"),
        Err(e) => println!("  local verify FAILED: {e}"),
    }

    // The proof blob hex-escapes to well over Linux's ARG_MAX (~128KB+ as
    // text) once wrapped in a full `dfx canister call` command line, so it
    // can't be passed as a shell argument -- write it as a Candid argument
    // file instead and invoke dfx with `--argument-file`, which reads the
    // args straight off disk with no shell length limit.
    let hex: String = proof_bytes.iter().map(|b| format!("\\{b:02x}")).collect();
    let candid_args = format!(
        "({{challengeId}}, blob \"{}\", record {{ registry_id = {} : nat64; merkle_root = \"{}\"; purpose = {} : nat64; request_nonce = {} : nat64; current_timestamp = {} : nat64; nullifier = \"{}\" }})",
        hex,
        pub_inputs.registry_id,
        pub_inputs.merkle_root,
        pub_inputs.purpose,
        pub_inputs.request_nonce,
        pub_inputs.current_timestamp,
        pub_inputs.nullifier,
    );
    std::fs::write("verify_args.candid", &candid_args).expect("failed to write verify_args.candid");

    println!();
    println!("Wrote verify_args.candid ({} bytes).", candid_args.len());
    println!("After calling request_challenge and noting its real challenge_id, replace");
    println!("the literal '{{challengeId}}' in verify_args.candid with that number, then:");
    println!();
    println!("  time dfx canister call title_verifier verify --argument-file verify_args.candid");
    println!();
    println!("The canister itself already logs instructions used via ic_cdk::println!,");
    println!("which the local replica prints to this terminal -- look for a line like");
    println!("  [Canister ...] verify: proof_bytes=<N>B instructions=<M>");
}