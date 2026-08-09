use title_air::*;
use winterfell::{Air, AirContext, EvaluationFrame, ProofOptions, TraceInfo};

// ---- SparseTree, copied verbatim from prover/src/main.rs ----
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
        Self { zero_hashes, nodes: Default::default() }
    }
    fn node_at(&self, level: usize, index: usize) -> BaseElement {
        *self.nodes.get(&(level, index)).unwrap_or(&self.zero_hashes[level])
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
    fn root(&self) -> BaseElement { self.node_at(TREE_DEPTH, 0) }
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

struct Witness {
    registry_id: BaseElement,
    purpose: BaseElement,
    request_nonce: BaseElement,
    current_timestamp: u64,
    owner_secret: BaseElement,
    property_id: BaseElement,
    license_expiry: u64,
    merkle_siblings: Vec<BaseElement>,
    merkle_bits: Vec<bool>,
}

fn to_bits_le(v: u64, n: usize) -> Vec<BaseElement> {
    (0..n).map(|i| BaseElement::new(((v >> i) & 1) as u128)).collect()
}

// ---- build_trace, copied verbatim (logic) from prover/src/main.rs, but
// returning plain Vec<Vec<BaseElement>> columns instead of a winterfell
// TraceTable (our facade doesn't implement the full Trace machinery -
// FRI/LDE/Merkle commitment - only the AIR's own constraint logic, same
// scope as the original test report). ----
fn build_trace(w: &Witness) -> (Vec<Vec<BaseElement>>, PublicInputs) {
    let rcs = round_constants();
    let mut cols: Vec<Vec<BaseElement>> = vec![vec![BaseElement::ZERO; TRACE_LENGTH]; TRACE_WIDTH];

    for r in 0..TRACE_LENGTH {
        cols[HELD_SECRET][r] = w.owner_secret;
        cols[HELD_PID][r] = w.property_id;
    }

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

    let owner_commitment = run_job(
        &mut cols, &rcs, JOB_OWNER,
        [dtag(DOMAIN_OWNER_COMMITMENT), w.owner_secret, w.property_id, z, z, z, z, z],
        [z, z, z, z],
    );

    let license_expiry_fe = BaseElement::new(w.license_expiry as u128);
    let leaf = run_job(
        &mut cols, &rcs, JOB_LEAF,
        [dtag(DOMAIN_LEAF), w.registry_id, owner_commitment, z, one, license_expiry_fe, z, z],
        [w.registry_id, z, one, license_expiry_fe],
    );

    {
        let diff = w.license_expiry.checked_sub(w.current_timestamp).and_then(|d| d.checked_sub(1))
            .expect("license_expiry must be > current_timestamp");
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
        let bit = if w.merkle_bits[level] { one } else { z };
        current = run_job(
            &mut cols, &rcs, job,
            [dtag(DOMAIN_NODE), current, sibling, z, z, z, z, z],
            [sibling, bit, z, z],
        );
    }
    let merkle_root = current;

    let nullifier = run_job(
        &mut cols, &rcs, JOB_NULLIFIER,
        [dtag(DOMAIN_NULLIFIER), w.owner_secret, w.property_id, w.purpose, w.request_nonce, z, z, z],
        [w.purpose, w.request_nonce, z, z],
    );

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

    (cols, pub_inputs)
}

fn eval_all_constraints(air: &TitleAir, cols: &[Vec<BaseElement>]) -> Vec<Vec<BaseElement>> {
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

fn main() {
    println!("=== Yaqeen STARK/Winterfell -- real end-to-end AIR behavioral test ===");
    println!("(facade built from real winter-air 0.13.1 signatures downloaded this session)\n");

    // ---- 1. demo registry / tree, exactly as prover/src/main.rs does ----
    let registry_id = BaseElement::new(1);
    let owner_secret = BaseElement::new(0xA11CE_u64 as u128);
    let property_id = BaseElement::new(42);
    let owner_commitment = hash(&[BaseElement::new(DOMAIN_OWNER_COMMITMENT as u128), owner_secret, property_id]);
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
    let merkle_root = tree.root();

    let purpose = BaseElement::new(1);
    let request_nonce = BaseElement::new(7);

    let witness = Witness {
        registry_id, purpose, request_nonce, current_timestamp,
        owner_secret, property_id, license_expiry,
        merkle_siblings: siblings, merkle_bits: bits,
    };

    // ---- 2. build_trace vs. independent SparseTree root (bug #1 check) ----
    let (cols, pub_inputs) = build_trace(&witness);
    if pub_inputs.merkle_root == merkle_root {
        println!("[ok] build_trace()'s merkle_root matches the independently-computed SparseTree root");
    } else {
        println!("[FAIL] merkle_root MISMATCH: trace={} tree={}", pub_inputs.merkle_root, merkle_root);
        std::process::exit(1);
    }

    // ---- 3. instantiate the real TitleAir and check every transition ----
    let trace_info = TraceInfo::new(TRACE_WIDTH, TRACE_LENGTH);
    let air = TitleAir::new(trace_info, pub_inputs.clone(), ProofOptions);
    let results = eval_all_constraints(&air, &cols);
    let mut nonzero = 0;
    for (step, r) in results.iter().enumerate() {
        for (i, v) in r.iter().enumerate() {
            if *v != BaseElement::ZERO {
                nonzero += 1;
                if nonzero <= 5 {
                    println!("  nonzero constraint at step {step}, index {i}: {v}");
                }
            }
        }
    }
    if nonzero == 0 {
        println!("[ok] all {} transition constraints evaluate to zero across all {} row-transitions",
            NUM_TRANSITION_CONSTRAINTS, TRACE_LENGTH);
    } else {
        println!("[FAIL] {nonzero} nonzero constraint evaluations on the honest trace");
        std::process::exit(1);
    }

    // ---- 4. check assertions hold on the honest trace ----
    let assertions = air.get_assertions();
    let mut assertion_fail = 0;
    for a in &assertions {
        let actual = cols[a.column][a.first_step];
        if actual != a.value {
            assertion_fail += 1;
            println!("  assertion FAILED: col={} step={} expected={} actual={}",
                a.column, a.first_step, a.value, actual);
        }
    }
    if assertion_fail == 0 {
        println!("[ok] all {} assertions (7 public-input + {} job-type) hold on the honest trace",
            assertions.len(), JOB_COUNT);
    } else {
        println!("[FAIL] {assertion_fail} assertions failed");
        std::process::exit(1);
    }

    // ---- 5. soundness sanity: tamper encumbrance_flag, expect divergence ----
    let mut tampered = cols.clone();
    let leaf_start = job_start_row(JOB_LEAF);
    tampered[AUX_B][leaf_start] = BaseElement::ONE; // encumbrance_flag: 0 -> 1
    let bad_val = tampered[AUX_B][leaf_start];
    let expected_encumbrance_assertion = assertions.iter().find(|a| a.column == AUX_B && a.first_step == leaf_start).unwrap();
    if bad_val != expected_encumbrance_assertion.value {
        println!("[ok] soundness sanity: tampering encumbrance_flag to 1 makes it mismatch the assertion");
    } else {
        println!("[FAIL] tampered trace did not diverge from assertion -- statement may be vacuous");
        std::process::exit(1);
    }

    // ---- 6. hash() round-count cross-check (bug #1, direct) ----
    // hash() must match exactly what run_job (ROUNDS-1 = 7 applications)
    // produces, independent of the tree/build_trace call above.
    {
        let mut state = [BaseElement::ZERO; STATE_WIDTH];
        state[0] = BaseElement::new(DOMAIN_OWNER_COMMITMENT as u128);
        state[1] = owner_secret;
        state[2] = property_id;
        let rcs = round_constants();
        let mut manual = state;
        for r in 0..ROUNDS - 1 {
            manual = apply_round(&manual, &rcs[r]);
        }
        let via_hash = hash(&[BaseElement::new(DOMAIN_OWNER_COMMITMENT as u128), owner_secret, property_id]);
        if manual[0] == via_hash {
            println!("[ok] hash() applies exactly ROUNDS-1={} permutation rounds, matching job logic directly", ROUNDS - 1);
        } else {
            println!("[FAIL] hash() round count still diverges from job logic");
            std::process::exit(1);
        }
    }

    println!("\nAll checks passed against the actual, unmodified shipped air/src/lib.rs.");
}
