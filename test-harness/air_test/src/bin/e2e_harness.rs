//! Human-readable demo/report runner for the checks in
//! `air_test::e2e_support`. Every check this prints has a matching
//! `#[test]` in `e2e_support.rs` that `cargo test` runs automatically --
//! this binary exists for a readable pass/fail narrative, not as the only
//! place these properties are checked.

use air_test_harness::e2e_support::*;
use air_test_harness::*;
use winterfell::{math::FieldElement, Air, TraceInfo};

fn main() {
    println!("=== Yaqeen STARK/Winterfell -- real end-to-end AIR behavioral test ===");
    println!("(real winter-air 0.13.1, real title_air crate; see test-harness/README.md)\n");

    // ---- 1. demo registry / tree ----
    let (witness, independent_root) = demo_witness();

    // ---- 2. build_trace vs. independently-computed SparseTree root ----
    let (cols, pub_inputs) = build_trace(&witness);
    if pub_inputs.merkle_root == independent_root {
        println!("[ok] build_trace()'s merkle_root matches the independently-computed SparseTree root");
    } else {
        println!(
            "[FAIL] merkle_root MISMATCH: trace={} tree={}",
            pub_inputs.merkle_root, independent_root
        );
        std::process::exit(1);
    }

    // ---- 3. instantiate the real TitleAir and check every transition ----
    let trace_info = TraceInfo::new(TRACE_WIDTH, TRACE_LENGTH);
    let air = TitleAir::new(trace_info, pub_inputs.clone(), demo_proof_options());
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
        println!(
            "[ok] all {} transition constraints evaluate to zero across all {} row-transitions",
            NUM_TRANSITION_CONSTRAINTS, TRACE_LENGTH
        );
    } else {
        println!("[FAIL] {nonzero} nonzero constraint evaluations on the honest trace");
        std::process::exit(1);
    }

    // ---- 4. check assertions hold on the honest trace ----
    let assertions = air.get_assertions();
    let mut assertion_fail = 0;
    for a in &assertions {
        let actual = cols[a.column()][a.first_step()];
        if actual != a.values()[0] {
            assertion_fail += 1;
            println!(
                "  assertion FAILED: col={} step={} expected={} actual={}",
                a.column(), a.first_step(), a.values()[0], actual
            );
        }
    }
    if assertion_fail == 0 {
        println!(
            "[ok] all {} assertions (7 public-input + {} job-type) hold on the honest trace",
            assertions.len(),
            JOB_COUNT
        );
    } else {
        println!("[FAIL] {assertion_fail} assertions failed");
        std::process::exit(1);
    }

    // ---- 5. soundness sanity: tamper encumbrance_flag, expect divergence ----
    let leaf_start = job_start_row(JOB_LEAF);
    let mut tampered = cols.clone();
    tampered[AUX_B][leaf_start] = BaseElement::ONE; // encumbrance_flag: 0 -> 1
    let expected = assertions
        .iter()
        .find(|a| a.column() == AUX_B && a.first_step() == leaf_start)
        .unwrap();
    if tampered[AUX_B][leaf_start] != expected.values()[0] {
        println!("[ok] soundness sanity: tampering encumbrance_flag to 1 makes it mismatch the assertion");
    } else {
        println!("[FAIL] tampered trace did not diverge from assertion -- statement may be vacuous");
        std::process::exit(1);
    }

    // ---- 6. soundness sanity: tamper a mid-permutation row, expect a
    // nonzero transition constraint (not just a broken assertion) ----
    tampered[S0][3] += BaseElement::ONE;
    let tampered_results = eval_all_constraints(&air, &tampered);
    if tampered_results.iter().flatten().any(|v| *v != BaseElement::ZERO) {
        println!("[ok] soundness sanity: tampering a mid-permutation row breaks a transition constraint");
    } else {
        println!("[FAIL] mid-permutation tamper produced no nonzero constraint anywhere");
        std::process::exit(1);
    }

    // ---- 7. hash() round-count cross-check ----
    {
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
        if manual[0] == via_hash {
            println!(
                "[ok] hash() applies exactly ROUNDS-1={} permutation rounds, matching job logic directly",
                ROUNDS - 1
            );
        } else {
            println!("[FAIL] hash() round count diverges from job logic");
            std::process::exit(1);
        }
    }

    println!("\nAll checks passed against the real air/src/lib.rs, compiled against real winterfell 0.13.1.");
    println!("(same logic is also covered by `cargo test -p title_air` -- see e2e_support.rs)");
}
