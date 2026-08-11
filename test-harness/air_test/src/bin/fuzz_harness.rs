//! Human-readable demo runner for `air_test::fuzz_support`, which is what
//! actually implements the fuzzing logic and has its own `#[test]`s (with
//! a smaller iteration count) that run under plain `cargo test`. This
//! binary runs a longer pass for manual or CI use.

use air_test_harness::fuzz_support::*;
use air_test_harness::TRACE_LENGTH;

fn main() {
    let total_steps = TRACE_LENGTH;

    let panics = fuzz_no_panics(0xF00DBABE, total_steps);
    println!("=== Fuzz 1: {total_steps} row-transitions with arbitrary (non-satisfying) data ===");
    println!("panics: {panics}");
    if panics == 0 {
        println!("[ok] no panics or out-of-bounds indexing across {total_steps} arbitrary row-transitions");
    } else {
        println!("[FAIL] {panics} panics found");
        std::process::exit(1);
    }

    // Soundness pass, not just robustness: for random non-boolean values
    // written into a boolean-constrained column, checks that the AIR's
    // own constraint actually flags the violation.
    let bool_iterations = 2000;
    let missed = fuzz_boolean_violations_are_caught(0xC0FFEE, bool_iterations);
    println!("\n=== Fuzz 2: {bool_iterations} random non-boolean AUX_B values ===");
    println!("violations missed by the merkle-bit constraint: {missed}");
    if missed == 0 {
        println!("[ok] every non-boolean value was caught by the merkle-bit constraint");
    } else {
        println!("[FAIL] {missed} non-boolean values were NOT flagged -- constraint may be broken or missing");
        std::process::exit(1);
    }
}
