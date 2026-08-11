//! Fuzzing support for `evaluate_transition`, factored out of
//! `src/bin/fuzz_harness.rs` so `cargo test` exercises it too (with a
//! smaller iteration count for speed; `bin/fuzz_harness.rs` runs a longer
//! pass for manual/CI use).

use crate::*;
use winterfell::{math::FieldElement, Air, EvaluationFrame, TraceInfo};

use crate::e2e_support::demo_proof_options;

/// xorshift64* PRNG. Not cryptographically secure -- fine for fuzz input
/// generation, not fine for anything key-related. No external crate
/// dependency on purpose (this harness is built to run in a
/// network-restricted sandbox).
pub struct Rng(pub u64);

impl Rng {
    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    pub fn field_elem(&mut self) -> BaseElement {
        BaseElement::new(self.next_u64() as u128)
    }
}

fn dummy_air() -> TitleAir {
    let dummy_pub = PublicInputs {
        registry_id: BaseElement::ZERO,
        merkle_root: BaseElement::ZERO,
        purpose: BaseElement::ZERO,
        request_nonce: BaseElement::ZERO,
        current_timestamp: BaseElement::ZERO,
        nullifier: BaseElement::ZERO,
    };
    let trace_info = TraceInfo::new(TRACE_WIDTH, TRACE_LENGTH);
    TitleAir::new(trace_info, dummy_pub, demo_proof_options())
}

/// Feeds `iterations` rows of arbitrary (almost certainly non-satisfying)
/// field data into `evaluate_transition` and reports how many panicked.
/// This only checks robustness (no panics/out-of-bounds on garbage input),
/// not soundness -- see `fuzz_boolean_violations_are_caught` for that.
pub fn fuzz_no_panics(seed: u64, iterations: usize) -> usize {
    let air = dummy_air();
    let periodic = air.get_periodic_column_values();
    let mut rng = Rng(seed);
    let mut panics = 0;

    for step in 0..iterations {
        let cur: Vec<BaseElement> = (0..TRACE_WIDTH).map(|_| rng.field_elem()).collect();
        let nxt: Vec<BaseElement> = (0..TRACE_WIDTH).map(|_| rng.field_elem()).collect();
        let frame = EvaluationFrame::from_rows(cur, nxt);
        let cycle_pos = step % ROUNDS;
        let pv: Vec<BaseElement> = periodic.iter().map(|col| col[cycle_pos % col.len()]).collect();
        let mut result = vec![BaseElement::ZERO; NUM_TRANSITION_CONSTRAINTS];
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            air.evaluate_transition::<BaseElement>(&frame, &pv, &mut result);
        }));
        if r.is_err() {
            panics += 1;
        }
    }
    panics
}

/// Stronger than `fuzz_no_panics`: for random non-boolean values written
/// into a boolean-constrained column, checks that the AIR's own
/// transition constraint actually reports a violation (nonzero), not just
/// that evaluation doesn't crash. A no-panic-only fuzz pass would happily
/// pass even if a boolean constraint were accidentally deleted; this
/// catches that class of regression.
///
/// Returns the number of trials where a value known to violate a boolean
/// constraint failed to produce a nonzero result at the expected index.
pub fn fuzz_boolean_violations_are_caught(seed: u64, iterations: usize) -> usize {
    let air = dummy_air();
    let periodic = air.get_periodic_column_values();
    let mut rng = Rng(seed);
    let mut missed = 0;

    for _ in 0..iterations {
        // Row 0 of a cycle (is_first=1) with T_MERKLE=1, so both the
        // t_merkle-boolean constraint (index 12) and the merkle-bit
        // constraint (index 15) are gated "live".
        let mut cur = vec![BaseElement::ZERO; TRACE_WIDTH];
        cur[T_MERKLE] = BaseElement::ONE;
        // A random nonzero, non-one value in AUX_B: guaranteed to violate
        // "must be boolean" except for the two field elements 0 and 1,
        // which next_u64() essentially never lands on.
        let bad_bit = rng.field_elem();
        if bad_bit == BaseElement::ZERO || bad_bit == BaseElement::ONE {
            continue; // not actually a violation this draw, skip it
        }
        cur[AUX_B] = bad_bit;
        let nxt = vec![BaseElement::ZERO; TRACE_WIDTH];
        let frame = EvaluationFrame::from_rows(cur, nxt);
        let pv: Vec<BaseElement> = periodic.iter().map(|col| col[0]).collect(); // cycle_pos = 0 => is_first
        let mut result = vec![BaseElement::ZERO; NUM_TRANSITION_CONSTRAINTS];
        air.evaluate_transition::<BaseElement>(&frame, &pv, &mut result);
        if result[15] == BaseElement::ZERO {
            missed += 1;
        }
    }
    missed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rng_is_deterministic_given_a_seed() {
        let mut a = Rng(12345);
        let mut b = Rng(12345);
        for _ in 0..10 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn rng_does_not_get_stuck() {
        // A buggy shift/xor sequence could collapse to a fixed point;
        // sanity-check consecutive outputs actually vary.
        let mut rng = Rng(0xF00DBABE);
        let first = rng.next_u64();
        let second = rng.next_u64();
        assert_ne!(first, second);
    }

    #[test]
    fn rng_zero_seed_still_produces_output() {
        // xorshift's one real footgun: seed 0 is a fixed point (0 stays
        // 0 forever). Not a bug to fix here (callers control the seed),
        // but worth pinning down so it's a known, deliberate property
        // instead of a silent surprise if a future seed ever computes
        // to 0.
        let mut rng = Rng(0);
        assert_eq!(rng.next_u64(), 0);
    }

    #[test]
    fn fuzz_no_panics_smoke_test() {
        // Small, fast iteration count for `cargo test`; bin/fuzz_harness.rs
        // runs a full TRACE_LENGTH pass for a more thorough manual/CI run.
        let panics = fuzz_no_panics(0xF00DBABE, 64);
        assert_eq!(panics, 0, "evaluate_transition panicked on arbitrary input");
    }

    #[test]
    fn fuzz_no_panics_is_deterministic_for_a_fixed_seed() {
        assert_eq!(fuzz_no_panics(1, 32), fuzz_no_panics(1, 32));
    }

    #[test]
    fn boolean_violations_are_always_caught() {
        let missed = fuzz_boolean_violations_are_caught(0xC0FFEE, 200);
        assert_eq!(
            missed, 0,
            "found a non-boolean AUX_B value that the merkle-bit constraint didn't flag"
        );
    }
}
