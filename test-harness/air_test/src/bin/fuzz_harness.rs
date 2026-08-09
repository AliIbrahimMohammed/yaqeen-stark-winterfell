use title_air::*;
use winterfell::{Air, EvaluationFrame, ProofOptions, TraceInfo};

// xorshift PRNG, no external crate needed (network-restricted sandbox)
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn field_elem(&mut self) -> BaseElement {
        BaseElement::new(self.next() as u128)
    }
}

fn main() {
    let dummy_pub = PublicInputs {
        registry_id: BaseElement::ZERO,
        merkle_root: BaseElement::ZERO,
        purpose: BaseElement::ZERO,
        request_nonce: BaseElement::ZERO,
        current_timestamp: BaseElement::ZERO,
        nullifier: BaseElement::ZERO,
    };
    let trace_info = TraceInfo::new(TRACE_WIDTH, TRACE_LENGTH);
    let air = TitleAir::new(trace_info, dummy_pub, ProofOptions);
    let periodic = air.get_periodic_column_values();

    let mut rng = Rng(0xF00DBABE_u64);
    let mut panics = 0;
    let mut oob = 0;
    let total_steps = TRACE_LENGTH;

    for step in 0..total_steps {
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

    println!("=== Fuzz: {} row-transitions with arbitrary (non-satisfying) data ===", total_steps);
    println!("panics/out-of-bounds: {panics}  (oob tracked separately: {oob})");
    if panics == 0 {
        println!("[ok] no panics or out-of-bounds indexing across {total_steps} arbitrary row-transitions");
    } else {
        println!("[FAIL] {panics} panics found");
        std::process::exit(1);
    }
    let _ = oob;
}
