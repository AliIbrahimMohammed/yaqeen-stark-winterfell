//! Off-chain prover CLI for `title_air::TitleAir`.
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
//!
//! The actual trace-building / proving logic lives in `src/lib.rs` (crate
//! `title_prover`) so `canister`'s test suite can reuse it to generate a
//! genuine proof for a real integration test, instead of only ever
//! testing `verify_crypto_impl` against garbage/malformed bytes.

use title_air::*;
use title_prover::{
    build_trace, BatchingMethod, FieldExtension, MerkleTree, Proof, ProofOptions, SparseTree,
    TitleProver, Witness, WinterFieldElement as FieldElement, WinterProver as Prover,
};

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