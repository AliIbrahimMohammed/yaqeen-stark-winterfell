//! `title_verifier` -- Yaqeen's registry/challenge/nullifier canister,
//! ported from Motoko (`motoko/src/main.mo`) to Rust so it can verify
//! Winterfell STARK proofs natively, the same way
//! `ic-winterfell-verifier/canister` verifies `WorkAir` proofs.
//!
//! Same three-step flow as the original (`submitRecord` -> `requestChallenge`
//! -> `verify`), same server-authoritative public inputs, same
//! domain-separated hashing discipline, same admin allow-list / throttle /
//! nullifier / challenge-pruning logic -- just verifying a STARK proof
//! against `title_air::TitleAir` instead of a Groth16 proof against the
//! vendored BLS12-381 verifier.
//!
//! Field elements that can be arbitrary 128-bit hash outputs (owner
//! commitments, tree nodes/root, nullifiers) are passed across the Candid
//! boundary as base-10 decimal strings, exactly the design decision
//! `ic-winterfell-verifier` made and documents in its README ("uneven
//! int128 support across tooling"). Small bounded integers (property ids,
//! flags, timestamps, nonces) use plain `nat64`.
//!
//! TESTABILITY NOTE: every `#[ic_cdk::update]`/`#[ic_cdk::query]` function
//! below is a thin wrapper: it pulls `caller`/`now_ns` out of `ic_cdk::api`
//! (the only parts that genuinely need a live IC execution context) and
//! immediately delegates to a plain `..._impl` function that takes those
//! values as ordinary parameters. All real business logic -- admin auth,
//! throttling, the Merkle tree, challenge lifecycle, and verify's
//! three-phase precheck/crypto/commit split -- lives in those `_impl`
//! functions, which touch no IC-specific API at all. That means the
//! `#[cfg(test)]` module at the bottom of this file exercises the exact
//! same code the canister runs in production, entirely offline, with
//! plain `cargo test -p title_verifier` -- no PocketIC / live replica
//! needed for logic correctness (the existing `run_full_cycle.sh` remains
//! the tool for exercising the real on-chain WASM end to end, including
//! genuine STARK proof bytes).

use candid::{CandidType, Principal};
use serde::Deserialize;
use std::cell::RefCell;
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use title_air::{BaseElement, PublicInputs, TitleAir, DOMAIN_LEAF, DOMAIN_NODE, TREE_DEPTH};
use winterfell::{math::FieldElement, AcceptableOptions, Proof};

fn fe(n: u64) -> BaseElement {
    BaseElement::new(n as u128)
}

fn parse_fe(s: &str) -> Result<BaseElement, String> {
    let n: u128 = s
        .trim()
        .parse()
        .map_err(|_| format!("could not parse '{s}' as a u128 decimal integer"))?;
    Ok(BaseElement::new(n))
}

fn fe_to_string(v: BaseElement) -> String {
    // BaseElement's Display already renders the canonical decimal value.
    format!("{v}")
}

// ---------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------

#[derive(Clone, CandidType, Deserialize, Debug)]
pub struct Record {
    pub property_id: u64,
    /// Poseidon-analog owner commitment, computed OFF-canister -- the
    /// canister never learns `owner_secret`. Decimal string, field element.
    pub owner_commitment: String,
    pub encumbrance_flag: u64,
    pub license_status: u64,
    pub license_expiry: u64,
}

#[derive(Clone, CandidType, Deserialize, Debug)]
pub struct MerkleProof {
    pub leaf_index: u64,
    pub siblings: Vec<String>,
    pub path_bits: Vec<bool>,
    pub root: String,
}

#[derive(Clone, CandidType, Deserialize, Debug)]
pub struct ChallengeView {
    pub challenge_id: u64,
    pub registry_id: u64,
    pub merkle_root: String,
    pub purpose: u64,
    pub request_nonce: u64,
    pub current_timestamp: u64,
    pub expires_at: i64,
}

// Internal-only: never crosses the Candid boundary directly (ChallengeView
// and StableChallenge do that, via decimal-string field elements), so it
// only needs Clone -- deriving CandidType/Deserialize here would require
// BaseElement itself to implement those traits, which it doesn't (see the
// "Upgrade hooks" comment below for the same constraint on StableState).
#[derive(Clone)]
struct Challenge {
    registry_id: u64,
    merkle_root: BaseElement,
    purpose: u64,
    request_nonce: u64,
    current_timestamp: u64,
    expires_at: i64,
    consumed: bool,
    /// The principal that called `request_challenge` to create this
    /// challenge. `request_challenge` is public and unauthenticated (any
    /// principal can call it), so without this binding a third party
    /// watching consensus could observe a freshly issued challenge and
    /// race a bogus `verify` call against it -- consuming the challenge
    /// (and, if their proof happened to verify, spending its nullifier)
    /// before the legitimate prover's real proof lands. The nullifier
    /// check alone doesn't stop this: it only prevents the *same*
    /// nullifier being spent twice, not a third party burning someone
    /// else's still-unconsumed challenge first. Scoping `verify` to the
    /// same caller who requested the challenge closes that race -- see
    /// the check in `verify_precheck_impl`.
    requester: Principal,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct VerifyPublicInputs {
    pub registry_id: u64,
    pub merkle_root: String,
    pub purpose: u64,
    pub request_nonce: u64,
    pub current_timestamp: u64,
    pub nullifier: String,
}

#[derive(CandidType, Deserialize, Debug)]
pub struct VerifyOk {
    pub nullifier: String,
}

// ---------------------------------------------------------------------
// State
// ---------------------------------------------------------------------

const CHALLENGE_TTL_NS: i64 = 5 * 60 * 1_000_000_000;
const MIN_CALL_INTERVAL_NS: i64 = 2_000_000_000;
const MAX_PRUNE_PER_HEARTBEAT: u64 = 50;
const REGISTRY_ID: u64 = 1;

#[derive(Default)]
struct State {
    admins: Vec<Principal>,

    records: HashMap<u64, Record>,
    leaf_index_by_property: HashMap<u64, u64>,
    zero_hashes: Vec<BaseElement>, // len TREE_DEPTH+1
    nodes: HashMap<(u8, u64), BaseElement>,
    current_root: BaseElement,
    next_leaf_index: u64,

    challenges: HashMap<u64, Challenge>,
    next_challenge_id: u64,
    next_nonce: u64,
    oldest_unpruned_challenge_id: u64,

    // decimal-string nullifier -> spent
    nullifiers: HashMap<String, bool>,

    last_challenge_call_at: HashMap<Principal, i64>,
    last_verify_call_at: HashMap<Principal, i64>,
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

fn init_zero_hashes() -> Vec<BaseElement> {
    let mut z = vec![BaseElement::ZERO; TREE_DEPTH + 1];
    for level in 1..=TREE_DEPTH {
        let prev = z[level - 1];
        z[level] = title_air::hash(&[fe(DOMAIN_NODE), prev, prev]);
    }
    z
}

/// Builds a fresh, correctly-initialized `State` the same way `init()`
/// does, without touching the thread-local `STATE` cell -- used by both
/// `init()` itself and every test in `mod tests` below, so tests are
/// fully isolated from each other (and from the canister's real global
/// state) rather than relying on `thread_local!`'s per-thread semantics,
/// which the test harness's thread-reuse would otherwise make fragile.
fn fresh_state() -> State {
    let mut s = State::default();
    s.zero_hashes = init_zero_hashes();
    s.current_root = s.zero_hashes[TREE_DEPTH];
    s
}

fn is_admin(s: &State, p: &Principal) -> bool {
    s.admins.iter().any(|a| a == p)
}

// ---------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------

#[ic_cdk::init]
fn init() {
    STATE.with(|s| {
        *s.borrow_mut() = fresh_state();
    });
}

// ---------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------

/// One-time bootstrap: succeeds only while there are no admins yet. See
/// `main.mo`'s `bootstrapAdmin` for the full rationale (no constructor
/// arguments available; this is the runtime equivalent). Call this in the
/// SAME deploy session, before the canister id is shared.
fn bootstrap_admin_impl(s: &mut State, real_admin: Principal) -> Result<(), String> {
    if !s.admins.is_empty() {
        return Err("admins already bootstrapped -- use add_admin instead".to_string());
    }
    s.admins.push(real_admin);
    Ok(())
}

#[ic_cdk::update]
fn bootstrap_admin(real_admin: Principal) -> Result<(), String> {
    STATE.with(|s| bootstrap_admin_impl(&mut s.borrow_mut(), real_admin))
}

fn add_admin_impl(s: &mut State, caller: Principal, new_admin: Principal) -> Result<(), String> {
    if !is_admin(s, &caller) {
        return Err("unauthorized".to_string());
    }
    if !s.admins.contains(&new_admin) {
        s.admins.push(new_admin);
    }
    Ok(())
}

#[ic_cdk::update]
fn add_admin(new_admin: Principal) -> Result<(), String> {
    let caller = ic_cdk::api::msg_caller();
    STATE.with(|s| add_admin_impl(&mut s.borrow_mut(), caller, new_admin))
}

fn remove_admin_impl(s: &mut State, caller: Principal, old_admin: Principal) -> Result<(), String> {
    if !is_admin(s, &caller) {
        return Err("unauthorized".to_string());
    }
    if s.admins.len() <= 1 {
        return Err("cannot remove the last remaining admin".to_string());
    }
    s.admins.retain(|a| a != &old_admin);
    Ok(())
}

#[ic_cdk::update]
fn remove_admin(old_admin: Principal) -> Result<(), String> {
    let caller = ic_cdk::api::msg_caller();
    STATE.with(|s| remove_admin_impl(&mut s.borrow_mut(), caller, old_admin))
}

// ---------------------------------------------------------------------
// Registry / Merkle tree
// ---------------------------------------------------------------------

fn node_at(s: &State, level: u8, index: u64) -> BaseElement {
    *s.nodes
        .get(&(level, index))
        .unwrap_or(&s.zero_hashes[level as usize])
}

fn leaf_hash(r: &Record) -> Result<BaseElement, String> {
    let owner_commitment = parse_fe(&r.owner_commitment)?;
    Ok(title_air::hash(&[
        fe(DOMAIN_LEAF),
        fe(REGISTRY_ID),
        owner_commitment,
        fe(r.encumbrance_flag),
        fe(r.license_status),
        fe(r.license_expiry),
    ]))
}

fn insert_leaf(s: &mut State, index: u64, leaf: BaseElement) {
    s.nodes.insert((0, index), leaf);
    let mut idx = index;
    let mut level: u8 = 0;
    let mut cur = leaf;
    while (level as usize) < TREE_DEPTH {
        let pair_base = (idx / 2) * 2;
        let sibling_index = if idx == pair_base { pair_base + 1 } else { pair_base };
        let sibling = node_at(s, level, sibling_index);
        let (l, r) = if idx % 2 == 0 { (cur, sibling) } else { (sibling, cur) };
        cur = title_air::hash(&[fe(DOMAIN_NODE), l, r]);
        idx /= 2;
        level += 1;
        s.nodes.insert((level, idx), cur);
    }
    s.current_root = cur;
}

/// Admin-only back-office write, gated the same way `submitRecord` is in
/// `main.mo`. Resubmitting an existing `property_id` UPDATES that
/// property's existing leaf in place (same fix as
/// `PATCH_NOTES-leaf-update-and-hardening.md`).
fn submit_record_impl(
    s: &mut State,
    caller: Principal,
    property_id: u64,
    owner_commitment: String,
    encumbrance_flag: u64,
    license_status: u64,
    license_expiry: u64,
) -> Result<String, String> {
    if !is_admin(s, &caller) {
        return Err("unauthorized -- gate this behind real admin auth".to_string());
    }
    let record = Record {
        property_id,
        owner_commitment,
        encumbrance_flag,
        license_status,
        license_expiry,
    };
    let leaf = leaf_hash(&record)?;
    let index = match s.leaf_index_by_property.get(&property_id) {
        Some(&i) => i,
        None => {
            let i = s.next_leaf_index;
            s.next_leaf_index += 1;
            s.leaf_index_by_property.insert(property_id, i);
            i
        }
    };
    s.records.insert(property_id, record);
    insert_leaf(s, index, leaf);
    Ok(fe_to_string(s.current_root))
}

#[ic_cdk::update]
fn submit_record(
    property_id: u64,
    owner_commitment: String,
    encumbrance_flag: u64,
    license_status: u64,
    license_expiry: u64,
) -> Result<String, String> {
    let caller = ic_cdk::api::msg_caller();
    STATE.with(|s| {
        submit_record_impl(
            &mut s.borrow_mut(),
            caller,
            property_id,
            owner_commitment,
            encumbrance_flag,
            license_status,
            license_expiry,
        )
    })
}

fn get_record_impl(s: &State, property_id: u64) -> Option<Record> {
    s.records.get(&property_id).cloned()
}

#[ic_cdk::query]
fn get_record(property_id: u64) -> Option<Record> {
    STATE.with(|s| get_record_impl(&s.borrow(), property_id))
}

fn get_merkle_proof_impl(s: &State, property_id: u64) -> Option<MerkleProof> {
    let &index = s.leaf_index_by_property.get(&property_id)?;
    let mut siblings = Vec::with_capacity(TREE_DEPTH);
    let mut path_bits = Vec::with_capacity(TREE_DEPTH);
    let mut idx = index;
    let mut level: u8 = 0;
    while (level as usize) < TREE_DEPTH {
        let pair_base = (idx / 2) * 2;
        let sibling_index = if idx == pair_base { pair_base + 1 } else { pair_base };
        siblings.push(fe_to_string(node_at(s, level, sibling_index)));
        path_bits.push(idx % 2 == 1);
        idx /= 2;
        level += 1;
    }
    Some(MerkleProof {
        leaf_index: index,
        siblings,
        path_bits,
        root: fe_to_string(s.current_root),
    })
}

#[ic_cdk::query]
fn get_merkle_proof(property_id: u64) -> Option<MerkleProof> {
    STATE.with(|s| get_merkle_proof_impl(&s.borrow(), property_id))
}

// ---------------------------------------------------------------------
// Challenges
// ---------------------------------------------------------------------

fn check_and_update_throttle(
    store: &mut HashMap<Principal, i64>,
    caller: Principal,
    now_ns: i64,
) -> Result<(), String> {
    if caller == Principal::anonymous() {
        return Err("anonymous callers are not permitted".to_string());
    }
    if let Some(&last) = store.get(&caller) {
        if now_ns - last < MIN_CALL_INTERVAL_NS {
            return Err("rate limit: try again shortly".to_string());
        }
    }
    store.insert(caller, now_ns);
    Ok(())
}

fn request_challenge_impl(
    s: &mut State,
    caller: Principal,
    now_ns: i64,
    purpose: u64,
) -> Result<ChallengeView, String> {
    check_and_update_throttle(&mut s.last_challenge_call_at, caller, now_ns)?;

    let id = s.next_challenge_id;
    s.next_challenge_id += 1;
    let nonce = s.next_nonce;
    s.next_nonce += 1;
    let ts = (now_ns / 1_000_000_000) as u64;

    let challenge = Challenge {
        registry_id: REGISTRY_ID,
        merkle_root: s.current_root,
        purpose,
        request_nonce: nonce,
        current_timestamp: ts,
        expires_at: now_ns + CHALLENGE_TTL_NS,
        consumed: false,
        requester: caller,
    };
    let view = ChallengeView {
        challenge_id: id,
        registry_id: challenge.registry_id,
        merkle_root: fe_to_string(challenge.merkle_root),
        purpose: challenge.purpose,
        request_nonce: challenge.request_nonce,
        current_timestamp: challenge.current_timestamp,
        expires_at: challenge.expires_at,
    };
    s.challenges.insert(id, challenge);
    Ok(view)
}

#[ic_cdk::update]
fn request_challenge(purpose: u64) -> Result<ChallengeView, String> {
    let caller = ic_cdk::api::msg_caller();
    let now_ns = ic_cdk::api::time() as i64;
    STATE.with(|s| request_challenge_impl(&mut s.borrow_mut(), caller, now_ns, purpose))
}

// ---------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------

/// Phase 1: cheap, state-dependent checks -- throttle, challenge lookup,
/// expiry, and public-input matching against the ORIGINALLY issued
/// challenge, checked BEFORE any cryptographic work (same ordering
/// `main.mo`'s `verify` calls load-bearing). Nothing besides the throttle
/// timestamp is mutated.
fn verify_precheck_impl(
    s: &mut State,
    caller: Principal,
    now_ns: i64,
    challenge_id: u64,
    public_inputs: &VerifyPublicInputs,
) -> Result<(), String> {
    check_and_update_throttle(&mut s.last_verify_call_at, caller, now_ns)?;

    let challenge = s
        .challenges
        .get(&challenge_id)
        .cloned()
        .ok_or_else(|| "unknown or expired challenge".to_string())?;
    // Front-running guard: only the principal that originally requested
    // this challenge may consume it with a `verify` call. Without this,
    // `request_challenge` being public and unauthenticated means anyone
    // watching consensus could see a freshly issued challenge and race a
    // bogus (or even garbage) `verify` call against it, burning the
    // challenge before the legitimate prover's real proof lands -- the
    // nullifier check doesn't help here since it only stops a nullifier
    // being *spent* twice, not a challenge being consumed by the wrong
    // party in the first place.
    if caller != challenge.requester {
        return Err("caller does not match the principal that requested this challenge".to_string());
    }
    if challenge.consumed {
        return Err("challenge already consumed".to_string());
    }
    if now_ns > challenge.expires_at {
        return Err("challenge expired".to_string());
    }
    if public_inputs.registry_id != challenge.registry_id {
        return Err("registry_id mismatch".to_string());
    }
    let merkle_root = parse_fe(&public_inputs.merkle_root)?;
    if merkle_root != challenge.merkle_root {
        return Err("merkle_root mismatch".to_string());
    }
    if public_inputs.purpose != challenge.purpose {
        return Err("purpose mismatch".to_string());
    }
    if public_inputs.request_nonce != challenge.request_nonce {
        return Err("request_nonce mismatch".to_string());
    }
    if public_inputs.current_timestamp != challenge.current_timestamp {
        return Err("current_timestamp mismatch".to_string());
    }
    if s.nullifiers.get(&public_inputs.nullifier).copied().unwrap_or(false) {
        return Err("nullifier already spent".to_string());
    }
    Ok(())
}

/// Phase 2: the actual cryptographic work -- deliberately done OUTSIDE any
/// state borrow (callers pass no `&State`), and with no `.await` on either
/// side of it in the real `verify` wrapper (an IC update call runs to
/// completion without interleaving other calls, so splitting the work
/// this way introduces no atomicity gap).
///
/// `Proof::from_bytes` and `winterfell::verify` are not guaranteed
/// panic-free against adversarial input -- an internal `assert_eq!` inside
/// Winterfell can fire on a structurally malformed (not just
/// cryptographically invalid) proof, which would otherwise trap the whole
/// canister `update` call instead of returning `Err(..)` (see "Known
/// limitations" in the README). `catch_unwind` converts that trap into an
/// ordinary error response. It's safe to use here specifically because
/// this closure touches no `RefCell`/canister state -- if it unwinds,
/// there is nothing left half-mutated to clean up.
fn verify_crypto_impl(public_inputs: &VerifyPublicInputs, proof_bytes: &[u8]) -> Result<(), String> {
    let merkle_root = parse_fe(&public_inputs.merkle_root)?;
    let nullifier_fe = parse_fe(&public_inputs.nullifier)?;
    let air_pub_inputs = PublicInputs {
        registry_id: fe(public_inputs.registry_id),
        merkle_root,
        purpose: fe(public_inputs.purpose),
        request_nonce: fe(public_inputs.request_nonce),
        current_timestamp: fe(public_inputs.current_timestamp),
        nullifier: nullifier_fe,
    };
    let acceptable = AcceptableOptions::MinConjecturedSecurity(80);

    catch_unwind(AssertUnwindSafe(|| {
        let proof = Proof::from_bytes(proof_bytes)
            .map_err(|e| format!("failed to decode proof bytes: {e}"))?;
        winterfell::verify::<TitleAir, title_air::HashFn, title_air::RandCoin, title_air::VC>(
            proof,
            air_pub_inputs,
            &acceptable,
        )
        .map_err(|e| format!("invalid proof: {e}"))
    }))
    .unwrap_or_else(|_| Err("invalid proof: verifier panicked on malformed proof data".to_string()))
}

/// Phase 3: commit -- only reached if verification actually succeeded.
fn verify_commit_impl(s: &mut State, challenge_id: u64, nullifier: &str) -> Result<VerifyOk, String> {
    // Defense in depth: re-check the nullifier here too. Unreachable in
    // today's single-threaded, non-`await`ing execution model, but cheap
    // insurance if this function ever grows an `.await` between phases 1
    // and 3.
    if s.nullifiers.get(nullifier).copied().unwrap_or(false) {
        return Err("nullifier already spent".to_string());
    }
    if let Some(c) = s.challenges.get_mut(&challenge_id) {
        c.consumed = true;
    }
    s.nullifiers.insert(nullifier.to_string(), true);
    Ok(VerifyOk {
        nullifier: nullifier.to_string(),
    })
}

/// Verifies a Winterfell STARK proof on-chain and, on success, marks the
/// challenge consumed and the nullifier spent. Declared as an `update`
/// call, not a `query` -- same reasoning as
/// `ic-winterfell-verifier/canister`: query calls aren't certified by
/// subnet consensus, which defeats the point.
#[ic_cdk::update]
fn verify(challenge_id: u64, proof_bytes: Vec<u8>, public_inputs: VerifyPublicInputs) -> Result<VerifyOk, String> {
    let caller = ic_cdk::api::msg_caller();
    let now_ns = ic_cdk::api::time() as i64;
    let start_instructions = ic_cdk::api::instruction_counter();

    let precheck = STATE.with(|s| verify_precheck_impl(&mut s.borrow_mut(), caller, now_ns, challenge_id, &public_inputs));
    let crypto_result = precheck.and_then(|()| verify_crypto_impl(&public_inputs, &proof_bytes));
    let result = crypto_result.and_then(|()| {
        STATE.with(|s| verify_commit_impl(&mut s.borrow_mut(), challenge_id, &public_inputs.nullifier))
    });

    let used = ic_cdk::api::instruction_counter().saturating_sub(start_instructions);
    ic_cdk::println!("verify: proof_bytes={}B instructions={used}", proof_bytes.len());
    result
}

// ---------------------------------------------------------------------
// Heartbeat -- prune expired challenges (bounded per tick), same
// discipline as `main.mo`'s `heartbeat`.
// ---------------------------------------------------------------------

fn heartbeat_impl(s: &mut State, now_ns: i64) {
    let mut scanned = 0u64;
    while scanned < MAX_PRUNE_PER_HEARTBEAT && s.oldest_unpruned_challenge_id < s.next_challenge_id {
        let id = s.oldest_unpruned_challenge_id;
        match s.challenges.get(&id) {
            None => {
                s.oldest_unpruned_challenge_id += 1;
            }
            Some(c) => {
                if now_ns > c.expires_at {
                    s.challenges.remove(&id);
                    s.oldest_unpruned_challenge_id += 1;
                } else {
                    return;
                }
            }
        }
        scanned += 1;
    }
}

#[ic_cdk::heartbeat]
fn heartbeat() {
    let now_ns = ic_cdk::api::time() as i64;
    STATE.with(|s| heartbeat_impl(&mut s.borrow_mut(), now_ns));
}

#[ic_cdk::query]
fn health() -> String {
    "title_verifier canister is running".to_string()
}

// ---------------------------------------------------------------------
// Upgrade hooks -- stable-memory snapshot. `BaseElement` doesn't implement
// Candid's traits, so the snapshot re-uses the same decimal-string
// encoding as the public interface for every field element. This is a
// simple/legacy `stable_save`/`stable_restore` approach, adequate for a
// prototype's state size; a production deployment with a large registry
// should move to `ic-stable-structures` instead (see README).
// ---------------------------------------------------------------------

#[derive(CandidType, Deserialize)]
struct StableRecord {
    property_id: u64,
    owner_commitment: String,
    encumbrance_flag: u64,
    license_status: u64,
    license_expiry: u64,
}

#[derive(CandidType, Deserialize)]
struct StableChallenge {
    id: u64,
    registry_id: u64,
    merkle_root: String,
    purpose: u64,
    request_nonce: u64,
    current_timestamp: u64,
    expires_at: i64,
    consumed: bool,
    requester: Principal,
}

#[derive(CandidType, Deserialize, Default)]
struct StableState {
    admins: Vec<Principal>,
    records: Vec<StableRecord>,
    leaf_index_by_property: Vec<(u64, u64)>,
    nodes: Vec<(u8, u64, String)>,
    next_leaf_index: u64,
    challenges: Vec<StableChallenge>,
    next_challenge_id: u64,
    next_nonce: u64,
    oldest_unpruned_challenge_id: u64,
    nullifiers: Vec<(String, bool)>,
    last_challenge_call_at: Vec<(Principal, i64)>,
    last_verify_call_at: Vec<(Principal, i64)>,
}

#[ic_cdk::pre_upgrade]
fn pre_upgrade() {
    STATE.with(|s| {
        let s = s.borrow();
        let snapshot = StableState {
            admins: s.admins.clone(),
            records: s
                .records
                .values()
                .map(|r| StableRecord {
                    property_id: r.property_id,
                    owner_commitment: r.owner_commitment.clone(),
                    encumbrance_flag: r.encumbrance_flag,
                    license_status: r.license_status,
                    license_expiry: r.license_expiry,
                })
                .collect(),
            leaf_index_by_property: s.leaf_index_by_property.iter().map(|(k, v)| (*k, *v)).collect(),
            nodes: s
                .nodes
                .iter()
                .map(|((level, idx), v)| (*level, *idx, fe_to_string(*v)))
                .collect(),
            next_leaf_index: s.next_leaf_index,
            challenges: s
                .challenges
                .iter()
                .map(|(id, c)| StableChallenge {
                    id: *id,
                    registry_id: c.registry_id,
                    merkle_root: fe_to_string(c.merkle_root),
                    purpose: c.purpose,
                    request_nonce: c.request_nonce,
                    current_timestamp: c.current_timestamp,
                    expires_at: c.expires_at,
                    consumed: c.consumed,
                    requester: c.requester,
                })
                .collect(),
            next_challenge_id: s.next_challenge_id,
            next_nonce: s.next_nonce,
            oldest_unpruned_challenge_id: s.oldest_unpruned_challenge_id,
            nullifiers: s.nullifiers.iter().map(|(k, v)| (k.clone(), *v)).collect(),
            last_challenge_call_at: s.last_challenge_call_at.iter().map(|(k, v)| (*k, *v)).collect(),
            last_verify_call_at: s.last_verify_call_at.iter().map(|(k, v)| (*k, *v)).collect(),
        };
        ic_cdk::storage::stable_save((snapshot,)).expect("pre_upgrade: stable_save failed");
    });
}

#[ic_cdk::post_upgrade]
fn post_upgrade() {
    let (snapshot,): (StableState,) =
        ic_cdk::storage::stable_restore().expect("post_upgrade: stable_restore failed");
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        s.zero_hashes = init_zero_hashes();
        s.admins = snapshot.admins;
        s.records = snapshot
            .records
            .into_iter()
            .map(|r| {
                (
                    r.property_id,
                    Record {
                        property_id: r.property_id,
                        owner_commitment: r.owner_commitment,
                        encumbrance_flag: r.encumbrance_flag,
                        license_status: r.license_status,
                        license_expiry: r.license_expiry,
                    },
                )
            })
            .collect();
        s.leaf_index_by_property = snapshot.leaf_index_by_property.into_iter().collect();
        s.nodes = snapshot
            .nodes
            .into_iter()
            .map(|(level, idx, v)| ((level, idx), parse_fe(&v).expect("bad stable field element")))
            .collect();
        s.current_root = s
            .nodes
            .get(&(TREE_DEPTH as u8, 0))
            .copied()
            .unwrap_or(s.zero_hashes[TREE_DEPTH]);
        s.next_leaf_index = snapshot.next_leaf_index;
        s.challenges = snapshot
            .challenges
            .into_iter()
            .map(|c| {
                (
                    c.id,
                    Challenge {
                        registry_id: c.registry_id,
                        merkle_root: parse_fe(&c.merkle_root).expect("bad stable field element"),
                        purpose: c.purpose,
                        request_nonce: c.request_nonce,
                        current_timestamp: c.current_timestamp,
                        expires_at: c.expires_at,
                        consumed: c.consumed,
                        requester: c.requester,
                    },
                )
            })
            .collect();
        s.next_challenge_id = snapshot.next_challenge_id;
        s.next_nonce = snapshot.next_nonce;
        s.oldest_unpruned_challenge_id = snapshot.oldest_unpruned_challenge_id;
        s.nullifiers = snapshot.nullifiers.into_iter().collect();
        s.last_challenge_call_at = snapshot.last_challenge_call_at.into_iter().collect();
        s.last_verify_call_at = snapshot.last_verify_call_at.into_iter().collect();
    });
}

ic_cdk::export_candid!();

// =======================================================================
// Tests
//
// Every test below calls the `_impl` functions directly with an explicit,
// freshly-constructed `State` (via `fresh_state()`) and explicit
// `caller`/`now_ns` values -- never the `#[ic_cdk::update]`/`#[query]`
// wrappers, and never the `thread_local! STATE` -- so tests run fully
// offline (`cargo test -p title_verifier`, no dfx/replica/PocketIC
// needed) and can't leak state between each other via thread reuse.
//
// Coverage is organized by public function, with an explicit section for
// attack scenarios: unauthorized access, replay attacks, nullifier
// double-spend, cross-challenge public-input mixing, anonymous-caller
// impersonation, rate-limit bypass attempts, admin lockout, and
// malformed/adversarial proof bytes hitting the `catch_unwind` boundary.
//
// One deliberate limitation: these are unit tests of the canister's
// BUSINESS LOGIC, not of `winterfell::verify`'s cryptographic behavior --
// constructing a genuine valid STARK proof requires the full AIR + prover
// pipeline (trace construction, FFT-based LDE, FRI, etc.), which is
// integration-level work already covered by `run_full_cycle.sh` against
// the real deployed WASM. The crypto-phase tests here instead focus on
// what unit tests are good at and what matters most for a security
// boundary: proving that NO input -- garbage, empty, truncated, or
// engineered to trip an internal panic -- can ever cause `verify_crypto`
// to panic instead of returning `Err(..)`.
// =======================================================================
#[cfg(test)]
mod tests {
    use super::*;

    fn p(n: u8) -> Principal {
        // Two-byte encoding, not one: the IC reserves specific short byte
        // sequences for special principals -- `Principal::anonymous()` is
        // exactly the single byte `[4]`, and canister-id principals are
        // recognizable by a trailing `0x01` suffix byte. A single-byte
        // `[n]` encoding collides with the anonymous principal the moment
        // a test picks `n == 4` (see the heartbeat-pruning and
        // nullifier-double-spend tests, which did exactly that and got
        // silently rejected by the real anonymous-caller guard instead of
        // exercising the behavior they meant to test). Padding to two
        // bytes keeps `p(n)` an ordinary, non-reserved principal for every
        // `n` in `0..=255`.
        Principal::from_slice(&[n, 0xFF])
    }

    fn vpi(root: BaseElement, nonce: u64, ts: u64, nullifier: &str) -> VerifyPublicInputs {
        VerifyPublicInputs {
            registry_id: REGISTRY_ID,
            merkle_root: fe_to_string(root),
            purpose: 1,
            request_nonce: nonce,
            current_timestamp: ts,
            nullifier: nullifier.to_string(),
        }
    }

    // -------------------------------------------------------------
    // bootstrap_admin / add_admin / remove_admin
    // -------------------------------------------------------------

    #[test]
    fn bootstrap_admin_succeeds_when_no_admins() {
        let mut s = fresh_state();
        assert!(bootstrap_admin_impl(&mut s, p(1)).is_ok());
        assert!(is_admin(&s, &p(1)));
    }

    #[test]
    fn bootstrap_admin_fails_second_time() {
        // ATTACK: a second party racing to call bootstrap_admin before the
        // legitimate deployer must not be able to seize admin.
        let mut s = fresh_state();
        bootstrap_admin_impl(&mut s, p(1)).unwrap();
        let err = bootstrap_admin_impl(&mut s, p(2)).unwrap_err();
        assert!(err.contains("already bootstrapped"));
        assert!(is_admin(&s, &p(1)));
        assert!(!is_admin(&s, &p(2)));
    }

    #[test]
    fn add_admin_unauthorized_rejected() {
        // ATTACK: a non-admin trying to grant itself admin rights.
        let mut s = fresh_state();
        bootstrap_admin_impl(&mut s, p(1)).unwrap();
        let err = add_admin_impl(&mut s, p(99), p(99)).unwrap_err();
        assert_eq!(err, "unauthorized");
        assert!(!is_admin(&s, &p(99)));
    }

    #[test]
    fn add_admin_by_admin_succeeds() {
        let mut s = fresh_state();
        bootstrap_admin_impl(&mut s, p(1)).unwrap();
        assert!(add_admin_impl(&mut s, p(1), p(2)).is_ok());
        assert!(is_admin(&s, &p(2)));
    }

    #[test]
    fn add_admin_duplicate_is_idempotent_noop() {
        let mut s = fresh_state();
        bootstrap_admin_impl(&mut s, p(1)).unwrap();
        add_admin_impl(&mut s, p(1), p(2)).unwrap();
        add_admin_impl(&mut s, p(1), p(2)).unwrap();
        assert_eq!(s.admins.iter().filter(|a| **a == p(2)).count(), 1);
    }

    #[test]
    fn remove_admin_unauthorized_rejected() {
        let mut s = fresh_state();
        bootstrap_admin_impl(&mut s, p(1)).unwrap();
        add_admin_impl(&mut s, p(1), p(2)).unwrap();
        let err = remove_admin_impl(&mut s, p(99), p(2)).unwrap_err();
        assert_eq!(err, "unauthorized");
        assert!(is_admin(&s, &p(2)));
    }

    #[test]
    fn remove_admin_last_admin_protected() {
        // ATTACK/DoS: removing the last admin would brick the registry
        // (no one left who can submit records or manage admins).
        let mut s = fresh_state();
        bootstrap_admin_impl(&mut s, p(1)).unwrap();
        let err = remove_admin_impl(&mut s, p(1), p(1)).unwrap_err();
        assert!(err.contains("last remaining admin"));
        assert!(is_admin(&s, &p(1)));
    }

    #[test]
    fn remove_admin_succeeds_with_multiple_admins() {
        let mut s = fresh_state();
        bootstrap_admin_impl(&mut s, p(1)).unwrap();
        add_admin_impl(&mut s, p(1), p(2)).unwrap();
        assert!(remove_admin_impl(&mut s, p(1), p(2)).is_ok());
        assert!(!is_admin(&s, &p(2)));
    }

    #[test]
    fn remove_admin_nonexistent_principal_is_noop_not_error() {
        let mut s = fresh_state();
        bootstrap_admin_impl(&mut s, p(1)).unwrap();
        add_admin_impl(&mut s, p(1), p(2)).unwrap();
        assert!(remove_admin_impl(&mut s, p(1), p(200)).is_ok());
        assert!(is_admin(&s, &p(1)) && is_admin(&s, &p(2)));
    }

    // -------------------------------------------------------------
    // submit_record
    // -------------------------------------------------------------

    #[test]
    fn submit_record_unauthorized_rejected() {
        // ATTACK: a non-admin trying to write a fraudulent record directly
        // (bypassing the intended admin-gated back office).
        let mut s = fresh_state();
        bootstrap_admin_impl(&mut s, p(1)).unwrap();
        let root_before = s.current_root;
        let err = submit_record_impl(&mut s, p(2), 42, "5".into(), 0, 1, 999).unwrap_err();
        assert!(err.contains("unauthorized"));
        assert_eq!(s.current_root, root_before, "an unauthorized call must not mutate the tree");
    }

    #[test]
    fn submit_record_by_admin_succeeds_and_changes_root() {
        let mut s = fresh_state();
        bootstrap_admin_impl(&mut s, p(1)).unwrap();
        let root_before = s.current_root;
        let root_after = submit_record_impl(&mut s, p(1), 42, "5".into(), 0, 1, 999).unwrap();
        assert_ne!(fe_to_string(root_before), root_after);
        assert_eq!(fe_to_string(s.current_root), root_after);
    }

    #[test]
    fn submit_record_invalid_owner_commitment_rejected() {
        // ATTACK/robustness: non-numeric owner_commitment must not be
        // silently accepted or panic the call.
        let mut s = fresh_state();
        bootstrap_admin_impl(&mut s, p(1)).unwrap();
        let err = submit_record_impl(&mut s, p(1), 42, "not-a-number".into(), 0, 1, 999).unwrap_err();
        assert!(err.contains("could not parse"));
    }

    #[test]
    fn submit_record_resubmission_updates_leaf_in_place_not_appended() {
        let mut s = fresh_state();
        bootstrap_admin_impl(&mut s, p(1)).unwrap();
        let r1 = submit_record_impl(&mut s, p(1), 42, "5".into(), 0, 1, 999).unwrap();
        // Resubmitting identical values must land on the SAME leaf index,
        // not silently grow the tree / shift other leaves' positions.
        let r2 = submit_record_impl(&mut s, p(1), 42, "5".into(), 0, 1, 999).unwrap();
        assert_eq!(r1, r2);
        assert_eq!(s.next_leaf_index, 1, "resubmission must not consume a new leaf index");
    }

    #[test]
    fn submit_record_two_distinct_properties_get_distinct_leaf_indices() {
        let mut s = fresh_state();
        bootstrap_admin_impl(&mut s, p(1)).unwrap();
        submit_record_impl(&mut s, p(1), 42, "5".into(), 0, 1, 999).unwrap();
        submit_record_impl(&mut s, p(1), 43, "6".into(), 0, 1, 999).unwrap();
        assert_eq!(s.next_leaf_index, 2);
        assert_ne!(s.leaf_index_by_property.get(&42), s.leaf_index_by_property.get(&43));
    }

    #[test]
    fn submit_record_updating_one_property_changes_root_but_preserves_other_leaf() {
        // ATTACK/robustness: updating property A must not corrupt property
        // B's leaf or its Merkle path.
        let mut s = fresh_state();
        bootstrap_admin_impl(&mut s, p(1)).unwrap();
        submit_record_impl(&mut s, p(1), 42, "5".into(), 0, 1, 999).unwrap();
        submit_record_impl(&mut s, p(1), 43, "6".into(), 0, 1, 999).unwrap();
        let proof_43_before = get_merkle_proof_impl(&s, 43).unwrap();

        submit_record_impl(&mut s, p(1), 42, "999".into(), 1, 0, 12345).unwrap();
        let proof_43_after = get_merkle_proof_impl(&s, 43).unwrap();

        assert_eq!(proof_43_before.leaf_index, proof_43_after.leaf_index);
        assert_ne!(
            proof_43_before.root, proof_43_after.root,
            "root must change after any leaf update"
        );
        // property 43's own record must be untouched
        assert_eq!(get_record_impl(&s, 43).unwrap().owner_commitment, "6");
    }

    // -------------------------------------------------------------
    // get_record / get_merkle_proof
    // -------------------------------------------------------------

    #[test]
    fn get_record_unknown_returns_none() {
        let s = fresh_state();
        assert!(get_record_impl(&s, 999).is_none());
    }

    #[test]
    fn get_record_known_returns_data() {
        let mut s = fresh_state();
        bootstrap_admin_impl(&mut s, p(1)).unwrap();
        submit_record_impl(&mut s, p(1), 42, "5".into(), 0, 1, 999).unwrap();
        let rec = get_record_impl(&s, 42).unwrap();
        assert_eq!(rec.property_id, 42);
        assert_eq!(rec.owner_commitment, "5");
    }

    #[test]
    fn get_merkle_proof_unknown_returns_none() {
        let s = fresh_state();
        assert!(get_merkle_proof_impl(&s, 999).is_none());
    }

    #[test]
    fn get_merkle_proof_matches_manually_recomputed_root() {
        // Correctness of the tree math: recompute the root from the leaf
        // + returned siblings + returned path_bits using the SAME hash
        // the canister uses, and confirm it equals the stored root -- this
        // is exactly what a real prover depends on being true.
        let mut s = fresh_state();
        bootstrap_admin_impl(&mut s, p(1)).unwrap();
        submit_record_impl(&mut s, p(1), 42, "5".into(), 0, 1, 999).unwrap();
        let rec = get_record_impl(&s, 42).unwrap();
        let proof = get_merkle_proof_impl(&s, 42).unwrap();

        let mut cur = leaf_hash(&rec).unwrap();
        for level in 0..TREE_DEPTH {
            let sib = parse_fe(&proof.siblings[level]).unwrap();
            let bit = proof.path_bits[level];
            cur = if bit {
                title_air::hash(&[fe(DOMAIN_NODE), sib, cur])
            } else {
                title_air::hash(&[fe(DOMAIN_NODE), cur, sib])
            };
        }
        assert_eq!(fe_to_string(cur), proof.root);
    }

    // -------------------------------------------------------------
    // request_challenge
    // -------------------------------------------------------------

    #[test]
    fn request_challenge_anonymous_rejected() {
        // ATTACK: anonymous principal trying to issue itself a challenge
        // (would defeat any accountability the throttle/rate-limit gives).
        let mut s = fresh_state();
        let err = request_challenge_impl(&mut s, Principal::anonymous(), 1_000_000_000, 1).unwrap_err();
        assert!(err.contains("anonymous"));
    }

    #[test]
    fn request_challenge_throttle_blocks_rapid_calls() {
        // ATTACK: spamming request_challenge to exhaust storage / churn
        // the nonce counter.
        let mut s = fresh_state();
        request_challenge_impl(&mut s, p(1), 1_000_000_000, 1).unwrap();
        let err = request_challenge_impl(&mut s, p(1), 1_000_000_000 + 1, 1).unwrap_err();
        assert!(err.contains("rate limit"));
    }

    #[test]
    fn request_challenge_succeeds_after_interval() {
        let mut s = fresh_state();
        request_challenge_impl(&mut s, p(1), 1_000_000_000, 1).unwrap();
        let ok = request_challenge_impl(&mut s, p(1), 1_000_000_000 + MIN_CALL_INTERVAL_NS, 1);
        assert!(ok.is_ok());
    }

    #[test]
    fn request_challenge_captures_current_root_snapshot() {
        let mut s = fresh_state();
        bootstrap_admin_impl(&mut s, p(1)).unwrap();
        submit_record_impl(&mut s, p(1), 42, "5".into(), 0, 1, 999).unwrap();
        let view = request_challenge_impl(&mut s, p(2), 1_000_000_000, 1).unwrap();
        assert_eq!(view.merkle_root, fe_to_string(s.current_root));
    }

    #[test]
    fn request_challenge_ids_and_nonces_increase_monotonically() {
        let mut s = fresh_state();
        let v1 = request_challenge_impl(&mut s, p(1), 1_000_000_000, 1).unwrap();
        let v2 = request_challenge_impl(&mut s, p(2), 1_000_000_000 + MIN_CALL_INTERVAL_NS, 1).unwrap();
        assert!(v2.challenge_id > v1.challenge_id);
        assert!(v2.request_nonce > v1.request_nonce);
    }

    #[test]
    fn request_challenge_expires_at_is_now_plus_ttl() {
        let mut s = fresh_state();
        let now = 1_000_000_000i64;
        let view = request_challenge_impl(&mut s, p(1), now, 1).unwrap();
        assert_eq!(view.expires_at, now + CHALLENGE_TTL_NS);
    }

    // -------------------------------------------------------------
    // verify: precheck attack surface
    // -------------------------------------------------------------

    #[test]
    fn verify_unknown_challenge_id_rejected() {
        // ATTACK: fabricating a challenge_id that was never issued.
        let mut s = fresh_state();
        let inputs = vpi(BaseElement::ZERO, 0, 0, "1");
        let err = verify_precheck_impl(&mut s, p(1), 1_000_000_000, 999_999, &inputs).unwrap_err();
        assert!(err.contains("unknown or expired"));
    }

    #[test]
    fn verify_consumed_challenge_rejected_replay_attack() {
        // ATTACK: replaying the exact same successful proof/challenge a
        // second time.
        let mut s = fresh_state();
        let view = request_challenge_impl(&mut s, p(1), 1_000_000_000, 1).unwrap();
        let root = s.current_root;
        let inputs = vpi(root, view.request_nonce, view.current_timestamp, "n1");
        let t2 = 1_000_000_000 + MIN_CALL_INTERVAL_NS;
        verify_precheck_impl(&mut s, p(1), t2, view.challenge_id, &inputs).unwrap();
        verify_commit_impl(&mut s, view.challenge_id, "n1").unwrap();

        let t3 = t2 + MIN_CALL_INTERVAL_NS;
        let err = verify_precheck_impl(&mut s, p(1), t3, view.challenge_id, &inputs).unwrap_err();
        assert!(err.contains("already consumed"));
    }

    #[test]
    fn verify_expired_challenge_rejected() {
        let mut s = fresh_state();
        let view = request_challenge_impl(&mut s, p(1), 1_000_000_000, 1).unwrap();
        let root = s.current_root;
        let inputs = vpi(root, view.request_nonce, view.current_timestamp, "n1");
        let after_expiry = view.expires_at + 1;
        let err = verify_precheck_impl(&mut s, p(1), after_expiry, view.challenge_id, &inputs).unwrap_err();
        assert!(err.contains("expired"));
    }

    #[test]
    fn verify_registry_id_mismatch_rejected() {
        let mut s = fresh_state();
        let view = request_challenge_impl(&mut s, p(1), 1_000_000_000, 1).unwrap();
        let root = s.current_root;
        let mut inputs = vpi(root, view.request_nonce, view.current_timestamp, "n1");
        inputs.registry_id = 999;
        let err = verify_precheck_impl(&mut s, p(1), 1_000_000_000 + 1, view.challenge_id, &inputs).unwrap_err();
        assert!(err.contains("registry_id"));
    }

    #[test]
    fn verify_merkle_root_mismatch_rejected() {
        // ATTACK: proving against a STALE root after the registry has
        // since been updated (or a fabricated root entirely).
        let mut s = fresh_state();
        let view = request_challenge_impl(&mut s, p(1), 1_000_000_000, 1).unwrap();
        let wrong_root = BaseElement::new(999_999_999);
        let inputs = vpi(wrong_root, view.request_nonce, view.current_timestamp, "n1");
        let err = verify_precheck_impl(&mut s, p(1), 1_000_000_000 + 1, view.challenge_id, &inputs).unwrap_err();
        assert!(err.contains("merkle_root"));
    }

    #[test]
    fn verify_purpose_mismatch_rejected() {
        // ATTACK: reusing a proof issued for one purpose (e.g. "lease")
        // against a challenge requested for a different, higher-stakes
        // purpose (e.g. "sale").
        let mut s = fresh_state();
        let view = request_challenge_impl(&mut s, p(1), 1_000_000_000, 1).unwrap();
        let root = s.current_root;
        let mut inputs = vpi(root, view.request_nonce, view.current_timestamp, "n1");
        inputs.purpose = 2;
        let err = verify_precheck_impl(&mut s, p(1), 1_000_000_000 + 1, view.challenge_id, &inputs).unwrap_err();
        assert!(err.contains("purpose"));
    }

    #[test]
    fn verify_cross_challenge_public_input_mixing_rejected() {
        // ATTACK: taking the public inputs generated for challenge A and
        // submitting them against challenge B's challenge_id (or a proof
        // generated for a stale/different challenge entirely).
        let mut s = fresh_state();
        let view_a = request_challenge_impl(&mut s, p(1), 1_000_000_000, 1).unwrap();
        let t2 = 1_000_000_000 + MIN_CALL_INTERVAL_NS;
        let view_b = request_challenge_impl(&mut s, p(2), t2, 1).unwrap();
        let root = s.current_root;
        let inputs_from_a = vpi(root, view_a.request_nonce, view_a.current_timestamp, "n1");

        let t3 = t2 + MIN_CALL_INTERVAL_NS;
        // caller must be view_b's own requester (p(2)) to get past the
        // front-running guard and reach the public-input mismatch check
        // this test actually targets.
        let err = verify_precheck_impl(&mut s, p(2), t3, view_b.challenge_id, &inputs_from_a).unwrap_err();
        assert!(err.contains("mismatch"));
    }

    #[test]
    fn verify_current_timestamp_mismatch_rejected() {
        let mut s = fresh_state();
        let view = request_challenge_impl(&mut s, p(1), 1_000_000_000, 1).unwrap();
        let root = s.current_root;
        let mut inputs = vpi(root, view.request_nonce, view.current_timestamp, "n1");
        inputs.current_timestamp += 1;
        let err = verify_precheck_impl(&mut s, p(1), 1_000_000_000 + 1, view.challenge_id, &inputs).unwrap_err();
        assert!(err.contains("current_timestamp"));
    }

    #[test]
    fn verify_nullifier_double_spend_across_different_challenges_rejected() {
        // ATTACK: the classic double-spend -- reusing the same nullifier
        // value against a SECOND, otherwise-valid challenge, to try to
        // prove the same fact twice (or bypass a one-time-use guarantee).
        let mut s = fresh_state();
        let view1 = request_challenge_impl(&mut s, p(1), 1_000_000_000, 1).unwrap();
        let root = s.current_root;
        let inputs1 = vpi(root, view1.request_nonce, view1.current_timestamp, "SAME_NULLIFIER");
        let t2 = 1_000_000_000 + MIN_CALL_INTERVAL_NS;
        verify_precheck_impl(&mut s, p(1), t2, view1.challenge_id, &inputs1).unwrap();
        verify_commit_impl(&mut s, view1.challenge_id, "SAME_NULLIFIER").unwrap();

        let t3 = t2 + MIN_CALL_INTERVAL_NS;
        let view2 = request_challenge_impl(&mut s, p(3), t3, 1).unwrap();
        let inputs2 = vpi(root, view2.request_nonce, view2.current_timestamp, "SAME_NULLIFIER");
        let t4 = t3 + MIN_CALL_INTERVAL_NS;
        // caller must be view2's own requester (p(3)) to get past the
        // front-running guard and reach the nullifier double-spend check
        // this test actually targets.
        let err = verify_precheck_impl(&mut s, p(3), t4, view2.challenge_id, &inputs2).unwrap_err();
        assert!(err.contains("nullifier already spent"));
    }

    #[test]
    fn verify_caller_other_than_requester_rejected_front_running_guard() {
        // ATTACK: a third party (or a copy-cat replaying an observed,
        // still-in-flight ingress message under their own principal)
        // tries to consume someone else's challenge -- even with
        // otherwise perfectly valid public inputs for that challenge.
        let mut s = fresh_state();
        let view = request_challenge_impl(&mut s, p(1), 1_000_000_000, 1).unwrap();
        let root = s.current_root;
        let inputs = vpi(root, view.request_nonce, view.current_timestamp, "n1");
        let err = verify_precheck_impl(&mut s, p(2), 1_000_000_000 + 1, view.challenge_id, &inputs).unwrap_err();
        assert!(err.contains("does not match"));
    }

    #[test]
    fn verify_by_original_requester_still_succeeds() {
        // Confirms the front-running guard isn't over-broad: the actual
        // requester can still verify their own challenge normally.
        let mut s = fresh_state();
        let view = request_challenge_impl(&mut s, p(1), 1_000_000_000, 1).unwrap();
        let root = s.current_root;
        let inputs = vpi(root, view.request_nonce, view.current_timestamp, "n1");
        assert!(verify_precheck_impl(&mut s, p(1), 1_000_000_000 + 1, view.challenge_id, &inputs).is_ok());
    }

    #[test]
    fn verify_anonymous_caller_rejected() {
        let mut s = fresh_state();
        let view = request_challenge_impl(&mut s, p(1), 1_000_000_000, 1).unwrap();
        let root = s.current_root;
        let inputs = vpi(root, view.request_nonce, view.current_timestamp, "n1");
        let err = verify_precheck_impl(&mut s, Principal::anonymous(), 1_000_000_000 + 1, view.challenge_id, &inputs)
            .unwrap_err();
        assert!(err.contains("anonymous"));
    }

    #[test]
    fn verify_throttle_blocks_rapid_repeated_calls() {
        // ATTACK: hammering `verify` to burn a victim's instruction
        // budget / spam consensus with near-duplicate calls.
        let mut s = fresh_state();
        let view = request_challenge_impl(&mut s, p(1), 1_000_000_000, 1).unwrap();
        let root = s.current_root;
        let inputs = vpi(root, view.request_nonce, view.current_timestamp, "n1");
        verify_precheck_impl(&mut s, p(1), 1_000_000_000 + 1, view.challenge_id, &inputs).unwrap();
        let err = verify_precheck_impl(&mut s, p(1), 1_000_000_000 + 2, view.challenge_id, &inputs).unwrap_err();
        assert!(err.contains("rate limit"));
    }

    #[test]
    fn verify_malformed_merkle_root_string_rejected_gracefully() {
        // ATTACK/robustness: a non-numeric merkle_root string must be
        // rejected with a normal Err, not panic the call.
        let mut s = fresh_state();
        let view = request_challenge_impl(&mut s, p(1), 1_000_000_000, 1).unwrap();
        let root = s.current_root;
        let mut inputs = vpi(root, view.request_nonce, view.current_timestamp, "n1");
        inputs.merkle_root = "'; DROP TABLE registry; --".to_string();
        let err = verify_precheck_impl(&mut s, p(1), 1_000_000_000 + 1, view.challenge_id, &inputs).unwrap_err();
        assert!(err.contains("could not parse"));
    }

    // -------------------------------------------------------------
    // verify: crypto-phase panic hardening
    // -------------------------------------------------------------

    #[test]
    fn verify_crypto_never_panics_on_arbitrary_garbage_bytes() {
        // SECURITY PROPERTY: no proof_bytes payload -- however malformed
        // or adversarially crafted -- may ever cause a Rust panic to
        // escape verify_crypto_impl. If it did, the real canister's
        // update call would trap entirely instead of returning Err(..),
        // which is a denial-of-service surface on a public method.
        let inputs = vpi(BaseElement::ZERO, 0, 0, "1");
        let payloads: Vec<Vec<u8>> = vec![
            vec![],
            vec![0u8; 4],
            vec![0xFFu8; 4],
            vec![0u8; 10_000],
            (0..2000u32).map(|i| (i % 256) as u8).collect(),
            b"not even close to a proof".to_vec(),
        ];
        for bytes in payloads {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                verify_crypto_impl(&inputs, &bytes)
            }));
            assert!(outcome.is_ok(), "a panic escaped verify_crypto_impl for payload len={}", bytes.len());
            assert!(outcome.unwrap().is_err(), "garbage proof bytes must be rejected with Err, never Ok");
        }
    }

    // Deterministic xorshift PRNG -- no external `rand`/`arbitrary` crate
    // needed (this workspace already avoids extra deps for this reason;
    // see `test-harness/air_test/src/bin/fuzz_harness.rs`, which uses the
    // exact same generator for the AIR's own transition-constraint
    // fuzzing). Deterministic seeding means a CI failure here is always
    // reproducible locally with no seed to hunt down.
    struct FuzzRng(u64);
    impl FuzzRng {
        fn next_u64(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn next_byte(&mut self) -> u8 {
            (self.next_u64() & 0xFF) as u8
        }
        fn bytes(&mut self, len: usize) -> Vec<u8> {
            (0..len).map(|_| self.next_byte()).collect()
        }
    }

    #[test]
    fn verify_crypto_fuzz_never_panics_on_random_proof_bytes() {
        // Formalizes the fuzz coverage `verify_crypto_never_panics_on_
        // arbitrary_garbage_bytes` above only spot-checks with a handful
        // of hand-picked payloads: this runs several thousand random
        // byte buffers of varying, including boundary-adjacent, lengths
        // through the exact same `Proof::from_bytes` / `winterfell::
        // verify` decode path a real `verify` update call hits, and
        // asserts the `catch_unwind` boundary in `verify_crypto_impl`
        // holds for all of them -- the class of bug an under-tested
        // proof-decoder could hide (an internal `assert_eq!`/indexing
        // panic reachable only for specific malformed byte patterns that
        // a small fixed payload list wouldn't happen to hit).
        let inputs = vpi(BaseElement::ZERO, 0, 0, "1");
        let mut rng = FuzzRng(0xC0FFEE_u64 ^ 0x5EED_1234_5678_9ABC);
        let lengths = [0usize, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256, 511, 1000, 4096];
        let iterations_per_length = 25;
        let mut total = 0u32;
        for &len in &lengths {
            for _ in 0..iterations_per_length {
                let bytes = rng.bytes(len);
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| verify_crypto_impl(&inputs, &bytes)));
                assert!(outcome.is_ok(), "panic escaped verify_crypto_impl for len={len} bytes={bytes:?}");
                assert!(outcome.unwrap().is_err(), "random bytes must never verify as a valid proof, len={len}");
                total += 1;
            }
        }
        assert_eq!(total, (lengths.len() * iterations_per_length) as u32);
    }

    #[test]
    fn verify_precheck_fuzz_malformed_public_input_strings_never_panic() {
        // Same property, aimed at the Candid-blob edge of the surface
        // instead of proof_bytes: `merkle_root` and `nullifier` arrive as
        // caller-controlled strings (see `VerifyPublicInputs`) parsed by
        // `parse_fe`. Random byte content coerced into (often invalid)
        // UTF-8 strings exercises the same decode boundary a malformed
        // Candid text argument would.
        let mut s = fresh_state();
        let view = request_challenge_impl(&mut s, p(1), 1_000_000_000, 1).unwrap();
        let mut rng = FuzzRng(0x9E3779B9_u64 ^ 0xDEAD_BEEF_CAFE_F00D);
        // Each iteration must advance past MIN_CALL_INTERVAL_NS, or every
        // call after the first would just hit the per-caller throttle
        // and return early without ever reaching `parse_fe` -- making
        // the "fuzz" only actually exercise the first junk string.
        let mut now_ns = 1_000_000_000 + 1;
        for _ in 0..200 {
            let junk_len = 1 + (rng.next_u64() % 64) as usize;
            let junk = rng.bytes(junk_len);
            let s_lossy = String::from_utf8_lossy(&junk).to_string();
            let mut inputs = vpi(BaseElement::ZERO, view.request_nonce, view.current_timestamp, "n1");
            inputs.merkle_root = s_lossy.clone();
            inputs.nullifier = s_lossy;
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                verify_precheck_impl(&mut s, p(1), now_ns, view.challenge_id, &inputs)
            }));
            assert!(outcome.is_ok(), "panic escaped verify_precheck_impl for junk={junk:?}");
            now_ns += MIN_CALL_INTERVAL_NS;
        }
    }

    #[test]
    fn verify_crypto_rejects_empty_proof_bytes() {
        let inputs = vpi(BaseElement::ZERO, 0, 0, "1");
        let result = verify_crypto_impl(&inputs, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn verify_crypto_rejects_malformed_merkle_root_before_touching_proof_bytes() {
        // Confirms the crypto phase's own decimal-string parsing (for
        // merkle_root/nullifier) also fails cleanly rather than panicking,
        // independent of proof_bytes content.
        let mut inputs = vpi(BaseElement::ZERO, 0, 0, "1");
        inputs.merkle_root = "not-a-number".to_string();
        let result = verify_crypto_impl(&inputs, b"anything");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("could not parse"));
    }

    // -------------------------------------------------------------
    // verify: commit-phase / state-integrity
    // -------------------------------------------------------------

    #[test]
    fn verify_commit_marks_challenge_consumed_and_nullifier_spent() {
        let mut s = fresh_state();
        let view = request_challenge_impl(&mut s, p(1), 1_000_000_000, 1).unwrap();
        let ok = verify_commit_impl(&mut s, view.challenge_id, "n1").unwrap();
        assert_eq!(ok.nullifier, "n1");
        assert!(s.challenges.get(&view.challenge_id).unwrap().consumed);
        assert!(*s.nullifiers.get("n1").unwrap());
    }

    #[test]
    fn verify_commit_rejects_already_spent_nullifier_defense_in_depth() {
        let mut s = fresh_state();
        let view = request_challenge_impl(&mut s, p(1), 1_000_000_000, 1).unwrap();
        verify_commit_impl(&mut s, view.challenge_id, "n1").unwrap();
        let err = verify_commit_impl(&mut s, view.challenge_id, "n1").unwrap_err();
        assert!(err.contains("nullifier already spent"));
    }

    #[test]
    fn verify_precheck_and_commit_leave_state_untouched_when_crypto_phase_fails() {
        // Mirrors the real catch_unwind hardening property end to end at
        // the business-logic level: if the crypto phase fails (whether by
        // ordinary rejection or a caught internal panic), the challenge
        // must NOT be marked consumed and the nullifier must NOT be
        // marked spent -- so a legitimate retry against the same
        // challenge afterward still succeeds.
        let mut s = fresh_state();
        let view = request_challenge_impl(&mut s, p(1), 1_000_000_000, 1).unwrap();
        let root = s.current_root;
        let inputs = vpi(root, view.request_nonce, view.current_timestamp, "n1");

        verify_precheck_impl(&mut s, p(1), 1_000_000_000 + 1, view.challenge_id, &inputs).unwrap();
        let crypto_result = verify_crypto_impl(&inputs, b"garbage-not-a-real-proof");
        assert!(crypto_result.is_err());

        // state must be completely untouched by the failed attempt
        assert!(!s.challenges.get(&view.challenge_id).unwrap().consumed);
        assert!(s.nullifiers.get("n1").is_none());

        // a legitimate retry against the SAME challenge must still be
        // possible (only the precheck phase is re-run here; the commit
        // phase itself is exercised separately above) -- and must come
        // from the same requester, same as any real retry would.
        let t2 = 1_000_000_000 + MIN_CALL_INTERVAL_NS + 1;
        assert!(verify_precheck_impl(&mut s, p(1), t2, view.challenge_id, &inputs).is_ok());
    }

    // -------------------------------------------------------------
    // heartbeat / challenge pruning
    // -------------------------------------------------------------

    #[test]
    fn heartbeat_prunes_expired_challenges() {
        let mut s = fresh_state();
        let view = request_challenge_impl(&mut s, p(1), 1_000_000_000, 1).unwrap();
        assert!(s.challenges.contains_key(&view.challenge_id));
        heartbeat_impl(&mut s, view.expires_at + 1);
        assert!(!s.challenges.contains_key(&view.challenge_id));
    }

    #[test]
    fn heartbeat_keeps_unexpired_challenges() {
        let mut s = fresh_state();
        let view = request_challenge_impl(&mut s, p(1), 1_000_000_000, 1).unwrap();
        heartbeat_impl(&mut s, view.expires_at - 1);
        assert!(s.challenges.contains_key(&view.challenge_id));
    }

    #[test]
    fn heartbeat_does_not_prune_more_than_its_per_tick_bound() {
        // ATTACK/DoS-resistance: an attacker spamming request_challenge to
        // build up a huge backlog of (eventually expired) challenges must
        // not be able to make a single heartbeat tick do unbounded work.
        let mut s = fresh_state();
        let mut now = 1_000_000_000i64;
        let mut last_expires = 0i64;
        let total = MAX_PRUNE_PER_HEARTBEAT + 10;
        for i in 0..total {
            let view = request_challenge_impl(&mut s, p((i % 250) as u8 + 1), now, 1).unwrap();
            last_expires = view.expires_at;
            now += MIN_CALL_INTERVAL_NS;
        }
        heartbeat_impl(&mut s, last_expires + 1);
        let remaining = s.challenges.len() as u64;
        assert!(
            remaining >= 10,
            "a single heartbeat tick must not prune more than MAX_PRUNE_PER_HEARTBEAT challenges"
        );
    }

    // -------------------------------------------------------------
    // Merkle tree math primitives
    // -------------------------------------------------------------

    #[test]
    fn init_zero_hashes_has_correct_length() {
        let z = init_zero_hashes();
        assert_eq!(z.len(), TREE_DEPTH + 1);
    }

    #[test]
    fn node_at_falls_back_to_zero_hash_for_unset_nodes() {
        let s = fresh_state();
        assert_eq!(node_at(&s, 2, 123_456), s.zero_hashes[2]);
    }

    #[test]
    fn insert_leaf_is_deterministic() {
        let mut s1 = fresh_state();
        let mut s2 = fresh_state();
        let leaf = BaseElement::new(777);
        insert_leaf(&mut s1, 0, leaf);
        insert_leaf(&mut s2, 0, leaf);
        assert_eq!(s1.current_root, s2.current_root);
    }

    #[test]
    fn insert_leaf_at_different_indices_produces_different_roots() {
        let mut s1 = fresh_state();
        let mut s2 = fresh_state();
        let leaf = BaseElement::new(777);
        insert_leaf(&mut s1, 0, leaf);
        insert_leaf(&mut s2, 1, leaf);
        assert_ne!(
            s1.current_root, s2.current_root,
            "the same leaf value at a different tree position must produce a different root"
        );
    }

    // -------------------------------------------------------------
    // Throttle unit tests (used by both request_challenge and verify)
    // -------------------------------------------------------------

    #[test]
    fn throttle_rejects_anonymous() {
        let mut store = HashMap::new();
        let err = check_and_update_throttle(&mut store, Principal::anonymous(), 0).unwrap_err();
        assert!(err.contains("anonymous"));
    }

    #[test]
    fn throttle_rejects_rapid_repeat_from_same_caller() {
        let mut store = HashMap::new();
        check_and_update_throttle(&mut store, p(1), 1000).unwrap();
        let err = check_and_update_throttle(&mut store, p(1), 1000 + MIN_CALL_INTERVAL_NS - 1).unwrap_err();
        assert!(err.contains("rate limit"));
    }

    #[test]
    fn throttle_allows_call_exactly_at_interval_boundary() {
        let mut store = HashMap::new();
        check_and_update_throttle(&mut store, p(1), 1000).unwrap();
        assert!(check_and_update_throttle(&mut store, p(1), 1000 + MIN_CALL_INTERVAL_NS).is_ok());
    }

    #[test]
    fn throttle_is_independent_per_principal() {
        // ATTACK-adjacent: one caller's rapid calls must not throttle a
        // DIFFERENT, innocent caller (no shared/global rate limit).
        let mut store = HashMap::new();
        check_and_update_throttle(&mut store, p(1), 1000).unwrap();
        assert!(check_and_update_throttle(&mut store, p(2), 1001).is_ok());
    }

    // -------------------------------------------------------------
    // Field-element string parsing
    // -------------------------------------------------------------

    #[test]
    fn parse_fe_rejects_non_numeric_input() {
        assert!(parse_fe("abc").is_err());
    }

    #[test]
    fn parse_fe_rejects_negative_numbers() {
        assert!(parse_fe("-5").is_err());
    }

    #[test]
    fn parse_fe_rejects_empty_string() {
        assert!(parse_fe("").is_err());
    }

    #[test]
    fn parse_fe_accepts_valid_decimal_and_roundtrips_through_fe_to_string() {
        let v = parse_fe("12345").unwrap();
        assert_eq!(fe_to_string(v), "12345");
    }

    #[test]
    fn parse_fe_tolerates_surrounding_whitespace() {
        assert!(parse_fe("  42  ").is_ok());
    }
}