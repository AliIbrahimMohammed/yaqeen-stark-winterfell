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

use candid::{CandidType, Principal};
use serde::Deserialize;
use std::cell::RefCell;
use std::collections::HashMap;
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

#[derive(Clone, CandidType, Deserialize)]
pub struct Record {
    pub property_id: u64,
    /// Poseidon-analog owner commitment, computed OFF-canister -- the
    /// canister never learns `owner_secret`. Decimal string, field element.
    pub owner_commitment: String,
    pub encumbrance_flag: u64,
    pub license_status: u64,
    pub license_expiry: u64,
}

#[derive(Clone, CandidType, Deserialize)]
pub struct MerkleProof {
    pub leaf_index: u64,
    pub siblings: Vec<String>,
    pub path_bits: Vec<bool>,
    pub root: String,
}

#[derive(Clone, CandidType, Deserialize)]
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
}

#[derive(CandidType, Deserialize, Clone)]
pub struct VerifyPublicInputs {
    pub registry_id: u64,
    pub merkle_root: String,
    pub purpose: u64,
    pub request_nonce: u64,
    pub current_timestamp: u64,
    pub nullifier: String,
}

#[derive(CandidType, Deserialize)]
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

fn is_admin(s: &State, p: &Principal) -> bool {
    s.admins.iter().any(|a| a == p)
}

// ---------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------

#[ic_cdk::init]
fn init() {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        s.zero_hashes = init_zero_hashes();
        s.current_root = s.zero_hashes[TREE_DEPTH];
    });
}

// ---------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------

/// One-time bootstrap: succeeds only while there are no admins yet. See
/// `main.mo`'s `bootstrapAdmin` for the full rationale (no constructor
/// arguments available; this is the runtime equivalent). Call this in the
/// SAME deploy session, before the canister id is shared.
#[ic_cdk::update]
fn bootstrap_admin(real_admin: Principal) -> Result<(), String> {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        if !s.admins.is_empty() {
            return Err("admins already bootstrapped -- use add_admin instead".to_string());
        }
        s.admins.push(real_admin);
        Ok(())
    })
}

#[ic_cdk::update]
fn add_admin(new_admin: Principal) -> Result<(), String> {
    let caller = ic_cdk::api::msg_caller();
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        if !is_admin(&s, &caller) {
            return Err("unauthorized".to_string());
        }
        if !s.admins.contains(&new_admin) {
            s.admins.push(new_admin);
        }
        Ok(())
    })
}

#[ic_cdk::update]
fn remove_admin(old_admin: Principal) -> Result<(), String> {
    let caller = ic_cdk::api::msg_caller();
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        if !is_admin(&s, &caller) {
            return Err("unauthorized".to_string());
        }
        if s.admins.len() <= 1 {
            return Err("cannot remove the last remaining admin".to_string());
        }
        s.admins.retain(|a| a != &old_admin);
        Ok(())
    })
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
        let mut s = s.borrow_mut();
        if !is_admin(&s, &caller) {
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
        insert_leaf(&mut s, index, leaf);
        Ok(fe_to_string(s.current_root))
    })
}

#[ic_cdk::query]
fn get_record(property_id: u64) -> Option<Record> {
    STATE.with(|s| s.borrow().records.get(&property_id).cloned())
}

#[ic_cdk::query]
fn get_merkle_proof(property_id: u64) -> Option<MerkleProof> {
    STATE.with(|s| {
        let s = s.borrow();
        let &index = s.leaf_index_by_property.get(&property_id)?;
        let mut siblings = Vec::with_capacity(TREE_DEPTH);
        let mut path_bits = Vec::with_capacity(TREE_DEPTH);
        let mut idx = index;
        let mut level: u8 = 0;
        while (level as usize) < TREE_DEPTH {
            let pair_base = (idx / 2) * 2;
            let sibling_index = if idx == pair_base { pair_base + 1 } else { pair_base };
            siblings.push(fe_to_string(node_at(&s, level, sibling_index)));
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
    })
}

// ---------------------------------------------------------------------
// Challenges
// ---------------------------------------------------------------------

fn check_and_update_throttle(
    store: &mut HashMap<Principal, i64>,
    caller: Principal,
) -> Result<(), String> {
    if caller == Principal::anonymous() {
        return Err("anonymous callers are not permitted".to_string());
    }
    let now = ic_cdk::api::time() as i64;
    if let Some(&last) = store.get(&caller) {
        if now - last < MIN_CALL_INTERVAL_NS {
            return Err("rate limit: try again shortly".to_string());
        }
    }
    store.insert(caller, now);
    Ok(())
}

#[ic_cdk::update]
fn request_challenge(purpose: u64) -> Result<ChallengeView, String> {
    let caller = ic_cdk::api::msg_caller();
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        check_and_update_throttle(&mut s.last_challenge_call_at, caller)?;

        let id = s.next_challenge_id;
        s.next_challenge_id += 1;
        let nonce = s.next_nonce;
        s.next_nonce += 1;
        let now_ns = ic_cdk::api::time() as i64;
        let ts = (now_ns / 1_000_000_000) as u64;

        let challenge = Challenge {
            registry_id: REGISTRY_ID,
            merkle_root: s.current_root,
            purpose,
            request_nonce: nonce,
            current_timestamp: ts,
            expires_at: now_ns + CHALLENGE_TTL_NS,
            consumed: false,
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
    })
}

// ---------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------

/// Verifies a Winterfell STARK proof on-chain and, on success, marks the
/// challenge consumed and the nullifier spent. Declared as an `update`
/// call, not a `query` -- same reasoning as
/// `ic-winterfell-verifier/canister`: query calls aren't certified by
/// subnet consensus, which defeats the point.
#[ic_cdk::update]
fn verify(challenge_id: u64, proof_bytes: Vec<u8>, public_inputs: VerifyPublicInputs) -> Result<VerifyOk, String> {
    let caller = ic_cdk::api::msg_caller();
    let start_instructions = ic_cdk::api::instruction_counter();

    let result = STATE.with(|s| {
        let mut s = s.borrow_mut();
        check_and_update_throttle(&mut s.last_verify_call_at, caller)?;

        let challenge = s
            .challenges
            .get(&challenge_id)
            .cloned()
            .ok_or_else(|| "unknown or expired challenge".to_string())?;
        if challenge.consumed {
            return Err("challenge already consumed".to_string());
        }
        if (ic_cdk::api::time() as i64) > challenge.expires_at {
            return Err("challenge expired".to_string());
        }

        // Public inputs must match the ORIGINALLY issued challenge exactly,
        // checked BEFORE any cryptographic work -- same ordering
        // `main.mo`'s `verify` calls load-bearing.
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

        let proof = Proof::from_bytes(&proof_bytes)
            .map_err(|e| format!("failed to decode proof bytes: {e}"))?;
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
        winterfell::verify::<TitleAir, title_air::HashFn, title_air::RandCoin, title_air::VC>(
            proof,
            air_pub_inputs,
            &acceptable,
        )
        .map_err(|e| format!("invalid proof: {e}"))?;

        if let Some(c) = s.challenges.get_mut(&challenge_id) {
            c.consumed = true;
        }
        s.nullifiers.insert(public_inputs.nullifier.clone(), true);

        Ok(VerifyOk {
            nullifier: public_inputs.nullifier,
        })
    });

    let used = ic_cdk::api::instruction_counter().saturating_sub(start_instructions);
    ic_cdk::println!("verify: proof_bytes={}B instructions={used}", proof_bytes.len());
    result
}

// ---------------------------------------------------------------------
// Heartbeat -- prune expired challenges (bounded per tick), same
// discipline as `main.mo`'s `heartbeat`.
// ---------------------------------------------------------------------

#[ic_cdk::heartbeat]
fn heartbeat() {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        let mut scanned = 0u64;
        let now = ic_cdk::api::time() as i64;
        while scanned < MAX_PRUNE_PER_HEARTBEAT && s.oldest_unpruned_challenge_id < s.next_challenge_id {
            let id = s.oldest_unpruned_challenge_id;
            match s.challenges.get(&id) {
                None => {
                    s.oldest_unpruned_challenge_id += 1;
                }
                Some(c) => {
                    if now > c.expires_at {
                        s.challenges.remove(&id);
                        s.oldest_unpruned_challenge_id += 1;
                    } else {
                        return;
                    }
                }
            }
            scanned += 1;
        }
    });
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
