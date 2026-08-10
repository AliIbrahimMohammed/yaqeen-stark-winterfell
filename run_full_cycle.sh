#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# yaqeen-stark: full A-to-Z build, deploy, and end-to-end verification cycle,
# including a test of the catch_unwind panic-hardening added to verify().
#
# PRECONDITION: the two edits described earlier are already applied:
#   1. workspace Cargo.toml: [profile.release] panic = "unwind" (not "abort")
#   2. canister/src/lib.rs: the three-phase verify() rewrite
# This script does not apply those edits -- it assumes they're already in
# your working tree, and will just build/test/deploy/exercise the result.
#
# Usage:
#   cd ~/repo          # your project root, containing dfx.json
#   bash run_full_cycle.sh
#
# The script is idempotent-ish but assumes a --clean start each run (a fresh
# registry, so the prover's leaf-index-0 assumption holds). Re-running it
# tears down and restarts the local replica each time.
#
# FIX (2026-08-10): the Ok/Err detection below used to grep for the literal
# single-line substrings "variant { Ok" / "variant { Err". Newer dfx/candid
# pretty-printers put a `record { ... }` payload on its own line instead of
# inline with `variant {`, e.g.:
#
#   variant {
#     Ok = record { nullifier = "..." }
#   },
#
# so "variant { Ok" never appears on one line and the check false-negatived
# even on a genuine Ok response. Checks now match "Ok =" / "Err =", which
# survive regardless of how the surrounding record is line-wrapped.
# ---------------------------------------------------------------------------
set -euo pipefail

# --- fixed demo constants -----------------------------------------------
# owner_commitment is a deterministic hash of the prover's hardcoded demo
# owner_secret/property_id (0xA11CE / 42). If you've since made those
# configurable in prover/src/main.rs, replace this with whatever your
# prover run actually prints/derives instead.
OWNER_COMMITMENT="337752673219787512927531106234209707758"
PROPERTY_ID=42
ENCUMBRANCE_FLAG=0
LICENSE_STATUS=1
# Comfortably in the future relative to real wall-clock time, so
# current_timestamp < license_expiry holds for the life of this run.
LICENSE_EXPIRY=$(( $(date +%s) + 5*365*24*3600 ))
REGISTRY_ID=1
PURPOSE=1

step() { printf '\n\033[1;36m==> %s\033[0m\n' "$1"; }

# Extracts `field = 123_456 : nat64` (or any type) out of a dfx candid
# response and returns it as a plain integer (underscores stripped).
extract_field() {
  local field="$1" text="$2"
  echo "$text" | grep -oP "${field}\s*=\s*\"?\K[0-9_]+" | head -n1 | tr -d '_'
}

# ---------------------------------------------------------------------------
step "0. Toolchain sanity"
# ---------------------------------------------------------------------------
rustup default stable
rustup target add wasm32-unknown-unknown
command -v candid-extractor >/dev/null || cargo install candid-extractor
export PATH="$HOME/.cargo/bin:$PATH"
rustc --version
dfx --version

# ---------------------------------------------------------------------------
step "1. Unit tests: does the AIR itself still hold up?"
# ---------------------------------------------------------------------------
cargo test -p title_air

# ---------------------------------------------------------------------------
step "2. Build the canister for wasm32-unknown-unknown"
# ---------------------------------------------------------------------------
cargo build --release --target wasm32-unknown-unknown -p title_verifier

# ---------------------------------------------------------------------------
step "3. Fresh local replica + deploy"
# ---------------------------------------------------------------------------
dfx stop >/dev/null 2>&1 || true
dfx start --clean --background
dfx deploy

# Regenerate the authoritative .did from the real build and redeploy once,
# so the committed hand-written stand-in never silently drifts.
step "3b. Regenerate candid interface from the real wasm"
candid-extractor target/wasm32-unknown-unknown/release/title_verifier.wasm \
  > canister/title_verifier.did
dfx deploy

# ---------------------------------------------------------------------------
step "4. Bootstrap admin + submit the demo record"
# ---------------------------------------------------------------------------
dfx canister call title_verifier bootstrap_admin \
  "(principal \"$(dfx identity get-principal)\")"

dfx canister call title_verifier submit_record \
  "(${PROPERTY_ID}:nat64, \"${OWNER_COMMITMENT}\", ${ENCUMBRANCE_FLAG}:nat64, ${LICENSE_STATUS}:nat64, ${LICENSE_EXPIRY}:nat64)"

# ---------------------------------------------------------------------------
# Reusable function: request a fresh challenge, prove against it immediately,
# patch the real challenge_id into verify_args.candid. Everything downstream
# reads challenge_id/request_nonce/current_timestamp straight out of dfx's
# own output -- no manual copy/paste, and no risk of stale/expired-challenge
# failures from pausing between steps.
# ---------------------------------------------------------------------------
prove_against_fresh_challenge() {
  local out cid nonce ts
  out=$(dfx canister call title_verifier request_challenge "(${PURPOSE}:nat64)")
  # NOTE: this function's stdout is captured via $(...) by callers (see
  # CHALLENGE_ID_1/CHALLENGE_ID_2 below), so every line meant purely for
  # human visibility must go to stderr (>&2). Only the final `echo "$cid"`
  # is allowed to reach stdout -- otherwise the caller's variable ends up
  # containing this entire log instead of just the challenge id.
  echo "$out" >&2

  cid=$(extract_field "challenge_id" "$out")
  nonce=$(extract_field "request_nonce" "$out")
  ts=$(extract_field "current_timestamp" "$out")

  echo "-> challenge_id=$cid request_nonce=$nonce current_timestamp=$ts" >&2

  cargo run --release -p title_prover -- "$ts" "$nonce" "$LICENSE_EXPIRY" >&2

  sed -i "s/{challengeId}/${cid}/" verify_args.candid
  echo "$cid"   # caller captures this -- must be the ONLY stdout line
}

# ---------------------------------------------------------------------------
step "5. Golden path: fresh challenge -> real proof -> verify -> expect Ok"
# ---------------------------------------------------------------------------
CHALLENGE_ID_1=$(prove_against_fresh_challenge)
time dfx canister call title_verifier verify --argument-file verify_args.candid \
  | tee /tmp/verify_good_output.txt

if grep -q "Ok = " /tmp/verify_good_output.txt; then
  echo "PASS: golden-path verify returned Ok -- nothing broke."
else
  echo "FAIL: golden-path verify did not return Ok. Stopping here." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
step "6. Panic-hardening test: corrupted proof bytes must return Err, not trap"
# ---------------------------------------------------------------------------
# New challenge + fresh valid proof (the previous challenge is already
# consumed by step 5, and its nullifier already spent).
CHALLENGE_ID_2=$(prove_against_fresh_challenge)
cp verify_args.candid verify_args_good.candid

# Flip 24 random bytes inside the proof blob, keeping the file otherwise
# byte-for-byte identical (same challenge_id, same public inputs) -- this
# corrupts the proof structurally/cryptographically without touching Candid
# syntax, so any failure is attributable to the corruption, not a typo.
python3 - "$OWNER_COMMITMENT" << 'PYEOF'
import re, random
random.seed(1234)
with open("verify_args.candid") as f:
    content = f.read()
m = re.search(r'blob "((?:\\[0-9a-fA-F]{2})+)"', content)
if not m:
    raise SystemExit("could not find blob literal in verify_args.candid")
hexbytes = re.findall(r'\\([0-9a-fA-F]{2})', m.group(1))
idxs = random.sample(range(len(hexbytes)), min(24, len(hexbytes)))
for i in idxs:
    hexbytes[i] = format(int(hexbytes[i], 16) ^ 0xFF, '02x')
new_blob = ''.join('\\' + b for b in hexbytes)
new_content = content[:m.start(1)] + new_blob + content[m.end(1):]
with open("verify_args_corrupt.candid", "w") as f:
    f.write(new_content)
print(f"corrupted {len(idxs)} of {len(hexbytes)} proof bytes -> verify_args_corrupt.candid")
PYEOF

echo "--- calling verify with the CORRUPTED proof (expect Err, not a trap) ---"
set +e
dfx canister call title_verifier verify --argument-file verify_args_corrupt.candid \
  | tee /tmp/verify_corrupt_output.txt
CORRUPT_EXIT=$?
set -e

if grep -q "Err = " /tmp/verify_corrupt_output.txt; then
  echo "PASS: corrupted proof returned Err(...) -- catch_unwind hardening is working."
elif grep -qi "trap\|IC05\|Canister .* trapped\|reject" /tmp/verify_corrupt_output.txt; then
  echo "FAIL: corrupted proof TRAPPED the call instead of returning Err." >&2
  echo "      This means panic=unwind wasn't actually picked up by the build," >&2
  echo "      or the catch_unwind wrapping didn't take -- re-check Fix 1 and Fix 2." >&2
  exit 1
else
  echo "UNCERTAIN: unexpected output shape, inspect /tmp/verify_corrupt_output.txt by hand." >&2
fi

echo
echo "--- calling verify with the ORIGINAL, uncorrupted proof for the SAME"
echo "    challenge (expect Ok -- proves the caught panic left state untouched) ---"
dfx canister call title_verifier verify --argument-file verify_args_good.candid \
  | tee /tmp/verify_retry_output.txt

if grep -q "Ok = " /tmp/verify_retry_output.txt; then
  echo "PASS: legitimate retry after the caught panic still succeeded --"
  echo "      state was NOT corrupted by the malformed-proof attempt."
else
  echo "FAIL: legitimate retry failed. The caught panic may have left state" >&2
  echo "      inconsistent -- worth investigating before trusting this in prod." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
step "Done. Summary"
# ---------------------------------------------------------------------------
echo "Golden-path challenge_id:      $CHALLENGE_ID_1  -> $(grep -o 'nullifier = "[0-9]*"' /tmp/verify_good_output.txt)"
echo "Hardening-test challenge_id:   $CHALLENGE_ID_2  -> corrupted attempt handled, retry succeeded"
echo
echo "Look at the local replica's own terminal output above for lines like:"
echo '  [Canister ...] verify: proof_bytes=<N>B instructions=<M>'
echo "to read the real on-chain instruction count for each call."
