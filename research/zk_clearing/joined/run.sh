#!/usr/bin/env bash
# M10: clearing16x4_owned end to end. groth16/run.sh does the generic work (compile, valid and
# invalid witnesses, setup, prove, verify, re-split, tampered signals, forged witness) with the
# joined fixtures; this script then checks what is specific to the join:
#
#   - every valid_*.json input (the rotated key) is accepted and satisfies the R1CS;
#   - every invalid input is refused inside the right template: the ownership fixtures in
#     SMTVerifier (the membership check of OwnedSale), the bad signature in EdDSAPoseidonVerifier.
#
# Usage: bash research/zk_clearing/joined/run.sh [build dir]
#   POWER and PTAU as for groth16/run.sh; PTAU=<prepared phase-1 file> reuses one. The circuit has
#   291,792 constraints, so the phase-1 power must be 19 or more. Setup stays the INSECURE
#   deterministic beacon of groth16/run.sh.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZK="$(dirname "$HERE")"
BUILD="$(mkdir -p "${1:-/tmp/zkc-owned}" && cd "${1:-/tmp/zkc-owned}" && pwd)"
CIRCUIT=clearing16x4_owned
NODE="${NODE:-node}"
export POWER="${POWER:-19}"
export FIXTURES="$HERE/fixtures.sh"
export COMMIT_JS="$ZK/signed/commit_signed.js"

status=0
bash "$ZK/groth16/run.sh" "$CIRCUIT" "$BUILD" || status=$?

SNARKJS=("$NODE" "$BUILD/deps/node_modules/snarkjs/build/cli.cjs")
WITNESS_JS=("$NODE" "$BUILD/${CIRCUIT}_js/generate_witness.js" "$BUILD/${CIRCUIT}_js/$CIRCUIT.wasm")
JOINED="$BUILD/joined-checks.txt"
: > "$JOINED"

echo "== extra valid inputs (the rotated key must be accepted)"
for input in "$BUILD"/inputs/valid_*.json; do
  [ -e "$input" ] || continue
  name="$(basename "$input" .json)"
  checked=""
  if "${WITNESS_JS[@]}" "$input" "$BUILD/$name.wtns" > "$BUILD/$name.log" 2>&1; then
    checked="$("${SNARKJS[@]}" wtns check "$BUILD/$CIRCUIT.r1cs" "$BUILD/$name.wtns" 2>&1 || true)"
  fi
  if grep -q "WITNESS IS CORRECT" <<< "$checked"; then
    echo "accepted $name (R1CS satisfied)" | tee -a "$JOINED"
  else
    echo "REFUSED (bad) $name: $(tail -1 "$BUILD/$name.log")" | tee -a "$JOINED"; status=1
  fi
done

echo "== the proof carries utxoRoot as its last public signal"
# Signals: 2 outputs (saleCommitment, escrowCommitment), then the 18 inputs of clearing16x4_signed, then utxoRoot.
expected="$("$NODE" -p "require('$BUILD/inputs/work/world.json').trees.T1.root")"
proved="$("$NODE" -p "require('$BUILD/public.json')[20]")"
if [ "$proved" = "$expected" ]; then
  echo "public signal 20 is the root of the tree built from the registry: $proved" | tee -a "$JOINED"
else
  echo "public signal 20 $proved != tree root $expected (bad)" | tee -a "$JOINED"; status=1
fi
"$NODE" -e "
  const fs = require('fs'); const p = JSON.parse(fs.readFileSync('$BUILD/public.json'));
  p[20] = (BigInt(p[20]) + 1n).toString(); fs.writeFileSync('$BUILD/public-tampered-utxoRoot.json', JSON.stringify(p));"
if "${SNARKJS[@]}" groth16 verify "$BUILD/verification_key.json" "$BUILD/public-tampered-utxoRoot.json" "$BUILD/proof.json" 2>&1 | grep -q "OK!"; then
  echo "tampered utxoRoot: VERIFIED (bad)" | tee -a "$JOINED"; status=1
else
  echo "tampered utxoRoot: rejected" | tee -a "$JOINED"
fi

echo "== the rotated batch proves under the same keys"
if [ -e "$BUILD/valid_rotated.wtns" ]; then
  "${SNARKJS[@]}" groth16 prove "$BUILD/$CIRCUIT.zkey" "$BUILD/valid_rotated.wtns" "$BUILD/rotated-proof.json" "$BUILD/rotated-public.json"
  if "${SNARKJS[@]}" groth16 verify "$BUILD/verification_key.json" "$BUILD/rotated-public.json" "$BUILD/rotated-proof.json" 2>&1 | grep -q "OK!"; then
    differing="$("$NODE" -p "
      const a = require('$BUILD/public.json'), b = require('$BUILD/rotated-public.json');
      a.map((v, i) => (v !== b[i] ? i : -1)).filter((i) => i >= 0).join(',')")"
    rotated_root="$("$NODE" -p "require('$BUILD/inputs/work/world.json').trees.T2.root")"
    echo "rotated batch: proof verifies; public signals that differ from the unrotated batch's: $differing" | tee -a "$JOINED"
    if [ "$differing" != "0,20" ] || [ "$("$NODE" -p "require('$BUILD/rotated-public.json')[20]")" != "$rotated_root" ]; then
      echo "rotated batch: unexpected public signals (bad)" | tee -a "$JOINED"; status=1
    fi
  else
    echo "rotated batch: proof does not verify (bad)" | tee -a "$JOINED"; status=1
  fi
fi

echo "== where each invalid input is refused"
for log in "$BUILD"/invalid-*.log; do
  name="$(basename "$log" .log)"; name="${name#invalid-}"
  chain="$(grep -o 'Error in template [A-Za-z0-9]*' "$log" | sed 's/Error in template //; s/_[0-9]*$//' | awk '!seen[$0]++' | paste -sd'<' - | sed 's/</ < /g')"
  case "$name" in
    bad_order_signature) want=EdDSAPoseidonVerifier ;;
    *) want=SMTVerifier ;;
  esac
  if grep -q "Error in template ${want}_" "$log"; then
    echo "$name: refused in $want ($chain)" | tee -a "$JOINED"
  else
    echo "$name: NOT refused in $want ($chain)" | tee -a "$JOINED"; status=1
  fi
done

{ echo; echo "checks specific to the join:"; sed 's/^/  /' "$JOINED"; } >> "$BUILD/results.txt"
exit $status
