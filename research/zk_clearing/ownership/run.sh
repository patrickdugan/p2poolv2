#!/usr/bin/env bash
# M5 ownership circuit, end to end: compile OwnedSales for 1 and 16 sale slots, valid and
# invalid witnesses, an insecure deterministic Groth16 setup, prove and verify for one slot,
# tampered public signals, a forged witness, and measurements.
#
# Usage: bash research/zk_clearing/ownership/run.sh [build dir]
#
# Needs circom 2.2.2, Node with npm, python3 and GNU time on PATH (or set CIRCOM / NODE / NPM).
# npm packages come from groth16/package-lock.json into <build dir>/deps, never into the repository.
# Set SKIP_N16=1 to skip the 16-slot circuit and SKIP_SWEEP=1 to skip the depth sweep.
#
# The setup is a single deterministic beacon, so the toxic waste is public and anyone can forge
# proofs. It exists only to measure the circuit and test its constraints.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZK="$(dirname "$HERE")"
BUILD="$(mkdir -p "${1:-/tmp/zkc-ownership}" && cd "${1:-/tmp/zkc-ownership}" && pwd)"
CIRCOM="${CIRCOM:-circom}"
NODE="${NODE:-node}"
NPM="${NPM:-npm}"
PYTHON="${PYTHON:-python3}"
POWER="${POWER:-14}"
REQUIRED_CIRCOM="2.2.2"
BEACON="$(printf 'p2poolv2 zk_clearing insecure deterministic setup v1' | sha256sum | cut -d' ' -f1)"
RESULTS="$BUILD/results.txt"
FAIL=0

"$CIRCOM" --version | grep -q "$REQUIRED_CIRCOM" || { echo "need circom $REQUIRED_CIRCOM, got: $("$CIRCOM" --version)"; exit 2; }
command -v /usr/bin/time >/dev/null || { echo "need GNU time at /usr/bin/time"; exit 2; }

mkdir -p "$BUILD/deps"
cp "$ZK/groth16/package.json" "$ZK/groth16/package-lock.json" "$BUILD/deps/"
(cd "$BUILD/deps" && "$NPM" ci --silent --no-audit --no-fund)
SNARKJS=("$NODE" "$BUILD/deps/node_modules/snarkjs/build/cli.cjs")

measure() { # measure <label> <command...>: run, append wall seconds and max RSS to results
  local label="$1"; shift
  /usr/bin/time -f "%e %M" -o "$BUILD/.time" "$@"
  read -r seconds rss_kb < "$BUILD/.time"
  printf '%-34s %8.2f s  %9d KiB max RSS\n' "$label" "$seconds" "$rss_kb" >> "$RESULTS"
}

constraints_of() { # constraints_of <name>: constraint count from snarkjs r1cs info
  "${SNARKJS[@]}" r1cs info "$BUILD/$1.r1cs" > "$BUILD/$1-r1cs-info.txt"
  grep -o "# of Constraints: [0-9]*" "$BUILD/$1-r1cs-info.txt" | grep -o "[0-9]*$"
}

: > "$RESULTS"
{
  echo "circuit: owned_sale (OwnedSales, SMTVerifier inclusion, Poseidon leaf value)"
  echo "git: $(git -C "$ZK" rev-parse HEAD 2>/dev/null || echo unknown)$(git -C "$ZK" diff --quiet 2>/dev/null || echo ' (uncommitted changes)')"
  echo "circom: $("$CIRCOM" --version)"
  echo "node: $("$NODE" --version)  snarkjs: $("$NODE" -p "require('$BUILD/deps/node_modules/snarkjs/package.json').version")"
  echo "setup: INSECURE deterministic beacon, power $POWER, beacon $BEACON"
  echo
} >> "$RESULTS"

echo "== compile"
for name in owned_sale_n1 owned_sale_n16; do
  if [ "$name" = owned_sale_n16 ] && [ "${SKIP_N16:-0}" = 1 ]; then continue; fi
  measure "compile $name" "$CIRCOM" "$HERE/circuits/$name.circom" --r1cs --wasm --sym --O2 \
    -l "$BUILD/deps/node_modules" -o "$BUILD"
  count="$(constraints_of "$name")"
  echo "$name: $count constraints" | tee -a "$RESULTS"
  grep -E "# of (Wires|Private Inputs|Public Inputs|Outputs)" "$BUILD/$name-r1cs-info.txt" | sed 's/.*\] /  /' >> "$RESULTS"
done

if [ "${SKIP_SWEEP:-0}" != 1 ]; then
  echo "== constraints against depth (one sale slot)"
  mkdir -p "$BUILD/sweep"
  for levels in 8 16 24 32 40 48; do
    wrapper="$BUILD/sweep/owned_sale_n1_l$levels.circom"
    printf 'pragma circom 2.1.8;\ninclude "%s/circuits/owned_sale.circom";\ncomponent main {public [utxoRoot, activeSale, saleId, sellerId]} = OwnedSales(1, %s);\n' \
      "$HERE" "$levels" > "$wrapper"
    "$CIRCOM" "$wrapper" --r1cs --O2 -l "$BUILD/deps/node_modules" -o "$BUILD/sweep" > /dev/null
    echo "levels $levels: $("${SNARKJS[@]}" r1cs info "$BUILD/sweep/owned_sale_n1_l$levels.r1cs" | grep -o '# of Constraints: [0-9]*') (one sale slot)" | tee -a "$RESULTS"
  done
fi

echo "== inputs"
"$PYTHON" "$HERE/gen_inputs.py" "$BUILD/inputs" | tee -a "$RESULTS"

check_circuit() { # check_circuit <name>: valid inputs satisfy the R1CS, every invalid input is rejected
  local name="$1" status=0
  local witness_js=("$NODE" "$BUILD/${name}_js/generate_witness.js" "$BUILD/${name}_js/$name.wasm")
  local dir="$BUILD/inputs/${name#owned_sale_}"
  echo "== $name: valid witnesses"
  for valid in "$dir"/valid*.json; do
    label="$(basename "$valid" .json)"
    "${witness_js[@]}" "$valid" "$BUILD/$name-$label.wtns"
    "${SNARKJS[@]}" wtns check "$BUILD/$name.r1cs" "$BUILD/$name-$label.wtns" | tail -1
    echo "  accepted $name/$label" | tee -a "$RESULTS"
  done
  echo "== $name: invalid witnesses (each must be rejected)"
  echo >> "$RESULTS"; echo "$name invalid inputs (witness calculator must reject):" >> "$RESULTS"
  for fixture in "$dir"/invalid/*.json; do
    label="$(basename "$fixture" .json)"
    if "${witness_js[@]}" "$fixture" "$BUILD/$name-invalid-$label.wtns" > "$BUILD/$name-invalid-$label.log" 2>&1; then
      echo "  ACCEPTED (bad) $label" | tee -a "$RESULTS"; status=1
    else
      where="$(grep -o 'Error in template [^ ]* line: [0-9]*' "$BUILD/$name-invalid-$label.log" | head -1)"
      echo "  rejected $label: ${where:-$(tail -1 "$BUILD/$name-invalid-$label.log")}" | tee -a "$RESULTS"
    fi
  done
  return $status
}

check_circuit owned_sale_n1 || FAIL=1
if [ "${SKIP_N16:-0}" != 1 ]; then check_circuit owned_sale_n16 || FAIL=1; fi

NAME=owned_sale_n1
echo "== setup (insecure deterministic beacon)"
constraints="$(constraints_of "$NAME")"
if [ $((constraints + 8)) -gt $((1 << POWER)) ]; then echo "power $POWER is too small for $constraints constraints"; exit 2; fi
measure "ptau new + beacon + prepare" bash -c "
  '${SNARKJS[0]}' '${SNARKJS[1]}' powersoftau new bn128 $POWER '$BUILD/pot_0.ptau' >/dev/null &&
  '${SNARKJS[0]}' '${SNARKJS[1]}' powersoftau beacon '$BUILD/pot_0.ptau' '$BUILD/pot_1.ptau' $BEACON 10 -n=insecure >/dev/null &&
  '${SNARKJS[0]}' '${SNARKJS[1]}' powersoftau prepare phase2 '$BUILD/pot_1.ptau' '$BUILD/pot_final.ptau' >/dev/null"
measure "groth16 setup + beacon" bash -c "
  '${SNARKJS[0]}' '${SNARKJS[1]}' groth16 setup '$BUILD/$NAME.r1cs' '$BUILD/pot_final.ptau' '$BUILD/${NAME}_0.zkey' >/dev/null &&
  '${SNARKJS[0]}' '${SNARKJS[1]}' zkey beacon '$BUILD/${NAME}_0.zkey' '$BUILD/$NAME.zkey' $BEACON 10 -n=insecure >/dev/null"
"${SNARKJS[@]}" zkey export verificationkey "$BUILD/$NAME.zkey" "$BUILD/verification_key.json" >/dev/null
{
  echo
  echo "proving key: $(stat -c %s "$BUILD/$NAME.zkey") bytes"
  echo "verifying key: $(stat -c %s "$BUILD/verification_key.json") bytes JSON, sha256 $(sha256sum "$BUILD/verification_key.json" | cut -d' ' -f1)"
} >> "$RESULTS"

echo "== prove and verify"
WTNS="$BUILD/$NAME-valid.wtns"
measure "groth16 prove" "${SNARKJS[@]}" groth16 prove "$BUILD/$NAME.zkey" "$WTNS" "$BUILD/proof.json" "$BUILD/public.json"
measure "groth16 verify (CLI)" "${SNARKJS[@]}" groth16 verify "$BUILD/verification_key.json" "$BUILD/public.json" "$BUILD/proof.json"
"${SNARKJS[@]}" groth16 verify "$BUILD/verification_key.json" "$BUILD/public.json" "$BUILD/proof.json" | grep -q "OK!"
echo "proof: 2 G1 + 1 G2 = 256 bytes uncompressed; public signals: $("$NODE" -p "require('$BUILD/public.json').length")" >> "$RESULTS"
echo "valid proof: verified" | tee -a "$RESULTS"

echo "== the deepest allowed leaf proves too"
"${SNARKJS[@]}" groth16 prove "$BUILD/$NAME.zkey" "$BUILD/$NAME-valid_deepest.wtns" "$BUILD/deepest-proof.json" "$BUILD/deepest-public.json"
"${SNARKJS[@]}" groth16 verify "$BUILD/verification_key.json" "$BUILD/deepest-public.json" "$BUILD/deepest-proof.json" | grep -q "OK!"
echo "deepest leaf (depth 39) proof: verified" | tee -a "$RESULTS"

echo "== tampered public signals (must not verify)"
# public.json order: utxoRoot, activeSale[0], saleId[0], sellerId[0]
for index in 0 3; do
  case $index in 0) what=utxoRoot;; 3) what=sellerId;; esac
  "$NODE" -e "
    const fs = require('fs'); const p = JSON.parse(fs.readFileSync('$BUILD/public.json'));
    p[$index] = (BigInt(p[$index]) + 1n).toString(); fs.writeFileSync('$BUILD/public-tampered-$what.json', JSON.stringify(p));"
  if "${SNARKJS[@]}" groth16 verify "$BUILD/verification_key.json" "$BUILD/public-tampered-$what.json" "$BUILD/proof.json" | grep -q "OK!"; then
    echo "tampered $what: VERIFIED (bad)" | tee -a "$RESULTS"; FAIL=1
  else
    echo "tampered $what: rejected" | tee -a "$RESULTS"
  fi
done

echo "== non-canonical public signal: value + r"
"$NODE" -e "
  const fs = require('fs'); const p = JSON.parse(fs.readFileSync('$BUILD/public.json'));
  const r = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  p[0] = (BigInt(p[0]) + r).toString(); fs.writeFileSync('$BUILD/public-plus-r.json', JSON.stringify(p));"
if "${SNARKJS[@]}" groth16 verify "$BUILD/verification_key.json" "$BUILD/public-plus-r.json" "$BUILD/proof.json" 2>&1 | grep -q "OK!"; then
  echo "public signal + r: ACCEPTED by snarkjs (an on-chain verifier must range-check public inputs)" | tee -a "$RESULTS"
else
  echo "public signal + r: rejected by snarkjs" | tee -a "$RESULTS"
fi

echo "== forged witness that bypasses the calculator (must not verify)"
"$PYTHON" "$ZK/wtns.py" forge "$WTNS" "$BUILD/forged.wtns" 1 1
"${SNARKJS[@]}" wtns check "$BUILD/$NAME.r1cs" "$BUILD/forged.wtns" > "$BUILD/forged-check.log" 2>&1 || true
if grep -q "WITNESS IS CORRECT" "$BUILD/forged-check.log"; then
  echo "forged witness: R1CS check passed (bad)" | tee -a "$RESULTS"; FAIL=1
else
  echo "forged witness: R1CS check rejects it ($(grep -o 'aborting checking process at constraint [0-9]*' "$BUILD/forged-check.log"))" | tee -a "$RESULTS"
fi
if "${SNARKJS[@]}" groth16 prove "$BUILD/$NAME.zkey" "$BUILD/forged.wtns" "$BUILD/forged-proof.json" \
     "$BUILD/forged-public.json" > "$BUILD/forged-prove.log" 2>&1; then
  if "${SNARKJS[@]}" groth16 verify "$BUILD/verification_key.json" "$BUILD/forged-public.json" "$BUILD/forged-proof.json" | grep -q "OK!"; then
    echo "forged witness proof: VERIFIED (bad)" | tee -a "$RESULTS"; FAIL=1
  else
    echo "forged witness proof: produced, rejected by the verifier" | tee -a "$RESULTS"
  fi
else
  echo "forged witness proof: prover refused ($(tail -1 "$BUILD/forged-prove.log"))" | tee -a "$RESULTS"
fi

echo; cat "$RESULTS"
exit $FAIL
