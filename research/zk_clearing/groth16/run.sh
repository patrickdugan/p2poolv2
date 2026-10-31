#!/usr/bin/env bash
# Groth16 experiment for a research/zk_clearing circuit, end to end:
# compile, valid and invalid witnesses, deterministic setup, prove, verify,
# tampered public inputs, forged witness, and measurements.
#
# Usage: bash research/zk_clearing/groth16/run.sh <circuit name> [build dir]
#   e.g. bash research/zk_clearing/groth16/run.sh accounting16x4 /tmp/zkc
#
# Needs circom 2.2.2, Node with npm, python3 and GNU time on PATH (or set
# CIRCOM / NODE / NPM). npm packages are installed from the committed
# package-lock.json into <build dir>/deps, never into the repository.
#
# The setup is a single deterministic beacon (no secret contribution), so
# anyone can rebuild the same verifying key. It is therefore INSECURE: the
# toxic waste is public and anyone can forge proofs. It exists only to
# measure the circuit and test its constraints.
set -euo pipefail

CIRCUIT="${1:?usage: run.sh <circuit name> [build dir]}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZK="$(dirname "$HERE")"
BUILD="$(mkdir -p "${2:-/tmp/zkc-$CIRCUIT}" && cd "${2:-/tmp/zkc-$CIRCUIT}" && pwd)"
CIRCOM="${CIRCOM:-circom}"
NODE="${NODE:-node}"
NPM="${NPM:-npm}"
POWER="${POWER:-14}"
# CIRCUIT_DIR holds <circuit>.circom (default circuits/). PTAU=<file> reuses a
# prepared phase-1 file (from an earlier run at a power >= the circuit needs)
# instead of generating one.
CIRCUIT_DIR="${CIRCUIT_DIR:-$ZK/circuits}"
PTAU="${PTAU:-}"
REQUIRED_CIRCOM="2.2.2"
BEACON="$(printf 'p2poolv2 zk_clearing insecure deterministic setup v1' | sha256sum | cut -d' ' -f1)"
RESULTS="$BUILD/results.txt"

"$CIRCOM" --version | grep -q "$REQUIRED_CIRCOM" || { echo "need circom $REQUIRED_CIRCOM, got: $("$CIRCOM" --version)"; exit 2; }
command -v /usr/bin/time >/dev/null || { echo "need GNU time at /usr/bin/time"; exit 2; }

mkdir -p "$BUILD/deps"
cp "$HERE/package.json" "$HERE/package-lock.json" "$BUILD/deps/"
(cd "$BUILD/deps" && "$NPM" ci --silent --no-audit --no-fund)
SNARKJS=("$NODE" "$BUILD/deps/node_modules/snarkjs/build/cli.cjs")

measure() { # measure <label> <command...>: run, append wall seconds and max RSS to results
  local label="$1"; shift
  /usr/bin/time -f "%e %M" -o "$BUILD/.time" "$@"
  read -r seconds rss_kb < "$BUILD/.time"
  printf '%-28s %8.2f s  %8d KiB max RSS\n' "$label" "$seconds" "$rss_kb" >> "$RESULTS"
}

: > "$RESULTS"
{
  echo "circuit: $CIRCUIT"
  echo "git: $(git -C "$ZK" rev-parse HEAD 2>/dev/null || echo unknown)$(git -C "$ZK" diff --quiet 2>/dev/null || echo ' (uncommitted changes)')"
  echo "circom: $("$CIRCOM" --version)"
  echo "node: $("$NODE" --version)  snarkjs: $("$NODE" -p "require('$BUILD/deps/node_modules/snarkjs/package.json').version")"
  echo "setup: INSECURE deterministic beacon, power $POWER, beacon $BEACON"
  echo
} >> "$RESULTS"

echo "== compile"
measure "compile" "$CIRCOM" "$CIRCUIT_DIR/$CIRCUIT.circom" --r1cs --wasm --sym --O2 \
  -l "$BUILD/deps/node_modules" -o "$BUILD"
"${SNARKJS[@]}" r1cs info "$BUILD/$CIRCUIT.r1cs" | tee "$BUILD/r1cs-info.txt"
grep -E "# of (Constraints|Wires|Private Inputs|Public Inputs|Outputs)" "$BUILD/r1cs-info.txt" \
  | sed 's/.*\] //' >> "$RESULTS"

echo "== fixtures"
# FIXTURES=<script> overrides the generator; it gets <out dir> <node_modules dir>.
if [ -n "${FIXTURES:-}" ]; then
  bash "$FIXTURES" "$BUILD/inputs" "$BUILD/deps/node_modules"
else
  python3 "$ZK/fixtures.py" "$BUILD/inputs" "$CIRCUIT"
fi
WITNESS_JS=("$NODE" "$BUILD/${CIRCUIT}_js/generate_witness.js" "$BUILD/${CIRCUIT}_js/$CIRCUIT.wasm")

echo "== valid witness"
"${WITNESS_JS[@]}" "$BUILD/inputs/valid.json" "$BUILD/valid.wtns"
"${SNARKJS[@]}" wtns check "$BUILD/$CIRCUIT.r1cs" "$BUILD/valid.wtns" | tail -1
# The Python adapter computes field inverses itself, so its modulus must be
# the prime Circom compiled the circuit over.
(cd "$ZK" && python3 -c "
import wtns, witness
prime = wtns.read_wtns('$BUILD/valid.wtns').prime
assert prime == witness.BN254_FR, f'witness.BN254_FR {witness.BN254_FR} != circuit prime {prime}'
print('field check: witness.BN254_FR matches the circuit prime')") | tee -a "$RESULTS"

echo "== invalid witnesses (each must be rejected)"
echo >> "$RESULTS"; echo "invalid fixtures (witness calculator must reject):" >> "$RESULTS"
invalid_status=0
for fixture in "$BUILD"/inputs/invalid/*.json; do
  name="$(basename "$fixture" .json)"
  if "${WITNESS_JS[@]}" "$fixture" "$BUILD/invalid-$name.wtns" > "$BUILD/invalid-$name.log" 2>&1; then
    echo "  ACCEPTED (bad) $name" | tee -a "$RESULTS"; invalid_status=1
  else
    where="$(grep -o 'Error in template [^ ]* line: [0-9]*' "$BUILD/invalid-$name.log" | head -1)"
    echo "  rejected $name: ${where:-$(tail -1 "$BUILD/invalid-$name.log")}" | tee -a "$RESULTS"
  fi
done

echo "== setup (insecure deterministic beacon)"
if [ -n "$PTAU" ]; then
  cp "$PTAU" "$BUILD/pot_final.ptau"
  echo "phase 1: reused $PTAU" >> "$RESULTS"
else
measure "ptau new + beacon + prepare" bash -c "
  '${SNARKJS[0]}' '${SNARKJS[1]}' powersoftau new bn128 $POWER '$BUILD/pot_0.ptau' >/dev/null &&
  '${SNARKJS[0]}' '${SNARKJS[1]}' powersoftau beacon '$BUILD/pot_0.ptau' '$BUILD/pot_1.ptau' $BEACON 10 -n=insecure >/dev/null &&
  '${SNARKJS[0]}' '${SNARKJS[1]}' powersoftau prepare phase2 '$BUILD/pot_1.ptau' '$BUILD/pot_final.ptau' >/dev/null"
fi
measure "groth16 setup + beacon" bash -c "
  '${SNARKJS[0]}' '${SNARKJS[1]}' groth16 setup '$BUILD/$CIRCUIT.r1cs' '$BUILD/pot_final.ptau' '$BUILD/${CIRCUIT}_0.zkey' >/dev/null &&
  '${SNARKJS[0]}' '${SNARKJS[1]}' zkey beacon '$BUILD/${CIRCUIT}_0.zkey' '$BUILD/$CIRCUIT.zkey' $BEACON 10 -n=insecure >/dev/null"
"${SNARKJS[@]}" zkey export verificationkey "$BUILD/$CIRCUIT.zkey" "$BUILD/verification_key.json" >/dev/null
{
  echo
  echo "proving key: $(stat -c %s "$BUILD/$CIRCUIT.zkey") bytes"
  echo "verifying key: $(stat -c %s "$BUILD/verification_key.json") bytes JSON, sha256 $(sha256sum "$BUILD/verification_key.json" | cut -d' ' -f1)"
} >> "$RESULTS"

echo "== prove and verify"
measure "groth16 prove" "${SNARKJS[@]}" groth16 prove "$BUILD/$CIRCUIT.zkey" "$BUILD/valid.wtns" \
  "$BUILD/proof.json" "$BUILD/public.json"
measure "groth16 verify (CLI)" "${SNARKJS[@]}" groth16 verify "$BUILD/verification_key.json" \
  "$BUILD/public.json" "$BUILD/proof.json"
"${SNARKJS[@]}" groth16 verify "$BUILD/verification_key.json" "$BUILD/public.json" "$BUILD/proof.json" | grep -q "OK!"
echo "proof: 2 G1 + 1 G2 = 256 bytes uncompressed; public signals: $("$NODE" -p "require('$BUILD/public.json').length")" >> "$RESULTS"
echo "valid proof: verified" | tee -a "$RESULTS"

echo "== re-split sale list with the same public totals"
"${WITNESS_JS[@]}" "$BUILD/inputs/resplit.json" "$BUILD/resplit.wtns"
"${SNARKJS[@]}" groth16 prove "$BUILD/$CIRCUIT.zkey" "$BUILD/resplit.wtns" "$BUILD/resplit-proof.json" "$BUILD/resplit-public.json"
"${SNARKJS[@]}" groth16 verify "$BUILD/verification_key.json" "$BUILD/resplit-public.json" "$BUILD/resplit-proof.json" | grep -q "OK!"
if cmp -s <("$NODE" -p "JSON.stringify(require('$BUILD/public.json'))") \
          <("$NODE" -p "JSON.stringify(require('$BUILD/resplit-public.json'))"); then
  echo "re-split sale list: proves the SAME public signals (the sale list is not bound)" | tee -a "$RESULTS"
else
  echo "re-split sale list: proves different public signals" | tee -a "$RESULTS"
fi
# COMMIT_JS=<script> recomputes public signal 0 (saleCommitment) from valid.json.
if [ -z "${COMMIT_JS:-}" ] && [ "$CIRCUIT" = accounting16x4_committed ]; then COMMIT_JS="$HERE/commit.js"; fi
if [ -n "${COMMIT_JS:-}" ]; then
  expected="$("$NODE" "$COMMIT_JS" "$BUILD/deps/node_modules" "$BUILD/inputs/valid.json")"
  proved="$("$NODE" -p "require('$BUILD/public.json')[0]")"
  resplit="$("$NODE" -p "require('$BUILD/resplit-public.json')[0]")"
  echo "saleCommitment (circomlibjs, honest sale list): $expected" >> "$RESULTS"
  if [ "$proved" = "$expected" ]; then
    echo "valid proof: saleCommitment matches circomlibjs" | tee -a "$RESULTS"
  else
    echo "valid proof: saleCommitment $proved != circomlibjs $expected (bad)" | tee -a "$RESULTS"; invalid_status=1
  fi
  if [ "$resplit" = "$expected" ]; then
    echo "re-split proof: commitment equals the honest one (bad)" | tee -a "$RESULTS"; invalid_status=1
  else
    echo "re-split proof: saleCommitment differs, so a verifier holding the honest sale list rejects it" | tee -a "$RESULTS"
  fi
fi
if grep -q "main.statementHash" "$BUILD/$CIRCUIT.sym"; then
  "$NODE" "$HERE/statement.js" "$BUILD/deps/node_modules" "$BUILD/inputs/valid.json" > "$BUILD/statement.json"
  expected="$("$NODE" -p "require('$BUILD/statement.json').statementHash")"
  proved="$("$NODE" -p "require('$BUILD/public.json')[0]")"
  resplit="$("$NODE" -p "require('$BUILD/resplit-public.json')[0]")"
  echo "statementHash (circomlibjs, honest statement): $expected" >> "$RESULTS"
  if [ "$proved" = "$expected" ]; then
    echo "valid proof: statementHash matches circomlibjs" | tee -a "$RESULTS"
  else
    echo "valid proof: statementHash $proved != circomlibjs $expected (bad)" | tee -a "$RESULTS"; invalid_status=1
  fi
  if [ "$resplit" = "$expected" ]; then
    echo "re-split proof: statementHash equals the honest one (bad)" | tee -a "$RESULTS"; invalid_status=1
  else
    echo "re-split proof: statementHash differs, so a verifier holding the honest statement rejects it" | tee -a "$RESULTS"
  fi
fi

echo "== tampered public signal (must not verify)"
"$NODE" -e "
  const fs = require('fs'); const p = JSON.parse(fs.readFileSync('$BUILD/public.json'));
  p[0] = (BigInt(p[0]) + 1n).toString(); fs.writeFileSync('$BUILD/public-tampered.json', JSON.stringify(p));"
if "${SNARKJS[@]}" groth16 verify "$BUILD/verification_key.json" "$BUILD/public-tampered.json" "$BUILD/proof.json" | grep -q "OK!"; then
  echo "tampered public signal: VERIFIED (bad)" | tee -a "$RESULTS"; invalid_status=1
else
  echo "tampered public signal: rejected" | tee -a "$RESULTS"
fi

echo "== non-canonical public signal: value + r (must not verify)"
# The same field element written as x + r. A verifier that reduces public
# inputs mod r instead of rejecting them would accept two encodings of one
# statement, which matters once public signals are matched against Bitcoin data.
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
# Wire 1 is the first public signal. Shift it by one so the R1CS no longer holds.
python3 "$ZK/wtns.py" forge "$BUILD/valid.wtns" "$BUILD/forged.wtns" 1 1
"${SNARKJS[@]}" wtns check "$BUILD/$CIRCUIT.r1cs" "$BUILD/forged.wtns" > "$BUILD/forged-check.log" 2>&1 || true
if grep -q "WITNESS IS CORRECT" "$BUILD/forged-check.log"; then
  echo "forged witness: R1CS check passed (bad)" | tee -a "$RESULTS"; invalid_status=1
else
  echo "forged witness: R1CS check rejects it ($(grep -o 'aborting checking process at constraint [0-9]*' "$BUILD/forged-check.log"))" | tee -a "$RESULTS"
fi
if "${SNARKJS[@]}" groth16 prove "$BUILD/$CIRCUIT.zkey" "$BUILD/forged.wtns" "$BUILD/forged-proof.json" \
     "$BUILD/forged-public.json" > "$BUILD/forged-prove.log" 2>&1; then
  if "${SNARKJS[@]}" groth16 verify "$BUILD/verification_key.json" "$BUILD/forged-public.json" \
       "$BUILD/forged-proof.json" | grep -q "OK!"; then
    echo "forged witness proof: VERIFIED (bad)" | tee -a "$RESULTS"; invalid_status=1
  else
    echo "forged witness proof: produced, rejected by the verifier" | tee -a "$RESULTS"
  fi
else
  echo "forged witness proof: prover refused ($(tail -1 "$BUILD/forged-prove.log"))" | tee -a "$RESULTS"
fi

echo; cat "$RESULTS"
exit $invalid_status
