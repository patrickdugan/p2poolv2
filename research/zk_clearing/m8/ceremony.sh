#!/usr/bin/env bash
# Multi-party Groth16 phase 2 for a zk_clearing circuit, on top of a phase-1 file.
#
# Usage: bash ceremony.sh <circuit.r1cs> <phase-1 .ptau> <contributors> <beacon hex> <out dir>
#
# Each contribution runs `snarkjs zkey contribute` with fresh entropy from
# /dev/urandom; in a real ceremony every contributor runs that step on their
# own machine on the previous zkey and passes the result on, and the setup is
# sound if any one of them destroyed their entropy. A final public beacon
# (for example a future Bitcoin block hash) closes it. `snarkjs zkey verify`
# then checks the whole chain against the circuit and the phase-1 file, and
# the contribution hashes are printed for each contributor to compare with
# what they saw.
#
# For a real deployment the phase-1 file must come from a public ceremony
# (for example the Perpetual Powers of Tau), not from groth16/run.sh's
# insecure local beacon.
set -euo pipefail

R1CS="${1:?r1cs}"; PTAU="${2:?ptau}"; CONTRIBUTORS="${3:?contributor count}"; BEACON="${4:?beacon hex}"; OUT="${5:?out dir}"
NODE="${NODE:-node}"
SNARKJS=("$NODE" "${SNARKJS_CLI:?set SNARKJS_CLI to snarkjs/build/cli.cjs}")
mkdir -p "$OUT"
NAME="$(basename "$R1CS" .r1cs)"

"${SNARKJS[@]}" groth16 setup "$R1CS" "$PTAU" "$OUT/${NAME}_0.zkey" > /dev/null
for i in $(seq 1 "$CONTRIBUTORS"); do
  entropy="$(head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  "${SNARKJS[@]}" zkey contribute "$OUT/${NAME}_$((i - 1)).zkey" "$OUT/${NAME}_$i.zkey" \
    --name="contributor $i" -e="$entropy" > "$OUT/contribution_$i.log"
  rm -f "$OUT/${NAME}_$((i - 1)).zkey"
  unset entropy
  echo "contribution $i: $(grep -A4 'Contribution Hash' "$OUT/contribution_$i.log" | tr -s ' ' | tr '\n' ' ' | sed 's/\x1b\[[0-9;]*m//g' | cut -c1-200)"
done
"${SNARKJS[@]}" zkey beacon "$OUT/${NAME}_${CONTRIBUTORS}.zkey" "$OUT/$NAME.zkey" "$BEACON" 10 -n="final beacon" > /dev/null
rm -f "$OUT/${NAME}_${CONTRIBUTORS}.zkey"
"${SNARKJS[@]}" zkey verify "$R1CS" "$PTAU" "$OUT/$NAME.zkey" | sed 's/\x1b\[[0-9;]*m//g' > "$OUT/verify.log"
grep -q "ZKey Ok!" "$OUT/verify.log" || { echo "zkey verify FAILED"; tail -20 "$OUT/verify.log"; exit 1; }
echo "zkey verify: ZKey Ok! ($CONTRIBUTORS contributions + beacon)"
grep -E "contribution #|Beacon generator|Hash:" "$OUT/verify.log" | head -40
"${SNARKJS[@]}" zkey export verificationkey "$OUT/$NAME.zkey" "$OUT/verification_key.json" > /dev/null
echo "verifying key sha256: $(sha256sum "$OUT/verification_key.json" | cut -d' ' -f1)"
