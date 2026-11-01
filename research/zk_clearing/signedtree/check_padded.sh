#!/usr/bin/env bash
# The padding rules: a batch with the last quarter of the sale slots and the last buyer slot
# unused (padding-key signatures, zeroed fields) must satisfy the circuit's R1CS.
#
# Usage: bash check_padded.sh <build dir of a run.sh run> <circuit name>
set -euo pipefail
BUILD="${1:?}"
CIRCUIT="${2:?}"
NODE="${NODE:-node}"
"$NODE" "$BUILD/${CIRCUIT}_js/generate_witness.js" "$BUILD/${CIRCUIT}_js/$CIRCUIT.wasm" \
  "$BUILD/inputs/padded.json" "$BUILD/padded.wtns"
"$NODE" "$BUILD/deps/node_modules/snarkjs/build/cli.cjs" wtns check "$BUILD/$CIRCUIT.r1cs" "$BUILD/padded.wtns" \
  > "$BUILD/padded-check.log" 2>&1
if grep -q "WITNESS CHECKING FINISHED SUCCESSFULLY" "$BUILD/padded-check.log"; then
  echo "padded batch (padding slots, padding-key signatures): witness satisfies the R1CS" | tee -a "$BUILD/results.txt"
else
  echo "padded batch: R1CS check failed (bad)" | tee -a "$BUILD/results.txt"
  exit 1
fi
