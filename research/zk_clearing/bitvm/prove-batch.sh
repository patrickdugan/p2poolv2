#!/usr/bin/env bash
# Groth16 inputs for the M1 demo, reusing groth16/run.sh:
#   1. run.sh accounting16x4_committed into <work>/v1 (circuit, insecure deterministic setup,
#      the example proof and every negative check), unless <work>/v1/results.txt exists;
#   2. check the verifying key is the one GROTH16.md recorded;
#   3. prove the regtest batch (batch.py) with the same proving key into <work>/batch and
#      recompute its saleCommitment with circomlibjs.
#
# Usage: bash research/zk_clearing/bitvm/prove-batch.sh <work dir>
# Needs the same tools as groth16/run.sh (circom 2.2.2, node, npm, python3, GNU time).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZK="$(dirname "$HERE")"
WORK="$(mkdir -p "${1:?usage: prove-batch.sh <work dir>}" && cd "$1" && pwd)"
NODE="${NODE:-node}"
CIRCUIT=accounting16x4_committed
V1="$WORK/v1"
BATCH="$WORK/batch"

if [ ! -f "$V1/results.txt" ] || [ ! -f "$V1/$CIRCUIT.zkey" ]; then
  bash "$ZK/groth16/run.sh" "$CIRCUIT" "$V1"
fi

vk_sha="$(sha256sum "$V1/verification_key.json" | cut -d' ' -f1)"
case "$vk_sha" in
  3d5030f9*b8533494ec) echo "verifying key sha256 $vk_sha (matches GROTH16.md)" ;;
  *) echo "verifying key sha256 $vk_sha differs from GROTH16.md (3d5030f9...b8533494ec)"; exit 1 ;;
esac

SNARKJS=("$NODE" "$V1/deps/node_modules/snarkjs/build/cli.cjs")
mkdir -p "$BATCH"
python3 "$HERE/batch.py" "$BATCH"
"$NODE" "$V1/${CIRCUIT}_js/generate_witness.js" "$V1/${CIRCUIT}_js/$CIRCUIT.wasm" \
  "$BATCH/input.json" "$BATCH/batch.wtns"
"${SNARKJS[@]}" wtns check "$V1/$CIRCUIT.r1cs" "$BATCH/batch.wtns" | tail -1
"${SNARKJS[@]}" groth16 prove "$V1/$CIRCUIT.zkey" "$BATCH/batch.wtns" "$BATCH/proof.json" "$BATCH/public.json"
"${SNARKJS[@]}" groth16 verify "$V1/verification_key.json" "$BATCH/public.json" "$BATCH/proof.json" | grep -q "OK!"
echo "batch proof: verified by snarkjs"
cp "$V1/verification_key.json" "$BATCH/verification_key.json"
"$NODE" "$ZK/groth16/commit.js" "$V1/deps/node_modules" "$BATCH/input.json" > "$BATCH/sale_commitment.txt"
proved="$("$NODE" -p "require('$BATCH/public.json')[0]")"
if [ "$proved" != "$(cat "$BATCH/sale_commitment.txt")" ]; then
  echo "batch saleCommitment $proved != circomlibjs $(cat "$BATCH/sale_commitment.txt")"; exit 1
fi
echo "batch saleCommitment matches circomlibjs: $proved"
