#!/usr/bin/env bash
# Prove M16's batch with the ceremony's key, into <work>/batch, the layout zkc-m1 and zkc-m2 read.
#
# Usage: bash prove_batch.sh <ceremony dir> <circuit build dir> <work dir> [--small]
#   <ceremony dir>       ceremony_sim.sh's output: accounting16x4_committed.zkey, verification_key.json
#   <circuit build dir>  a groth16/run.sh build of accounting16x4_committed: its _js/ witness
#                        generator and deps/node_modules (snarkjs, circomlibjs)
#   --small              batch.py's testnet4 batch
#
# Writes input.json, opening.json, batch.wtns, proof.json, public.json, verification_key.json
# and sale_commitment.txt, after snarkjs verifies the proof against the ceremony's key and
# circomlibjs recomputes the sale commitment the proof carries.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZK="$(dirname "$HERE")"
CEREMONY="$(cd "${1:?ceremony dir}" && pwd)"
BUILD="$(cd "${2:?circuit build dir}" && pwd)"
WORK="$(mkdir -p "${3:?work dir}" && cd "$3" && pwd)"
shift 3
CIRCUIT=accounting16x4_committed
NODE="${NODE:-node}"
SNARKJS=("$NODE" "$BUILD/deps/node_modules/snarkjs/build/cli.cjs")
BATCH="$WORK/batch"
mkdir -p "$BATCH"

python3 "$ZK/bitvm/batch.py" "$BATCH" "$@"
"$NODE" "$BUILD/${CIRCUIT}_js/generate_witness.js" "$BUILD/${CIRCUIT}_js/$CIRCUIT.wasm" "$BATCH/input.json" "$BATCH/batch.wtns"
"${SNARKJS[@]}" wtns check "$BUILD/$CIRCUIT.r1cs" "$BATCH/batch.wtns" | tail -1
/usr/bin/time -f "prove: %e s, %M KiB" "${SNARKJS[@]}" groth16 prove "$CEREMONY/$CIRCUIT.zkey" "$BATCH/batch.wtns" "$BATCH/proof.json" "$BATCH/public.json"
"${SNARKJS[@]}" groth16 verify "$CEREMONY/verification_key.json" "$BATCH/public.json" "$BATCH/proof.json" | grep -q "OK!"
echo "batch proof: verified by snarkjs against the ceremony's verifying key"
cp "$CEREMONY/verification_key.json" "$BATCH/verification_key.json"
"$NODE" "$ZK/groth16/commit.js" "$BUILD/deps/node_modules" "$BATCH/input.json" > "$BATCH/sale_commitment.txt"
proved="$("$NODE" -p "require('$BATCH/public.json')[0]")"
[ "$proved" = "$(cat "$BATCH/sale_commitment.txt")" ] || { echo "saleCommitment $proved != circomlibjs $(cat "$BATCH/sale_commitment.txt")"; exit 1; }
echo "batch saleCommitment matches circomlibjs: $proved"
echo "verifying key sha256: $(sha256sum "$BATCH/verification_key.json" | cut -d' ' -f1)"
