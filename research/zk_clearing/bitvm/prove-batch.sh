#!/usr/bin/env bash
# Groth16 inputs for the BitVM demos, reusing groth16/run.sh:
#   1. run.sh <circuit> into <work>/<setup dir> (circuit, insecure deterministic setup, the
#      example proof and every negative check), unless its results.txt exists;
#   2. check the verifying key is the one recorded in GROTH16.md (M1) or M3.md (M3);
#   3. prove the regtest batch (batch.py) with the same proving key into <work>/batch and
#      recompute its saleCommitment (and for M3 its statement and statementHash) with
#      circomlibjs.
#
# Usage: bash research/zk_clearing/bitvm/prove-batch.sh <work dir> [circuit]
#   circuit: accounting16x4_committed (M1, the default, setup dir v1)
#            accounting16x4_hashed    (M3, setup dir hashed)
# Needs the same tools as groth16/run.sh (circom 2.2.2, node, npm, python3, GNU time).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZK="$(dirname "$HERE")"
WORK="$(mkdir -p "${1:?usage: prove-batch.sh <work dir> [circuit]}" && cd "$1" && pwd)"
CIRCUIT="${2:-accounting16x4_committed}"
NODE="${NODE:-node}"
case "$CIRCUIT" in
  accounting16x4_committed) SETUP="$WORK/v1"; VK_PREFIX=3d5030f9; VK_SUFFIX=b8533494ec; VK_DOC=GROTH16.md ;;
  accounting16x4_hashed) SETUP="$WORK/hashed"; VK_PREFIX=3264f607; VK_SUFFIX=530ae009fc; VK_DOC=bitvm/M3.md ;;
  *) echo "unknown circuit $CIRCUIT"; exit 2 ;;
esac
BATCH="$WORK/batch"

if [ ! -f "$SETUP/results.txt" ] || [ ! -f "$SETUP/$CIRCUIT.zkey" ]; then
  bash "$ZK/groth16/run.sh" "$CIRCUIT" "$SETUP"
fi

vk_sha="$(sha256sum "$SETUP/verification_key.json" | cut -d' ' -f1)"
case "$vk_sha" in
  "$VK_PREFIX"*"$VK_SUFFIX") echo "verifying key sha256 $vk_sha (matches $VK_DOC)" ;;
  *) echo "verifying key sha256 $vk_sha differs from $VK_DOC ($VK_PREFIX...$VK_SUFFIX)"; exit 1 ;;
esac

SNARKJS=("$NODE" "$SETUP/deps/node_modules/snarkjs/build/cli.cjs")
mkdir -p "$BATCH"
python3 "$HERE/batch.py" "$BATCH"
"$NODE" "$SETUP/${CIRCUIT}_js/generate_witness.js" "$SETUP/${CIRCUIT}_js/$CIRCUIT.wasm" \
  "$BATCH/input.json" "$BATCH/batch.wtns"
"${SNARKJS[@]}" wtns check "$SETUP/$CIRCUIT.r1cs" "$BATCH/batch.wtns" | tail -1
"${SNARKJS[@]}" groth16 prove "$SETUP/$CIRCUIT.zkey" "$BATCH/batch.wtns" "$BATCH/proof.json" "$BATCH/public.json"
"${SNARKJS[@]}" groth16 verify "$SETUP/verification_key.json" "$BATCH/public.json" "$BATCH/proof.json" | grep -q "OK!"
echo "batch proof: verified by snarkjs"
cp "$SETUP/verification_key.json" "$BATCH/verification_key.json"
"$NODE" "$ZK/groth16/commit.js" "$SETUP/deps/node_modules" "$BATCH/input.json" > "$BATCH/sale_commitment.txt"
if [ "$CIRCUIT" = accounting16x4_committed ]; then
  proved="$("$NODE" -p "require('$BATCH/public.json')[0]")"
  if [ "$proved" != "$(cat "$BATCH/sale_commitment.txt")" ]; then
    echo "batch saleCommitment $proved != circomlibjs $(cat "$BATCH/sale_commitment.txt")"; exit 1
  fi
  echo "batch saleCommitment matches circomlibjs: $proved"
else
  "$NODE" "$ZK/groth16/statement.js" "$SETUP/deps/node_modules" "$BATCH/input.json" > "$BATCH/statement.json"
  proved="$("$NODE" -p "require('$BATCH/public.json')[0]")"
  expected="$("$NODE" -p "require('$BATCH/statement.json').statementHash")"
  opened="$("$NODE" -p "require('$BATCH/statement.json').statement[0]")"
  if [ "$proved" != "$expected" ]; then
    echo "batch statementHash $proved != circomlibjs $expected"; exit 1
  fi
  if [ "$opened" != "$(cat "$BATCH/sale_commitment.txt")" ]; then
    echo "statement saleCommitment $opened != commit.js $(cat "$BATCH/sale_commitment.txt")"; exit 1
  fi
  echo "batch statementHash matches circomlibjs: $proved"
fi
