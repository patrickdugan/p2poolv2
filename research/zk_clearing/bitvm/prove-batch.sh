#!/usr/bin/env bash
# Groth16 inputs for the BitVM demos, reusing groth16/run.sh:
#   1. run.sh <circuit> into <work>/<setup dir> (circuit, insecure deterministic setup, the
#      example proof and every negative check), unless its results.txt exists;
#   2. check the verifying key is the one recorded in GROTH16.md (M1), M3.md (M3) or
#      SIGNED_TREE.md (M14) or M17.md (M17);
#   3. prove the regtest batch (batch.py, batch_signed.py for M14, batch_joined.py for M17) with the
#      same proving key
#      into <work>/batch and recompute its saleCommitment (and for M3 and M14 its statement and
#      statementHash) with circomlibjs;
#   4. write the circuit's name to <work>/batch/circuit.txt, which zkc-m1 reads to pick the
#      statement layout.
#
# Usage: bash research/zk_clearing/bitvm/prove-batch.sh <work dir> [circuit]
#   circuit: accounting16x4_committed (M1, the default, setup dir v1)
#            accounting16x4_hashed    (M3, setup dir hashed)
#            signed_tree_16x4         (M14, setup dir signed_tree_16x4; M11's circuit, set up on the
#                                      power-20 phase-1 file $PTAU, default /root/zkc-m6/pot20_final.ptau)
#            owned_tree_pk_16x4       (M17, setup dir owned_tree_pk_16x4; M15's packed joined circuit,
#                                      OwnedSignedTreePacked, set up the same way through
#                                      joinedtree/run_size.sh pk 16 4; its statement is M11's 4 + 4B
#                                      values and the window tree's root)
# Needs the same tools as groth16/run.sh (circom 2.2.2, node, npm, python3, GNU time).
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZK="$(dirname "$HERE")"
WORK="$(mkdir -p "${1:?usage: prove-batch.sh <work dir> [circuit]}" && cd "$1" && pwd)"
CIRCUIT="${2:-accounting16x4_committed}"
NODE="${NODE:-node}"
case "$CIRCUIT" in
  accounting16x4_committed) SETUP="$WORK/v1"; VK_PREFIX=3d5030f9; VK_SUFFIX=b8533494ec; VK_DOC=GROTH16.md ;;
  accounting16x4_hashed) SETUP="$WORK/hashed"; VK_PREFIX=3264f607; VK_SUFFIX=530ae009fc; VK_DOC=bitvm/M3.md ;;
  signed_tree_16x4) SETUP="$WORK/signed_tree_16x4"; VK_PREFIX=d8937b82; VK_SUFFIX=1dc9c6c4; VK_DOC=signedtree/SIGNED_TREE.md ;;
  owned_tree_pk_16x4) SETUP="$WORK/owned_tree_pk_16x4"; VK_PREFIX=25ba85a4; VK_SUFFIX=771edfeb; VK_DOC=bitvm/M17.md ;;
  *) echo "unknown circuit $CIRCUIT"; exit 2 ;;
esac
BATCH="$WORK/batch"

if [ ! -f "$SETUP/results.txt" ] || [ ! -f "$SETUP/$CIRCUIT.zkey" ]; then
  case "$CIRCUIT" in
    signed_tree_16x4) POWER=20 PTAU="${PTAU:-/root/zkc-m6/pot20_final.ptau}" bash "$ZK/signedtree/run_size.sh" 16 4 "$SETUP" ;;
    owned_tree_pk_16x4) POWER=20 PTAU="${PTAU:-/root/zkc-m6/pot20_final.ptau}" bash "$ZK/joinedtree/run_size.sh" pk 16 4 "$SETUP" ;;
    *) bash "$ZK/groth16/run.sh" "$CIRCUIT" "$SETUP" ;;
  esac
fi

vk_sha="$(sha256sum "$SETUP/verification_key.json" | cut -d' ' -f1)"
case "$vk_sha" in
  "$VK_PREFIX"*"$VK_SUFFIX") echo "verifying key sha256 $vk_sha (matches $VK_DOC)" ;;
  *) echo "verifying key sha256 $vk_sha differs from $VK_DOC ($VK_PREFIX...$VK_SUFFIX)"; exit 1 ;;
esac

SNARKJS=("$NODE" "$SETUP/deps/node_modules/snarkjs/build/cli.cjs")
mkdir -p "$BATCH"
if [ "$CIRCUIT" = signed_tree_16x4 ]; then
  # The unsigned batch and its opening, then keys and signatures (sign.js also writes M11's
  # invalid fixtures next to valid.json; only valid.json is used).
  python3 -B "$HERE/batch_signed.py" "$BATCH"
  mkdir -p "$BATCH/signed"
  "$NODE" "$ZK/signedtree/sign.js" "$SETUP/deps/node_modules" "$BATCH/signed" "$BATCH/spec.json" "$BATCH/spec.json"
  cp "$BATCH/signed/valid.json" "$BATCH/input.json"
elif [ "$CIRCUIT" = owned_tree_pk_16x4 ]; then
  # The joined fixture's valid batch (run_size.sh left it under <setup>/inputs/work) with the
  # regtest amounts and heights, signed by the registered owners' order keys, then joined with its
  # membership witness (sign_tree.js).
  python3 -B "$HERE/batch_joined.py" "$SETUP/inputs/work" "$BATCH"
  "$NODE" "$ZK/joinedtree/sign_tree.js" sign "$SETUP/deps/node_modules" "$BATCH/variants" "$BATCH/signed"
  cp "$BATCH/signed/valid.json" "$BATCH/input.json"
else
  python3 -B "$HERE/batch.py" "$BATCH"
fi
"$NODE" "$SETUP/${CIRCUIT}_js/generate_witness.js" "$SETUP/${CIRCUIT}_js/$CIRCUIT.wasm" \
  "$BATCH/input.json" "$BATCH/batch.wtns"
"${SNARKJS[@]}" wtns check "$SETUP/$CIRCUIT.r1cs" "$BATCH/batch.wtns" | tail -1
"${SNARKJS[@]}" groth16 prove "$SETUP/$CIRCUIT.zkey" "$BATCH/batch.wtns" "$BATCH/proof.json" "$BATCH/public.json"
"${SNARKJS[@]}" groth16 verify "$SETUP/verification_key.json" "$BATCH/public.json" "$BATCH/proof.json" | grep -q "OK!"
echo "batch proof: verified by snarkjs"
cp "$SETUP/verification_key.json" "$BATCH/verification_key.json"
printf '%s\n' "$CIRCUIT" > "$BATCH/circuit.txt"
case "$CIRCUIT" in
  accounting16x4_committed)
    "$NODE" "$ZK/groth16/commit.js" "$SETUP/deps/node_modules" "$BATCH/input.json" > "$BATCH/sale_commitment.txt"
    proved="$("$NODE" -p "require('$BATCH/public.json')[0]")"
    if [ "$proved" != "$(cat "$BATCH/sale_commitment.txt")" ]; then
      echo "batch saleCommitment $proved != circomlibjs $(cat "$BATCH/sale_commitment.txt")"; exit 1
    fi
    echo "batch saleCommitment matches circomlibjs: $proved"
    ;;
  accounting16x4_hashed)
    "$NODE" "$ZK/groth16/commit.js" "$SETUP/deps/node_modules" "$BATCH/input.json" > "$BATCH/sale_commitment.txt"
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
    ;;
  signed_tree_16x4)
    "$NODE" "$ZK/signedtree/statement_signed_tree.js" "$SETUP/deps/node_modules" "$BATCH/input.json" > "$BATCH/statement.json"
    "$NODE" -p "require('$BATCH/statement.json').saleCommitment" > "$BATCH/sale_commitment.txt"
    "$NODE" -p "require('$BATCH/statement.json').escrowCommitment" > "$BATCH/escrow_commitment.txt"
    proved="$("$NODE" -p "require('$BATCH/public.json')[0]")"
    expected="$("$NODE" -p "require('$BATCH/statement.json').statementHash")"
    if [ "$proved" != "$expected" ]; then
      echo "batch statementHash $proved != circomlibjs $expected"; exit 1
    fi
    echo "batch statementHash matches circomlibjs: $proved"
    ;;
  owned_tree_pk_16x4)
    "$NODE" "$ZK/joinedtree/statement_joined_tree.js" "$SETUP/deps/node_modules" "$BATCH/input.json" > "$BATCH/statement.json"
    "$NODE" -p "require('$BATCH/statement.json').saleCommitment" > "$BATCH/sale_commitment.txt"
    "$NODE" -p "require('$BATCH/statement.json').escrowCommitment" > "$BATCH/escrow_commitment.txt"
    proved="$("$NODE" -p "require('$BATCH/public.json')[0]")"
    expected="$("$NODE" -p "require('$BATCH/statement.json').statementHash")"
    if [ "$proved" != "$expected" ]; then
      echo "batch statementHash $proved != circomlibjs $expected"; exit 1
    fi
    # The statement's last value is the window tree's root, which the opening publishes.
    last="$("$NODE" -p "const s = require('$BATCH/statement.json').statement; s[s.length - 1]")"
    published="$("$NODE" -p "require('$BATCH/opening.json').window_root")"
    if [ "$last" != "$published" ]; then
      echo "statement windowRoot $last != opening window_root $published"; exit 1
    fi
    echo "batch statementHash matches circomlibjs: $proved; windowRoot $last is the opening's"
    ;;
esac
