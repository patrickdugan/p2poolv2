#!/usr/bin/env bash
# Fixtures for the joined signed-tree circuits, called by groth16/run.sh through FIXTURES=...
# with <out dir> <node_modules dir>. Environment: SCALE_SALES, SCALE_BUYERS, MEMBERSHIP
# (window | smt) and RADIX_BITS (1 | 3, window only).
#
# 1. make_joined_tree.py names the order keys the world needs.
# 2. joined/sign_joined.js turns the names into key hashes (BabyJubjub, circomlibjs).
# 3. make_joined_tree.py builds the registry, the sharechain, both trees and one batch spec with
#    its membership witness per variant.
# 4. sign_tree.js signs the specs and writes valid.json, resplit.json, padded.json,
#    valid_<name>.json and invalid/*.json. The working files stay in <out dir>/work.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$1"
MODULES="$2"
WORK="$OUT/work"
mkdir -p "$OUT" "$WORK"
python3 "$HERE/make_joined_tree.py" labels > "$WORK/labels.json"
node "$HERE/../joined/sign_joined.js" keyhashes "$MODULES" "$WORK/labels.json" > "$WORK/keyhashes.json"
python3 "$HERE/make_joined_tree.py" build "$WORK/keyhashes.json" "$WORK" \
  --sales "${SCALE_SALES:?}" --buyers "${SCALE_BUYERS:?}" --membership "${MEMBERSHIP:?}" --radix-bits "${RADIX_BITS:-1}"
node "$HERE/sign_tree.js" sign "$MODULES" "$WORK/variants" "$OUT"
