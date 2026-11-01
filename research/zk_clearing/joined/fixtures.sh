#!/usr/bin/env bash
# Fixtures for clearing16x4_owned.circom, called by groth16/run.sh through
# FIXTURES=... with <out dir> <node_modules dir>.
#
# 1. make_joined.py names the order keys the world needs.
# 2. sign_joined.js turns the names into key hashes (BabyJubjub, circomlibjs).
# 3. make_joined.py builds the registry, the sharechain, the two trees (before and after Alice
#    rotates her order key) and one batch spec with its ownership witness per variant.
# 4. sign_joined.js signs the specs and writes valid.json, resplit.json, valid_rotated.json and
#    invalid/*.json. The working files stay in <out dir>/work.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$1"
MODULES="$2"
WORK="$OUT/work"
mkdir -p "$OUT" "$WORK"
python3 "$HERE/make_joined.py" labels > "$WORK/labels.json"
node "$HERE/sign_joined.js" keyhashes "$MODULES" "$WORK/labels.json" > "$WORK/keyhashes.json"
python3 "$HERE/make_joined.py" build "$WORK/keyhashes.json" "$WORK"
node "$HERE/sign_joined.js" sign "$MODULES" "$WORK/variants" "$OUT"
