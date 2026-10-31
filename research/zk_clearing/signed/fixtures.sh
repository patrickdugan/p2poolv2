#!/usr/bin/env bash
# Fixtures for clearing16x4_signed.circom, called by groth16/run.sh through
# FIXTURES=... with <out dir> <node_modules dir>.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$1"
MODULES="$2"
mkdir -p "$OUT"
python3 "$HERE/make_batch.py" valid > "$OUT/valid.spec.json"
python3 "$HERE/make_batch.py" resplit > "$OUT/resplit.spec.json"
node "$HERE/sign.js" "$MODULES" "$OUT/valid.spec.json" "$OUT/resplit.spec.json" "$OUT"
