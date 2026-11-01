#!/usr/bin/env bash
# FIXTURES hook for groth16/run.sh: <out dir> <node_modules dir>.
# The batch size comes from SCALE_SALES and SCALE_BUYERS.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$1"
MODULES="$2"
mkdir -p "$OUT"
for variant in valid resplit padded; do
  python3 "$HERE/gen_batch.py" "$variant" "${SCALE_SALES:?}" "${SCALE_BUYERS:?}" > "$OUT/$variant.spec.json"
done
node "$HERE/sign.js" "$MODULES" "$OUT" "$OUT/valid.spec.json" "$OUT/resplit.spec.json" "$OUT/padded.spec.json"
