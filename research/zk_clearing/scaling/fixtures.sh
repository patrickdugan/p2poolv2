#!/usr/bin/env bash
# FIXTURES hook for groth16/run.sh: <out dir> <node_modules dir>.
# The batch size comes from SCALE_SALES and SCALE_BUYERS.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$HERE/gen_inputs.py" "$1" "${SCALE_SALES:?}" "${SCALE_BUYERS:?}"
