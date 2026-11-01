#!/usr/bin/env bash
# One size of the signed tree circuit, end to end through groth16/run.sh, then the padding
# check.
#
# Usage: bash research/zk_clearing/signedtree/run_size.sh <sale slots> <buyer slots> <build dir>
# Environment: PTAU=<prepared phase-1 file>, POWER (default 20). circom 2.2.2, Node and
# GNU time must be on PATH, as for run.sh.
set -euo pipefail
SALES="${1:?usage: run_size.sh <sale slots> <buyer slots> <build dir>}"
BUYERS="${2:?}"
BUILD="${3:?}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZK="$(dirname "$HERE")"
CIRCUIT="signed_tree_${SALES}x${BUYERS}"

SCALE_SALES="$SALES" SCALE_BUYERS="$BUYERS" POWER="${POWER:-20}" PTAU="${PTAU:-}" \
CIRCUIT_DIR="$HERE/circuits" \
FIXTURES="$HERE/fixtures.sh" \
STATEMENT_JS="$HERE/statement_signed_tree.js" \
  bash "$ZK/groth16/run.sh" "$CIRCUIT" "$BUILD"

bash "$HERE/check_padded.sh" "$BUILD" "$CIRCUIT"
