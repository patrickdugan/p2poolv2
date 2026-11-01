#!/usr/bin/env bash
# Constraint count of every part of signed_tree_<S>x<B>, each compiled as its own main with
# circom --O2, and the sum against the whole circuit.
#
# Usage: bash research/zk_clearing/signedtree/cost_split.sh <sale slots> <buyer slots> <node_modules dir> <work dir>
# <node_modules dir> is any directory holding circomlib (a run.sh build's deps/node_modules).
# SKIP_WHOLE=1 skips compiling the whole circuit and reports the sum of the parts.
set -euo pipefail
SALES="${1:?usage: cost_split.sh <sale slots> <buyer slots> <node_modules dir> <work dir>}"
BUYERS="${2:?}"
MODULES="${3:?}"
WORK="$(mkdir -p "${4:?}" && cd "$4" && pwd)"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUITS="$(dirname "$HERE")/circuits"
CIRCOM="${CIRCOM:-circom}"
DEPTH=0
while [ $((1 << DEPTH)) -lt "$SALES" ]; do DEPTH=$((DEPTH + 1)); done
[ $((1 << DEPTH)) -eq "$SALES" ] || { echo "sale slots must be a power of two"; exit 2; }
STATEMENT=$((4 + 4 * BUYERS))

count() { # count <name> <main component expression> <include...>: constraints of one part
  local name="$1" expr="$2"; shift 2
  {
    echo "pragma circom 2.1.8;"
    for file in "$@"; do echo "include \"$file\";"; done
    echo "component main = $expr;"
  } > "$WORK/$name.circom"
  if ! "$CIRCOM" "$WORK/$name.circom" --r1cs --O2 -l "$MODULES" -o "$WORK" > "$WORK/$name.log" 2>&1; then
    sed 's/\x1b\[[0-9;]*m//g' "$WORK/$name.log" >&2
    echo "circom failed on $name" >&2
    exit 1
  fi
  sed 's/\x1b\[[0-9;]*m//g' "$WORK/$name.log" \
    | awk -F': ' '/^non-linear constraints/ {n += $2} /^linear constraints/ {n += $2} END {print n}'
}

TREE_SIGNED="$CIRCUITS/clearing_tree_signed.circom"
POSEIDON="circomlib/circuits/poseidon.circom"
order=$(count part_order "SignedOrder()" "$TREE_SIGNED")
escrow=$(count part_escrow "SignedEscrow()" "$TREE_SIGNED")
amounts=$(count part_amounts "ClearingAmounts($SALES, $BUYERS)" "$CIRCUITS/clearing.circom")
saleleaf=$(count part_saleleaf "Poseidon(6)" "$POSEIDON")
tree=$(count part_tree "PoseidonTreeRoot($DEPTH)" "$CIRCUITS/clearing_tree.circom")
escrowleaf=$(count part_escrowleaf "Poseidon(5)" "$POSEIDON")
escrowroot=$(count part_escrowroot "PoseidonChunked($BUYERS)" "$TREE_SIGNED")
statement=$(count part_statement "PoseidonChunked($STATEMENT)" "$TREE_SIGNED")
height=$(count part_height "Bits51()" "$CIRCUITS/clearing.circom")
selected=$((SALES * BUYERS))

sum=$((SALES * order + BUYERS * escrow + amounts + SALES * saleleaf + tree + BUYERS * escrowleaf + escrowroot + statement + height + selected))
# SKIP_WHOLE=1 skips compiling the whole circuit (too large for the machine at 1,024 slots);
# the sum of parts is then the count, exact wherever the whole circuit was also compiled.
if [ "${SKIP_WHOLE:-0}" = 1 ]; then
  whole=$sum
  whole_label="whole circuit (not compiled; = sum of parts)"
else
  whole=$(count whole "SignedClearingTree($SALES, $BUYERS, $DEPTH, 0)" "$TREE_SIGNED")
  whole_label="whole circuit"
fi
sig=$((SALES * order + BUYERS * escrow))
rest=$((whole - sig))

printf 'signed_tree_%sx%s (depth %s)\n' "$SALES" "$BUYERS" "$DEPTH"
printf '%-46s %10s %8s %12s\n' part "each" count total
printf '%-46s %10s %8s %12s\n' "SignedOrder (signature part, per sale slot)" "$order" "$SALES" "$((SALES * order))"
printf '%-46s %10s %8s %12s\n' "SignedEscrow (signature part, per buyer slot)" "$escrow" "$BUYERS" "$((BUYERS * escrow))"
printf '%-46s %10s %8s %12s\n' "ClearingAmounts (arithmetic, ranges, selectors)" "$amounts" 1 "$amounts"
printf '%-46s %10s %8s %12s\n' "selected-buyer products (selector x buyerId)" 1 "$selected" "$selected"
printf '%-46s %10s %8s %12s\n' "sale leaf Poseidon(6)" "$saleleaf" "$SALES" "$((SALES * saleleaf))"
printf '%-46s %10s %8s %12s\n' "sale tree: $((SALES - 1)) x Poseidon(2)" "$tree" 1 "$tree"
printf '%-46s %10s %8s %12s\n' "escrow leaf Poseidon(5)" "$escrowleaf" "$BUYERS" "$((BUYERS * escrowleaf))"
printf '%-46s %10s %8s %12s\n' "escrow commitment PoseidonChunked($BUYERS)" "$escrowroot" 1 "$escrowroot"
printf '%-46s %10s %8s %12s\n' "statement hash PoseidonChunked($STATEMENT)" "$statement" 1 "$statement"
printf '%-46s %10s %8s %12s\n' "batchHeight Bits51" "$height" 1 "$height"
printf '%-46s %10s %8s %12s\n' "sum of parts" "" "" "$sum"
printf '%-46s %10s %8s %12s\n' "$whole_label" "" "" "$whole"
printf '%-46s %10s %8s %12s\n' "difference (whole - sum)" "" "" "$((whole - sum))"
printf 'signature part: %s (%s%% of the circuit); everything else: %s\n' "$sig" "$(awk -v s="$sig" -v w="$whole" 'BEGIN {printf "%.1f", 100 * s / w}')" "$rest"
printf 'per sale slot: signature part %s, everything else %s (whole circuit %s)\n' \
  "$order" "$(awk -v r="$rest" -v s="$SALES" 'BEGIN {printf "%.0f", r / s}')" \
  "$(awk -v w="$whole" -v s="$SALES" 'BEGIN {printf "%.0f", w / s}')"

# Inside one SignedOrder: the signature verifier, the two hashes, the curve checks and the
# expiry check. "other" is the zeroing rules for unused slots and the key-hash equality.
eddsa=$(count part_eddsa "EdDSAPoseidonVerifier()" "circomlib/circuits/eddsaposeidon.circom")
keyhash=$(count part_keyhash "Poseidon(2)" "$POSEIDON")
babycheck=$(count part_babycheck "BabyCheck()" "circomlib/circuits/babyjub.circom")
expiry=$(count part_expiry "AtMostHeight()" "$CIRCUITS/signed_terms.circom")
printf 'inside one SignedOrder (%s): EdDSAPoseidonVerifier %s, message Poseidon(6) %s, key hash Poseidon(2) %s, 2 x BabyCheck %s, expiry check %s, other %s\n' \
  "$order" "$eddsa" "$saleleaf" "$keyhash" "$((2 * babycheck))" "$expiry" \
  "$((order - eddsa - saleleaf - keyhash - 2 * babycheck - expiry))"
