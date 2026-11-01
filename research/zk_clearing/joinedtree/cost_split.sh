#!/usr/bin/env bash
# Constraint count of every part of the joined signed-tree circuits, each compiled as its own main
# with circom --O2 (compile only, nothing is proved), and the sum of the parts per membership
# kind. Optional WHOLE_BIN, WHOLE_R8 and WHOLE_SMT give the compiled whole circuit's count (from a
# run_size.sh results file) and the script prints the difference.
#
# Usage: bash research/zk_clearing/joinedtree/cost_split.sh <sale slots> <buyer slots> <node_modules dir> <work dir>
# <node_modules dir> is any directory holding circomlib (a run.sh build's deps/node_modules).
set -euo pipefail
SALES="${1:?usage: cost_split.sh <sale slots> <buyer slots> <node_modules dir> <work dir>}"
BUYERS="${2:?}"
MODULES="${3:?}"
WORK="$(mkdir -p "${4:?}" && cd "$4" && pwd)"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUITS="$(dirname "$HERE")/circuits"
OWNERSHIP="$(dirname "$HERE")/ownership/circuits"
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
  local attempt
  for attempt in 1 2 3 4 5 6; do # circom panics with SystemTimeError when the VM clock steps back
    "$CIRCOM" "$WORK/$name.circom" --r1cs --O2 -l "$MODULES" -o "$WORK" > "$WORK/$name.log" 2>&1 && break
    grep -q SystemTimeError "$WORK/$name.log" || { sed 's/\x1b\[[0-9;]*m//g' "$WORK/$name.log" >&2; echo "circom failed on $name" >&2; exit 1; }
    sleep 2
  done
  sed 's/\x1b\[[0-9;]*m//g' "$WORK/$name.log" \
    | awk -F': ' '/^non-linear constraints/ {n += $2} /^linear constraints/ {n += $2} END {print n}'
}

POSEIDON="circomlib/circuits/poseidon.circom"
base=$(count part_base "SignedClearingTree($SALES, $BUYERS, $DEPTH, 0)" "$CIRCUITS/clearing_tree_signed.circom")
statement4=$(count part_statement4 "PoseidonChunked($STATEMENT)" "$CIRCUITS/clearing_tree_signed.circom")
statement5=$(count part_statement5 "PoseidonChunked($((STATEMENT + 1)))" "$CIRCUITS/clearing_tree_signed.circom")
sale_bin=$(count part_sale_bin "WindowSale(1, 17)" "$OWNERSHIP/window_sale.circom")
sale_r8=$(count part_sale_r8 "WindowSale(3, 6)" "$OWNERSHIP/window_sale.circom")
sale_smt=$(count part_sale_smt "OwnedSale(40)" "$OWNERSHIP/owned_sale.circom")
order_bin=$(count part_order_bin "WindowOrder(17)" "$OWNERSHIP/window_sale.circom")
order_r8=$(count part_order_r8 "WindowOrder(18)" "$OWNERSHIP/window_sale.circom")
level_bin=$(count part_level_bin "WindowLevel(1)" "$OWNERSHIP/window_sale.circom")
level_r8=$(count part_level_r8 "WindowLevel(3)" "$OWNERSHIP/window_sale.circom")
leaf4=$(count part_leaf4 "Poseidon(4)" "$POSEIDON")
node2=$(count part_node2 "Poseidon(2)" "$POSEIDON")
node8=$(count part_node8 "Poseidon(8)" "$POSEIDON")
digits_bin=$(count part_digits_bin "Num2Bits(17)" "circomlib/circuits/bitify.circom")
digits_r8=$(count part_digits_r8 "Num2Bits(18)" "circomlib/circuits/bitify.circom")

overhead=$((statement5 - statement4))
sum_bin=$((base + SALES * sale_bin + (SALES - 1) * order_bin + overhead))
sum_r8=$((base + SALES * sale_r8 + (SALES - 1) * order_r8 + overhead))
sum_smt=$((base + SALES * sale_smt + overhead))

printf 'joined signed tree %sx%s (depth %s), compile-only parts\n' "$SALES" "$BUYERS" "$DEPTH"
printf '%-58s %10s\n' part constraints
printf '%-58s %10s\n' "SignedClearingTree($SALES, $BUYERS, $DEPTH, 0): M11's whole circuit" "$base"
printf '%-58s %10s\n' "statement hash over $STATEMENT values (M11)" "$statement4"
printf '%-58s %10s\n' "statement hash over $((STATEMENT + 1)) values (root appended)" "$statement5"
printf '%-58s %10s\n' "  the root's cost in the statement hash" "$overhead"
printf '%-58s %10s\n' "WindowSale, binary, 17 levels (per sale slot)" "$sale_bin"
printf '%-58s %10s\n' "  one WindowLevel(1): Poseidon(2) $node2 + 1 select" "$level_bin"
printf '%-58s %10s\n' "  17 digit bits, Num2Bits(17)" "$digits_bin"
printf '%-58s %10s\n' "  leaf Poseidon(4)" "$leaf4"
printf '%-58s %10s\n' "WindowSale, eight-way, 6 levels (per sale slot)" "$sale_r8"
printf '%-58s %10s\n' "  one WindowLevel(3): Poseidon(8) $node8 + 7 selects" "$level_r8"
printf '%-58s %10s\n' "  18 digit bits, Num2Bits(18)" "$digits_r8"
printf '%-58s %10s\n' "OwnedSale(40): M5's SMTVerifier (per sale slot)" "$sale_smt"
printf '%-58s %10s\n' "WindowOrder(17), per neighbouring pair" "$order_bin"
printf '%-58s %10s\n' "WindowOrder(18), per neighbouring pair" "$order_r8"
printf '%-58s %10s\n' "sum, binary window: base + S x sale + (S-1) x order + root" "$sum_bin"
printf '%-58s %10s\n' "sum, eight-way window" "$sum_r8"
printf '%-58s %10s\n' "sum, M5's sparse tree" "$sum_smt"
for kind in BIN R8 SMT; do
  var="WHOLE_$kind"
  if [ -n "${!var:-}" ]; then
    case "$kind" in BIN) sum=$sum_bin ;; R8) sum=$sum_r8 ;; SMT) sum=$sum_smt ;; esac
    printf '%-58s %10s\n' "compiled whole circuit ($kind) minus sum of parts" "$((${!var} - sum))"
  fi
done
