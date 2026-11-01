#!/usr/bin/env bash
# One joined signed-tree circuit end to end through groth16/run.sh, then the checks that belong
# to the join: padding, the extra valid inputs, and where each invalid input is refused.
#
# Usage: bash research/zk_clearing/joinedtree/run_size.sh <bin|r8|smt> <sale slots> <buyer slots> <build dir>
#   bin  the dense binary window tree, 17 levels       (OwnedSignedTreeWindow(.., 1, 17))
#   r8   the dense eight-way window tree, 6 levels     (OwnedSignedTreeWindow(.., 3, 6))
#   smt  M5's 40-level sparse Merkle tree              (OwnedSignedTreeSmt(.., 40))
# Environment: PTAU=<prepared phase-1 file>, POWER (default 20). circom 2.2.2, Node, python3 and
# GNU time must be on PATH, as for groth16/run.sh. The setup is the INSECURE deterministic one.
set -euo pipefail
KIND="${1:?usage: run_size.sh <bin|r8|smt> <sale slots> <buyer slots> <build dir>}"
SALES="${2:?}"
BUYERS="${3:?}"
BUILD="${4:?}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZK="$(dirname "$HERE")"
NODE="${NODE:-node}"
CIRCUIT="owned_tree_${KIND}_${SALES}x${BUYERS}"
case "$KIND" in
  bin) export MEMBERSHIP=window RADIX_BITS=1 ;;
  r8) export MEMBERSHIP=window RADIX_BITS=3 ;;
  smt) export MEMBERSHIP=smt RADIX_BITS=1 ;;
  *) echo "kind must be bin, r8 or smt"; exit 2 ;;
esac

status=0
# SKIP_RUN=1 repeats only the join's checks on a finished build directory.
if [ "${SKIP_RUN:-0}" != 1 ]; then
  SCALE_SALES="$SALES" SCALE_BUYERS="$BUYERS" POWER="${POWER:-20}" PTAU="${PTAU:-}" \
  CIRCUIT_DIR="$HERE/circuits" \
  FIXTURES="$HERE/fixtures.sh" \
  STATEMENT_JS="$HERE/statement_joined_tree.js" \
    bash "$ZK/groth16/run.sh" "$CIRCUIT" "$BUILD" || status=$?
fi

BUILD="$(cd "$BUILD" && pwd)"
SNARKJS=("$NODE" "$BUILD/deps/node_modules/snarkjs/build/cli.cjs")
WITNESS_JS=("$NODE" "$BUILD/${CIRCUIT}_js/generate_witness.js" "$BUILD/${CIRCUIT}_js/$CIRCUIT.wasm")
JOINED="$BUILD/joined-checks.txt"
: > "$JOINED"

echo "== padded batch (padding slots, padding-key signatures): witness must satisfy the R1CS"
if "${WITNESS_JS[@]}" "$BUILD/inputs/padded.json" "$BUILD/padded.wtns" > "$BUILD/padded.log" 2>&1 \
   && "${SNARKJS[@]}" wtns check "$BUILD/$CIRCUIT.r1cs" "$BUILD/padded.wtns" 2>&1 | grep -q "WITNESS IS CORRECT"; then
  echo "padded batch: witness satisfies the R1CS" | tee -a "$JOINED"
else
  echo "padded batch: REFUSED (bad): $(tail -1 "$BUILD/padded.log")" | tee -a "$JOINED"; status=1
fi

echo "== extra valid inputs"
for input in "$BUILD"/inputs/valid_*.json; do
  [ -e "$input" ] || continue
  name="$(basename "$input" .json)"
  if "${WITNESS_JS[@]}" "$input" "$BUILD/$name.wtns" > "$BUILD/$name.log" 2>&1 \
     && "${SNARKJS[@]}" wtns check "$BUILD/$CIRCUIT.r1cs" "$BUILD/$name.wtns" 2>&1 | grep -q "WITNESS IS CORRECT"; then
    echo "accepted $name (R1CS satisfied)" | tee -a "$JOINED"
  else
    echo "REFUSED (bad) $name: $(tail -1 "$BUILD/$name.log")" | tee -a "$JOINED"; status=1
  fi
done

echo "== the statement carries the ownership root"
expected="$("$NODE" -p "require('$BUILD/inputs/work/world.json').root")"
carried="$("$NODE" -p "require('$BUILD/statement.json').ownershipRoot")"
count="$("$NODE" -p "require('$BUILD/statement.json').statement.length")"
if [ "$carried" = "$expected" ] && [ "$count" = "$((5 + 4 * BUYERS))" ]; then
  echo "statement has $count values and its last is the tree's root: $carried" | tee -a "$JOINED"
else
  echo "statement root $carried or length $count does not match the world (root $expected) (bad)" | tee -a "$JOINED"; status=1
fi

echo "== where each invalid input is refused"
# The witness calculator's error names a chain of templates, innermost first. Skipping circomlib's
# helpers (ForceEqualIfEnabled, Num2Bits, ...), the first template of the join or of the signed
# tree must be the one the manifest names.
KNOWN=" WindowSale WindowLevel WindowOrder SMTVerifier OwnedSale EdDSAPoseidonVerifier SignedOrder SignedEscrow SignedClearingTree "
rm -f "$BUILD/.refusal-bad"
"$NODE" -e "
  const manifest = require('$BUILD/inputs/work/variants/manifest.json');
  for (const v of manifest) if (v.kind === 'invalid') console.log(v.name + ' ' + v.rejectedIn + ' ' + JSON.stringify(v.predicted));" \
  | while read -r name want predicted; do
  # The pure-Python model of the membership and order rules predicts the same template (or none,
  # for the signature and statement-hash inputs, which it does not model).
  case "$want" in
    WindowSale|WindowLevel|WindowOrder|SMTVerifier) model="[\"$want\"]" ;;
    *) model="[]" ;;
  esac
  if [ "$predicted" != "$model" ]; then
    echo "$name: the Python model predicts $predicted, expected $model (bad)" | tee -a "$JOINED"; echo bad >> "$BUILD/.refusal-bad"
  fi
  log="$BUILD/invalid-$name.log"
  chain="$(grep -o 'Error in template [A-Za-z0-9]*' "$log" | sed 's/Error in template //; s/_[0-9]*$//' | awk '!seen[$0]++' | paste -sd'<' - | sed 's/</ < /g')"
  first=""
  for template in ${chain//</ }; do
    case "$KNOWN" in *" $template "*) first="$template"; break ;; esac
  done
  [ "$first" = "$want" ] && ok=1 || ok=0
  if [ "$ok" = 1 ]; then
    echo "$name: refused in $want ($chain)" | tee -a "$JOINED"
  else
    echo "$name: NOT refused in $want ($chain) (bad)" | tee -a "$JOINED"; echo bad >> "$BUILD/.refusal-bad"
  fi
done
[ ! -e "$BUILD/.refusal-bad" ] || status=1

{ echo; echo "checks specific to the join:"; sed 's/^/  /' "$JOINED"; } >> "$BUILD/results.txt"
exit $status
