#!/usr/bin/env bash
# Dump a stopped P2Poolv2 node store with p2poolv2_cli for real_store.py.
#
# Usage: bash dump_store.sh <p2poolv2_cli binary> <node config> <store path> <dump dir>
# The config supplies the network, so the CLI prints each miner_address as a share address
# instead of witness-program hex. Writes <dump dir>/shares.json (the confirmed chain),
# share-<hash>.json for each confirmed share whose body the store holds, and pruned.txt with
# the heights whose bodies the node has pruned.
set -euo pipefail
CLI="$1"; CONFIG="$2"; STORE="$3"; OUT="$4"
mkdir -p "$OUT"
: > "$OUT/pruned.txt"
"$CLI" --config "$CONFIG" --db-path "$STORE" shares --num 4294967295 > "$OUT/shares.json"
python3 - "$OUT/shares.json" <<'PY' > "$OUT/hashes.txt"
import json, sys
for share in json.load(open(sys.argv[1]))["shares"]:
    print(share["blockhash"], share["height"])
PY
while read -r hash height; do
  if ! "$CLI" --config "$CONFIG" --db-path "$STORE" share --hash "$hash" --full \
      > "$OUT/share-$hash.json" 2> "$OUT/error.txt"; then
    grep -q "Full share not found" "$OUT/error.txt" || { cat "$OUT/error.txt" >&2; exit 1; }
    rm -f "$OUT/share-$hash.json"
    echo "$height" >> "$OUT/pruned.txt"
  fi
done < "$OUT/hashes.txt"
rm -f "$OUT/error.txt"
echo "dumped $(wc -l < "$OUT/hashes.txt") confirmed shares from $STORE, $(wc -l < "$OUT/pruned.txt") with pruned bodies"
