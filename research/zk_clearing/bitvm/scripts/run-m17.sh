#!/usr/bin/env bash
# M17: M15's packed joined statement (owned_tree_pk_16x4) through M14's one-public-input BitVM
# pipeline, on M13's bound graph with M9's anchors, on a private Bitcoin Core regtest node.
#
# Usage: bash research/zk_clearing/bitvm/scripts/run-m17.sh <work dir> [scenario...]
#   default scenarios: unchallenged challenged tampered late stall
#
# Expects, with the same <work dir>:
#   prove-batch.sh <work dir> owned_tree_pk_16x4   the setup, the batch and its proof
#   ZKC_PUBS=1 build.sh <work dir>                  the one-public-input build
#   zkc-m1 prepare <work dir>                       the disprove scripts and assertions for this key
# and bitcoind and bitcoin-cli on PATH (or BITCOIN_BIN=<dir>).
#
# Each scenario gets a fresh regtest chain at height 200: the batch's batchHeight (230) was fixed
# when the proof was made, so the driver mines up to batchHeight - 3 before it funds the escrows,
# which a chain that an earlier scenario advanced could no longer do. The graph is anchored
# (ZKC_GRAPH=anchored) and bound (ZKC_BIND_HEIGHT=1) at the presigned 2 sat/vB on a default node.
# RPC port ZKC_RPC_PORT (default 18813). Results land in <work>/m17.
set -euo pipefail

WORK="$(cd "${1:?usage: run-m17.sh <work dir> [scenario...]}" && pwd)"
shift
if [ $# -gt 0 ]; then SCENARIOS=("$@"); else SCENARIOS=(unchallenged challenged tampered late stall); fi
BIN="$WORK/target/release"
BTC="${BITCOIN_BIN:+$BITCOIN_BIN/}"
DATADIR="$WORK/regtest-m17"
PORT="${ZKC_RPC_PORT:-18813}"
export ZKC_RPC_URL="http://127.0.0.1:$PORT" ZKC_RPC_USER=zkc ZKC_RPC_PASS=zkc-m17-regtest ZKC_WALLET=m17
export ZKC_GRAPH=anchored ZKC_BIND_HEIGHT=1 ZKC_MARKET_FEE_RATE=2
CLI=("${BTC}bitcoin-cli" -regtest -datadir="$DATADIR" -rpcport="$PORT" -rpcuser=zkc -rpcpassword=zkc-m17-regtest)
NODE_ARGS=(-regtest -datadir="$DATADIR" -daemon -txindex=1 -fallbackfee=0.0005 -rpcport="$PORT" -port="$((PORT + 1))"
  -rpcuser=zkc -rpcpassword=zkc-m17-regtest -rpcthreads=4 -blockmaxweight=4000000 -listen=0)

[ "$(cat "$WORK/batch/circuit.txt")" = owned_tree_pk_16x4 ] || { echo "$WORK/batch is not an owned_tree_pk_16x4 batch"; exit 2; }
for f in partial/done assertions-honest.json assertions-tampered.json; do
  [ -e "$WORK/m1/$f" ] || { echo "missing $WORK/m1/$f: run zkc-m1 prepare $WORK first"; exit 2; }
done

mkdir -p "$WORK/m17"
trap '"${CLI[@]}" stop >/dev/null 2>&1 || true' EXIT
for s in "${SCENARIOS[@]}"; do
  "${CLI[@]}" stop >/dev/null 2>&1 && sleep 3 || true
  rm -rf "$DATADIR"
  mkdir -p "$DATADIR"
  "${BTC}bitcoind" "${NODE_ARGS[@]}"
  for _ in $(seq 60); do "${CLI[@]}" getblockcount >/dev/null 2>&1 && break; sleep 1; done
  "${CLI[@]}" createwallet m17 >/dev/null
  "${CLI[@]}" -rpcwallet=m17 generatetoaddress 200 "$("${CLI[@]}" -rpcwallet=m17 getnewaddress)" >/dev/null
  echo "== anchored, bound, owned_tree_pk_16x4: scenario $s (height $("${CLI[@]}" getblockcount))"
  /usr/bin/time -f "scenario $s: %e s, %M KiB max RSS" "${BIN}/zkc-m2" scenario "$WORK" "$s" 2>&1 | tee "$WORK/m17/$s.log"
  cp "$WORK/m13/anchored-2-bound/scenario-$s.json" "$WORK/m17/"
done
"${BTC}bitcoind" -version | head -1 > "$WORK/m17/node-version.txt"
echo "policy: default node, -blockmaxweight=4000000" >> "$WORK/m17/node-version.txt"
echo "results: $WORK/m17"
