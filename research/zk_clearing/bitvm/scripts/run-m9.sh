#!/usr/bin/env bash
# M9 end to end on a private Bitcoin Core regtest node: fee bumping in the optimistic graph.
#
# Usage: bash research/zk_clearing/bitvm/scripts/run-m9.sh <work dir> fee|spike [scenario...]
#   fee    the anchored graph at the presigned FEE_RATE, on a node with default policy.
#          Default scenarios: unchallenged challenged tampered silent incomplete stall
#   spike  a market at SPIKE sat/vB (default 10, the graph's MAX_FEE_RATE): the node runs with
#          -blockmintxfee at that rate, so blocks take only packages paying it. `unchallenged`
#          and `challenged` (default) for the anchored graph, then for the M2 graph. The
#          challenger's BitVM validation is skipped (ZKC_VALIDATE=0); the fee run covers it.
#
# Expects build.sh and `zkc-m1 prepare` to have run with the same <work dir> (M2's setup), and
# bitcoind and bitcoin-cli on PATH (or BITCOIN_BIN=<dir>). Results land in <work>/m9/<graph>-<rate>.
set -euo pipefail

WORK="$(cd "${1:?usage: run-m9.sh <work dir> fee|spike [scenario...]}" && pwd)"
MODE="${2:?usage: run-m9.sh <work dir> fee|spike [scenario...]}"
shift 2
SPIKE="${SPIKE:-10}"
BIN="$WORK/target/release"
BTC="${BITCOIN_BIN:+$BITCOIN_BIN/}"
DATADIR="$WORK/regtest-m9"
export ZKC_RPC_URL="http://127.0.0.1:18763" ZKC_RPC_USER=zkc ZKC_RPC_PASS=zkc-m9-regtest ZKC_WALLET=m9
CLI=("${BTC}bitcoin-cli" -regtest -datadir="$DATADIR" -rpcport=18763 -rpcuser=zkc -rpcpassword=zkc-m9-regtest)

case "$MODE" in
  fee) RATE=2; POLICY=(); GRAPHS=(anchored); DEFAULT=(unchallenged challenged tampered silent incomplete stall) ;;
  spike) RATE="$SPIKE"; POLICY=(-blockmintxfee="$(printf '0.%08d' $((SPIKE * 1000)))"); GRAPHS=(anchored m2); DEFAULT=(unchallenged challenged); export ZKC_VALIDATE=0 ;;
  *) echo "mode must be fee or spike"; exit 2 ;;
esac
if [ $# -gt 0 ]; then SCENARIOS=("$@"); else SCENARIOS=("${DEFAULT[@]}"); fi
for f in partial/done assertions-honest.json assertions-tampered.json; do
  [ -e "$WORK/m1/$f" ] || { echo "missing $WORK/m1/$f: run zkc-m1 prepare $WORK first"; exit 2; }
done

# A fresh chain each run, so heights in the traces are comparable.
"${CLI[@]}" stop >/dev/null 2>&1 && sleep 3 || true
rm -rf "$DATADIR"
mkdir -p "$DATADIR"
"${BTC}bitcoind" -regtest -datadir="$DATADIR" -daemon -txindex=1 -fallbackfee=0.0002 \
  -rpcport=18763 -port=18764 -rpcuser=zkc -rpcpassword=zkc-m9-regtest -rpcthreads=4 \
  -blockmaxweight=4000000 -listen=0 "${POLICY[@]}"
for _ in $(seq 60); do "${CLI[@]}" getblockcount >/dev/null 2>&1 && break; sleep 1; done
trap '"${CLI[@]}" stop >/dev/null 2>&1 || true' EXIT
"${CLI[@]}" createwallet m9 >/dev/null
"${CLI[@]}" -rpcwallet=m9 generatetoaddress 200 "$("${CLI[@]}" -rpcwallet=m9 getnewaddress)" >/dev/null

for graph in "${GRAPHS[@]}"; do
  out="$WORK/m9/$graph-$RATE"
  mkdir -p "$out"
  "${BTC}bitcoind" -version | head -1 > "$out/node-version.txt"
  echo "policy: ${POLICY[*]:-default}" >> "$out/node-version.txt"
  for s in "${SCENARIOS[@]}"; do
    echo "== $graph at $RATE sat/vB: scenario $s"
    ZKC_GRAPH="$graph" ZKC_MARKET_FEE_RATE="$RATE" \
      /usr/bin/time -f "scenario $graph-$RATE $s: %e s, %M KiB max RSS" "${BIN}/zkc-m2" scenario "$WORK" "$s"
  done
done
echo "results: $WORK/m9"
