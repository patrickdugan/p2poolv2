#!/usr/bin/env bash
# M2 end to end on a private Bitcoin Core regtest node: the optimistic graph's scenarios.
#
# Usage: bash research/zk_clearing/bitvm/scripts/run-m2.sh <work dir> [scenario...]
#   default scenarios: unchallenged challenged tampered silent incomplete stall
#
# Expects prove-batch.sh and build.sh to have run with the same <work dir>, and bitcoind and
# bitcoin-cli on PATH (or BITCOIN_BIN=<dir>). M2 reuses the disprove scripts and assertions that
# `zkc-m1 prepare` caches under <work>/m1, running it first if they are missing. Results land in
# <work>/m2/*.json.
set -euo pipefail

WORK="$(cd "${1:?usage: run-m2.sh <work dir> [scenario...]}" && pwd)"
shift
if [ $# -gt 0 ]; then SCENARIOS=("$@"); else SCENARIOS=(unchallenged challenged tampered silent incomplete stall); fi
BIN="$WORK/target/release"
BTC="${BITCOIN_BIN:+$BITCOIN_BIN/}"
DATADIR="$WORK/regtest-m2"
export ZKC_RPC_URL="http://127.0.0.1:18743" ZKC_RPC_USER=zkc ZKC_RPC_PASS=zkc-m1-regtest ZKC_WALLET=m2
CLI=("${BTC}bitcoin-cli" -regtest -datadir="$DATADIR" -rpcport=18743 -rpcuser=zkc -rpcpassword=zkc-m1-regtest)

if [ ! -f "$WORK/m1/partial/done" ] || [ ! -f "$WORK/m1/assertions-honest.json" ] || [ ! -f "$WORK/m1/assertions-tampered.json" ]; then
  /usr/bin/time -f "prepare: %e s, %M KiB max RSS" "${BIN}/zkc-m1" prepare "$WORK"
fi
mkdir -p "$WORK/m2"
"${BIN}/zkc-m2" timing > "$WORK/m2/timing.json"

# A fresh chain each run, so heights in the traces are comparable.
"${CLI[@]}" stop >/dev/null 2>&1 && sleep 3 || true
rm -rf "$DATADIR"
mkdir -p "$DATADIR"
"${BTC}bitcoind" -regtest -datadir="$DATADIR" -daemon -txindex=1 -fallbackfee=0.0002 \
  -rpcport=18743 -port=18744 -rpcuser=zkc -rpcpassword=zkc-m1-regtest -rpcthreads=4 \
  -blockmaxweight=4000000 -listen=0
for _ in $(seq 60); do "${CLI[@]}" getblockcount >/dev/null 2>&1 && break; sleep 1; done
"${BTC}bitcoind" -version | head -1 > "$WORK/m2/node-version.txt"
"${CLI[@]}" createwallet m2 >/dev/null
"${CLI[@]}" -rpcwallet=m2 generatetoaddress 200 "$("${CLI[@]}" -rpcwallet=m2 getnewaddress)" >/dev/null

trap '"${CLI[@]}" stop >/dev/null 2>&1 || true' EXIT
for s in "${SCENARIOS[@]}"; do
  echo "== scenario $s"
  /usr/bin/time -f "scenario $s: %e s, %M KiB max RSS" "${BIN}/zkc-m2" scenario "$WORK" "$s"
done
echo "results: $WORK/m2"
