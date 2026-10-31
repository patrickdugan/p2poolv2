#!/usr/bin/env bash
# M1 end to end on a private Bitcoin Core regtest node.
#
# Usage: bash research/zk_clearing/bitvm/scripts/run-m1.sh <work dir> [scenario...]
#   default scenarios: honest tampered mismatch plus-r stall
#
# Expects prove-batch.sh and build.sh to have run with the same <work dir>, and bitcoind and
# bitcoin-cli on PATH (or BITCOIN_BIN=<dir>). Results land in <work>/m1/*.json.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(cd "${1:?usage: run-m1.sh <work dir> [scenario...]}" && pwd)"
shift
if [ $# -gt 0 ]; then SCENARIOS=("$@"); else SCENARIOS=(honest tampered mismatch plus-r stall); fi
BIN="$WORK/target/release"
BTC="${BITCOIN_BIN:+$BITCOIN_BIN/}"
DATADIR="$WORK/regtest"
export ZKC_RPC_URL="http://127.0.0.1:18743" ZKC_RPC_USER=zkc ZKC_RPC_PASS=zkc-m1-regtest ZKC_WALLET=m1
CLI=("${BTC}bitcoin-cli" -regtest -datadir="$DATADIR" -rpcport=18743 -rpcuser=zkc -rpcpassword=zkc-m1-regtest)

"${BIN}/zkc-convert" "$WORK/v1/verification_key.json" "$WORK/v1/proof.json" "$WORK/v1/public.json" "$WORK/m1-convert-example.json"
"${BIN}/zkc-convert" "$WORK/batch/verification_key.json" "$WORK/batch/proof.json" "$WORK/batch/public.json" "$WORK/m1-convert-batch.json"

/usr/bin/time -f "prepare: %e s, %M KiB max RSS" "${BIN}/zkc-m1" prepare "$WORK"

# A fresh chain each run, so heights in the traces are comparable.
"${CLI[@]}" stop >/dev/null 2>&1 && sleep 3 || true
rm -rf "$DATADIR"
mkdir -p "$DATADIR"
"${BTC}bitcoind" -regtest -datadir="$DATADIR" -daemon -txindex=1 -fallbackfee=0.0002 \
  -rpcport=18743 -port=18744 -rpcuser=zkc -rpcpassword=zkc-m1-regtest -rpcthreads=4 \
  -blockmaxweight=4000000 -listen=0
for _ in $(seq 60); do "${CLI[@]}" getblockcount >/dev/null 2>&1 && break; sleep 1; done
"${BTC}bitcoind" -version | head -1 > "$WORK/m1/node-version.txt"
"${CLI[@]}" createwallet m1 >/dev/null
"${CLI[@]}" -rpcwallet=m1 generatetoaddress 200 "$("${CLI[@]}" -rpcwallet=m1 getnewaddress)" >/dev/null

trap '"${CLI[@]}" stop >/dev/null 2>&1 || true' EXIT
for s in "${SCENARIOS[@]}"; do
  echo "== scenario $s"
  /usr/bin/time -f "scenario $s: %e s, %M KiB max RSS" "${BIN}/zkc-m1" scenario "$WORK" "$s"
done
echo "results: $WORK/m1"
