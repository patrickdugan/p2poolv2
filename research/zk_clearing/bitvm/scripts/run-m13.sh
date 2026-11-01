#!/usr/bin/env bash
# M13 on a private Bitcoin Core regtest node, on the anchored graph of M9.
#
# Usage: bash research/zk_clearing/bitvm/scripts/run-m13.sh <work dir> rise|bound [scenario...]
#   rise   `challenged` in a market at SPIKE sat/vB (default 10) that rises to RISE sat/vB
#          (default 20) after assert_init's CPFP child is posted. The scenario restarts the node
#          with the higher -blockmintxfee through the restart script this file writes; the
#          mempool is saved at shutdown and loaded at start. BitVM validation is skipped.
#   bound  the kickoff's lock time is the statement's batchHeight, it spends a deadline
#          connector anyone may sweep after batchHeight + 4, and the escrows refund through CLTV
#          at an absolute expiry; at the presigned 2 sat/vB on a default node. Default
#          scenarios: unchallenged silent stall late
#
# Expects build.sh and `zkc-m1 prepare` to have run with the same <work dir>, as for run-m9.sh,
# and bitcoind and bitcoin-cli on PATH (or BITCOIN_BIN=<dir>). Results land in <work>/m13.
set -euo pipefail

WORK="$(cd "${1:?usage: run-m13.sh <work dir> rise|bound [scenario...]}" && pwd)"
MODE="${2:?usage: run-m13.sh <work dir> rise|bound [scenario...]}"
shift 2
SPIKE="${SPIKE:-10}"
RISE="${RISE:-20}"
BIN="$WORK/target/release"
BTC="${BITCOIN_BIN:+$BITCOIN_BIN/}"
DATADIR="$WORK/regtest-m13"
export ZKC_RPC_URL="http://127.0.0.1:18793" ZKC_RPC_USER=zkc ZKC_RPC_PASS=zkc-m13-regtest ZKC_WALLET=m13
CLI=("${BTC}bitcoin-cli" -regtest -datadir="$DATADIR" -rpcport=18793 -rpcuser=zkc -rpcpassword=zkc-m13-regtest)
NODE_ARGS=(-regtest -datadir="$DATADIR" -daemon -txindex=1 -fallbackfee=0.0005 -rpcport=18793 -port=18794
  -rpcuser=zkc -rpcpassword=zkc-m13-regtest -rpcthreads=4 -blockmaxweight=4000000 -listen=0)
feerate() { printf '0.%08d' $(($1 * 1000)); }

case "$MODE" in
  rise) RATE="$SPIKE"; POLICY=(-blockmintxfee="$(feerate "$SPIKE")"); DEFAULT=(challenged)
        export ZKC_VALIDATE=0 ZKC_RISE_TO="$RISE" ZKC_RESTART_CMD="$WORK/restart-m13.sh" ;;
  bound) RATE=2; POLICY=(); DEFAULT=(unchallenged silent stall late); export ZKC_BIND_HEIGHT=1 ;;
  *) echo "mode must be rise or bound"; exit 2 ;;
esac
if [ $# -gt 0 ]; then SCENARIOS=("$@"); else SCENARIOS=("${DEFAULT[@]}"); fi
for f in partial/done assertions-honest.json assertions-tampered.json; do
  [ -e "$WORK/m1/$f" ] || { echo "missing $WORK/m1/$f: run zkc-m1 prepare $WORK first"; exit 2; }
done

# The restart a rising market uses: stop, wait for the process to exit, start with the new
# -blockmintxfee and the wallet loaded.
cat > "$WORK/restart-m13.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
${CLI[*]} stop >/dev/null
for _ in \$(seq 60); do pgrep -f "bitcoind -regtest -datadir=$DATADIR" >/dev/null || break; sleep 1; done
${BTC}bitcoind ${NODE_ARGS[*]} -wallet=m13 -blockmintxfee=\$(printf '0.%08d' \$((\$1 * 1000))) >/dev/null
EOF

"${CLI[@]}" stop >/dev/null 2>&1 && sleep 3 || true
rm -rf "$DATADIR"
mkdir -p "$DATADIR"
"${BTC}bitcoind" "${NODE_ARGS[@]}" "${POLICY[@]}"
for _ in $(seq 60); do "${CLI[@]}" getblockcount >/dev/null 2>&1 && break; sleep 1; done
trap '"${CLI[@]}" stop >/dev/null 2>&1 || true' EXIT
"${CLI[@]}" createwallet m13 >/dev/null
"${CLI[@]}" -rpcwallet=m13 generatetoaddress 200 "$("${CLI[@]}" -rpcwallet=m13 getnewaddress)" >/dev/null

for s in "${SCENARIOS[@]}"; do
  echo "== anchored at $RATE sat/vB, $MODE: scenario $s"
  ZKC_GRAPH=anchored ZKC_MARKET_FEE_RATE="$RATE" \
    /usr/bin/time -f "scenario $MODE $s: %e s, %M KiB max RSS" "${BIN}/zkc-m2" scenario "$WORK" "$s"
done
case "$MODE" in rise) out="$WORK/m13/anchored-$SPIKE-to-$RISE" ;; bound) out="$WORK/m13/anchored-2-bound" ;; esac
"${BTC}bitcoind" -version | head -1 > "$out/node-version.txt"
echo "policy: ${POLICY[*]:-default}${ZKC_RISE_TO:+, rising to $ZKC_RISE_TO sat/vB}" >> "$out/node-version.txt"
echo "results: $WORK/m13"
