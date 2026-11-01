#!/usr/bin/env bash
# M16: the anchored, bound graph (M9, M13) on a live chain, with the ceremony's verifying key.
#
# Usage: bash research/zk_clearing/bitvm/scripts/run-m16.sh <work dir> rehearse|testnet4 [scenario...]
#   rehearse  a private regtest node whose blocks come from a timer (BLOCK_SECONDS, default 15),
#             not from the scenario: the scenario runs exactly as on testnet4, waiting for blocks
#   testnet4  the testnet4 node at TESTNET4_DATADIR (default /root/testnet4, RPC 48342) and its
#             wallet m16, which must hold the coins (fund the address `run-m16.sh <work> address`
#             prints)
#   address   prints a testnet4 address of wallet m16 to fund, and its balance
# Default scenarios: unchallenged late stall challenged.
#
# Both modes presign at 100 sat/kvB (testnet4's relay floor) and pay the same for transactions
# signed when posted (the wallet funds at 1 sat/vB), price the challenge at the presigned rate,
# and use a 5,000-sat bond, a 2,500-sat burn and a 1,000-sat deadline connector. testnet4's
# blocks take 100 sat/kvB transactions, so there is no fee spike to bump through here (M9 and
# M13 cover that). Every key is salted with <work>/key-salt
# (made here, mode 600, never committed): on a public chain, keys from public labels alone
# would be anyone's. Expects prove_batch.sh --small and `zkc-m1 prepare` to have filled <work>.
# Results land in <work>/m16/<mode>/.
set -euo pipefail

WORK="$(cd "${1:?usage: run-m16.sh <work dir> rehearse|testnet4|address [scenario...]}" && pwd)"
MODE="${2:?usage: run-m16.sh <work dir> rehearse|testnet4|address [scenario...]}"
shift 2
if [ $# -gt 0 ]; then SCENARIOS=("$@"); else SCENARIOS=(unchallenged late stall challenged); fi
BIN="$WORK/target/release"
BTC="${BITCOIN_BIN:+$BITCOIN_BIN/}"
[ -f "$WORK/key-salt" ] || { (umask 077; head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$WORK/key-salt"); }

# The amounts can be set from outside (the testnet4 run used a 2,500-sat bond, a 1,000-sat burn
# and a 500-sat connector to fit the coins it had).
export ZKC_CHAIN=live ZKC_GRAPH=anchored ZKC_BIND_HEIGHT=1 ZKC_VALIDATE=0 \
  ZKC_PRESIGN_SAT_PER_KVB=100 ZKC_MARKET_SAT_PER_KVB=100 ZKC_MAX_SAT_PER_KVB=100 \
  ZKC_BOND_SATS="${ZKC_BOND_SATS:-5000}" ZKC_BURN_SATS="${ZKC_BURN_SATS:-2500}" ZKC_DEADLINE_SATS="${ZKC_DEADLINE_SATS:-1000}" \
  ZKC_KEY_SALT="$(cat "$WORK/key-salt")" ZKC_WALLET=m16

case "$MODE" in
  rehearse)
    DATADIR="$WORK/regtest-m16"
    CLI=("${BTC}bitcoin-cli" -regtest -datadir="$DATADIR" -rpcport=18803 -rpcuser=zkc -rpcpassword=zkc-m16-regtest)
    export ZKC_RPC_URL="http://127.0.0.1:18803" ZKC_RPC_USER=zkc ZKC_RPC_PASS=zkc-m16-regtest
    "${CLI[@]}" stop >/dev/null 2>&1 && sleep 3 || true
    rm -rf "$DATADIR"
    mkdir -p "$DATADIR"
    "${BTC}bitcoind" -regtest -datadir="$DATADIR" -daemon -txindex=1 -fallbackfee=0.0002 \
      -rpcport=18803 -port=18804 -rpcuser=zkc -rpcpassword=zkc-m16-regtest -rpcthreads=4 -listen=0
    for _ in $(seq 60); do "${CLI[@]}" getblockcount >/dev/null 2>&1 && break; sleep 1; done
    "${CLI[@]}" createwallet m16 >/dev/null
    "${CLI[@]}" -rpcwallet=m16 generatetoaddress 200 "$("${CLI[@]}" -rpcwallet=m16 getnewaddress)" >/dev/null
    # The chain's own clock: a block every BLOCK_SECONDS whatever the scenario does.
    miner_address="$("${CLI[@]}" -rpcwallet=m16 getnewaddress)"
    ( while [ ! -f "$DATADIR/stop-miner" ]; do sleep "${BLOCK_SECONDS:-15}"; "${CLI[@]}" generatetoaddress 1 "$miner_address" >/dev/null 2>&1 || true; done ) &
    trap 'touch "$DATADIR/stop-miner"; "${CLI[@]}" stop >/dev/null 2>&1 || true' EXIT
    ;;
  testnet4|address)
    DATADIR="${TESTNET4_DATADIR:-/root/testnet4}"
    CLI=("${BTC}bitcoin-cli" -datadir="$DATADIR")
    "${CLI[@]}" getblockcount >/dev/null
    export ZKC_RPC_URL="http://127.0.0.1:48342" ZKC_RPC_USER=__cookie__
    ZKC_RPC_PASS="$(cut -d: -f2 "$DATADIR/testnet4/.cookie")"; export ZKC_RPC_PASS
    "${CLI[@]}" listwallets | grep -q '"m16"' || "${CLI[@]}" loadwallet m16 >/dev/null 2>&1 || "${CLI[@]}" createwallet m16 >/dev/null
    if [ "$MODE" = address ]; then
      echo "fund this testnet4 address: $("${CLI[@]}" -rpcwallet=m16 getnewaddress m16-funding bech32m)"
      "${CLI[@]}" -rpcwallet=m16 getbalances
      exit 0
    fi
    ;;
  *) echo "mode must be rehearse, testnet4 or address"; exit 2 ;;
esac

out="$WORK/m16/$MODE"
mkdir -p "$out"
"${BTC}bitcoind" -version | head -1 > "$out/node-version.txt"
echo "mode $MODE; chain $("${CLI[@]}" getblockchaininfo | grep '"chain"' | tr -d ' ,')" >> "$out/node-version.txt"
for s in "${SCENARIOS[@]}"; do
  echo "== $MODE: scenario $s (height $("${CLI[@]}" getblockcount))"
  /usr/bin/time -f "scenario $MODE $s: %e s, %M KiB max RSS" "${BIN}/zkc-m2" scenario "$WORK" "$s"
  mv "$WORK"/m16/anchored-100kvb-bound-live/scenario-"$s".json "$out/"
done
"${CLI[@]}" -rpcwallet=m16 getbalances > "$out/wallet-after.json"
echo "results: $out"
