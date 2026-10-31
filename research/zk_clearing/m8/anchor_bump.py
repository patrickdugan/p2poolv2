"""Can a presigned BitVM graph transaction be fee-bumped after the fact?

Regtest check with Bitcoin Core (31.1): a zero-fee TRUC (version 3)
transaction with a zero-value pay-to-anchor (P2A) output stands in for a
presigned payout. It cannot enter the mempool alone; a TRUC child spending
the anchor pays for both through `submitpackage`; and a second party can
replace that child with a higher-fee sibling, so a low-fee child cannot pin
the parent. Prints one JSON result.

Usage: python3 anchor_bump.py <bitcoin bin dir> <data dir>
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from decimal import Decimal

P2A_SCRIPT = "51024e73"  # OP_1 <0x4e73>, BIP-anchor "pay to anchor"
RPC_PORT = 28443
P2P_PORT = 28444


def main() -> None:
    bin_dir, data_dir = sys.argv[1], sys.argv[2]
    os.makedirs(data_dir, exist_ok=True)
    base = [f"-datadir={data_dir}", "-regtest", f"-rpcport={RPC_PORT}"]

    def cli(*args, wallet=None):
        command = [os.path.join(bin_dir, "bitcoin-cli"), *base]
        if wallet:
            command.append(f"-rpcwallet={wallet}")
        out = subprocess.run(command + [str(a) for a in args], capture_output=True, text=True)
        if out.returncode:
            raise RuntimeError(f"bitcoin-cli {args[0]}: {out.stderr.strip()}")
        text = out.stdout.strip()
        try:
            return json.loads(text, parse_float=Decimal)
        except json.JSONDecodeError:
            return text

    subprocess.run([os.path.join(bin_dir, "bitcoind"), *base, f"-port={P2P_PORT}", "-daemon",
                    "-fallbackfee=0.0001", "-listen=0", "-txindex=0"], check=True)
    result: dict = {"node": None}
    try:
        for _ in range(60):
            try:
                result["node"] = cli("getnetworkinfo")["subversion"]
                break
            except RuntimeError:
                time.sleep(1)
        cli("createwallet", "m8")
        mine_to = cli("getnewaddress", "", "bech32m", wallet="m8")
        cli("generatetoaddress", 103, mine_to)
        utxos = sorted(cli("listunspent", 1, 9999999, wallet="m8"), key=lambda u: u["confirmations"], reverse=True)
        parent_in, fee_in_1, fee_in_2 = utxos[0], utxos[1], utxos[2]

        # Parent: v3, zero fee, payee output plus a zero-value P2A anchor.
        payee = cli("getnewaddress", "", "bech32m", wallet="m8")
        raw = cli("createrawtransaction",
                  json.dumps([{"txid": parent_in["txid"], "vout": parent_in["vout"]}]),
                  json.dumps([{payee: str(parent_in["amount"])}]), 0, "false", 3)
        # Append the P2A output (0 sats) to the unsigned transaction by re-creating it with a raw script.
        unsigned = append_output(raw, 0, P2A_SCRIPT)
        parent = cli("signrawtransactionwithwallet", unsigned, wallet="m8")["hex"]
        parent_info = cli("decoderawtransaction", parent)
        anchor_vout = next(o["n"] for o in parent_info["vout"] if o["scriptPubKey"]["hex"] == P2A_SCRIPT)
        result["parent"] = {"version": parent_info["version"], "vsize": parent_info["vsize"],
                            "outputs": len(parent_info["vout"]), "fee_sats": 0}
        result["parent_alone"] = cli("testmempoolaccept", json.dumps([parent]))[0]

        def child(fee_in, fee_sats):
            change = cli("getnewaddress", "", "bech32m", wallet="m8")
            value = (fee_in["amount"] - Decimal(fee_sats) / Decimal(100_000_000)).quantize(Decimal("0.00000001"))
            raw_child = cli("createrawtransaction",
                            json.dumps([{"txid": parent_info["txid"], "vout": anchor_vout},
                                        {"txid": fee_in["txid"], "vout": fee_in["vout"]}]),
                            json.dumps([{change: str(value)}]), 0, "false", 3)
            prevtxs = [{"txid": parent_info["txid"], "vout": anchor_vout, "scriptPubKey": P2A_SCRIPT, "amount": 0}]
            signed = cli("signrawtransactionwithwallet", raw_child, json.dumps(prevtxs), wallet="m8")
            return signed["hex"]

        child_1 = child(fee_in_1, 1_000)
        package = cli("submitpackage", json.dumps([parent, child_1]))
        child_1_info = cli("decoderawtransaction", child_1)
        result["package"] = {"message": package.get("package_msg"),
                             "child_vsize": child_1_info["vsize"], "child_fee_sats": 1_000}
        mempool = set(cli("getrawmempool"))
        result["in_mempool_after_package"] = {"parent": parent_info["txid"] in mempool,
                                              "child": child_1_info["txid"] in mempool}

        # A second party replaces the child with a higher-fee sibling spending the same anchor.
        child_2 = child(fee_in_2, 5_000)
        child_2_info = cli("decoderawtransaction", child_2)
        try:
            result["sibling_replacement"] = cli("sendrawtransaction", child_2)
        except RuntimeError as error:
            result["sibling_replacement"] = f"rejected: {error}"
        mempool = set(cli("getrawmempool"))
        result["in_mempool_after_replacement"] = {"parent": parent_info["txid"] in mempool,
                                                  "low_fee_child": child_1_info["txid"] in mempool,
                                                  "high_fee_child": child_2_info["txid"] in mempool}
        block = cli("generatetoaddress", 1, mine_to)[0]
        mined = set(cli("getblock", block)["tx"])
        result["mined"] = {"parent": parent_info["txid"] in mined, "high_fee_child": child_2_info["txid"] in mined,
                           "low_fee_child": child_1_info["txid"] in mined}
    finally:
        subprocess.run([os.path.join(bin_dir, "bitcoin-cli"), *base, "stop"], capture_output=True)
    print(json.dumps(result, indent=2, default=str))


def append_output(raw_hex: str, value_sats: int, script_hex: str) -> str:
    """Add one output to an unsigned non-segwit-serialized transaction."""
    data = bytes.fromhex(raw_hex)
    version, rest = data[:4], data[4:]
    count, offset = read_varint(rest, 0)
    for _ in range(count):  # inputs: outpoint 36, script, sequence 4
        offset += 36
        length, offset = read_varint(rest, offset)
        offset += length + 4
    inputs = rest[:offset]
    out_count, out_start = read_varint(rest, offset)
    offset = out_start
    for _ in range(out_count):
        offset += 8
        length, offset = read_varint(rest, offset)
        offset += length
    outputs = rest[out_start:offset]
    locktime = rest[offset:]
    script = bytes.fromhex(script_hex)
    new_output = value_sats.to_bytes(8, "little") + bytes([len(script)]) + script
    return (version + inputs + bytes([out_count + 1]) + outputs + new_output + locktime).hex()


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    if first < 0xFD:
        return first, offset + 1
    size = {0xFD: 2, 0xFE: 4, 0xFF: 8}[first]
    return int.from_bytes(data[offset + 1 : offset + 1 + size], "little"), offset + 1 + size


if __name__ == "__main__":
    main()
