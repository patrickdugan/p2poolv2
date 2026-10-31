"""Build the ownership tree from a real P2Poolv2 node store, dumped by `dump_store.sh`.

    python3 real_store.py [--params production|sim] [--compare <dump dir>] <dump dir> <output dir>

`<dump dir>/shares.json` is `p2poolv2_cli --config <node config> --db-path <store> shares
--num <n>` (the confirmed chain). `<dump dir>/share-<hash>.json` is `share --hash <hash> --full`
for each confirmed share whose body the store still holds; its first transaction id is the
sharechain coinbase.

The script replays the run of bodies that ends at the confirmed tip through
`utxo_set.SharechainUtxo`, one coinbase per share (section 1.1: the node builds no other share
transactions yet, and uncles' coinbase outputs are never spendable). It then takes the tip's set
exactly as section 1.4 defines it, with the chosen chain parameters. The tip's window has to lie
inside the replayed run, which is what section 1.4 says a node's retention window guarantees.

`--compare` replays a second node's dump and compares the two roots at every anchor both dumps
cover. Writes:

    <output>/tree.json   tip, replayed heights, anchor window, root, leaves, owners, depths
    <output>/n1/valid.json                 owned_sale_n1 inputs for the deepest leaf
    <output>/n1/invalid/wrong_owner.json   that leaf sold under another leaf's owner
    <output>/n1/invalid/immature.json      the tip share's own coinbase output
    <output>/n1/invalid/expired.json       the newest output just below the window
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gen_inputs  # noqa: E402
import smt  # noqa: E402
import utxo_set  # noqa: E402

# p2poolv2_sim builds the library with the `sim` feature, which scales the depths down
# (accounting/payout/sharechain_pplns/pplns_window.rs): coinbase maturity 20 and a PPLNS window
# of 80, so PAYOUT_DEPTH 100 and PRUNE_DEPTH 200. The expiry margin keeps production's ratio to
# the maturity (1,008 / 6,048 = 1/6), rounded up.
SIM = utxo_set.ChainParams(coinbase_maturity=20, payout_depth=100, expiry_margin=4, max_depth=gen_inputs.MAX_DEPTH)
PARAMS = {"production": utxo_set.PRODUCTION, "sim": SIM}

TAPROOT_PREFIXES = tuple(hrp + "1p" for hrp in smt.SHARE_HRP.values())


class Chain:
    """A dumped confirmed chain, replayed from the first body of the run that reaches the tip."""

    def __init__(self, dump: Path, params: utxo_set.ChainParams):
        self.shares = sorted(json.loads((dump / "shares.json").read_text())["shares"], key=lambda s: s["height"])
        self.coinbases = {}
        for share in self.shares:
            address = share["miner_address"]
            if not address.startswith(TAPROOT_PREFIXES):
                sys.exit(
                    f"share {share['blockhash']}: miner_address {address!r} is not a P2TR share "
                    "address; dump with the node's --config so the CLI renders it"
                )
            path = dump / f"share-{share['blockhash']}.json"
            if not path.exists():
                continue
            lookup = json.loads(path.read_text())
            if isinstance(lookup, list):
                lookup = next(item for item in lookup if item["blockhash"] == share["blockhash"])
            assert lookup["miner_address"] == address, share["blockhash"]
            if len(lookup["transactions"]) != 1:
                sys.exit(
                    f"share {share['blockhash']} carries {len(lookup['transactions'])} transactions; "
                    "the replay models the share coinbase only"
                )
            self.coinbases[share["height"]] = lookup["transactions"][0]
        self.params = params
        self.tip = self.shares[-1]["height"]
        if self.tip not in self.coinbases:
            sys.exit(f"the tip share at {self.tip} has no body in the dump")
        self.first = self.tip
        while self.first - 1 in self.coinbases:
            self.first -= 1
        self.model = utxo_set.SharechainUtxo(params)
        self.model.tip = self.first - 1
        by_height = {share["height"]: share for share in self.shares}
        for height in range(self.first, self.tip + 1):
            coinbase = utxo_set.share_coinbase(self.coinbases[height], by_height[height]["miner_address"])
            self.model.apply_block(height, [coinbase])

    def anchors(self) -> range:
        """Anchors whose whole window lies in the replayed run, so their sets are exact."""
        if self.first == 0:
            return range(0, self.tip + 1)
        lowest = self.first + self.params.payout_depth - self.params.expiry_margin - 1
        return range(lowest, self.tip + 1)

    def leaves(self, anchor: int) -> list[gen_inputs.Leaf]:
        return [leaf_of(output) for output in self.model.snapshot(anchor)]


def leaf_of(output: utxo_set.Output) -> gen_inputs.Leaf:
    return gen_inputs.Leaf(output.key, smt.owner_id(output.owner), output.units, output.root_height)


def tree_of(leaves: list[gen_inputs.Leaf]) -> smt.SparseMerkleTree:
    return smt.SparseMerkleTree.from_items(((leaf.key, leaf.value) for leaf in leaves), max_depth=gen_inputs.MAX_DEPTH)


def compare(a: Chain, b: Chain) -> dict:
    shared = range(max(a.anchors().start, b.anchors().start), min(a.tip, b.tip) + 1)
    differing = [anchor for anchor in shared if tree_of(a.leaves(anchor)).root != tree_of(b.leaves(anchor)).root]
    return {"anchors": [shared.start, shared.stop - 1], "count": len(shared), "differing": differing}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("dump", type=Path)
    parser.add_argument("out", type=Path)
    parser.add_argument("--params", choices=sorted(PARAMS), default="production")
    parser.add_argument("--compare", type=Path, help="a second node's dump")
    args = parser.parse_args()
    params = PARAMS[args.params]

    chain = Chain(args.dump, params)
    anchor = chain.tip
    if anchor not in chain.anchors():
        sys.exit(f"the dump replays heights {chain.first}..{chain.tip}, short of the tip's window")
    lower, upper = params.window(anchor)
    leaves = chain.leaves(anchor)
    if not leaves:
        sys.exit(f"the window {lower}..{upper} at anchor {anchor} holds no output")
    tree = tree_of(leaves)
    proofs = {leaf.key: tree.prove(leaf.key) for leaf in leaves}
    owners = Counter(leaf.owner for leaf in leaves)
    stats = {
        "params": args.params,
        "confirmed_tip": chain.tip,
        "shares": len(chain.shares),
        "replayed_heights": [chain.first, chain.tip],
        "bodies_missing": len(chain.shares) - len(chain.coinbases),
        "anchor": anchor,
        "window": [max(lower, 0), upper],
        "leaves": len(tree),
        "root": str(tree.root),
        "owners": len(owners),
        "leaves_per_owner": sorted(owners.values(), reverse=True),
        "depth_mean": round(statistics.mean(p.depth for p in proofs.values()), 2),
        "depth_max": max(p.depth for p in proofs.values()),
        "proof_bytes_mean": round(statistics.mean(p.size_bytes() for p in proofs.values()), 1),
    }
    if args.compare:
        stats["compare"] = compare(chain, Chain(args.compare, params))
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "tree.json").write_text(json.dumps(stats, indent=2) + "\n")

    deepest = max(leaves, key=lambda leaf: proofs[leaf.key].depth)
    valid_row = gen_inputs.row(tree, deepest)
    gen_inputs.write(args.out / "n1", "valid", gen_inputs.assemble(tree.root, [valid_row]))
    invalid = {"wrong_owner": dict(valid_row, sellerId=next(l.owner for l in leaves if l.owner != deepest.owner))}
    outputs = chain.model.outputs
    tip_output = leaf_of(outputs[(chain.coinbases[chain.tip], 0)])
    invalid["immature"] = dict(valid_row, saleId=tip_output.key, sellerId=tip_output.owner, rootHeight=tip_output.root_height)
    if lower - 1 >= chain.first:
        old = leaf_of(outputs[(chain.coinbases[lower - 1], 0)])
        invalid["expired"] = dict(valid_row, saleId=old.key, sellerId=old.owner, rootHeight=old.root_height)
    for name, row in invalid.items():
        gen_inputs.write(args.out / "n1" / "invalid", name, gen_inputs.assemble(tree.root, [row]))
    print(json.dumps(stats))


if __name__ == "__main__":
    main()
