"""Write circuit inputs for owned_sale_n1.circom and owned_sale_n16.circom, valid and invalid.

    python3 gen_inputs.py <output dir> [--leaves 2000]

Builds a UTXO tree with `smt.py` from synthetic outputs, then writes, for each width:

    <dir>/n1/valid.json, valid_deepest.json, valid_padding.json, invalid/*.json
    <dir>/n16/valid.json, invalid/*.json

`run.sh` feeds the valid files to the witness calculator and prover and checks that every
invalid file is rejected. Each invalid file breaks exactly one thing, named by the file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import smt  # noqa: E402
import utxo_set  # noqa: E402

N_LEVELS = 40
MAX_DEPTH = N_LEVELS - 1


class Leaf:
    def __init__(self, key: int, owner: int, units: int, root_height: int):
        self.key, self.owner, self.units, self.root_height = key, owner, units, root_height
        self.value = smt.leaf_value(owner, units, root_height)


def synthetic_outputs(count: int, seed: int) -> list[Leaf]:
    """Share outputs as the watcher would index them: coinbase outputs and some transfers."""
    rng = random.Random(seed)
    leaves = []
    for index in range(count):
        txid = hashlib.sha256(f"tx-{seed}-{index}".encode()).hexdigest()
        miner = smt.share_address(hashlib.sha256(f"miner-{rng.randrange(60)}".encode()).digest(), "signet")
        units = utxo_set.SHARE_UNITS if rng.random() < 0.8 else rng.randrange(1, utxo_set.SHARE_UNITS)
        root_height = 300_000 + rng.randrange(120_000)
        leaves.append(Leaf(smt.outpoint_id(txid, 0), smt.owner_id(miner), units, root_height))
    return leaves


def row(tree: smt.SparseMerkleTree, leaf: Leaf, active: int = 1) -> dict:
    proof = tree.prove(leaf.key)
    return {
        "activeSale": active,
        "saleId": leaf.key,
        "sellerId": leaf.owner,
        "units": leaf.units,
        "rootHeight": leaf.root_height,
        "siblings": smt.pad_siblings(proof.siblings, N_LEVELS),
    }


def padding_row() -> dict:
    return {"activeSale": 0, "saleId": 0, "sellerId": 0, "units": 0, "rootHeight": 0, "siblings": [0] * N_LEVELS}


def assemble(root: int, rows: list[dict]) -> dict:
    def column(name):
        return [r[name] for r in rows]

    return {
        "utxoRoot": root,
        "activeSale": column("activeSale"),
        "saleId": column("saleId"),
        "sellerId": column("sellerId"),
        "units": column("units"),
        "rootHeight": column("rootHeight"),
        "siblings": column("siblings"),
    }


def encode(value):
    if isinstance(value, bool):
        return str(int(value))
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        return [encode(item) for item in value]
    if isinstance(value, dict):
        return {key: encode(item) for key, item in value.items()}
    raise TypeError(type(value))


def write(directory: Path, name: str, inputs: dict) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{name}.json").write_text(json.dumps(encode(inputs), sort_keys=True, separators=(",", ":")))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output")
    parser.add_argument("--leaves", type=int, default=2000)
    args = parser.parse_args()
    out = Path(args.output)

    leaves = synthetic_outputs(args.leaves, seed=1)
    members = {leaf.key: leaf for leaf in leaves}

    # Two extra leaves that sit at the deepest depth the circuit allows (39): their keys share 38 low bits.
    rng = random.Random(77)
    deep_key = rng.getrandbits(253)
    deep_a = Leaf(deep_key, smt.owner_id("p2pool1deepAlice"), utxo_set.SHARE_UNITS, 400_001)
    deep_b = Leaf(deep_key ^ (1 << 38), smt.owner_id("p2pool1deepBob"), utxo_set.SHARE_UNITS, 400_002)
    tree = smt.SparseMerkleTree.from_items(
        [(leaf.key, leaf.value) for leaf in leaves] + [(deep_a.key, deep_a.value), (deep_b.key, deep_b.value)],
        max_depth=MAX_DEPTH,
    )
    root = tree.root
    assert tree.prove(deep_a.key).depth == MAX_DEPTH, tree.prove(deep_a.key).depth

    seller = leaves[0]
    other = leaves[1]
    stranger_key = smt.outpoint_id("f" * 64, 0)
    assert stranger_key not in tree

    n1 = out / "n1"
    write(n1, "valid", assemble(root, [row(tree, seller)]))
    write(n1, "valid_deepest", assemble(root, [row(tree, deep_a)]))
    write(n1, "valid_padding", assemble(root, [padding_row()]))

    invalid = n1 / "invalid"
    good = row(tree, seller)

    def broken(**changes) -> dict:
        return assemble(root, [{**good, **changes}])

    write(invalid, "wrong_owner", broken(sellerId=other.owner))
    write(invalid, "wrong_units", broken(units=seller.units + 1))
    write(invalid, "wrong_root_height", broken(rootHeight=seller.root_height + 1))
    write(invalid, "wrong_root", assemble(root + 1, [good]))
    write(invalid, "wrong_sale_id", broken(saleId=other.key))
    siblings = list(good["siblings"])
    first_nonzero = next(i for i, s in enumerate(siblings) if s)
    siblings[first_nonzero] += 1
    write(invalid, "tampered_sibling", broken(siblings=siblings))

    # A key that is not in the tree, with the siblings circomlib's own find returns for it.
    absent = tree.prove_absent(stranger_key)
    write(invalid, "non_member_with_exclusion_path", broken(
        saleId=stranger_key, sellerId=seller.owner, siblings=smt.pad_siblings(absent.siblings, N_LEVELS)))
    # A non-member claiming a member's leaf and path.
    write(invalid, "non_member_with_borrowed_path", broken(saleId=seller.key ^ (1 << 5)))

    # The same proof against a root from after the output was spent: freshness is exactly the root.
    spent_tree = smt.SparseMerkleTree.from_items(
        [(leaf.key, leaf.value) for leaf in leaves[1:]] + [(deep_a.key, deep_a.value), (deep_b.key, deep_b.value)],
        max_depth=MAX_DEPTH,
    )
    write(invalid, "spent_output_against_new_root", assemble(spent_tree.root, [good]))

    # Leaf one level too deep for the circuit: the last sibling would be non-zero.
    too_deep_key = deep_a.key ^ (1 << 39)
    too_deep = Leaf(too_deep_key, smt.owner_id("p2pool1deepCarol"), utxo_set.SHARE_UNITS, 400_003)
    deep_tree = smt.SparseMerkleTree.from_items(
        [(deep_a.key, deep_a.value), (deep_b.key, deep_b.value), (too_deep.key, too_deep.value)]
    )
    proof = deep_tree.prove(too_deep.key)
    assert proof.depth == N_LEVELS, proof.depth
    write(invalid, "leaf_deeper_than_circuit", assemble(deep_tree.root, [{
        "activeSale": 1, "saleId": too_deep.key, "sellerId": too_deep.owner, "units": too_deep.units,
        "rootHeight": too_deep.root_height, "siblings": list(proof.siblings)}]))

    write(invalid, "padding_slot_names_an_output", assemble(root, [{**padding_row(), "saleId": seller.key}]))
    write(invalid, "active_flag_not_boolean", broken(activeSale=2))

    # Sixteen slots: eleven sales (the deepest leaf among them) and five padding slots.
    sellers = [leaves[i] for i in range(2, 12)] + [deep_b]
    rows16 = [row(tree, leaf) for leaf in sellers] + [padding_row() for _ in range(16 - len(sellers))]
    n16 = out / "n16"
    write(n16, "valid", assemble(root, rows16))
    invalid16 = n16 / "invalid"
    rows = [dict(r) for r in rows16]
    rows[9] = {**rows[9], "sellerId": other.owner}
    write(invalid16, "wrong_owner_in_slot_9", assemble(root, rows))
    rows = [dict(r) for r in rows16]
    rows[3] = {**rows[3], "saleId": stranger_key, "siblings": smt.pad_siblings(absent.siblings, N_LEVELS)}
    write(invalid16, "non_member_in_slot_3", assemble(root, rows))
    rows = [dict(r) for r in rows16]
    rows[15] = {**rows[15], "saleId": seller.key}
    write(invalid16, "padding_slot_15_names_an_output", assemble(root, rows))

    (out / "tree.json").write_text(json.dumps({
        "leaves": len(tree), "n_levels": N_LEVELS, "root": str(root),
        "mean_leaf_depth": sum(tree.leaf_depths()) / len(tree), "max_leaf_depth": max(tree.leaf_depths()),
    }))
    print(f"wrote inputs for a {len(tree)}-leaf tree, root {root}")


if __name__ == "__main__":
    main()
