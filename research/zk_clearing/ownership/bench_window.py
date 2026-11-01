"""Cost of building the dense window tree at production size, beside M5's sparse Merkle tree.

    python3 bench_window.py build [--leaves 119953] [--radix-bits 1] [--sparse] [--seed 1]
                                  [--write-input DIR]

`build` makes `--leaves` synthetic outputs (random 253-bit outpoint ids and owners, units and root
heights as in `gen_inputs.synthetic_outputs`), builds the window tree and prints one JSON line:
leaves, levels, capacity, root, Poseidon evaluations, seconds and the proof size. With `--sparse`
it builds M5's tree over the same outputs for comparison. `--write-input DIR` writes the circuit
input of `window_sale_n1.circom` (radix 2) or `window_sale_r8_n1.circom` (radix 8) for a sold
output, valid.json, plus two broken ones in DIR/invalid: the same leaf with a wrong owner, and a
position one off.

Everything is CPython on one core, so the seconds are the cost of a watcher without a native
Poseidon. The evaluation counts do not depend on the machine.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import smt  # noqa: E402
import window_tree as wt  # noqa: E402

FIELD_BITS = 253


def synthetic(count: int, seed: int) -> list[wt.WindowLeaf]:
    rng = random.Random(seed)
    keys = set()
    while len(keys) < count:
        keys.add(rng.getrandbits(FIELD_BITS))
    leaves = []
    for key in sorted(keys):
        units = 100_000_000 if rng.random() < 0.8 else rng.randrange(1, 100_000_000)
        leaves.append(wt.WindowLeaf(key, rng.getrandbits(FIELD_BITS), units, 300_000 + rng.randrange(120_000)))
    return leaves


def build_window(leaves, radix_bits, levels):
    smt.reset_hash_counts()
    start = time.perf_counter()
    tree = wt.WindowTree(leaves, radix_bits, levels)
    seconds = time.perf_counter() - start
    return tree, seconds, dict(smt.WIDE_HASH_COUNTS), dict(smt.HASH_COUNTS)


def build_sparse(leaves):
    smt.reset_hash_counts()
    start = time.perf_counter()
    tree = smt.SparseMerkleTree.from_items(
        [(leaf.key, smt.leaf_value(leaf.owner, leaf.units, leaf.root_height)) for leaf in leaves], max_depth=39)
    root = tree.root
    seconds = time.perf_counter() - start
    return tree, root, seconds, dict(smt.HASH_COUNTS)


def circuit_input(tree: wt.WindowTree, leaf: wt.WindowLeaf, owner_delta: int = 0, position_delta: int = 0) -> dict:
    position = tree.position_of(leaf.key)
    path = tree.path(position)
    claimed_owner = leaf.owner + owner_delta
    if owner_delta:
        path = tree.spliced_path(position, wt.leaf_hash(leaf.key, claimed_owner, leaf.units, leaf.root_height))
    return {
        "windowRoot": tree.root,
        "activeSale": [1],
        "saleId": [leaf.key],
        "sellerId": [claimed_owner],
        "units": [leaf.units],
        "rootHeight": [leaf.root_height],
        "position": [position + position_delta],
        "children": [[list(group) for group in path.children]],
    }


def encode(value):
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        return [encode(item) for item in value]
    if isinstance(value, dict):
        return {key: encode(item) for key, item in value.items()}
    raise TypeError(type(value))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["build"])
    parser.add_argument("--leaves", type=int, default=119_953)
    parser.add_argument("--radix-bits", type=int, default=1)
    parser.add_argument("--levels", type=int, default=None)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--sparse", action="store_true")
    parser.add_argument("--write-input", default=None)
    args = parser.parse_args()

    leaves = synthetic(args.leaves, args.seed)
    if args.sparse:
        tree, root, seconds, counts = build_sparse(leaves)
        depths = tree.leaf_depths()
        print(json.dumps({
            "tree": "sparse (M5)", "leaves": len(leaves), "root": str(root), "seconds": round(seconds, 1),
            "poseidon2": counts["poseidon2"], "poseidon3": counts["poseidon3"],
            "mean_leaf_depth": round(sum(depths) / len(depths), 2), "max_leaf_depth": max(depths),
            "proof_bytes_at_mean_depth": round(32 * sum(depths) / len(depths)),
        }))
        return
    tree, seconds, wide, narrow = build_window(leaves, args.radix_bits, args.levels)
    probe = tree.path(len(leaves) // 2)
    print(json.dumps({
        "tree": f"window radix {tree.radix}", "leaves": len(leaves), "levels": tree.levels, "capacity": tree.capacity,
        "root": str(tree.root), "seconds": round(seconds, 1), "poseidon_by_inputs": {str(k): v for k, v in sorted({**wide, 2: narrow["poseidon2"]}.items())},
        "evaluations": sum(wide.values()) + narrow["poseidon2"] + narrow["poseidon3"],
        "proof_bytes": probe.size_bytes(tree.radix_bits),
    }))
    if args.write_input:
        out = Path(args.write_input)
        (out / "invalid").mkdir(parents=True, exist_ok=True)
        leaf = tree.leaves[len(leaves) // 2]
        (out / "valid.json").write_text(json.dumps(encode(circuit_input(tree, leaf))))
        (out / "invalid" / "wrong_owner.json").write_text(json.dumps(encode(circuit_input(tree, leaf, owner_delta=1))))
        (out / "invalid" / "position_off_by_one.json").write_text(json.dumps(encode(circuit_input(tree, leaf, position_delta=1))))


if __name__ == "__main__":
    main()
