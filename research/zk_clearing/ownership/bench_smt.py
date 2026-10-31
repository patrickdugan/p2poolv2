"""Measure the sparse Merkle UTXO accumulator on a workload sized from P2Poolv2's parameters.

    python3 bench_smt.py depth            # leaf depth against set size, no hashing
    python3 bench_smt.py cost [--quick]   # hashes and time to build and to keep up, per share
    python3 bench_smt.py poseidon         # Poseidon speed in this interpreter

Every run prints its assumptions and a JSON object, so OWNERSHIP.md can quote the numbers.
Times are CPython on one core; hash counts do not depend on the machine.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import smt  # noqa: E402
import utxo_set  # noqa: E402
from utxo_set import Accumulator, Tx, share_coinbase  # noqa: E402

PARAMS = utxo_set.PRODUCTION
SHARES_PER_DAY = 86_400 // 10  # 10 s target


def _ctz(x: int) -> int:
    return (x & -x).bit_length() - 1


def max_leaf_depth(keys: list[int]) -> tuple[int, float]:
    """Deepest leaf and mean leaf depth of the tree over `keys`, from their bit-reversed order.

    Paths read bits least significant first, so sorting by the bit-reversed low 64 bits puts
    keys that share a long path prefix next to each other. A leaf's depth is one more than the
    longest prefix it shares with a neighbour.
    """
    order = sorted(keys, key=lambda k: int(format(k & ((1 << 64) - 1), "064b")[::-1], 2))
    shared = [_ctz((a ^ b) & ((1 << 64) - 1) or (1 << 64)) for a, b in zip(order, order[1:])]
    depths = []
    for i in range(len(order)):
        left = shared[i - 1] if i > 0 else -1
        right = shared[i] if i < len(shared) else -1
        depths.append(1 + max(left, right, 0) if len(order) > 1 else 0)
    return max(depths), sum(depths) / len(depths)


def depth_table(trials: int, sizes: list[int], seed: int = 5) -> list[dict]:
    rng = random.Random(seed)
    rows = []
    for n in sizes:
        maxima, means = [], []
        for _ in range(trials):
            keys = [rng.getrandbits(64) for _ in range(n)]
            deepest, mean = max_leaf_depth(keys)
            maxima.append(deepest)
            means.append(mean)
        rows.append(
            {
                "leaves": n,
                "log2": round(math.log2(n), 2),
                "mean_leaf_depth": round(statistics.mean(means), 2),
                "max_depth_min": min(maxima),
                "max_depth_median": int(statistics.median(maxima)),
                "max_depth_max": max(maxima),
                "trials": trials,
            }
        )
    return rows


def conflict_table(live_sizes: dict[str, int], entrants_per_day: dict[str, float], levels: list[int]) -> list[dict]:
    """Expected honest slot conflicts per year, and the grinding cost, for each tree width.

    Two outputs conflict when they share their low `max_depth` bits. A new output meets one of the
    `live` outputs with probability live / 2^max_depth, so that many conflicts a year. At any
    moment about live / 2^(max_depth + 1) of the live outputs have lost their slot to an older one.
    """
    rows = []
    for n_levels in levels:
        bits = n_levels - 1
        row = {"n_levels": n_levels, "max_depth": bits, "grind_sha256_evaluations": f"2^{bits}"}
        for name, live in live_sizes.items():
            per_day = entrants_per_day[name] * live / 2**bits
            row[f"conflicts_per_year_{name}"] = round(per_day * 365, 4)
            row[f"untracked_fraction_{name}"] = float(f"{live / 2 ** (bits + 1):.2e}")
        rows.append(row)
    return rows


def _txid(*parts) -> str:
    return hashlib.sha256("-".join(str(p) for p in parts).encode()).hexdigest()


def _owner(index: int) -> str:
    return smt.share_address(hashlib.sha256(f"miner-{index}".encode()).digest(), "mainnet")


def fill_history(accumulator: Accumulator, tip: int, miners: int) -> None:
    owners = [_owner(i) for i in range(miners)]
    rng = random.Random(1)
    for height in range(tip + 1):
        accumulator.apply_block(height, [share_coinbase(_txid("cb", height), owners[rng.randrange(miners)])])


def spendable_pick(accumulator: Accumulator, height: int, rng: random.Random):
    """A random tracked output that a block at `height` may spend, or None."""
    lower, upper = accumulator.params.window(height - 1)
    for _ in range(50):
        root = rng.randint(lower, upper)
        for output in accumulator.model.by_root.get(root, ()):
            if output.owner is None or output.outpoint in accumulator.model.spent_at:
                continue
            if accumulator._tracked.get(output.key & accumulator._mask) is output:
                return output
    return None


def run_scenario(name: str, transfers_per_share: float, fan_out: int, blocks: int, miners: int = 200, seed: int = 4) -> dict:
    accumulator = Accumulator(PARAMS)
    tip = PARAMS.payout_depth + PARAMS.coinbase_maturity + 2000  # a full window, with the oldest roots already expired
    owners = [_owner(i) for i in range(miners)]
    t0 = time.perf_counter()
    fill_history(accumulator, tip, miners)
    history_seconds = time.perf_counter() - t0

    smt.reset_hash_counts()
    t0 = time.perf_counter()
    initial_root = accumulator.root
    build_seconds = time.perf_counter() - t0
    build_hashes = dict(smt.HASH_COUNTS)
    leaves = len(accumulator)
    del initial_root

    rng = random.Random(seed)
    per_block = []
    inserts0, deletes0 = accumulator.inserts, accumulator.deletes
    for step in range(blocks):
        height = tip + 1 + step
        txs: list[Tx] = [share_coinbase(_txid("cb", height), owners[rng.randrange(miners)])]
        count = int(transfers_per_share) + (1 if rng.random() < transfers_per_share % 1 else 0)
        taken = set()
        for index in range(count):
            pick = spendable_pick(accumulator, height, rng)
            if pick is None or pick.outpoint in taken:
                continue
            taken.add(pick.outpoint)
            share = pick.units // fan_out
            outs = tuple((owners[rng.randrange(miners)], share) for _ in range(fan_out))
            txs.append(Tx(_txid("tx", height, index), inputs=(pick.outpoint,), outputs=outs))
        smt.reset_hash_counts()
        start = time.perf_counter()
        accumulator.apply_block(height, txs)
        accumulator.root  # noqa: B018  (the root a watcher publishes for this share)
        elapsed = time.perf_counter() - start
        per_block.append((elapsed, smt.HASH_COUNTS["poseidon2"], smt.HASH_COUNTS["poseidon3"]))
    ops = (accumulator.inserts - inserts0) + (accumulator.deletes - deletes0)

    depths = accumulator.tree.leaf_depths()
    sample = random.Random(9).sample(accumulator.tracked_outputs(), min(2000, len(accumulator)))
    proofs = [accumulator.tree.prove(output.key) for output in sample]
    proof_depths = [proof.depth for proof in proofs]
    return {
        "scenario": name,
        "transfers_per_share": transfers_per_share,
        "fan_out": fan_out,
        "blocks_measured": blocks,
        "history_blocks": tip + 1,
        "live_leaves_at_start": leaves,
        "live_leaves_at_end": len(accumulator),
        "history_replay_seconds": round(history_seconds, 1),
        "initial_build": {
            "seconds": round(build_seconds, 1),
            "poseidon2": build_hashes["poseidon2"],
            "poseidon3": build_hashes["poseidon3"],
            "hashes_per_leaf": round((build_hashes["poseidon2"] + build_hashes["poseidon3"]) / leaves, 2),
        },
        "per_share_update": {
            "tree_ops_per_share": round(ops / blocks, 2),
            "poseidon2_mean": round(statistics.mean(p2 for _, p2, _ in per_block), 1),
            "poseidon3_mean": round(statistics.mean(p3 for _, _, p3 in per_block), 1),
            "hashes_mean": round(statistics.mean(p2 + p3 for _, p2, p3 in per_block), 1),
            "hashes_max": max(p2 + p3 for _, p2, p3 in per_block),
            "ms_mean": round(1000 * statistics.mean(t for t, _, _ in per_block), 2),
            "ms_p99": round(1000 * sorted(t for t, _, _ in per_block)[int(0.99 * len(per_block))], 2),
        },
        "tree": {
            "mean_leaf_depth": round(sum(depths) / len(depths), 2),
            "max_leaf_depth": max(depths),
        },
        "membership_proof": {
            "sampled": len(proofs),
            "siblings_mean": round(statistics.mean(proof_depths), 2),
            "siblings_p99": sorted(proof_depths)[int(0.99 * len(proof_depths))],
            "siblings_max": max(proof_depths),
            "bytes_full_mean": round(32 * statistics.mean(proof_depths)),
            "bytes_compressed_mean": round(statistics.mean(p.size_bytes(compressed=True) for p in proofs)),
            "bytes_fixed_for_circuit": 32 * PARAMS.max_depth + 32,
        },
    }


def poseidon_speed(rounds: int = 3000) -> dict:
    t0 = time.perf_counter()
    for i in range(rounds):
        smt.poseidon2(i, i + 1)
    two = (time.perf_counter() - t0) / rounds
    t0 = time.perf_counter()
    for i in range(rounds):
        smt.poseidon3(i, i + 1, 1)
    three = (time.perf_counter() - t0) / rounds
    return {"python": sys.version.split()[0], "poseidon2_us": round(two * 1e6, 1), "poseidon3_us": round(three * 1e6, 1)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("depth", "cost", "poseidon", "conflicts"))
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--trials", type=int, default=40)
    parser.add_argument("--scale", type=int, default=1, help="divide the consensus depths by this, for a fast smoke run")
    args = parser.parse_args()
    global PARAMS
    if args.scale > 1:
        PARAMS = utxo_set.ChainParams(
            PARAMS.coinbase_maturity // args.scale,
            PARAMS.payout_depth // args.scale,
            PARAMS.expiry_margin // args.scale,
            PARAMS.max_depth,
        )

    window = PARAMS.payout_depth - PARAMS.coinbase_maturity - PARAMS.expiry_margin + 1
    if args.mode == "poseidon":
        print(json.dumps(poseidon_speed(), indent=1))
    elif args.mode == "depth":
        sizes = [2**14, window, 3 * window // 2, 3 * window, 2**20]
        if args.quick:
            sizes = [2**14, window]
        print(f"window of root heights = {window}; trials per size = {args.trials}")
        print(json.dumps(depth_table(args.trials, sizes), indent=1))
    elif args.mode == "conflicts":
        live = {"rho1": window, "rho3": 3 * window}
        entrants = {"rho1": SHARES_PER_DAY, "rho3": 3 * SHARES_PER_DAY}
        print(json.dumps(conflict_table(live, entrants, [28, 32, 36, 40, 44, 48]), indent=1))
    else:
        blocks = 60 if args.quick else 600
        scenarios = [
            ("today: coinbase outputs only", 0.0, 1),
            ("1 whole-share transfer per share", 1.0, 1),
            ("4 transfers per share, each split in 2", 4.0, 2),
        ]
        results = [run_scenario(name, rate, fan, blocks) for name, rate, fan in scenarios]
        print(json.dumps({"params": PARAMS.__dict__, "window_root_heights": window, "poseidon": poseidon_speed(), "scenarios": results}, indent=1))


if __name__ == "__main__":
    main()
