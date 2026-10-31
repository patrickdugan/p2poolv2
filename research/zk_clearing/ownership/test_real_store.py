"""Tests of real_store.py on small dumps in the shape `dump_store.sh` writes.

Run from the repository root:

    python3 -m unittest discover -s research/zk_clearing/ownership
"""

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import real_store  # noqa: E402
import smt  # noqa: E402
import utxo_set  # noqa: E402

SIM = real_store.SIM


def coinbase_txid(height: int) -> str:
    return hashlib.sha256(f"coinbase-{height}".encode()).hexdigest()


def regtest_owner(index: int) -> str:
    return smt.share_address(hashlib.sha256(f"owner-{index}".encode()).digest(), "regtest")


def write_dump(directory: Path, tip: int, pruned: range, owner=lambda h: regtest_owner(h % 3)) -> None:
    """Confirmed shares 0..tip as `shares` prints them (newest first); no bodies for `pruned`."""
    directory.mkdir(parents=True, exist_ok=True)
    shares = []
    for height in range(tip, -1, -1):
        blockhash = hashlib.sha256(f"share-{height}".encode()).hexdigest()
        shares.append({"blockhash": blockhash, "height": height, "miner_address": owner(height)})
        if height not in pruned:
            body = [{"blockhash": blockhash, "miner_address": owner(height), "transactions": [coinbase_txid(height)]}]
            (directory / f"share-{blockhash}.json").write_text(json.dumps(body))
    (directory / "shares.json").write_text(json.dumps({"shares": shares}))


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(HERE / "real_store.py"), *args], capture_output=True, text=True)


class RealStoreTests(unittest.TestCase):
    def test_the_tip_set_is_the_window_of_mature_unexpired_coinbases(self):
        with tempfile.TemporaryDirectory() as tmp:
            dump = Path(tmp) / "dump"
            write_dump(dump, tip=149, pruned=range(1, 30))
            chain = real_store.Chain(dump, SIM)
        self.assertEqual((chain.first, chain.tip), (30, 149))
        self.assertEqual(chain.anchors().start, 30 + SIM.payout_depth - SIM.expiry_margin - 1)
        lower, upper = SIM.window(149)
        leaves = chain.leaves(149)
        self.assertEqual(sorted(leaf.root_height for leaf in leaves), list(range(lower, upper + 1)))
        for leaf in leaves:
            self.assertEqual(leaf.key, smt.outpoint_id(coinbase_txid(leaf.root_height), 0))
            self.assertEqual(leaf.owner, smt.owner_id(regtest_owner(leaf.root_height % 3)))
            self.assertEqual(leaf.units, utxo_set.SHARE_UNITS)

    def test_witness_program_hex_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            dump = Path(tmp) / "dump"
            write_dump(dump, tip=5, pruned=range(0), owner=lambda h: hashlib.sha256(b"program").hexdigest())
            with self.assertRaises(SystemExit):
                real_store.Chain(dump, SIM)

    def test_a_dump_pruned_into_the_window_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            dump = Path(tmp) / "dump"
            write_dump(dump, tip=149, pruned=range(1, 61))
            result = run("--params", "sim", str(dump), str(Path(tmp) / "out"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("short of the tip's window", result.stderr)

    def test_fixtures_and_watcher_comparison(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b, out = Path(tmp) / "a", Path(tmp) / "b", Path(tmp) / "out"
            write_dump(a, tip=149, pruned=range(1, 30))
            write_dump(b, tip=147, pruned=range(1, 40))
            result = run("--params", "sim", "--compare", str(b), str(a), str(out))
            self.assertEqual(result.returncode, 0, result.stderr)
            stats = json.loads((out / "tree.json").read_text())
            fixtures = {
                path.stem: json.loads(path.read_text())
                for path in [out / "n1" / "valid.json", *(out / "n1" / "invalid").glob("*.json")]
            }
        self.assertEqual(stats["leaves"], 77)
        self.assertEqual(stats["compare"], {"anchors": [135, 147], "count": 13, "differing": []})

        def folds_to_root(inputs: dict) -> bool:
            value = smt.leaf_value(int(inputs["sellerId"][0]), int(inputs["units"][0]), int(inputs["rootHeight"][0]))
            siblings = [int(s) for s in inputs["siblings"][0]]
            return str(smt.root_from_proof(int(inputs["saleId"][0]), value, siblings)) == stats["root"]

        self.assertTrue(folds_to_root(fixtures["valid"]))
        self.assertEqual(sorted(fixtures), ["expired", "immature", "valid", "wrong_owner"])
        for name in ("expired", "immature", "wrong_owner"):
            self.assertFalse(folds_to_root(fixtures[name]), name)
        self.assertEqual(fixtures["immature"]["rootHeight"], ["149"])
        self.assertEqual(fixtures["expired"]["rootHeight"], [str(SIM.window(149)[0] - 1)])

    def test_comparison_finds_a_different_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b, out = Path(tmp) / "a", Path(tmp) / "b", Path(tmp) / "out"
            write_dump(a, tip=149, pruned=range(1, 30))
            write_dump(b, tip=149, pruned=range(1, 30), owner=lambda h: regtest_owner(h % 3 if h != 100 else 7))
            result = run("--params", "sim", "--compare", str(b), str(a), str(out))
            self.assertEqual(result.returncode, 0, result.stderr)
            stats = json.loads((out / "tree.json").read_text())
        # height 100 is in an anchor's set from anchor 119 (maturity) to anchor 195 (expiry)
        self.assertEqual(stats["compare"]["differing"], list(range(max(125, 100 + SIM.coinbase_maturity - 1), 150)))


if __name__ == "__main__":
    unittest.main()
