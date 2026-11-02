"""Tests for the M17 regtest batch (batch_joined.py).

Run from this directory, in its own process (batch_signed.py and the joined fixtures both import a module
named gen_inputs): python3 -B -m unittest test_batch_joined

The joined fixture's world is built with a stand-in key hash per order-key label (as
joinedtree/test_make_joined_tree.py does), which is all the batch's amounts, heights, labels and
window root depend on.
"""

import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "joinedtree"))

import batch_joined as bj  # noqa: E402
import make_joined_tree as mjt  # noqa: E402
import smt  # noqa: E402
from witness import field_id  # noqa: E402

P2TR_DUST = 330


def as_ints(value):
    return [as_ints(item) for item in value] if isinstance(value, list) else int(value)


class BatchJoinedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        key_hashes = {
            label: str(smt.poseidon2(int.from_bytes(hashlib.sha256(label.encode()).digest(), "big") >> 3, 1))
            for label in mjt.labels()
        }
        cls.tmp = tempfile.TemporaryDirectory()
        cls.work = pathlib.Path(cls.tmp.name) / "work"
        mjt.build(key_hashes, cls.work, "packed", bj.SALE_SLOTS, bj.BUYER_SLOTS)
        cls.out = pathlib.Path(cls.tmp.name) / "batch"
        sys.argv = ["batch_joined.py", str(cls.work), str(cls.out)]
        bj.main()
        cls.spec = json.loads((cls.out / "variants" / "valid.spec.json").read_text())
        cls.opening = json.loads((cls.out / "opening.json").read_text())
        cls.world = json.loads((cls.work / "world.json").read_text())
        cls.inputs = {key: as_ints(value) for key, value in cls.spec["inputs"].items()}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_the_opening_carries_the_window_root_of_the_world(self):
        self.assertEqual(self.opening["window_root"], self.world["window_tree"]["root"])
        self.assertEqual(self.opening["window_root"], self.world["root"])

    def test_the_height_is_one_the_regtest_chain_reaches_and_the_expiries_clear_the_circuit(self):
        i = self.inputs
        self.assertEqual(i["batchHeight"], bj.BATCH_HEIGHT)
        self.assertGreater(bj.BATCH_HEIGHT - 3, 200)
        for expiry in i["escrowExpiry"]:
            self.assertEqual(expiry, bj.BATCH_HEIGHT + 27)
            self.assertGreaterEqual(expiry, bj.BATCH_HEIGHT + bj.ESCROW_AFTER_BATCH)
        for expiry in i["orderExpiry"]:
            self.assertGreaterEqual(expiry, bj.BATCH_HEIGHT + bj.DEADLINE_AFTER_BATCH)

    def test_every_output_clears_the_dust_limit_and_the_money_balances(self):
        i = self.inputs
        outputs = list(i["price"]) + list(i["refund"]) + [sum(i["feeBudget"])]
        self.assertTrue(all(amount >= P2TR_DUST for amount in outputs), outputs)
        self.assertEqual(sum(outputs), sum(i["funding"]))
        self.assertEqual(list(i["refund"]), list(bj.REFUNDS))
        for buyer in range(bj.BUYER_SLOTS):
            cost = sum(i["price"][s] for s in range(bj.SALE_SLOTS) if i["selector"][s][buyer])
            self.assertEqual(i["funding"][buyer], cost + i["feeBudget"][buyer] + i["refund"][buyer])

    def test_signed_ids_are_the_field_encodings_of_the_labels_the_graph_pays(self):
        i = self.inputs
        for sale, slot in enumerate(self.opening["sale_slots"]):
            self.assertEqual(i["sellerPayoutId"][sale], field_id("seller_payout_script", slot["seller_payee"]))
        for buyer, slot in enumerate(self.opening["buyer_slots"]):
            self.assertEqual(i["escrowId"][buyer], field_id("escrow_outpoint", slot["escrow"]))
            self.assertEqual(i["refundScriptId"][buyer], field_id("refund_script", slot["refund_payee"]))

    def test_the_sale_slots_sell_the_tree_in_position_order(self):
        # The membership witness is the fixture's, untouched: the same positions, rising.
        own = json.loads((self.work / "variants" / "valid.own.json").read_text())
        positions = [int(p) for p in own["position"]]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(len(set(positions)), len(positions))
        self.assertEqual(own["windowRoot"], self.world["window_tree"]["root"])

    def test_the_manifest_has_the_one_valid_variant(self):
        manifest = json.loads((self.out / "variants" / "manifest.json").read_text())
        self.assertEqual([m["name"] for m in manifest], ["valid"])
        self.assertEqual(manifest[0]["post"], [])


if __name__ == "__main__":
    unittest.main()
