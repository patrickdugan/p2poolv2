"""Tests for the M14 regtest batch (batch_signed.py).

Run from this directory: python3 -B -m unittest test_batch_signed
"""

import unittest

from batch_signed import BUYER_SLOTS, FEE_PAYEE, REFUNDS, SALE_SLOTS, build
from witness import field_id

P2TR_DUST = 330
MOVED = 10_000  # the tampered scenario's refund move (template.rs Kind::moved_sats)


def as_ints(value):
    return [as_ints(item) for item in value] if isinstance(value, list) else int(value)


class BatchSignedTests(unittest.TestCase):
    def setUp(self):
        spec, self.opening = build()
        self.spec = spec
        self.inputs = {key: as_ints(value) for key, value in spec["inputs"].items()}

    def test_every_slot_is_active_at_the_circuit_size(self):
        i = self.inputs
        self.assertEqual(len(i["price"]), SALE_SLOTS)
        self.assertEqual(len(i["funding"]), BUYER_SLOTS)
        self.assertEqual(sum(i["activeSale"]), SALE_SLOTS)
        self.assertEqual(sum(i["activeBuyer"]), BUYER_SLOTS)

    def test_signed_ids_are_the_field_encodings_of_the_labels_the_graph_pays(self):
        i = self.inputs
        for sale, slot in enumerate(self.opening["sale_slots"]):
            self.assertEqual(i["sellerPayoutId"][sale], field_id("seller_payout_script", slot["seller_payee"]))
            self.assertEqual(i["saleId"][sale], field_id("share_outpoint", slot["share_outpoint"]))
        for buyer, slot in enumerate(self.opening["buyer_slots"]):
            self.assertEqual(i["escrowId"][buyer], field_id("escrow_outpoint", slot["escrow"]))
            self.assertEqual(i["refundScriptId"][buyer], field_id("refund_script", slot["refund_payee"]))

    def test_payee_labels_are_distinct_so_every_output_is_its_own(self):
        labels = [s["seller_payee"] for s in self.opening["sale_slots"]]
        labels += [b["refund_payee"] for b in self.opening["buyer_slots"]] + [FEE_PAYEE]
        self.assertEqual(len(labels), len(set(labels)))

    def test_every_output_clears_the_dust_limit_and_the_money_balances(self):
        i = self.inputs
        outputs = list(i["price"]) + list(i["refund"]) + [sum(i["feeBudget"])]
        self.assertTrue(all(amount >= P2TR_DUST for amount in outputs), outputs)
        self.assertEqual(sum(outputs), sum(i["funding"]))
        self.assertEqual(list(i["refund"]), list(REFUNDS))

    def test_the_tampered_move_leaves_no_dust(self):
        i = self.inputs
        self.assertGreaterEqual(i["refund"][1] - MOVED, P2TR_DUST)

    def test_labels_name_one_key_per_slot(self):
        self.assertEqual(len(self.spec["sellerKeyLabels"]), SALE_SLOTS)
        self.assertEqual(len(self.spec["buyerKeyLabels"]), BUYER_SLOTS)


if __name__ == "__main__":
    unittest.main()
