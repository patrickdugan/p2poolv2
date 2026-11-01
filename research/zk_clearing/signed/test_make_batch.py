"""Tests for the M4 batch spec (the signing itself is exercised by run.sh)."""

import unittest

from make_batch import BATCH_HEIGHT, FEE_CAP_MARGIN, batch_spec


class BatchSpecTests(unittest.TestCase):
    def setUp(self):
        self.spec = batch_spec()
        self.inputs = self.spec["inputs"]

    def test_terms_fill_active_slots_only(self):
        active_sales = [i for i, flag in enumerate(self.inputs["activeSale"]) if flag == "1"]
        active_buyers = [i for i, flag in enumerate(self.inputs["activeBuyer"]) if flag == "1"]
        for index, label in enumerate(self.spec["sellerKeyLabels"]):
            self.assertEqual(label is not None, index in active_sales)
            self.assertEqual(self.inputs["sellerPayoutId"][index] != "0", index in active_sales)
        for index, label in enumerate(self.spec["buyerKeyLabels"]):
            self.assertEqual(label is not None, index in active_buyers)
            self.assertEqual(self.inputs["escrowId"][index] != "0", index in active_buyers)

    def test_fee_cap_covers_fee_budget(self):
        for budget, cap, active in zip(self.inputs["feeBudget"], self.inputs["feeCap"], self.inputs["activeBuyer"]):
            if active == "1":
                self.assertEqual(int(cap), int(budget) + FEE_CAP_MARGIN)

    def test_expiries_are_not_before_the_batch(self):
        self.assertEqual(self.inputs["batchHeight"], str(BATCH_HEIGHT))
        for expiry, active in zip(self.inputs["orderExpiry"], self.inputs["activeSale"]):
            if active == "1":
                self.assertGreaterEqual(int(expiry), BATCH_HEIGHT)

    def test_resplit_keeps_public_totals(self):
        resplit = batch_spec(resplit=True)["inputs"]
        for key in ("funding", "feeBudget", "refund", "totalPayout"):
            self.assertEqual(resplit[key], self.inputs[key], key)
        self.assertNotEqual(resplit["saleId"], self.inputs["saleId"])

    def test_explicit_sales_replace_the_example_sales(self):
        from model import Sale
        from witness import field_id

        sales = (
            Sale("aa:0", "shareAddressX", "btcX", "exampleBuyerShare1", "buyer1", 1200),
            Sale("bb:1", "shareAddressY", "btcY", "exampleBuyerShare2", "buyer2", 1800),
        )
        spec = batch_spec(sales=sales)
        self.assertEqual(
            spec["inputs"]["saleId"][:2],
            [str(field_id("share_outpoint", "aa:0")), str(field_id("share_outpoint", "bb:1"))],
        )
        self.assertEqual(spec["sellerKeyLabels"][:2], ["shareAddressX", "shareAddressY"])
        self.assertEqual(spec["inputs"]["totalPayout"], "3000")
        self.assertEqual(batch_spec(sales=None), batch_spec())


if __name__ == "__main__":
    unittest.main()
