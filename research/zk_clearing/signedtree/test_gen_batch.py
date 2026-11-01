"""Tests for the signed-tree batch generator."""

import copy
import unittest

from gen_batch import BATCH_HEIGHT, batch_spec, check, with_signed_terms
from gen_inputs import batch


def as_ints(value):
    return [as_ints(item) for item in value] if isinstance(value, list) else int(value)


def spec_inputs(sales, buyers, variant="valid"):
    return {key: as_ints(value) for key, value in batch_spec(sales, buyers, variant)["inputs"].items()}


class GenBatchTests(unittest.TestCase):
    def test_every_slot_is_active_and_the_rules_hold_at_every_size(self):
        for sales, buyers in ((16, 4), (64, 8), (128, 8)):
            inputs = spec_inputs(sales, buyers)
            check(inputs)
            self.assertEqual(sum(inputs["activeSale"]), sales)
            self.assertEqual(sum(inputs["activeBuyer"]), buyers)
            self.assertEqual(inputs["batchHeight"], BATCH_HEIGHT)

    def test_every_field_the_circuit_reads_is_present_with_the_right_length(self):
        inputs = spec_inputs(64, 8)
        per_sale = ("price", "activeSale", "priceInverse", "selector", "saleId", "sellerId", "sellerPayoutId", "orderExpiry")
        per_buyer = ("funding", "feeBudget", "refund", "buyerId", "activeBuyer", "buyerCountInverse",
                     "escrowId", "feeCap", "refundScriptId", "escrowExpiry")
        for name in per_sale:
            self.assertEqual(len(inputs[name]), 64, name)
        for name in per_buyer:
            self.assertEqual(len(inputs[name]), 8, name)

    def test_labels_name_one_key_per_active_slot(self):
        spec = batch_spec(64, 8)
        self.assertEqual(len(spec["sellerKeyLabels"]), 64)
        self.assertEqual(len(spec["buyerKeyLabels"]), 8)
        self.assertNotIn(None, spec["sellerKeyLabels"] + spec["buyerKeyLabels"])
        self.assertEqual(len(set(spec["buyerKeyLabels"])), 8)

    def test_deterministic(self):
        self.assertEqual(batch_spec(64, 8), batch_spec(64, 8))

    def test_valid_prices_match_the_scaling_batch(self):
        self.assertEqual(spec_inputs(64, 8)["price"], batch(64, 8)["price"])

    def test_resplit_swaps_two_sale_ids_and_keeps_the_public_totals(self):
        valid, resplit = spec_inputs(16, 4), spec_inputs(16, 4, "resplit")
        self.assertEqual(resplit["saleId"][0], valid["saleId"][1])
        self.assertEqual(resplit["saleId"][1], valid["saleId"][0])
        for name in ("funding", "feeBudget", "refund", "totalPayout", "price"):
            self.assertEqual(valid[name], resplit[name], name)

    def test_padded_variant_leaves_a_quarter_of_the_sales_and_one_buyer_unused(self):
        spec = batch_spec(16, 4, "padded")
        inputs = {key: as_ints(value) for key, value in spec["inputs"].items()}
        check(inputs)
        self.assertEqual(sum(inputs["activeSale"]), 12)
        self.assertEqual(sum(inputs["activeBuyer"]), 3)
        self.assertEqual(spec["sellerKeyLabels"][12:], [None] * 4)
        self.assertIsNone(spec["buyerKeyLabels"][3])
        self.assertEqual(inputs["funding"][3], 0)
        self.assertEqual(inputs["buyerId"][3], 0)

    def test_fee_over_cap_fails_the_check(self):
        inputs = copy.deepcopy(spec_inputs(16, 4))
        inputs["feeBudget"][0] = inputs["feeCap"][0] + 1
        with self.assertRaises(AssertionError):
            check(inputs)

    def test_expired_order_fails_the_check(self):
        inputs = copy.deepcopy(spec_inputs(16, 4))
        inputs["orderExpiry"][0] = BATCH_HEIGHT - 1
        with self.assertRaises(AssertionError):
            check(inputs)

    def test_funding_mismatch_fails_the_check(self):
        inputs = copy.deepcopy(spec_inputs(16, 4))
        inputs["funding"][0] += 1
        with self.assertRaises(AssertionError):
            check(inputs)

    def test_rejects_sizes_that_are_not_powers_of_two(self):
        with self.assertRaises(ValueError):
            batch_spec(48, 4)

    def test_unknown_variant_is_refused(self):
        with self.assertRaises(ValueError):
            batch_spec(16, 4, "other")

    def test_signed_terms_helper_marks_inactive_slots_with_no_label(self):
        merged, sellers, buyers = with_signed_terms(batch(16, 4))
        self.assertNotIn(None, sellers + buyers)
        self.assertEqual(len(merged["sellerPayoutId"]), 16)


if __name__ == "__main__":
    unittest.main()
