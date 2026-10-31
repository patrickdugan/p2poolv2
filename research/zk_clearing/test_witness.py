"""Offline tests of the 16-sale, four-buyer arithmetic relation and adapter."""

import copy
import json
import unittest
from dataclasses import replace

from model import Context, Escrow, InputState, InvalidBatch, Sale
from witness import BN254_FR, build_circuit_inputs, check_relation, encode_snarkjs_input


class CircuitInputTests(unittest.TestCase):
    def setUp(self):
        self.context = Context("signet", "share-tip", "bitcoin-tip", 100)
        self.sales = (
            Sale("s:2", "shareBob", "btcBob", "mm2Shares", "mm2", 900),
            Sale("s:1", "shareAlice", "btcAlice", "mm1Shares", "mm1", 1100),
        )
        self.escrows = (
            Escrow("mm2", "btc:2", "refundB", 1200, 70),
            Escrow("mm1", "btc:1", "refundA", 1500, 100),
        )
        self.state = InputState(
            context=self.context,
            owners_by_outpoint={sale.share_outpoint: sale.seller_share_address for sale in self.sales},
            authorized_sales_by_outpoint={sale.share_outpoint: sale for sale in self.sales},
            previously_cleared_outpoints=frozenset(),
            previously_used_escrows=frozenset(),
        )
        self.inputs, self.plan = build_circuit_inputs(
            self.sales, self.escrows, self.state, self.context, 99
        )

    def changed(self):
        return copy.deepcopy(self.inputs)

    def test_snarkjs_input_uses_strings_without_rounding(self):
        encoded = encode_snarkjs_input(self.inputs)
        decoded = json.loads(encoded)
        self.assertEqual(decoded["priceInverse"][0], str(self.inputs["priceInverse"][0]))
        self.assertIsInstance(decoded["selector"][0][0], str)
        self.assertEqual(decoded["totalPayout"], "2000")

    def test_valid_conservation_and_padding(self):
        check_relation(self.inputs)
        self.assertEqual(self.inputs["totalPayout"], 2000)
        self.assertEqual(self.inputs["funding"], [1500, 1200, 0, 0])
        self.assertEqual(self.inputs["refund"], [300, 230, 0, 0])
        self.assertEqual(self.inputs["activeSale"], [1, 1] + [0] * 14)
        self.assertEqual(self.inputs["activeBuyer"], [1, 1, 0, 0])

    def test_canonical_order_independent_of_input_order(self):
        other, other_plan = build_circuit_inputs(
            tuple(reversed(self.sales)), tuple(reversed(self.escrows)), self.state, self.context, 99
        )
        self.assertEqual(other, self.inputs)
        self.assertEqual(other_plan, self.plan)

    def test_wrong_funding_rejected(self):
        witness = self.changed()
        witness["funding"][0] += 1
        with self.assertRaisesRegex(InvalidBatch, "funding mismatch"):
            check_relation(witness)

    def test_double_buyer_assignment_rejected(self):
        witness = self.changed()
        witness["selector"][0][1] = 1
        with self.assertRaisesRegex(InvalidBatch, "one-hot"):
            check_relation(witness)

    def test_missing_buyer_assignment_rejected(self):
        witness = self.changed()
        witness["selector"][0][0] = 0
        with self.assertRaisesRegex(InvalidBatch, "one-hot"):
            check_relation(witness)

    def test_modified_sale_price_rejected(self):
        witness = self.changed()
        witness["price"][0] += 1
        with self.assertRaisesRegex(InvalidBatch, "inverse"):
            check_relation(witness)

    def test_zero_price_active_rejected(self):
        witness = self.changed()
        witness["price"][0] = 0
        with self.assertRaisesRegex(InvalidBatch, "inverse"):
            check_relation(witness)

    def test_padded_sale_with_price_rejected(self):
        witness = self.changed()
        witness["price"][15] = 1
        with self.assertRaisesRegex(InvalidBatch, "inactive sale"):
            check_relation(witness)

    def test_refund_changed_rejected(self):
        witness = self.changed()
        witness["refund"][0] = 301
        with self.assertRaisesRegex(InvalidBatch, "funding mismatch"):
            check_relation(witness)

    def test_large_amount_rejected(self):
        witness = self.changed()
        witness["funding"][0] = 2100000000000001
        with self.assertRaisesRegex(InvalidBatch, "amount out"):
            check_relation(witness)

    def test_negative_field_amount_rejected(self):
        witness = self.changed()
        witness["price"][0] = BN254_FR - 1
        with self.assertRaisesRegex(InvalidBatch, "amount out"):
            check_relation(witness)

    def test_selector_nonbinary_rejected(self):
        witness = self.changed()
        witness["selector"][0][0] = 2
        with self.assertRaisesRegex(InvalidBatch, "nonbinary"):
            check_relation(witness)

    def test_active_buyer_with_no_assigned_sales_rejected(self):
        witness = self.changed()
        witness["activeBuyer"][3] = 1
        with self.assertRaisesRegex(InvalidBatch, "buyer count inverse"):
            check_relation(witness)

    def test_buyer_count_inverse_mismatch_rejected(self):
        witness = self.changed()
        witness["buyerCountInverse"][0] = 0
        with self.assertRaisesRegex(InvalidBatch, "buyer count inverse"):
            check_relation(witness)

    def test_overflow_sale_count_rejected(self):
        extra_sales = tuple(replace(self.sales[0], share_outpoint=f"s-extra:{i}") for i in range(15))
        with self.assertRaisesRegex(InvalidBatch, "sale count"):
            build_circuit_inputs(self.sales + extra_sales, self.escrows, self.state, self.context, 99)

    def test_overflow_buyer_count_rejected(self):
        extra_escrows = tuple(replace(self.escrows[0], buyer_id=f"extra{i}") for i in range(3))
        with self.assertRaisesRegex(InvalidBatch, "buyer count"):
            build_circuit_inputs(self.sales, self.escrows + extra_escrows, self.state, self.context, 99)

    def test_modified_authorization_rejected_upstream_of_witness(self):
        sale = replace(self.sales[0], price_sats=901)
        with self.assertRaisesRegex(InvalidBatch, "authorization"):
            build_circuit_inputs((sale, self.sales[1]), self.escrows, self.state, self.context, 99)

    def test_replayed_share_rejected_upstream_of_witness(self):
        state = replace(self.state, previously_cleared_outpoints=frozenset({"s:1"}))
        with self.assertRaisesRegex(InvalidBatch, "already cleared"):
            build_circuit_inputs(self.sales, self.escrows, state, self.context, 99)

    def test_empty_sale_rejected_upstream_of_witness(self):
        with self.assertRaisesRegex(InvalidBatch, "empty batch"):
            build_circuit_inputs((), self.escrows, self.state, self.context, 99)

    def test_empty_buyer_rejected_upstream_of_witness(self):
        with self.assertRaisesRegex(InvalidBatch, "no escrow"):
            build_circuit_inputs(self.sales, (), self.state, self.context, 99)


if __name__ == "__main__":
    unittest.main()
