"""Tests for the Groth16 pipeline's Python side: field, identities, fixtures, wtns."""

import copy
import os
import tempfile
import unittest

from example_inputs import example_circuit_inputs, resplit_sales
from fixtures import invalid_fixtures
from model import InvalidBatch
from witness import (
    BN254_FR,
    BUYER_SLOTS,
    SALE_SLOTS,
    check_committed_relation,
    field_id,
)
from wtns import Witness, read_wtns, write_wtns

# BN254 curve parameter u. For BN curves the base field is
# q = 36u^4 + 36u^3 + 24u^2 + 6u + 1 and the group order (Circom's scalar
# field) is r = 36u^4 + 36u^3 + 18u^2 + 6u + 1.
BN_U = 4965661367192848881


class FieldTests(unittest.TestCase):
    def test_field_is_the_bn254_scalar_field_not_the_base_field(self):
        r = 36 * BN_U**4 + 36 * BN_U**3 + 18 * BN_U**2 + 6 * BN_U + 1
        q = 36 * BN_U**4 + 36 * BN_U**3 + 24 * BN_U**2 + 6 * BN_U + 1
        self.assertEqual(BN254_FR, r)
        self.assertNotEqual(BN254_FR, q)

    def test_inverses_hold_in_the_scalar_field(self):
        inputs = example_circuit_inputs()
        for price, inverse, active in zip(inputs["price"], inputs["priceInverse"], inputs["activeSale"]):
            self.assertEqual(price * inverse % BN254_FR, active)

    def test_field_id_is_nonzero_and_below_the_prime(self):
        element = field_id("share_outpoint", "example-share:0")
        self.assertGreater(element, 0)
        self.assertLess(element, BN254_FR)
        self.assertNotEqual(element, field_id("share_outpoint", "example-share:1"))
        self.assertNotEqual(element, field_id("seller_share_address", "example-share:0"))


class CommittedInputTests(unittest.TestCase):
    def setUp(self):
        self.inputs = example_circuit_inputs(committed=True)

    def test_identities_fill_active_slots_only(self):
        active_sales = sum(self.inputs["activeSale"])
        self.assertEqual(sum(1 for value in self.inputs["saleId"] if value), active_sales)
        self.assertEqual(sum(1 for value in self.inputs["sellerId"] if value), active_sales)
        self.assertEqual(
            sum(1 for value in self.inputs["buyerId"] if value), sum(self.inputs["activeBuyer"])
        )
        self.assertEqual(len(self.inputs["saleId"]), SALE_SLOTS)
        self.assertEqual(len(self.inputs["buyerId"]), BUYER_SLOTS)

    def test_padding_slot_with_identity_rejected(self):
        inputs = copy.deepcopy(self.inputs)
        inputs["saleId"][SALE_SLOTS - 1] = 7
        with self.assertRaisesRegex(InvalidBatch, "padding sale slot"):
            check_committed_relation(inputs)

    def test_unused_escrow_with_identity_rejected(self):
        inputs = copy.deepcopy(self.inputs)
        inputs["buyerId"][BUYER_SLOTS - 1] = 7
        with self.assertRaisesRegex(InvalidBatch, "unused escrow slot"):
            check_committed_relation(inputs)

    def test_resplit_keeps_public_totals_but_changes_sale_list(self):
        resplit = example_circuit_inputs(committed=True, sales=resplit_sales())
        for key in ("funding", "feeBudget", "refund", "totalPayout", "buyerId"):
            self.assertEqual(resplit[key], self.inputs[key], key)
        self.assertNotEqual(resplit["price"], self.inputs["price"])
        self.assertNotEqual(resplit["saleId"], self.inputs["saleId"])


class FixtureTests(unittest.TestCase):
    def test_each_invalid_fixture_differs_from_valid(self):
        for committed in (False, True):
            valid = example_circuit_inputs(committed=committed)
            fixtures = invalid_fixtures(valid)
            self.assertEqual(len(fixtures), 17 if committed else 14)
            for name, inputs in fixtures.items():
                self.assertNotEqual(inputs, valid, name)


class WtnsTests(unittest.TestCase):
    def test_round_trip(self):
        witness = Witness(prime=BN254_FR, values=[1, 5, BN254_FR - 1, 0])
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "w.wtns")
            write_wtns(path, witness)
            again = read_wtns(path)
        self.assertEqual(again.prime, BN254_FR)
        self.assertEqual(again.values, witness.values)


if __name__ == "__main__":
    unittest.main()
