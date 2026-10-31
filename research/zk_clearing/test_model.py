"""Dependency-free offline checks for the proposed clearing research model."""

import unittest
from dataclasses import replace

from model import Context, Escrow, InputState, InvalidBatch, Sale, plan_batch


class ClearingReferenceTests(unittest.TestCase):
    def setUp(self):
        self.context = Context("signet", "share-tip-A", "bitcoin-tip-B", 200)
        self.sale_a = Sale("share:0", "p2poolAlice", "btcAlice", "p2poolMM1", "mm1", 1500)
        self.sale_b = Sale("share:1", "p2poolBob", "btcBob", "p2poolMM2", "mm2", 2500)
        self.fund_a = Escrow("mm1", "btc:0", "btcRefund1", 2000, 100)
        self.fund_b = Escrow("mm2", "btc:1", "btcRefund2", 3000, 200)
        self.state = InputState(
            context=self.context,
            owners_by_outpoint={"share:0": "p2poolAlice", "share:1": "p2poolBob"},
            authorized_sales_by_outpoint={"share:0": self.sale_a, "share:1": self.sale_b},
            previously_cleared_outpoints=frozenset(),
            previously_used_escrows=frozenset(),
        )

    def plan(self, sales=None, escrows=None, state=None, expected=None, height=199):
        return plan_batch(
            (self.sale_a, self.sale_b) if sales is None else sales,
            (self.fund_a, self.fund_b) if escrows is None else escrows,
            self.state if state is None else state,
            self.context if expected is None else expected,
            height,
        )

    def test_happy_path_and_conservation(self):
        result = self.plan()
        self.assertEqual(result.payouts, (("btcAlice", 1500), ("btcBob", 2500)))
        self.assertEqual(result.refunds, (("btcRefund1", 400), ("btcRefund2", 300)))
        self.assertEqual(result.funding_sats, 5000)
        self.assertEqual(result.fee_budget_sats, 300)
        self.assertEqual(4000 + 700 + 300, result.funding_sats)

    def test_canonical_input_order(self):
        original = self.plan()
        reordered = self.plan(sales=(self.sale_b, self.sale_a), escrows=(self.fund_b, self.fund_a))
        self.assertEqual(original, reordered)

    def test_duplicate_share_rejected(self):
        with self.assertRaisesRegex(InvalidBatch, "duplicate share"):
            self.plan(sales=(self.sale_a, self.sale_a))

    def test_owner_mismatch_rejected(self):
        state = replace(self.state, owners_by_outpoint={"share:0": "differentOwner", "share:1": "p2poolBob"})
        with self.assertRaisesRegex(InvalidBatch, "owner"):
            self.plan(state=state)

    def test_modified_price_fails_authorization_match(self):
        tampered = replace(self.sale_a, price_sats=1700)
        with self.assertRaisesRegex(InvalidBatch, "authorization"):
            self.plan(sales=(tampered, self.sale_b))

    def test_unfunded_buyer_rejected(self):
        with self.assertRaisesRegex(InvalidBatch, "undercollateralized"):
            self.plan(escrows=(replace(self.fund_a, funding_sats=1599), self.fund_b))

    def test_duplicate_escrow_rejected(self):
        with self.assertRaisesRegex(InvalidBatch, "duplicate escrow outpoint"):
            self.plan(escrows=(self.fund_a, replace(self.fund_b, bitcoin_outpoint="btc:0")))

    def test_wrong_tip_rejected(self):
        expected = replace(self.context, sharechain_tip="reorged-tip")
        with self.assertRaisesRegex(InvalidBatch, "snapshot context"):
            self.plan(expected=expected)

    def test_expired_snapshot_rejected(self):
        with self.assertRaisesRegex(InvalidBatch, "expired"):
            self.plan(height=201)

    def test_previously_cleared_claim_rejected(self):
        state = replace(self.state, previously_cleared_outpoints=frozenset({"share:0"}))
        with self.assertRaisesRegex(InvalidBatch, "already cleared"):
            self.plan(state=state)

    def test_escrow_replay_rejected(self):
        state = replace(self.state, previously_used_escrows=frozenset({"btc:0"}))
        with self.assertRaisesRegex(InvalidBatch, "escrow reused"):
            self.plan(state=state)

    def test_negative_and_boolean_amounts_rejected(self):
        with self.assertRaisesRegex(InvalidBatch, "sale price"):
            self.plan(sales=(replace(self.sale_a, price_sats=-1), self.sale_b))
        with self.assertRaisesRegex(InvalidBatch, "sale price"):
            self.plan(sales=(replace(self.sale_a, price_sats=True), self.sale_b))

    def test_unused_funding_rejected(self):
        with self.assertRaisesRegex(InvalidBatch, "unused buyer escrow"):
            self.plan(sales=(self.sale_a,))

    def test_network_bound_into_commitment(self):
        other_context = replace(self.context, network="testnet4")
        other_state = replace(self.state, context=other_context)
        self.assertNotEqual(self.plan().commitment,
                            self.plan(state=other_state, expected=other_context).commitment)

    def test_escrow_fee_change_bound_into_commitment(self):
        other_escrow = replace(self.fund_a, fee_budget_sats=101)
        self.assertNotEqual(self.plan().commitment,
                            self.plan(escrows=(other_escrow, self.fund_b)).commitment)


if __name__ == "__main__":
    unittest.main()
