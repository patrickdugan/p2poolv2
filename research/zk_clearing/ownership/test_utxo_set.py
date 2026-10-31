"""Tests of the UTXO-set definition and the incremental accumulator.

Run from the repository root:

    python3 -m unittest discover -s research/zk_clearing/ownership

The small parameters below play the role of the Rust sim build (`cfg(feature = "sim")`),
which shrinks COINBASE_MATURITY and PPLNS_WINDOW_SHARES so rules are reachable in a short run.
"""

import random
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import smt  # noqa: E402
import utxo_set  # noqa: E402
from utxo_set import Accumulator, ChainParams, ConsensusError, SharechainUtxo, Tx, share_coinbase  # noqa: E402

# maturity 3, payout depth 10 (so a window of 7), margin 2.
SMALL = ChainParams(coinbase_maturity=3, payout_depth=10, expiry_margin=2, max_depth=12)
ALICE, BOB, CAROL = "p2pool1alice", "p2pool1bob", "p2pool1carol"


def coinbase(height: int, owner: str = ALICE) -> Tx:
    return share_coinbase(f"cb{height:05d}", owner)


def run_chain(model, upto: int, owner: str = ALICE) -> None:
    for height in range(model.tip + 1, upto + 1):
        model.apply_block(height, [coinbase(height, owner)])


class SpendRuleTests(unittest.TestCase):
    """The rules of `check_prevouts` (store/transaction_store.rs) and `validate_prevouts`."""

    def setUp(self):
        self.model = SharechainUtxo(SMALL)
        run_chain(self.model, 20)

    def spend(self, height: int, source_height: int, vout: int = 0) -> Tx:
        return Tx(f"spend{height}-{source_height}", inputs=((f"cb{source_height:05d}", vout),), outputs=((BOB, 100_000_000),))

    def test_coinbase_maturity_boundary(self):
        # Coinbase at height 10 is spendable by a block at height 13 (depth 3), not at 12.
        self.assertEqual(self.model.spend_error(("cb00010", 0), 12), "immature coinbase")
        self.assertIsNone(self.model.spend_error(("cb00010", 0), 13))

    def test_expiry_boundary(self):
        # root 5, payout depth 10: a block at height 15 may spend it, one at 16 may not.
        self.assertIsNone(self.model.spend_error(("cb00005", 0), 15))
        self.assertEqual(self.model.spend_error(("cb00005", 0), 16), "coinbase root too old")

    def test_expiry_saturates_near_genesis(self):
        self.assertIsNone(self.model.spend_error(("cb00000", 0), 10))
        self.assertEqual(self.model.spend_error(("cb00000", 0), 11), "coinbase root too old")

    def test_op_return_output_is_a_real_outpoint_but_never_a_leaf(self):
        self.assertIn(("cb00010", 1), self.model.outputs)
        self.assertNotIn(("cb00010", 1), {o.outpoint for o in self.model.snapshot(20)})

    def test_double_spend_and_missing_output(self):
        self.model.apply_block(21, [coinbase(21), self.spend(21, 12)])
        with self.assertRaises(ConsensusError):
            self.model.apply_block(22, [coinbase(22), self.spend(22, 12)])
        model = SharechainUtxo(SMALL)
        run_chain(model, 5)
        with self.assertRaises(ConsensusError):
            model.apply_block(6, [coinbase(6), Tx("x", inputs=(("nope", 0),), outputs=((BOB, 1),))])

    def test_two_inputs_naming_one_outpoint_in_a_block_are_refused(self):
        twice = Tx("dup", inputs=(("cb00012", 0), ("cb00012", 0)), outputs=((BOB, 1),))
        with self.assertRaises(ConsensusError):
            self.model.apply_block(21, [coinbase(21), twice])

    def test_a_block_may_spend_an_output_created_earlier_in_the_same_block(self):
        parent = self.spend(21, 12)
        child = Tx("child", inputs=((parent.txid, 0),), outputs=((CAROL, 100_000_000),))
        self.model.apply_block(21, [coinbase(21), parent, child])
        self.assertIn((parent.txid, 0), self.model.spent_at)

    def test_derived_outputs_inherit_the_oldest_root_and_expire_with_it(self):
        # Spend coinbase roots 11 and 12 together at height 21: the new output has root 11.
        merge = Tx("merge", inputs=(("cb00011", 0), ("cb00012", 0)), outputs=((BOB, 200_000_000),))
        self.model.apply_block(21, [coinbase(21), merge])
        self.assertEqual(self.model.outputs[("merge", 0)].root_height, 11)
        self.assertFalse(self.model.outputs[("merge", 0)].is_coinbase)
        self.assertIsNone(self.model.spend_error(("merge", 0), 21))  # not a coinbase: no maturity
        self.assertEqual(self.model.spend_error(("merge", 0), 22), "coinbase root too old")

    def test_blocks_must_extend_the_tip(self):
        with self.assertRaises(ConsensusError):
            self.model.apply_block(25, [coinbase(25)])


class SetDefinitionTests(unittest.TestCase):
    def test_a_coinbase_output_is_in_the_set_for_exactly_the_window_of_anchors(self):
        model = SharechainUtxo(SMALL)
        run_chain(model, 40)
        # In the set iff anchor >= r + maturity - 1 and anchor <= r + payout - margin - 1.
        root = 12
        lo = root + SMALL.coinbase_maturity - 1
        hi = root + SMALL.payout_depth - SMALL.expiry_margin - 1
        membership = {anchor: (f"cb{root:05d}", 0) in {o.outpoint for o in model.snapshot(anchor)} for anchor in range(root, 40)}
        self.assertEqual([a for a, inside in membership.items() if inside], list(range(lo, hi + 1)))

    def test_everything_in_the_set_is_spendable_with_margin_blocks_to_spare(self):
        model = SharechainUtxo(SMALL)
        run_chain(model, 40)
        for anchor in range(0, 40):
            for output in model.snapshot(anchor):
                self.assertIsNone(model.spend_error(output.outpoint, anchor + 1))
                self.assertIsNone(model.spend_error(output.outpoint, anchor + 1 + SMALL.expiry_margin))

    def test_every_spendable_unspent_tracked_output_is_in_the_set_or_inside_the_margin(self):
        model = SharechainUtxo(SMALL)
        run_chain(model, 40)
        for anchor in range(0, 40):
            in_set = {o.outpoint for o in model.snapshot(anchor)}
            lower, _ = SMALL.window(anchor)
            for output in model.outputs.values():
                if output.owner is None or output.order[0] > anchor:
                    continue
                if model.spend_error(output.outpoint, anchor + 1) is not None:
                    continue
                if output.outpoint in in_set:
                    continue
                self.assertLess(output.root_height, lower)  # excluded only by the expiry margin

    def test_a_spent_output_leaves_the_set_at_the_spending_anchor(self):
        model = SharechainUtxo(SMALL)
        run_chain(model, 20)
        victim = ("cb00015", 0)
        self.assertIn(victim, {o.outpoint for o in model.snapshot(20)})
        model.apply_block(21, [coinbase(21), Tx("sell", inputs=(victim,), outputs=((BOB, 100_000_000),))])
        self.assertIn(victim, {o.outpoint for o in model.snapshot(20)})  # history is stable
        self.assertNotIn(victim, {o.outpoint for o in model.snapshot(21)})
        self.assertIn(("sell", 0), {o.outpoint for o in model.snapshot(21)})

    def test_the_slot_rule_keeps_the_oldest_output(self):
        tight = ChainParams(coinbase_maturity=1, payout_depth=40, expiry_margin=0, max_depth=3)
        model = SharechainUtxo(tight)
        run_chain(model, 30)
        kept = model.snapshot(30)
        slots = [o.key & 0b111 for o in kept]
        self.assertEqual(len(slots), len(set(slots)))
        self.assertLessEqual(len(kept), 8)
        for output in model.eligible(30):
            winner = next(o for o in kept if o.key & 0b111 == output.key & 0b111)
            self.assertLessEqual(winner.order, output.order)

    def test_the_dust_floor_leaves_small_outputs_out(self):
        floor = ChainParams(coinbase_maturity=3, payout_depth=10, expiry_margin=2, max_depth=12, min_units=1000)
        accumulator = Accumulator(floor)
        for height in range(0, 12):
            txs = [coinbase(height)]
            if height == 8:
                txs.append(Tx("split", inputs=(("cb00005", 0),), outputs=((BOB, 999), (CAROL, 1000), (None, 5))))
            accumulator.apply_block(height, txs)
        tracked = {o.outpoint for o in accumulator.tracked_outputs()}
        self.assertIn(("split", 1), tracked)
        self.assertNotIn(("split", 0), tracked)
        self.assertEqual(tracked, {o.outpoint for o in accumulator.model.snapshot(11)})

    def test_the_production_parameters(self):
        production = utxo_set.PRODUCTION
        self.assertEqual(production.payout_depth, production.coinbase_maturity + 120_960)
        lower, upper = production.window(1_000_000)
        self.assertEqual(upper - lower + 1, 127_008 - 6048 - 1008 + 1)
        self.assertEqual(utxo_set.SHARE_UNITS, 100_000_000)


class AccumulatorTests(unittest.TestCase):
    def random_block(self, rng, accumulator, height):
        txs = [coinbase(height, rng.choice((ALICE, BOB, CAROL)))]
        spendable = [
            o for o in accumulator.model.outputs.values()
            if o.owner is not None and accumulator.model.spend_error(o.outpoint, height) is None
        ]
        rng.shuffle(spendable)
        used = set()
        for index in range(rng.choice((0, 1, 2, 3))):
            if not spendable:
                break
            inputs = []
            for _ in range(rng.choice((1, 1, 2))):
                if spendable:
                    pick = spendable.pop()
                    inputs.append(pick.outpoint)
                    used.add(pick.outpoint)
            fan_out = rng.choice((1, 1, 2, 3))
            outputs = tuple((rng.choice((ALICE, BOB, CAROL, None)), 1000 + n) for n in range(fan_out))
            txs.append(Tx(f"t{height:05d}-{index}", inputs=tuple(inputs), outputs=outputs))
        # Sometimes spend an output created by an earlier transaction of this block.
        if len(txs) >= 2 and rng.random() < 0.3 and txs[1].outputs and txs[1].outputs[0][0] is not None:
            txs.append(Tx(f"chain{height:05d}", inputs=((txs[1].txid, 0),), outputs=((BOB, 5),)))
        return txs

    def check_equal_to_snapshot(self, accumulator):
        expected = accumulator.model.build_tree(accumulator.anchor)
        self.assertEqual(accumulator.root, expected.root)
        self.assertEqual(
            {o.outpoint for o in accumulator.tracked_outputs()},
            {o.outpoint for o in accumulator.model.snapshot(accumulator.anchor)},
        )
        self.assertEqual(len(accumulator), len(expected))

    def test_incremental_tree_equals_the_snapshot_after_every_block(self):
        rng = random.Random(2026)
        accumulator = Accumulator(SMALL)
        for height in range(0, 45):
            accumulator.apply_block(height, self.random_block(rng, accumulator, height))
            self.check_equal_to_snapshot(accumulator)
        self.assertGreater(accumulator.inserts, 30)
        self.assertGreater(accumulator.deletes, 15)

    def test_incremental_tree_equals_the_snapshot_when_slots_collide(self):
        # 8 slots for far more live outputs: the slot rule decides almost everything.
        crowded = ChainParams(coinbase_maturity=2, payout_depth=14, expiry_margin=1, max_depth=3)
        rng = random.Random(99)
        accumulator = Accumulator(crowded)
        for height in range(0, 40):
            accumulator.apply_block(height, self.random_block(rng, accumulator, height))
            self.check_equal_to_snapshot(accumulator)
        self.assertLessEqual(len(accumulator), 8)

    def test_membership_proof_of_a_tracked_output_verifies_against_the_root(self):
        accumulator = Accumulator(SMALL)
        for height in range(0, 20):
            accumulator.apply_block(height, [coinbase(height, ALICE if height % 2 else BOB)])
        output = accumulator.tracked_outputs()[0]
        proof, same = accumulator.prove(output.outpoint)
        self.assertIs(same, output)
        self.assertTrue(smt.verify_membership(accumulator.root, proof))
        self.assertEqual(proof.key, smt.outpoint_id(*output.outpoint))
        self.assertEqual(proof.value, smt.leaf_value(smt.owner_id(output.owner), output.units, output.root_height))

    def test_the_owner_of_the_proof_is_the_owner_of_the_output(self):
        accumulator = Accumulator(SMALL)
        for height in range(0, 20):
            accumulator.apply_block(height, [coinbase(height, ALICE if height % 2 else BOB)])
        output = accumulator.tracked_outputs()[0]
        proof, _ = accumulator.prove(output.outpoint)
        other = BOB if output.owner == ALICE else ALICE
        forged = smt.MembershipProof(
            proof.key, smt.leaf_value(smt.owner_id(other), output.units, output.root_height), proof.siblings
        )
        self.assertFalse(smt.verify_membership(accumulator.root, forged))

    def test_a_block_that_breaks_a_rule_changes_nothing(self):
        accumulator = Accumulator(SMALL)
        for height in range(0, 10):
            accumulator.apply_block(height, [coinbase(height)])
        root = accumulator.root
        with self.assertRaises(ConsensusError):
            accumulator.apply_block(10, [coinbase(10), Tx("bad", inputs=(("cb00009", 0),), outputs=((BOB, 1),))])
        self.assertEqual(accumulator.root, root)


if __name__ == "__main__":
    unittest.main()
