"""Tests of the tree with registered owners: a leaf's owner is the registered order key hash.

Run from the repository root:

    python3 -m unittest discover -s research/zk_clearing/ownership

Without a registry the tree is the M5 tree (the other test files pin that). Here: with one, an
address that registered an order key has that key hash as the owner of its outputs, any other
address keeps its address id, which outputs are in the tree does not change, and the incremental
accumulator agrees with the snapshot, including across a rotation.
"""

import hashlib
import random
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import real_store  # noqa: E402
import register  # noqa: E402
import smt  # noqa: E402
from utxo_set import Accumulator, ChainParams, SharechainUtxo, Tx, share_coinbase  # noqa: E402

SMALL = ChainParams(coinbase_maturity=3, payout_depth=10, expiry_margin=2, max_depth=12)
ALICE, BOB, CAROL = "p2pool1alice", "p2pool1bob", "p2pool1carol"
KEY_HASH = {ALICE: 1111, BOB: 2222}


def chain(model, upto: int, owners=(ALICE, BOB, CAROL)) -> None:
    for height in range(model.tip + 1, upto + 1):
        model.apply_block(height, [share_coinbase(f"cb{height:05d}", owners[height % len(owners)])])


class OwnerFieldTests(unittest.TestCase):
    def test_a_registered_address_gets_its_key_hash_and_others_their_address_id(self):
        self.assertEqual(smt.owner_field(ALICE, KEY_HASH), 1111)
        self.assertEqual(smt.owner_field(CAROL, KEY_HASH), smt.owner_id(CAROL))
        self.assertEqual(smt.owner_field(ALICE, None), smt.owner_id(ALICE))
        self.assertEqual(smt.owner_field(ALICE, {}), smt.owner_id(ALICE))

    def test_the_two_owner_spaces_do_not_overlap_in_practice(self):
        # An address id is a 253-bit SHA-256 truncation; a key hash is a Poseidon output.
        self.assertNotEqual(smt.owner_id(ALICE), smt.poseidon2(5, 6))


class TreeWithRegistryTests(unittest.TestCase):
    def setUp(self):
        self.model = SharechainUtxo(SMALL)
        chain(self.model, 40)
        self.anchor = 40

    def values(self, tree):
        return dict(tree.items())

    def test_no_registry_and_an_empty_registry_give_the_m5_tree(self):
        plain = self.model.build_tree(self.anchor)
        self.assertEqual(self.model.build_tree(self.anchor, None).root, plain.root)
        self.assertEqual(self.model.build_tree(self.anchor, {}).root, plain.root)
        for output in self.model.snapshot(self.anchor):
            self.assertEqual(plain.get(output.key), output.value)
            self.assertEqual(
                plain.get(output.key),
                smt.leaf_value(smt.owner_id(output.owner), output.units, output.root_height),
            )

    def test_registered_outputs_carry_the_key_hash_and_the_rest_keep_the_address_id(self):
        tree = self.model.build_tree(self.anchor, KEY_HASH)
        seen = set()
        for output in self.model.snapshot(self.anchor):
            owner = KEY_HASH.get(output.owner, smt.owner_id(output.owner))
            self.assertEqual(tree.get(output.key), smt.leaf_value(owner, output.units, output.root_height))
            seen.add(output.owner)
        self.assertEqual(seen, {ALICE, BOB, CAROL})

    def test_the_registry_changes_the_values_and_not_the_set(self):
        plain = self.model.build_tree(self.anchor)
        registered = self.model.build_tree(self.anchor, KEY_HASH)
        self.assertNotEqual(registered.root, plain.root)
        self.assertEqual(sorted(k for k, _ in registered.items()), sorted(k for k, _ in plain.items()))
        carol = [o for o in self.model.snapshot(self.anchor) if o.owner == CAROL]
        self.assertTrue(carol)
        for output in carol:
            self.assertEqual(registered.get(output.key), plain.get(output.key))
        alice = [o for o in self.model.snapshot(self.anchor) if o.owner == ALICE]
        for output in alice:
            self.assertNotEqual(registered.get(output.key), plain.get(output.key))

    def test_a_proof_names_the_registered_key_hash_and_no_other_owner(self):
        tree = self.model.build_tree(self.anchor, KEY_HASH)
        output = next(o for o in self.model.snapshot(self.anchor) if o.owner == ALICE)
        proof = tree.prove(output.key)
        self.assertTrue(smt.verify_membership(tree.root, proof))
        for wrong_owner in (smt.owner_id(ALICE), KEY_HASH[BOB], 1112):
            forged = smt.MembershipProof(
                proof.key, smt.leaf_value(wrong_owner, output.units, output.root_height), proof.siblings
            )
            self.assertFalse(smt.verify_membership(tree.root, forged), wrong_owner)

    def test_real_store_leaves_use_the_registry(self):
        output = next(o for o in self.model.snapshot(self.anchor) if o.owner == ALICE)
        self.assertEqual(real_store.leaf_of(output).owner, smt.owner_id(ALICE))
        self.assertEqual(real_store.leaf_of(output, KEY_HASH).owner, 1111)
        self.assertEqual(real_store.leaf_of(output, KEY_HASH).value, output.value_for(KEY_HASH))


class AccumulatorWithRegistryTests(unittest.TestCase):
    def random_block(self, rng, accumulator, height):
        owners = (ALICE, BOB, CAROL)
        txs = [share_coinbase(f"cb{height:05d}", rng.choice(owners))]
        spendable = [
            o for o in accumulator.model.outputs.values()
            if o.owner is not None and accumulator.model.spend_error(o.outpoint, height) is None
        ]
        rng.shuffle(spendable)
        for index in range(rng.choice((0, 1, 2))):
            if spendable:
                pick = spendable.pop()
                outputs = tuple((rng.choice(owners), 1000 + n) for n in range(rng.choice((1, 2))))
                txs.append(Tx(f"t{height:05d}-{index}", inputs=(pick.outpoint,), outputs=outputs))
        return txs

    def assert_equals_snapshot(self, accumulator):
        expected = accumulator.model.build_tree(accumulator.anchor, accumulator.registry)
        self.assertEqual(accumulator.root, expected.root)
        self.assertEqual(sorted(accumulator.tree.items()), sorted(expected.items()))

    def test_incremental_tree_equals_the_snapshot_with_a_registry(self):
        rng = random.Random(2026)
        accumulator = Accumulator(SMALL, KEY_HASH)
        for height in range(0, 45):
            accumulator.apply_block(height, self.random_block(rng, accumulator, height))
            self.assert_equals_snapshot(accumulator)
        self.assertGreater(accumulator.inserts, 30)

    def test_the_default_accumulator_is_unchanged(self):
        rng = random.Random(7)
        accumulator = Accumulator(SMALL)
        for height in range(0, 30):
            accumulator.apply_block(height, self.random_block(rng, accumulator, height))
        self.assertEqual(accumulator.root, accumulator.model.build_tree(accumulator.anchor).root)
        self.assertEqual(accumulator.updates, 0)

    def test_rotating_a_key_rewrites_the_address_leaves_and_matches_the_snapshot(self):
        rng = random.Random(11)
        accumulator = Accumulator(SMALL, KEY_HASH)
        for height in range(0, 30):
            accumulator.apply_block(height, self.random_block(rng, accumulator, height))
        before = accumulator.root
        tracked = [o for o in accumulator.tracked_outputs() if o.owner == ALICE]
        self.assertTrue(tracked)
        proof_before, output = accumulator.prove(tracked[0].outpoint)

        rewritten = accumulator.set_owner_key(ALICE, 3333)
        self.assertEqual(rewritten, len(tracked))
        self.assertNotEqual(accumulator.root, before)
        self.assert_equals_snapshot(accumulator)
        self.assertEqual(accumulator.registry[ALICE], 3333)

        # The old key hash no longer proves ownership; the new one does.
        proof_after, _ = accumulator.prove(output.outpoint)
        self.assertEqual(proof_after.value, smt.leaf_value(3333, output.units, output.root_height))
        self.assertTrue(smt.verify_membership(accumulator.root, proof_after))
        self.assertFalse(smt.verify_membership(accumulator.root, proof_before))

        # Blocks after the rotation insert leaves with the new owner.
        for height in range(30, 40):
            accumulator.apply_block(height, self.random_block(rng, accumulator, height))
            self.assert_equals_snapshot(accumulator)

    def test_unregistering_returns_the_address_id(self):
        rng = random.Random(3)
        registered, plain = Accumulator(SMALL, {ALICE: 5}), Accumulator(SMALL)
        for height in range(0, 25):
            txs = self.random_block(rng, registered, height)
            registered.apply_block(height, txs)
            plain.apply_block(height, txs)
        self.assertNotEqual(registered.root, plain.root)
        registered.set_owner_key(ALICE, None)
        self.assertEqual(registered.root, plain.root)

    def test_registering_an_address_with_no_tracked_output_rewrites_nothing(self):
        accumulator = Accumulator(SMALL)
        self.assertEqual(accumulator.set_owner_key(ALICE, 9), 0)


class RegistryToTreeTests(unittest.TestCase):
    """Real registrations (BIP340 over real share addresses) drive the owners of the tree."""

    def test_registrations_set_the_owner_and_a_rotation_replaces_it(self):
        secrets = {
            name: (int.from_bytes(hashlib.sha256(f"registered owners/{name}".encode()).digest(), "big") % (register.N - 1) + 1).to_bytes(32, "big")
            for name in ("alice", "bob", "carol")
        }
        address = {name: smt.share_address(register.pubkey_gen(sk), "regtest") for name, sk in secrets.items()}
        registry = register.Registry("regtest")
        registry.add(register.sign_registration(secrets["alice"], "regtest", 71, 1, bytes(32)))
        registry.add(register.sign_registration(secrets["bob"], "regtest", 72, 1, bytes(32)))

        model = SharechainUtxo(SMALL)
        chain(model, 30, owners=tuple(address[name] for name in ("alice", "bob", "carol")))
        tree = model.build_tree(30, registry.owners())
        for output in model.snapshot(30):
            expected_owner = {address["alice"]: 71, address["bob"]: 72}.get(output.owner, smt.owner_id(output.owner))
            self.assertEqual(tree.get(output.key), smt.leaf_value(expected_owner, output.units, output.root_height))

        registry.add(register.sign_registration(secrets["alice"], "regtest", 73, 2, bytes(32)))
        rotated = model.build_tree(30, registry.owners())
        self.assertNotEqual(rotated.root, tree.root)
        alice_output = next(o for o in model.snapshot(30) if o.owner == address["alice"])
        self.assertEqual(
            rotated.get(alice_output.key), smt.leaf_value(73, alice_output.units, alice_output.root_height)
        )

    def test_an_empty_registry_gives_the_plain_tree(self):
        registry = register.Registry("regtest")
        self.assertEqual(registry.owners(), {})
        model = SharechainUtxo(SMALL)
        chain(model, 20)
        self.assertEqual(model.build_tree(20, registry.owners()).root, model.build_tree(20).root)


if __name__ == "__main__":
    unittest.main()
