"""Tests of the dense window tree (M15): hashes against circomlibjs, the tree's shape and rules,
the forgeries a prover can attempt, and its relation to M5's set.

Run from the repository root:

    python3 -m unittest discover -s research/zk_clearing/ownership

`window_vectors.json` holds outputs of the pinned circomlibjs (Poseidon with 4 and 8 inputs, and
dense trees built with its Poseidon), written by `gen_window_vectors.js`. The circuit itself is
exercised by `joinedtree/run_size.sh`.
"""

import json
import random
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import smt  # noqa: E402
import window_tree as wt  # noqa: E402
from utxo_set import ChainParams, SharechainUtxo, share_coinbase  # noqa: E402

VECTORS = json.loads((HERE / "window_vectors.json").read_text())
P = smt.FIELD


def leaves_of(entry) -> list:
    return [
        wt.WindowLeaf(int(l["key"]), int(l["owner"]), int(l["units"]), int(l["rootHeight"]))
        for l in entry["leaves"]
    ]


def small_tree(radix_bits=1, levels=4, count=11, seed=3):
    rng = random.Random(seed)
    keys = sorted({rng.getrandbits(200) + 1 for _ in range(count)})
    assert len(keys) == count
    leaves = [wt.WindowLeaf(key, rng.getrandbits(250), rng.randrange(1, 10**8), rng.randrange(10**5)) for key in keys]
    return wt.WindowTree(leaves, radix_bits, levels), leaves


class WidePoseidonTests(unittest.TestCase):
    def test_four_and_eight_inputs_match_circomlibjs(self):
        for vector in VECTORS["poseidon"]:
            inputs = [int(x) for x in vector["inputs"]]
            expected = int(vector["out"])
            self.assertEqual(smt.poseidon_n(inputs), expected, vector["inputs"])
            self.assertEqual(smt.poseidon_reference(inputs), expected, vector["inputs"])

    def test_narrow_widths_take_the_unrolled_paths_and_agree(self):
        rng = random.Random(5)
        a, b, c = (rng.getrandbits(253) for _ in range(3))
        self.assertEqual(smt.poseidon_n([a, b]), smt.poseidon2(a, b))
        self.assertEqual(smt.poseidon_n([a, b, c]), smt.poseidon3(a, b, c))

    def test_a_width_without_constants_is_refused(self):
        with self.assertRaises(ValueError):
            smt.poseidon_n([1])
        with self.assertRaises(ValueError):
            smt.poseidon_n([1] * 5)

    def test_wide_calls_are_counted_by_width(self):
        smt.reset_hash_counts()
        smt.poseidon_n([1, 2, 3, 4])
        smt.poseidon_n([1, 2, 3, 4])
        smt.poseidon_n([1] * 8)
        self.assertEqual(smt.WIDE_HASH_COUNTS, {4: 2, 8: 1})

    def test_the_sparse_tree_counter_is_unchanged(self):
        smt.reset_hash_counts()
        smt.poseidon2(1, 2)
        self.assertEqual(smt.HASH_COUNTS, {"poseidon2": 1, "poseidon3": 0})


class CircomlibjsTreeTests(unittest.TestCase):
    def test_every_vector_tree_has_the_same_leaf_hashes_root_and_paths(self):
        for entry in VECTORS["trees"]:
            with self.subTest(entry["name"]):
                tree = wt.WindowTree(leaves_of(entry), entry["radixBits"], entry["levels"])
                self.assertEqual([leaf.hash for leaf in tree.leaves], [int(h) for h in entry["leafHashes"]])
                self.assertEqual(tree.root, int(entry["root"]))
                for probe in entry["paths"]:
                    path = tree.path(probe["position"])
                    self.assertEqual(
                        [list(map(int, group)) for group in probe["children"]],
                        [list(group) for group in path.children],
                        f"position {probe['position']}",
                    )
                    leaf = path.children[0][path.digits(tree.radix_bits)[0]]
                    self.assertEqual(wt.root_from_path(leaf, path, tree.radix_bits), tree.root)

    def test_the_vectors_cover_both_radices_empty_and_full_trees_and_the_production_depth(self):
        shapes = {(e["radixBits"], e["levels"], len(e["leaves"])) for e in VECTORS["trees"]}
        self.assertIn((1, 3, 0), shapes)
        self.assertIn((1, 4, 16), shapes)
        self.assertIn((1, 17, 9), shapes)
        self.assertTrue(any(bits == 3 for bits, _, _ in shapes))
        self.assertTrue(any(bits == 2 for bits, _, _ in shapes))


class TreeRuleTests(unittest.TestCase):
    def test_an_empty_tree_has_the_root_of_empty_nodes(self):
        tree = wt.WindowTree([], 1, 3)
        node = 0
        for _ in range(3):
            node = smt.poseidon2(node, node)
        self.assertEqual(tree.root, node)
        self.assertEqual(len(tree), 0)

    def test_production_levels_hold_the_production_window(self):
        self.assertGreaterEqual(2 ** wt.PRODUCTION_LEVELS[1], 119_953)
        self.assertLess(2 ** (wt.PRODUCTION_LEVELS[1] - 1), 119_953)
        self.assertGreaterEqual(8 ** wt.PRODUCTION_LEVELS[3], 119_953)
        self.assertLess(8 ** (wt.PRODUCTION_LEVELS[3] - 1), 119_953)

    def test_keys_must_ascend_strictly(self):
        low, high = wt.WindowLeaf(5, 1, 1, 1), wt.WindowLeaf(9, 1, 1, 1)
        wt.WindowTree([low, high], 1, 2)
        with self.assertRaises(wt.KeysNotAscending):
            wt.WindowTree([high, low], 1, 2)
        with self.assertRaises(wt.KeysNotAscending):
            wt.WindowTree([low, low], 1, 2)

    def test_capacity_is_enforced(self):
        leaves = [wt.WindowLeaf(key, 1, 1, 1) for key in range(1, 6)]
        with self.assertRaises(wt.CapacityExceeded):
            wt.WindowTree(leaves, 1, 2)
        wt.WindowTree(leaves, 1, 3)
        wt.WindowTree(leaves, 3, 1)  # radix 8, one level: 8 positions

    def test_leaf_fields_must_be_canonical_field_elements(self):
        for fields in ((P, 1, 1, 1), (1, P, 1, 1), (1, 1, -1, 1), (1, 1, 1, P + 1)):
            with self.assertRaises(wt.WindowTreeError):
                wt.leaf_hash(*fields)

    def test_positions_are_ranks_and_keys_are_found_by_binary_search(self):
        tree, leaves = small_tree()
        for rank, leaf in enumerate(leaves):
            self.assertEqual(tree.position_of(leaf.key), rank)
            self.assertIn(leaf.key, tree)
        self.assertIsNone(tree.position_of(leaves[0].key - 1))
        self.assertNotIn(leaves[-1].key + 1, tree)

    def test_digits_are_little_endian_base_r(self):
        self.assertEqual(wt.digits_of(0b1011, 1, 4), [1, 1, 0, 1])
        self.assertEqual(wt.digits_of(0o3210, 3, 4), [0, 1, 2, 3])
        with self.assertRaises(wt.WindowTreeError):
            wt.digits_of(16, 1, 4)
        with self.assertRaises(wt.WindowTreeError):
            wt.digits_of(-1, 1, 4)

    def test_every_leaf_proves_and_a_wrong_fact_does_not(self):
        for radix_bits, levels in ((1, 5), (2, 3), (3, 2)):
            tree, leaves = small_tree(radix_bits, levels, count=11 if radix_bits == 1 else 20)
            for leaf in leaves:
                _, path = tree.prove(leaf.key)
                self.assertTrue(tree.verify(leaf, path))
            leaf = leaves[4]
            _, path = tree.prove(leaf.key)
            for wrong in (
                wt.WindowLeaf(leaf.key + 1, leaf.owner, leaf.units, leaf.root_height),
                wt.WindowLeaf(leaf.key, leaf.owner + 1, leaf.units, leaf.root_height),
                wt.WindowLeaf(leaf.key, leaf.owner, leaf.units + 1, leaf.root_height),
                wt.WindowLeaf(leaf.key, leaf.owner, leaf.units, leaf.root_height + 1),
            ):
                self.assertFalse(tree.verify(wrong, path))

    def test_an_empty_position_proves_the_empty_leaf_and_no_real_leaf(self):
        tree, leaves = small_tree(1, 4, 11)
        empty = tree.path(13)
        self.assertEqual(wt.root_from_path(0, empty, 1), tree.root)
        self.assertFalse(tree.verify(leaves[0], empty))

    def test_a_path_of_another_position_does_not_verify_the_leaf(self):
        tree, leaves = small_tree(1, 4, 11)
        _, path = tree.prove(leaves[3].key)
        moved = wt.WindowPath(path.position ^ 1, path.children)
        self.assertFalse(tree.verify(leaves[3], moved))
        with self.assertRaises(wt.PathMismatch):
            wt.root_from_path(leaves[3].hash, moved, 1)

    def test_a_tampered_sibling_changes_the_root(self):
        tree, leaves = small_tree(1, 4, 11)
        _, path = tree.prove(leaves[3].key)
        for level in range(4):
            digit = path.digits(1)[level]
            groups = [list(group) for group in path.children]
            groups[level][1 - digit] += 1
            forged = wt.WindowPath(path.position, tuple(map(tuple, groups)))
            self.assertFalse(tree.verify(leaves[3], forged), f"level {level}")

    def test_the_running_hash_must_sit_at_the_digit(self):
        tree, leaves = small_tree(3, 2, 20)
        _, path = tree.prove(leaves[7].key)
        digit = path.digits(3)[0]
        groups = [list(group) for group in path.children]
        groups[0][(digit + 1) % 8], groups[0][digit] = groups[0][digit], groups[0][(digit + 1) % 8]
        with self.assertRaises(wt.PathMismatch):
            wt.root_from_path(leaves[7].hash, wt.WindowPath(path.position, tuple(map(tuple, groups))), 3)
        short = wt.WindowPath(path.position, ((path.children[0][0],), path.children[1]))
        with self.assertRaises(wt.WindowTreeError):
            wt.root_from_path(leaves[7].hash, short, 3)

    def test_a_spliced_forgery_passes_every_selection_check_and_fails_the_root(self):
        tree, leaves = small_tree(1, 5, 11)
        fake = wt.WindowLeaf(leaves[2].key + 1, leaves[2].owner, leaves[2].units, leaves[2].root_height)
        for position in (2, 6, 20):
            forged = tree.spliced_path(position, fake.hash)
            digits = forged.digits(1)
            running = fake.hash
            for level, group in enumerate(forged.children):
                self.assertEqual(group[digits[level]], running)
                running = smt.poseidon_n(group)
            self.assertEqual(wt.root_from_path(fake.hash, forged, 1), running)
            self.assertNotEqual(running, tree.root)
            self.assertFalse(tree.verify(fake, forged))

    def test_splicing_the_stored_leaf_gives_the_real_path(self):
        tree, leaves = small_tree(2, 3, 20)
        for rank in (0, 9, 19):
            self.assertEqual(tree.spliced_path(rank, leaves[rank].hash), tree.path(rank))

    def test_proof_size_counts_the_siblings(self):
        tree, leaves = small_tree(1, 17, 9)
        self.assertEqual(tree.path(3).size_bytes(1), 32 * 17)
        wide, _ = small_tree(3, 6, 5)
        self.assertEqual(wide.path(3).size_bytes(3), 32 * 6 * 7)
        self.assertEqual(len(tree.path(3).siblings(1)), 17)

    def test_hash_count_is_the_stored_nodes(self):
        tree, _ = small_tree(1, 4, 16)
        self.assertEqual(tree.hash_count(), 16 + 8 + 4 + 2 + 1)
        smt.reset_hash_counts()
        wt.WindowTree([wt.WindowLeaf(k, 1, 1, 1) for k in range(1, 17)], 1, 4)
        calls = smt.WIDE_HASH_COUNTS.get(4, 0), smt.HASH_COUNTS["poseidon2"]
        # 16 leaves, 4 zero-subtree nodes, 15 nodes above the leaves
        self.assertEqual(calls, (16, 4 + 15))

    def test_order_rule_wants_a_prefix_of_active_slots_with_rising_positions(self):
        self.assertTrue(wt.check_ascending([3, 9, 10, 0], [1, 1, 1, 0]))
        self.assertTrue(wt.check_ascending([0, 0, 0], [0, 0, 0]))
        self.assertFalse(wt.check_ascending([3, 3, 10], [1, 1, 1]))  # the same output twice
        self.assertFalse(wt.check_ascending([9, 3, 10], [1, 1, 1]))  # out of order
        self.assertFalse(wt.check_ascending([3, 0, 10], [1, 0, 1]))  # a hole
        self.assertFalse(wt.check_ascending([3, 9], [0, 1]))  # padding first


SMALL = ChainParams(coinbase_maturity=3, payout_depth=40, expiry_margin=2, max_depth=3)
ALICE, BOB, CAROL = "p2pool1alice", "p2pool1bob", "p2pool1carol"


def model_to(height: int) -> SharechainUtxo:
    model = SharechainUtxo(SMALL)
    owners = (ALICE, BOB, CAROL)
    for h in range(height + 1):
        model.apply_block(h, [share_coinbase(f"cb{h:05d}", owners[h % 3])])
    return model


class SharechainSetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = model_to(100)
        cls.anchor = 100

    def test_the_set_is_m5s_eligible_set_sorted_by_key(self):
        outputs = wt.window_outputs(self.model, self.anchor)
        self.assertEqual({o.outpoint for o in outputs}, {o.outpoint for o in self.model.eligible(self.anchor)})
        keys = [o.key for o in outputs]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual(len(keys), len(set(keys)))
        lower, upper = SMALL.window(self.anchor)
        self.assertEqual(len(outputs), upper - lower + 1)
        for output in outputs:
            self.assertTrue(lower <= output.root_height <= upper)

    def test_the_slot_rule_drops_outputs_that_the_window_tree_keeps(self):
        window = {o.outpoint for o in wt.window_outputs(self.model, self.anchor)}
        sparse = {o.outpoint for o in self.model.snapshot(self.anchor)}
        self.assertTrue(sparse < window)
        self.assertGreater(len(window - sparse), 0)
        mask = (1 << SMALL.max_depth) - 1
        by_slot = {}
        for output in wt.window_outputs(self.model, self.anchor):
            by_slot.setdefault(output.key & mask, []).append(output)
        losers = {o.outpoint for group in by_slot.values() for o in sorted(group, key=lambda o: o.order)[1:]}
        self.assertEqual(window - sparse, losers)

    def test_immature_and_expired_outputs_are_not_leaves(self):
        outputs = {o.outpoint for o in wt.window_outputs(self.model, self.anchor)}
        lower, upper = SMALL.window(self.anchor)
        for output in self.model.outputs.values():
            if output.owner is None:
                continue
            in_window = lower <= output.root_height <= upper
            self.assertEqual(output.outpoint in outputs, in_window, output.outpoint)

    def test_a_spent_output_is_not_a_leaf(self):
        from utxo_set import Tx

        model = model_to(100)
        victim = next(o for o in model.eligible(100) if o.is_coinbase and o.root_height == 80)
        model.apply_block(101, [
            share_coinbase("cb00101", BOB),
            Tx("spend101", inputs=(victim.outpoint,), outputs=((CAROL, 100_000_000),)),
        ])
        before = {o.outpoint for o in wt.window_outputs(model, 100)}
        after = {o.outpoint for o in wt.window_outputs(model, 101)}
        self.assertIn(victim.outpoint, before)
        self.assertNotIn(victim.outpoint, after)
        self.assertIn(("spend101", 0), after)

    def test_leaves_carry_the_registered_key_hash_or_the_address_id(self):
        registry = {ALICE: 12345}
        tree, outputs = wt.build_window_tree(self.model, self.anchor, registry, 1, 7)
        for position, output in enumerate(outputs):
            leaf = tree.leaves[position]
            self.assertEqual(leaf.key, output.key)
            self.assertEqual(leaf.owner, 12345 if output.owner == ALICE else smt.owner_id(output.owner))
            self.assertEqual((leaf.units, leaf.root_height), (output.units, output.root_height))

    def test_the_registry_changes_the_values_and_not_the_positions(self):
        plain, outputs = wt.build_window_tree(self.model, self.anchor, None, 1, 7)
        registered, same = wt.build_window_tree(self.model, self.anchor, {BOB: 777}, 1, 7)
        self.assertEqual([o.outpoint for o in outputs], [o.outpoint for o in same])
        self.assertEqual(plain.keys, registered.keys)
        self.assertNotEqual(plain.root, registered.root)

    def test_the_tree_is_a_function_of_the_set(self):
        first, _ = wt.build_window_tree(self.model, self.anchor, None, 1, 7)
        second, _ = wt.build_window_tree(model_to(100), self.anchor, None, 1, 7)
        self.assertEqual(first.root, second.root)
        wide, _ = wt.build_window_tree(self.model, self.anchor, None, 3, 3)
        self.assertNotEqual(first.root, wide.root)

    def test_a_set_past_capacity_is_refused(self):
        with self.assertRaises(wt.CapacityExceeded):
            wt.build_window_tree(self.model, self.anchor, None, 1, 4)

    def test_every_output_proves_membership_in_the_chain_tree(self):
        tree, outputs = wt.build_window_tree(self.model, self.anchor, {ALICE: 1}, 3, 3)
        for output in outputs:
            leaf, path = tree.prove(output.key)
            self.assertEqual(leaf, wt.leaf_of(output, {ALICE: 1}))
            self.assertTrue(tree.verify(leaf, path))


if __name__ == "__main__":
    unittest.main()
