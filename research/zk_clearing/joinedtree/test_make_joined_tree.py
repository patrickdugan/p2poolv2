"""Tests of the joined signed-tree fixtures' world: registry, both trees, the sold outputs, and
each variant's witness and predicted refusal.

Run from the repository root:

    python3 -m unittest discover -s research/zk_clearing/joinedtree

The order-key hashes come from BabyJubjub in joined/sign_joined.js. Here a stand-in Poseidon hash
of the label plays that role, so everything that does not need EdDSA runs in pure Python. The
circuits themselves are exercised by run_size.sh.
"""

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import make_joined_tree as mjt  # noqa: E402
import smt  # noqa: E402
import window_tree as wt  # noqa: E402


def stand_in_key_hashes() -> dict:
    return {
        label: str(smt.poseidon2(int.from_bytes(hashlib.sha256(label.encode()).digest(), "big") >> 3, 1))
        for label in mjt.labels()
    }


def as_ints(value):
    if isinstance(value, dict):
        return {key: as_ints(item) for key, item in value.items()}
    return [as_ints(item) for item in value] if isinstance(value, list) else int(value)


MEMBERSHIP_TEMPLATES = {mjt.SALE, mjt.LEVEL, mjt.ORDER, mjt.SMT}


class WorldTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key_hashes = stand_in_key_hashes()
        cls.world = mjt.build_world(cls.key_hashes)

    def test_the_labels_cover_every_miner_and_the_intruder(self):
        labels = mjt.labels()
        self.assertEqual(len(labels), len(set(labels)))
        for name in mjt.mj.MINERS:
            self.assertIn(mjt.mj.address_of(name), labels)
        self.assertIn(mjt.mj.MALLORY_LABEL, labels)

    def test_every_miner_but_zed_is_registered(self):
        owners = self.world.registry.owners()
        self.assertEqual(set(owners), {mjt.mj.address_of(name) for name in mjt.REGISTERED})
        self.assertNotIn(mjt.mj.address_of("zed"), owners)
        for registration in self.world.registrations:
            self.assertTrue(mjt.register.verify_registration(registration))

    def test_the_two_trees_hold_the_same_set_here_and_a_window_leaf_carries_the_owner(self):
        world = self.world
        self.assertEqual(set(world.window.keys), {key for key, _ in world.smt_tree.items()})
        self.assertEqual(world.window.keys, sorted(world.window.keys))
        owners = world.registry.owners()
        for output, leaf in zip(world.window_outputs, world.window.leaves):
            self.assertEqual(leaf.owner, smt.owner_field(output.owner, owners))
            self.assertEqual(world.smt_tree.get(output.key), smt.leaf_value(leaf.owner, leaf.units, leaf.root_height))

    def test_there_are_enough_sellable_outputs_for_a_64_slot_batch(self):
        self.assertGreaterEqual(len(self.world.sellable), 65)
        owners = self.world.registry.owners()
        for output in self.world.sellable:
            self.assertIn(output.owner, owners)

    def test_the_named_outputs_are_outside_the_window_or_unregistered(self):
        world = self.world
        out = world.outputs
        self.assertIn(out["D_spent"].outpoint, world.model.spent_at)
        for name in ("D_spent", "expired", "immature"):
            self.assertNotIn(out[name].key, world.window, name)
            self.assertNotIn(out[name].key, world.smt_tree, name)
        zed = out["Z0"]
        self.assertIn(zed.key, world.window)
        self.assertEqual(world.window.leaves[world.window.position_of(zed.key)].owner, smt.owner_id(zed.owner))

    def test_the_circuits_depths_hold_the_world(self):
        self.assertLessEqual(max(self.world.smt_tree.leaf_depths()), mjt.SMT_LEVELS - 1)
        self.assertLessEqual(len(self.world.window), self.world.window.capacity)
        self.assertEqual(self.world.window.levels, wt.PRODUCTION_LEVELS[1])


class VariantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key_hashes = stand_in_key_hashes()
        cls.worlds = {1: mjt.build_world(cls.key_hashes, 1), 3: mjt.build_world(cls.key_hashes, 3)}

    def each(self):
        for membership, radix_bits in (("window", 1), ("window", 3), ("smt", 1)):
            for sales, buyers in ((16, 4), (32, 8)):
                world = self.worlds[radix_bits]
                yield membership, radix_bits, sales, buyers, world, mjt.variants(world, membership, sales, buyers)

    def test_every_invalid_variant_is_refused_where_the_python_model_says(self):
        for membership, bits, sales, buyers, world, items in self.each():
            for variant in items:
                _, predicted = mjt.witness_for(world, membership, variant)
                want = [variant.rejected_in] if variant.rejected_in in MEMBERSHIP_TEMPLATES else []
                self.assertEqual(predicted, want, (membership, bits, sales, variant.name))

    def test_the_accepted_variants_pass_every_membership_and_order_rule(self):
        for membership, bits, sales, buyers, world, items in self.each():
            for variant in items:
                if variant.rejected_in is None:
                    _, predicted = mjt.witness_for(world, membership, variant)
                    self.assertEqual(predicted, [], (membership, bits, sales, variant.name))

    def test_the_variant_names_and_kinds(self):
        window = {v.name: v for v in mjt.variants(self.worlds[1], "window", 16, 4)}
        sparse = {v.name: v for v in mjt.variants(self.worlds[1], "smt", 16, 4)}
        for name in ("valid", "resplit", "padded"):
            self.assertIn(name, window)
            self.assertIn(name, sparse)
        for name in ("position_disagrees_with_path", "member_leaf_at_wrong_position", "duplicate_output_two_slots",
                     "slots_out_of_position_order", "hole_in_active_slots", "wrong_window_root"):
            self.assertEqual(window[name].kind, "invalid")
        self.assertNotIn("slots_out_of_position_order", sparse)
        self.assertIn("wrong_utxo_root", sparse)
        # M5's tree cannot refuse a repeated output; the fixture records that it is accepted.
        self.assertEqual(sparse["duplicate_output_two_slots"].kind, "valid_extra")
        self.assertIsNone(sparse["duplicate_output_two_slots"].rejected_in)
        for variants in (window, sparse):
            self.assertEqual(variants["statement_hash_omits_root"].rejected_in, mjt.HASH)
            self.assertEqual(variants["bad_order_signature"].rejected_in, mjt.EDDSA)

    def test_every_spec_keeps_the_v1_relation_and_the_m4_term_rules(self):
        for membership, bits, sales, buyers, world, items in self.each():
            for variant in items:
                mjt.gen_batch.check(as_ints(variant.spec["inputs"]))

    def test_the_valid_batch_sells_the_lowest_positions_in_order(self):
        for membership, bits, sales, buyers, world, items in self.each():
            valid = items[0].spec
            keys = [int(key) for key in valid["inputs"]["saleId"]]
            self.assertEqual(keys, [o.key for o in world.sellable[:sales]])
            positions = [world.window.position_of(key) for key in keys]
            self.assertEqual(positions, sorted(positions))
            self.assertEqual(len(set(positions)), sales)
            self.assertEqual(valid["sellerKeyLabels"], [o.owner for o in world.sellable[:sales]])

    def test_the_resplit_batch_has_the_same_prices_and_other_outputs(self):
        world = self.worlds[1]
        items = {v.name: v for v in mjt.variants(world, "window", 16, 4)}
        self.assertEqual(items["resplit"].spec["inputs"]["totalPayout"], items["valid"].spec["inputs"]["totalPayout"])
        self.assertNotEqual(items["resplit"].spec["inputs"]["saleId"], items["valid"].spec["inputs"]["saleId"])

    def test_the_valid_witness_proves_the_signed_leaf_at_the_stored_position(self):
        world = self.worlds[1]
        valid = mjt.variants(world, "window", 16, 4)[0]
        witness, _ = mjt.window_witness(world, valid.spec)
        self.assertEqual(int(witness["windowRoot"]), world.window.root)
        for slot, output in enumerate(world.sellable[:16]):
            owner = int(self.key_hashes[output.owner])
            leaf = wt.leaf_hash(output.key, owner, output.units, output.root_height)
            self.assertEqual(int(witness["units"][slot]), output.units)
            self.assertEqual(int(witness["rootHeight"][slot]), output.root_height)
            children = tuple(tuple(int(c) for c in group) for group in witness["children"][slot])
            path = wt.WindowPath(int(witness["position"][slot]), children)
            self.assertEqual(wt.root_from_path(leaf, path, 1), world.window.root)
            self.assertEqual(path.position, world.window.position_of(output.key))

    def test_the_duplicate_variant_names_one_output_twice_and_the_hole_has_an_unused_slot_inside(self):
        world = self.worlds[1]
        items = {v.name: v for v in mjt.variants(world, "window", 16, 4)}
        ids = items["duplicate_output_two_slots"].spec["inputs"]["saleId"]
        self.assertEqual(ids[3], ids[4])
        active = items["hole_in_active_slots"].spec["inputs"]["activeSale"]
        first_unused = active.index("0")
        self.assertIn("1", active[first_unused:])
        swapped = [int(k) for k in items["slots_out_of_position_order"].spec["inputs"]["saleId"]]
        self.assertGreater(swapped[3], swapped[4])

    def test_rows_move_together_when_permuted(self):
        world = self.worlds[1]
        valid = mjt.variants(world, "window", 16, 4)[0].spec
        order = list(reversed(range(16)))
        flipped = mjt.permuted(valid, order)
        for key in mjt.SALE_ROW_KEYS:
            self.assertEqual(flipped["inputs"][key], list(reversed(valid["inputs"][key])))
        self.assertEqual(flipped["inputs"]["selector"], list(reversed(valid["inputs"]["selector"])))
        self.assertEqual(flipped["sellerKeyLabels"], list(reversed(valid["sellerKeyLabels"])))

    def test_non_members_sort_after_members_and_take_the_first_free_positions(self):
        world = self.worlds[1]
        items = {v.name: v for v in mjt.variants(world, "window", 16, 4)}
        for name in ("output_spent_before_anchor", "output_expired", "output_immature"):
            spec = items[name].spec
            keys = [int(k) for k in spec["inputs"]["saleId"]]
            self.assertEqual(sum(1 for k in keys if k not in world.window), 1)
            self.assertNotIn(keys[-1], world.window)
            witness, _ = mjt.window_witness(world, spec)
            self.assertEqual(int(witness["position"][-1]), len(world.window))

    def test_the_build_is_deterministic_and_writes_every_file(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            for directory in (first, second):
                mjt.build(self.key_hashes, Path(directory), "window", 16, 4)
            manifest = json.loads((Path(first) / "variants" / "manifest.json").read_text())
            names = [entry["name"] for entry in manifest]
            self.assertEqual(len(names), len(set(names)))
            for name in names:
                for suffix in ("spec", "own"):
                    one = (Path(first) / "variants" / f"{name}.{suffix}.json").read_text()
                    two = (Path(second) / "variants" / f"{name}.{suffix}.json").read_text()
                    self.assertEqual(one, two, name)
            world = json.loads((Path(first) / "world.json").read_text())
            self.assertEqual(world["window_tree"]["levels"], 17)
            self.assertEqual(world["root"], world["window_tree"]["root"])
            self.assertTrue(all(entry["predicted"] == ([entry["rejectedIn"]] if entry["rejectedIn"] in MEMBERSHIP_TEMPLATES else [])
                                for entry in manifest))
        with tempfile.TemporaryDirectory() as directory:
            mjt.build(self.key_hashes, Path(directory), "smt", 16, 4)
            world = json.loads((Path(directory) / "world.json").read_text())
            self.assertEqual(world["root"], world["smt"]["root"])


if __name__ == "__main__":
    unittest.main()
