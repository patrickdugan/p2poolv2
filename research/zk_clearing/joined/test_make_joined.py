"""Tests of the joined fixtures' world: registry, trees, sold outputs and each variant's predicted outcome.

Run from the repository root:

    python3 -m unittest discover -s research/zk_clearing/joined

The order-key hashes come from BabyJubjub in sign_joined.js. Here a stand-in Poseidon hash of the
label plays that role, so everything that does not need EdDSA runs in pure Python. The circuit
itself is exercised by run.sh.
"""

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import make_joined as mj  # noqa: E402
import smt  # noqa: E402


def stand_in_key_hashes() -> dict:
    return {
        label: str(smt.poseidon2(int.from_bytes(hashlib.sha256(label.encode()).digest(), "big") >> 3, 1))
        for label in mj.labels()
    }


class JoinedWorldTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key_hashes = stand_in_key_hashes()
        cls.world = mj.build_world(cls.key_hashes)
        cls.variants = {variant.name: variant for variant in mj.variants(cls.world)}

    def test_the_labels_cover_every_registered_key_a_rotation_and_the_intruder(self):
        labels = mj.labels()
        self.assertEqual(len(labels), len(set(labels)))
        for name in (*mj.REGISTERED, "zed"):
            self.assertIn(mj.address_of(name), labels)
        self.assertIn(mj.address_of("alice") + "#2", labels)
        self.assertIn(mj.MALLORY_LABEL, labels)

    def test_addresses_are_share_addresses_of_the_demo_bip340_keys(self):
        for name in mj.MINERS:
            network, output_key = smt.decode_share_address(mj.address_of(name))
            self.assertEqual(network, mj.NETWORK)
            self.assertEqual(output_key, mj.register.pubkey_gen(mj.bip340_secret(name)))

    def test_every_registration_verifies_and_only_the_registered_addresses_are_in_the_registry(self):
        for registration in self.world.registrations:
            self.assertTrue(mj.register.verify_registration(registration))
        owners = self.world.registry2.owners()
        self.assertEqual(set(owners), {mj.address_of(name) for name in mj.REGISTERED})
        self.assertNotIn(mj.address_of("zed"), owners)

    def test_the_rotation_changes_alices_entry_only(self):
        first, second = self.world.registry1.owners(), self.world.registry2.owners()
        alice = mj.address_of("alice")
        self.assertEqual(first[alice], int(self.key_hashes[mj.order_label("alice")]))
        self.assertEqual(second[alice], int(self.key_hashes[mj.order_label("alice", 2)]))
        self.assertEqual({a: k for a, k in first.items() if a != alice}, {a: k for a, k in second.items() if a != alice})

    def test_the_trees_hold_the_window_and_differ_only_by_alices_leaves(self):
        lower, upper = mj.PARAMS.window(mj.TIP)
        self.assertEqual((lower, upper), (105, 181))
        self.assertEqual(len(self.world.tree1), 77)
        self.assertEqual(len(self.world.tree2), 77)
        alice = mj.address_of("alice")
        alice_keys = {o.key for o in self.world.model.snapshot(mj.TIP) if o.owner == alice}
        self.assertTrue(alice_keys)
        values1, values2 = dict(self.world.tree1.items()), dict(self.world.tree2.items())
        self.assertEqual({k for k in values1 if values1[k] != values2[k]}, alice_keys)

    def test_the_named_outputs(self):
        out = self.world.outputs
        self.assertTrue(all(out[name].key in self.world.tree1 for name in ("A0", "B0", "C0", "C1", "D0", "D1", "E0", "Z0")))
        self.assertNotIn(out["D_spent"].key, self.world.tree1)
        self.assertIn(out["D_spent"].outpoint, self.world.model.spent_at)
        self.assertEqual(self.world.model.spent_at[out["D_spent"].outpoint], mj.TRANSFER_HEIGHT)
        # The transferred output belongs to Carol and keeps the root of the output it came from.
        self.assertEqual(out["C1"].owner, mj.address_of("carol"))
        self.assertFalse(out["C1"].is_coinbase)
        self.assertEqual(out["C1"].root_height, out["D_spent"].root_height)
        for name, owner in (("A0", "alice"), ("B0", "bob"), ("C0", "carol"), ("D0", "dave"), ("E0", "eve"), ("Z0", "zed")):
            self.assertEqual(out[name].owner, mj.address_of(owner))

    def test_leaves_of_registered_addresses_carry_the_key_hash_and_zeds_keep_the_address_id(self):
        tree = self.world.tree1
        registered = self.world.registry1.owners()
        for output in self.world.model.snapshot(mj.TIP):
            owner = registered.get(output.owner, smt.owner_id(output.owner))
            self.assertEqual(tree.get(output.key), smt.leaf_value(owner, output.units, output.root_height))
        zed = self.world.outputs["Z0"]
        self.assertEqual(tree.get(zed.key), smt.leaf_value(smt.owner_id(zed.owner), zed.units, zed.root_height))


class VariantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key_hashes = stand_in_key_hashes()
        cls.world = mj.build_world(cls.key_hashes)
        cls.variants = {variant.name: variant for variant in mj.variants(cls.world)}

    def alice_slot(self):
        return mj.slot_of(self.variants["valid"].spec, self.world.outputs["A0"].key)

    def test_the_variants_and_their_kinds(self):
        kinds = {name: variant.kind for name, variant in self.variants.items()}
        self.assertEqual(kinds["valid"], "valid")
        self.assertEqual(kinds["resplit"], "resplit")
        self.assertEqual(kinds["rotated"], "valid_extra")
        invalid = {name for name, kind in kinds.items() if kind == "invalid"}
        self.assertEqual(invalid, {
            "order_key_not_registered_owner", "output_of_another_registered_seller", "rotated_key_sells_with_old_key",
            "unregistered_owner_output", "output_spent_before_anchor", "wrong_utxo_root", "bad_order_signature",
        })
        for name, variant in self.variants.items():
            self.assertEqual(variant.expect, "accept" if variant.kind != "invalid" else "reject", name)

    def test_the_valid_batches_sell_leaves_owned_by_the_signing_keys(self):
        for name in ("valid", "resplit", "rotated"):
            variant = self.variants[name]
            self.assertEqual(mj.predicted_membership_failures(self.world, variant), [], name)
            tree = self.world.tree1 if variant.tree == "T1" else self.world.tree2
            inputs = variant.spec["inputs"]
            sold = [int(k) for k, flag in zip(inputs["saleId"], inputs["activeSale"]) if flag == "1"]
            self.assertTrue(all(k in tree for k in sold), name)
        self.assertEqual(sum(f == "1" for f in self.variants["valid"].spec["inputs"]["activeSale"]), 2)
        self.assertEqual(sum(f == "1" for f in self.variants["resplit"].spec["inputs"]["activeSale"]), 4)

    def test_each_ownership_fixture_fails_in_alices_slot_only(self):
        slot = self.alice_slot()
        for name in ("order_key_not_registered_owner", "output_of_another_registered_seller",
                     "rotated_key_sells_with_old_key", "unregistered_owner_output", "output_spent_before_anchor"):
            self.assertEqual(mj.predicted_membership_failures(self.world, self.variants[name]), [slot], name)

    def test_the_root_and_signature_fixtures_have_fully_owned_slots(self):
        self.assertEqual(mj.predicted_membership_failures(self.world, self.variants["bad_order_signature"]), [])
        valid_slots = [i for i, f in enumerate(self.variants["valid"].spec["inputs"]["activeSale"]) if f == "1"]
        self.assertEqual(mj.predicted_membership_failures(self.world, self.variants["wrong_utxo_root"]), valid_slots)
        self.assertEqual(self.variants["bad_order_signature"].post, [{"op": "orderS_plus_one", "slot": self.alice_slot()}])

    def test_the_rotation_variants_use_the_right_keys_and_trees(self):
        slot = self.alice_slot()
        self.assertEqual(self.variants["rotated"].tree, "T2")
        self.assertEqual(self.variants["rotated"].spec["sellerKeyLabels"][slot], mj.order_label("alice", 2))
        self.assertEqual(self.variants["rotated_key_sells_with_old_key"].tree, "T2")
        self.assertEqual(self.variants["rotated_key_sells_with_old_key"].spec["sellerKeyLabels"][slot], mj.order_label("alice"))
        # The rotated key sells against the old tree: refused. The old key against the new: refused above.
        stale = mj.Variant("x", "invalid", "T1", self.variants["rotated"].spec, "", "reject")
        self.assertEqual(mj.predicted_membership_failures(self.world, stale), [slot])

    def test_valid_and_resplit_share_the_public_totals_and_differ_in_the_sale_list(self):
        valid, resplit = self.variants["valid"].spec["inputs"], self.variants["resplit"].spec["inputs"]
        for name in ("funding", "feeBudget", "refund", "totalPayout", "buyerId", "batchHeight"):
            self.assertEqual(valid[name], resplit[name], name)
        self.assertNotEqual(valid["saleId"], resplit["saleId"])

    def test_the_ownership_witness_reproduces_the_root_for_every_owned_slot(self):
        for name in ("valid", "resplit", "rotated"):
            variant = self.variants[name]
            tree = self.world.tree1 if variant.tree == "T1" else self.world.tree2
            witness = mj.ownership_witness(self.world, tree, variant.spec)
            inputs = variant.spec["inputs"]
            self.assertEqual(witness["utxoRoot"], tree.root)
            for slot in range(16):
                self.assertEqual(len(witness["siblings"][slot]), mj.N_LEVELS)
                if inputs["activeSale"][slot] != "1":
                    self.assertEqual((witness["units"][slot], witness["rootHeight"][slot]), (0, 0))
                    self.assertFalse(any(witness["siblings"][slot]))
                    continue
                seller = int(self.key_hashes[variant.spec["sellerKeyLabels"][slot]])
                value = smt.leaf_value(seller, witness["units"][slot], witness["rootHeight"][slot])
                self.assertEqual(smt.root_from_proof(int(inputs["saleId"][slot]), value, witness["siblings"][slot]), tree.root)

    def test_the_witness_of_a_spent_output_does_not_reach_the_root(self):
        variant = self.variants["output_spent_before_anchor"]
        witness = mj.ownership_witness(self.world, self.world.tree1, variant.spec)
        slot = self.alice_slot()
        seller = int(self.key_hashes[variant.spec["sellerKeyLabels"][slot]])
        value = smt.leaf_value(seller, witness["units"][slot], witness["rootHeight"][slot])
        root = smt.root_from_proof(int(variant.spec["inputs"]["saleId"][slot]), value, witness["siblings"][slot])
        self.assertNotEqual(root, self.world.tree1.root)

    def test_build_writes_the_files_sign_joined_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            mj.build(self.key_hashes, out)
            manifest = json.loads((out / "variants" / "manifest.json").read_text())
            self.assertEqual([entry["name"] for entry in manifest], [v for v in self.variants])
            for entry in manifest:
                spec = json.loads((out / "variants" / f"{entry['name']}.spec.json").read_text())
                own = json.loads((out / "variants" / f"{entry['name']}.own.json").read_text())
                self.assertEqual(set(own), {"utxoRoot", "units", "rootHeight", "siblings"})
                self.assertEqual(len(own["siblings"]), 16)
                self.assertEqual(len(spec["sellerKeyLabels"]), 16)
            world = json.loads((out / "world.json").read_text())
            self.assertEqual(world["trees"]["T1"]["leaves"], 77)
            self.assertEqual(world["outputs"]["D_spent"]["in_T1"], False)
            wrong_root = json.loads((out / "variants" / "wrong_utxo_root.own.json").read_text())
            self.assertEqual(int(wrong_root["utxoRoot"]), self.world.tree1.root + 1)
            registrations = json.loads((out / "registrations.json").read_text())
            self.assertEqual(len(registrations), 6)

    def test_the_build_is_deterministic(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            mj.build(self.key_hashes, Path(a))
            mj.build(self.key_hashes, Path(b))
            names = sorted(p.relative_to(a) for p in Path(a).rglob("*.json"))
            self.assertEqual(names, sorted(p.relative_to(b) for p in Path(b).rglob("*.json")))
            for name in names:
                self.assertEqual((Path(a) / name).read_bytes(), (Path(b) / name).read_bytes(), str(name))


if __name__ == "__main__":
    unittest.main()
