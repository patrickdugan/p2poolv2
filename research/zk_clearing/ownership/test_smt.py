"""Offline tests of the Poseidon sparse Merkle tree against circomlib and circomlibjs.

Run from the repository root:

    python3 -m unittest discover -s research/zk_clearing/ownership

`circomlibjs_vectors.json` holds outputs of the pinned circomlibjs (Poseidon and
its SMT: roots after each insert, update and delete, then `find` proofs), written
by `gen_vectors.js`. The circuit itself is exercised by `run.sh`.
"""

import json
import random
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import smt  # noqa: E402

VECTORS = json.loads((HERE / "circomlibjs_vectors.json").read_text())
P = smt.FIELD


def element(rng: random.Random) -> int:
    return rng.getrandbits(253)


class PoseidonTests(unittest.TestCase):
    def test_reference_matches_the_published_circomlib_values(self):
        self.assertEqual(
            smt.poseidon_reference([1, 2]),
            7853200120776062878684798364095072458815029376092732009249414926327459813530,
        )
        self.assertEqual(
            smt.poseidon_reference([1, 2, 3]),
            6542985608222806190361240322586112750744169038454362455181422643027100751666,
        )

    def test_circomlibjs_vectors(self):
        for vector in VECTORS["poseidon"]:
            inputs = [int(x) for x in vector["inputs"]]
            expected = int(vector["out"])
            fast = smt.poseidon2(*inputs) if len(inputs) == 2 else smt.poseidon3(*inputs)
            self.assertEqual(fast, expected, vector["inputs"])
            self.assertEqual(smt.poseidon_reference(inputs), expected, vector["inputs"])

    def test_unrolled_hashes_match_the_reference(self):
        rng = random.Random(1)
        edge = [0, 1, P - 1]
        for _ in range(25):
            a, b, c = (rng.choice(edge + [element(rng)]) for _ in range(3))
            self.assertEqual(smt.poseidon2(a, b), smt.poseidon_reference([a, b]))
            self.assertEqual(smt.poseidon3(a, b, c), smt.poseidon_reference([a, b, c]))

    def test_hash_counter_counts_evaluations(self):
        smt.reset_hash_counts()
        smt.poseidon2(1, 2)
        smt.poseidon3(1, 2, 3)
        smt.poseidon3(1, 2, 3)
        self.assertEqual(smt.HASH_COUNTS, {"poseidon2": 1, "poseidon3": 2})


class CircomlibjsReplayTests(unittest.TestCase):
    """Replay circomlibjs's scripted operations and compare every root and proof."""

    @classmethod
    def setUpClass(cls):
        cls.tree = smt.SparseMerkleTree()
        cls.roots = []
        for op in VECTORS["smt"]["ops"]:
            key = int(op["key"])
            value = None if op["value"] is None else int(op["value"])
            if op["op"] == "insert":
                cls.tree.insert(key, value)
            elif op["op"] == "update":
                cls.tree.update(key, value)
            else:
                cls.tree.delete(key)
            cls.roots.append((op, cls.tree.root))

    def test_roots_after_every_operation(self):
        self.assertGreater(len(self.roots), 50)
        for op, root in self.roots:
            self.assertEqual(root, int(op["root"]), f'{op["op"]} {op["key"]}')

    def test_final_root(self):
        self.assertEqual(self.tree.root, int(VECTORS["smt"]["finalRoot"]))

    def test_membership_proofs_equal_circomlibjs_find(self):
        checked = 0
        for proof in VECTORS["smt"]["proofs"]:
            if not proof["found"]:
                continue
            ours = self.tree.prove(int(proof["key"]))
            self.assertEqual(list(ours.siblings), [int(s) for s in proof["siblings"]])
            self.assertEqual(ours.value, int(proof["value"]))
            self.assertTrue(smt.verify_membership(self.tree.root, ours))
            checked += 1
        self.assertGreaterEqual(checked, 40)

    def test_exclusion_proofs_equal_circomlibjs_find(self):
        checked = 0
        ended_empty = ended_on_leaf = 0
        for proof in VECTORS["smt"]["proofs"]:
            if proof["found"]:
                continue
            ours = self.tree.prove_absent(int(proof["key"]))
            self.assertEqual(list(ours.siblings), [int(s) for s in proof["siblings"]])
            self.assertEqual(ours.is_old0, proof["isOld0"])
            if not ours.is_old0:
                self.assertEqual(ours.old_key, int(proof["notFoundKey"]))
                self.assertEqual(ours.old_value, int(proof["notFoundValue"]))
            self.assertTrue(smt.verify_absence(self.tree.root, ours))
            ended_empty += ours.is_old0
            ended_on_leaf += not ours.is_old0
            checked += 1
        self.assertGreaterEqual(checked, 5)
        self.assertGreater(ended_empty, 0)
        self.assertGreater(ended_on_leaf, 0)

    def test_the_script_reaches_deep_leaves(self):
        # The pairs sharing 20 and 33 low bits give chains of zero siblings.
        self.assertGreaterEqual(max(self.tree.leaf_depths()), 20)


class TreeTests(unittest.TestCase):
    def setUp(self):
        self.rng = random.Random(7)
        self.items = {element(self.rng): element(self.rng) for _ in range(120)}

    def build(self, items, order=None):
        tree = smt.SparseMerkleTree()
        for key, value in order or items.items():
            tree.insert(key, value)
        return tree

    def test_empty_and_single_leaf(self):
        self.assertEqual(smt.SparseMerkleTree().root, 0)
        tree = smt.SparseMerkleTree()
        tree.insert(5, 9)
        self.assertEqual(tree.root, smt.leaf_hash(5, 9))
        self.assertEqual(tree.prove(5).siblings, ())

    def test_root_does_not_depend_on_insertion_order(self):
        shuffled = list(self.items.items())
        random.Random(3).shuffle(shuffled)
        self.assertEqual(self.build(self.items).root, self.build(self.items, shuffled).root)

    def test_bulk_build_equals_incremental(self):
        self.assertEqual(smt.SparseMerkleTree.from_items(self.items.items()).root, self.build(self.items).root)

    def test_root_is_the_same_whether_hashed_lazily_or_after_each_edit(self):
        eager, lazy = smt.SparseMerkleTree(), smt.SparseMerkleTree()
        for key, value in self.items.items():
            eager.insert(key, value)
            eager.root  # noqa: B018
            lazy.insert(key, value)
        self.assertEqual(eager.root, lazy.root)

    def test_delete_restores_the_previous_root(self):
        tree = self.build(self.items)
        before = tree.root
        extra = 2**200 + 12345
        tree.insert(extra, 77)
        self.assertNotEqual(tree.root, before)
        tree.delete(extra)
        self.assertEqual(tree.root, before)

    def test_deleting_everything_gives_the_empty_root(self):
        tree = self.build(self.items)
        for key in list(self.items):
            tree.delete(key)
        self.assertEqual(tree.root, 0)
        self.assertEqual(len(tree), 0)

    def test_a_pair_collapses_to_a_single_leaf_when_one_is_deleted(self):
        # Keys sharing 6 low bits sit under a chain of branches with empty siblings.
        a, b = 0b000001, 0b1000001
        tree = smt.SparseMerkleTree()
        tree.insert(a, 11)
        tree.insert(b, 22)
        self.assertEqual(tree.prove(a).depth, 7)
        tree.delete(b)
        self.assertEqual(tree.root, smt.leaf_hash(a, 11))
        self.assertEqual(tree.prove(a).depth, 0)

    def test_update_equals_a_fresh_tree(self):
        tree = self.build(self.items)
        key = next(iter(self.items))
        tree.update(key, 123456789)
        fresh = dict(self.items)
        fresh[key] = 123456789
        self.assertEqual(tree.root, self.build(fresh).root)

    def test_duplicates_and_missing_keys_are_errors(self):
        tree = self.build(self.items)
        key = next(iter(self.items))
        with self.assertRaises(smt.KeyExists):
            tree.insert(key, 1)
        with self.assertRaises(smt.KeyMissing):
            tree.delete(2**100 + 1)
        with self.assertRaises(smt.KeyMissing):
            tree.prove(2**100 + 1)
        with self.assertRaises(smt.SmtError):
            tree.insert(P, 1)  # not a canonical field element
        with self.assertRaises(smt.KeyExists):
            smt.SparseMerkleTree.from_items([(1, 1), (1, 2)])

    def test_membership_proof_verifies_and_every_tamper_fails(self):
        tree = self.build(self.items)
        key = next(iter(self.items))
        proof = tree.prove(key)
        root = tree.root
        self.assertTrue(smt.verify_membership(root, proof))
        wrong_value = smt.MembershipProof(key, proof.value + 1, proof.siblings)
        self.assertFalse(smt.verify_membership(root, wrong_value))
        wrong_key = smt.MembershipProof(key ^ 1, proof.value, proof.siblings)
        self.assertFalse(smt.verify_membership(root, wrong_key))
        siblings = list(proof.siblings)
        siblings[len(siblings) // 2] ^= 1
        self.assertFalse(smt.verify_membership(root, smt.MembershipProof(key, proof.value, tuple(siblings))))
        self.assertFalse(smt.verify_membership(root + 1, proof))

    def test_a_non_member_cannot_borrow_a_members_path(self):
        tree = self.build(self.items)
        member = next(iter(self.items))
        proof = tree.prove(member)
        stranger = member ^ (1 << 3)  # same path above level 3
        self.assertNotIn(stranger, tree)
        self.assertFalse(smt.verify_membership(tree.root, smt.MembershipProof(stranger, proof.value, proof.siblings)))

    def test_absence_proofs_verify_and_a_member_has_none(self):
        tree = self.build(self.items)
        for _ in range(30):
            probe = element(self.rng)
            self.assertTrue(smt.verify_absence(tree.root, tree.prove_absent(probe)))
        with self.assertRaises(smt.SmtError):
            tree.prove_absent(next(iter(self.items)))

    def test_proofs_pad_to_the_circuit_width(self):
        tree = self.build(self.items)
        proof = tree.prove(next(iter(self.items)))
        padded = smt.pad_siblings(proof.siblings, 40)
        self.assertEqual(len(padded), 40)
        self.assertEqual(padded[-1], 0)
        self.assertEqual(smt.root_from_proof(proof.key, proof.value, padded), tree.root)
        with self.assertRaises(smt.DepthExceeded):
            smt.pad_siblings([1] * 40, 40)  # the last level must stay free

    def test_proof_sizes(self):
        tree = self.build(self.items)
        proof = tree.prove(next(iter(self.items)))
        self.assertEqual(proof.size_bytes(), 32 * proof.depth)
        self.assertLessEqual(proof.size_bytes(compressed=True), 1 + (proof.depth + 7) // 8 + 32 * proof.depth)

    def test_depth_bound_boundary(self):
        tree = smt.SparseMerkleTree(max_depth=5)
        self.assertEqual(tree.n_levels, 6)  # a circuit with 6 levels holds leaves of depth <= 5
        # Sharing max_depth - 1 low bits puts both leaves at depth max_depth: allowed.
        tree.insert(0b00001, 1)
        tree.insert(0b10001, 2)
        self.assertEqual(max(tree.leaf_depths()), 5)
        # Sharing max_depth low bits would need depth max_depth + 1: refused, tree unchanged.
        before = tree.root
        with self.assertRaises(smt.DepthExceeded):
            tree.insert(0b110001, 3)
        self.assertEqual(tree.root, before)
        self.assertEqual(len(tree), 2)
        with self.assertRaises(smt.DepthExceeded):
            smt.SparseMerkleTree.from_items([(0b00001, 1), (0b100001, 2)], max_depth=5)

    def test_leaf_depth_grows_like_log2_of_the_leaf_count(self):
        rng = random.Random(11)
        tree = smt.SparseMerkleTree.from_items((element(rng), 1) for _ in range(4096))
        depths = tree.leaf_depths()
        mean = sum(depths) / len(depths)
        self.assertGreater(mean, 12.0)
        self.assertLess(mean, 14.0)  # log2(4096) = 12 plus the usual 1.33 of a random trie
        self.assertLess(max(depths), 26)


class BenchDepthTests(unittest.TestCase):
    def test_leaf_depth_from_key_order_equals_the_real_tree(self):
        import bench_smt

        rng = random.Random(21)
        for _ in range(3):
            keys = [rng.getrandbits(253) for _ in range(3000)]
            depths = smt.SparseMerkleTree.from_items((k, 1) for k in keys).leaf_depths()
            deepest, mean = bench_smt.max_leaf_depth([k & ((1 << 64) - 1) for k in keys])
            self.assertEqual(deepest, max(depths))
            self.assertAlmostEqual(mean, sum(depths) / len(depths))

    def test_conflict_table_shrinks_by_half_per_level(self):
        import bench_smt

        rows = bench_smt.conflict_table({"a": 1000}, {"a": 100.0}, [20, 21])
        self.assertAlmostEqual(rows[0]["conflicts_per_year_a"] / rows[1]["conflicts_per_year_a"], 2.0, places=2)


class IdentityTests(unittest.TestCase):
    def test_ids_are_the_v1_circuits_identities(self):
        from example_inputs import example_circuit_inputs

        inputs = example_circuit_inputs(committed=True)
        # The sales sort by outpoint string: example-share:0 (Alice), example-share:1 (Bob).
        self.assertEqual(inputs["saleId"][0], smt.outpoint_id("example-share", 0))
        self.assertEqual(inputs["saleId"][1], smt.outpoint_id("example-share", 1))
        self.assertEqual(inputs["sellerId"][0], smt.owner_id("exampleShareAlice"))
        self.assertEqual(inputs["sellerId"][1], smt.owner_id("exampleShareBob"))
        self.assertEqual(inputs["saleId"][2], 0)  # padding slots carry no identity

    def test_share_address_vectors_from_address_format_md(self):
        genesis_output_key = bytes.fromhex("66db9f0ac8ca0a00603027b3a445da6ee2df6c0e04f8dc6f996db4e59d0e45bf")
        self.assertEqual(
            smt.share_address(genesis_output_key, "mainnet"),
            "p2pool1pvmde7zkgeg9qqcpsy7e6g3w6dm3d7mqwqnudcmuedk6wt8gwgklsuackff",
        )
        self.assertEqual(
            smt.share_address(genesis_output_key, "regtest"),
            "rp2pool1pvmde7zkgeg9qqcpsy7e6g3w6dm3d7mqwqnudcmuedk6wt8gwgkls63pz3k",
        )
        numps_x = bytes.fromhex("ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d")
        self.assertEqual(
            smt.share_address(numps_x, "testnet4"),
            "tp2pool1p43yn7gfseftvkhp62kvxpnhe4p8epddgthlya3hxqelwactlf5kst4gevn",
        )
        wallet_key = bytes.fromhex("a3ea4c1c5f042ae7fbd086bc7f30e2a08c8b6753c4631db7d4b1fcb3ab941900")
        self.assertEqual(
            smt.share_address(wallet_key, "signet"),
            "sp2pool1p504yc8zlqs4w077ss6787v8z5zxgke6nc333md75k87t82u5ryqqd9033x",
        )

    def test_leaf_value_is_poseidon_of_owner_units_and_root_height(self):
        owner = smt.owner_id("p2pool1pexample")
        value = smt.leaf_value(owner, 100_000_000, 1234)
        self.assertEqual(value, smt.poseidon_reference([owner, 100_000_000, 1234]))
        self.assertNotEqual(value, smt.leaf_value(owner, 100_000_000, 1235))
        self.assertNotEqual(value, smt.leaf_value(owner + 1, 100_000_000, 1234))
        self.assertNotEqual(value, smt.leaf_value(owner, 99_999_999, 1234))
        with self.assertRaises(ValueError):
            smt.leaf_value(P, 1, 1)


if __name__ == "__main__":
    unittest.main()
