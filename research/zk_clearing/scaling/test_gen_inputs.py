"""Tests for the scaling input generator."""

import copy
import unittest

from gen_inputs import batch, check


class GenInputsTests(unittest.TestCase):
    def test_relation_holds_at_every_size(self):
        for sales, buyers in ((16, 4), (64, 8), (256, 8), (1024, 8)):
            inputs = batch(sales, buyers)
            check(inputs)
            self.assertEqual(len(inputs["price"]), sales)
            self.assertEqual(len(inputs["funding"]), buyers)

    def test_deterministic(self):
        self.assertEqual(batch(64, 8), batch(64, 8))

    def test_funding_mismatch_fails_the_check(self):
        inputs = copy.deepcopy(batch(64, 8))
        inputs["funding"][0] += 1
        with self.assertRaises(AssertionError):
            check(inputs)

    def test_rejects_sizes_that_are_not_powers_of_two(self):
        with self.assertRaises(ValueError):
            batch(48, 4)


if __name__ == "__main__":
    unittest.main()
