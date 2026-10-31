"""Tests for the M7 benchmark model."""

import json
import pathlib
import unittest

import bench
from workload import OFFERS, offers

MEASURED = json.loads((pathlib.Path(__file__).resolve().parent / "measurements.json").read_text())


class WorkloadTests(unittest.TestCase):
    def test_fixed_seed_and_size(self):
        first, second = offers(), offers()
        self.assertEqual(len(first), OFFERS)
        self.assertEqual(first, second)
        self.assertEqual(first, sorted(first, key=lambda offer: offer.arrival))


class ModelTests(unittest.TestCase):
    def setUp(self):
        self.workload = offers()

    def test_bilateral_sizes(self):
        p2wsh = bench.bilateral(self.workload, 0, "p2wsh")
        self.assertEqual((p2wsh["funding_vbytes"], p2wsh["claim_vbytes"]), (153, 157))
        batched = bench.bilateral(self.workload, 0, "p2tr-batched-funding")
        self.assertLess(batched["vbytes_total"], bench.bilateral(self.workload, 0, "p2tr")["vbytes_total"])

    def test_bigger_batches_cost_less_per_sale(self):
        totals = [bench.batch_clearing(self.workload, n, MEASURED)["on_chain_vbytes_total"]
                  for n in bench.BATCH_SIZES]
        self.assertEqual(totals, sorted(totals, reverse=True))

    def test_breakeven_rises_with_lightning_capital(self):
        day = bench.breakeven(self.workload, MEASURED, 1024, 0.0, 1 / 7, 0.05)
        week = bench.breakeven(self.workload, MEASURED, 1024, 0.0, 1, 0.05)
        challenged = bench.breakeven(self.workload, MEASURED, 1024, 0.01, 1 / 7, 0.05)
        self.assertGreater(week, day)
        self.assertGreater(day, challenged)
        self.assertGreater(challenged, 0)


if __name__ == "__main__":
    unittest.main()
