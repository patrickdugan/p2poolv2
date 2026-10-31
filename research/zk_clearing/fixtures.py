"""Write valid, invalid and alternative input fixtures for the Groth16 pipeline.

The invalid fixtures are written WITHOUT the Python oracle, so the Circom
witness calculator (and through it the circuit's constraints) is what must
reject them. `groth16/run.sh` expects witness generation to fail for every
file under `invalid/`.

`resplit.json` is a valid witness for a DIFFERENT sale list with the same
public totals. Under v0 it proves exactly the same public statement; under
the committed circuit its saleCommitment differs.

Usage: python3 fixtures.py <output directory> <circuit name>
"""

from __future__ import annotations

import copy
import json
import pathlib
import sys

from example_inputs import example_circuit_inputs, resplit_sales
from model import MAX_SATS
from witness import BN254_FR, BUYER_SLOTS, SALE_SLOTS

COMMITTED_CIRCUITS = {"accounting16x4_committed"}


def _encode(inputs: dict) -> str:
    def stringify(value):
        if isinstance(value, list):
            return [stringify(item) for item in value]
        return str(value)

    return json.dumps({key: stringify(value) for key, value in inputs.items()}, sort_keys=True)


def _empty_batch(valid: dict) -> dict:
    inputs = copy.deepcopy(valid)
    for key in ("funding", "feeBudget", "refund", "activeBuyer", "buyerCountInverse", "buyerId"):
        if key in inputs:
            inputs[key] = [0] * BUYER_SLOTS
    for key in ("price", "activeSale", "priceInverse", "saleId", "sellerId"):
        if key in inputs:
            inputs[key] = [0] * SALE_SLOTS
    inputs["selector"] = [[0] * BUYER_SLOTS for _ in range(SALE_SLOTS)]
    inputs["totalPayout"] = 0
    inputs["activeCountInverse"] = 0
    return inputs


def invalid_fixtures(valid: dict) -> dict[str, dict]:
    """Each entry breaks exactly one rule of the relation."""
    fixtures: dict[str, dict] = {}

    def mutate(name, change):
        inputs = copy.deepcopy(valid)
        change(inputs)
        fixtures[name] = inputs

    mutate("funding_mismatch", lambda i: i["funding"].__setitem__(0, i["funding"][0] + 1))
    mutate("refund_inflated", lambda i: i["refund"].__setitem__(0, i["refund"][0] + 1))
    mutate("total_payout_mismatch", lambda i: i.__setitem__("totalPayout", i["totalPayout"] + 1))
    mutate("negative_price", lambda i: i["price"].__setitem__(0, BN254_FR - 1))
    mutate("price_above_max", lambda i: i["price"].__setitem__(0, MAX_SATS + 1))
    mutate("refund_above_max", lambda i: i["refund"].__setitem__(0, MAX_SATS + 1))
    mutate("zero_price_active_sale", lambda i: i["price"].__setitem__(0, 0))
    mutate("priced_padding_slot", lambda i: i["price"].__setitem__(SALE_SLOTS - 1, 5))
    mutate("nonbinary_selector", lambda i: i["selector"][0].__setitem__(0, 2))
    mutate("sale_assigned_twice", lambda i: i["selector"][0].__setitem__(1, 1 - i["selector"][0][1]))
    mutate("active_sale_unassigned", lambda i: i["selector"].__setitem__(0, [0] * BUYER_SLOTS))
    mutate("active_buyer_without_sales", lambda i: i["activeBuyer"].__setitem__(BUYER_SLOTS - 1, 1))
    mutate("wrong_price_inverse", lambda i: i["priceInverse"].__setitem__(0, i["priceInverse"][0] + 1))
    fixtures["empty_batch"] = _empty_batch(valid)
    if "saleId" in valid:
        mutate("padding_slot_with_sale_id", lambda i: i["saleId"].__setitem__(SALE_SLOTS - 1, 7))
        mutate("padding_slot_with_seller_id", lambda i: i["sellerId"].__setitem__(SALE_SLOTS - 1, 7))
        mutate("unused_escrow_with_buyer_id", lambda i: i["buyerId"].__setitem__(BUYER_SLOTS - 1, 7))
    return fixtures


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit("usage: fixtures.py <output directory> <circuit name>")
    out = pathlib.Path(sys.argv[1])
    committed = sys.argv[2] in COMMITTED_CIRCUITS
    (out / "invalid").mkdir(parents=True, exist_ok=True)
    valid = example_circuit_inputs(committed=committed)
    (out / "valid.json").write_text(_encode(valid) + "\n")
    resplit = example_circuit_inputs(committed=committed, sales=resplit_sales())
    (out / "resplit.json").write_text(_encode(resplit) + "\n")
    invalid = invalid_fixtures(valid)
    for name, inputs in invalid.items():
        (out / "invalid" / f"{name}.json").write_text(_encode(inputs) + "\n")
    print(f"wrote valid.json, resplit.json and {len(invalid)} invalid fixtures to {out}")


if __name__ == "__main__":
    main()
