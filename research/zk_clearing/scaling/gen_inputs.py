"""Synthetic inputs for the CommittedClearingTree scaling circuits.

Every sale slot is active (the worst case for the prover). Sale s goes to
buyer s % buyers, prices, fees and refunds come from a fixed seed, and
funding = cost + fee + refund for every buyer. Writes valid.json,
resplit.json (sale IDs of slots 0 and 1 swapped: same public totals, a
different commitment) and invalid/funding_mismatch.json.

Usage: python3 gen_inputs.py <out dir> <sale slots> <buyer slots>
"""

from __future__ import annotations

import copy
import json
import pathlib
import random
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from model import MAX_SATS  # noqa: E402
from witness import BN254_FR, field_id  # noqa: E402

SEED = 20261101


def batch(sales: int, buyers: int) -> dict:
    if sales & (sales - 1) or sales < 2:
        raise ValueError("sale slots must be a power of two")
    if buyers > sales:
        raise ValueError("more buyers than sales leaves a buyer with no sale")
    rng = random.Random(SEED + sales * 31 + buyers)
    prices = [rng.randint(1_000, 100_000) for _ in range(sales)]
    selector = [[1 if sale % buyers == buyer else 0 for buyer in range(buyers)] for sale in range(sales)]
    cost = [sum(prices[sale] for sale in range(sales) if sale % buyers == buyer) for buyer in range(buyers)]
    count = [sum(1 for sale in range(sales) if sale % buyers == buyer) for buyer in range(buyers)]
    fee = [rng.randint(100, 5_000) for _ in range(buyers)]
    refund = [rng.randint(0, 50_000) for _ in range(buyers)]
    return {
        "funding": [cost[b] + fee[b] + refund[b] for b in range(buyers)],
        "feeBudget": fee,
        "refund": refund,
        "totalPayout": sum(prices),
        "buyerId": [field_id("buyer", f"scale-buyer:{b}") for b in range(buyers)],
        "price": prices,
        "activeSale": [1] * sales,
        "priceInverse": [pow(price, -1, BN254_FR) for price in prices],
        "selector": selector,
        "activeBuyer": [1] * buyers,
        "buyerCountInverse": [pow(n, -1, BN254_FR) for n in count],
        "activeCountInverse": pow(sales, -1, BN254_FR),
        "saleId": [field_id("share_outpoint", f"scale-share:{sale}") for sale in range(sales)],
        "sellerId": [field_id("seller_share_address", f"scale-seller:{sale % 37}") for sale in range(sales)],
    }


def check(inputs: dict) -> None:
    """The relation, for any slot counts (witness.check_relation is fixed at 16x4)."""
    sales, buyers = len(inputs["price"]), len(inputs["funding"])
    for value in (*inputs["funding"], *inputs["feeBudget"], *inputs["refund"], *inputs["price"], inputs["totalPayout"]):
        assert 0 <= value <= MAX_SATS
    assert sum(inputs["price"]) == inputs["totalPayout"]
    for sale in range(sales):
        assert sum(inputs["selector"][sale]) == inputs["activeSale"][sale]
        assert inputs["price"][sale] * inputs["priceInverse"][sale] % BN254_FR == inputs["activeSale"][sale]
    assert sales * inputs["activeCountInverse"] % BN254_FR == 1
    for buyer in range(buyers):
        cost = sum(inputs["price"][s] * inputs["selector"][s][buyer] for s in range(sales))
        count = sum(inputs["selector"][s][buyer] for s in range(sales))
        assert count * inputs["buyerCountInverse"][buyer] % BN254_FR == inputs["activeBuyer"][buyer]
        assert inputs["funding"][buyer] == cost + inputs["feeBudget"][buyer] + inputs["refund"][buyer]


def encode(inputs: dict) -> str:
    def stringify(value):
        return [stringify(item) for item in value] if isinstance(value, list) else str(value)

    return json.dumps({key: stringify(value) for key, value in inputs.items()})


def main() -> None:
    if len(sys.argv) != 4:
        sys.exit("usage: gen_inputs.py <out dir> <sale slots> <buyer slots>")
    out = pathlib.Path(sys.argv[1])
    valid = batch(int(sys.argv[2]), int(sys.argv[3]))
    check(valid)
    resplit = copy.deepcopy(valid)
    resplit["saleId"][0], resplit["saleId"][1] = resplit["saleId"][1], resplit["saleId"][0]
    invalid = copy.deepcopy(valid)
    invalid["funding"][0] += 1
    (out / "invalid").mkdir(parents=True, exist_ok=True)
    (out / "valid.json").write_text(encode(valid))
    (out / "resplit.json").write_text(encode(resplit))
    (out / "invalid" / "funding_mismatch.json").write_text(encode(invalid))
    print(f"wrote {sys.argv[2]}x{sys.argv[3]} valid, resplit and 1 invalid fixture to {out}")


if __name__ == "__main__":
    main()
