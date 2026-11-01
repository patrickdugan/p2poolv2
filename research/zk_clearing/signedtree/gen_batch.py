"""Unsigned batch specs for the SignedClearingTree circuits (M11).

Builds on scaling/gen_inputs.py (M6): the same deterministic batch with every sale slot
active (the prover's worst case), plus the M4 terms. Each sale carries a payout script and an
order expiry, each buyer an escrow outpoint, a fee cap, a refund script and an expiry.
`sign.js` derives the keys, replaces sellerId and buyerId with key hashes, signs, and writes
the circuit inputs.

Variants:
  valid    every sale and buyer slot active.
  resplit  the sale IDs of slots 0 and 1 swapped: same public totals, different commitment.
  padded   the last quarter of the sale slots and the last buyer slot unused, to exercise the
           padding rules (zeroed fields, padding-key signatures).

Usage: python3 gen_batch.py <valid|resplit|padded> <sale slots> <buyer slots>
       (the spec is written to stdout as JSON)
"""

from __future__ import annotations

import copy
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scaling"))

from gen_inputs import batch  # noqa: E402
from model import MAX_SATS  # noqa: E402
from witness import BN254_FR, field_id  # noqa: E402

BATCH_HEIGHT = 905_000
EXPIRY_WINDOW = 144
FEE_CAP_MARGIN = 50
SELLER_KEYS = 37  # distinct seller order keys; sale s signs with key s % SELLER_KEYS


def pad(inputs: dict, active_sales: int, active_buyers: int) -> dict:
    """Deactivate the sale slots from `active_sales` up and the buyer slots from `active_buyers` up."""
    sales, buyers = len(inputs["price"]), len(inputs["funding"])
    padded = copy.deepcopy(inputs)
    for sale in range(sales):
        live = sale < active_sales
        padded["activeSale"][sale] = 1 if live else 0
        padded["price"][sale] = inputs["price"][sale] if live else 0
        padded["priceInverse"][sale] = inputs["priceInverse"][sale] if live else 0
        padded["saleId"][sale] = inputs["saleId"][sale] if live else 0
        padded["sellerId"][sale] = inputs["sellerId"][sale] if live else 0
        padded["selector"][sale] = [1 if live and sale % active_buyers == buyer else 0 for buyer in range(buyers)]
    for buyer in range(buyers):
        live = buyer < active_buyers
        count = sum(1 for sale in range(active_sales) if sale % active_buyers == buyer)
        cost = sum(padded["price"][sale] for sale in range(active_sales) if sale % active_buyers == buyer)
        padded["activeBuyer"][buyer] = 1 if live else 0
        padded["buyerCountInverse"][buyer] = pow(count, -1, BN254_FR) if live else 0
        padded["feeBudget"][buyer] = inputs["feeBudget"][buyer] if live else 0
        padded["refund"][buyer] = inputs["refund"][buyer] if live else 0
        padded["funding"][buyer] = cost + padded["feeBudget"][buyer] + padded["refund"][buyer] if live else 0
        padded["buyerId"][buyer] = inputs["buyerId"][buyer] if live else 0
    padded["totalPayout"] = sum(padded["price"])
    padded["activeCountInverse"] = pow(active_sales, -1, BN254_FR)
    return padded


def with_signed_terms(inputs: dict) -> tuple[dict, list, list]:
    """Add the M4 terms to a (possibly padded) v1 batch; returns inputs and the key labels."""
    sales, buyers = len(inputs["price"]), len(inputs["funding"])
    merged = dict(inputs)
    expiry = BATCH_HEIGHT + EXPIRY_WINDOW
    seller_labels: list = []
    buyer_labels: list = []
    merged["batchHeight"] = BATCH_HEIGHT
    merged["sellerPayoutId"] = []
    merged["orderExpiry"] = []
    for sale in range(sales):
        live = inputs["activeSale"][sale] == 1
        merged["sellerPayoutId"].append(field_id("seller_payout_script", f"scale-payout:{sale}") if live else 0)
        merged["orderExpiry"].append(expiry if live else 0)
        seller_labels.append(f"scale-seller:{sale % SELLER_KEYS}" if live else None)
    merged["escrowId"] = []
    merged["feeCap"] = []
    merged["refundScriptId"] = []
    merged["escrowExpiry"] = []
    for buyer in range(buyers):
        live = inputs["activeBuyer"][buyer] == 1
        merged["escrowId"].append(field_id("escrow_outpoint", f"scale-escrow:{buyer}:0") if live else 0)
        merged["feeCap"].append(inputs["feeBudget"][buyer] + FEE_CAP_MARGIN if live else 0)
        merged["refundScriptId"].append(field_id("refund_script", f"scale-refund:{buyer}") if live else 0)
        merged["escrowExpiry"].append(expiry if live else 0)
        buyer_labels.append(f"scale-buyer:{buyer}" if live else None)
    return merged, seller_labels, buyer_labels


def check(spec_inputs: dict) -> None:
    """The v1 relation and the M4 term rules, for any slot counts and any active pattern."""
    i = spec_inputs
    sales, buyers = len(i["price"]), len(i["funding"])
    active_sales = sum(i["activeSale"])
    for value in (*i["funding"], *i["feeBudget"], *i["refund"], *i["price"], i["totalPayout"], *i["feeCap"]):
        assert 0 <= value <= MAX_SATS
    assert sum(i["price"]) == i["totalPayout"]
    assert active_sales * i["activeCountInverse"] % BN254_FR == 1
    for sale in range(sales):
        assert i["activeSale"][sale] in (0, 1)
        assert sum(i["selector"][sale]) == i["activeSale"][sale]
        assert i["price"][sale] * i["priceInverse"][sale] % BN254_FR == i["activeSale"][sale]
        if i["activeSale"][sale]:
            assert i["batchHeight"] <= i["orderExpiry"][sale] < 2**32
            assert i["sellerPayoutId"][sale] != 0
        else:
            assert i["saleId"][sale] == i["sellerId"][sale] == i["sellerPayoutId"][sale] == 0
    for buyer in range(buyers):
        assert i["activeBuyer"][buyer] in (0, 1)
        cost = sum(i["price"][s] * i["selector"][s][buyer] for s in range(sales))
        count = sum(i["selector"][s][buyer] for s in range(sales))
        assert count * i["buyerCountInverse"][buyer] % BN254_FR == i["activeBuyer"][buyer]
        assert i["funding"][buyer] == cost + i["feeBudget"][buyer] + i["refund"][buyer]
        if i["activeBuyer"][buyer]:
            assert i["feeBudget"][buyer] <= i["feeCap"][buyer]
            assert i["batchHeight"] <= i["escrowExpiry"][buyer] < 2**32
            assert i["escrowId"][buyer] != 0 and i["refundScriptId"][buyer] != 0
        else:
            assert i["buyerId"][buyer] == i["escrowId"][buyer] == i["feeCap"][buyer] == i["refundScriptId"][buyer] == 0


def stringify(value):
    if isinstance(value, list):
        return [stringify(item) for item in value]
    return str(value)


def batch_spec(sales: int, buyers: int, variant: str = "valid") -> dict:
    if variant not in ("valid", "resplit", "padded"):
        raise ValueError(f"unknown variant {variant!r}")
    inputs = batch(sales, buyers)
    if variant == "resplit":
        inputs["saleId"][0], inputs["saleId"][1] = inputs["saleId"][1], inputs["saleId"][0]
    if variant == "padded":
        if buyers < 2:
            raise ValueError("a padded batch needs at least 2 buyer slots")
        inputs = pad(inputs, sales - sales // 4, buyers - 1)
    merged, seller_labels, buyer_labels = with_signed_terms(inputs)
    check(merged)
    return {
        "inputs": {key: stringify(value) for key, value in merged.items()},
        "sellerKeyLabels": seller_labels,
        "buyerKeyLabels": buyer_labels,
    }


def main() -> None:
    if len(sys.argv) != 4 or sys.argv[1] not in ("valid", "resplit", "padded"):
        sys.exit("usage: gen_batch.py <valid|resplit|padded> <sale slots> <buyer slots>")
    print(json.dumps(batch_spec(int(sys.argv[2]), int(sys.argv[3]), sys.argv[1]), sort_keys=True))


if __name__ == "__main__":
    main()
