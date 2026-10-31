"""Unsigned batch spec for clearing16x4_signed.circom.

Builds the v1 committed inputs from the reference model, then adds the M4
terms in the same slot order: the seller's Bitcoin payout script and order
expiry per sale, and the escrow outpoint, fee cap, refund script and expiry
per buyer. `sign.js` derives keys, replaces sellerId/buyerId with key hashes
and signs. All identities are placeholders.

Usage: python3 make_batch.py <valid|resplit>  (writes JSON to stdout)
"""

from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from example_inputs import example_batch, resplit_sales  # noqa: E402
from witness import BUYER_SLOTS, SALE_SLOTS, build_committed_inputs, field_id  # noqa: E402

FEE_CAP_MARGIN = 50
BATCH_HEIGHT = 499


def batch_spec(resplit: bool = False) -> dict:
    sales, escrows, state, context = example_batch(resplit_sales() if resplit else None)
    inputs, _ = build_committed_inputs(sales, escrows, state, context, BATCH_HEIGHT)
    ordered_sales = sorted(sales, key=lambda sale: sale.share_outpoint)
    ordered_escrows = sorted(escrows, key=lambda escrow: escrow.buyer_id)

    extra = {
        "batchHeight": BATCH_HEIGHT,
        "sellerPayoutId": [0] * SALE_SLOTS,
        "orderExpiry": [0] * SALE_SLOTS,
        "escrowId": [0] * BUYER_SLOTS,
        "feeCap": [0] * BUYER_SLOTS,
        "refundScriptId": [0] * BUYER_SLOTS,
        "escrowExpiry": [0] * BUYER_SLOTS,
    }
    seller_keys: list[str | None] = [None] * SALE_SLOTS
    buyer_keys: list[str | None] = [None] * BUYER_SLOTS
    for index, sale in enumerate(ordered_sales):
        extra["sellerPayoutId"][index] = field_id("seller_payout_script", sale.seller_bitcoin_address)
        extra["orderExpiry"][index] = context.expiry_bitcoin_height
        seller_keys[index] = sale.seller_share_address
    for index, escrow in enumerate(ordered_escrows):
        extra["escrowId"][index] = field_id("escrow_outpoint", escrow.bitcoin_outpoint)
        extra["feeCap"][index] = escrow.fee_budget_sats + FEE_CAP_MARGIN
        extra["refundScriptId"][index] = field_id("refund_script", escrow.bitcoin_refund_address)
        extra["escrowExpiry"][index] = context.expiry_bitcoin_height
        buyer_keys[index] = escrow.buyer_id

    def stringify(value):
        if isinstance(value, list):
            return [stringify(item) for item in value]
        return str(value)

    merged = {**inputs, **extra}
    return {
        "inputs": {key: stringify(value) for key, value in merged.items()},
        "sellerKeyLabels": seller_keys,
        "buyerKeyLabels": buyer_keys,
    }


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in ("valid", "resplit"):
        sys.exit("usage: make_batch.py <valid|resplit>")
    print(json.dumps(batch_spec(resplit=sys.argv[1] == "resplit"), sort_keys=True))


if __name__ == "__main__":
    main()
