"""The regtest clearing batch settled by the BitVM M1 demo.

Three sellers, three buyers, four sales, sized so that every payout, refund and
the fee clear Bitcoin Core's dust limit. The identities are labels: the M1
harness turns each payee label into a deterministic regtest key.

Writes two files into the output directory:
  input.json    witness input for accounting16x4_committed (snarkjs encoding)
  opening.json  the slot layout of the sale list and escrows, with payee labels

Usage: python3 batch.py <output directory>
"""

from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from model import DOMAIN, Context, Escrow, InputState, Sale  # noqa: E402
from witness import (  # noqa: E402
    BUYER_SLOTS,
    SALE_SLOTS,
    build_committed_inputs,
    encode_snarkjs_input,
)

FEE_PAYEE = "operator-fee"

SALES = (
    Sale("m1-share:0", "m1ShareAlice", "seller-alice", "m1BuyerShare1", "buyer1", 1_200_000),
    Sale("m1-share:1", "m1ShareBob", "seller-bob", "m1BuyerShare2", "buyer2", 1_800_000),
    Sale("m1-share:2", "m1ShareAlice", "seller-alice", "m1BuyerShare3", "buyer3", 700_000),
    Sale("m1-share:3", "m1ShareCarol", "seller-carol", "m1BuyerShare1", "buyer1", 450_000),
)

ESCROWS = (
    Escrow("buyer1", "regtest-escrow:buyer1", "refund-buyer1", 2_000_000, 20_000),
    Escrow("buyer2", "regtest-escrow:buyer2", "refund-buyer2", 1_900_000, 18_000),
    Escrow("buyer3", "regtest-escrow:buyer3", "refund-buyer3", 750_000, 7_000),
)


def build() -> tuple[dict, dict]:
    context = Context("regtest", "m1-share-tip", "m1-bitcoin-tip", 1_000)
    state = InputState(
        context=context,
        owners_by_outpoint={sale.share_outpoint: sale.seller_share_address for sale in SALES},
        authorized_sales_by_outpoint={sale.share_outpoint: sale for sale in SALES},
        previously_cleared_outpoints=frozenset(),
        previously_used_escrows=frozenset(),
    )
    inputs, plan = build_committed_inputs(SALES, ESCROWS, state, context, 999)

    # Same slot order as build_committed_inputs.
    ordered_sales = sorted(SALES, key=lambda sale: sale.share_outpoint)
    ordered_escrows = sorted(ESCROWS, key=lambda escrow: escrow.buyer_id)
    sale_slots = []
    for slot in range(SALE_SLOTS):
        sale = ordered_sales[slot] if slot < len(ordered_sales) else None
        sale_slots.append({
            "share_outpoint": sale.share_outpoint if sale else None,
            "seller_payee": sale.seller_bitcoin_address if sale else None,
        })
    buyer_slots = []
    for slot in range(BUYER_SLOTS):
        escrow = ordered_escrows[slot] if slot < len(ordered_escrows) else None
        buyer_slots.append({
            "buyer": escrow.buyer_id if escrow else None,
            "refund_payee": escrow.bitcoin_refund_address if escrow else None,
        })
    opening = {
        "domain": DOMAIN,
        "plan_commitment": plan.commitment,
        "fee_payee": FEE_PAYEE,
        "sale_slots": sale_slots,
        "buyer_slots": buyer_slots,
    }
    return inputs, opening


def main() -> None:
    out = pathlib.Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    inputs, opening = build()
    (out / "input.json").write_text(encode_snarkjs_input(inputs))
    (out / "opening.json").write_text(json.dumps(opening, indent=1, sort_keys=True))
    print(f"wrote {out / 'input.json'} and {out / 'opening.json'}")


if __name__ == "__main__":
    main()
