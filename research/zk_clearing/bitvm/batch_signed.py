"""The regtest clearing batch settled by the BitVM M14 demo (signed_tree_16x4, M11's circuit).

M11's deterministic 16 x 4 batch (signedtree/gen_batch.py, every slot active) with the refunds
set so that every output the template builds clears Bitcoin Core's dust limit: the original
refunds include 290 sats for buyer slot 2.

Every id the circuit signs is the field encoding of a label, and the labels are the payees the
regtest graph pays, so the template can check that the script it pays is the one the seller or
buyer signed:
  sellerPayoutId[s]  = field_id("seller_payout_script", "scale-payout:<s>")
  escrowId[b]        = field_id("escrow_outpoint", "scale-escrow:<b>:0")
  refundScriptId[b]  = field_id("refund_script", "scale-refund:<b>")

Writes two files into the output directory:
  spec.json     the unsigned batch, for signedtree/sign.js (keys, signatures, statementHash)
  opening.json  the slot layout with the payee labels the graph pays

Usage: python3 -B batch_signed.py <output directory>
"""

from __future__ import annotations

import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "signedtree"))

from gen_batch import check, stringify, with_signed_terms  # noqa: E402
from gen_inputs import batch  # noqa: E402
from model import DOMAIN  # noqa: E402

SALE_SLOTS = 16
BUYER_SLOTS = 4
FEE_PAYEE = "operator-fee"
# Refund per buyer slot, in sats: all at least the 330-sat P2TR dust limit, and buyer slot 1 holds
# enough to move 10,000 sats to slot 0 in the tampered scenario.
REFUNDS = (38_000, 31_000, 12_000, 17_000)


def build() -> tuple[dict, dict]:
    inputs = batch(SALE_SLOTS, BUYER_SLOTS)
    for buyer in range(BUYER_SLOTS):
        cost = sum(inputs["price"][sale] for sale in range(SALE_SLOTS) if sale % BUYER_SLOTS == buyer)
        inputs["refund"][buyer] = REFUNDS[buyer]
        inputs["funding"][buyer] = cost + inputs["feeBudget"][buyer] + REFUNDS[buyer]
    merged, seller_labels, buyer_labels = with_signed_terms(inputs)
    check(merged)
    spec = {
        "inputs": {key: stringify(value) for key, value in merged.items()},
        "sellerKeyLabels": seller_labels,
        "buyerKeyLabels": buyer_labels,
    }
    opening = {
        "domain": DOMAIN,
        "fee_payee": FEE_PAYEE,
        "sale_slots": [
            {"share_outpoint": f"scale-share:{sale}", "seller_payee": f"scale-payout:{sale}"}
            for sale in range(SALE_SLOTS)
        ],
        "buyer_slots": [
            {"buyer": f"scale-buyer:{buyer}", "escrow": f"scale-escrow:{buyer}:0", "refund_payee": f"scale-refund:{buyer}"}
            for buyer in range(BUYER_SLOTS)
        ],
    }
    return spec, opening


def main() -> None:
    out = pathlib.Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    spec, opening = build()
    (out / "spec.json").write_text(json.dumps(spec, sort_keys=True))
    (out / "opening.json").write_text(json.dumps(opening, indent=1, sort_keys=True))
    print(f"wrote {out / 'spec.json'} and {out / 'opening.json'}")


if __name__ == "__main__":
    main()
