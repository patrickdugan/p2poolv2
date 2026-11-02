"""The regtest clearing batch settled by the BitVM M17 run (owned_tree_pk_16x4, M15's packed joined
circuit).

Starts from the joined fixture's `valid` variant (joinedtree/fixtures.sh: sale slot s sells the
output at the s-th lowest position of the packed window tree, signed by its registered owner's order
key) and changes what the regtest graph needs, as batch_signed.py does for M14:
  - refunds are 38,000, 31,000, 12,000 and 17,000 sats, so every output the template builds clears
    the 330-sat P2TR dust limit, and funding follows (cost + fee budget + refund);
  - batchHeight is BATCH_HEIGHT, a height the regtest chain reaches (it starts at 200): the driver
    mines up to BATCH_HEIGHT - 3 and funds the escrows in the next block;
  - every escrowExpiry is batchHeight + ESCROW_EXPIRY_AFTER_BATCH (27: M13's timing, five blocks
    more than the circuit's ESCROW_AFTER_BATCH = 22), every orderExpiry batchHeight + 144.
The ids the circuit signs are the field encodings of the labels batch_signed.py documents
(`scale-payout:<s>`, `scale-escrow:<b>:0`, `scale-refund:<b>`), which fixtures give the joined
batch as well.

Writes into the output directory:
  variants/manifest.json, variants/valid.spec.json, variants/valid.own.json
                the one-variant input of joinedtree/sign_tree.js (spec with the changes above, and
                the membership witness, which does not depend on amounts or heights)
  opening.json  the slot layout with the payee labels the graph pays, and `window_root`, the
                root of the dense window tree as joined/world.json records it: the root watchers
                publish, which the committee's template compares with the statement's last value

Usage: python3 -B batch_joined.py <joined fixture work dir> <output directory>
       (the work dir is <joined build dir>/inputs/work: world.json and variants/)
"""

from __future__ import annotations

import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from model import DOMAIN  # noqa: E402

SALE_SLOTS = 16
BUYER_SLOTS = 4
FEE_PAYEE = "operator-fee"
REFUNDS = (38_000, 31_000, 12_000, 17_000)
BATCH_HEIGHT = 230
ESCROW_EXPIRY_AFTER_BATCH = 27
ORDER_EXPIRY_AFTER_BATCH = 144
# signed_terms.circom
DEADLINE_AFTER_BATCH = 4
ESCROW_AFTER_BATCH = 22
P2TR_DUST = 330


def adjust(spec: dict) -> dict:
    """The fixture's valid spec with the regtest refunds, funding, height and expiries."""
    inputs = spec["inputs"]
    assert len(inputs["price"]) == SALE_SLOTS and len(inputs["funding"]) == BUYER_SLOTS
    out = json.loads(json.dumps(spec))
    new = out["inputs"]
    new["batchHeight"] = str(BATCH_HEIGHT)
    for sale in range(SALE_SLOTS):
        assert inputs["activeSale"][sale] == "1"
        new["orderExpiry"][sale] = str(BATCH_HEIGHT + ORDER_EXPIRY_AFTER_BATCH)
    for buyer in range(BUYER_SLOTS):
        assert inputs["activeBuyer"][buyer] == "1"
        cost = sum(int(inputs["price"][s]) for s in range(SALE_SLOTS) if inputs["selector"][s][buyer] == "1")
        new["refund"][buyer] = str(REFUNDS[buyer])
        new["funding"][buyer] = str(cost + int(inputs["feeBudget"][buyer]) + REFUNDS[buyer])
        new["escrowExpiry"][buyer] = str(BATCH_HEIGHT + ESCROW_EXPIRY_AFTER_BATCH)
        assert int(new["escrowExpiry"][buyer]) >= BATCH_HEIGHT + ESCROW_AFTER_BATCH
        assert int(inputs["feeBudget"][buyer]) <= int(inputs["feeCap"][buyer])
    for sale in range(SALE_SLOTS):
        assert int(new["orderExpiry"][sale]) >= BATCH_HEIGHT + DEADLINE_AFTER_BATCH
        assert int(new["price"][sale]) >= P2TR_DUST
    assert sum(int(p) for p in new["price"]) == int(new["totalPayout"])
    return out


def main() -> None:
    work = pathlib.Path(sys.argv[1])
    out = pathlib.Path(sys.argv[2])
    variants = out / "variants"
    variants.mkdir(parents=True, exist_ok=True)
    spec = adjust(json.loads((work / "variants" / "valid.spec.json").read_text()))
    world = json.loads((work / "world.json").read_text())
    assert world["membership"] == "packed" and world["sales"] == SALE_SLOTS and world["buyers"] == BUYER_SLOTS
    (variants / "valid.spec.json").write_text(json.dumps(spec, sort_keys=True, separators=(",", ":")))
    (variants / "valid.own.json").write_bytes((work / "variants" / "valid.own.json").read_bytes())
    (variants / "manifest.json").write_text(json.dumps(
        [{"name": "valid", "kind": "valid", "note": "the regtest batch", "rejectedIn": None, "predicted": [], "post": []}]))
    opening = {
        "domain": DOMAIN,
        "fee_payee": FEE_PAYEE,
        "window_root": world["window_tree"]["root"],
        "sale_slots": [
            {"share_outpoint": f"scale-share:{sale}", "seller_payee": f"scale-payout:{sale}"}
            for sale in range(SALE_SLOTS)
        ],
        "buyer_slots": [
            {"buyer": f"scale-buyer:{buyer}", "escrow": f"scale-escrow:{buyer}:0", "refund_payee": f"scale-refund:{buyer}"}
            for buyer in range(BUYER_SLOTS)
        ],
    }
    (out / "opening.json").write_text(json.dumps(opening, indent=1, sort_keys=True))
    print(f"wrote {variants} and {out / 'opening.json'} (batchHeight {BATCH_HEIGHT}, window root {opening['window_root']})")


if __name__ == "__main__":
    main()
