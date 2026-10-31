"""M7: clear the same 10,000 offers three ways and compare.

  A. bilateral on-chain HTLC swaps (docs/atomic-swap/htlc_scripts.md),
  B. Lightning swaps (docs/atomic-swap/p2pool-2-lightinig-example.md),
  C. batch clearing with the M2 optimistic BitVM graph, at several batch sizes.

Measured inputs (regtest runs, proving runs) come from measurements.json,
each with its source. Transaction sizes not measured on regtest are computed
by txsize.py from serialization rules. Everything else is a stated model
parameter in MODEL below. Output: results.json and the tables in BENCHMARK.md
(printed as Markdown with --markdown).
"""

from __future__ import annotations

import json
import math
import pathlib
import statistics
import sys
from collections import defaultdict

from txsize import (
    P2TR_KEY_IN,
    P2TR_OUT,
    P2WPKH_IN,
    P2WPKH_OUT,
    P2WSH_OUT,
    Input,
    htlc_p2tr_claim_input,
    htlc_p2wsh_claim_input,
    p2tr_committee_leaf_input,
    vbytes,
    witness,
)
from workload import MARKET_MAKERS, MINERS, OFFERS, WEEK_SECONDS, offers

HERE = pathlib.Path(__file__).resolve().parent
BLOCK_SECONDS = 600
FEE_RATES = (2, 10, 50)
BATCH_SIZES = (16, 64, 256, 1024)

# Model parameters (not measured). Each is used exactly where named.
MODEL = {
    "htlc_wait_blocks": 144,  # bilateral HTLC refund delay
    "htlc_claim_confirmations": 1,
    "ln_hops": 2,  # miner <- hub <- market maker
    "ln_base_fee_msat": 1_000,  # per hop
    "ln_fee_ppm": 100,  # per hop
    "ln_channel_lifetime_weeks": 4,  # opens and closes amortized over this
    "ln_inbound_weeks": 1,  # miner inbound capacity sized to this many weeks of sales
    "challenge_probability": (0.0, 0.01),  # share of batches that get challenged
    "capital_cost_per_year": (0.02, 0.05, 0.10),  # what locking 1 BTC for a year costs its owner
}


def ln_cooperative_close_vbytes() -> int:
    # 2-of-2 P2WSH: <> <sig> <sig> <2 <pk> <pk> 2 CHECKMULTISIG>, two P2WPKH outputs.
    multisig_script = 1 + 34 + 34 + 1 + 1
    close_input = Input(witness([0, 72, 72, multisig_script]))
    return vbytes([close_input], [P2WPKH_OUT, P2WPKH_OUT])


def bilateral(workload, fee_rate: int, variant: str) -> dict:
    """One HTLC per offer: the market maker funds it, the miner claims it."""
    if variant == "p2wsh":
        funding = vbytes([P2WPKH_IN], [P2WSH_OUT, P2WPKH_OUT])
        claim = vbytes([htlc_p2wsh_claim_input(MODEL["htlc_wait_blocks"])], [P2WPKH_OUT])
    elif variant == "p2tr":
        funding = vbytes([P2TR_KEY_IN], [P2TR_OUT, P2TR_OUT])
        claim = vbytes([htlc_p2tr_claim_input()], [P2TR_OUT])
    elif variant == "p2tr-batched-funding":
        # Each market maker funds all HTLCs that arrive within a block in one transaction.
        per_mm_block = defaultdict(int)
        for offer in workload:
            per_mm_block[(offer.market_maker, int(offer.arrival // BLOCK_SECONDS))] += 1
        total_funding = sum(vbytes([P2TR_KEY_IN], [P2TR_OUT] * (n + 1)) for n in per_mm_block.values())
        claim = vbytes([htlc_p2tr_claim_input()], [P2TR_OUT])
        total = total_funding + claim * len(workload)
        return {"vbytes_total": total, "funding_txs": len(per_mm_block), "claim_vbytes": claim}
    else:
        raise ValueError(variant)
    total = (funding + claim) * len(workload)
    return {"vbytes_total": total, "funding_vbytes": funding, "claim_vbytes": claim}


def lightning(workload) -> dict:
    """On-chain cost is channel opens and closes; per-sale cost is routing fees."""
    open_vbytes = vbytes([P2TR_KEY_IN], [P2WSH_OUT, P2TR_OUT])
    close_vbytes = ln_cooperative_close_vbytes()
    weekly_channel_vbytes = MINERS * (open_vbytes + close_vbytes) / MODEL["ln_channel_lifetime_weeks"]
    fees_msat = sum(
        MODEL["ln_hops"] * (MODEL["ln_base_fee_msat"] + offer.price_sats * 1000 * MODEL["ln_fee_ppm"] // 1_000_000)
        for offer in workload
    )
    weekly_receipts = defaultdict(int)
    for offer in workload:
        weekly_receipts[offer.miner] += offer.price_sats
    inbound_capacity = sum(weekly_receipts.values()) * MODEL["ln_inbound_weeks"]
    return {
        "open_vbytes": open_vbytes,
        "close_vbytes": close_vbytes,
        "weekly_channel_vbytes": weekly_channel_vbytes,
        "routing_fees_sats": fees_msat / 1000,
        # Routing V from market maker to miner needs capacity V in each hop's channel,
        # locked for the whole week.
        "collateral_btc_hours": MODEL["ln_hops"] * inbound_capacity / 1e8 * 168,
    }


def batch_clearing(workload, batch_size: int, measured: dict) -> dict:
    m2 = measured["m2"]
    escrow_funding = vbytes([P2TR_KEY_IN], [P2TR_OUT, P2TR_OUT])
    escrow_spend = p2tr_committee_leaf_input(1)
    escrow_input_delta = math.ceil((4 * 41 + escrow_spend.witness_bytes) / 4)
    batches = [workload[i : i + batch_size] for i in range(0, len(workload), batch_size)]
    per_batch = []
    for batch in batches:
        payees = len({offer.miner for offer in batch})
        escrows = len({offer.market_maker for offer in batch})
        outputs = payees + escrows + 1 + 1  # sellers, refunds, fee, operator change
        # Anchored on M2's measured payout (4 inputs, 8 outputs); computed deltas per output and escrow.
        payout = m2["payout_vbytes"] + 43 * (outputs - 8) + escrow_input_delta * (escrows - 3)
        on_chain = escrows * escrow_funding + m2["honest_unchallenged_vbytes"] - m2["payout_vbytes"] + payout
        fill_seconds = batch[-1].arrival - batch[0].arrival
        per_batch.append(
            {
                "sales": len(batch),
                "payees": payees,
                "escrows": escrows,
                "on_chain_vbytes": on_chain,
                "fill_seconds": fill_seconds,
                "escrow_sats": sum(offer.price_sats for offer in batch),
            }
        )
    window_seconds = (m2["t_challenge_blocks"] + 2) * BLOCK_SECONDS
    prove = measured["m6"].get(str(batch_size), {}).get("prove_seconds")
    return {
        "batches": len(batches),
        "on_chain_vbytes_total": sum(b["on_chain_vbytes"] for b in per_batch),
        "median_fill_seconds": statistics.median(b["fill_seconds"] for b in per_batch),
        "prove_seconds_per_batch": prove,
        "settlement_latency_seconds": (
            statistics.median(b["fill_seconds"] for b in per_batch) + (prove or 0) + window_seconds
        ),
        "collateral_btc_hours": (
            sum(b["escrow_sats"] for b in per_batch) / 1e8 * window_seconds / 3600
            + len(batches) * m2["bond_sats"] / 1e8 * window_seconds / 3600
        ),
        "challenged_batch_extra_vbytes": m2["challenged_extra_vbytes"],
        "refund_delay_blocks": m2["t_refund_blocks"],
    }


def breakeven(workload, measured, batch_size: int, challenge_probability: float,
              ln_inbound_weeks: float, capital_cost: float) -> float:
    """Fee rate (sat/vB) below which batch clearing costs less per sale than Lightning.

    Cost per sale = on-chain vbytes x fee rate + routing fees + capital cost of the
    collateral at `capital_cost` per year. Challenged batches add the measured
    challenged-path vbytes with the given probability.
    """
    n = len(workload)
    hour_cost = capital_cost / 8760 * 1e8
    b = batch_clearing(workload, batch_size, measured)
    batch_vb = (b["on_chain_vbytes_total"] + challenge_probability * b["batches"] * b["challenged_batch_extra_vbytes"]) / n
    batch_fixed = b["collateral_btc_hours"] * hour_cost / n
    saved = MODEL["ln_inbound_weeks"]
    MODEL["ln_inbound_weeks"] = ln_inbound_weeks
    ln = lightning(workload)
    MODEL["ln_inbound_weeks"] = saved
    ln_vb = ln["weekly_channel_vbytes"] / n
    ln_fixed = (ln["routing_fees_sats"] + ln["collateral_btc_hours"] * hour_cost) / n
    if batch_vb <= ln_vb:
        return math.inf
    return (ln_fixed - batch_fixed) / (batch_vb - ln_vb)


def run() -> dict:
    measured = json.loads((HERE / "measurements.json").read_text())
    workload = offers()
    volume = sum(offer.price_sats for offer in workload)
    result = {
        "workload": {"miners": MINERS, "market_makers": MARKET_MAKERS, "offers": OFFERS,
                     "volume_sats": volume, "week_seconds": WEEK_SECONDS},
        "model": MODEL,
        "bilateral": {v: bilateral(workload, 0, v) for v in ("p2wsh", "p2tr", "p2tr-batched-funding")},
        "lightning": lightning(workload),
        "batch": {str(n): batch_clearing(workload, n, measured) for n in BATCH_SIZES},
        "breakeven_fee_rate": {
            f"{n}/challenged {p}/ln {weeks}w": breakeven(workload, measured, n, p, weeks, 0.05)
            for n in BATCH_SIZES for p in MODEL["challenge_probability"] for weeks in (1 / 7, 1)
        },
    }
    return result


if __name__ == "__main__":
    out = run()
    (HERE / "results.json").write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
    print(json.dumps(out, indent=2, sort_keys=True)[:4000] if "--markdown" not in sys.argv else "")
