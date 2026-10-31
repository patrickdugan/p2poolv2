"""Render results.json as the Markdown tables in BENCHMARK.md.

Usage: python3 tables.py  (reads results.json, prints Markdown)
"""

from __future__ import annotations

import json
import pathlib
import sys

from bench import FEE_RATES, MODEL

HERE = pathlib.Path(__file__).resolve().parent
HOURS_PER_YEAR = 8760


def number(x: float) -> str:
    return f"{x:,.0f}" if abs(x) >= 100 else f"{x:,.1f}"


def schemes(r: dict) -> list[dict]:
    """One row per scheme: on-chain vbytes, fixed sats, collateral, latency, prover, refund."""
    rows = []
    labels = {"p2wsh": "Bilateral HTLC, P2WSH", "p2tr": "Bilateral HTLC, P2TR",
              "p2tr-batched-funding": "Bilateral HTLC, P2TR, funding batched per block"}
    for variant, label in labels.items():
        b = r["bilateral"][variant]
        hold_hours = r["model"]["htlc_claim_confirmations"] * 600 / 3600
        rows.append({"name": label, "vbytes": b["vbytes_total"], "fixed_sats": 0,
                     "collateral": r["workload"]["volume_sats"] / 1e8 * hold_hours,
                     "latency": "1 block", "prover": "—",
                     "refund": f"{r['model']['htlc_wait_blocks']} blocks"})
    ln = r["lightning"]
    rows.append({"name": f"Lightning ({r['model']['ln_hops']} hops)", "vbytes": ln["weekly_channel_vbytes"],
                 "fixed_sats": ln["routing_fees_sats"], "collateral": ln["collateral_btc_hours"],
                 "latency": "seconds", "prover": "—", "refund": "—"})
    for size, b in sorted(r["batch"].items(), key=lambda item: int(item[0])):
        prove = b["prove_seconds_per_batch"]
        rows.append({"name": f"Batch clearing, {size} sales/batch", "vbytes": b["on_chain_vbytes_total"],
                     "fixed_sats": 0, "collateral": b["collateral_btc_hours"],
                     "latency": f"{b['settlement_latency_seconds'] / 3600:,.1f} h",
                     "prover": f"{prove:,.1f} s/batch" if prove is not None else "not run",
                     "refund": f"{b['refund_delay_blocks']} blocks"})
    return rows


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    r = json.loads((HERE / "results.json").read_text())
    offers = r["workload"]["offers"]
    rows = schemes(r)

    print("**Fees per sale** (sats; on-chain vbytes at each fee rate plus Lightning routing fees)\n")
    header = ["Scheme", "vB per sale"] + [f"@{rate} sat/vB" for rate in FEE_RATES]
    print("| " + " | ".join(header) + " |\n|" + "---|" * len(header))
    for row in rows:
        cells = [row["name"], number(row["vbytes"] / offers)]
        cells += [number((row["vbytes"] * rate + row["fixed_sats"]) / offers) for rate in FEE_RATES]
        print("| " + " | ".join(cells) + " |")

    print("\n**Capital and time** (collateral locked per week of this workload, its cost per sale)\n")
    rates = MODEL["capital_cost_per_year"]
    header = ["Scheme", "Collateral (BTC·h/week)"] + [f"Capital cost/sale @{int(c * 100)}%/yr" for c in rates]
    header += ["Settlement latency (median)", "Refund delay"]
    print("| " + " | ".join(header) + " |\n|" + "---|" * len(header))
    for row in rows:
        cells = [row["name"], number(row["collateral"])]
        cells += [number(row["collateral"] * c / HOURS_PER_YEAR * 1e8 / offers) for c in rates]
        cells += [row["latency"], row["refund"]]
        print("| " + " | ".join(cells) + " |")




def breakevens() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    r = json.loads((HERE / "results.json").read_text())
    table = r["breakeven_fee_rate"]
    print("| Batch size | Challenged batches | LN capacity = 1 day of sales | LN capacity = 1 week of sales |")
    print("|---|---|---|---|")
    for size in sorted({int(key.split("/")[0]) for key in table}):
        for p in MODEL["challenge_probability"]:
            day = table[f"{size}/challenged {p}/ln {1 / 7}w"]
            week = table[f"{size}/challenged {p}/ln 1w"]
            print(f"| {size} | {p:.0%} | {day:.1f} sat/vB | {week:.1f} sat/vB |")


if __name__ == "__main__":
    breakevens() if "--breakeven" in sys.argv else main()
