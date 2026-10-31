# M7: batch clearing against bilateral and Lightning swaps

Run 2026-11-01. `python3 bench.py && python3 tables.py` reproduces every number below from
`measurements.json` and the fixed-seed workload. `python3 tables.py --breakeven` gives the
break-even table.

## Workload

- **Size:** 100 miners, 5 market makers, and 10,000 share-sale offers arriving uniformly over
  one week (`workload.py`, seed 20261101).
- **Miners:** hashrate shares are Pareto (α = 1.2); each offer's seller is drawn by hashrate and
  its buyer uniformly.
- **Prices:** log-normal with a 50,000-sat median, 8.32 BTC in total.

## What is measured, computed and modelled

| Kind | Inputs | Source |
|---|---|---|
| **Measured** on regtest (Bitcoin Core 31.1) | Honest unchallenged batch, 897 vB (kickoff 197 + payout 700); challenge tx, 212 vB; challenge window 6 blocks; refund delay 30 blocks; bond 0.1 BTC | M2 run (`zk-clearing-bitvm-m2`) |
| **Measured** on regtest | Assert chain, 422,650 vB; final-pairing disprove, 238,931 vB. Used as the extra cost of a challenged batch | M1, [bitvm/M1.md](../bitvm/M1.md) |
| **Measured** proving | 0.85 s for v1 (16×4), 10.2 s for the signed v2 (16×4, 20 signatures); per-size times in M6 | [GROTH16.md](../GROTH16.md), [signed/SIGNED.md](../signed/SIGNED.md), [scaling/SCALING.md](../scaling/SCALING.md) |
| **Computed** from serialization rules (`txsize.py`, checked against reference sizes) | Bilateral HTLC funding 153–154 vB and claim 154–157 vB per swap; Lightning channel open 154 vB and close 169 vB; per-output (43 vB) and per-escrow-input deltas when a batch payout grows | `txsize.py`, `test_txsize.py` |
| **Modelled** (`MODEL` in `bench.py`) | HTLC wait 144 blocks; Lightning: 2 hops at 1 sat + 100 ppm per hop, channels living 4 weeks, capacity sized to a week (or a day) of sales; capital cost 2/5/10% a year; 0% or 1% of batches challenged | stated assumptions |

**How a batch is assembled.** Offers are taken in arrival order, N per batch. Each batch pays:

- one escrow-funding transaction per market maker in it;
- M2's measured kickoff;
- a payout anchored on M2's measured 700 vB (4 inputs, 8 outputs) plus 43 vB per additional
  output, with one output per distinct seller, refund, fee and change.

Collateral is the escrowed amount plus the bond, locked for the challenge window plus two
blocks.

## Results

**Fees per sale** (sats; on-chain vbytes at each fee rate plus Lightning routing fees)

| Scheme | vB per sale | @2 sat/vB | @10 sat/vB | @50 sat/vB |
|---|---|---|---|---|
| Bilateral HTLC, P2WSH | 310 | 620 | 3,100 | 15,500 |
| Bilateral HTLC, P2TR | 308 | 616 | 3,080 | 15,400 |
| Bilateral HTLC, P2TR, funding batched per block | 245 | 491 | 2,454 | 12,268 |
| Lightning (2 hops) | 0.8 | 20.2 | 26.7 | 59.0 |
| Batch clearing, 16 sales/batch | 147 | 294 | 1,468 | 7,342 |
| Batch clearing, 64 sales/batch | 55.6 | 111 | 556 | 2,778 |
| Batch clearing, 256 sales/batch | 20.8 | 41.7 | 208 | 1,042 |
| Batch clearing, 1024 sales/batch | 6.1 | 12.1 | 60.7 | 303 |

**Capital and time** (collateral locked per week of this workload, its cost per sale)

| Scheme | Collateral (BTC·h/week) | Capital cost/sale @2%/yr | Capital cost/sale @5%/yr | Capital cost/sale @10%/yr | Settlement latency (median) | Refund delay |
|---|---|---|---|---|---|---|
| Bilateral HTLC, P2WSH | 1.4 | 0.0 | 0.1 | 0.2 | 1 block | 144 blocks |
| Bilateral HTLC, P2TR | 1.4 | 0.0 | 0.1 | 0.2 | 1 block | 144 blocks |
| Bilateral HTLC, P2TR, funding batched per block | 1.4 | 0.0 | 0.1 | 0.2 | 1 block | 144 blocks |
| Lightning (2 hops) | 2,794 | 63.8 | 159 | 319 | seconds | — |
| Batch clearing, 16 sales/batch | 94.4 | 2.2 | 5.4 | 10.8 | 1.6 h | 30 blocks |
| Batch clearing, 64 sales/batch | 32.0 | 0.7 | 1.8 | 3.7 | 2.4 h | 30 blocks |
| Batch clearing, 256 sales/batch | 16.4 | 0.4 | 0.9 | 1.9 | 5.6 h | 30 blocks |
| Batch clearing, 1024 sales/batch | 12.4 | 0.3 | 0.7 | 1.4 | 18.4 h | 30 blocks |

**Challenged batches.** A challenged batch adds about 662 kvB (challenge, assert chain and
disprove, from the M1 and M2 measurements). At 1% of batches that raises the cost per sale:

| Batch size | Without challenges | With 1% challenged |
|---|---|---|
| 1,024 | 6.1 vB | 12.7 vB |
| 256 | 20.8 vB | 47.3 vB |
| 64 | 55.6 vB | 159.5 vB |
| 16 | 146.8 vB | 560.5 vB |

**Proving time does not decide anything.** It is seconds per batch on one laptop (see
M4 and M6), and the payout waits six blocks for the challenge window anyway.

## Break-even fee rate

Below these on-chain fee rates batch clearing costs less per sale than the 2-hop Lightning swap.
Cost counts fees, routing, and capital at 5% a year:

| Batch size | Challenged batches | LN capacity = 1 day of sales | LN capacity = 1 week of sales |
|---|---|---|---|
| 16 | 0% | 0.2 sat/vB | 1.2 sat/vB |
| 16 | 1% | 0.1 sat/vB | 0.3 sat/vB |
| 64 | 0% | 0.7 sat/vB | 3.2 sat/vB |
| 64 | 1% | 0.2 sat/vB | 1.1 sat/vB |
| 256 | 0% | 2.0 sat/vB | 8.8 sat/vB |
| 256 | 1% | 0.9 sat/vB | 3.8 sat/vB |
| 1024 | 0% | 7.7 sat/vB | 33.7 sat/vB |
| 1024 | 1% | 3.4 sat/vB | 14.9 sat/vB |

## Decision (the roadmap's stop rule)

The rule: *"If batch clearing does not beat swaps over Lightning per sale at realistic sizes, the
BitVM path stops."*

- **Batch clearing loses to Lightning outside a narrow band.**
  - It wins only with large batches: 1,024 sales, which at this workload's rate of about one
    offer a minute means roughly daily settlement (median 18 h to fill).
  - It also needs low fee rates. Below 3.4–7.7 sat/vB it wins even against Lightning channels
    sized to one day of sales; against week-sized channels, below 15–34 sat/vB.
  - At 256-sale batches the band shrinks to 0.9–8.8 sat/vB; smaller batches essentially never win.
- **Bilateral on-chain swaps lose to both** by an order of magnitude or more at every fee rate:
  245–310 vB per sale.
- **Its real advantage is capital.** Collateral is 12–94 BTC·h a week against Lightning's
  2,794: escrows are locked only through the challenge window, not for the life of a channel.

**Verdict: the BitVM path does not stop, but it narrows to one mode.** That mode is periodic
(daily) settlement of large batches when fees are low, as the capital-efficient alternative to
Lightning liquidity. The default for individual and urgent sales stays Lightning or Ark swaps,
with off-chain netting. M8 proceeds only for that mode.

## Limits

- **Sharechain side not costed.** Share transfers on P2Poolv2's sharechain cost nothing in
  bitcoin; they are the same in every scheme, so they are left out.
- **Lightning is simplified.** No liquidity-ads market, no splicing, no loop-out fees beyond
  sizing capacity to a day or a week, and no payment failures. Real Lightning costs could be
  higher (failures, rebalancing) or lower (channels reused for other traffic).
- **Batch latency is fill time at this arrival rate.** A busier pool fills 1,024-sale batches
  faster.
- **The challenged-batch cost uses M1's 18-input assert chain.** M3's single-input statement
  shrinks it by about 18% *est.*, and M2's own challenged runs will replace it when they land.
- **No real-value deployment** has been measured: the setup is insecure, and the keys and
  committee are demo ones (see M8).
