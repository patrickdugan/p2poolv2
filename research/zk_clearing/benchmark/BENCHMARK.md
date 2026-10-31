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
| **Measured** on regtest (Bitcoin Core 31.1) | Honest unchallenged batch, 897 vB (kickoff 197 + payout 700), fitted as 423 vB + 57.5 vB per escrow + 43 vB per payout output; challenged with an honest operator, 423,708 vB; tampered and disproved, 662,428 vB; challenge window 6 blocks; refund delay 30 blocks; bond 0.1 BTC | M2, [bitvm/M2.md](../bitvm/M2.md) (`zk-clearing-bitvm-m2`, 55b89b2b) |
| **Measured** proving | 0.85 s for v1 (16×4), 10.2 s for the signed v2 (16×4, 20 signatures); per-size times in M6 | [GROTH16.md](../GROTH16.md), [signed/SIGNED.md](../signed/SIGNED.md), [scaling/SCALING.md](../scaling/SCALING.md) |
| **Computed** from serialization rules (`txsize.py`, checked against reference sizes) | Bilateral HTLC funding 153–154 vB and claim 154–157 vB per swap; Lightning channel open 154 vB and close 169 vB; escrow funding 154 vB | `txsize.py`, `test_txsize.py` |
| **Modelled** (`MODEL` in `bench.py`) | HTLC wait 144 blocks; Lightning: 2 hops at 1 sat + 100 ppm per hop, channels living 4 weeks, capacity sized to a week (or a day) of sales; capital cost 2/5/10% a year; 0% or 1% of batches challenged | stated assumptions |

**How a batch is assembled.** Offers are taken in arrival order, N per batch. Each batch pays:

- one escrow-funding transaction per market maker in it;
- M2's measured honest path, 423 vB + 57.5 vB per escrow + 43 vB per payout output, with one
  output per distinct seller, one refund per market maker and one fee output.

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
| Batch clearing, 16 sales/batch | 144 | 288 | 1,439 | 7,195 |
| Batch clearing, 64 sales/batch | 54.8 | 110 | 548 | 2,738 |
| Batch clearing, 256 sales/batch | 20.6 | 41.3 | 206 | 1,032 |
| Batch clearing, 1024 sales/batch | 6.0 | 12.0 | 60.2 | 301 |

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

**Challenged batches.** A challenged batch whose operator lied costs 662,428 vB in M2's run
(challenge, assert chain, disprove and refunds), that is 661,531 vB more than an unchallenged one.
An honest operator who is challenged costs 423,708 vB. At 1% of batches challenged and disproved:

| Batch size | Without challenges | With 1% challenged |
|---|---|---|
| 1,024 | 6.0 vB | 12.6 vB |
| 256 | 20.6 vB | 47.1 vB |
| 64 | 54.8 vB | 158.6 vB |
| 16 | 143.9 vB | 557.3 vB |

**Proving time does not decide anything.** It is seconds per batch on one laptop (see
M4 and M6), and the payout waits six blocks for the challenge window anyway.

## Break-even fee rate

Below these on-chain fee rates batch clearing costs less per sale than the 2-hop Lightning swap.
Cost counts fees, routing, and capital at 5% a year:

| Batch size | Challenged batches | LN capacity = 1 day of sales | LN capacity = 1 week of sales |
|---|---|---|---|
| 16 | 0% | 0.3 sat/vB | 1.2 sat/vB |
| 16 | 1% | 0.1 sat/vB | 0.3 sat/vB |
| 64 | 0% | 0.7 sat/vB | 3.3 sat/vB |
| 64 | 1% | 0.3 sat/vB | 1.1 sat/vB |
| 256 | 0% | 2.0 sat/vB | 8.9 sat/vB |
| 256 | 1% | 0.9 sat/vB | 3.8 sat/vB |
| 1024 | 0% | 7.8 sat/vB | 34.1 sat/vB |
| 1024 | 1% | 3.4 sat/vB | 15.0 sat/vB |

## Decision (the roadmap's stop rule)

The rule: *"If batch clearing does not beat swaps over Lightning per sale at realistic sizes, the
BitVM path stops."*

- **Batch clearing loses to Lightning outside a narrow band.**
  - It wins only with large batches: 1,024 sales, which at this workload's rate of about one
    offer a minute means roughly daily settlement (median 18 h to fill).
  - It also needs low fee rates. Below 3.4–7.8 sat/vB it wins even against Lightning channels
    sized to one day of sales; against week-sized channels, below 15–34 sat/vB.
  - At 256-sale batches the band shrinks to 0.9–8.9 sat/vB; smaller batches essentially never win.
- **Bilateral on-chain swaps lose to both** by an order of magnitude or more at every fee rate:
  245–310 vB per sale.
- **Its real advantage is capital.** Collateral is 12–94 BTC·h a week against Lightning's
  2,794: escrows are locked only through the challenge window, not for the life of a channel.

**The challenge reward bounds the mode from the security side too.** M2 measured a disprove
paying the challenger 4.52 M sats from a 0.1 BTC bond. It estimates that this covers a disprove
through the largest leaf only up to about 3.5 sat/vB. Above that, an honest challenger loses
money, so the bond, and its share of the collateral, has to grow with the fee rate the mode
runs at. In the low-fee band that is a few times today's 0.1 BTC per batch, still small next to
Lightning's capacity.

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
- **The challenged-batch cost is for 18 public inputs.** M3's single-input statement shrinks the
  assert chain by about 18% *est.*
- **No real-value deployment** has been measured: the setup is insecure, and the keys and
  committee are demo ones (see M8).
