# Timeouts sized for a public chain

ROADMAP item 1. M16's testnet4 run used up every margin of the graph: the kickoff waited 7 empty
blocks, the challenge landed in its last allowed block, and a 4-block reorg re-mined assert_final
2 blocks after the timeout opened. The T values were regtest numbers. They are now a function of
two chain parameters, and the regtest numbers are one profile of it.

Numbers marked *est.* are arithmetic, not runs.

## 1. The two parameters

| | Meaning | How to get it |
|---|---|---|
| **G** | blocks in a row that may include none of our transactions | the longest run of blocks that take no transaction at the fee rate the graph pays |
| **R** | the deepest reorg to survive | the deepest stale branch the chain shows |

From them, **W = G + 1** is one inclusion step: a transaction posted at tip *t* is mined by block
*t* + W. A transaction first mined at block *x* can be mined again as late as *x* + R: a reorg
replaces at most R blocks, and the blocks that replace them may omit it. M16 showed exactly this
(assert_final first mined at 158614, mined again at 158618 after a 4-block reorg).

**What a window needs.** A window ends at block D, the block in which a competing transaction
first becomes valid. The last block in which our transaction can safely be mined is D − 1. A
window with *s* sequential transactions therefore needs *s*·W + R blocks.

The model is one reorg of depth at most R per window, with G and R taken from a record. It sizes
the clocks against the chain's observed behaviour. It is not a bound against an attacker who
controls hashrate: a miner majority can exceed any R.

## 2. The windows

Heights: *h_k* is the block that mines the kickoff, *h_a* the block that mines assert_final,
*h_e* the block that mines the escrows. Relative locktimes open in block (confirmation + value),
so a CSV of *v* leaves *v* − 1 blocks in which the competing transaction is not valid.

| # | Window | Starts | Competing transaction valid in | Needs | Constraint |
|---|---|---|---|---|---|
| 1 | Challenge | the watcher sees the kickoff at *h_k* | payout_unchallenged, block *h_k* + T_challenge | W + R | T_challenge − 1 ≥ W + R |
| 2 | Unchallenged payout | the payout opens (tip *h_k* + T_challenge − 1) | timeout, block *h_k* + T_assert | W + R | T_assert − T_challenge ≥ W + R |
| 3 | Assert chain | the last-block challenge, *h_k* + T_challenge − 1 | timeout, block *h_k* + T_assert | 3W + R | T_assert − T_challenge ≥ 3W + R |
| 4 | Disprove | assert_final at *h_a* | payout_asserted, block *h_a* + T_disprove | W_d + R | T_disprove − 1 ≥ W_d + R |
| 5 | Kickoff (bound) | tip batchHeight | the sweep of the deadline connector, block batchHeight + D + 1 | W + R | D ≥ W + R |
| 6 | Latest payout (bound) | the latest payout_asserted opens | the earliest signed refund, block batchHeight + E + 1 | W + R | E ≥ D + (T_assert − 1) + T_disprove + (W + R) − 1 |
| 7 | Latest payout (unbound) | the latest payout_asserted opens | a CSV refund, block *h_e* + T_refund | W + R | T_refund ≥ T_kickoff + (T_assert − 1) + T_disprove + (W + R) |
| 8 | Kickoff (unbound, policy) | the escrows confirm | | W + R | T_kickoff ≥ W + R |

where D = DEADLINE_AFTER_BATCH, E = ESCROW_AFTER_BATCH, and W_d = G_d + 1 for the disprove.

Why each is what it is:

1. A challenge that lands after the payout opens races the payout for KC. The watcher posts when
   it sees the kickoff mined, so the challenge lands by *h_k* + W, and again by *h_k* + W + R.
2. KB can only be spent by the payout from *h_k* + T_challenge until the timeout opens. The
   operator posts the payout at tip *h_k* + T_challenge − 1.
3. The challenger can wait until the last block, *h_k* + T_challenge − 1. The operator starts
   assert_init when it sees the challenge mined. Three steps follow: assert_init with commit[0],
   commits 1 to 4, assert_final (M2 probes why: only one commit fits in the mempool beside an
   unconfirmed assert_init). assert_final lands by *h_k* + T_challenge − 1 + 3W and again by + R,
   and must be in by *h_k* + T_assert − 1. A timeout in block *h_k* + T_assert conflicts with it
   over KA, so landing in that block is a loss. Window 3 contains window 2.
4. The disprove is non-standard (M12), so it has its own gap G_d: the longest run of blocks that
   take a disprove. It equals G unless set (`ZKC_DISPROVE_GAP`). A deployment sets G_d from the
   hashrate that accepts non-standard transactions: M12 gives 135 blocks at 5% and 688 at 1%
   (ε = 10⁻³). With G = 90 the testnet4 profile gives the disprove no more than a standard
   transaction gets; real disproves need the larger G_d, and T_disprove, the escrow bound and
   T_refund grow with it (section 5).
5. batchHeight is the lock time, so the kickoff is valid from batchHeight + 1. The connector is
   sweepable in block batchHeight + D + 1 (CLTV height batchHeight + D, nLockTime must be below the
   block height), so the kickoff's last safe block is batchHeight + D.
6. The latest kickoff lands at batchHeight + D. Its challenge window and assert chain end at
   *h_k* + T_assert − 1, payout_asserted opens T_disprove later, and the operator needs W + R blocks
   to land it. A CLTV refund at expiry batchHeight + E is valid from the next block.
7. The same without a deadline connector: kickoff by *h_e* + T_kickoff.

### Closed forms (G_d = G)

| | |
|---|---|
| T_challenge | W + R + 1 |
| T_assert | 4W + 2R + 1 |
| T_disprove | W + R + 1 |
| T_kickoff, DEADLINE_AFTER_BATCH | W + R |
| ESCROW_AFTER_BATCH | 7W + 5R |
| T_REFUND | 7W + 5R + 1 |

`Timing::from_chain(G, R, G_d)` computes them as the least values that pass; a unit test shrinks
each by one block and requires the check to fail.

### Two off-by-ones

Two inequalities are one block stricter than the first draft of the formulas:

- **Window 3** is T_assert − T_challenge ≥ 3W + R, not T_assert − (T_challenge − 1) ≥ 3W + R. The
  draft put assert_final's re-landing in block *h_k* + T_assert, the block that opens the timeout.
- **Window 4** is T_disprove − 1 ≥ W_d + R. payout_asserted opens in block *h_a* + T_disprove, so
  the disprove's last safe block is *h_a* + T_disprove − 1. The first draft had T_disprove ≥ W + R.

Both leave the regtest numbers dominated (section 4).

## 3. What the code does

[`m2/src/graph.rs`](m2/src/graph.rs) has `Timing` in place of the constants T_KICKOFF,
T_CHALLENGE, T_ASSERT, T_DISPROVE, T_REFUND, MARGIN, DEADLINE_AFTER_BATCH and ESCROW_AFTER_BATCH.
`Timing::constraints()` lists the eight windows above with the blocks each has and needs;
`Timing::check()` requires every one to have what it needs, every need to be at least W + R, and
every clock to fit BIP68 (at most 65,535). `from_chain` returns an error when a clock does not
fit; T_REFUND = 7W + 5R + 1 is the largest.

The driver ([`m2/src/main.rs`](m2/src/main.rs)) builds one `Timing` per run and threads it through
every CSV and CLTV script (challenge, assert, disprove, timeout, CSV refunds), the deadline
connector's height, the escrow expiries the buyers sign, the probe heights of each scenario and
`timing_slack`. It records the profile, the eight constraints and whether the circuit covers the
profile in every result JSON (`timing`).

| Environment | Effect |
|---|---|
| (none), `ZKC_TIMING=regtest` | the regtest profile: the numbers M2 to M17 ran with |
| `ZKC_TIMING=testnet4` | G = 90, R = 16, G_d = G |
| `ZKC_INCLUSION_GAP=<G> ZKC_REORG_DEPTH=<R> [ZKC_DISPROVE_GAP=<G_d>]` | a custom profile; G and R must both be set and win over `ZKC_TIMING` |

A non-default profile's results go to a directory with the profile's tag appended
(`testnet4`, `g3r2`, `g3r2d40`), and `run-m16.sh` follows that (`<work>/m16/<mode>-<tag>`).
`zkc-m2 timing` prints the active profile and its constraints.
`run-m16.sh rehearse` takes `REHEARSE_RPC_PORT` (default 18803) for the private node.

**Escrow expiries.** In a run whose statement fixes the expiries (M17), the driver refuses an
escrow whose committed `escrowExpiry` is below batchHeight + the profile's ESCROW_AFTER_BATCH. In
a run that picks them (M13, M16) buyers sign batchHeight + max(ESCROW_AFTER_BATCH,
T_REFUND − 1 − 2), which is 27 on regtest, as before.

## 4. Profiles

| Profile | G | R | T_kickoff | T_challenge | T_assert | T_disprove | T_refund | DEADLINE_AFTER_BATCH | ESCROW_AFTER_BATCH |
|---|---|---|---|---|---|---|---|---|---|
| `regtest` (M2 to M17) | 0 | 1 | 6 | 6 | 12 | 6 | 30 | 4 | 22 |
| least for G 0, R 1 | 0 | 1 | 2 | 3 | 7 | 3 | 13 | 2 | 12 |
| rehearsal | 3 | 2 | 6 | 7 | 21 | 7 | 39 | 6 | 38 |
| mainnet-like, **an assumption, not a measurement** | 6 | 6 | 13 | 14 | 41 | 14 | 80 | 13 | 79 |
| `testnet4` | 90 | 16 | 107 | 108 | 397 | 108 | 718 | 107 | 717 |

The regtest profile is G = 0, R = 1, so W + R = 2, which is the old MARGIN. Every regtest clock is
at least the derived least. The escrow bound is the one place with no room: ESCROW_AFTER_BATCH = 4
+ 11 + 6 + 2 − 1 = 22 exactly, as M13 derived it. The regtest slack by constraint:

| Constraint | Has | Needs | Slack |
|---|---|---|---|
| challenge | 5 | 2 | 3 |
| unchallenged payout | 6 | 2 | 4 |
| assert chain | 6 | 4 | 2 |
| disprove | 5 | 2 | 3 |
| refund (unbound) | 7 | 2 | 5 |
| bound refund | 2 | 2 | 0 |
| kickoff (bound) | 4 | 2 | 2 |
| kickoff (policy) | 6 | 2 | 4 |

The `testnet4` profile has no slack anywhere, by construction: each clock is the least that
passes. The mainnet-like row assumes at most 6 blocks in a row without inclusion and a 6-block
reorg. It shows the scale of a profile that is not a regtest one: T_REFUND 80 blocks is about 13
hours at ten-minute blocks (*est.*). It is not derived from a mainnet record.

On the testnet4 profile refunds open 718 blocks after funding and a challenged settlement runs up
to 397 blocks after the kickoff: about 5 days and 2.8 days at ten-minute blocks (*est.*).
The G of 90 is the record at 1 sat/vB, so the profile matches runs with `ZKC_SAT_PER_KVB=1000`;
M16's default of 100 sat/kvB (0.1 sat/vB) needs its own record (section 7).

## 5. Choosing G and R

Take G from the longest run of blocks that took none of the transactions the graph will post, at
the fee rate it posts them, over a record at least as long as the longest window. Take R from the
deepest stale branch. Then rerun with a longer record: the profile is a function of two
maxima, and a longer record can raise either.

The two parameters enter at different places: G multiplies (7G + 7 in T_refund), R adds
(5R). One deep reorg costs five times its depth in the refund window. One long empty run costs
seven times its length.

## 6. Another profile and the circuit

The batch proof holds two numbers that the graph's clocks have to match
([`circuits/signed_terms.circom`](../circuits/signed_terms.circom)):

| Circuit constant | Value | Must be at least | Enforces |
|---|---|---|---|
| `DEADLINE_AFTER_BATCH` | 4 | the profile's DEADLINE_AFTER_BATCH | `batchHeight + DEADLINE_AFTER_BATCH <= orderExpiry` for every sale |
| `ESCROW_AFTER_BATCH` | 22 | the profile's ESCROW_AFTER_BATCH | `batchHeight + ESCROW_AFTER_BATCH <= escrowExpiry` for every buyer |

These are the regtest profile's. A deployment on another profile has to:

1. set both constants in `signed_terms.circom` to the profile's values (testnet4: 107 and 717);
2. recompile every circuit that includes it (`signed_clearing.circom`, so `clearing16x4_signed`
   and `clearing16x4_owned`; `clearing_tree_signed.circom`, so `clearing_tree_owned` and
   `owned_tree_pk_16x4`) and run phase 2 again, since the circuit and so the proving key and
   verifying key change;
3. run `zkc-m1 prepare` again for the new verifying key (M14: five leaves embed it);
4. set the same constants in [`batch_joined.py`](batch_joined.py) and have sellers and buyers sign
   expiries that clear them (M17's batch signs escrowExpiry = batchHeight + 27 and orderExpiry =
   batchHeight + 144: the order expiry clears testnet4's 107, the escrow expiry does not clear 717).

**Why the order bound matters.** A sale leaf does not carry `orderExpiry`, so the committee, which
sees only the template, cannot check that an order is still valid when the kickoff lands. The
kickoff can land at batchHeight + DEADLINE_AFTER_BATCH. Only the circuit holds
`orderExpiry >= batchHeight + DEADLINE_AFTER_BATCH`, so only the circuit protects a seller from
being settled after the order it signed has expired. With the regtest constant (4) under the
testnet4 profile (107) a seller's order could expire up to 103 blocks before the kickoff lands.

**The escrow bound** is also enforced outside the circuit: the committee reads every `escrowExpiry`
from `escrowCommitment`, and the driver refuses any below the active profile's bound. A buyer who
signed an earlier expiry could refund while the dispute window is open, which invalidates the
payout (it spends every escrow) and lets the timeout slash an honest operator.

On a non-regtest profile the driver prints and records whether the compiled circuit covers it
(`timing.circuit.orders_covered`, `escrows_covered`). It does not refuse to run: the rehearsal
profiles in this file run on the regtest circuit.

## 7. testnet4 record

Measured on a testnet4 node, the last 2,016 blocks up to height 158678 (156663 to 158678).
The raw table is `/root/tn4_record.json` in WSL: `[height, min_difficulty, ntx, min_fee_rate_sat_per_kvb_or_null, time]`.

| | |
|---|---|
| Blocks | 2,016 |
| Coinbase-only | 1,422 (70.5%) |
| Longest coinbase-only run | 67 |
| Longest run with no transaction at ≤ 1 sat/vB | 90 |
| Minimum-difficulty blocks | 1,857 (92.1%) |
| Stale branches seen since 158478 | 114 |
| Stale branch length: count | 1: 39, 2: 51, 3: 15, 4: 5, 5: 1, 7: 1, 12: 1, 16: 1 |

The `testnet4` profile takes G = 90 (the longest run with no transaction at 1 sat/vB or less) and
R = 16 (the deepest branch). The 67 is for runs with no transaction at all; the 90 is for runs
with none at 1 sat/vB or less, which is the rate the profile assumes the graph pays. 114 branches
in 200 blocks is the chain's own churn: minimum-difficulty and real-difficulty miners keep
replacing each other's blocks (M16).

## 8. Verification

Run 2026-11-03 on Bitcoin Core v31.1.0 (regtest). Nothing was run on testnet4.

- **Builds and tests.** `build.sh /root/zkc-m9` (default build): 32 tests pass in `zkc-m2`, six of
  them the timing tests (every constraint at least W + R and satisfied for regtest, testnet4 and
  eight more (G, R) pairs; the regtest profile equals M2 to M17's numbers; regtest dominates
  `from_chain(0, 1)`; each testnet4 clock is tight; a wider disprove gap; signed expiries cover the
  bound). `ZKC_PUBS=1 build.sh /root/zkc-m17` builds and passes the same 32.
- **Default profile reproduces M13's bound results** (`run-m13.sh bound unchallenged late`): the
  kickoff refused at tip h_e, mined at batchHeight + 1, the payout 6 blocks after it (998 vB on
  chain; the same transaction rows as the run before the change); late: deadline h_e + 6, escrow
  expiry h_e + 29, sweeper keeps 9,790 sats, 495 vB, as in M13.
- **A small non-default profile, G 3, R 2** (T_kickoff 6, T_challenge 7, T_assert 21, T_disprove 7,
  T_refund 39, deadline +6, escrow +38), on a timed regtest chain (`run-m16.sh rehearse`,
  BLOCK_SECONDS 8, `REHEARSE_RPC_PORT` 18823). All four scenarios pass, with their heights from the
  profile:

| Scenario | Heights |
|---|---|
| unchallenged | funded 201, batchHeight 203, kickoff 204 (refused as non-final before), payout 7 blocks later (T_challenge); the early payout and early timeout refused |
| challenged | funded 297, batchHeight 298, kickoff 299, deadline 304 (batchHeight + 6), escrow expiries 336 (batchHeight + 38); assert_final 5 blocks after the kickoff, 15 blocks before the timeout opens; payout_asserted refused one block early and mined after T_disprove; timeout after assert refused |
| late | batchHeight 214, deadline 220 (+6), early sweep refused, sweep mined, kickoff then refused, refunds at 252 (+38) |
| stall | batchHeight 256, escrow expiries 294 (+38); early refund refused, refunds mined |

Results: `<work>/m16/rehearse-g3r2/`. Each JSON has the profile and its eight constraints under `timing`.
The challenged run challenges at once (a live-chain rule), so it does not exercise the last-block
challenge that window 3 sizes; the unit tests and the constraint table cover that window.

## 9. Reproduce

```sh
# The default build and tests, then the one-input build and tests:
BITVM_SRC=/root/zkc-m1/BitVM-c620dbf bash research/zk_clearing/bitvm/scripts/build.sh /root/zkc-m9
ZKC_PUBS=1 BITVM_SRC=/root/zkc-m1/BitVM-c620dbf bash research/zk_clearing/bitvm/scripts/build.sh /root/zkc-m17

# The profile and its constraints:
ZKC_TIMING=testnet4 /root/zkc-m9/target/release/zkc-m2 timing

# A non-default profile on a timed regtest chain (a private node on REHEARSE_RPC_PORT):
BITCOIN_BIN=/root/opt/bitcoin-31.1/bin REHEARSE_RPC_PORT=18823 BLOCK_SECONDS=8 \
  ZKC_INCLUSION_GAP=3 ZKC_REORG_DEPTH=2 \
  bash research/zk_clearing/bitvm/scripts/run-m16.sh <work> rehearse unchallenged late stall challenged

# testnet4 on the derived profile:
ZKC_TIMING=testnet4 bash research/zk_clearing/bitvm/scripts/run-m16.sh <work> testnet4 unchallenged
```
