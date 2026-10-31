# Roadmap: proof-backed share clearing

Written 2026-11-01 after M1; M2 to M8 were executed the same day. This file is the status.

**The question.** Can batched, proof-backed clearing of share sales between miners and market
makers beat P2Poolv2's bilateral atomic swaps on cost or on guarantees?

**The boundary.** Nothing here changes P2Poolv2 consensus, payouts or node code. Each milestone
has its own write-up with measured numbers.

Numbers marked *est.* are arithmetic on measurements, not runs.

**The answer (M7).** Only in one mode: periodic (about daily) settlement of large batches when
on-chain fees are low.

- In that mode, batch clearing costs less per sale than 2-hop Lightning swaps and locks about
  200× less capital.
- Everywhere else Lightning wins, and bilateral on-chain swaps lose to both.
- M8 prepared that mode for real value only as far as it can go without third parties.

## Done

| | Result | Write-up |
|---|---|---|
| M0 | v0 and v1 circuits (16 sales × 4 buyers; v1 is 9,004 constraints) with a Poseidon commitment to the sale list. A reproducible Groth16 pipeline; real proofs verify; invalid, tampered, forged and x + r inputs are rejected | [GROTH16.md](GROTH16.md) |
| M1 | The v1 proof settles on regtest through BitVM's chunked verifier, patched to 18 public inputs. The honest, tampered, mismatch, plus-r and stall scenarios all behave correctly | [bitvm/M1.md](bitvm/M1.md) |
| M2 | The optimistic BitVM2 graph on regtest: kickoff, a challenge anyone can post, payout with no assert when unchallenged, assert-timeout slash, a half-bond burn on every slash, timeouts set against each other and a reorg policy. The honest unchallenged batch costs **897 vB** on chain, 472× less than M1. Six scenarios pass | [bitvm/M2.md](bitvm/M2.md) |
| M3 | One hashed public input (`accounting16x4_hashed`, 10,078 constraints). The assert chain is **336,528 vB, 20.4% less**; 364 disprove leaves instead of 432 (1.11 GB instead of 1.29 GB); one binding leaf instead of 18; prepare peaks at 5.9 GB instead of 13.0 GB. Five scenarios pass | [bitvm/M3.md](bitvm/M3.md) |
| M4 | Signed terms in the circuit (`clearing16x4_signed`, 108,784 constraints). EdDSA-Poseidon over BabyJubjub signs every seller order (share, price, buyer, payout script, expiry) and every buyer's escrow terms (outpoint, funding, fee cap, refund script, expiry), at about 5,000 constraints per signature; `feeBudget <= feeCap`. Proving takes 10.2 s; 8 rule-breaking fixtures are rejected. The proof now carries facts a committee cannot recompute | [signed/SIGNED.md](signed/SIGNED.md) |
| M5 | Sharechain ownership. A 40-level Poseidon sparse Merkle tree over the sharechain's unspent outputs (about 120k live), matching circomlibjs, at 11,438 constraints per membership proof; a Groth16 proof verifies and 15 invalid inputs are rejected. A root is trusted through watchers, not disproved in BitVM | [ownership/OWNERSHIP.md](ownership/OWNERSHIP.md) |
| M6 | Batch size, with a binary Poseidon tree commitment at 16, 64, 256 and 1,024 slots. Every size proves and verifies. About 700 constraints and 34 ms of snarkjs proving per sale from 64 slots up; 1,024 sales prove in 35 s with 6.6 GiB | [scaling/SCALING.md](scaling/SCALING.md) |
| M7 | The benchmark: 10,000 offers, 100 miners, 5 market makers, three schemes. Batch clearing beats Lightning only for about daily 1,024-sale batches, below about 3.4–7.8 sat/vB (or 15–34 against week-sized channels). It locks 12–94 BTC·h a week against Lightning's 2,794. Bilateral swaps cost 245–310 vB per sale | [benchmark/BENCHMARK.md](benchmark/BENCHMARK.md) |
| M8 | For the mode M7 kept: a multi-party phase-2 ceremony script (3 contributors + beacon verified); a TRUC + pay-to-anchor fee bump verified on Core 31.1, so a low-fee child cannot pin; and a fee and pinning plan for every transaction in M2's graph | [m8/M8.md](m8/M8.md) |

What M1 taught:

- **The honest path is too expensive as built.** M1 always posts the assert chain: 422,650 vB,
  about 845,000 sats at 2 sat/vB, before the 711 vB payout. In BitVM2 the assert is posted
  only when someone challenges. Until the optimistic path exists, no cost comparison means
  anything.
- **v1's proof proves little that a committee cannot recompute.** Every input to the circuit is
  in the opened sale list or the public signals. A proof earns its cost only when it carries
  facts the committee cannot check cheaply: seller signatures and sharechain ownership.
- **Each public input costs on chain.** Going from 1 to 18 inputs added 68 hashed intermediates
  and about 175 MB of disprove leaves.
- **Two economic terms are still unbound:** the fee budget and the seller payout scripts. An
  operator can honestly prove a statement that moves value from a refund into the fee.

What M2 taught:

- **The gate passes.** The honest unchallenged batch costs 897 vB: a kickoff and one payout,
  about 423 vB plus 57.5 vB per escrow and 43 vB per payee output. That is 472 times less than
  M1. A challenge still costs about 423 kvB, paid by the challenger.
- **The fees freeze at signing.** The committee's signatures fix the fees of the payouts and the
  assert chain, and the assert chain has no output to bump from. If fees rise during a challenge,
  an honest operator can be slashed. Fee bumping (M8) is a safety issue, not only a cost one.
- **The bond has to scale with the fee rate.** A fraud-proving challenger pays for the assert
  and for the disprove, up to about 1.41 MvB together. With half of a 0.1 BTC bond as the reward,
  it breaks even only up to about 3.5 sat/vB, *est.*
- **A slash needs `maxburnamount`.** Core's `sendrawtransaction` refuses the burn output unless
  the poster raises `maxburnamount`. Relay policy accepts it.

What M3 to M8 taught:

- **The challenge reward bounds the mode from the security side too (M2, M7).** At 0.1 BTC the
  bond pays for a largest-leaf disprove only to about 3.5 sat/vB. So the bond is set from the
  highest fee rate the mode accepts.
- **Signatures are cheap enough in BabyJubjub (M4)**, about 200× cheaper than secp256k1 inside
  the circuit *est.* Each order key is bound once to the seller's `miner_address` outside the
  circuit.
- **Ownership needs a lock, not just a root (M5).**
  - A root says what was true at an anchor.
  - Non-spend afterwards needs each sold output locked on the sharechain before payout, so it
    depends on sharechain validation enforcing the lock's refund timeout.
- **Proving is not the bottleneck (M6).** Fill time and the one-time setup are.
- **The assert chain needs keyed anchors (M8).** Its commit transactions (53–92 kvB) are too
  large for TRUC, so they cannot use keyless pay-to-anchor bumping.

## Remaining work

Engineering that can be done next without anyone else:

1. **Anchors in M2's graph.** TRUC + pay-to-anchor on both payouts; operator-keyed anchors on the
   assert chain (M8's table). Re-run M2's scenarios with a fee spike.
2. **The signed tree circuit at scale.** M4's signatures on M6's tree, with M3's single input.
   A 1,024-slot signed batch is about 5.8 M constraints *est.*, so measure it with rapidsnark,
   which was not built here: the delegated build was refused by the tool policy.
3. **M5 joined to M4.** Store each order key's hash as the output's owner, so ownership and
   signature checks meet in one statement.
4. **A disprove path that relays.** Shrink BitVM leaves under the standardness limit, or document
   the route to a miner (M8 section 3).

Waiting on Patrick or third parties (details in M8):

- a public phase-1 file (Perpetual Powers of Tau) instead of the insecure local one;
- independent ceremony contributors and n-of-n committee signers;
- signet funds and a P2Poolv2 signet node for the trial;
- presenting the results to the P2Poolv2 maintainers.

## Branches

All on `patrickdugan/p2poolv2`, each off `zk-clearing-roadmap` (6778e29e) unless noted.
`zk-clearing-integration` merges them all.

| Milestone | Branch |
|---|---|
| M2 | `zk-clearing-bitvm-m2` |
| M3 | `zk-clearing-bitvm-m3` |
| M4 | `zk-clearing-m4` |
| M5 | `zk-clearing-m5` |
| M6 | `zk-clearing-m6` |
| M7 | `zk-clearing-m7` |
| M8 | `zk-clearing-m8` (on `zk-clearing-m7`) |
