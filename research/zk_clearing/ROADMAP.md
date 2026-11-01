# Roadmap: proof-backed share clearing

Written 2026-11-01 after M1; M2 to M12 were executed the same day. This file is the status.

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
| M5 | Sharechain ownership. A 40-level Poseidon sparse Merkle tree over the sharechain's unspent outputs (about 120k live), matching circomlibjs, at 11,438 constraints per membership proof; a Groth16 proof verifies and 15 invalid inputs are rejected. Built from real node stores too: a 5-node P2Poolv2 sim swarm on regtest gives 77 leaves at its tip, two nodes' stores agree on the root at all 126 anchors compared, and a real share output proves membership. A root is trusted through watchers, not disproved in BitVM | [ownership/OWNERSHIP.md](ownership/OWNERSHIP.md) |
| M6 | Batch size, with a binary Poseidon tree commitment at 16, 64, 256 and 1,024 slots. Every size proves and verifies. About 700 constraints and 34 ms of snarkjs proving per sale from 64 slots up; 1,024 sales prove in 35 s with 6.6 GiB | [scaling/SCALING.md](scaling/SCALING.md) |
| M7 | The benchmark: 10,000 offers, 100 miners, 5 market makers, three schemes. Batch clearing beats Lightning only for about daily 1,024-sale batches, below about 3.4–7.8 sat/vB (or 15–34 against week-sized channels). It locks 12–94 BTC·h a week against Lightning's 2,794. Bilateral swaps cost 245–310 vB per sale | [benchmark/BENCHMARK.md](benchmark/BENCHMARK.md) |
| M8 | For the mode M7 kept: a multi-party phase-2 ceremony script (3 contributors + beacon verified); a TRUC + pay-to-anchor fee bump verified on Core 31.1, so a low-fee child cannot pin; and a fee and pinning plan for every transaction in M2's graph. M2 and M3 already ran under mainnet relay policy (regtest requires standard transactions), with the disproves mined through a miner's own template; what only signet adds is listed in M8 section 5 | [m8/M8.md](m8/M8.md) |
| M9 | Fee bumping in M2's graph: TRUC payouts with the operator's back output as the handle, operator-keyed anchors on the kickoff and the assert chain, and a challenge priced at the assert's cost at 10 sat/vB. In a 10 sat/vB spike on regtest, **M2's graph slashed an honest operator on both paths**: a payee pinned the payout with 63 children and posted the timeout itself, and the assert chain never entered a template. **The anchored graph settled both**, on the same timeline. M2's six scenarios rerun on it with the same outcomes, at +43 vB per anchor (honest path 940 vB) | [bitvm/M9.md](bitvm/M9.md) |
| M10 | Ownership joined to signed orders. A share address's key registers a BabyJubjub order key with BIP340; the tree stores the key's hash as the owner; one circuit (291,792 constraints) proves M4's signatures and M5's membership for the same seller. Proves in 11.8 s; a seller selling with an unregistered, rotated-out or someone else's key is refused in the membership check | [joined/JOINED.md](joined/JOINED.md) |
| M11 | M4's signatures on M6's tree behind one hashed public input, at 16, 64 and 128 slots. 128 sales: 760,801 constraints, prove 19–50 s and 6.8 GiB in snarkjs. Signatures are 87% of the circuit, 4,852 constraints per sale. 1,024 sales: about 5.76 M constraints, phase-1 power 23, 30–51 GiB to prove, *est.* | [signedtree/SIGNED_TREE.md](signedtree/SIGNED_TREE.md) |
| M12 | Every disprove weighed: 430 of 432 are over the relay limit, none is over a default block template (the heaviest is 3,960,303 WU, 31,697 under it). BLAKE3 in Script costs 232 kB per hash of BitVM's Fp12 state, so pairing leaves cannot be cut under the relay limit. The disprove window has to come from the hashrate that accepts non-standard transactions: 135 blocks at 5%, 688 at 1% (ε = 10⁻³) | [bitvm/M12.md](bitvm/M12.md) |

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
- **A node's store is enough to build the root (M5).** The bodies a node keeps (`PRUNE_DEPTH`)
  cover the root's window (`PAYOUT_DEPTH`), and independent stores give the same root.
- **Proving is not the bottleneck (M6).** Fill time and the one-time setup are.
- **The assert chain needs keyed anchors (M8).** Its commit transactions (53–92 kvB) are too
  large for TRUC, so they cannot use keyless pay-to-anchor bumping.

What M9 to M12 taught:

- **Frozen fees are a safety bug, not a cost (M9).**
  - In a spike, M2's version 2 payout could be pinned by any payee with 63 cheap children. The
    pinning payee then posted the timeout and took half the bond, 4.99 M sats, against a 43,000
    sat payout.
  - TRUC bounds the pin: one child of at most 1,000 vB, which the operator evicts.
  - The kickoff's fee is fixed at presigning too, so it needs an anchor.
- **The challenge has to pay for the assert at the highest fee rate the mode accepts (M9).**
  Otherwise an honest operator who is challenged in a spike pays for its own CPFP. At 10 sat/vB
  that is a 4.25 M sat challenge, five times M2's, which also makes griefing five times dearer.
- **Registration is the bridge between a sharechain address and an order key (M10).** The
  circuit needs no secp256k1. The root becomes a function of the sharechain and of the
  registrations, so watchers have to agree on both.
- **Signatures, not the tree, dominate the signed circuit (M11).** 87% at every size. A day's
  1,024 sales need phase-1 power 23 and 30–51 GiB for snarkjs, *est.*
- **The disprove route is through miners (M12).** The pairing leaves cannot be cut under the
  relay limit, because hashing their state costs 232 kB of script per side. T_disprove has to be
  set from the hashrate share that accepts non-standard transactions. The heaviest disprove
  fills 99% of a block, so a 1% larger leaf would not fit a default template.

## Remaining work

Done since the first version of this list: anchors in M2's graph (M9), the signed tree at scale
(M11), M5 joined to M4 (M10), and the disprove route (M12).

Engineering that can be done next without anyone else:

1. **The joined statement at scale.** M10's membership on M11's tree costs about 17,000
   constraints per sale (5,600 for the signed tree, 11,400 for the membership), so 1,024 sales
   come to about 17.5 M constraints and phase-1 power 25, *est.* A cheaper membership proof is the next step: a shallower tree for the live window
   (M5 section 6), or one root per seller.
2. **BitVM on M11's statement.** Port M11's chunked Poseidon to the Rust template, and rerun
   M3's scenarios with a signed-tree proof.
3. **Bind `batchHeight` to the chain.** For example a CLTV on the kickoff, so the expiry checks of
   M4 and M11 refer to the real height.
4. **Rising fees during an assert.** Replace the bump children by RBF as the market climbs. M9
   ran a constant spike only.

Waiting on Patrick or third parties (details in M8):

- a public phase-1 file (Perpetual Powers of Tau) instead of the insecure local one, at power 23
  or more for a day's signed batch;
- independent ceremony contributors and n-of-n committee signers. A MuSig2 aggregate key is
  one BIP340 key on chain, so M2's traces already cover the chain side; what is missing is
  independent people;
- signet coins and a P2Poolv2 signet node for the trial. The signet faucets require CAPTCHAs;
- a rapidsnark build, and a machine with more than 19 GB of RAM, to time a 1,024-slot signed
  proof. This session's tool policy refused the rapidsnark build;
- miners or pools that agree to include non-standard disproves, since their hashrate share sets
  T_disprove (M12);
- presenting the results to the P2Poolv2 maintainers.

## Branches

All on `patrickdugan/p2poolv2`, each off `zk-clearing-roadmap` (6778e29e) unless noted.
`zk-clearing-integration` merges them all. M9 to M12 branch off `zk-clearing-integration`
(9fc8dc96).

| Milestone | Branch |
|---|---|
| M2 | `zk-clearing-bitvm-m2` |
| M3 | `zk-clearing-bitvm-m3` |
| M4 | `zk-clearing-m4` |
| M5 | `zk-clearing-m5` |
| M6 | `zk-clearing-m6` |
| M7 | `zk-clearing-m7` |
| M8 | `zk-clearing-m8` (on `zk-clearing-m7`) |
| M9 and M12 | `zk-clearing-m9` |
| M10 | `zk-clearing-m10` |
| M11 | `zk-clearing-m11` |
