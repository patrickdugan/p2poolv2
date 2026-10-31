# Roadmap: proof-backed share clearing

Written 2026-11-01, after M1.

**The question.** Can batched, proof-backed clearing of share sales between miners and market
makers beat P2Poolv2's bilateral atomic swaps on cost or on guarantees?

**The boundary.** Nothing here changes P2Poolv2 consensus, payouts or node code. Each milestone
ends with measured numbers in its own write-up, and with a decision.

Numbers marked *est.* are arithmetic on the measurements so far, not runs.

## Done

| | What exists | Write-up |
|---|---|---|
| M0 | v0 and v1 circuits (16 sales × 4 buyers; v1 is 9,004 constraints) with a Poseidon commitment to the sale list. A reproducible Groth16 pipeline; real proofs verify; invalid, tampered, forged and x + r inputs are rejected | [GROTH16.md](GROTH16.md) |
| M1 | The v1 proof settles on regtest through BitVM's chunked verifier, patched to 18 public inputs. The honest, tampered, mismatch, plus-r and stall scenarios all behave correctly | [bitvm/M1.md](bitvm/M1.md) |

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

## Next

### M2: the optimistic BitVM2 graph (do first)

Build the honest path the protocol is meant to have:

- **Kickoff:** the operator claims the batch.
- **Challenge window:** anyone may post a challenge, which forces the assert.
- **Payout without a challenge:** the payout spends after the window.
- **Penalties:** an assert timeout slashes an operator who is challenged and goes silent.
  Burning part of the bond keeps a miner from taking all of it by challenging itself.
- **Timing:** set the challenge, assert and refund timeouts against each other.
- **Reorgs:** a stated policy for the depth at which each step counts as final.

Measure the vbytes of the honest path (expected to be on the order of 1–2 kvB per batch plus
about 43 vB per payee output, *est.*) and of the challenged path.

**Gate.** If the honest path is not far below M1's 423 kvB, stop and find out why before going
further.

### M3: one public input

- Replace the 18 public signals with a single one: a Poseidon hash of the full statement,
  computed in the circuit (about 1,000 constraints, *est.*).
- The committee and the payout template check the preimage off-chain. A single binding leaf
  replaces the 18.
- *est.*: about 68 fewer hashed intermediates and 68 fewer disprove leaves, about 175 MB less
  leaf data, and 85 fewer Winternitz commitments in the assert (17 signals plus 68 hashes): 85
  of the 463 values committed, about 18%.
- Measure all of it.

### M4: bind the economic terms

- **Buyer side.** Signed escrow terms: funding, a fee cap and the refund script.
- **Seller side.** Signed sale orders: share outpoint, price, buyer, the seller's Bitcoin payout
  script, and expiry. That payout script is the order's, not `miner_bitcoin_address`, which
  receives coinbase PPLNS payouts and is a separate identity.
- **Where signatures are checked.** The choice to settle with measurements:
  - (a) inside the circuit with BIP340 Schnorr: on the order of a million constraints per
    signature, *est.*;
  - (b) inside the circuit with order keys on BabyJubjub (EdDSA, a few thousand constraints
    each), with each order key bound once to a Bitcoin key;
  - (c) outside the circuit, by the committee, with a BitVM disprove for a bad signature.
- **Done when:** the proof carries at least one fact the committee cannot recompute from public
  data. That fixes the first M1 lesson.

### M5: sharechain ownership

- **The problem.** Prove that each sold `saleId` is an unspent sharechain output owned by the
  seller's `miner_address` at an anchored share height.
- **The blocker.** P2Poolv2 share headers commit to transactions, not to a UTXO set, so
  membership needs one of:
  - an offline UTXO accumulator, with a non-spend argument that can be challenged in BitVM;
  - a UTXO commitment in share headers, which is a consensus change. That would be proposed
    upstream as a design discussion only after M2–M4 show it is worth it.
- **First step.** Build a sparse Merkle UTXO root from a node's store, offline, and measure
  proof sizes and update cost per share.
- **Out of scope.** PPLNS reward entitlement (anchor walk, maturity, uncle weighting, Bitcoin
  ancestry) is a different predicate, benchmarked separately if at all.

### M6: scale the batch

- **Where it stands.** v1 runs about 560 constraints per sale slot (9,004 / 16).
- **Sizes to try.** 64-, 256- and 1,024-slot circuits, with a Merkle tree replacing the flat
  Poseidon16 root. A 1,024-slot circuit is about 0.6 M constraints before any signature
  checks, *est.*
- **Prover.** Compare snarkjs with rapidsnark on proving time and memory.
- **Output.** The batch size where the cost per sale levels off.

### M7: the benchmark (phase 4 of the original plan)

- **Workload:** about 100 miners, 5 market makers and 10,000 share-sale offers.
- **Baselines:**
  - bilateral HTLC swaps on chain;
  - swaps over Lightning, as `docs/atomic-swap/` describes;
  - M2–M6 batch clearing.
- **Measure:** vbytes and fees, prover time, settlement latency, collateral-hours, refund
  delays, and the worst-case loss for each party.
- **Reporting:** measured runs and modelled assumptions in separate tables.

**Decision.** If batch clearing does not beat swaps over Lightning per sale at realistic sizes,
the BitVM path stops. Clearing then continues only as an off-chain netting layer that settles
over Lightning or Ark.

### M8: toward real value (only if M7 says yes)

- A multi-party phase 2 setup on top of a public phase 1 ceremony, replacing the insecure
  deterministic one.
- A real n-of-n committee and real operator, challenger and party keys.
- Fee bumping, and pinning analysis for every transaction in the graph.
- Plans for disprove leaves above standardness: 430 of 432 need a miner to include them
  directly.
- A signet trial with a P2Poolv2 node.
- **Upstream.** Present the results to the P2Poolv2 maintainers as research. No consensus change
  is requested before M5's case is made.

## Order and dependencies

```
M2 optimistic graph ──► M7 benchmark ──► decision ──► M8
M3 one public input ──┘      ▲
M4 signed terms ─────────────┤
M5 ownership ────────────────┤ (M5 can follow M7 if M4 already gives the proof a job)
M6 batch size ───────────────┘
```

M2 and M3 change only the BitVM side and can run in parallel. M4 changes the circuit and the
template.
