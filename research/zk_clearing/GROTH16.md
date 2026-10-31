# Groth16 experiment: share-clearing circuits

Measured 2026-10-31.

- **Machine:** AMD Ryzen AI 9 365 (20 threads), WSL2 Ubuntu 24.04 with a 20 GB VM.
- **Toolchain:** circom 2.2.2 built from the `v2.2.2` tag with `--locked`; Node 22.12.0;
  snarkjs 0.7.5, circomlib 2.0.5 and circomlibjs 0.1.7, pinned by
  `groth16/package-lock.json`.
- **Setup: INSECURE.** One deterministic beacon contribution (`groth16/run.sh`), so the toxic
  waste is public and anyone can forge proofs. It exists to measure the circuits and test their
  constraints. A real deployment needs a multi-party phase 2 on top of a public phase-1 ceremony.

## Reproduce

```sh
bash research/zk_clearing/groth16/run.sh accounting16x4 /tmp/zkc-v0
bash research/zk_clearing/groth16/run.sh accounting16x4_committed /tmp/zkc-v1
```

Each run writes `results.txt` into its build directory and exits non-zero if any invalid
witness, tampered signal or forged witness is accepted. Because the setup is deterministic, the
verifying key hashes below reproduce exactly (checked across 3 runs for v0 and 2 for v1).

## Results

| | v0 `accounting16x4` | v1 `accounting16x4_committed` |
|---|---|---|
| Constraints | 3,159 | 9,004 |
| Wires | 3,078 | 8,923 |
| Public inputs + outputs | 13 + 0 | 17 + 1 |
| Private inputs | 121 | 153 |
| Compile | 0.08 s, 15 MiB | 3.19 s, 792 MiB |
| Phase 1 (power 14, new + beacon + prepare) | 52.0 s, 489 MiB | 46.1 s, 477 MiB |
| Phase 2 (setup + beacon) | 5.6 s, 378 MiB | 16.6 s, 607 MiB |
| Proving key | 1,941,850 B | 10,464,674 B |
| Verifying key (JSON) | 5,129 B | 6,041 B |
| Verifying key sha256 | `aada67b0…dada65dabe` | `3d5030f9…b8533494ec` |
| Prove (snarkjs CLI) | 0.57 s, 438 MiB | 0.85 s, 703 MiB |
| Verify (snarkjs CLI) | 0.43 s, 297 MiB | 0.35 s, 296 MiB |
| Proof | 256 B uncompressed (2 G1 + 1 G2) | 256 B |

The CLI times include Node start-up and loading the WASM curve code. The pairing check itself
is a small part of the verify figure.

Every run checks the following, and every check passes for both circuits:

| Check | v0 | v1 |
|---|---|---|
| Valid witness satisfies the R1CS (`snarkjs wtns check`) | yes | yes |
| `witness.BN254_FR` equals the prime in the `.wtns` header | yes | yes |
| Invalid fixtures rejected by the witness calculator, each at the constraint it targets | 14 of 14 | 17 of 17 |
| Valid proof verifies | yes | yes |
| A public signal changed by one fails to verify | yes | yes |
| A public signal encoded as `x + r` fails to verify | yes | yes |
| A forged `.wtns` (one public wire shifted) fails `wtns check` | constraint 129 | constraint 8,799 |
| A proof built from that forged witness fails to verify | yes | yes |
| A different sale list with the same totals (`resplit.json`) | **proves identical public signals** | different `saleCommitment` |
| `saleCommitment` equals circomlibjs Poseidon of the honest sale list | — | yes |

## Audit of the original circuit (`08552d87`)

1. **Wrong field: the Python witness could never satisfy the circuit (fixed).**
   - `witness.py` computed every modular inverse mod
     `21888…208583`, which is BN254's base field q. Circom works in the scalar field
     r = `21888…495617`.
   - With the code as committed, circom's witness calculator failed on the example at
     `price * priceInverse === activeSale` (`ClearingAmounts` line 63). The previous "36 tests
     passing" checked Python against the same wrong modulus.
   - The fix is in `witness.py`. `test_groth16_inputs.py` now derives r and q from the BN
     parameter u and asserts which one is used. `run.sh` compares the constant with the prime in
     the generated witness.
2. **v0 proves almost nothing beyond its public inputs (addressed by v1).**
   - The public `funding`, `feeBudget` and `refund` already fix each buyer's cost and
     `totalPayout`. The private sale list is bound to nothing.
   - Shown on the real prover: `resplit.json` (four different sales with the same per-buyer
     totals) proves exactly the same public signals as the honest list.
   - v1 publishes a Poseidon commitment over every slot's (active flag, sale ID, seller ID,
     price, selected buyer ID), and requires zero identities in padding slots.
3. **Range checks are sound.**
   - `SatoshiAmount` decomposes both `x` and `MAX_SATS - x` into 51 bits. Since 2^51 > MAX_SATS,
     this is exactly `0 <= x <= MAX_SATS` for any field element. Negative values (`r - 1`) and
     `MAX_SATS + 1` are rejected (fixtures `negative_price`, `price_above_max`,
     `refund_above_max`).
   - The largest linear sum is 16 prices plus fee and refund, at most 18 · 2.1e15 < 2^56. That
     is far below r, so every field equation equals the integer equation and nothing wraps.
4. **No unconstrained signal changes the statement.**
   - The `Bits51` hints (`<--`) are pinned by booleanity plus recomposition.
   - `priceInverse` for padding slots and `buyerCountInverse` for unused buyers are free. They
     appear only in products that are zero in those slots, so a prover gains nothing by
     choosing them.
   - `activeCountInverse` forces at least one active sale.
5. **Public-input encoding.** snarkjs rejects `x + r`. Any Bitcoin-side or BitVM verifier must
   reject non-canonical public inputs in the same way, or one statement has several encodings.

## What v1 still does not authenticate

Each row is a predicate the full statement needs. The right-hand column says how it would be
bound.

| Fact | Status in v1 | Binding needed |
|---|---|---|
| The sale list (IDs, sellers, prices, buyers) | **Bound** by `saleCommitment` | The verifier recomputes it from signed sale orders |
| Each `saleId` is a spendable sharechain output owned by `sellerId` | Not bound | Membership in a committed sharechain UTXO set at an anchored share height. P2Poolv2 share headers commit to transactions, not to a UTXO set, so this needs either a new UTXO commitment (a consensus change, out of scope) or an inclusion-plus-non-spend argument checked outside the circuit |
| The seller authorized the sale | Not bound | A signature by the key behind the sharechain `miner_address` over (domain, network, saleId, price, buyerId, seller payout script, expiry). Verifying secp256k1 inside a BN254 circuit costs on the order of a million constraints per signature, so the alternative to benchmark is checking signatures in the BitVM layer |
| Where the seller is paid in bitcoin | **Not bound** | Add the seller's Bitcoin payout script to the leaf. It must come from the signed order, not from `miner_bitcoin_address`: that address receives coinbase PPLNS payouts and is a separate identity from the share owner |
| Buyer escrow outpoints and amounts | `buyerId` public; amounts public | The Bitcoin transaction graph must spend exactly those escrows. The proof cannot see UTXOs |
| Replay | Not bound | A nullifier per `saleId`, with a public nullifier-set root, or the sharechain spend itself as the nullifier |
| Canonical chain state | Not bound | Public sharechain tip and Bitcoin anchor, checked by the enforcement layer against headers |
| PPLNS reward entitlement | Not in scope | A separate predicate: the anchor walk, maturity skip, uncle weights, Bitcoin-ancestry eligibility and rounding from `docs/architecture/payout-distribution.md` and `mine-on-bitcoin-chain.md`. Ownership of a share output and entitlement to its reward are different statements, and should be benchmarked separately |

## Next concrete BitVM milestone

**M1: assert this proof's public signals on Bitcoin regtest, and settle according to them.**

1. **Proof conversion.** Convert the v1 snarkjs proof and verifying key to the arkworks BN254
   Groth16 types used by the BitVM Groth16 verifier. Check that the converted proof still
   verifies off-chain.
2. **Funding.** Fund one escrow per active buyer on regtest.
3. **Payout template.** Build a payout transaction template whose outputs are a deterministic
   function of the 18 public signals: seller payouts from the committed sale list, the buyer
   refund, and the fee.
4. **Assert and disprove.** The operator commits the public signals and the proof in an assert
   transaction. A challenger can disprove an invalid proof through the chunked verifier. A
   timeout path refunds the buyers.
5. **Demonstrate:**
   - the honest path pays exactly the committed outputs;
   - a proof with a tampered public signal is disproved and the operator's bond is slashed;
   - a stalled operator lets buyers refund after the timeout.
6. **Measure:** the vbytes of each transaction in both paths.

Phase 3 (the full BitVM transaction-state spec, including reorgs) and phase 4 (the 100-miner,
5-market-maker, 10,000-offer benchmark against bilateral HTLC swaps) have not started. None of
the numbers here say anything yet about fees, collateral-hours or latency.
