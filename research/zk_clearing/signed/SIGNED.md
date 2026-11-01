# M4: signed economic terms in the circuit

Measured 2026-11-01 on the M0 toolchain (circom 2.2.2, snarkjs 0.7.5, circomlib 2.0.5), on an
AMD Ryzen AI 9 365 under WSL2 Ubuntu 24.04. The setup is the insecure deterministic one from
GROTH16.md, and the keys are public demo keys.

## What changed from v1

`circuits/clearing16x4_signed.circom` (v2) keeps v1's arithmetic and sale commitment and adds:

| Term | Signed by | Message (Poseidon6) | Enforced |
|---|---|---|---|
| Seller order, per active sale | the seller's BabyJubjub order key | tag 1, `saleId`, `price`, the buyer's `buyerId`, `sellerPayoutId`, `orderExpiry` | EdDSA-Poseidon signature; `sellerId = Poseidon(Ax, Ay)` of the signing key; `batchHeight <= orderExpiry` |
| Buyer escrow terms, per active buyer | the buyer's order key | tag 2, `escrowId`, `funding`, `feeCap`, `refundScriptId`, `escrowExpiry` | signature; public `buyerId = Poseidon(Ax, Ay)`; `feeBudget <= feeCap`; `batchHeight <= escrowExpiry` |

Two more changes:

- **Payout script bound.** Sale leaves gain `sellerPayoutId`, so the seller's Bitcoin payout
  script is now inside `saleCommitment`.
- **Escrow commitment.** A second output, `escrowCommitment`, hashes each buyer's escrow
  outpoint, funding, fee cap and refund script.
- **Domain tags.** The tags (1 and 2) keep an order signature from being reused as escrow terms.

**Hardening.** circomlib's `EdDSAPoseidonVerifier` does not check that the key `A` or the nonce
point `R8` lies on BabyJubjub. v2 adds `BabyCheck` for both, in every slot. Padding slots carry
a valid signature from a padding key over message 0, so the verifier never sees degenerate
points, and its `enabled` input is the slot's active flag.

**What a proof now says that the payout committee cannot recompute from public data.**

- Public: the per-buyer amounts, buyer IDs, batch height and the two commitments.
- Proven: every committed sale carries a valid order signature by the key whose hash is its
  `sellerId`, for that exact share, price, buyer, payout script and expiry. Every escrow's terms,
  including the fee cap, were signed by its buyer.
- Private: the orders and signatures.

This answers M1's first lesson: the proof now carries facts the committee cannot recompute.

M1's fee-budget gap is closed in the circuit: `feeBudget[b] <= feeCap[b]`, and `feeCap` is
under the buyer's signature. An operator can still move value between refund and fee, but
only up to the cap the buyer signed.

## Results

Reproduce, from the repository root, in WSL:

```sh
POWER=17 FIXTURES=research/zk_clearing/signed/fixtures.sh COMMIT_JS=research/zk_clearing/signed/commit_signed.js   bash research/zk_clearing/groth16/run.sh clearing16x4_signed /tmp/zkc-v2
```

| | v1 `accounting16x4_committed` | v2 `clearing16x4_signed` |
|---|---|---|
| Constraints | 9,004 | 108,784 |
| Wires | 8,923 | 108,571 |
| Public inputs + outputs | 17 + 1 | 18 + 2 |
| Private inputs | 153 | 301 |
| Compile | 3.2 s, 792 MiB | 16.6 s, 1.23 GiB |
| Phase 1 (new + beacon + prepare) | power 14: 46 s | power 17: 491 s, 1.04 GiB |
| Phase 2 (setup + beacon) | 16.6 s | 91.0 s, 1.51 GiB |
| Proving key | 10.5 MB | 78.2 MB |
| Verifying key sha256 | `3d5030f9…b8533494ec` | `74905f3c…9b1af55166` |
| Prove (snarkjs) | 0.85 s, 703 MiB | 10.15 s, 2.22 GiB |
| Verify (snarkjs CLI) | 0.35 s | 1.13 s |
| Proof | 256 B | 256 B |

Every check in `run.sh` passes for v2:

- the valid witness satisfies the R1CS;
- the valid proof verifies;
- `saleCommitment` matches circomlibjs (`signed/commit_signed.js`);
- a re-split sale list (different, validly signed sales with the same totals) gives a different
  commitment;
- a tampered public signal, a public signal written as `x + r`, and a forged `.wtns` (it fails at
  constraint 104,691) are all rejected.

The eight M4 fixtures, each rejected by the witness calculator at the rule it breaks:

| Fixture | What changed | Rejected at |
|---|---|---|
| `bad_order_signature` | order `S` + 1 | EdDSA equality (`ForceEqualIfEnabled`) |
| `bad_escrow_signature` | escrow `S` + 1 | EdDSA equality |
| `price_changed_after_signing` | price + 1, refund − 1 (arithmetic still balances) | EdDSA equality |
| `payout_script_swapped` | `sellerPayoutId` replaced by another seller's | EdDSA equality |
| `seller_id_not_signer` | `sellerId` set to another seller's key hash | `sellerId = Poseidon(A)` |
| `fee_over_cap` | `feeBudget` = cap + 1, refund lowered to balance | `feeCap - feeBudget` range check |
| `expired_order` | order validly re-signed with expiry = batch height − 1 | height range check |
| `order_r8_off_curve` | `R8.x` + 1 | `BabyCheck` on `R8` |

## Signature options (the roadmap's three)

| Option | Cost per signature | Status |
|---|---|---|
| (a) BIP340 Schnorr over secp256k1, inside the circuit | non-native field arithmetic on BN254, on the order of a million constraints per signature (*est.* from published secp256k1-in-circom work, not built here) | not built |
| (b) EdDSA-Poseidon over BabyJubjub, inside the circuit | about 5,000 constraints: (108,784 − 9,004) / 20 = 4,989 (measured: v2 minus v1, over 20 signatures, including the key hash, message hash and both on-curve checks) | **built and proven** |
| (c) checked by the committee off-circuit, with a BitVM disprove for a bad signature | 0 constraints; every order is revealed to the committee | not built |

(b) is about 200× cheaper than (a) *est.*, and keeps orders private, unlike (c).

**The cost of (b): each order key must be bound once to the seller's sharechain `miner_address`.**
That binding is a single registration outside the circuit. One way is a BIP340 signature by the
key controlling `miner_address` over `Poseidon(Ax, Ay)`. M5's ownership tree could then store
that key hash as the output's owner, which joins M4 to M5 without verifying secp256k1 inside the
circuit.

## Not covered

- **Key registration** (above) was specified here and is built in M10
  ([../joined/JOINED.md](../joined/JOINED.md)), with the ownership tree storing the registered key
  hash.
- **`escrowId` and `refundScriptId`** are field encodings of labels. The Bitcoin transaction
  graph, not the proof, must spend exactly those outpoints and pay exactly those scripts. The
  payout template (M1) is where that check lives.
- **Expiry heights** are compared with a public `batchHeight` that the operator supplies. The
  BitVM graph has to bind `batchHeight` to the Bitcoin height (for example with a CLTV on the
  kickoff) for expiry to mean anything.
- **Batch size and statement form.** v2 is fixed at 16×4 and keeps 20 public signals. M3's single
  hashed public input and M6's tree commitment apply to it unchanged.
