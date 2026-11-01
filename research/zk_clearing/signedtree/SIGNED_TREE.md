# M11: the signed tree circuit at scale

Measured 2026-11-01. Toolchain: circom 2.2.2 and snarkjs 0.7.5 (pinned by
`groth16/package-lock.json`). Machine: AMD Ryzen AI 9 365, WSL2 Ubuntu 24.04 with a 19 GB VM.
Two other sessions' jobs ran on the machine at the same time (load average 9 to 13 during the
repeat proves), so the times carry that noise. The setup is insecure: one deterministic
beacon, as in GROTH16.md, and the keys are public demo keys. M6's phase-1 file at power 20
serves every size. All prove times are snarkjs; rapidsnark was not built here.

## The statement

`circuits/clearing_tree_signed.circom` defines `SignedClearingTree(saleSlots, buyerSlots, depth, extraValues)`.
It puts M4's signed terms on M6's tree behind M3's single public input. `extraValues` was added
by M15 ([joinedtree/JOINED_TREE.md](../joinedtree/JOINED_TREE.md)): that many private values are
appended to the hashed statement. The three circuits below pass 0, which declares no signal, and
their compiled R1CS and symbol files at 16×4 and 64×8 are byte-identical before and after the
change (sha256 `d58a0716…` / `8aab9175…` and `9ff782a0…` / `7d2c5960…`).

**Public:** `statementHash` and nothing else. Every other value is private.

```
statement     = [saleCommitment, escrowCommitment, batchHeight, totalPayout,
                 funding[0..B-1], feeBudget[0..B-1], refund[0..B-1], buyerId[0..B-1]]   (4 + 4B values)
statementHash = PoseidonChunked(statement)
```

**`PoseidonChunked`** is M3's two-level hash made general. Up to 12 values go through one Poseidon.
Longer lists are cut into chunks of 12 (the last may be shorter), each chunk is hashed, and the
chunk digests are hashed together. M3's 18 values were `Poseidon2(Poseidon9, Poseidon9)`. Here B = 4
gives 20 values (chunks of 12 and 8) and B = 8 gives 36 (three chunks of 12). The template accepts
up to 144 values, which is B up to 35. Every Poseidon call in the circuit has at most 12 inputs,
the cap of the Rust side (light-poseidon).

**Reference implementation:** `signedtree/statement_signed_tree.js` recomputes the sale tree, the
escrow commitment, the statement and the hash with circomlibjs's Poseidon. `groth16/run.sh` runs it
(through the new `STATEMENT_JS` hook) and compares its `statementHash` with the proof's public
signal, and with the re-split batch's.

**What the proof checks**, per slot:

| Term | Signed by | Message (Poseidon6) | Enforced |
|---|---|---|---|
| Seller order, per active sale | the seller's BabyJubjub order key | tag 1, `saleId`, `price`, the selected buyer's `buyerId`, `sellerPayoutId`, `orderExpiry` | EdDSA-Poseidon signature; `sellerId = Poseidon(Ax, Ay)`; `batchHeight <= orderExpiry` |
| Buyer escrow terms, per active buyer | the buyer's order key | tag 2, `escrowId`, `funding`, `feeCap`, `refundScriptId`, `escrowExpiry` | signature; `buyerId = Poseidon(Ax, Ay)`; `feeBudget <= feeCap`; `batchHeight <= escrowExpiry` |

`BabyCheck` runs on `A` and `R8` in every slot. Padding slots carry a valid signature from a
padding key over message 0, with the verifier's `enabled` input set to the slot's active flag.
`saleCommitment` is the root of M6's binary Poseidon2 tree over Poseidon6 sale leaves (M4's leaf,
which includes `sellerPayoutId`). `escrowCommitment` is `PoseidonChunked` over M4's Poseidon5
escrow leaves, which for up to 12 buyer slots is a single Poseidon, as in M4.

**`statementHash` is a public input, not an output.** The circuit constrains it to equal the hash of
the statement, so a wrong claimed hash fails in the witness calculator and the invalid-hash fixture
below is meaningful. The proof still has one public signal, at wire 1, and the verifying key has the
same shape as M3's.

**Reuse.**
- `ClearingAmounts` and `PoseidonTreeRoot` are included, not copied.
- `AtMostHeight` and the two domain tags moved out of `clearing16x4_signed.circom` into
  `circuits/signed_terms.circom`, because a file with a `main` cannot be included. M4's circuit
  includes the new file and compiles to the same R1CS and symbol file, byte for byte (sha256
  `572f5cd5…cac3a` and `11daa872…1d2de`, before and after).
- `SignedOrder` and `SignedEscrow` are M4's per-slot checks written as templates. They are new
  code, with the same rules as M4's inline ones.

**Sizes.** `signedtree/circuits/signed_tree_{16x4,64x8,128x8}.circom`. Fixtures: `gen_batch.py`
(batch specs, every slot active, M6's deterministic batch plus the M4 terms), `sign.js` (keys,
signatures, `statementHash`, fixtures), `fixtures.sh` (the `run.sh` hook). 128×8 is the largest
power of two under the 2^20 ceiling; 256×8 would exceed it (below).

Reproduce one size, from the repository root, with circom 2.2.2, Node, python3 and GNU time on
`PATH`:

```sh
POWER=20 PTAU=<prepared power-20 ptau> \
  bash research/zk_clearing/signedtree/run_size.sh 128 8 /tmp/zkc-signed-128x8
```

`run_size.sh` calls `groth16/run.sh` with `CIRCUIT_DIR`, `FIXTURES` and `STATEMENT_JS` set, then
`check_padded.sh`. Without `PTAU`, `run.sh` generates its own phase-1 file at `POWER`. The
per-part constraint counts:

```sh
bash research/zk_clearing/signedtree/cost_split.sh 128 8 /tmp/zkc-signed-128x8/deps/node_modules /tmp/zkc-split-128
SKIP_WHOLE=1 bash research/zk_clearing/signedtree/cost_split.sh 1024 8 <node_modules> /tmp/zkc-split-1024
```

Raw outputs are in [`results/`](results/): `run-*.txt` and `log-*.txt` from `run.sh`,
`cost-split-*.txt`, and `repeat-prove.txt`.

## Results

Every size passes every check in `run.sh`:

- the valid witness satisfies the R1CS, and the proof verifies;
- the proof's public signal equals circomlibjs's `statementHash`;
- the re-split batch (two sale IDs swapped and re-signed: same public totals, different tree) proves
  a different `statementHash`;
- ten invalid fixtures are each rejected by the witness calculator (below);
- a tampered public signal, a public signal written as `x + r`, and a forged `.wtns` (it fails at
  constraint 109,149, 388,712 and 730,152 for the three sizes) are all rejected;
- a batch with the last quarter of the sale slots and the last buyer slot unused (12 of 16, 48 of 64
  and 96 of 128 sales; 3, 7 and 7 buyers) satisfies the R1CS, so the padding rules and padding-key
  signatures hold at each size.

| | 16×4 | 64×8 | 128×8 |
|---|---|---|---|
| Signatures (sales + buyers) | 20 | 72 | 136 |
| Constraints | 112,921 | 404,001 | 760,801 |
| Constraints per sale slot | 7,058 | 6,313 | 5,944 |
| Wires | 112,708 | 403,288 | 759,512 |
| Private / public inputs | 319 / 1 | 1,403 / 1 | 2,683 / 1 |
| Compile | 13.95 s, 1.32 GiB | 49.75 s, 1.65 GiB | 61.24 s, 3.02 GiB |
| Phase 2 (setup + beacon, power-20 phase 1) | 41.80 s, 1.60 GiB | 183.1 s, 3.81 GiB | 370.4 s, 5.98 GiB |
| Proving key | 80.5 MB | 290.1 MB | 549.2 MB |
| Witness (wasm), 3 runs | 1.30 to 1.50 s, 0.20 GiB | 3.46 to 4.21 s, 0.30 GiB | 6.16 to 6.74 s, 0.39 GiB |
| **Prove (snarkjs)**, in `run.sh` | **3.68 s**, 2.09 GiB | **22.29 s**, 5.14 GiB | **19.18 s**, 6.77 GiB |
| Prove, 3 repeats on the same zkey | 3.59 to 8.35 s | 22.41 to 35.27 s | 27.06 to 49.78 s |
| Verify (snarkjs CLI) | 0.40 s | 0.87 s | 0.39 s |
| Proof / public signals | 256 B / 1 | 256 B / 1 | 256 B / 1 |
| Verifying key sha256 | `ef1a22e3…bf4ad364` | `db925be2…daca4728` | `364039e6…aeb2398` |

128×8 uses 73% of the 2^20 = 1,048,576 constraint ceiling, so it ran and 32×8 was not needed. Its
setup peaked at 5.98 GiB and its proof at 6.77 GiB.

**Read the prove times as a range.** The `run.sh` figure is one run. The three repeats ran later,
under a load average of 9 to 13 from two other sessions' jobs. At 128×8 they are 1.4 to 2.6 times
the `run.sh` figure. The 64×8 figure from `run.sh` (22.29 s) is slower than the 128×8 one (19.18 s)
because the machine was busier then. The lowest observed time is the closest to an idle machine.
Witness generation (wasm, 1 to 7 s) is separate from proving.

The ten invalid fixtures, each rejected by the witness calculator at the rule it breaks (the
`statementHash` of every mutation except the last is recomputed, so the named rule is the only one
broken). The same rules fire at all three sizes.

| Fixture | What changed | Rejected at |
|---|---|---|
| `bad_order_signature` | order `S` + 1 | EdDSA equality (`ForceEqualIfEnabled`) |
| `bad_escrow_signature` | escrow `S` + 1 | EdDSA equality |
| `price_changed_after_signing` | price + 1, refund − 1, total + 1 (arithmetic still balances) | EdDSA equality |
| `payout_script_swapped` | `sellerPayoutId` replaced by another sale's | EdDSA equality |
| `seller_id_not_signer` | `sellerId` set to another seller's key hash | `sellerId = Poseidon(A)` in `SignedOrder` |
| `fee_over_cap` | `feeBudget` = cap + 1, refund lowered to balance | `Bits51` range check on `feeCap − feeBudget` |
| `order_r8_off_curve` | `R8.x` + 1 | `BabyCheck` on `R8` |
| `expired_order` | order validly re-signed with expiry = `batchHeight` − 1 | `AtMostHeight` (`Num2Bits(32)` on the gap) |
| `expired_escrow` | escrow terms validly re-signed with expiry = `batchHeight` − 1 | `AtMostHeight` |
| `wrong_statement_hash` | claimed `statementHash` + 1, statement unchanged | `statementHash === statement.out` in `SignedClearingTree` |

## Where the constraints go

`cost_split.sh` compiles each part of the circuit as its own main and adds them up. At 16×4, 64×8
and 128×8 the sum equals the compiled whole circuit exactly (difference 0).

At 128×8:

| Part | Each | Count | Total |
|---|---|---|---|
| `SignedOrder` (signature part, per sale slot) | 4,852 | 128 | 621,056 |
| `SignedEscrow` (signature part, per buyer slot) | 5,006 | 8 | 40,048 |
| `ClearingAmounts` (ranges, selectors, sums) | | 1 | 18,087 |
| Selected-buyer products (selector × buyerId) | 1 | 1,024 | 1,024 |
| Sale leaf, Poseidon(6) | 354 | 128 | 45,312 |
| Sale tree, 127 × Poseidon(2) | | 1 | 30,480 |
| Escrow leaves and commitment | 321 / 402 | 8 / 1 | 2,970 |
| Statement hash, `PoseidonChunked(36)` | | 1 | 1,773 |
| `batchHeight` range check | | 1 | 51 |
| **Whole circuit** | | | **760,801** |

A `SignedOrder` is 4,852 constraints: `EdDSAPoseidonVerifier` 4,217, the message Poseidon(6) 354, the
key hash Poseidon(2) 240, two `BabyCheck` 6, the expiry check 32, other 3.

Per sale slot, across sizes:

| | 16×4 | 64×8 | 128×8 | 1,024×8 (*est.*) |
|---|---|---|---|---|
| Seller signatures | 4,852 | 4,852 | 4,852 | 4,852 |
| Buyer signatures (5,006 each, spread over the sale slots) | 1,252 | 626 | 313 | 39 |
| Everything else: amounts, leaves, tree, escrow commitment, statement hash | 954 | 835 | 779 | 730 |
| Whole circuit | 7,058 | 6,313 | 5,944 | 5,621 |
| Signatures as a share of the circuit | 86.5% | 86.8% | 86.9% | 87.0% |

The seller signature is a constant 4,852 per sale slot. The buyer signatures and the rest fall as
their fixed parts (per-buyer range checks, the escrow commitment, the statement hash, the tree's
top levels) are spread over more sales. The rest levels off near 730 per slot, close to the 694 M6
found for the unsigned circuit at 1,024 slots. The tree itself is 4% of the circuit at 128 slots
(30,480 of 760,801 constraints).

## Extrapolation to 1,024 slots (*est.*)

Not a run. A 1,024-slot batch is far above what this machine can hold.

| | 1,024×8 | Basis |
|---|---|---|
| Constraints | **5,756,001** | Sum of the parts compiled for 1,024×8 (`results/cost-split-1024x8-est.txt`). The same sum is exact at the three measured sizes, so the whole circuit is expected to match. The roadmap's estimate was 5.8 M |
| Per sale slot | 5,621 | |
| Phase-1 power | **23** | 2^22 = 4,194,304 is too small; 2^23 = 8,388,608. A prepared power-23 file is about 9.7 GB (8 × the 1.21 GB power-20 file) |
| Compile | about 460 s, 22 to 23 GiB | 128×8 scaled by 7.57 (the constraint ratio); memory from the 64×8 → 128×8 slope up to proportional |
| Phase 2 (setup + beacon) | about 2,800 s, 36 to 45 GiB | 128×8 scaled by 7.57 |
| Proving key | about 4.2 GB | 128×8 scaled by 7.57 |
| **Prove (snarkjs)** | **about 150 to 250 s**, 30 to 51 GiB | 7.57 × the lowest observed 128×8 time (19.18 s) and × the median of its repeats (33.5 s). Memory from the 64×8 → 128×8 slope (4.8 KiB per constraint) up to proportional (9.3 KiB per constraint) |
| Verify, proof, public signals | about 0.4 s, 256 B, 1 | Independent of the circuit |

The memory at this size is above the machine's 19 GB for setup and for proving, so snarkjs could not
run it here. rapidsnark was not built, so its time and memory at this size are unmeasured.
Measured memory grew more slowly than the constraint count (from 64×8 to 128×8 it grew 1.3 times
for 1.9 times the constraints), which is why the memory is a range.

## Reading

- **Signatures are 87% of the circuit at every size.** 4,852 constraints per sale slot, 4,217 of
  them circomlib's `EdDSAPoseidonVerifier`. The tree, the leaves, the arithmetic and the hash of
  the whole statement together cost 730 to 954 per slot. M6's unsigned circuit cost about 700, so
  the signed circuit is about 8 times larger per sale from 128 slots up, the 8× that SCALING.md
  estimated.
- **The ceiling is the power-20 phase-1 file.** 128 sale slots take 73% of it. 256 slots would need
  about 1.5 M constraints (*est.*, 128×8 plus 128 more slots at about 5,600) and a power-21
  phase-1 file. A day's 1,024 sales need power 23.
- **One public input keeps the verifier side the same at every size.** The proof is 256 bytes with
  one public signal and the verifying key is about 2.9 KB, for 16, 64 and 128 slots. BitVM's
  verifier follows the verifying key's shape, not the constraint count: in M3 the disprove leaves
  matched M1's in size apart from the MSM, although the circuit grew by 1,074 constraints. The
  BitVM graph was not re-run on these proofs. Patch 0002 (`NUM_PUBS = 1`) is the count of this
  verifying key.
- **Only the hash goes on chain.** As in M3, the committee needs the statement's 4 + 4B values from
  the operator before it presigns, and recomputes `statementHash` from them.
  `statement_signed_tree.js` is that computation.

## Not run, not covered

- **rapidsnark.** Not built here. All prove times are snarkjs.
- **1,024 slots.** Estimated only (above). Its 6 M constraints do not compile or prove in this VM.
- **The Rust side and BitVM** were not run here. M14 ([../bitvm/M14.md](../bitvm/M14.md)) ran
  both afterwards: `PoseidonChunked` in light-poseidon matches circomlibjs, and the 16×4 proof
  settles through BitVM on regtest as M3's did.
- **M4's open items stay open.** An order key is not bound to the seller's sharechain
  `miner_address` (M5's ownership tree is the way to do that, roadmap item 3). `escrowId` and
  `refundScriptId` are field encodings of labels, and the Bitcoin transaction graph must spend
  exactly those outpoints and pay those scripts. `batchHeight` is supplied by the operator, so the
  graph must bind it to the Bitcoin height for the expiry checks to mean anything.
- **circom and the WSL clock.** On the measurement VM, several compiles panicked inside circom
  2.2.2 (`constraint_simplification.rs`, a `SystemTimeError` of a fraction of a second to 25
  minutes) when the VM's clock stepped backwards. Re-running the same command compiled the same
  circuit. The results above are from runs that completed.
- **The setup is insecure** (public beacon, local phase-1 file). The keys are public demo keys.
