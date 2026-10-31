# M6: how the clearing proof scales with batch size

Measured 2026-11-01. Toolchain: circom 2.2.2 and snarkjs 0.7.5 (pinned by
`groth16/package-lock.json`). Machine: AMD Ryzen AI 9 365, WSL2 Ubuntu 24.04 with a 20 GB VM;
other jobs were running on the machine at the same time. The setup is insecure: one
deterministic beacon, as in GROTH16.md. A single phase-1 file at power 20 serves every size.

## The circuit

`circuits/clearing_tree.circom` defines `CommittedClearingTree(saleSlots, buyerSlots, depth)`.

- **Statement:** v1's (arithmetic, padding rules, Poseidon5 sale leaves).
- **Commitment:** a binary Poseidon2 tree replaces the flat Poseidon16 root, so the slot count can
  be any power of two.
- **Check:** `scaling/commit_tree.js` recomputes the root with circomlibjs.
- **Inputs:** `scaling/gen_inputs.py` writes a deterministic batch with every slot active (the
  prover's worst case), plus a funding-mismatch fixture.

Reproduce one size:

```sh
SCALE_SALES=256 SCALE_BUYERS=8 POWER=20 PTAU=<prepared power-20 ptau> \
CIRCUIT_DIR=research/zk_clearing/scaling/circuits \
FIXTURES=research/zk_clearing/scaling/fixtures.sh \
COMMIT_JS=research/zk_clearing/scaling/commit_tree.js \
  bash research/zk_clearing/groth16/run.sh tree_256x8 /tmp/zkc-256
```

Without `PTAU`, `run.sh` generates the phase-1 file itself.

## Results

Every size passes every check in `run.sh`:

- the valid witness satisfies the R1CS, and the proof verifies;
- the tree root matches circomlibjs;
- a sale list with two IDs swapped gives a different commitment;
- the funding-mismatch fixture is rejected by the witness calculator;
- a tampered public signal, a public signal written as `x + r`, and a forged `.wtns` are all
  rejected.

| | 16×4 | 64×8 | 256×8 | 1024×8 |
|---|---|---|---|---|
| Constraints | 11,995 | 46,655 | 179,519 | 710,975 |
| Constraints per sale slot | 750 | 729 | 701 | 694 |
| Wires | 11,914 | 46,398 | 178,686 | 707,838 |
| Private / public inputs | 153 / 17 | 849 / 33 | 3,345 / 33 | 13,329 / 33 |
| Compile | 3.3 s, 352 MiB | 3.6 s, 452 MiB | 13.9 s, 923 MiB | 52.0 s, 3.34 GiB |
| Phase 2 (setup + beacon, power-20 phase 1) | 19.4 s, 591 MiB | 35.6 s, 1.12 GiB | 136 s, 2.54 GiB | 582 s, 7.08 GiB |
| Proving key | 11.3 MB | 44.7 MB | 174.9 MB | 695.8 MB |
| **Prove (snarkjs)** | **0.94 s**, 795 MiB | **2.20 s**, 1.17 GiB | **8.73 s**, 3.19 GiB | **35.3 s**, 6.61 GiB |
| Prove time per sale | 59 ms | 34 ms | 34 ms | 34 ms |
| Verify (snarkjs CLI) | 0.37 s | 0.34 s | 0.36 s | 0.45 s |
| Proof | 256 B | 256 B | 256 B | 256 B |

The shared phase-1 file (power 20, one insecure beacon) took 45 s to create, 300 s for the
beacon and 3,892 s for `prepare phase2`, a peak of 2.1 GiB, while other heavy jobs shared the
machine. It is 1,207,961,038 bytes, sha256 `53df507c…cc300ddbbd0`. A real deployment would use a
public ceremony's file instead (see M8).

## Reading

- **Where the cost per sale levels off.**
  - Constraints per slot fall from 750 to about 700, and stay there from 256 slots up. The fixed
    part (per-buyer range checks, the commitment's top levels) is spread over more sales.
  - Proving time per sale levels off at about 34 ms from 64 slots up.
  - Proving key size and setup memory grow linearly.
- **The largest size fits on a laptop.** A 1,024-sale batch, about a day of M7's workload, proves
  in 35 s with 6.6 GiB of RAM. Proving is not what limits batch size. The limits are fill time
  (M7) and the one-time setup (about 10 min and 7 GiB per circuit, plus the power-20 phase-1
  file).
- **Against the flat root.** At 16 slots the binary tree costs 11,995 constraints against v1's
  9,004. Fifteen Poseidon2 nodes cost more than one Poseidon16, but the tree is what allows more
  than 16 slots.
- **Verification stays constant**, as Groth16 promises: 256-byte proofs and about 0.4 s in the
  snarkjs CLI, most of which is Node start-up.

## Not run

- **rapidsnark (C++ prover).** It was not built. Delegating its source build was refused by the
  session's tool policy, and it was not retried. All prove times here are snarkjs (WASM witness,
  JS prover). rapidsnark is commonly several times faster, but that was not measured here.
- **Signature cost at scale.** The signature checks M4 added (about 5,000 constraints per
  signature) are not in these circuits. At one signature per sale they would add about 5,000 per
  slot, so a 1,024-slot signed batch is about 5.8 M constraints (*est.*, about 8× the unsigned
  circuit).
