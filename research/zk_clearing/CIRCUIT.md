# Research: bounded Groth16-compatible share-clearing arithmetic

Status: **uncompiled research circuit**. This is a Circom source, Python witness adapter and equation oracle. It has no generated Groth16 proof, verification key or Bitcoin-enforced escrow.

This is a **stacked follow-up** to `docs/proposals/provable-share-clearing-v0.md`. It does not change P2Poolv2 sharechain consensus, PPLNS payouts, wallet behavior, node deployment, or existing atomic swaps.

## What the proposed circuit checks

`circuits/accounting16x4.circom` uses sixteen sale slots and four buyer escrow slots. Every satoshi amount is bounded to 0 through 2,100,000,000,000,000. Active sale prices must be positive. Active sales select exactly one buyer, and unused sale or buyer slots contain zero amounts.

The public inputs are `funding[4]`, `feeBudget[4]`, `refund[4]` and `totalPayout`. Private inputs include sale prices, active-slot flags, the buyer assignment matrix and modular inverses to enforce nonzero active values.

For each buyer, the arithmetic relation is:

```text
funding[buyer] = feeBudget[buyer] + refund[buyer]
               + sum(price[sale] * selector[sale][buyer])
```

The circuit also requires `totalPayout = sum(price)`. The range constraints rule out negative amounts and field-wraparound for this bounded number of sales.

`witness.py` derives the inputs from an already successful `model.plan_batch` and uses the BN254 scalar field for inverses. `encode_snarkjs_input` serializes all field elements as decimal strings to avoid JavaScript number precision loss. `example_inputs.py` emits deterministic JSON with placeholder identities.

## Crucial trust boundary

Even if compiled and proven, this circuit would certify **only arithmetic consistency of caller-supplied figures**. It cannot authenticate Bitcoin funding outpoints, signed sale orders, sharechain UTXO membership, owner identity, replay history, chain tips, payout addresses or refund destinations.

The SHA-256 `BatchPlan.commitment` from the reference model is **not bound into this circuit**. A valid proof could be paired with an unrelated Bitcoin transaction. The circuit says nothing about a market maker's solvency, Bitcoin finality, or the enforceability of a BitVM challenge. The PPLNS maturity, uncle weighting, paying-block anchor and Bitcoin ancestry rules are also outside this circuit.

This is a candidate arithmetic subcircuit for a larger, authenticated settlement statement.

## Validation

From repository root, with Python 3:

```sh
python3 -m unittest discover -s research/zk_clearing -p 'test_*.py' -v
python3 -m py_compile research/zk_clearing/model.py research/zk_clearing/witness.py research/zk_clearing/example_inputs.py
python3 research/zk_clearing/example_inputs.py > /tmp/p2pool-clearing-example-inputs.json
```

The local semantic equation tests passed (36 Python tests across the original model and this extension). They are **not** a Circom compiler, R1CS witness checker or Groth16 proof verification.

With a separately installed and reviewed Circom compiler 2.1.8+ and `snarkjs`, the next gate is:

```sh
mkdir -p /tmp/p2pool-clearing-circuit
circom research/zk_clearing/circuits/accounting16x4.circom --r1cs --wasm --sym -o /tmp/p2pool-clearing-circuit
snarkjs r1cs info /tmp/p2pool-clearing-circuit/accounting16x4.r1cs
python3 research/zk_clearing/example_inputs.py > /tmp/p2pool-clearing-circuit/example-inputs.json
node /tmp/p2pool-clearing-circuit/accounting16x4_js/generate_witness.js /tmp/p2pool-clearing-circuit/accounting16x4_js/accounting16x4.wasm /tmp/p2pool-clearing-circuit/example-inputs.json /tmp/p2pool-clearing-circuit/example.wtns
```

A complete Groth16 check requires a securely generated setup, pinned verifying key, valid proof verification and adversarial witness tests. Do not use a toy or single-operator setup to imply production-ready trust assumptions.

## Acceptance gates before real settlement

1. Compile the circuit; measure its R1CS constraints and proving costs; verify an actual proof and failed forged witnesses with a pinned toolchain.
2. Add cryptographic authorization and sharechain-membership predicates bound to an authenticated chain state, plus externally enforced nullifier/replay rules and reorganization policy.
3. Bind the proved statement to actual escrow UTXOs, payout addresses, amounts, refund paths, transaction graph and challenge data using a specified BitVM implementation.
4. Compare full collateral-hours, Bitcoin vbytes, latency, liveness and failure rates against bilateral HTLC/Lightning or Ark swaps using identical trades and a declared workload.

No resources from the separate private security-fixes repository are used here.
