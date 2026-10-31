# Research: bounded Groth16 share-clearing arithmetic

Status: **compiled and proven with an insecure single-party setup.** Both circuits below compile
with circom 2.2.2, produce Groth16 proofs that snarkjs 0.7.5 verifies, and reject every invalid
fixture. The measurements, audit and remaining limits are in [GROTH16.md](GROTH16.md). There is
no Bitcoin-enforced escrow.

This is a follow-up to `docs/proposals/provable-share-clearing-v0.md`. It does not change
P2Poolv2 sharechain consensus, PPLNS payouts, wallet behavior, node deployment, or existing
atomic swaps.

## Circuits

| File | Statement | Constraints |
|---|---|---|
| `circuits/clearing.circom` | Shared templates: `Bits51`, `SatoshiAmount`, `ClearingAmounts` | — |
| `circuits/accounting16x4.circom` | v0: arithmetic only | 3,159 |
| `circuits/accounting16x4_committed.circom` | v1: v0 plus a public Poseidon commitment to the sale list | 9,004 |

Both use sixteen sale slots and four buyer escrow slots.

- **Amounts.** Every satoshi amount is bounded to 0 through 2,100,000,000,000,000. Active sale
  prices must be positive.
- **Slots.** Each active sale selects exactly one buyer, and unused sale or buyer slots contain
  zero amounts.
- **Per buyer:**

```text
funding[buyer] = feeBudget[buyer] + refund[buyer]
               + sum(price[sale] * selector[sale][buyer])
```

- **Total:** `totalPayout = sum(price)`. Every sum is far below the field prime, so the field
  equations are the integer equations.

**v0 binds nothing private.** Its public inputs (`funding[4]`, `feeBudget[4]`, `refund[4]`,
`totalPayout`) already determine each buyer's total cost. Any other sale list with the same
totals proves the identical statement; the pipeline demonstrates this with `resplit.json`.

**v1 adds a commitment.**

- **New inputs:** public `buyerId[4]`, and private `saleId[16]` (share outpoint) and
  `sellerId[16]` (the seller's sharechain `miner_address`, which owns the share output).
- **New output:** public `saleCommitment = Poseidon16(leaf[0..15])`, where each leaf is
  `Poseidon5(activeSale, saleId, sellerId, price, selected buyerId)`.
- **Padding:** padding slots must carry zero identities.
- **Checking a proof:** a verifier holding the sale list recomputes the commitment
  (`groth16/commit.js`, using circomlibjs) and compares it with the proof's public output.

## Python side

- **`witness.py`:** builds circuit inputs from an already successful `model.plan_batch` and
  computes the field inverses in the BN254 scalar field. `field_id` maps identity strings to
  field elements.
- **`fixtures.py`:** writes `valid.json`, `resplit.json` and one invalid fixture per rule. The
  invalid fixtures bypass the Python oracle.
- **`wtns.py`:** reads and writes `.wtns` files, so `run.sh` can forge a witness that skips the
  witness calculator.

## Trust boundary

Even with v1, a proof certifies the arithmetic and binds a specific sale list. It does not
authenticate any of the following:

- that the sale IDs are spendable sharechain outputs;
- that the sellers own or signed for them;
- the seller's Bitcoin payout destination;
- the buyers' escrow outpoints or funding amounts;
- replay history, chain tips or Bitcoin ancestry.

PPLNS maturity, uncle weighting, the paying-block anchor and Bitcoin ancestry rules are outside
the circuit. [GROTH16.md](GROTH16.md) lists each missing predicate and how it would be bound.

## Validation

Python, from the repository root (stdlib only):

```sh
python3 -m unittest discover -s research/zk_clearing -p 'test_*.py' -v
```

Groth16 end to end. This needs circom 2.2.2, Node with npm, python3 and GNU time. npm packages
come from the committed lockfile:

```sh
bash research/zk_clearing/groth16/run.sh accounting16x4 /tmp/zkc-v0
bash research/zk_clearing/groth16/run.sh accounting16x4_committed /tmp/zkc-v1
```

No resources from the separate private security-fixes repository are used here.
