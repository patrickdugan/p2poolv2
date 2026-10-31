# Proposal: externally verified share clearing (research v0)

Status: **research-only**, non-consensus, offline reference model. This is a proposal for discussion, not a deployed Groth16 circuit, BitVM escrow, signature verifier, wallet, or Bitcoin transaction builder.

## Motivation and scope

P2Poolv2 already has the central primitive: sharechain outputs owned by the sharechain `miner_address`, independent of the `miner_bitcoin_address` used for Bitcoin coinbase payouts. Its design anticipates trading sharechain outputs to market makers through atomic swaps over Lightning or Ark. An additional clearing layer may allow multiple signed sales to be netted against funded market-maker escrow positions, with one reproducible settlement statement. Whether it beats individual swaps on total cost and trust assumptions is an experiment, not an assumption.

This proposal changes **no sharechain consensus rules**, PPLNS payout code, address logic, Bitcoin coinbase outputs, wallet behavior, or existing HTLC workflow. It also deliberately avoids any dependency on security-sensitive branches or unpublished fixes.

## Existing rules the future proof must preserve

1. Sharechain `miner_address` owns share outputs; Bitcoin `miner_bitcoin_address` receives PPLNS payouts. They are independent identities. A seller's Bitcoin payment address must be authorized separately from their sharechain ownership.
2. PPLNS pays from a window anchored at the paying share's parent. Immature shares are skipped, uncles have special weighting, and the output split has deterministic rounding. See `docs/architecture/payout-distribution.md`.
3. Eligibility also depends on the Bitcoin parent chain of the *paying* share. A share with an ineligible Bitcoin parent retains its PPLNS window slot but contributes zero weight. See `docs/architecture/mine-on-bitcoin-chain.md`.
4. A sharechain transfer, an economically valid claim on eventual rewards, a currently spendable sharechain UTXO and a funded Bitcoin escrow are distinct facts. A proof for one is not evidence of all four.

## Research statement v0

The experimental `research/zk_clearing/model.py` plans a batch from:

- A pinned `Context`: Bitcoin network, sharechain tip, Bitcoin tip, and expiry Bitcoin height.
- `Sale` records: sharechain outpoint, seller's sharechain address, the seller's authorized **Bitcoin** payment address, buyer's sharechain address, buyer ID, and integer price in satoshis.
- Asserted `InputState`: outpoint-to-owner bindings, independently approved sale instructions, plus previously cleared share outpoints and previously used escrow UTXOs.
- `Escrow` records: buyer ID, Bitcoin outpoint, refund address, gross funding in sats, and reserved fee budget.

The model rejects duplicate share inputs, repeated Bitcoin escrow inputs, replay against supplied spent sets, unauthorized modifications relative to **asserted** approvals, insufficient buyer funding, an expired snapshot and an unexpected tip or network. Successful plans aggregate seller payments and buyer refunds in sorted order. Their conservation rule is

```
sum(seller_payouts) + sum(buyer_refunds) + sum(fee_budgets)
    == sum(escrow_funding)
```

Each output includes a SHA-256 commitment over a canonical JSON encoding with a domain/version string, all input assertions, network/tips, sale instructions, funding/fee assignments, and settlement outputs. SHA-256 commitment is a **binding label only**. It is neither a zero-knowledge proof nor an authenticated statement that a Bitcoin transaction spends the named escrows.

The `InputState` objects are *trusted inputs to this toy model*. An adversary can supply false ownership, approvals, Bitcoin funding or replay state and still produce a mathematically consistent batch. The model cannot establish that the supplied spendable outputs exist, that a seller signed an order, that Bitcoin funding is confirmed, or that the chain tip is canonical. The expiry check is a local policy check with an asserted observed height.

## Path to a Groth16 circuit

A separately reviewed v1 circuit would prove membership of accepted, mature/eligible share outputs in a committed sharechain state **and** verify ownership/authorization for each sale against canonical, versioned rules. A proof of PPLNS entitlement additionally needs the paying-block anchor, Bitcoin ancestry eligibility, uncle weighting, deterministic rounding and window maturity logic. These are different proof predicates and should be benchmarked separately. Proof-of-membership inputs must be authenticated to consensus, with a documented reorganization/finality policy.

Proposed *public inputs* include the domain/version, network/chain IDs, rooted share state, Bitcoin anchor, expiry/challenge parameters, input-escrow commitment, output commitment and per-batch nullifier root. Private witnesses might include inclusion paths and signed sale orders, with a specified signature circuit. Funding and authorization verification must be implemented rather than assumed. Proving costs and circuit sizes are unknown.

## Path to a BitVM settlement bridge

Bitcoin must enforce the linkage between an escrow's actual input outpoints, an authenticated proof statement, the permitted payout/refund transaction graph and a challenge resolution. A valid Groth16 proof alone does not constrain a Bitcoin spend. A v1 escrow protocol must specify an operator's bonded collateral, challengers, fraud/dispute data availability, challenge window, timeout refund, maximum per-counterparty loss, funding confirmations, fees and Bitcoin reorg handling. It needs full regtest adversarial transaction traces and a clearly named BitVM verifier implementation before claiming soundness.

A future proof-verifier binding should commit to transaction templates and amounts, and should explain the liveness and trust assumptions under which honest counterparties can recover funds. An escrow ledger is not a Bitcoin covenant.

## Comparison to baseline

Measure at least: 100 sellers, 5 market makers and 10,000 offers under fixed seeds. Compare (a) bilateral HTLC swaps against (b) batched clearing with escrow. Report on-chain bytes/vbytes, Lightning/Ark fees, proving time, verifier cost, operator collateral-hours, settlement latency, refund time, reorg exposure, and loss bounds. Report failures and rejected offers. Do not equate the toy model's passing tests with a reduction in real fees or trust.

## Offline reference tests

Run from repository root with Python 3 (stdlib only):

```sh
python3 -m unittest discover -s research/zk_clearing -p 'test_*.py' -v
```

Fixtures test accounting conservation, canonical ordering, changed authorizations, duplicate inputs, underfunding, escrow reuse, stale tips, expiry, replay, network binding, fee binding, and invalid amounts. No model calls, crypto dependencies, Bitcoin node, or mining equipment are needed.

## Review boundary

This should land as a standalone research discussion before introducing new consensus or Bitcoin-spending code. It is independent of the existing `docs/atomic-swap/` designs and the unfinished upstream atomic-swap PR. Any security findings about production code belong in the private disclosure channel described in `SECURITY.md`.
