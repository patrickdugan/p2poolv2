"""The sharechain UTXO set as an executable definition, and its incremental accumulator.

`SharechainUtxo` replays P2Poolv2's output rules on one branch of the sharechain.
`accumulator_snapshot` is the pure function a watcher computes: the exact set of
outputs a published root commits to at an anchor height. `Accumulator` maintains
the same tree incrementally, one share block at a time, and `test_utxo_set.py`
checks the two agree.

The rules mirror the Rust code (see OWNERSHIP.md for file and line references):

* the share coinbase makes output 0 (one share, 100,000,000 units, paid to the
  header's `miner_address`) and an OP_RETURN witness-commitment output 1;
* an output's `root_height` is the block height for a coinbase output and the
  minimum over its inputs for any other output (`add_sharechain_txs`);
* a block at height `h` may spend an output only if it exists, is unspent,
  has `root_height >= h - payout_depth`, and, if it is a coinbase output,
  has `h - root_height >= coinbase_maturity` (`check_prevouts`).

The accumulator then commits to the outputs that are spendable at the next
block with at least `expiry_margin` blocks of life left, that are worth at least
`min_units`, and that fit the tree.

Owners. By default a leaf's owner is the address id of the output's share address
(`smt.owner_id`). Given a `registry`, a mapping from share address to a registered order
key hash (`register.Registry.owners()`), an output whose address is registered has that
hash as its owner instead, and any other output keeps the address id. Which outputs are in
the tree does not depend on the registry; only the leaf values do.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Sequence

import smt

OutPoint = tuple[str, int]


class ConsensusError(ValueError):
    """A block breaks an output rule the Rust node enforces."""


@dataclass(frozen=True)
class ChainParams:
    coinbase_maturity: int  # COINBASE_MATURITY
    payout_depth: int  # PAYOUT_DEPTH = COINBASE_MATURITY + PPLNS_WINDOW_SHARES
    expiry_margin: int  # accumulator choice, not consensus
    max_depth: int  # deepest leaf the tree (and the circuit) allows; n_levels = max_depth + 1
    min_units: int = 0  # dust floor of the accumulator (not consensus): smaller outputs are not tracked

    def window(self, anchor: int) -> tuple[int, int]:
        """Inclusive range of root heights an anchor's set holds."""
        lower = anchor + 1 - self.payout_depth + self.expiry_margin
        upper = anchor + 1 - self.coinbase_maturity
        return lower, upper


# accounting/payout/sharechain_pplns/pplns_window.rs: 6,048 + 120,960
PRODUCTION = ChainParams(coinbase_maturity=6048, payout_depth=127_008, expiry_margin=1008, max_depth=39)

SHARE_UNITS = 100_000_000  # shares/transactions/coinbase.rs SHARE_VALUE: 1 BTC per share


@dataclass(frozen=True)
class Tx:
    txid: str
    inputs: tuple[OutPoint, ...] = ()
    outputs: tuple[tuple[str | None, int], ...] = ()  # (share address or None if not a P2TR output, units)
    is_coinbase: bool = False


def share_coinbase(txid: str, miner_address: str) -> Tx:
    """The sharechain coinbase (build_sharechain_coinbase_for_witness_root): a share, then OP_RETURN."""
    return Tx(txid=txid, outputs=((miner_address, SHARE_UNITS), (None, 0)), is_coinbase=True)


@dataclass
class Output:
    txid: str
    vout: int
    owner: str | None
    units: int
    root_height: int
    is_coinbase: bool
    order: tuple[int, int, int]  # (block height, tx index, vout)
    _key: int | None = field(default=None, repr=False)
    _value: int | None = field(default=None, repr=False)

    @property
    def outpoint(self) -> OutPoint:
        return (self.txid, self.vout)

    @property
    def key(self) -> int:
        if self._key is None:
            self._key = smt.outpoint_id(self.txid, self.vout)
        return self._key

    @property
    def value(self) -> int:
        if self._value is None:
            self._value = smt.leaf_value(smt.owner_id(self.owner), self.units, self.root_height)
        return self._value

    def value_for(self, registry: Mapping[str, int] | None = None) -> int:
        """The leaf value with the owner the registry gives this output's address."""
        if registry and self.owner in registry:
            return smt.leaf_value(registry[self.owner], self.units, self.root_height)
        return self.value


class SharechainUtxo:
    """All outputs and spends on one branch, with P2Poolv2's spend rules."""

    def __init__(self, params: ChainParams):
        self.params = params
        self.outputs: dict[OutPoint, Output] = {}
        self.spent_at: dict[OutPoint, int] = {}
        self.by_root: dict[int, list[Output]] = {}
        self.tip = -1

    def spend_error(
        self,
        outpoint: OutPoint,
        height: int,
        staged_outputs: dict[OutPoint, Output] | None = None,
        staged_spent: dict[OutPoint, int] | None = None,
    ) -> str | None:
        """Why a block at `height` may not spend `outpoint`, or None. Mirrors `check_prevouts`."""
        output = (staged_outputs or {}).get(outpoint) or self.outputs.get(outpoint)
        if output is None:
            return "missing output"
        if outpoint in self.spent_at or outpoint in (staged_spent or {}):
            return "already spent"
        if output.root_height < max(0, height - self.params.payout_depth):
            return "coinbase root too old"
        if output.is_coinbase and height - output.root_height < self.params.coinbase_maturity:
            return "immature coinbase"
        return None

    def apply_block(self, height: int, txs: Sequence[Tx]) -> list[Output]:
        """Apply a block atomically: a rule violation leaves the state untouched."""
        if height != self.tip + 1:
            raise ConsensusError(f"block {height} does not extend tip {self.tip}")
        created: list[Output] = []
        staged_outputs: dict[OutPoint, Output] = {}
        staged_spent: dict[OutPoint, int] = {}
        for index, tx in enumerate(txs):
            if tx.is_coinbase:
                if tx.inputs:
                    raise ConsensusError("coinbase with inputs")
                root = height
            else:
                if not tx.inputs:
                    raise ConsensusError("transaction with no inputs")
                roots = []
                for outpoint in tx.inputs:
                    if outpoint in staged_spent:
                        raise ConsensusError(f"{outpoint} spent twice in one block")
                    error = self.spend_error(outpoint, height, staged_outputs, staged_spent)
                    if error:
                        raise ConsensusError(f"{outpoint}: {error}")
                    roots.append((staged_outputs.get(outpoint) or self.outputs[outpoint]).root_height)
                    staged_spent[outpoint] = height
                root = min(roots)
            for vout, (owner, units) in enumerate(tx.outputs):
                output = Output(tx.txid, vout, owner, units, root, tx.is_coinbase, (height, index, vout))
                if output.outpoint in self.outputs or output.outpoint in staged_outputs:
                    raise ConsensusError(f"duplicate outpoint {output.outpoint}")
                staged_outputs[output.outpoint] = output
                created.append(output)
        self.outputs.update(staged_outputs)
        self.spent_at.update(staged_spent)
        for output in created:
            self.by_root.setdefault(output.root_height, []).append(output)
        self.tip = height
        return created

    # -- the definition ------------------------------------------------------
    def eligible(self, anchor: int) -> Iterable[Output]:
        """Outputs the anchor's set holds before the slot rule: tracked, created, unspent, in the window."""
        lower, upper = self.params.window(anchor)
        for root in range(max(lower, 0), upper + 1):
            for output in self.by_root.get(root, ()):
                if output.owner is None or output.units < self.params.min_units or output.order[0] > anchor:
                    continue
                spent = self.spent_at.get(output.outpoint)
                if spent is not None and spent <= anchor:
                    continue
                yield output

    def snapshot(self, anchor: int) -> list[Output]:
        """The tracked outputs at `anchor`: eligible, with the oldest output winning each tree slot."""
        mask = (1 << self.params.max_depth) - 1
        winners: dict[int, Output] = {}
        for output in self.eligible(anchor):
            slot = output.key & mask
            held = winners.get(slot)
            if held is None or output.order < held.order:
                winners[slot] = output
        return sorted(winners.values(), key=lambda output: output.key)

    def build_tree(self, anchor: int, registry: Mapping[str, int] | None = None) -> smt.SparseMerkleTree:
        """The anchor's tree. `registry` maps share addresses to registered order key hashes."""
        tree = smt.SparseMerkleTree.from_items(
            ((output.key, output.value_for(registry)) for output in self.snapshot(anchor)),
            max_depth=self.params.max_depth,
        )
        return tree


class Accumulator:
    """The same tree, kept up to date block by block."""

    def __init__(self, params: ChainParams, registry: Mapping[str, int] | None = None):
        self.params = params
        self.model = SharechainUtxo(params)
        self.tree = smt.SparseMerkleTree(max_depth=params.max_depth)
        self.registry: dict[str, int] = dict(registry or {})
        self._mask = (1 << params.max_depth) - 1
        self._candidates: dict[int, list[Output]] = {}  # slot -> eligible outputs, oldest first
        self._tracked: dict[int, Output] = {}  # slot -> the output in the tree
        self.inserts = 0
        self.deletes = 0
        self.updates = 0

    @property
    def anchor(self) -> int:
        return self.model.tip

    @property
    def root(self) -> int:
        return self.tree.root

    def __len__(self) -> int:
        return len(self.tree)

    def apply_block(self, height: int, txs: Sequence[Tx]) -> None:
        created = self.model.apply_block(height, txs)
        lower, upper = self.params.window(height)
        for tx in txs:
            for outpoint in tx.inputs:
                self._drop(self.model.outputs[outpoint])
        for output in created:
            if (
                not output.is_coinbase
                and output.owner is not None
                and output.units >= self.params.min_units
                and output.outpoint not in self.model.spent_at
                and lower <= output.root_height <= upper
            ):
                self._add(output)
        # Coinbase outputs become spendable `coinbase_maturity` blocks after their block.
        for output in self.model.by_root.get(upper, ()):
            if output.is_coinbase and output.owner is not None and output.units >= self.params.min_units and upper >= lower:
                if output.outpoint not in self.model.spent_at:
                    self._add(output)
        # Outputs whose remaining life fell below the margin leave.
        for output in self.model.by_root.get(lower - 1, ()):
            self._drop(output)

    def _add(self, output: Output) -> None:
        slot = output.key & self._mask
        candidates = self._candidates.setdefault(slot, [])
        if any(held is output for held in candidates):
            return
        bisect.insort(candidates, output, key=lambda held: held.order)
        if candidates[0] is output:
            self._set_head(slot, output)

    def _drop(self, output: Output) -> None:
        slot = output.key & self._mask
        candidates = self._candidates.get(slot)
        if not candidates:
            return
        for position, held in enumerate(candidates):
            if held is output:
                del candidates[position]
                break
        else:
            return
        if position == 0:
            self._set_head(slot, candidates[0] if candidates else None)
        if not candidates:
            del self._candidates[slot]

    def _set_head(self, slot: int, output: Output | None) -> None:
        held = self._tracked.pop(slot, None)
        if held is not None:
            self.tree.delete(held.key)
            self.deletes += 1
        if output is not None:
            self.tree.insert(output.key, output.value_for(self.registry))
            self._tracked[slot] = output
            self.inserts += 1

    def set_owner_key(self, address: str, key_hash: int | None) -> int:
        """Register (or with None, unregister) an order key hash for a share address.

        Every output of the address that is in the tree gets its leaf rewritten, so a rotation
        costs one tree update per tracked output of the address. Returns the number rewritten.
        Outputs that enter the tree later pick up the new owner on insertion.
        """
        if key_hash is None:
            self.registry.pop(address, None)
        else:
            self.registry[address] = key_hash
        rewritten = 0
        for output in self._tracked.values():
            if output.owner == address:
                self.tree.update(output.key, output.value_for(self.registry))
                rewritten += 1
        self.updates += rewritten
        return rewritten

    def tracked_outputs(self) -> list[Output]:
        return list(self._tracked.values())

    def prove(self, outpoint: OutPoint) -> tuple[smt.MembershipProof, Output]:
        output = self.model.outputs[outpoint]
        return self.tree.prove(output.key), output
