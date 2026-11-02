"""A dense Poseidon tree over the anchor's window of sharechain outputs (M15), the cheaper
membership proof next to M5's sparse Merkle tree.

The set. It is M5's set (`utxo_set.SharechainUtxo.eligible`, OWNERSHIP.md section 1.4 items 1
to 5): outputs on the chain ending at the anchor, unspent at it, P2TR, at least `min_units`,
with a root height inside the window. M5's item 6, the slot rule that keeps a sparse tree
shallow, is dropped: the tree here is dense, so two outputs never compete for a slot. The set
may hold at most `radix ** levels` outputs (`CapacityExceeded` otherwise); a watcher that
reaches the limit raises `min_units`, the dust floor of the accumulator.

The order. Outputs are sorted by `key`, the outpoint's field id (`smt.outpoint_id`, the
`saleId` of the circuits), strictly ascending. The position of an output is its rank. A
watcher finds the position of an outpoint by binary search, and a published leaf list can be
checked for order and duplicates with one scan.

The hashes, in circomlib's `Poseidon(n)`:

    leaf[i] = Poseidon(key, owner, units, root_height)         four inputs
    node    = Poseidon(child_0, ..., child_{r-1})              r = 2 ** radix_bits inputs
    empty   = leaf 0; nodes above empty leaves hash their children like any other node

Level 0 holds the leaf hashes of positions 0 to `radix ** levels - 1` (positions past the end
are 0). A node's children are consecutive; the digit of a position at level l, in base r, is
the index of the child that holds the path. `circuits/window_sale.circom` checks a path the way
`root_from_path` does: at each level the child at the digit must be the running hash, and the
next running hash is the node over the children.

`radix_bits` 1 is a binary tree (17 levels hold 131,072 outputs, M5's live set is 119,953);
`radix_bits` 3 is a tree of eight-way nodes (6 levels hold 262,144). A wider node hashes more
bits per constraint (`Poseidon(8)` is 402 constraints for 3 bits, `Poseidon(2)` is 240 for one)
and carries more siblings in a proof.

Owners follow `smt.owner_field`: the registered order key hash of the output's address, else
M5's address id.
"""

from __future__ import annotations

import bisect
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import smt  # noqa: E402
import utxo_set  # noqa: E402

FIELD = smt.FIELD

# By radix_bits, the smallest level count whose capacity holds M5's production live set
# (119,953 outputs, OWNERSHIP.md section 3.1).
PRODUCTION_LEVELS = {1: 17, 2: 9, 3: 6, 4: 5}


class WindowTreeError(ValueError):
    pass


class CapacityExceeded(WindowTreeError):
    """More outputs than `radix ** levels`: raise `min_units` or use a deeper circuit."""


class KeysNotAscending(WindowTreeError):
    """Leaves must be sorted by key, strictly: a repeated key is two positions for one output."""


class PathMismatch(WindowTreeError):
    """A path whose children do not hold the running hash at the position's digit."""


class RecordMismatch(PathMismatch):
    """A packed path whose bottom node does not hold (key, owner) at the position's record index."""


def leaf_hash(key: int, owner: int, units: int, root_height: int) -> int:
    """Poseidon(key, owner, units, root_height): the leaf of an output in the window tree."""
    for name, number in (("key", key), ("owner", owner), ("units", units), ("root height", root_height)):
        if type(number) is not int or not 0 <= number < FIELD:
            raise WindowTreeError(f"{name} is not a canonical field element")
    return smt.poseidon_n([key, owner, units, root_height])


EMPTY_LEAF_HASH = 0


@dataclass(frozen=True)
class WindowLeaf:
    key: int
    owner: int
    units: int
    root_height: int

    @property
    def hash(self) -> int:
        return leaf_hash(self.key, self.owner, self.units, self.root_height)


@dataclass(frozen=True)
class WindowPath:
    """What the circuit takes per slot besides the leaf's fields: the position and every level's children.

    `children[l]` are the r children of the node that level l hashes; `children[l][digit_l]` is the
    running hash (the leaf hash at l = 0).
    """

    position: int
    children: tuple[tuple[int, ...], ...]

    def digits(self, radix_bits: int) -> list[int]:
        return digits_of(self.position, radix_bits, len(self.children))

    def siblings(self, radix_bits: int) -> list[list[int]]:
        """The r - 1 children that are not on the path, per level: what a proof carries."""
        out = []
        for digit, group in zip(self.digits(radix_bits), self.children):
            out.append([child for index, child in enumerate(group) if index != digit])
        return out

    def size_bytes(self, radix_bits: int) -> int:
        return 32 * sum(len(level) for level in self.siblings(radix_bits))


def digits_of(position: int, radix_bits: int, levels: int) -> list[int]:
    """Base-r digits of a position, least significant (level 0) first."""
    if not 0 <= position < 1 << (radix_bits * levels):
        raise WindowTreeError(f"position {position} outside {1 << (radix_bits * levels)} leaves")
    mask = (1 << radix_bits) - 1
    return [(position >> (radix_bits * level)) & mask for level in range(levels)]


def root_from_path(leaf: int, path: WindowPath, radix_bits: int) -> int:
    """Fold a leaf hash up its path, mirroring `WindowSale`: select, check, hash, per level."""
    current = leaf
    for level, (digit, group) in enumerate(zip(path.digits(radix_bits), path.children)):
        if len(group) != 1 << radix_bits:
            raise WindowTreeError(f"level {level} has {len(group)} children, expected {1 << radix_bits}")
        if group[digit] != current:
            raise PathMismatch(f"level {level}: the child at digit {digit} is not the running hash")
        current = smt.poseidon_n(group)
    return current


class WindowTree:
    """The dense tree of `leaves` (sorted by key, strictly ascending) with `radix ** levels` positions."""

    def __init__(self, leaves: Sequence[WindowLeaf], radix_bits: int = 1, levels: int | None = None):
        if radix_bits < 1:
            raise WindowTreeError("radix_bits must be at least 1")
        self.radix_bits = radix_bits
        self.radix = 1 << radix_bits
        self.levels = PRODUCTION_LEVELS[radix_bits] if levels is None else levels
        self.capacity = self.radix ** self.levels
        if len(leaves) > self.capacity:
            raise CapacityExceeded(f"{len(leaves)} outputs; {self.radix}^{self.levels} = {self.capacity} positions")
        self.leaves = list(leaves)
        self.keys = [leaf.key for leaf in self.leaves]
        for before, after in zip(self.keys, self.keys[1:]):
            if not before < after:
                raise KeysNotAscending(f"key {after} follows {before}")
        for leaf in self.leaves:
            if type(leaf.key) is not int or not 0 <= leaf.key < FIELD:
                raise WindowTreeError("key is not a canonical field element")
        self._zero = [EMPTY_LEAF_HASH]
        for _ in range(self.levels):
            self._zero.append(smt.poseidon_n([self._zero[-1]] * self.radix))
        self._nodes = [[leaf.hash for leaf in self.leaves]]
        for level in range(1, self.levels + 1):
            below = self._nodes[-1]
            count = -(-len(below) // self.radix)
            padding = self._zero[level - 1]
            self._nodes.append([
                smt.poseidon_n([
                    below[index] if index < len(below) else padding
                    for index in range(group * self.radix, (group + 1) * self.radix)
                ])
                for group in range(count)
            ])

    # -- shape ------------------------------------------------------------
    def __len__(self) -> int:
        return len(self.leaves)

    @property
    def root(self) -> int:
        top = self._nodes[self.levels]
        return top[0] if top else self._zero[self.levels]

    def _node(self, level: int, index: int) -> int:
        row = self._nodes[level]
        return row[index] if index < len(row) else self._zero[level]

    def hash_count(self) -> int:
        """Poseidon evaluations the build took: one per leaf and one per stored node."""
        return sum(len(row) for row in self._nodes)

    # -- reads ------------------------------------------------------------
    def position_of(self, key: int) -> int | None:
        index = bisect.bisect_left(self.keys, key)
        return index if index < len(self.keys) and self.keys[index] == key else None

    def __contains__(self, key: int) -> bool:
        return self.position_of(key) is not None

    def insertion_point(self, key: int) -> int:
        """Where `key` would sort; used to aim a forged witness at a plausible position."""
        return min(bisect.bisect_left(self.keys, key), self.capacity - 1)

    def path(self, position: int) -> WindowPath:
        """The children along the path to `position` (a real leaf or an empty position)."""
        digits_of(position, self.radix_bits, self.levels)
        groups = []
        for level in range(self.levels):
            first = (position >> (self.radix_bits * (level + 1))) << self.radix_bits
            groups.append(tuple(self._node(level, first + child) for child in range(self.radix)))
        return WindowPath(position, tuple(groups))

    def prove(self, key: int) -> tuple[WindowLeaf, WindowPath]:
        position = self.position_of(key)
        if position is None:
            raise WindowTreeError(f"key {key} not in the tree")
        return self.leaves[position], self.path(position)

    def spliced_path(self, position: int, leaf: int) -> WindowPath:
        """The real path at `position` with `leaf` put in place of the stored leaf hash and every
        parent recomputed. It passes every level's selection check, and its root is the tree's
        only when `leaf` is what the tree holds there: the strongest forgery a prover can build."""
        real = self.path(position)
        current = leaf
        groups = []
        for digit, group in zip(real.digits(self.radix_bits), real.children):
            group = list(group)
            group[digit] = current
            groups.append(tuple(group))
            current = smt.poseidon_n(group)
        return WindowPath(position, tuple(groups))

    def verify(self, leaf: WindowLeaf, path: WindowPath) -> bool:
        try:
            return root_from_path(leaf.hash, path, self.radix_bits) == self.root
        except PathMismatch:
            return False


def check_ascending(positions: Sequence[int], active: Sequence[int]) -> bool:
    """The circuit's order rule over a batch: active slots are a prefix, and their positions strictly increase."""
    seen_inactive = False
    previous = -1
    for position, flag in zip(positions, active):
        if not flag:
            seen_inactive = True
            continue
        if seen_inactive or position <= previous:
            return False
        previous = position
    return True


# ---------------------------------------------------------------------------
# From the sharechain


def window_outputs(model: utxo_set.SharechainUtxo, anchor: int) -> list[utxo_set.Output]:
    """The anchor's set in tree order: M5's eligible outputs, sorted by key, with no slot rule."""
    outputs = sorted(model.eligible(anchor), key=lambda output: output.key)
    for before, after in zip(outputs, outputs[1:]):
        if before.key == after.key:
            raise KeysNotAscending(f"outpoints {before.outpoint} and {after.outpoint} share a field id")
    return outputs


def leaf_of(output: utxo_set.Output, registry: Mapping[str, int] | None = None) -> WindowLeaf:
    return WindowLeaf(output.key, smt.owner_field(output.owner, registry), output.units, output.root_height)


def build_window_tree(
    model: utxo_set.SharechainUtxo,
    anchor: int,
    registry: Mapping[str, int] | None = None,
    radix_bits: int = 1,
    levels: int | None = None,
) -> tuple[WindowTree, list[utxo_set.Output]]:
    """The anchor's window tree and its outputs in position order."""
    outputs = window_outputs(model, anchor)
    return WindowTree([leaf_of(output, registry) for output in outputs], radix_bits, levels), outputs


# ---------------------------------------------------------------------------
# The packed layout (ROADMAP item 3, joinedtree/JOINED_TREE.md section 12)


PACKED_GROUP_BITS = 2
PACKED_RADIX_BITS = 3
PACKED_LEVELS = 5


@dataclass(frozen=True)
class PackedLeaf:
    """A record of the packed tree: the outpoint's field id and its owner. Units and root height
    are not stored: no circuit rule reads them, and the builder's set rule decides who is a record."""

    key: int
    owner: int


@dataclass(frozen=True)
class PackedPath:
    """What the circuit takes per slot besides the record: the position, the bottom node's
    `2 * 2**group_bits` fields (key_0, owner_0, key_1, ...) and `levels` groups of `radix` children."""

    position: int
    group: tuple[int, ...]
    children: tuple[tuple[int, ...], ...]

    def digits(self, group_bits: int, radix_bits: int) -> tuple[int, list[int]]:
        """(the record's index in the bottom node, the base-r digits of the upper levels)."""
        return digits_of_packed(self.position, group_bits, radix_bits, len(self.children))

    def size_bytes(self, radix_bits: int) -> int:
        """A proof carries the bottom node's other records and the other children per upper level."""
        records = len(self.group) // 2
        return 32 * (2 * (records - 1) + len(self.children) * ((1 << radix_bits) - 1))


def digits_of_packed(position: int, group_bits: int, radix_bits: int, levels: int) -> tuple[int, list[int]]:
    total = group_bits + radix_bits * levels
    if not 0 <= position < 1 << total:
        raise WindowTreeError(f"position {position} outside {1 << total} records")
    within = position & ((1 << group_bits) - 1)
    rest = position >> group_bits
    mask = (1 << radix_bits) - 1
    return within, [(rest >> (radix_bits * level)) & mask for level in range(levels)]


def packed_root_from_path(key: int, owner: int, path: PackedPath,
                          group_bits: int = PACKED_GROUP_BITS, radix_bits: int = PACKED_RADIX_BITS) -> int:
    """Fold a record up its path, mirroring `PackedWindowSale`: the record at the position's low
    bits must be (key, owner), then select, check and hash per level."""
    for name, number in (("key", key), ("owner", owner)):
        if type(number) is not int or not 0 <= number < FIELD:
            raise WindowTreeError(f"{name} is not a canonical field element")
    records = 1 << group_bits
    if len(path.group) != 2 * records:
        raise WindowTreeError(f"bottom node has {len(path.group)} fields, expected {2 * records}")
    within, digits = path.digits(group_bits, radix_bits)
    if path.group[2 * within] != key or path.group[2 * within + 1] != owner:
        raise RecordMismatch(f"the record at index {within} of the bottom node is not (key, owner)")
    current = smt.poseidon_n(list(path.group))
    for level, (digit, group) in enumerate(zip(digits, path.children), start=1):
        if len(group) != 1 << radix_bits:
            raise WindowTreeError(f"level {level} has {len(group)} children, expected {1 << radix_bits}")
        if group[digit] != current:
            raise PathMismatch(f"level {level}: the child at digit {digit} is not the running hash")
        current = smt.poseidon_n(list(group))
    return current


class PackedWindowTree:
    """The dense tree whose bottom nodes hold `2 ** group_bits` records (key, owner) each, with
    `levels` levels of `2 ** radix_bits`-way nodes above: `2 ** group_bits * radix ** levels` positions.

        bottom[g] = Poseidon(key_0, owner_0, ..., key_{r-1}, owner_{r-1})     r = 2 ** group_bits
        node      = Poseidon(child_0, ..., child_{R-1})                       R = 2 ** radix_bits
        empty     = a record of (0, 0); nodes over empty records hash like any other node

    The order, the sort key and the set are those of `WindowTree`. The interface mirrors
    `WindowTree` (`leaves`, `keys`, `position_of`, `path`, `spliced_path`, `root`, `verify`).
    """

    def __init__(self, leaves: Sequence[PackedLeaf], group_bits: int = PACKED_GROUP_BITS,
                 radix_bits: int = PACKED_RADIX_BITS, levels: int = PACKED_LEVELS):
        if group_bits < 1 or radix_bits < 1 or levels < 1:
            raise WindowTreeError("group_bits, radix_bits and levels must be at least 1")
        self.group_bits = group_bits
        self.radix_bits = radix_bits
        self.levels = levels
        self.records = 1 << group_bits
        self.radix = 1 << radix_bits
        self.capacity = self.records * self.radix ** levels
        if len(leaves) > self.capacity:
            raise CapacityExceeded(f"{len(leaves)} outputs; {self.records} * {self.radix}^{levels} = {self.capacity} positions")
        self.leaves = list(leaves)
        self.keys = [leaf.key for leaf in self.leaves]
        for before, after in zip(self.keys, self.keys[1:]):
            if not before < after:
                raise KeysNotAscending(f"key {after} follows {before}")
        for leaf in self.leaves:
            for number in (leaf.key, leaf.owner):
                if type(number) is not int or not 0 <= number < FIELD:
                    raise WindowTreeError("key or owner is not a canonical field element")
        self._zero = [smt.poseidon_n([0] * (2 * self.records))]
        for _ in range(levels):
            self._zero.append(smt.poseidon_n([self._zero[-1]] * self.radix))
        self._nodes = [[
            smt.poseidon_n(list(self._group(index))) for index in range(-(-len(self.leaves) // self.records))
        ]]
        for level in range(1, levels + 1):
            below = self._nodes[-1]
            padding = self._zero[level - 1]
            self._nodes.append([
                smt.poseidon_n([
                    below[index] if index < len(below) else padding
                    for index in range(group * self.radix, (group + 1) * self.radix)
                ])
                for group in range(-(-len(below) // self.radix))
            ])

    def _group(self, index: int) -> tuple[int, ...]:
        """The fields of bottom node `index`: its records, then (0, 0) for positions past the end."""
        fields: list[int] = []
        for position in range(index * self.records, (index + 1) * self.records):
            if position < len(self.leaves):
                fields += [self.leaves[position].key, self.leaves[position].owner]
            else:
                fields += [0, 0]
        return tuple(fields)

    def __len__(self) -> int:
        return len(self.leaves)

    @property
    def root(self) -> int:
        top = self._nodes[self.levels]
        return top[0] if top else self._zero[self.levels]

    def _node(self, level: int, index: int) -> int:
        row = self._nodes[level]
        return row[index] if index < len(row) else self._zero[level]

    def hash_count(self) -> int:
        """Poseidon evaluations the build took: one per stored node."""
        return sum(len(row) for row in self._nodes)

    def position_of(self, key: int) -> int | None:
        index = bisect.bisect_left(self.keys, key)
        return index if index < len(self.keys) and self.keys[index] == key else None

    def __contains__(self, key: int) -> bool:
        return self.position_of(key) is not None

    def insertion_point(self, key: int) -> int:
        return min(bisect.bisect_left(self.keys, key), self.capacity - 1)

    def path(self, position: int) -> PackedPath:
        """The bottom node and the children along the path to `position` (a record or an empty position)."""
        digits_of_packed(position, self.group_bits, self.radix_bits, self.levels)
        group_index = position >> self.group_bits
        groups = []
        for level in range(self.levels):
            first = (group_index >> (self.radix_bits * (level + 1))) << self.radix_bits
            groups.append(tuple(self._node(level, first + child) for child in range(self.radix)))
        return PackedPath(position, self._group(group_index), tuple(groups))

    def prove(self, key: int) -> tuple[PackedLeaf, PackedPath]:
        position = self.position_of(key)
        if position is None:
            raise WindowTreeError(f"key {key} not in the tree")
        return self.leaves[position], self.path(position)

    def spliced_path(self, position: int, record: tuple[int, int]) -> PackedPath:
        """The real path at `position` with the record (key, owner) put in place of the stored one
        and every parent recomputed: it passes every selection check, and its root is the tree's only
        when the record is what the tree holds there. The strongest forgery a prover can build."""
        real = self.path(position)
        within, digits = real.digits(self.group_bits, self.radix_bits)
        fields = list(real.group)
        fields[2 * within], fields[2 * within + 1] = record
        current = smt.poseidon_n(fields)
        groups = []
        for digit, group in zip(digits, real.children):
            group = list(group)
            group[digit] = current
            groups.append(tuple(group))
            current = smt.poseidon_n(group)
        return PackedPath(position, tuple(fields), tuple(groups))

    def verify(self, leaf: PackedLeaf, path: PackedPath) -> bool:
        try:
            return packed_root_from_path(leaf.key, leaf.owner, path, self.group_bits, self.radix_bits) == self.root
        except PathMismatch:
            return False


def packed_leaf_of(output: utxo_set.Output, registry: Mapping[str, int] | None = None) -> PackedLeaf:
    return PackedLeaf(output.key, smt.owner_field(output.owner, registry))


def build_packed_window_tree(
    model: utxo_set.SharechainUtxo,
    anchor: int,
    registry: Mapping[str, int] | None = None,
    group_bits: int = PACKED_GROUP_BITS,
    radix_bits: int = PACKED_RADIX_BITS,
    levels: int = PACKED_LEVELS,
) -> tuple[PackedWindowTree, list[utxo_set.Output]]:
    """The anchor's packed window tree and its outputs in position order."""
    outputs = window_outputs(model, anchor)
    return PackedWindowTree([packed_leaf_of(output, registry) for output in outputs],
                            group_bits, radix_bits, levels), outputs
