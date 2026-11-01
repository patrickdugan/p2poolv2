"""Poseidon sparse Merkle tree that matches circomlib's SMT, for M5 (sharechain ownership).

Everything here is an offline reference. It builds the accumulator a watcher
would publish and the membership proofs `circuits/owned_sale.circom` consumes.

Hashing follows circomlib's `smt/smthash_poseidon.circom` and circomlibjs's
`smt.js`:

    leaf hash   = Poseidon(key, value, 1)      three inputs (t = 4)
    branch hash = Poseidon(left, right)        two inputs (t = 3)
    empty       = 0

The path of a key is its bits least significant first. A subtree holding one
leaf is that leaf (the compressed form circomlib uses), so the shape is a
function of the key set alone, not of insertion order. A branch with an empty
child still hashes that child as 0.

`max_depth` bounds the depth of a leaf, which is the number of siblings in its
proof. The verifier circuit built for `nLevels` levels handles leaves of depth
up to `nLevels - 1` (SMTLevIns forces the last sibling to be zero), so
`n_levels = max_depth + 1`.

Poseidon constants come from `poseidon_bn254.json`, extracted from the pinned
circomlibjs by `extract_poseidon_constants.js`. `poseidon_reference` follows
circomlibjs's `poseidon_reference.js`; `poseidon2` and `poseidon3` are unrolled
for speed and checked against it in `test_smt.py` and against circomlibjs in
`circomlibjs_vectors.json`. `poseidon_n` hashes the other widths the constants file holds
(4 and 8 inputs, for the dense window tree of `window_tree.py`).
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

_HERE = Path(__file__).resolve().parent
_ZK = _HERE.parent
if str(_ZK) not in sys.path:
    sys.path.insert(0, str(_ZK))

from witness import BN254_FR, field_id  # noqa: E402  (shared identity encoding with the v1 circuit)

FIELD = BN254_FR

# ---------------------------------------------------------------------------
# Poseidon over the BN254 scalar field


def _load_params() -> tuple[int, dict[int, tuple[int, list[int], list[list[int]]]]]:
    data = json.loads((_HERE / "poseidon_bn254.json").read_text())
    if int(data["prime"]) != FIELD:
        raise RuntimeError("poseidon_bn254.json is for a different field")
    params = {
        int(t): (
            int(entry["nRoundsP"]),
            [int(x) for x in entry["C"]],
            [[int(x) for x in row] for row in entry["M"]],
        )
        for t, entry in data["params"].items()
    }
    return int(data["nRoundsF"]), params


_N_ROUNDS_F, _PARAMS = _load_params()

# Counts of Poseidon evaluations, so callers can report hashes per operation. WIDE_HASH_COUNTS
# counts `poseidon_n` calls by number of inputs (the dense window tree, window_tree.py).
HASH_COUNTS = {"poseidon2": 0, "poseidon3": 0}
WIDE_HASH_COUNTS: dict[int, int] = {}


def reset_hash_counts() -> None:
    HASH_COUNTS["poseidon2"] = 0
    HASH_COUNTS["poseidon3"] = 0
    WIDE_HASH_COUNTS.clear()


def poseidon_reference(inputs: list[int]) -> int:
    """Poseidon with 2, 3, 4 or 8 inputs, written as in circomlibjs `poseidon_reference.js`."""
    t = len(inputs) + 1
    if t not in _PARAMS:
        raise ValueError("no constants extracted for this number of inputs")
    n_partial, round_constants, mds = _PARAMS[t]
    state = [0, *inputs]
    half = _N_ROUNDS_F // 2
    for r in range(_N_ROUNDS_F + n_partial):
        state = [(a + round_constants[r * t + i]) % FIELD for i, a in enumerate(state)]
        if r < half or r >= half + n_partial:
            state = [pow(a, 5, FIELD) for a in state]
        else:
            state[0] = pow(state[0], 5, FIELD)
        state = [sum(mds[i][j] * state[j] for j in range(t)) % FIELD for i in range(t)]
    return state[0]


def _build_poseidon2():
    n_partial, c, m = _PARAMS[3]
    (m00, m01, m02), (m10, m11, m12), (m20, m21, m22) = m
    half = _N_ROUNDS_F // 2
    total = _N_ROUNDS_F + n_partial
    p = FIELD

    def poseidon2(a: int, b: int) -> int:
        HASH_COUNTS["poseidon2"] += 1
        s0, s1, s2 = 0, a, b
        for r in range(total):
            k = r * 3
            if r < half or r >= half + n_partial:
                s0 = pow(s0 + c[k], 5, p)
                s1 = pow(s1 + c[k + 1], 5, p)
                s2 = pow(s2 + c[k + 2], 5, p)
            else:
                s0 = pow(s0 + c[k], 5, p)
                s1 += c[k + 1]
                s2 += c[k + 2]
            s0, s1, s2 = (
                (m00 * s0 + m01 * s1 + m02 * s2) % p,
                (m10 * s0 + m11 * s1 + m12 * s2) % p,
                (m20 * s0 + m21 * s1 + m22 * s2) % p,
            )
        return s0

    return poseidon2


def _build_poseidon3():
    n_partial, c, m = _PARAMS[4]
    (m00, m01, m02, m03), (m10, m11, m12, m13), (m20, m21, m22, m23), (m30, m31, m32, m33) = m
    half = _N_ROUNDS_F // 2
    total = _N_ROUNDS_F + n_partial
    p = FIELD

    def poseidon3(a: int, b: int, d: int) -> int:
        HASH_COUNTS["poseidon3"] += 1
        s0, s1, s2, s3 = 0, a, b, d
        for r in range(total):
            k = r * 4
            if r < half or r >= half + n_partial:
                s0 = pow(s0 + c[k], 5, p)
                s1 = pow(s1 + c[k + 1], 5, p)
                s2 = pow(s2 + c[k + 2], 5, p)
                s3 = pow(s3 + c[k + 3], 5, p)
            else:
                s0 = pow(s0 + c[k], 5, p)
                s1 += c[k + 1]
                s2 += c[k + 2]
                s3 += c[k + 3]
            s0, s1, s2, s3 = (
                (m00 * s0 + m01 * s1 + m02 * s2 + m03 * s3) % p,
                (m10 * s0 + m11 * s1 + m12 * s2 + m13 * s3) % p,
                (m20 * s0 + m21 * s1 + m22 * s2 + m23 * s3) % p,
                (m30 * s0 + m31 * s1 + m32 * s2 + m33 * s3) % p,
            )
        return s0

    return poseidon3


poseidon2 = _build_poseidon2()
poseidon3 = _build_poseidon3()


def _build_poseidon_n(n_inputs: int):
    """Poseidon over `n_inputs` values for any width whose constants `poseidon_bn254.json` holds."""
    t = n_inputs + 1
    if t not in _PARAMS:
        raise ValueError(f"no Poseidon constants for {n_inputs} inputs; extract them with extract_poseidon_constants.js")
    n_partial, c, m = _PARAMS[t]
    half = _N_ROUNDS_F // 2
    total = _N_ROUNDS_F + n_partial
    p = FIELD
    rows = [tuple(row) for row in m]
    lanes = range(1, t)

    def poseidon_n(inputs) -> int:
        if len(inputs) != n_inputs:
            raise ValueError(f"this hash takes {n_inputs} inputs, got {len(inputs)}")
        WIDE_HASH_COUNTS[n_inputs] = WIDE_HASH_COUNTS.get(n_inputs, 0) + 1
        state = [0, *inputs]
        for r in range(total):
            k = r * t
            if r < half or r >= half + n_partial:
                state = [pow(state[i] + c[k + i], 5, p) for i in range(t)]
            else:
                state = [pow(state[0] + c[k], 5, p)] + [state[i] + c[k + i] for i in lanes]
            state = [sum(a * b for a, b in zip(row, state)) % p for row in rows]
        return state[0]

    return poseidon_n


_POSEIDON_N: dict[int, object] = {}


def poseidon_n(inputs) -> int:
    """Poseidon of `len(inputs)` values (circomlib's `Poseidon(n)`); 2 and 3 inputs have unrolled fast paths."""
    inputs = list(inputs)
    if len(inputs) == 2:
        return poseidon2(*inputs)
    if len(inputs) == 3:
        return poseidon3(*inputs)
    hasher = _POSEIDON_N.get(len(inputs))
    if hasher is None:
        hasher = _POSEIDON_N[len(inputs)] = _build_poseidon_n(len(inputs))
    return hasher(inputs)


def leaf_hash(key: int, value: int) -> int:
    """circomlib SMTHash1: Poseidon(key, value, 1)."""
    return poseidon3(key, value, 1)


def node_hash(left: int, right: int) -> int:
    """circomlib SMTHash2: Poseidon(left, right)."""
    return poseidon2(left, right)


# ---------------------------------------------------------------------------
# Identities and leaf encoding shared with the v1 circuit


def outpoint_id(txid: str, vout: int) -> int:
    """Field id of a sharechain outpoint, `txid:vout` as P2Poolv2 keys its Outputs column family.

    `txid` is the display form of a bitcoin Txid (byte-reversed hex). The id is
    the same `share_outpoint` identity the v1 circuit commits as `saleId`.
    """
    return field_id("share_outpoint", f"{txid}:{vout}")


def owner_id(share_address: str) -> int:
    """Field id of an owner, by the bech32m share address string (`p2pool1p...`).

    The same `seller_share_address` identity the v1 circuit commits as `sellerId`.
    """
    return field_id("seller_share_address", share_address)


def owner_field(share_address: str, registry: Mapping[str, int] | None = None) -> int:
    """The owner stored in a leaf: the registered order key hash of the address, else `owner_id`.

    `registry` maps a share address to `Poseidon(Ax, Ay)` of the BabyJubjub order key its
    controlling key registered (`register.py`). An address without an entry keeps the address
    id, which no order key hashes to, so its outputs cannot be sold through the signed circuit.
    """
    if registry is not None:
        key_hash = registry.get(share_address)
        if key_hash is not None:
            return key_hash
    return owner_id(share_address)


def leaf_value(owner: int, units: int, root_height: int) -> int:
    """Poseidon(owner id, units, root height): the value stored under an outpoint's key.

    `units` is the output value in satoshis (a share coinbase output is 100,000,000).
    `root_height` is the height of the oldest coinbase in the output's ancestry,
    P2Poolv2's `StoredTxOut::coinbase_root_height`.
    """
    for name, number in (("owner", owner), ("units", units), ("root height", root_height)):
        if not 0 <= number < FIELD:
            raise ValueError(f"{name} outside the field")
    return poseidon3(owner, units, root_height)


_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32M_CONST = 0x2BC830A3
SHARE_HRP = {"mainnet": "p2pool", "testnet4": "tp2pool", "signet": "sp2pool", "regtest": "rp2pool"}


def _bech32_polymod(values: list[int]) -> int:
    generator = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if (top >> i) & 1 else 0
    return chk


def share_address(output_key: bytes, network: str = "mainnet") -> str:
    """Encode a 32-byte taproot output key as a P2Poolv2 share address (docs/architecture/address-format.md)."""
    if len(output_key) != 32:
        raise ValueError("share addresses encode a 32-byte output key")
    hrp = SHARE_HRP[network]
    acc, bits, data = 0, 0, [1]  # witness version 1
    for byte in output_key:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            data.append((acc >> bits) & 31)
    if bits:
        data.append((acc << (5 - bits)) & 31)
    hrp_expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    polymod = _bech32_polymod(hrp_expanded + data + [0] * 6) ^ _BECH32M_CONST
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_BECH32_CHARSET[d] for d in data + checksum)


def decode_share_address(address: str) -> tuple[str, bytes]:
    """Parse a share address into (network, 32-byte taproot output key), refusing anything else.

    The rules of docs/architecture/address-format.md: a P2Poolv2 HRP, a valid bech32m checksum,
    witness version 1 and a 32-byte program with canonical padding. Only the lowercase spelling
    is accepted, so one address has one string.
    """
    if address != address.lower():
        raise ValueError("share addresses are lowercase")
    separator = address.rfind("1")
    hrp, payload = address[:separator], address[separator + 1:]
    network = next((name for name, prefix in SHARE_HRP.items() if prefix == hrp), None)
    if separator < 1 or network is None:
        raise ValueError("not a share address: unknown human readable part")
    if len(payload) < 7 or any(c not in _BECH32_CHARSET for c in payload):
        raise ValueError("invalid bech32 data part")
    data = [_BECH32_CHARSET.index(c) for c in payload]
    hrp_expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    if _bech32_polymod(hrp_expanded + data) != _BECH32M_CONST:
        raise ValueError("bad bech32m checksum")
    witness_version, groups = data[0], data[1:-6]
    if witness_version != 1:
        raise ValueError("share addresses are witness version 1 only")
    acc, bits, program = 0, 0, bytearray()
    for group in groups:
        acc = (acc << 5) | group
        bits += 5
        if bits >= 8:
            bits -= 8
            program.append((acc >> bits) & 0xFF)
        acc &= (1 << bits) - 1
    if bits >= 5 or acc:
        raise ValueError("non-canonical padding")
    if len(program) != 32:
        raise ValueError("share addresses carry a 32-byte output key")
    return network, bytes(program)


# ---------------------------------------------------------------------------
# The tree


class SmtError(ValueError):
    pass


class KeyExists(SmtError):
    pass


class KeyMissing(SmtError):
    pass


class DepthExceeded(SmtError):
    """A leaf would sit deeper than `max_depth`: two keys share their low `max_depth` bits."""


class _Leaf:
    __slots__ = ("key", "value", "hash")

    def __init__(self, key: int, value: int):
        self.key = key
        self.value = value
        self.hash: int | None = None


class _Branch:
    __slots__ = ("left", "right", "hash")

    def __init__(self, left, right):
        self.left = left
        self.right = right
        self.hash: int | None = None


def _node_hash_of(node) -> int:
    """Hash of a node, computed once and cached. Edits clear the cache along their path."""
    if node is None:
        return 0
    cached = node.hash
    if cached is None:
        if node.__class__ is _Leaf:
            cached = poseidon3(node.key, node.value, 1)
        else:
            cached = poseidon2(_node_hash_of(node.left), _node_hash_of(node.right))
        node.hash = cached
    return cached


def _check_field(name: str, number: int) -> None:
    if type(number) is not int or not 0 <= number < FIELD:
        raise SmtError(f"{name} is not a canonical field element")


@dataclass(frozen=True)
class MembershipProof:
    key: int
    value: int
    siblings: tuple[int, ...]  # one per level from the root, length = leaf depth

    @property
    def depth(self) -> int:
        return len(self.siblings)

    def size_bytes(self, compressed: bool = False) -> int:
        """Serialized size: full is 32 bytes per sibling; compressed drops zero siblings for a bitmap."""
        if not compressed:
            return 32 * self.depth
        return 1 + (self.depth + 7) // 8 + 32 * sum(1 for s in self.siblings if s)


@dataclass(frozen=True)
class ExclusionProof:
    key: int
    siblings: tuple[int, ...]
    old_key: int  # the leaf found at the end of the path, if any
    old_value: int
    is_old0: bool  # True when the path ends in an empty slot


class SparseMerkleTree:
    def __init__(self, max_depth: int | None = None):
        self.max_depth = max_depth
        self._root = None
        self._size = 0

    # -- shape ------------------------------------------------------------
    @property
    def n_levels(self) -> int:
        if self.max_depth is None:
            raise SmtError("no depth bound set")
        return self.max_depth + 1

    def __len__(self) -> int:
        return self._size

    @property
    def root(self) -> int:
        return _node_hash_of(self._root)

    # -- edits ------------------------------------------------------------
    def insert(self, key: int, value: int) -> None:
        _check_field("key", key)
        _check_field("value", value)
        self._root = self._insert(self._root, key, value, 0)
        self._size += 1

    def _insert(self, node, key: int, value: int, level: int):
        if node is None:
            return _Leaf(key, value)
        if node.__class__ is _Leaf:
            if node.key == key:
                raise KeyExists(f"key {key} already present")
            return self._split(node, _Leaf(key, value), level)
        if (key >> level) & 1:
            node.right = self._insert(node.right, key, value, level + 1)
        else:
            node.left = self._insert(node.left, key, value, level + 1)
        node.hash = None
        return node

    def _split(self, existing: _Leaf, new: _Leaf, level: int):
        # Both leaves share the path above `level`. A branch here puts them at depth level + 1.
        if self.max_depth is not None and level + 1 > self.max_depth:
            raise DepthExceeded(f"keys share their low {level} bits; max depth is {self.max_depth}")
        bit_existing = (existing.key >> level) & 1
        bit_new = (new.key >> level) & 1
        if bit_existing != bit_new:
            return _Branch(new, existing) if bit_existing else _Branch(existing, new)
        child = self._split(existing, new, level + 1)
        return _Branch(None, child) if bit_existing else _Branch(child, None)

    def delete(self, key: int) -> None:
        _check_field("key", key)
        self._root = self._delete(self._root, key, 0)
        self._size -= 1

    def _delete(self, node, key: int, level: int):
        if node is None:
            raise KeyMissing(f"key {key} not present")
        if node.__class__ is _Leaf:
            if node.key != key:
                raise KeyMissing(f"key {key} not present")
            return None
        if (key >> level) & 1:
            node.right = self._delete(node.right, key, level + 1)
        else:
            node.left = self._delete(node.left, key, level + 1)
        node.hash = None
        left, right = node.left, node.right
        # A subtree left holding one leaf is that leaf.
        if left is None and right.__class__ is _Leaf:
            return right
        if right is None and left.__class__ is _Leaf:
            return left
        return node

    def update(self, key: int, value: int) -> None:
        _check_field("value", value)
        node = self._find_leaf(key)
        if node is None:
            raise KeyMissing(f"key {key} not present")
        node_path = self._path_nodes(key)
        node.value = value
        node.hash = None
        for branch in node_path:
            branch.hash = None

    def _path_nodes(self, key: int) -> list[_Branch]:
        path, node, level = [], self._root, 0
        while node.__class__ is _Branch:
            path.append(node)
            node = node.right if (key >> level) & 1 else node.left
            level += 1
        return path

    # -- reads ------------------------------------------------------------
    def _find_leaf(self, key: int) -> _Leaf | None:
        node, level = self._root, 0
        while node.__class__ is _Branch:
            node = node.right if (key >> level) & 1 else node.left
            level += 1
        if node is not None and node.key == key:
            return node
        return None

    def get(self, key: int) -> int | None:
        leaf = self._find_leaf(key)
        return None if leaf is None else leaf.value

    def __contains__(self, key: int) -> bool:
        return self._find_leaf(key) is not None

    def items(self):
        stack = [self._root]
        while stack:
            node = stack.pop()
            if node is None:
                continue
            if node.__class__ is _Leaf:
                yield node.key, node.value
            else:
                stack.append(node.right)
                stack.append(node.left)

    def prove(self, key: int) -> MembershipProof:
        siblings: list[int] = []
        node, level = self._root, 0
        while node.__class__ is _Branch:
            if (key >> level) & 1:
                siblings.append(_node_hash_of(node.left))
                node = node.right
            else:
                siblings.append(_node_hash_of(node.right))
                node = node.left
            level += 1
        if node is None or node.key != key:
            raise KeyMissing(f"key {key} not present")
        return MembershipProof(key, node.value, tuple(siblings))

    def prove_absent(self, key: int) -> ExclusionProof:
        """The proof circomlib's `find` returns for a key that is not in the tree."""
        siblings: list[int] = []
        node, level = self._root, 0
        while node.__class__ is _Branch:
            if (key >> level) & 1:
                siblings.append(_node_hash_of(node.left))
                node = node.right
            else:
                siblings.append(_node_hash_of(node.right))
                node = node.left
            level += 1
        if node is None:
            return ExclusionProof(key, tuple(siblings), key, 0, True)
        if node.key == key:
            raise SmtError(f"key {key} is present")
        return ExclusionProof(key, tuple(siblings), node.key, node.value, False)

    def leaf_depths(self) -> list[int]:
        depths, stack = [], [(self._root, 0)]
        while stack:
            node, depth = stack.pop()
            if node is None:
                continue
            if node.__class__ is _Leaf:
                depths.append(depth)
            else:
                stack.append((node.left, depth + 1))
                stack.append((node.right, depth + 1))
        return depths

    # -- bulk build -------------------------------------------------------
    @classmethod
    def from_items(cls, items, max_depth: int | None = None) -> SparseMerkleTree:
        tree = cls(max_depth)
        leaves = []
        seen = set()
        for key, value in items:
            _check_field("key", key)
            _check_field("value", value)
            if key in seen:
                raise KeyExists(f"key {key} listed twice")
            seen.add(key)
            leaves.append(_Leaf(key, value))
        tree._root = tree._build(leaves, 0)
        tree._size = len(leaves)
        return tree

    def _build(self, leaves: list[_Leaf], level: int):
        if not leaves:
            return None
        if len(leaves) == 1:
            return leaves[0]
        if self.max_depth is not None and level + 1 > self.max_depth:
            raise DepthExceeded(f"{len(leaves)} keys share their low {level} bits; max depth is {self.max_depth}")
        zeros = [leaf for leaf in leaves if not (leaf.key >> level) & 1]
        ones = [leaf for leaf in leaves if (leaf.key >> level) & 1]
        return _Branch(self._build(zeros, level + 1), self._build(ones, level + 1))


# ---------------------------------------------------------------------------
# Verification, written to mirror circomlib's SMTVerifier for fnc = 0 and 1


def root_from_proof(key: int, value: int, siblings: tuple[int, ...] | list[int]) -> int:
    """Fold a leaf up its siblings. Trailing zero siblings are padding and carry no level."""
    siblings = list(siblings)
    while siblings and siblings[-1] == 0:
        siblings.pop()
    node = leaf_hash(key, value)
    for level in range(len(siblings) - 1, -1, -1):
        if (key >> level) & 1:
            node = node_hash(siblings[level], node)
        else:
            node = node_hash(node, siblings[level])
    return node


def verify_membership(root: int, proof: MembershipProof) -> bool:
    return root_from_proof(proof.key, proof.value, proof.siblings) == root


def verify_absence(root: int, proof: ExclusionProof) -> bool:
    siblings = list(proof.siblings)
    if proof.is_old0:
        node = 0
        # An empty slot hangs under its last sibling; the zero leaf hash is 0.
        for level in range(len(siblings) - 1, -1, -1):
            if (proof.key >> level) & 1:
                node = node_hash(siblings[level], node)
            else:
                node = node_hash(node, siblings[level])
        return node == root
    if proof.old_key == proof.key:
        return False
    # The leaf at the end of the path must lie on the path of `key`.
    for level in range(len(siblings)):
        if ((proof.old_key ^ proof.key) >> level) & 1:
            return False
    return root_from_proof(proof.old_key, proof.old_value, siblings) == root


def pad_siblings(siblings: tuple[int, ...] | list[int], n_levels: int) -> list[int]:
    """Pad a proof's siblings with zeros to the circuit's `nLevels`; the last entry must be zero."""
    if len(siblings) > n_levels - 1:
        raise DepthExceeded(f"proof has {len(siblings)} siblings; a {n_levels}-level circuit holds {n_levels - 1}")
    return list(siblings) + [0] * (n_levels - len(siblings))
