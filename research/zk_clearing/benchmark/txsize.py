"""Exact segwit transaction sizes from serialization rules (BIP141/BIP341).

These are computed, not mined: each function adds up the bytes a transaction
of that shape serializes to. ECDSA signatures are counted at 72 bytes (the
DER maximum with sighash byte), Schnorr at 64 (SIGHASH_DEFAULT).
"""

from __future__ import annotations

from dataclasses import dataclass
import math

ECDSA_SIG = 72
SCHNORR_SIG = 64
PUBKEY = 33
XONLY = 32


def varint(n: int) -> int:
    return 1 if n < 0xFD else 3 if n <= 0xFFFF else 5


def push(n: int) -> int:
    """Bytes to push n bytes of data (minimal push)."""
    return n + (1 if n <= 75 else 2 if n <= 255 else 3)


def script_number(value: int) -> int:
    """Bytes to push a small script integer (OP_1..OP_16 or a minimal number push)."""
    if 0 <= value <= 16:
        return 1
    size = 0
    v = abs(value)
    while v:
        size += 1
        v >>= 8
    if abs(value) >> (8 * size - 1):
        size += 1
    return push(size)


def witness(items: list[int]) -> int:
    return varint(len(items)) + sum(varint(n) + n for n in items)


@dataclass(frozen=True)
class Input:
    witness_bytes: int  # serialized witness stack for this input (0 for none)


@dataclass(frozen=True)
class Output:
    script_bytes: int

    @property
    def size(self) -> int:
        return 8 + varint(self.script_bytes) + self.script_bytes


P2WPKH_OUT = Output(22)
P2WSH_OUT = Output(34)
P2TR_OUT = Output(34)
P2WPKH_IN = Input(witness([ECDSA_SIG, PUBKEY]))
P2TR_KEY_IN = Input(witness([SCHNORR_SIG]))


def weight(inputs: list[Input], outputs: list[Output]) -> int:
    base = 4 + varint(len(inputs)) + 41 * len(inputs) + varint(len(outputs)) + sum(o.size for o in outputs) + 4
    wit = 2 + sum(i.witness_bytes if i.witness_bytes else 1 for i in inputs)
    return 4 * base + wit


def vbytes(inputs: list[Input], outputs: list[Output]) -> int:
    return math.ceil(weight(inputs, outputs) / 4)


def htlc_p2wsh_script(wait_blocks: int) -> int:
    """docs/atomic-swap/htlc_scripts.md, P2WSH with public keys and three paths."""
    return (
        1 + 1 + push(32) + 1 + push(PUBKEY) + 1  # IF SHA256 <h> EQUALVERIFY <redeemer> CHECKSIG
        + 1 + 1 + 1 + push(PUBKEY) + push(PUBKEY) + 1 + 1  # ELSE IF 2 <i> <r> 2 CHECKMULTISIG
        + 1 + script_number(wait_blocks) + 1 + 1 + push(PUBKEY) + 1  # ELSE <t> CSV DROP <i> CHECKSIG
        + 1 + 1  # ENDIF ENDIF
    )


def htlc_p2wsh_claim_input(wait_blocks: int) -> Input:
    """Redeemer's success path: <sig> <preimage> 1 <script>."""
    return Input(witness([ECDSA_SIG, 32, 1, htlc_p2wsh_script(wait_blocks)]))


HTLC_P2TR_CLAIM_LEAF = 1 + push(32) + 1 + push(XONLY) + 1  # SHA256 <h> EQUALVERIFY <r> CHECKSIG


def htlc_p2tr_claim_input() -> Input:
    """docs/atomic-swap/htlc_scripts.md taproot tree: happy path at depth 1."""
    control = 33 + 32 * 1
    return Input(witness([SCHNORR_SIG, 32, HTLC_P2TR_CLAIM_LEAF, control]))


def p2tr_committee_leaf_input(tree_depth: int) -> Input:
    """Script path through `<committee> CHECKSIG` at the given tree depth."""
    leaf = push(XONLY) + 1
    return Input(witness([SCHNORR_SIG, leaf, 33 + 32 * tree_depth]))
