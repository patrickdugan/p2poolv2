"""Registration of order keys to share addresses, for the joined statement (M10).

M4's circuit checks a seller's order with a BabyJubjub key, and sets the order's `sellerId` to
`Poseidon(Ax, Ay)` of that key. M5's tree stores an owner per sharechain output. To make the two
meet, the key controlling an output's share address registers the order key's hash, and the tree
stores that hash as the owner of the address's outputs (`utxo_set.py`, `registry=`).

A share address is a P2TR output key (`smt.share_address`), so the key that controls it can sign
BIP340 Schnorr signatures, verified here against the 32-byte x-only key the address encodes. The
registration signs this message:

    message  = tagged_hash(DOMAIN_TAG, preimage)         BIP340 tagged hash, 32 bytes
    preimage = len(network) || network || len(address) || address
               || key_hash (32 bytes, big-endian) || sequence (8 bytes, big-endian)

with the lengths as one byte, `network` and `address` in ASCII, `key_hash` = `Poseidon(Ax, Ay)`
as a field element and `sequence` an unsigned 64-bit integer. The network and the address are
both in the message, so a registration made for one network is not valid on another, even for
the same output key. For one address the registration with the highest sequence wins, which
is how a key is rotated; a replay of an older registration changes nothing.

`sign_registration` takes the secret key whose public key is the address's output key. For a
key-path P2TR output that is the tweaked key that signs spends. Outputs that cannot be spent by
key path (a script-only taproot output) have no such key and cannot register.

The BIP340 functions follow the BIP's `reference.py` and are checked against its test vectors in
`test_register.py`. They are for tests and for watchers that verify public registrations; they
are not constant-time and must not be used to sign with a real key.
"""

from __future__ import annotations

import hashlib
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

sys.path.insert(0, str(Path(__file__).resolve().parent))

import smt  # noqa: E402

DOMAIN_TAG = "p2poolv2/zk-clearing/order-key-registration/v1"
MAX_SEQUENCE = (1 << 64) - 1

# ---------------------------------------------------------------------------
# BIP340 over secp256k1 (reference.py of bip-0340)

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

Point = tuple[int, int]


def tagged_hash(tag: str, message: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + message).digest()


def _point_add(a: Point | None, b: Point | None) -> Point | None:
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and a[1] != b[1]:
        return None
    if a == b:
        slope = (3 * a[0] * a[0] * pow(2 * a[1], -1, P)) % P
    else:
        slope = ((b[1] - a[1]) * pow(b[0] - a[0], -1, P)) % P
    x = (slope * slope - a[0] - b[0]) % P
    return (x, (slope * (a[0] - x) - a[1]) % P)


def _point_mul(point: Point | None, scalar: int) -> Point | None:
    result = None
    for bit in range(256):
        if (scalar >> bit) & 1:
            result = _point_add(result, point)
        point = _point_add(point, point)
    return result


def _has_even_y(point: Point) -> bool:
    return point[1] % 2 == 0


def _lift_x(x: int) -> Point | None:
    if x >= P:
        return None
    y_squared = (pow(x, 3, P) + 7) % P
    y = pow(y_squared, (P + 1) // 4, P)
    if pow(y, 2, P) != y_squared:
        return None
    return (x, y if y % 2 == 0 else P - y)


def _x_bytes(point: Point) -> bytes:
    return point[0].to_bytes(32, "big")


def pubkey_gen(secret_key: bytes) -> bytes:
    """The 32-byte x-only public key of a 32-byte secret key."""
    d0 = int.from_bytes(secret_key, "big")
    if not 1 <= d0 <= N - 1:
        raise ValueError("secret key out of range")
    return _x_bytes(_point_mul(G, d0))


def schnorr_sign(message: bytes, secret_key: bytes, aux_rand: bytes) -> bytes:
    if len(secret_key) != 32 or len(aux_rand) != 32:
        raise ValueError("secret key and aux_rand are 32 bytes")
    d0 = int.from_bytes(secret_key, "big")
    if not 1 <= d0 <= N - 1:
        raise ValueError("secret key out of range")
    public = _point_mul(G, d0)
    d = d0 if _has_even_y(public) else N - d0
    t = (d ^ int.from_bytes(tagged_hash("BIP0340/aux", aux_rand), "big")).to_bytes(32, "big")
    k0 = int.from_bytes(tagged_hash("BIP0340/nonce", t + _x_bytes(public) + message), "big") % N
    if k0 == 0:
        raise ValueError("nonce is zero; retry with other aux_rand")
    nonce_point = _point_mul(G, k0)
    k = k0 if _has_even_y(nonce_point) else N - k0
    e = int.from_bytes(tagged_hash("BIP0340/challenge", _x_bytes(nonce_point) + _x_bytes(public) + message), "big") % N
    signature = _x_bytes(nonce_point) + ((k + e * d) % N).to_bytes(32, "big")
    if not schnorr_verify(message, _x_bytes(public), signature):
        raise ValueError("a fresh signature failed its own check")
    return signature


def schnorr_verify(message: bytes, public_key: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    public = _lift_x(int.from_bytes(public_key, "big"))
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if public is None or r >= P or s >= N:
        return False
    e = int.from_bytes(tagged_hash("BIP0340/challenge", signature[:32] + public_key + message), "big") % N
    nonce_point = _point_add(_point_mul(G, s), _point_mul(public, N - e))
    return nonce_point is not None and _has_even_y(nonce_point) and nonce_point[0] == r


# ---------------------------------------------------------------------------
# Registrations


class RegistrationError(ValueError):
    """A registration that must not enter a registry."""


@dataclass(frozen=True)
class Registration:
    network: str  # smt.SHARE_HRP key: mainnet, testnet4, signet or regtest
    address: str  # the share address whose output key signed
    key_hash: int  # Poseidon(Ax, Ay) of the BabyJubjub order key, a nonzero field element
    sequence: int  # the highest valid sequence for an address wins
    signature: bytes  # 64-byte BIP340 signature

    def message(self) -> bytes:
        return registration_message(self.network, self.address, self.key_hash, self.sequence)

    def to_json(self) -> dict:
        return {
            "network": self.network,
            "address": self.address,
            "orderKeyHash": self.key_hash.to_bytes(32, "big").hex(),
            "sequence": self.sequence,
            "signature": self.signature.hex(),
        }

    @classmethod
    def from_json(cls, data: dict) -> Registration:
        try:
            key_hash_hex, signature_hex = data["orderKeyHash"], data["signature"]
            if len(key_hash_hex) != 64 or len(signature_hex) != 128:
                raise ValueError("orderKeyHash is 64 hex characters and signature 128")
            return cls(
                network=data["network"],
                address=data["address"],
                key_hash=int(key_hash_hex, 16),
                sequence=int(data["sequence"]),
                signature=bytes.fromhex(signature_hex),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise RegistrationError(f"malformed registration: {error}") from error


def registration_message(network: str, address: str, key_hash: int, sequence: int) -> bytes:
    """The 32-byte BIP340 message of a registration (see the module docstring)."""
    network_bytes, address_bytes = network.encode("ascii"), address.encode("ascii")
    if not 0 < key_hash < smt.FIELD:
        raise RegistrationError("order key hash is not a nonzero field element")
    if not 0 <= sequence <= MAX_SEQUENCE:
        raise RegistrationError("sequence is not an unsigned 64-bit integer")
    preimage = (
        bytes([len(network_bytes)]) + network_bytes
        + bytes([len(address_bytes)]) + address_bytes
        + key_hash.to_bytes(32, "big")
        + sequence.to_bytes(8, "big")
    )
    return tagged_hash(DOMAIN_TAG, preimage)


def check_registration(registration: Registration) -> None:
    """Raise RegistrationError unless the registration is well formed and correctly signed."""
    if registration.network not in smt.SHARE_HRP:
        raise RegistrationError(f"unknown network {registration.network!r}")
    try:
        address_network, output_key = smt.decode_share_address(registration.address)
    except ValueError as error:
        raise RegistrationError(f"bad share address: {error}") from error
    if address_network != registration.network:
        raise RegistrationError(f"address is for {address_network}, registration says {registration.network}")
    if not isinstance(registration.signature, bytes) or len(registration.signature) != 64:
        raise RegistrationError("signature is not 64 bytes")
    message = registration.message()  # also range-checks the key hash and the sequence
    if not schnorr_verify(message, output_key, registration.signature):
        raise RegistrationError("signature does not verify under the address's output key")


def verify_registration(registration: Registration) -> bool:
    try:
        check_registration(registration)
    except RegistrationError:
        return False
    return True


def sign_registration(
    secret_key: bytes, network: str, key_hash: int, sequence: int, aux_rand: bytes | None = None
) -> Registration:
    """Sign a registration with the secret key of the share address it names.

    The address is the one that encodes the secret key's x-only public key on `network`.
    """
    address = smt.share_address(pubkey_gen(secret_key), network)
    message = registration_message(network, address, key_hash, sequence)
    signature = schnorr_sign(message, secret_key, os.urandom(32) if aux_rand is None else aux_rand)
    return Registration(network, address, key_hash, sequence, signature)


# ---------------------------------------------------------------------------
# The registry a watcher builds from the registrations it has seen


class Registry:
    """The winning registration per address on one network.

    For an address the highest sequence wins. Two different key hashes at the same highest
    sequence are ambiguous, and only the address's own key can make that: the address then has
    no registered key until a higher sequence arrives. The result does not depend on the order
    in which registrations are added.
    """

    def __init__(self, network: str):
        if network not in smt.SHARE_HRP:
            raise ValueError(f"unknown network {network!r}")
        self.network = network
        self._winner: dict[str, Registration] = {}
        self._ambiguous: set[str] = set()

    def add(self, registration: Registration) -> bool:
        """Verify and record a registration. True when it became the address's registered key.

        Raises RegistrationError for a registration that is invalid or for another network.
        """
        if registration.network != self.network:
            raise RegistrationError(f"registration is for {registration.network}, registry is {self.network}")
        check_registration(registration)
        held = self._winner.get(registration.address)
        if held is None or registration.sequence > held.sequence:
            self._winner[registration.address] = registration
            self._ambiguous.discard(registration.address)
            return True
        if registration.sequence == held.sequence and registration.key_hash != held.key_hash:
            self._ambiguous.add(registration.address)
        return False

    def ingest(self, registrations: Iterable[Registration]) -> list[tuple[Registration, str]]:
        """Add every registration, returning the invalid ones with the reason instead of raising."""
        rejected = []
        for registration in registrations:
            try:
                self.add(registration)
            except RegistrationError as error:
                rejected.append((registration, str(error)))
        return rejected

    def key_hash(self, address: str) -> int | None:
        if address in self._ambiguous:
            return None
        winner = self._winner.get(address)
        return None if winner is None else winner.key_hash

    def owners(self) -> dict[str, int]:
        """Share address to registered order key hash: what `utxo_set` takes as `registry`."""
        return {a: r.key_hash for a, r in sorted(self._winner.items()) if a not in self._ambiguous}

    def registrations(self) -> list[Registration]:
        return [r for a, r in sorted(self._winner.items()) if a not in self._ambiguous]

    def sequence(self, address: str) -> int | None:
        winner = self._winner.get(address)
        return None if winner is None else winner.sequence

    def __len__(self) -> int:
        return len(self.owners())

    def to_json(self) -> dict:
        return {"network": self.network, "registrations": [r.to_json() for r in self.registrations()]}

    @classmethod
    def from_json(cls, data: dict) -> Registry:
        registry = cls(data["network"])
        for entry in data["registrations"]:
            registry.add(Registration.from_json(entry))
        return registry
