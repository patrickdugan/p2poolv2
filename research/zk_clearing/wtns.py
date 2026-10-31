"""Read and write snarkjs/circom `.wtns` witness files.

Used to forge witnesses that bypass the Circom witness calculator, so the
R1CS and the Groth16 verifier are tested directly rather than the
calculator's own asserts.

Format (iden3 binfile): magic b"wtns", u32 version, u32 section count, then
sections of (u32 type, u64 size, payload). Section 1 holds u32 n8, the prime
as n8 little-endian bytes and u32 witness count. Section 2 holds the witness
values, n8 little-endian bytes each.
"""

from __future__ import annotations

import struct
import sys
from dataclasses import dataclass


@dataclass
class Witness:
    prime: int
    values: list[int]
    version: int = 2


def read_wtns(path: str) -> Witness:
    with open(path, "rb") as handle:
        data = handle.read()
    if data[:4] != b"wtns":
        raise ValueError(f"{path}: not a wtns file")
    version, section_count = struct.unpack_from("<II", data, 4)
    offset = 12
    sections: dict[int, bytes] = {}
    for _ in range(section_count):
        section_type, size = struct.unpack_from("<IQ", data, offset)
        offset += 12
        sections[section_type] = data[offset : offset + size]
        offset += size
    header = sections[1]
    (n8,) = struct.unpack_from("<I", header, 0)
    prime = int.from_bytes(header[4 : 4 + n8], "little")
    (count,) = struct.unpack_from("<I", header, 4 + n8)
    body = sections[2]
    if len(body) != count * n8:
        raise ValueError(f"{path}: witness section has {len(body)} bytes, expected {count * n8}")
    values = [int.from_bytes(body[i * n8 : (i + 1) * n8], "little") for i in range(count)]
    return Witness(prime=prime, values=values, version=version)


def write_wtns(path: str, witness: Witness) -> None:
    n8 = 32
    header = struct.pack("<I", n8) + witness.prime.to_bytes(n8, "little")
    header += struct.pack("<I", len(witness.values))
    body = b"".join((value % witness.prime).to_bytes(n8, "little") for value in witness.values)
    with open(path, "wb") as handle:
        handle.write(b"wtns" + struct.pack("<II", witness.version, 2))
        handle.write(struct.pack("<IQ", 1, len(header)) + header)
        handle.write(struct.pack("<IQ", 2, len(body)) + body)


def forge(source: str, destination: str, index: int, delta: int) -> None:
    """Copy a witness, adding `delta` to wire `index` (wire 0 is the constant 1)."""
    witness = read_wtns(source)
    witness.values[index] = (witness.values[index] + delta) % witness.prime
    write_wtns(destination, witness)


if __name__ == "__main__":
    # Usage: python3 wtns.py forge <in.wtns> <out.wtns> <wire index> <delta>
    if len(sys.argv) != 6 or sys.argv[1] != "forge":
        sys.exit("usage: wtns.py forge <in.wtns> <out.wtns> <wire index> <delta>")
    forge(sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5]))
