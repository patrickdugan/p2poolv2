"""The world and the batches behind the joined fixtures (M10): registry, sharechain, trees, specs.

    python3 make_joined.py labels                              > labels.json
    python3 make_joined.py build <key hashes.json> <out dir>

`labels` prints the BabyJubjub order-key labels the world needs. `sign_joined.js keyhashes`
turns them into `{label: Poseidon(Ax, Ay)}`, and `build` then writes, under <out dir>:

    world.json                  addresses, registered key hashes, roots, named outputs, variants
    registrations.json          every registration, as a feed would carry them (stale ones too)
    variants/manifest.json      each variant: name, kind, tree, what it must do
    variants/<name>.spec.json   an M4 batch spec (signed/make_batch.py format)
    variants/<name>.own.json    the ownership witness: utxoRoot, units, rootHeight, siblings

`sign_joined.js sign` signs the specs and joins each with its ownership witness into the inputs of
`clearing16x4_owned.circom`.

The world is a short synthetic sharechain with the sim depths of `ownership/real_store.py`
(maturity 20, payout depth 100, expiry margin 4). Ten miners take the coinbases in turn. At height
150 Dave's mature coinbase output is spent into an output paid to Carol, so one sold output was
transferred and one output is spent before the anchor. Alice rotates her order key after her first
registration. Eve registers too but sells nothing in the valid batches; Zed owns outputs and never
registers; Mallory is an order key with no share address.

Every secret here is a demo key derived from a public label.
"""

from __future__ import annotations

import functools
import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
ZK = HERE.parent
for directory in (ZK, ZK / "ownership", ZK / "signed"):
    sys.path.insert(0, str(directory))

import gen_inputs  # noqa: E402
import register  # noqa: E402
import smt  # noqa: E402
import utxo_set  # noqa: E402
from make_batch import batch_spec  # noqa: E402
from model import Sale  # noqa: E402
from witness import SALE_SLOTS  # noqa: E402

NETWORK = "signet"
N_LEVELS = gen_inputs.N_LEVELS
PARAMS = utxo_set.ChainParams(coinbase_maturity=20, payout_depth=100, expiry_margin=4, max_depth=gen_inputs.MAX_DEPTH)
TIP = 200
TRANSFER_HEIGHT = 150
MINERS = ("alice", "bob", "carol", "dave", "eve", "zed", "miner6", "miner7", "miner8", "miner9")
REGISTERED = ("alice", "bob", "carol", "dave", "eve")  # zed and the numbered miners never register
MALLORY_LABEL = "mallory-order-key"
DOMAIN = "p2poolv2 zk_clearing joined demo"


def bip340_secret(name: str) -> bytes:
    number = int.from_bytes(hashlib.sha256(f"{DOMAIN}/bip340/{name}".encode()).digest(), "big")
    return (number % (register.N - 1) + 1).to_bytes(32, "big")


@functools.cache
def address_of(name: str) -> str:
    return smt.share_address(register.pubkey_gen(bip340_secret(name)), NETWORK)


def order_label(name: str, generation: int = 1) -> str:
    """The label sign.js derives a seller's BabyJubjub order key from: the share address (+ '#2' after a rotation)."""
    return address_of(name) if generation == 1 else f"{address_of(name)}#{generation}"


def labels() -> list[str]:
    names = [order_label(name) for name in (*REGISTERED, "zed")]
    return names + [order_label("alice", 2), MALLORY_LABEL]


def coinbase_txid(height: int) -> str:
    return hashlib.sha256(f"{DOMAIN}/coinbase/{height}".encode()).hexdigest()


TRANSFER_TXID = hashlib.sha256(f"{DOMAIN}/transfer/{TRANSFER_HEIGHT}".encode()).hexdigest()


def replay_chain(registry: dict[str, int]) -> utxo_set.Accumulator:
    accumulator = utxo_set.Accumulator(PARAMS, registry)
    miner_at = {height: MINERS[height % len(MINERS)] for height in range(TIP + 1)}
    # Dave's first in-window coinbase is spent into an output paid to Carol.
    spent_height = next(h for h in range(PARAMS.window(TIP)[0], TIP) if miner_at[h] == "dave")
    for height in range(TIP + 1):
        txs = [utxo_set.share_coinbase(coinbase_txid(height), address_of(miner_at[height]))]
        if height == TRANSFER_HEIGHT:
            txs.append(utxo_set.Tx(
                TRANSFER_TXID, inputs=((coinbase_txid(spent_height), 0),),
                outputs=((address_of("carol"), utxo_set.SHARE_UNITS),),
            ))
        accumulator.apply_block(height, txs)
    return accumulator


@dataclass
class Variant:
    name: str
    kind: str  # valid | resplit | valid_extra | invalid
    tree: str  # "T1" (the registry with Alice's first key) or "T2" (Alice rotated)
    spec: dict
    note: str
    expect: str  # accept | reject
    post: list = field(default_factory=list)  # operations sign_joined.js applies after signing


@dataclass
class World:
    key_hashes: dict
    registrations: list
    registry1: register.Registry
    registry2: register.Registry
    model: utxo_set.SharechainUtxo
    tree1: smt.SparseMerkleTree
    tree2: smt.SparseMerkleTree
    outputs: dict  # name -> utxo_set.Output
    by_key: dict  # outpoint id -> utxo_set.Output
    sales: dict  # "valid" | "resplit" -> tuple[Sale]


def build_world(key_hashes: dict) -> World:
    secrets = {name: bip340_secret(name) for name in REGISTERED}

    def registration(name: str, generation: int) -> register.Registration:
        aux = hashlib.sha256(f"{DOMAIN}/aux/{name}/{generation}".encode()).digest()
        return register.sign_registration(
            secrets[name], NETWORK, int(key_hashes[order_label(name, generation)]), generation, aux
        )

    first = [registration(name, 1) for name in REGISTERED]
    second = registration("alice", 2)
    registrations = first + [second]

    registry1, registry2 = register.Registry(NETWORK), register.Registry(NETWORK)
    assert not registry1.ingest(first)
    # The feed delivers Alice's rotation, then a replay of her first registration.
    assert not registry2.ingest([second, *first])
    assert registry1.key_hash(address_of("alice")) == int(key_hashes[order_label("alice")])
    assert registry2.key_hash(address_of("alice")) == int(key_hashes[order_label("alice", 2)])

    acc1 = replay_chain(registry1.owners())
    acc2 = replay_chain(registry1.owners())
    acc2.set_owner_key(address_of("alice"), registry2.owners()[address_of("alice")])
    model = acc1.model
    tree1 = model.build_tree(TIP, registry1.owners())
    tree2 = model.build_tree(TIP, registry2.owners())
    # The incremental accumulators and the pure snapshots must agree, rotation included.
    assert acc1.root == tree1.root and acc2.root == tree2.root and tree1.root != tree2.root

    lower, upper = PARAMS.window(TIP)
    coinbases = {
        name: sorted(
            (o for o in model.outputs.values()
             if o.is_coinbase and o.owner == address_of(name) and lower <= o.root_height <= upper),
            key=lambda o: o.root_height,
        )
        for name in MINERS
    }
    outputs = {
        "A0": coinbases["alice"][0],
        "B0": coinbases["bob"][0],
        "C0": coinbases["carol"][0],
        "C1": model.outputs[(TRANSFER_TXID, 0)],  # transferred from Dave to Carol at height 150
        "D_spent": coinbases["dave"][0],  # spent by the transfer
        "D0": coinbases["dave"][1],
        "D1": coinbases["dave"][2],
        "E0": coinbases["eve"][0],
        "Z0": coinbases["zed"][0],
    }
    assert outputs["D_spent"].outpoint in model.spent_at
    by_key = {o.key: o for o in model.outputs.values() if o.owner is not None}

    def sale(output_name: str, owner: str, price: int, buyer: int) -> Sale:
        txid, vout = outputs[output_name].outpoint
        return Sale(f"{txid}:{vout}", address_of(owner), f"exampleBtc{owner.title()}",
                    f"exampleBuyerShare{buyer}", f"buyer{buyer}", price)

    sales = {
        "valid": (sale("A0", "alice", 1200, 1), sale("B0", "bob", 1800, 2)),
        "resplit": (
            sale("C0", "carol", 600, 1), sale("C1", "carol", 600, 1),
            sale("D0", "dave", 1000, 2), sale("D1", "dave", 800, 2),
        ),
    }
    return World(key_hashes, registrations, registry1, registry2, model, tree1, tree2, outputs, by_key, sales)


def slot_of(spec: dict, key: int) -> int:
    return spec["inputs"]["saleId"].index(str(key))


def edited(spec: dict, slot: int, *, sale_id: int | None = None, label: str | None = None) -> dict:
    out = json.loads(json.dumps(spec))
    if sale_id is not None:
        out["inputs"]["saleId"][slot] = str(sale_id)
    if label is not None:
        out["sellerKeyLabels"][slot] = label
    return out


def variants(world: World) -> list[Variant]:
    valid = batch_spec(sales=world.sales["valid"])
    resplit = batch_spec(sales=world.sales["resplit"])
    alice = slot_of(valid, world.outputs["A0"].key)
    alice_label = order_label("alice")
    rotated = edited(valid, alice, label=order_label("alice", 2))
    out = world.outputs
    return [
        Variant("valid", "valid", "T1", valid, "Alice sells A0 and Bob sells B0, each with the registered key.", "accept"),
        Variant("resplit", "resplit", "T1", resplit,
                "Carol sells C0 and the output Dave transferred to her, Dave sells D0 and D1; the public totals equal valid's.",
                "accept"),
        Variant("rotated", "valid_extra", "T2", rotated,
                "Alice rotated to her second key (sequence 2) and sells A0 with it.", "accept"),
        Variant("order_key_not_registered_owner", "invalid", "T1",
                edited(valid, alice, label=MALLORY_LABEL),
                "A validly signed order for A0 by a key that no address registered.", "reject"),
        Variant("output_of_another_registered_seller", "invalid", "T1",
                edited(valid, alice, sale_id=out["E0"].key),
                "Alice, a registered seller, signs an order for E0, which belongs to Eve's registered key.", "reject"),
        Variant("rotated_key_sells_with_old_key", "invalid", "T2", valid,
                "Alice's registration was rotated to key 2; the order for A0 is signed with key 1.", "reject"),
        Variant("unregistered_owner_output", "invalid", "T1",
                edited(valid, alice, sale_id=out["Z0"].key, label=order_label("zed")),
                "Zed signs an order for his own output Z0, but his address never registered a key.", "reject"),
        Variant("output_spent_before_anchor", "invalid", "T1",
                edited(valid, alice, sale_id=out["D_spent"].key, label=order_label("dave")),
                "Dave, the registered owner, sells an output that the sharechain spent at height 150.", "reject"),
        Variant("wrong_utxo_root", "invalid", "T1", valid,
                "The valid batch against a utxoRoot one higher than the tree's.", "reject"),
        Variant("bad_order_signature", "invalid", "T1", valid,
                "The valid batch with Alice's order signature S + 1: M4's rule still holds in the joined circuit.",
                "reject", post=[{"op": "orderS_plus_one", "slot": alice}]),
    ]


def ownership_witness(world: World, tree: smt.SparseMerkleTree, spec: dict, root_offset: int = 0) -> dict:
    """utxoRoot, units, rootHeight and siblings for every slot of a spec, from the tree and the sharechain."""
    inputs = spec["inputs"]
    units, root_height, siblings = [], [], []
    for slot in range(SALE_SLOTS):
        if inputs["activeSale"][slot] != "1":
            units.append(0)
            root_height.append(0)
            siblings.append([0] * N_LEVELS)
            continue
        key = int(inputs["saleId"][slot])
        output = world.by_key[key]
        proof = tree.prove(key) if key in tree else tree.prove_absent(key)
        units.append(output.units)
        root_height.append(output.root_height)
        siblings.append(smt.pad_siblings(proof.siblings, N_LEVELS))
    return {
        "utxoRoot": tree.root + root_offset,
        "units": units,
        "rootHeight": root_height,
        "siblings": siblings,
    }


def predicted_membership_failures(world: World, variant: Variant) -> list[int]:
    """Active slots whose membership check the circuit will refuse, from the key hashes alone.

    The circuit checks tree[saleId] = Poseidon(sellerId, units, rootHeight) with sellerId the hash of
    the signing key. This recomputes that with the key hash of each slot's label. EdDSA checks and
    the arithmetic are not modelled; the fixtures script runs those in the circuit.
    """
    tree = world.tree1 if variant.tree == "T1" else world.tree2
    inputs = variant.spec["inputs"]
    failures = []
    for slot in range(SALE_SLOTS):
        if inputs["activeSale"][slot] != "1":
            continue
        output = world.by_key[int(inputs["saleId"][slot])]
        seller = int(world.key_hashes[variant.spec["sellerKeyLabels"][slot]])
        if tree.get(output.key) != smt.leaf_value(seller, output.units, output.root_height):
            failures.append(slot)
    if variant.name == "wrong_utxo_root":
        failures = [slot for slot in range(SALE_SLOTS) if inputs["activeSale"][slot] == "1"]
    return failures


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")))


def build(key_hashes: dict, out: Path) -> World:
    world = build_world(key_hashes)
    manifest = []
    for variant in variants(world):
        tree = world.tree1 if variant.tree == "T1" else world.tree2
        offset = 1 if variant.name == "wrong_utxo_root" else 0
        write_json(out / "variants" / f"{variant.name}.spec.json", variant.spec)
        write_json(out / "variants" / f"{variant.name}.own.json",
                   gen_inputs.encode(ownership_witness(world, tree, variant.spec, offset)))
        manifest.append({"name": variant.name, "kind": variant.kind, "tree": variant.tree,
                         "note": variant.note, "expect": variant.expect, "post": variant.post})
    write_json(out / "variants" / "manifest.json", manifest)
    write_json(out / "registrations.json", [r.to_json() for r in world.registrations])
    lower, upper = PARAMS.window(TIP)
    write_json(out / "world.json", {
        "network": NETWORK,
        "tip": TIP,
        "params": {"coinbase_maturity": PARAMS.coinbase_maturity, "payout_depth": PARAMS.payout_depth,
                   "expiry_margin": PARAMS.expiry_margin, "max_depth": PARAMS.max_depth},
        "window": [lower, upper],
        "addresses": {name: address_of(name) for name in MINERS},
        "registered_key_hash": {a: str(k) for a, k in world.registry2.owners().items()},
        "trees": {
            "T1": {"root": str(world.tree1.root), "leaves": len(world.tree1),
                   "max_depth": max(world.tree1.leaf_depths())},
            "T2": {"root": str(world.tree2.root), "leaves": len(world.tree2),
                   "max_depth": max(world.tree2.leaf_depths())},
        },
        "outputs": {name: {"outpoint": f"{o.txid}:{o.vout}", "owner": o.owner, "root_height": o.root_height,
                           "units": o.units, "in_T1": o.key in world.tree1} for name, o in world.outputs.items()},
    })
    return world


def main() -> None:
    if len(sys.argv) == 2 and sys.argv[1] == "labels":
        print(json.dumps(labels()))
    elif len(sys.argv) == 4 and sys.argv[1] == "build":
        key_hashes = json.loads(Path(sys.argv[2]).read_text())
        world = build(key_hashes, Path(sys.argv[3]))
        print(f"wrote {len(variants(world))} variants: T1 root {world.tree1.root}, T2 root {world.tree2.root}, "
              f"{len(world.tree1)} leaves")
    else:
        sys.exit("usage: make_joined.py labels | build <key hashes.json> <out dir>")


if __name__ == "__main__":
    main()
