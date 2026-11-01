"""The world and the batches behind the joined signed-tree fixtures (M15): registry, sharechain,
the window tree and M5's tree, a batch of any power-of-two size, and every variant.

    python3 make_joined_tree.py labels                                  > labels.json
    python3 make_joined_tree.py build <key hashes.json> <out dir> --sales S --buyers B \\
        --membership window|smt [--radix-bits K]

`labels` prints the BabyJubjub order-key labels the world needs. `joined/sign_joined.js keyhashes`
turns them into `{label: Poseidon(Ax, Ay)}`, and `build` then writes, under <out dir>:

    world.json                  addresses, roots, named outputs, tree shapes, variants
    registrations.json          every registration, as a feed would carry them
    variants/manifest.json      each variant: name, kind, what it must do and where it is refused
    variants/<name>.spec.json   an M4 batch spec with sale slots that name real sharechain outputs
    variants/<name>.own.json    the membership witness: the root, units, rootHeight and the path

`sign_tree.js sign` signs the specs and joins each with its witness into the inputs of
`clearing_tree_owned.circom`'s mains.

The world is `joined/make_joined.py`'s sharechain (201 blocks at the sim depths of
`ownership/real_store.py`, window of root heights 105 to 181, a share transaction at height 150
that moves Dave's output to Carol), with every miner except Zed registering an order key, so
there are 69 outputs a registered key can sell. The batch sells the first `sales` of them in tree
order: sale slot s names the output at the s-th lowest position.

Every variant breaks exactly one rule, so the circuit's refusal can be attributed. The names of
the rules are the templates of `ownership/circuits/window_sale.circom` and `owned_sale.circom`.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
ZK = HERE.parent
for directory in (ZK, ZK / "ownership", ZK / "signed", ZK / "joined"):
    sys.path.insert(0, str(directory))

import make_joined as mj  # noqa: E402  (imports ownership/gen_inputs.py as `gen_inputs`)
import register  # noqa: E402
import smt  # noqa: E402
import window_tree as wt  # noqa: E402


def _load_gen_batch():
    """signedtree/gen_batch.py imports scaling/gen_inputs.py under the name `gen_inputs`, which
    ownership/gen_inputs.py already holds. Import it with the name free, then put ours back."""
    ownership_gen_inputs = sys.modules.pop("gen_inputs")
    sys.path.insert(0, str(ZK / "signedtree"))
    try:
        import gen_batch
    finally:
        sys.modules["gen_inputs"] = ownership_gen_inputs
    return gen_batch


gen_batch = _load_gen_batch()
ownership_gen_inputs = sys.modules["gen_inputs"]

REGISTERED = tuple(name for name in mj.MINERS if name != "zed")
SMT_LEVELS = ownership_gen_inputs.N_LEVELS
SALE_ROW_KEYS = ("price", "activeSale", "priceInverse", "saleId", "sellerId", "sellerPayoutId", "orderExpiry")

# Where the circuit must refuse each invalid variant: the innermost template named by the witness
# calculator's error, by membership kind.
SALE = "WindowSale"
LEVEL = "WindowLevel"
ORDER = "WindowOrder"
SMT = "SMTVerifier"
EDDSA = "EdDSAPoseidonVerifier"
HASH = "SignedClearingTree"


def labels() -> list[str]:
    return [mj.order_label(name) for name in mj.MINERS] + [mj.MALLORY_LABEL]


@dataclass
class World:
    key_hashes: dict
    registrations: list
    registry: register.Registry
    model: object
    smt_tree: smt.SparseMerkleTree
    window: wt.WindowTree
    window_outputs: list  # in position order
    radix_bits: int
    outputs: dict  # name -> utxo_set.Output
    by_key: dict  # outpoint id -> utxo_set.Output, for every output with an owner
    sellable: list  # window outputs a registered key owns, in position order


def build_world(key_hashes: dict, radix_bits: int = 1, levels: int | None = None) -> World:
    registrations = []
    for name in REGISTERED:
        aux = hashlib.sha256(f"{mj.DOMAIN}/aux/{name}/1".encode()).digest()
        registrations.append(register.sign_registration(
            mj.bip340_secret(name), mj.NETWORK, int(key_hashes[mj.order_label(name)]), 1, aux))
    registry = register.Registry(mj.NETWORK)
    assert not registry.ingest(registrations)
    owners = registry.owners()
    for name in REGISTERED:
        assert owners[mj.address_of(name)] == int(key_hashes[mj.order_label(name)])
    assert mj.address_of("zed") not in owners

    accumulator = mj.replay_chain(owners)
    model = accumulator.model
    smt_tree = model.build_tree(mj.TIP, owners)
    assert accumulator.root == smt_tree.root
    window, window_outputs = wt.build_window_tree(model, mj.TIP, owners, radix_bits, levels)

    lower, upper = mj.PARAMS.window(mj.TIP)
    coinbases = {
        name: sorted(
            (o for o in model.outputs.values()
             if o.is_coinbase and o.owner == mj.address_of(name) and lower <= o.root_height <= upper),
            key=lambda o: o.root_height,
        )
        for name in mj.MINERS
    }
    by_key = {o.key: o for o in model.outputs.values() if o.owner is not None}
    expired = next(o for h in range(lower - 1, lower - 12, -1)
                   for o in model.by_root.get(h, ()) if o.is_coinbase and o.owner != mj.address_of("zed"))
    immature = next(o for o in model.by_root.get(mj.TIP, ()) if o.is_coinbase)
    outputs = {
        "D_spent": coinbases["dave"][0],  # spent by the share transaction at height 150
        "Z0": coinbases["zed"][0],  # Zed never registered
        "expired": expired,  # root height just below the window
        "immature": immature,  # the tip's own coinbase output
    }
    assert outputs["D_spent"].outpoint in model.spent_at
    assert expired.root_height < lower and immature.root_height > upper
    for name in ("D_spent", "expired", "immature"):
        assert outputs[name].owner in owners, name
    sellable = [o for o in window_outputs if o.owner in owners]
    return World(key_hashes, registrations, registry, model, smt_tree, window, window_outputs, radix_bits,
                 outputs, by_key, sellable)


# ---------------------------------------------------------------------------
# Specs


def assigned(spec: dict, sold: list, world: World) -> dict:
    """`spec` with its first len(sold) sale slots naming `sold` and signed by the registered keys."""
    out = copy.deepcopy(spec)
    for slot, output in enumerate(sold):
        assert out["inputs"]["activeSale"][slot] == "1"
        out["inputs"]["saleId"][slot] = str(output.key)
        out["sellerKeyLabels"][slot] = output.owner
    return out


def edited(spec: dict, slot: int, *, output=None, label: str | None = None) -> dict:
    out = copy.deepcopy(spec)
    if output is not None:
        out["inputs"]["saleId"][slot] = str(output.key)
        out["sellerKeyLabels"][slot] = output.owner
    if label is not None:
        out["sellerKeyLabels"][slot] = label
    return out


def permuted(spec: dict, order: list[int]) -> dict:
    """The sale rows rearranged: row `new` is old row `order[new]`. Every per-sale column moves together."""
    out = copy.deepcopy(spec)
    inputs = spec["inputs"]
    for key in SALE_ROW_KEYS:
        out["inputs"][key] = [inputs[key][old] for old in order]
    out["inputs"]["selector"] = [list(inputs["selector"][old]) for old in order]
    out["sellerKeyLabels"] = [spec["sellerKeyLabels"][old] for old in order]
    return out


def active_slots(spec: dict) -> list[int]:
    return [slot for slot, flag in enumerate(spec["inputs"]["activeSale"]) if flag == "1"]


def position_hint(world: World, key: int) -> tuple[int, int]:
    """Sort key of a claimed output: its real position when the tree holds it, else past the end."""
    position = world.window.position_of(key)
    return (0, position) if position is not None else (1, key)


def sorted_by_position(spec: dict, world: World) -> dict:
    """The active rows in ascending tree position, non-members last, inactive rows after."""
    live = active_slots(spec)
    rest = [slot for slot in range(len(spec["inputs"]["activeSale"])) if slot not in live]
    live.sort(key=lambda slot: position_hint(world, int(spec["inputs"]["saleId"][slot])))
    return permuted(spec, live + rest)


# ---------------------------------------------------------------------------
# Membership witnesses


def encode(value):
    return ownership_gen_inputs.encode(value)


def claim_of(world: World, spec: dict, slot: int):
    """(active, key, seller key hash, output) the circuit's slot is asked to prove."""
    inputs = spec["inputs"]
    if inputs["activeSale"][slot] != "1":
        return False, 0, 0, None
    key = int(inputs["saleId"][slot])
    return True, key, int(world.key_hashes[spec["sellerKeyLabels"][slot]]), world.by_key[key]


def window_witness(world: World, spec: dict, root_offset: int = 0, overrides: dict | None = None):
    """The circuit inputs of WindowSales for a spec, and the checks they would pass.

    A slot that names a member with the right owner gets the real path. Anything else gets the
    strongest forgery: the real path at the output's position (or at the first free position for
    a non-member) with the claimed leaf spliced in, which satisfies every selection check and
    fails at the root. `overrides[slot]` is 'position_off_path' (the position is one higher than
    the children's) or 'member_at_wrong_position' (a real leaf spliced into the path one position
    higher). The overrides go on the last slot, so the positions still rise and only the
    membership rule is broken.
    """
    tree = world.window
    overrides = overrides or {}
    units, root_height, positions, children, trace = [], [], [], [], []
    next_free = len(tree)
    for slot in range(len(spec["inputs"]["saleId"])):
        active, key, seller, output = claim_of(world, spec, slot)
        if not active:
            leaf = wt.leaf_hash(0, 0, 0, 0)
            path = tree.spliced_path(0, leaf)
            u = rh = 0
        else:
            u, rh = output.units, output.root_height
            leaf = wt.leaf_hash(key, seller, u, rh)
            position = tree.position_of(key)
            if position is None:
                position, next_free = next_free, next_free + 1
            stored = tree.leaves[position].hash if position < len(tree) else None
            path = tree.path(position) if stored == leaf else tree.spliced_path(position, leaf)
            mode = overrides.get(slot)
            if mode == "position_off_path":
                path = wt.WindowPath(position + 1, path.children)
            elif mode == "member_at_wrong_position":
                path = tree.spliced_path(position + 1, leaf)
        units.append(u)
        root_height.append(rh)
        positions.append(path.position)
        children.append([list(group) for group in path.children])
        trace.append({"active": active, "leaf": leaf, "path": path})
    claimed_root = tree.root + root_offset
    witness = {"windowRoot": claimed_root, "units": units, "rootHeight": root_height,
               "position": positions, "children": children}
    return encode(witness), trace


def predicted_window_failures(world: World, trace: list, claimed_root: int) -> list[str]:
    """Which templates of window_sale.circom refuse these slots, from the paths alone."""
    failures = set()
    for entry in trace:
        try:
            reached = wt.root_from_path(entry["leaf"], entry["path"], world.window.radix_bits)
        except wt.PathMismatch:
            failures.add(LEVEL)
            continue
        if entry["active"] and reached != claimed_root:
            failures.add(SALE)
    positions = [entry["path"].position for entry in trace]
    flags = [1 if entry["active"] else 0 for entry in trace]
    if not wt.check_ascending(positions, flags):
        failures.add(ORDER)
    return sorted(failures)


def smt_witness(world: World, spec: dict, root_offset: int = 0):
    tree = world.smt_tree
    units, root_height, siblings, trace = [], [], [], []
    for slot in range(len(spec["inputs"]["saleId"])):
        active, key, seller, output = claim_of(world, spec, slot)
        if not active:
            units.append(0)
            root_height.append(0)
            siblings.append([0] * SMT_LEVELS)
            trace.append(None)
            continue
        proof = tree.prove(key) if key in tree else tree.prove_absent(key)
        units.append(output.units)
        root_height.append(output.root_height)
        siblings.append(smt.pad_siblings(proof.siblings, SMT_LEVELS))
        member = tree.get(key) == smt.leaf_value(seller, output.units, output.root_height)
        trace.append(member)
    witness = {"utxoRoot": tree.root + root_offset, "units": units, "rootHeight": root_height, "siblings": siblings}
    return encode(witness), trace


def predicted_smt_failures(trace: list, root_offset: int) -> list[str]:
    if root_offset or any(entry is False for entry in trace):
        return [SMT]
    return []


# ---------------------------------------------------------------------------
# Variants


@dataclass
class Variant:
    name: str
    kind: str  # valid | resplit | padded | valid_extra | invalid
    spec: dict
    note: str
    rejected_in: str | None  # innermost template of the refusal; None when accepted
    post: list = field(default_factory=list)  # operations sign_tree.js applies after signing
    root_offset: int = 0
    overrides: dict = field(default_factory=dict)


def variants(world: World, membership: str, sales: int, buyers: int) -> list[Variant]:
    assert len(world.sellable) >= sales + 1, "the world has too few sellable outputs for this batch"
    valid = assigned(gen_batch.batch_spec(sales, buyers, "valid"), world.sellable[:sales], world)
    resplit = assigned(gen_batch.batch_spec(sales, buyers, "resplit"), world.sellable[1:sales + 1], world)
    live = sales - sales // 4
    padded = assigned(gen_batch.batch_spec(sales, buyers, "padded"), world.sellable[:live], world)
    # Row 3 and 4 name the outputs at positions p3 < p4. These variants need 5+ sale slots.
    assert sales >= 8
    out = world.outputs
    last = sales - 1
    window = membership == "window"
    own_sale, own_level, own_order = (SALE, LEVEL, ORDER) if window else (SMT, SMT, None)

    other_label = next(o.owner for o in world.sellable if o.owner != world.sellable[0].owner)
    items: list[Variant] = [
        Variant("valid", "valid", valid,
                f"Sale slot s sells the output at the s-th lowest position, each with its registered key.", None),
        Variant("resplit", "resplit", resplit,
                "The same totals and prices, sold from the outputs one position higher: a different statement.", None),
        Variant("padded", "padded", padded,
                f"The last {sales - live} sale slots and the last buyer slot unused: the padding rules hold.", None),
        Variant("signer_not_registered_owner", "invalid", edited(valid, 0, label=mj.MALLORY_LABEL),
                "Slot 0 is signed by a key that no address registered.", own_sale),
        Variant("signer_is_another_registered_seller", "invalid", edited(valid, 0, label=other_label),
                "Slot 0 is signed by another registered seller's key.", own_sale),
        Variant("unregistered_owner_output", "invalid",
                sorted_by_position(edited(valid, 0, output=out["Z0"], label=mj.order_label("zed")), world),
                "Zed signs an order for his own output, but his address never registered a key.", own_sale),
    ]
    for name, key, note in (
        ("output_spent_before_anchor", "D_spent", "Dave, the registered owner, sells an output that the sharechain spent at height 150."),
        ("output_expired", "expired", "A registered owner sells an output whose root height is below the window."),
        ("output_immature", "immature", "A registered owner sells the tip's own coinbase output, above the window."),
    ):
        items.append(Variant(name, "invalid", sorted_by_position(edited(valid, last, output=out[key]), world),
                             note, own_sale))
    items.append(Variant("wrong_window_root" if window else "wrong_utxo_root", "invalid", valid,
                         "The valid batch against an ownership root one higher than the tree's.", own_sale,
                         root_offset=1))
    items.append(Variant("bad_order_signature", "invalid", valid,
                         "Slot 0's order signature S + 1: M4's rule still holds in the joined circuit.", EDDSA,
                         post=[{"op": "orderS_plus_one", "slot": 0}]))
    items.append(Variant("statement_hash_omits_root", "invalid", valid,
                         "The public hash is M11's, over the 4 + 4B values without the ownership root.", HASH,
                         post=[{"op": "statement_hash_without_root"}]))
    if window:
        swapped = permuted(valid, [0, 1, 2, 4, 3] + list(range(5, sales)))
        duplicate = copy.deepcopy(valid)
        duplicate["inputs"]["saleId"][4] = duplicate["inputs"]["saleId"][3]
        duplicate["sellerKeyLabels"][4] = duplicate["sellerKeyLabels"][3]
        hole = permuted(padded, [0, 1, live] + list(range(2, live)) + list(range(live + 1, sales)))
        items += [
            Variant("position_disagrees_with_path", "invalid", valid,
                    f"The last slot names its real leaf and path but the position one above its own.", own_level,
                    overrides={last: "position_off_path"}),
            Variant("member_leaf_at_wrong_position", "invalid", valid,
                    "The last slot's real leaf spliced into the path of the next position up.", own_sale,
                    overrides={last: "member_at_wrong_position"}),
            Variant("duplicate_output_two_slots", "invalid", duplicate,
                    "Slots 3 and 4 both sell the output at position 3, each validly signed.", own_order),
            Variant("slots_out_of_position_order", "invalid", swapped,
                    "Slots 3 and 4 swapped: both memberships hold, the positions fall.", own_order),
            Variant("hole_in_active_slots", "invalid", hole,
                    "An unused sale slot between active ones, which are otherwise in position order.", own_order),
        ]
    else:
        items.append(Variant(
            "duplicate_output_two_slots", "valid_extra", edited(valid, 4, output=world.sellable[3]),
            "Slots 3 and 4 both sell the same output, each validly signed. M5's tree has no distinctness check.", None))
    return items


def witness_for(world: World, membership: str, variant: Variant):
    """(encoded witness, the templates the checks above predict will refuse it)."""
    if membership == "window":
        witness, trace = window_witness(world, variant.spec, variant.root_offset, variant.overrides)
        return witness, predicted_window_failures(world, trace, world.window.root + variant.root_offset)
    witness, trace = smt_witness(world, variant.spec, variant.root_offset)
    return witness, predicted_smt_failures(trace, variant.root_offset)


# ---------------------------------------------------------------------------
# Output


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")))


def build(key_hashes: dict, out: Path, membership: str, sales: int, buyers: int, radix_bits: int = 1) -> World:
    world = build_world(key_hashes, radix_bits)
    manifest = []
    for variant in variants(world, membership, sales, buyers):
        witness, predicted = witness_for(world, membership, variant)
        write_json(out / "variants" / f"{variant.name}.spec.json", variant.spec)
        write_json(out / "variants" / f"{variant.name}.own.json", witness)
        manifest.append({"name": variant.name, "kind": variant.kind, "note": variant.note,
                         "rejectedIn": variant.rejected_in, "predicted": predicted, "post": variant.post})
    write_json(out / "variants" / "manifest.json", manifest)
    write_json(out / "registrations.json", [r.to_json() for r in world.registrations])
    lower, upper = mj.PARAMS.window(mj.TIP)
    tree = world.window
    write_json(out / "world.json", {
        "network": mj.NETWORK, "tip": mj.TIP, "window": [lower, upper],
        "membership": membership, "sales": sales, "buyers": buyers,
        "window_tree": {"radix_bits": tree.radix_bits, "levels": tree.levels, "leaves": len(tree),
                        "capacity": tree.capacity, "root": str(tree.root)},
        "smt": {"leaves": len(world.smt_tree), "levels": SMT_LEVELS, "root": str(world.smt_tree.root),
                "max_leaf_depth": max(world.smt_tree.leaf_depths())},
        "sellable": len(world.sellable),
        "root": str(tree.root if membership == "window" else world.smt_tree.root),
        "outputs": {name: {"outpoint": f"{o.txid}:{o.vout}", "owner": o.owner, "root_height": o.root_height,
                           "in_window": o.key in tree} for name, o in world.outputs.items()},
    })
    return world


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["labels", "build"])
    parser.add_argument("paths", nargs="*")
    parser.add_argument("--sales", type=int, default=16)
    parser.add_argument("--buyers", type=int, default=4)
    parser.add_argument("--membership", choices=["window", "smt"], default="window")
    parser.add_argument("--radix-bits", type=int, default=1)
    args = parser.parse_args()
    if args.mode == "labels":
        print(json.dumps(labels()))
        return
    if len(args.paths) != 2:
        sys.exit("usage: make_joined_tree.py build <key hashes.json> <out dir> [--sales S --buyers B --membership M]")
    key_hashes = json.loads(Path(args.paths[0]).read_text())
    world = build(key_hashes, Path(args.paths[1]), args.membership, args.sales, args.buyers, args.radix_bits)
    count = len(variants(world, args.membership, args.sales, args.buyers))
    print(f"wrote {count} variants ({args.membership}, {args.sales}x{args.buyers}): window root {world.window.root}, "
          f"M5 root {world.smt_tree.root}, {len(world.window)} leaves, {len(world.sellable)} sellable")


if __name__ == "__main__":
    main()
