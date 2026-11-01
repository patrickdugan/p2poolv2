pragma circom 2.1.8;

// M15: membership of each sold share outpoint in the anchor's dense window tree
// (ownership/window_tree.py), the cheaper counterpart of owned_sale.circom.
//
// For every active sale slot s the circuit checks
//
//     leaf    = Poseidon(saleId[s], sellerId[s], units[s], rootHeight[s])
//     windowRoot = the root reached from leaf along the path at position[s]
//
// where a path is, per level, the r = 2^radixBits children of the node hashed at that level:
// the child at the position's digit must be the running hash, and the node is Poseidon over
// the children. The position is a private input and is NOT derived from saleId. That is
// sound for membership because the leaf holds saleId: whatever position the prover names, a
// matching path exists only if that exact (outpoint, owner, units, root height) leaf was put
// into the tree. What the position buys is order: across the batch the active slots must be
// a prefix and their positions must strictly increase, so two slots cannot name the same
// output (when the tree holds each outpoint once, which is what a watcher's rebuild checks).
//
// saleId and sellerId are the field ids that clearing_tree_signed.circom hashes into its
// saleCommitment; units and rootHeight are private and fixed by the tree, as in M5.
//
// What this proves, and what it does not, is in joinedtree/JOINED_TREE.md. The root is not
// known to be root(T(A)) of a canonical anchor, and nothing here says the output stays
// unspent; both are M5 section 7. Unlike M5's tree, the root does not bind a key to a single
// value by construction: a root that holds one outpoint at two positions with two owners
// would pass here. Watchers refuse to presign a root they do not reproduce from the sorted set.
//
// Padding slots (activeSale 0) carry zeros and a consistent dummy path, and the root check is
// off for them.

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/mux1.circom";

// out = in[index], index given by `bits` (little-endian, booleans checked by the caller):
// a binary tree of Mux1, 2^bits - 1 constraints.
template SelectByBits(nBits) {
    var width = 1 << nBits;
    signal input in[width];
    signal input bits[nBits];
    signal output out;

    component mux[width - 1];
    var offset = 0;
    var count = width / 2;
    for (var stage = 0; stage < nBits; stage++) {
        for (var index = 0; index < count; index++) {
            mux[offset + index] = Mux1();
            mux[offset + index].s <== bits[stage];
            if (stage == 0) {
                mux[offset + index].c[0] <== in[2 * index];
                mux[offset + index].c[1] <== in[2 * index + 1];
            } else {
                var below = offset - 2 * count;
                mux[offset + index].c[0] <== mux[below + 2 * index].out;
                mux[offset + index].c[1] <== mux[below + 2 * index + 1].out;
            }
        }
        offset += count;
        count = count / 2;
    }
    out <== mux[width - 2].out;
}

// One level of a path: the running hash must be the child at the digit, and the parent is the
// node over all children.
template WindowLevel(radixBits) {
    var radix = 1 << radixBits;
    signal input current;
    signal input digit[radixBits];
    signal input children[radix];
    signal output parent;

    component select = SelectByBits(radixBits);
    for (var index = 0; index < radix; index++) {
        select.in[index] <== children[index];
    }
    for (var bit = 0; bit < radixBits; bit++) {
        select.bits[bit] <== digit[bit];
    }
    select.out === current;

    component node = Poseidon(radix);
    for (var index = 0; index < radix; index++) {
        node.inputs[index] <== children[index];
    }
    parent <== node.out;
}

template WindowSale(radixBits, levels) {
    var radix = 1 << radixBits;
    signal input enabled;   // 1 for a sale, 0 for padding
    signal input windowRoot;
    signal input saleId;
    signal input sellerId;
    signal input units;
    signal input rootHeight;
    signal input position;
    signal input children[levels][radix];

    enabled * (1 - enabled) === 0;
    // A padding slot names nothing, matching the v1 circuit's padding rule.
    (1 - enabled) * saleId === 0;
    (1 - enabled) * sellerId === 0;
    (1 - enabled) * units === 0;
    (1 - enabled) * rootHeight === 0;

    component leaf = Poseidon(4);
    leaf.inputs[0] <== saleId;
    leaf.inputs[1] <== sellerId;
    leaf.inputs[2] <== units;
    leaf.inputs[3] <== rootHeight;

    // The position's digits, least significant (the leaf's level) first. Num2Bits also makes
    // them booleans and the position less than radix^levels.
    component bits = Num2Bits(radixBits * levels);
    bits.in <== position;

    component level[levels];
    for (var l = 0; l < levels; l++) {
        level[l] = WindowLevel(radixBits);
        if (l == 0) {
            level[l].current <== leaf.out;
        } else {
            level[l].current <== level[l - 1].parent;
        }
        for (var bit = 0; bit < radixBits; bit++) {
            level[l].digit[bit] <== bits.out[l * radixBits + bit];
        }
        for (var index = 0; index < radix; index++) {
            level[l].children[index] <== children[l][index];
        }
    }

    enabled * (level[levels - 1].parent - windowRoot) === 0;
}

// Two neighbouring slots: the active slots are a prefix, and positions strictly increase.
template WindowOrder(positionBits) {
    signal input previousActive;
    signal input active;
    signal input previousPosition;
    signal input position;

    active * (1 - previousActive) === 0;

    // position - previousPosition - 1 must fit in positionBits bits, which holds exactly when
    // it is not negative (both positions are below 2^positionBits). Zero for an inactive slot.
    signal step;
    step <== active * (position - previousPosition - 1);
    component fits = Num2Bits(positionBits);
    fits.in <== step;
}

template WindowSales(saleSlots, radixBits, levels) {
    var radix = 1 << radixBits;
    signal input windowRoot;
    signal input activeSale[saleSlots];
    signal input saleId[saleSlots];
    signal input sellerId[saleSlots];
    signal input units[saleSlots];
    signal input rootHeight[saleSlots];
    signal input position[saleSlots];
    signal input children[saleSlots][levels][radix];

    component sale[saleSlots];
    component order[saleSlots];
    for (var slot = 0; slot < saleSlots; slot++) {
        sale[slot] = WindowSale(radixBits, levels);
        sale[slot].enabled <== activeSale[slot];
        sale[slot].windowRoot <== windowRoot;
        sale[slot].saleId <== saleId[slot];
        sale[slot].sellerId <== sellerId[slot];
        sale[slot].units <== units[slot];
        sale[slot].rootHeight <== rootHeight[slot];
        sale[slot].position <== position[slot];
        for (var l = 0; l < levels; l++) {
            for (var index = 0; index < radix; index++) {
                sale[slot].children[l][index] <== children[slot][l][index];
            }
        }
        if (slot > 0) {
            order[slot] = WindowOrder(radixBits * levels);
            order[slot].previousActive <== activeSale[slot - 1];
            order[slot].active <== activeSale[slot];
            order[slot].previousPosition <== position[slot - 1];
            order[slot].position <== position[slot];
        }
    }
}
