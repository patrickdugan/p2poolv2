pragma circom 2.1.8;

// M5: prove that each sold share outpoint is a live sharechain output owned by
// the seller, against a public root of the sparse Merkle UTXO tree that
// ownership/smt.py builds.
//
// For every active sale slot s the circuit checks, with circomlib's SMTVerifier
// (inclusion, fnc = 0):
//
//     tree(utxoRoot)[ saleId[s] ] = Poseidon(sellerId[s], units[s], rootHeight[s])
//
// saleId is the outpoint's field id and sellerId the owner's field id, the same
// encodings accounting16x4_committed.circom commits as saleId and sellerId (see
// witness.py `field_id`). units (the output value in satoshis) and rootHeight
// (P2Poolv2's coinbase_root_height) are private: the tree commits to them, so a
// prover cannot choose them.
//
// What this proves: at the anchored share height the tree was built for, this
// outpoint was in the set of unspent, spendable outputs, owned by sellerId. It
// does not prove the anchor is canonical, that the tree was built honestly from
// the sharechain, or that the output stays unspent afterwards. See OWNERSHIP.md.
//
// nLevels is one more than the deepest leaf the tree allows. SMTLevIns forces
// the last sibling to zero, so a leaf may sit at depth nLevels - 1 at most.
// Unused trailing siblings are zero.

include "circomlib/circuits/smt/smtverifier.circom";
include "circomlib/circuits/poseidon.circom";

template OwnedSale(nLevels) {
    signal input enabled;   // 1 for a sale, 0 for padding
    signal input utxoRoot;
    signal input saleId;
    signal input sellerId;
    signal input units;
    signal input rootHeight;
    signal input siblings[nLevels];

    enabled * (1 - enabled) === 0;
    // A padding slot names nothing, matching the v1 circuit's padding rule.
    (1 - enabled) * saleId === 0;
    (1 - enabled) * sellerId === 0;
    (1 - enabled) * units === 0;
    (1 - enabled) * rootHeight === 0;

    component leafValue = Poseidon(3);
    leafValue.inputs[0] <== sellerId;
    leafValue.inputs[1] <== units;
    leafValue.inputs[2] <== rootHeight;

    component membership = SMTVerifier(nLevels);
    membership.enabled <== enabled;
    membership.root <== utxoRoot;
    for (var level = 0; level < nLevels; level++) {
        membership.siblings[level] <== siblings[level];
    }
    // Inclusion only: the old-leaf inputs belong to the exclusion mode.
    membership.oldKey <== 0;
    membership.oldValue <== 0;
    membership.isOld0 <== 0;
    membership.key <== saleId;
    membership.value <== leafValue.out;
    membership.fnc <== 0;
}

template OwnedSales(saleSlots, nLevels) {
    signal input utxoRoot;
    signal input activeSale[saleSlots];
    signal input saleId[saleSlots];
    signal input sellerId[saleSlots];
    signal input units[saleSlots];
    signal input rootHeight[saleSlots];
    signal input siblings[saleSlots][nLevels];

    component sale[saleSlots];
    for (var slot = 0; slot < saleSlots; slot++) {
        sale[slot] = OwnedSale(nLevels);
        sale[slot].enabled <== activeSale[slot];
        sale[slot].utxoRoot <== utxoRoot;
        sale[slot].saleId <== saleId[slot];
        sale[slot].sellerId <== sellerId[slot];
        sale[slot].units <== units[slot];
        sale[slot].rootHeight <== rootHeight[slot];
        for (var level = 0; level < nLevels; level++) {
            sale[slot].siblings[level] <== siblings[slot][level];
        }
    }
}
