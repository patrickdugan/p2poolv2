pragma circom 2.1.8;

// v1's statement at any batch size: the arithmetic of ClearingAmounts plus a
// commitment to the sale list, with the flat Poseidon16 root replaced by a
// binary Poseidon tree so the slot count is not capped at 16.
//
// leaf[s]        = Poseidon5(activeSale, saleId, sellerId, price, selected buyerId)
// saleCommitment = root of the binary Poseidon2 tree over leaf[0..2^depth - 1]

include "clearing.circom";
include "circomlib/circuits/poseidon.circom";

template PoseidonTreeRoot(depth) {
    var count = 1 << depth;
    signal input leaves[count];
    signal output root;

    component node[count - 1];
    // Nodes are stored level by level: the first count/2 hash leaf pairs.
    var offset = 0;
    var width = count / 2;
    for (var level = 0; level < depth; level++) {
        for (var index = 0; index < width; index++) {
            node[offset + index] = Poseidon(2);
            if (level == 0) {
                node[offset + index].inputs[0] <== leaves[2 * index];
                node[offset + index].inputs[1] <== leaves[2 * index + 1];
            } else {
                var below = offset - 2 * width;
                node[offset + index].inputs[0] <== node[below + 2 * index].out;
                node[offset + index].inputs[1] <== node[below + 2 * index + 1].out;
            }
        }
        offset += width;
        width = width / 2;
    }
    root <== node[count - 2].out;
}

template CommittedClearingTree(saleSlots, buyerSlots, depth) {
    assert(saleSlots == (1 << depth));

    signal input funding[buyerSlots];
    signal input feeBudget[buyerSlots];
    signal input refund[buyerSlots];
    signal input totalPayout;
    signal input buyerId[buyerSlots];

    signal input price[saleSlots];
    signal input activeSale[saleSlots];
    signal input priceInverse[saleSlots];
    signal input selector[saleSlots][buyerSlots];
    signal input activeBuyer[buyerSlots];
    signal input buyerCountInverse[buyerSlots];
    signal input activeCountInverse;
    signal input saleId[saleSlots];
    signal input sellerId[saleSlots];

    signal output saleCommitment;

    component amounts = ClearingAmounts(saleSlots, buyerSlots);
    amounts.totalPayout <== totalPayout;
    amounts.activeCountInverse <== activeCountInverse;
    for (var buyer = 0; buyer < buyerSlots; buyer++) {
        amounts.funding[buyer] <== funding[buyer];
        amounts.feeBudget[buyer] <== feeBudget[buyer];
        amounts.refund[buyer] <== refund[buyer];
        amounts.activeBuyer[buyer] <== activeBuyer[buyer];
        amounts.buyerCountInverse[buyer] <== buyerCountInverse[buyer];
        (1 - activeBuyer[buyer]) * buyerId[buyer] === 0;
    }

    signal selectedBuyerTerm[saleSlots][buyerSlots];
    component leaf[saleSlots];
    component tree = PoseidonTreeRoot(depth);

    for (var sale = 0; sale < saleSlots; sale++) {
        amounts.price[sale] <== price[sale];
        amounts.activeSale[sale] <== activeSale[sale];
        amounts.priceInverse[sale] <== priceInverse[sale];
        var selectedBuyerId = 0;
        for (var buyer = 0; buyer < buyerSlots; buyer++) {
            amounts.selector[sale][buyer] <== selector[sale][buyer];
            selectedBuyerTerm[sale][buyer] <== selector[sale][buyer] * buyerId[buyer];
            selectedBuyerId += selectedBuyerTerm[sale][buyer];
        }
        (1 - activeSale[sale]) * saleId[sale] === 0;
        (1 - activeSale[sale]) * sellerId[sale] === 0;

        leaf[sale] = Poseidon(5);
        leaf[sale].inputs[0] <== activeSale[sale];
        leaf[sale].inputs[1] <== saleId[sale];
        leaf[sale].inputs[2] <== sellerId[sale];
        leaf[sale].inputs[3] <== price[sale];
        leaf[sale].inputs[4] <== selectedBuyerId;
        tree.leaves[sale] <== leaf[sale].out;
    }
    saleCommitment <== tree.root;
}
