pragma circom 2.1.8;

// CommittedClearing, the v1 template (see accounting16x4_committed.circom), kept in a file
// without a main component so other circuits can include it.

include "clearing.circom";
include "circomlib/circuits/poseidon.circom";

template CommittedClearing(saleSlots, buyerSlots) {
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
        // An unused escrow slot names no buyer.
        (1 - activeBuyer[buyer]) * buyerId[buyer] === 0;
    }

    signal selectedBuyerTerm[saleSlots][buyerSlots];
    component leaf[saleSlots];
    component root = Poseidon(saleSlots);

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

        // Padding slots carry no identities, so every padding leaf is the
        // same constant and the commitment cannot hide extra data in them.
        (1 - activeSale[sale]) * saleId[sale] === 0;
        (1 - activeSale[sale]) * sellerId[sale] === 0;

        leaf[sale] = Poseidon(5);
        leaf[sale].inputs[0] <== activeSale[sale];
        leaf[sale].inputs[1] <== saleId[sale];
        leaf[sale].inputs[2] <== sellerId[sale];
        leaf[sale].inputs[3] <== price[sale];
        leaf[sale].inputs[4] <== selectedBuyerId;
        root.inputs[sale] <== leaf[sale].out;
    }
    saleCommitment <== root.out;
}
