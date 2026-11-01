pragma circom 2.1.8;

// M15: M11's signed clearing tree joined to a sharechain membership check, behind M11's one
// hashed public input.
//
// SignedClearingTree (clearing_tree_signed.circom) proves, for every active sale, an
// EdDSA-Poseidon order signature by the BabyJubjub key whose hash is sellerId. A membership
// template proves, for the same slot, that the outpoint saleId is a leaf of the anchor's tree
// with sellerId as its owner. Both are instantiated unchanged and share the signals
// activeSale, saleId and sellerId, as M10 does for the flat circuit, so a sale passes only if
// the key that signed the order is the key hash the tree stores as the owner of the sold output.
//
// The ownership root is a private input bound into the one public hash:
//
//   statement     = [saleCommitment, escrowCommitment, batchHeight, totalPayout,
//                    funding[], feeBudget[], refund[], buyerId[], ownershipRoot]   (5 + 4B values)
//   statementHash = PoseidonChunked(statement)
//
// SignedClearingTree takes the root through its `extra` input. The proof's only public signal
// is statementHash; a committee that recomputes it from the 5 + 4B values learns the root.
//
// Two membership templates are joined here, with the same signed tree:
//   OwnedSignedTreeWindow  the dense window tree of ownership/window_tree.py
//                          (ownership/circuits/window_sale.circom)
//   OwnedSignedTreeSmt     M5's 40-level sparse Merkle tree (ownership/circuits/owned_sale.circom)
// The window variant also needs the active sale slots to be a prefix with strictly rising tree
// positions, which is how it keeps two slots from naming one output.
//
// Not proven here, as in M10 and M11: that the root is the root of a canonical anchor or of a
// registry-correct tree, that a sold output stays unspent after the anchor, or that escrowId
// names a funded UTXO. See joinedtree/JOINED_TREE.md.

include "clearing_tree_signed.circom";
include "../ownership/circuits/window_sale.circom";
include "../ownership/circuits/owned_sale.circom";

template OwnedSignedTreeWindow(saleSlots, buyerSlots, depth, radixBits, levels) {
    var radix = 1 << radixBits;

    // The one public signal.
    signal input statementHash;

    // The ownership root, bound to statementHash.
    signal input windowRoot;

    // The statement's values.
    signal input funding[buyerSlots];
    signal input feeBudget[buyerSlots];
    signal input refund[buyerSlots];
    signal input totalPayout;
    signal input buyerId[buyerSlots];
    signal input batchHeight;

    // v1 witness.
    signal input price[saleSlots];
    signal input activeSale[saleSlots];
    signal input priceInverse[saleSlots];
    signal input selector[saleSlots][buyerSlots];
    signal input activeBuyer[buyerSlots];
    signal input buyerCountInverse[buyerSlots];
    signal input activeCountInverse;
    signal input saleId[saleSlots];
    signal input sellerId[saleSlots];

    // Seller orders.
    signal input sellerPayoutId[saleSlots];
    signal input orderExpiry[saleSlots];
    signal input sellerAx[saleSlots];
    signal input sellerAy[saleSlots];
    signal input orderR8x[saleSlots];
    signal input orderR8y[saleSlots];
    signal input orderS[saleSlots];

    // Buyer escrow terms.
    signal input escrowId[buyerSlots];
    signal input feeCap[buyerSlots];
    signal input refundScriptId[buyerSlots];
    signal input escrowExpiry[buyerSlots];
    signal input buyerAx[buyerSlots];
    signal input buyerAy[buyerSlots];
    signal input escrowR8x[buyerSlots];
    signal input escrowR8y[buyerSlots];
    signal input escrowS[buyerSlots];

    // The sold outputs' leaves and paths in the window tree.
    signal input units[saleSlots];
    signal input rootHeight[saleSlots];
    signal input position[saleSlots];
    signal input children[saleSlots][levels][radix];

    component signedTree = SignedClearingTree(saleSlots, buyerSlots, depth, 1);
    component owned = WindowSales(saleSlots, radixBits, levels);

    signedTree.statementHash <== statementHash;
    signedTree.extra[0] <== windowRoot;
    signedTree.totalPayout <== totalPayout;
    signedTree.batchHeight <== batchHeight;
    signedTree.activeCountInverse <== activeCountInverse;
    for (var buyer = 0; buyer < buyerSlots; buyer++) {
        signedTree.funding[buyer] <== funding[buyer];
        signedTree.feeBudget[buyer] <== feeBudget[buyer];
        signedTree.refund[buyer] <== refund[buyer];
        signedTree.buyerId[buyer] <== buyerId[buyer];
        signedTree.activeBuyer[buyer] <== activeBuyer[buyer];
        signedTree.buyerCountInverse[buyer] <== buyerCountInverse[buyer];
        signedTree.escrowId[buyer] <== escrowId[buyer];
        signedTree.feeCap[buyer] <== feeCap[buyer];
        signedTree.refundScriptId[buyer] <== refundScriptId[buyer];
        signedTree.escrowExpiry[buyer] <== escrowExpiry[buyer];
        signedTree.buyerAx[buyer] <== buyerAx[buyer];
        signedTree.buyerAy[buyer] <== buyerAy[buyer];
        signedTree.escrowR8x[buyer] <== escrowR8x[buyer];
        signedTree.escrowR8y[buyer] <== escrowR8y[buyer];
        signedTree.escrowS[buyer] <== escrowS[buyer];
    }

    owned.windowRoot <== windowRoot;
    for (var sale = 0; sale < saleSlots; sale++) {
        signedTree.price[sale] <== price[sale];
        signedTree.activeSale[sale] <== activeSale[sale];
        signedTree.priceInverse[sale] <== priceInverse[sale];
        for (var buyer = 0; buyer < buyerSlots; buyer++) {
            signedTree.selector[sale][buyer] <== selector[sale][buyer];
        }
        signedTree.saleId[sale] <== saleId[sale];
        signedTree.sellerId[sale] <== sellerId[sale];
        signedTree.sellerPayoutId[sale] <== sellerPayoutId[sale];
        signedTree.orderExpiry[sale] <== orderExpiry[sale];
        signedTree.sellerAx[sale] <== sellerAx[sale];
        signedTree.sellerAy[sale] <== sellerAy[sale];
        signedTree.orderR8x[sale] <== orderR8x[sale];
        signedTree.orderR8y[sale] <== orderR8y[sale];
        signedTree.orderS[sale] <== orderS[sale];

        // The shared signals: the same saleId and sellerId feed the signature check above and
        // the membership check here.
        owned.activeSale[sale] <== activeSale[sale];
        owned.saleId[sale] <== saleId[sale];
        owned.sellerId[sale] <== sellerId[sale];
        owned.units[sale] <== units[sale];
        owned.rootHeight[sale] <== rootHeight[sale];
        owned.position[sale] <== position[sale];
        for (var l = 0; l < levels; l++) {
            for (var index = 0; index < radix; index++) {
                owned.children[sale][l][index] <== children[sale][l][index];
            }
        }
    }
}

template OwnedSignedTreeSmt(saleSlots, buyerSlots, depth, nLevels) {
    // The one public signal.
    signal input statementHash;

    // The ownership root, bound to statementHash.
    signal input utxoRoot;

    // The statement's values.
    signal input funding[buyerSlots];
    signal input feeBudget[buyerSlots];
    signal input refund[buyerSlots];
    signal input totalPayout;
    signal input buyerId[buyerSlots];
    signal input batchHeight;

    // v1 witness.
    signal input price[saleSlots];
    signal input activeSale[saleSlots];
    signal input priceInverse[saleSlots];
    signal input selector[saleSlots][buyerSlots];
    signal input activeBuyer[buyerSlots];
    signal input buyerCountInverse[buyerSlots];
    signal input activeCountInverse;
    signal input saleId[saleSlots];
    signal input sellerId[saleSlots];

    // Seller orders.
    signal input sellerPayoutId[saleSlots];
    signal input orderExpiry[saleSlots];
    signal input sellerAx[saleSlots];
    signal input sellerAy[saleSlots];
    signal input orderR8x[saleSlots];
    signal input orderR8y[saleSlots];
    signal input orderS[saleSlots];

    // Buyer escrow terms.
    signal input escrowId[buyerSlots];
    signal input feeCap[buyerSlots];
    signal input refundScriptId[buyerSlots];
    signal input escrowExpiry[buyerSlots];
    signal input buyerAx[buyerSlots];
    signal input buyerAy[buyerSlots];
    signal input escrowR8x[buyerSlots];
    signal input escrowR8y[buyerSlots];
    signal input escrowS[buyerSlots];

    // The sold outputs' leaves in M5's sparse Merkle tree.
    signal input units[saleSlots];
    signal input rootHeight[saleSlots];
    signal input siblings[saleSlots][nLevels];

    component signedTree = SignedClearingTree(saleSlots, buyerSlots, depth, 1);
    component owned = OwnedSales(saleSlots, nLevels);

    signedTree.statementHash <== statementHash;
    signedTree.extra[0] <== utxoRoot;
    signedTree.totalPayout <== totalPayout;
    signedTree.batchHeight <== batchHeight;
    signedTree.activeCountInverse <== activeCountInverse;
    for (var buyer = 0; buyer < buyerSlots; buyer++) {
        signedTree.funding[buyer] <== funding[buyer];
        signedTree.feeBudget[buyer] <== feeBudget[buyer];
        signedTree.refund[buyer] <== refund[buyer];
        signedTree.buyerId[buyer] <== buyerId[buyer];
        signedTree.activeBuyer[buyer] <== activeBuyer[buyer];
        signedTree.buyerCountInverse[buyer] <== buyerCountInverse[buyer];
        signedTree.escrowId[buyer] <== escrowId[buyer];
        signedTree.feeCap[buyer] <== feeCap[buyer];
        signedTree.refundScriptId[buyer] <== refundScriptId[buyer];
        signedTree.escrowExpiry[buyer] <== escrowExpiry[buyer];
        signedTree.buyerAx[buyer] <== buyerAx[buyer];
        signedTree.buyerAy[buyer] <== buyerAy[buyer];
        signedTree.escrowR8x[buyer] <== escrowR8x[buyer];
        signedTree.escrowR8y[buyer] <== escrowR8y[buyer];
        signedTree.escrowS[buyer] <== escrowS[buyer];
    }

    owned.utxoRoot <== utxoRoot;
    for (var sale = 0; sale < saleSlots; sale++) {
        signedTree.price[sale] <== price[sale];
        signedTree.activeSale[sale] <== activeSale[sale];
        signedTree.priceInverse[sale] <== priceInverse[sale];
        for (var buyer = 0; buyer < buyerSlots; buyer++) {
            signedTree.selector[sale][buyer] <== selector[sale][buyer];
        }
        signedTree.saleId[sale] <== saleId[sale];
        signedTree.sellerId[sale] <== sellerId[sale];
        signedTree.sellerPayoutId[sale] <== sellerPayoutId[sale];
        signedTree.orderExpiry[sale] <== orderExpiry[sale];
        signedTree.sellerAx[sale] <== sellerAx[sale];
        signedTree.sellerAy[sale] <== sellerAy[sale];
        signedTree.orderR8x[sale] <== orderR8x[sale];
        signedTree.orderR8y[sale] <== orderR8y[sale];
        signedTree.orderS[sale] <== orderS[sale];

        owned.activeSale[sale] <== activeSale[sale];
        owned.saleId[sale] <== saleId[sale];
        owned.sellerId[sale] <== sellerId[sale];
        owned.units[sale] <== units[sale];
        owned.rootHeight[sale] <== rootHeight[sale];
        for (var level = 0; level < nLevels; level++) {
            owned.siblings[sale][level] <== siblings[sale][level];
        }
    }
}
