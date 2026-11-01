pragma circom 2.1.8;

// M10: M4's signed clearing joined to M5's sharechain ownership.
//
// SignedClearing (signed_clearing.circom) proves, for every active sale, an
// EdDSA-Poseidon order signature by the BabyJubjub key whose hash is sellerId.
// OwnedSales (ownership/circuits/owned_sale.circom) proves, for the same slot,
//
//     tree(utxoRoot)[ saleId ] = Poseidon( sellerId, units, rootHeight )
//
// Both templates are instantiated unchanged and share the signals saleId,
// sellerId and activeSale. So a sale passes only if the key that signed the
// order is the key hash stored as the owner of the sold output in the tree.
// The tree stores Poseidon(Ax, Ay) of a seller's order key as the owner when
// the key controlling the output's share address has registered that key
// (ownership/register.py); the circuit does not know about registrations, only
// that the leaf's owner equals the signer.
//
// utxoRoot is a new public input, declared last, so the public signals are
// those of clearing16x4_signed followed by utxoRoot. units, rootHeight and the
// 40 siblings per slot are new private inputs. Padding slots carry zeros for
// all of them.
//
// Not proven here: that utxoRoot is the root of the sharechain at a canonical
// anchor, that the registry behind it is current, that a sold output stays
// unspent after the anchor, or that two slots name different outputs. See
// joined/JOINED.md.

include "signed_clearing.circom";
include "../ownership/circuits/owned_sale.circom";

template OwnedClearing(saleSlots, buyerSlots, nLevels) {
    // Public: the signed clearing statement, then the ownership root.
    signal input funding[buyerSlots];
    signal input feeBudget[buyerSlots];
    signal input refund[buyerSlots];
    signal input totalPayout;
    signal input buyerId[buyerSlots];
    signal input batchHeight;
    signal input utxoRoot;

    // Private: v1 witness.
    signal input price[saleSlots];
    signal input activeSale[saleSlots];
    signal input priceInverse[saleSlots];
    signal input selector[saleSlots][buyerSlots];
    signal input activeBuyer[buyerSlots];
    signal input buyerCountInverse[buyerSlots];
    signal input activeCountInverse;
    signal input saleId[saleSlots];
    signal input sellerId[saleSlots];

    // Private: seller orders.
    signal input sellerPayoutId[saleSlots];
    signal input orderExpiry[saleSlots];
    signal input sellerAx[saleSlots];
    signal input sellerAy[saleSlots];
    signal input orderR8x[saleSlots];
    signal input orderR8y[saleSlots];
    signal input orderS[saleSlots];

    // Private: buyer escrow terms.
    signal input escrowId[buyerSlots];
    signal input feeCap[buyerSlots];
    signal input refundScriptId[buyerSlots];
    signal input escrowExpiry[buyerSlots];
    signal input buyerAx[buyerSlots];
    signal input buyerAy[buyerSlots];
    signal input escrowR8x[buyerSlots];
    signal input escrowR8y[buyerSlots];
    signal input escrowS[buyerSlots];

    // Private: the sold outputs' leaves in the ownership tree.
    signal input units[saleSlots];
    signal input rootHeight[saleSlots];
    signal input siblings[saleSlots][nLevels];

    signal output saleCommitment;
    signal output escrowCommitment;

    component clearing = SignedClearing(saleSlots, buyerSlots);
    component owned = OwnedSales(saleSlots, nLevels);

    for (var buyer = 0; buyer < buyerSlots; buyer++) {
        clearing.funding[buyer] <== funding[buyer];
        clearing.feeBudget[buyer] <== feeBudget[buyer];
        clearing.refund[buyer] <== refund[buyer];
        clearing.buyerId[buyer] <== buyerId[buyer];
        clearing.activeBuyer[buyer] <== activeBuyer[buyer];
        clearing.buyerCountInverse[buyer] <== buyerCountInverse[buyer];
        clearing.escrowId[buyer] <== escrowId[buyer];
        clearing.feeCap[buyer] <== feeCap[buyer];
        clearing.refundScriptId[buyer] <== refundScriptId[buyer];
        clearing.escrowExpiry[buyer] <== escrowExpiry[buyer];
        clearing.buyerAx[buyer] <== buyerAx[buyer];
        clearing.buyerAy[buyer] <== buyerAy[buyer];
        clearing.escrowR8x[buyer] <== escrowR8x[buyer];
        clearing.escrowR8y[buyer] <== escrowR8y[buyer];
        clearing.escrowS[buyer] <== escrowS[buyer];
    }
    clearing.totalPayout <== totalPayout;
    clearing.batchHeight <== batchHeight;
    clearing.activeCountInverse <== activeCountInverse;

    owned.utxoRoot <== utxoRoot;
    for (var sale = 0; sale < saleSlots; sale++) {
        clearing.price[sale] <== price[sale];
        clearing.activeSale[sale] <== activeSale[sale];
        clearing.priceInverse[sale] <== priceInverse[sale];
        for (var buyer = 0; buyer < buyerSlots; buyer++) {
            clearing.selector[sale][buyer] <== selector[sale][buyer];
        }
        clearing.saleId[sale] <== saleId[sale];
        clearing.sellerId[sale] <== sellerId[sale];
        clearing.sellerPayoutId[sale] <== sellerPayoutId[sale];
        clearing.orderExpiry[sale] <== orderExpiry[sale];
        clearing.sellerAx[sale] <== sellerAx[sale];
        clearing.sellerAy[sale] <== sellerAy[sale];
        clearing.orderR8x[sale] <== orderR8x[sale];
        clearing.orderR8y[sale] <== orderR8y[sale];
        clearing.orderS[sale] <== orderS[sale];

        // The shared signals: the same saleId and sellerId feed the signature
        // check above and the membership check here.
        owned.activeSale[sale] <== activeSale[sale];
        owned.saleId[sale] <== saleId[sale];
        owned.sellerId[sale] <== sellerId[sale];
        owned.units[sale] <== units[sale];
        owned.rootHeight[sale] <== rootHeight[sale];
        for (var level = 0; level < nLevels; level++) {
            owned.siblings[sale][level] <== siblings[sale][level];
        }
    }

    saleCommitment <== clearing.saleCommitment;
    escrowCommitment <== clearing.escrowCommitment;
}

component main {public [funding, feeBudget, refund, totalPayout, buyerId, batchHeight, utxoRoot]} = OwnedClearing(16, 4, 40);
