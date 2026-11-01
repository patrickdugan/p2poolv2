pragma circom 2.1.8;

// v2 (M4): v1's arithmetic and sale commitment, plus signed economic terms.
//
// Seller order, signed per active sale with the seller's BabyJubjub order key:
//   M = Poseidon6(ORDER_TAG, saleId, price, buyerId of the selected buyer,
//                 sellerPayoutId, orderExpiry)
// Buyer escrow terms, signed per active buyer with the buyer's order key:
//   M = Poseidon6(ESCROW_TAG, escrowId, funding, feeCap, refundScriptId, escrowExpiry)
//
// sellerId and buyerId are Poseidon(Ax, Ay) of the signing key, so a
// signature only counts for the identity it names. feeBudget <= feeCap and
// batchHeight <= every expiry. Signatures stay private: a verifier learns
// that every committed sale and escrow was signed, not the orders.
//
// Outputs: saleCommitment (leaves now include sellerPayoutId, so the payout
// script is bound) and escrowCommitment (escrow outpoint, funding, fee cap
// and refund script per buyer).
//
// Not proven here: that an order key belongs to the sharechain miner_address
// that owns the share (a one-time registration outside the circuit, or M5's
// ownership tree), or that escrowId names a funded UTXO (the Bitcoin
// transaction graph enforces that).

include "clearing.circom";
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/eddsaposeidon.circom";
include "circomlib/circuits/babyjub.circom";
include "circomlib/circuits/bitify.circom";
include "signed_terms.circom";

template SignedClearing(saleSlots, buyerSlots) {
    // Public.
    signal input funding[buyerSlots];
    signal input feeBudget[buyerSlots];
    signal input refund[buyerSlots];
    signal input totalPayout;
    signal input buyerId[buyerSlots];
    signal input batchHeight;

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

    signal output saleCommitment;
    signal output escrowCommitment;

    component amounts = ClearingAmounts(saleSlots, buyerSlots);
    amounts.totalPayout <== totalPayout;
    amounts.activeCountInverse <== activeCountInverse;

    component heightBound = Bits51();
    heightBound.in <== batchHeight;

    // ---- buyers: identity, signed escrow terms, fee cap, expiry ----
    component buyerKeyHash[buyerSlots];
    component buyerKeyOnCurve[buyerSlots];
    component escrowROnCurve[buyerSlots];
    component escrowMessage[buyerSlots];
    component escrowSig[buyerSlots];
    component feeCapBound[buyerSlots];
    component feeWithinCap[buyerSlots];
    component escrowNotExpired[buyerSlots];
    component escrowLeaf[buyerSlots];
    component escrowRoot = Poseidon(buyerSlots);

    for (var buyer = 0; buyer < buyerSlots; buyer++) {
        amounts.funding[buyer] <== funding[buyer];
        amounts.feeBudget[buyer] <== feeBudget[buyer];
        amounts.refund[buyer] <== refund[buyer];
        amounts.activeBuyer[buyer] <== activeBuyer[buyer];
        amounts.buyerCountInverse[buyer] <== buyerCountInverse[buyer];

        // Unused escrow slots carry no identity or terms.
        (1 - activeBuyer[buyer]) * buyerId[buyer] === 0;
        (1 - activeBuyer[buyer]) * escrowId[buyer] === 0;
        (1 - activeBuyer[buyer]) * feeCap[buyer] === 0;
        (1 - activeBuyer[buyer]) * refundScriptId[buyer] === 0;

        // circomlib's verifier does not check that the points are on the
        // curve; require it for every slot (padding slots use dummy keys).
        buyerKeyOnCurve[buyer] = BabyCheck();
        buyerKeyOnCurve[buyer].x <== buyerAx[buyer];
        buyerKeyOnCurve[buyer].y <== buyerAy[buyer];
        escrowROnCurve[buyer] = BabyCheck();
        escrowROnCurve[buyer].x <== escrowR8x[buyer];
        escrowROnCurve[buyer].y <== escrowR8y[buyer];

        buyerKeyHash[buyer] = Poseidon(2);
        buyerKeyHash[buyer].inputs[0] <== buyerAx[buyer];
        buyerKeyHash[buyer].inputs[1] <== buyerAy[buyer];
        activeBuyer[buyer] * (buyerId[buyer] - buyerKeyHash[buyer].out) === 0;

        escrowMessage[buyer] = Poseidon(6);
        escrowMessage[buyer].inputs[0] <== ESCROW_TAG();
        escrowMessage[buyer].inputs[1] <== escrowId[buyer];
        escrowMessage[buyer].inputs[2] <== funding[buyer];
        escrowMessage[buyer].inputs[3] <== feeCap[buyer];
        escrowMessage[buyer].inputs[4] <== refundScriptId[buyer];
        escrowMessage[buyer].inputs[5] <== escrowExpiry[buyer];

        escrowSig[buyer] = EdDSAPoseidonVerifier();
        escrowSig[buyer].enabled <== activeBuyer[buyer];
        escrowSig[buyer].Ax <== buyerAx[buyer];
        escrowSig[buyer].Ay <== buyerAy[buyer];
        escrowSig[buyer].S <== escrowS[buyer];
        escrowSig[buyer].R8x <== escrowR8x[buyer];
        escrowSig[buyer].R8y <== escrowR8y[buyer];
        escrowSig[buyer].M <== escrowMessage[buyer].out;

        feeCapBound[buyer] = SatoshiAmount();
        feeCapBound[buyer].in <== feeCap[buyer];
        feeWithinCap[buyer] = Bits51();
        feeWithinCap[buyer].in <== feeCap[buyer] - feeBudget[buyer];

        escrowNotExpired[buyer] = AtMostHeight();
        escrowNotExpired[buyer].x <== activeBuyer[buyer] * batchHeight;
        escrowNotExpired[buyer].limit <== activeBuyer[buyer] * escrowExpiry[buyer];

        escrowLeaf[buyer] = Poseidon(5);
        escrowLeaf[buyer].inputs[0] <== activeBuyer[buyer];
        escrowLeaf[buyer].inputs[1] <== escrowId[buyer];
        escrowLeaf[buyer].inputs[2] <== funding[buyer];
        escrowLeaf[buyer].inputs[3] <== feeCap[buyer];
        escrowLeaf[buyer].inputs[4] <== refundScriptId[buyer];
        escrowRoot.inputs[buyer] <== escrowLeaf[buyer].out;
    }
    escrowCommitment <== escrowRoot.out;

    // ---- sales: identity, signed orders, expiry, commitment ----
    signal selectedBuyerTerm[saleSlots][buyerSlots];
    component sellerKeyHash[saleSlots];
    component sellerKeyOnCurve[saleSlots];
    component orderROnCurve[saleSlots];
    component orderMessage[saleSlots];
    component orderSig[saleSlots];
    component orderNotExpired[saleSlots];
    component saleLeaf[saleSlots];
    component saleRoot = Poseidon(saleSlots);

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
        (1 - activeSale[sale]) * sellerPayoutId[sale] === 0;

        sellerKeyOnCurve[sale] = BabyCheck();
        sellerKeyOnCurve[sale].x <== sellerAx[sale];
        sellerKeyOnCurve[sale].y <== sellerAy[sale];
        orderROnCurve[sale] = BabyCheck();
        orderROnCurve[sale].x <== orderR8x[sale];
        orderROnCurve[sale].y <== orderR8y[sale];

        sellerKeyHash[sale] = Poseidon(2);
        sellerKeyHash[sale].inputs[0] <== sellerAx[sale];
        sellerKeyHash[sale].inputs[1] <== sellerAy[sale];
        activeSale[sale] * (sellerId[sale] - sellerKeyHash[sale].out) === 0;

        orderMessage[sale] = Poseidon(6);
        orderMessage[sale].inputs[0] <== ORDER_TAG();
        orderMessage[sale].inputs[1] <== saleId[sale];
        orderMessage[sale].inputs[2] <== price[sale];
        orderMessage[sale].inputs[3] <== selectedBuyerId;
        orderMessage[sale].inputs[4] <== sellerPayoutId[sale];
        orderMessage[sale].inputs[5] <== orderExpiry[sale];

        orderSig[sale] = EdDSAPoseidonVerifier();
        orderSig[sale].enabled <== activeSale[sale];
        orderSig[sale].Ax <== sellerAx[sale];
        orderSig[sale].Ay <== sellerAy[sale];
        orderSig[sale].S <== orderS[sale];
        orderSig[sale].R8x <== orderR8x[sale];
        orderSig[sale].R8y <== orderR8y[sale];
        orderSig[sale].M <== orderMessage[sale].out;

        orderNotExpired[sale] = AtMostHeight();
        orderNotExpired[sale].x <== activeSale[sale] * batchHeight;
        orderNotExpired[sale].limit <== activeSale[sale] * orderExpiry[sale];

        saleLeaf[sale] = Poseidon(6);
        saleLeaf[sale].inputs[0] <== activeSale[sale];
        saleLeaf[sale].inputs[1] <== saleId[sale];
        saleLeaf[sale].inputs[2] <== sellerId[sale];
        saleLeaf[sale].inputs[3] <== price[sale];
        saleLeaf[sale].inputs[4] <== selectedBuyerId;
        saleLeaf[sale].inputs[5] <== sellerPayoutId[sale];
        saleRoot.inputs[sale] <== saleLeaf[sale].out;
    }
    saleCommitment <== saleRoot.out;
}

component main {public [funding, feeBudget, refund, totalPayout, buyerId, batchHeight]} = SignedClearing(16, 4);
