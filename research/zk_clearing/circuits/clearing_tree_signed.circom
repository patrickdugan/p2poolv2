pragma circom 2.1.8;

// M11: M4's signed economic terms on M6's binary Poseidon tree, behind M3's single hashed
// public input, at any power-of-two batch size.
//
// The proof's only public signal is statementHash. Everything else is private.
//
//   statement     = [saleCommitment, escrowCommitment, batchHeight, totalPayout,
//                    funding[0..B-1], feeBudget[0..B-1], refund[0..B-1], buyerId[0..B-1]]
//                   (4 + 4B values, B = buyerSlots)
//   statementHash = PoseidonChunked(statement)
//
// PoseidonChunked hashes up to 12 values with one Poseidon call. Longer lists are cut into
// chunks of 12 (the last one may be shorter), each chunk is hashed, and the chunk digests are
// hashed together. M3's 18 values were Poseidon2(Poseidon9, Poseidon9); this is the same shape
// for any length up to 144. Every Poseidon call in the circuit has at most 12 inputs, the cap
// of the Rust side (light-poseidon) that recomputes the hash.
//
// Per active sale (M4):
//   - an EdDSA-Poseidon signature by the seller's BabyJubjub order key over
//     Poseidon6(ORDER_TAG, saleId, price, selected buyerId, sellerPayoutId, orderExpiry);
//   - sellerId = Poseidon(Ax, Ay) of that key;
//   - batchHeight <= orderExpiry.
// Per active buyer (M4):
//   - a signature over Poseidon6(ESCROW_TAG, escrowId, funding, feeCap, refundScriptId,
//     escrowExpiry) by the buyer's order key; buyerId = Poseidon(Ax, Ay);
//   - feeBudget <= feeCap and batchHeight <= escrowExpiry.
// A and R8 are checked to lie on BabyJubjub in every slot. Padding slots carry a valid
// signature from a padding key over message 0, and the verifier's `enabled` input is the
// slot's active flag.
//
// saleCommitment is the root of the binary Poseidon2 tree (M6) over Poseidon6 sale leaves
// (activeSale, saleId, sellerId, price, selected buyerId, sellerPayoutId). escrowCommitment is
// PoseidonChunked over each buyer's Poseidon5 escrow leaf (active, escrowId, funding, feeCap,
// refundScriptId); up to 12 buyer slots it is a single Poseidon.
//
// statementHash is a public input constrained to equal the hash of the statement, so a wrong
// claimed hash fails in the witness calculator. Its wire is the same as an output's would be.
//
// Not proven here: that an order key belongs to the sharechain miner_address that owns the
// share, or that escrowId names a funded UTXO (see SIGNED.md).

include "clearing_tree.circom";
include "signed_terms.circom";
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/eddsaposeidon.circom";
include "circomlib/circuits/babyjub.circom";

function POSEIDON_MAX_INPUTS() { return 12; }

// Poseidon over n values with every call at most POSEIDON_MAX_INPUTS wide.
template PoseidonChunked(n) {
    var width = POSEIDON_MAX_INPUTS();
    var chunks = (n + width - 1) \ width;
    assert(n >= 1);
    assert(chunks <= width);

    signal input in[n];
    signal output out;

    if (chunks == 1) {
        component single = Poseidon(n);
        for (var index = 0; index < n; index++) {
            single.inputs[index] <== in[index];
        }
        out <== single.out;
    } else {
        component chunk[chunks];
        component top = Poseidon(chunks);
        for (var c = 0; c < chunks; c++) {
            var size = (c == chunks - 1) ? n - width * (chunks - 1) : width;
            chunk[c] = Poseidon(size);
            for (var index = 0; index < size; index++) {
                chunk[c].inputs[index] <== in[width * c + index];
            }
            top.inputs[c] <== chunk[c].out;
        }
        out <== top.out;
    }
}

// One seller order slot: identity, signature, expiry. `buyerId` is the selected buyer's ID.
template SignedOrder() {
    signal input active;
    signal input saleId;
    signal input sellerId;
    signal input price;
    signal input buyerId;
    signal input sellerPayoutId;
    signal input orderExpiry;
    signal input batchHeight;
    signal input Ax;
    signal input Ay;
    signal input R8x;
    signal input R8y;
    signal input S;

    // Unused sale slots carry no identity or payout script.
    (1 - active) * saleId === 0;
    (1 - active) * sellerId === 0;
    (1 - active) * sellerPayoutId === 0;

    // circomlib's verifier does not check that the points are on the curve.
    component keyOnCurve = BabyCheck();
    keyOnCurve.x <== Ax;
    keyOnCurve.y <== Ay;
    component rOnCurve = BabyCheck();
    rOnCurve.x <== R8x;
    rOnCurve.y <== R8y;

    component keyHash = Poseidon(2);
    keyHash.inputs[0] <== Ax;
    keyHash.inputs[1] <== Ay;
    active * (sellerId - keyHash.out) === 0;

    component message = Poseidon(6);
    message.inputs[0] <== ORDER_TAG();
    message.inputs[1] <== saleId;
    message.inputs[2] <== price;
    message.inputs[3] <== buyerId;
    message.inputs[4] <== sellerPayoutId;
    message.inputs[5] <== orderExpiry;

    component sig = EdDSAPoseidonVerifier();
    sig.enabled <== active;
    sig.Ax <== Ax;
    sig.Ay <== Ay;
    sig.S <== S;
    sig.R8x <== R8x;
    sig.R8y <== R8y;
    sig.M <== message.out;

    component notExpired = AtMostHeight();
    notExpired.x <== active * batchHeight;
    notExpired.limit <== active * orderExpiry;
}

// One buyer escrow slot: identity, signed terms, fee cap, expiry.
template SignedEscrow() {
    signal input active;
    signal input buyerId;
    signal input escrowId;
    signal input funding;
    signal input feeBudget;
    signal input feeCap;
    signal input refundScriptId;
    signal input escrowExpiry;
    signal input batchHeight;
    signal input Ax;
    signal input Ay;
    signal input R8x;
    signal input R8y;
    signal input S;

    // Unused escrow slots carry no identity or terms.
    (1 - active) * buyerId === 0;
    (1 - active) * escrowId === 0;
    (1 - active) * feeCap === 0;
    (1 - active) * refundScriptId === 0;

    component keyOnCurve = BabyCheck();
    keyOnCurve.x <== Ax;
    keyOnCurve.y <== Ay;
    component rOnCurve = BabyCheck();
    rOnCurve.x <== R8x;
    rOnCurve.y <== R8y;

    component keyHash = Poseidon(2);
    keyHash.inputs[0] <== Ax;
    keyHash.inputs[1] <== Ay;
    active * (buyerId - keyHash.out) === 0;

    component message = Poseidon(6);
    message.inputs[0] <== ESCROW_TAG();
    message.inputs[1] <== escrowId;
    message.inputs[2] <== funding;
    message.inputs[3] <== feeCap;
    message.inputs[4] <== refundScriptId;
    message.inputs[5] <== escrowExpiry;

    component sig = EdDSAPoseidonVerifier();
    sig.enabled <== active;
    sig.Ax <== Ax;
    sig.Ay <== Ay;
    sig.S <== S;
    sig.R8x <== R8x;
    sig.R8y <== R8y;
    sig.M <== message.out;

    component feeCapBound = SatoshiAmount();
    feeCapBound.in <== feeCap;
    component feeWithinCap = Bits51();
    feeWithinCap.in <== feeCap - feeBudget;

    component notExpired = AtMostHeight();
    notExpired.x <== active * batchHeight;
    notExpired.limit <== active * escrowExpiry;
}

template SignedClearingTree(saleSlots, buyerSlots, depth) {
    assert(saleSlots == (1 << depth));

    // The statement's values.
    signal input funding[buyerSlots];
    signal input feeBudget[buyerSlots];
    signal input refund[buyerSlots];
    signal input totalPayout;
    signal input buyerId[buyerSlots];
    signal input batchHeight;

    // The one public signal.
    signal input statementHash;

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

    component amounts = ClearingAmounts(saleSlots, buyerSlots);
    amounts.totalPayout <== totalPayout;
    amounts.activeCountInverse <== activeCountInverse;

    component heightBound = Bits51();
    heightBound.in <== batchHeight;

    // ---- buyers: signed escrow terms and the escrow commitment ----
    component escrow[buyerSlots];
    component escrowLeaf[buyerSlots];
    component escrowRoot = PoseidonChunked(buyerSlots);

    for (var buyer = 0; buyer < buyerSlots; buyer++) {
        amounts.funding[buyer] <== funding[buyer];
        amounts.feeBudget[buyer] <== feeBudget[buyer];
        amounts.refund[buyer] <== refund[buyer];
        amounts.activeBuyer[buyer] <== activeBuyer[buyer];
        amounts.buyerCountInverse[buyer] <== buyerCountInverse[buyer];

        escrow[buyer] = SignedEscrow();
        escrow[buyer].active <== activeBuyer[buyer];
        escrow[buyer].buyerId <== buyerId[buyer];
        escrow[buyer].escrowId <== escrowId[buyer];
        escrow[buyer].funding <== funding[buyer];
        escrow[buyer].feeBudget <== feeBudget[buyer];
        escrow[buyer].feeCap <== feeCap[buyer];
        escrow[buyer].refundScriptId <== refundScriptId[buyer];
        escrow[buyer].escrowExpiry <== escrowExpiry[buyer];
        escrow[buyer].batchHeight <== batchHeight;
        escrow[buyer].Ax <== buyerAx[buyer];
        escrow[buyer].Ay <== buyerAy[buyer];
        escrow[buyer].R8x <== escrowR8x[buyer];
        escrow[buyer].R8y <== escrowR8y[buyer];
        escrow[buyer].S <== escrowS[buyer];

        escrowLeaf[buyer] = Poseidon(5);
        escrowLeaf[buyer].inputs[0] <== activeBuyer[buyer];
        escrowLeaf[buyer].inputs[1] <== escrowId[buyer];
        escrowLeaf[buyer].inputs[2] <== funding[buyer];
        escrowLeaf[buyer].inputs[3] <== feeCap[buyer];
        escrowLeaf[buyer].inputs[4] <== refundScriptId[buyer];
        escrowRoot.in[buyer] <== escrowLeaf[buyer].out;
    }

    // ---- sales: signed orders and the binary sale tree ----
    signal selectedBuyerTerm[saleSlots][buyerSlots];
    component order[saleSlots];
    component saleLeaf[saleSlots];
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

        order[sale] = SignedOrder();
        order[sale].active <== activeSale[sale];
        order[sale].saleId <== saleId[sale];
        order[sale].sellerId <== sellerId[sale];
        order[sale].price <== price[sale];
        order[sale].buyerId <== selectedBuyerId;
        order[sale].sellerPayoutId <== sellerPayoutId[sale];
        order[sale].orderExpiry <== orderExpiry[sale];
        order[sale].batchHeight <== batchHeight;
        order[sale].Ax <== sellerAx[sale];
        order[sale].Ay <== sellerAy[sale];
        order[sale].R8x <== orderR8x[sale];
        order[sale].R8y <== orderR8y[sale];
        order[sale].S <== orderS[sale];

        saleLeaf[sale] = Poseidon(6);
        saleLeaf[sale].inputs[0] <== activeSale[sale];
        saleLeaf[sale].inputs[1] <== saleId[sale];
        saleLeaf[sale].inputs[2] <== sellerId[sale];
        saleLeaf[sale].inputs[3] <== price[sale];
        saleLeaf[sale].inputs[4] <== selectedBuyerId;
        saleLeaf[sale].inputs[5] <== sellerPayoutId[sale];
        tree.leaves[sale] <== saleLeaf[sale].out;
    }

    // ---- the one public input ----
    var statementLength = 4 + 4 * buyerSlots;
    component statement = PoseidonChunked(statementLength);
    statement.in[0] <== tree.root;
    statement.in[1] <== escrowRoot.out;
    statement.in[2] <== batchHeight;
    statement.in[3] <== totalPayout;
    for (var buyer = 0; buyer < buyerSlots; buyer++) {
        statement.in[4 + buyer] <== funding[buyer];
        statement.in[4 + buyerSlots + buyer] <== feeBudget[buyer];
        statement.in[4 + 2 * buyerSlots + buyer] <== refund[buyer];
        statement.in[4 + 3 * buyerSlots + buyer] <== buyerId[buyer];
    }
    statementHash === statement.out;
}
