pragma circom 2.1.8;

// Research-only BN254/Groth16 arithmetic relation. This is NOT a proof of
// share ownership, authorization, funding UTXOs, or Bitcoin spendability.
// No commitment to a sale order or Bitcoin transaction is verified here.

template Bits51() {
    signal input in;
    signal bit[51];
    var reconstructed = 0;

    for (var index = 0; index < 51; index++) {
        bit[index] <-- (in >> index) & 1;
        bit[index] * (bit[index] - 1) === 0;
        reconstructed += bit[index] * (2 ** index);
    }
    in === reconstructed;
}

// Every amount is an integer in [0, 21,000,000 * 100,000,000] satoshis.
// The two ranges also prevent negative field elements from masquerading as
// large positive amounts. A 51-bit range is sufficient for MAX_SATS.
template SatoshiAmount() {
    signal input in;
    component amount = Bits51();
    component slack = Bits51();
    amount.in <== in;
    slack.in <== 2100000000000000 - in;
}

template ClearingAmounts(saleSlots, buyerSlots) {
    // Only these public inputs are verified by this circuit.
    signal input funding[buyerSlots];
    signal input feeBudget[buyerSlots];
    signal input refund[buyerSlots];
    signal input totalPayout;

    // Private witness. These are unverified caller assertions.
    signal input price[saleSlots];
    signal input activeSale[saleSlots];
    signal input priceInverse[saleSlots];
    signal input selector[saleSlots][buyerSlots];
    signal input activeBuyer[buyerSlots];
    signal input buyerCountInverse[buyerSlots];
    signal input activeCountInverse;

    component priceBounds[saleSlots];
    component fundingBounds[buyerSlots];
    component feeBounds[buyerSlots];
    component refundBounds[buyerSlots];
    component payoutBound = SatoshiAmount();
    payoutBound.in <== totalPayout;

    signal assignmentCost[buyerSlots][saleSlots];
    var saleCount = 0;
    var payoutSum = 0;

    for (var sale = 0; sale < saleSlots; sale++) {
        priceBounds[sale] = SatoshiAmount();
        priceBounds[sale].in <== price[sale];
        activeSale[sale] * (activeSale[sale] - 1) === 0;
        (1 - activeSale[sale]) * price[sale] === 0;
        price[sale] * priceInverse[sale] === activeSale[sale];

        var assignments = 0;
        for (var buyer = 0; buyer < buyerSlots; buyer++) {
            selector[sale][buyer] * (selector[sale][buyer] - 1) === 0;
            assignments += selector[sale][buyer];
        }
        assignments === activeSale[sale];
        saleCount += activeSale[sale];
        payoutSum += price[sale];
    }

    // An empty batch cannot be certified.
    saleCount * activeCountInverse === 1;
    totalPayout === payoutSum;

    for (var buyer = 0; buyer < buyerSlots; buyer++) {
        fundingBounds[buyer] = SatoshiAmount();
        feeBounds[buyer] = SatoshiAmount();
        refundBounds[buyer] = SatoshiAmount();
        fundingBounds[buyer].in <== funding[buyer];
        feeBounds[buyer].in <== feeBudget[buyer];
        refundBounds[buyer].in <== refund[buyer];
        activeBuyer[buyer] * (activeBuyer[buyer] - 1) === 0;

        var buyerCount = 0;
        var buyerCost = 0;
        for (var saleIndex = 0; saleIndex < saleSlots; saleIndex++) {
            assignmentCost[buyer][saleIndex] <== price[saleIndex] * selector[saleIndex][buyer];
            buyerCost += assignmentCost[buyer][saleIndex];
            buyerCount += selector[saleIndex][buyer];
        }
        buyerCount * buyerCountInverse[buyer] === activeBuyer[buyer];
        (1 - activeBuyer[buyer]) * buyerCount === 0;
        (1 - activeBuyer[buyer]) * funding[buyer] === 0;
        (1 - activeBuyer[buyer]) * feeBudget[buyer] === 0;
        (1 - activeBuyer[buyer]) * refund[buyer] === 0;
        funding[buyer] === buyerCost + feeBudget[buyer] + refund[buyer];
    }
}

// Bound a toy proof to sixteen sales and four funding escrows. This circuit
// is far smaller than the proposed 10,000-transfer benchmark.
component main {public [funding, feeBudget, refund, totalPayout]} = ClearingAmounts(16, 4);
