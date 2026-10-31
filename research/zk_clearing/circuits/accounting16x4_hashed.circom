pragma circom 2.1.8;

// v1 with one public signal (M3): the 18 public signals of accounting16x4_committed become
// private, and the proof's only public signal is a Poseidon hash of them.
//
// statement      = [saleCommitment, funding[0..3], feeBudget[0..3], refund[0..3],
//                   totalPayout, buyerId[0..3]]           (v1's public-signal order)
// statementHash  = Poseidon2(Poseidon9(statement[0..8]), Poseidon9(statement[9..17]))
//
// circomlib's Poseidon takes at most 16 inputs, so 18 values need two levels. Two width-10
// sponges under one width-3 keep every arity within what the Rust side (light-poseidon, at
// most 12 inputs) computes with the same circomlib parameters.
//
// A verifier who holds the statement (the operator publishes it with the sale list) hashes
// it and compares with the proof's public signal. The relation proved is v1's, unchanged.

include "committed.circom";
include "circomlib/circuits/poseidon.circom";

template HashedClearing(saleSlots, buyerSlots) {
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

    signal output statementHash;

    component clearing = CommittedClearing(saleSlots, buyerSlots);
    clearing.totalPayout <== totalPayout;
    clearing.activeCountInverse <== activeCountInverse;
    for (var buyer = 0; buyer < buyerSlots; buyer++) {
        clearing.funding[buyer] <== funding[buyer];
        clearing.feeBudget[buyer] <== feeBudget[buyer];
        clearing.refund[buyer] <== refund[buyer];
        clearing.buyerId[buyer] <== buyerId[buyer];
        clearing.activeBuyer[buyer] <== activeBuyer[buyer];
        clearing.buyerCountInverse[buyer] <== buyerCountInverse[buyer];
    }
    for (var sale = 0; sale < saleSlots; sale++) {
        clearing.price[sale] <== price[sale];
        clearing.activeSale[sale] <== activeSale[sale];
        clearing.priceInverse[sale] <== priceInverse[sale];
        clearing.saleId[sale] <== saleId[sale];
        clearing.sellerId[sale] <== sellerId[sale];
        for (var buyer = 0; buyer < buyerSlots; buyer++) {
            clearing.selector[sale][buyer] <== selector[sale][buyer];
        }
    }

    var statementLength = 2 + 4 * buyerSlots;
    signal statement[statementLength];
    statement[0] <== clearing.saleCommitment;
    for (var buyer = 0; buyer < buyerSlots; buyer++) {
        statement[1 + buyer] <== funding[buyer];
        statement[1 + buyerSlots + buyer] <== feeBudget[buyer];
        statement[1 + 2 * buyerSlots + buyer] <== refund[buyer];
        statement[2 + 3 * buyerSlots + buyer] <== buyerId[buyer];
    }
    statement[1 + 3 * buyerSlots] <== totalPayout;

    var half = statementLength \ 2;
    component low = Poseidon(half);
    component high = Poseidon(statementLength - half);
    for (var i = 0; i < half; i++) {
        low.inputs[i] <== statement[i];
    }
    for (var i = half; i < statementLength; i++) {
        high.inputs[i - half] <== statement[i];
    }
    component top = Poseidon(2);
    top.inputs[0] <== low.out;
    top.inputs[1] <== high.out;
    statementHash <== top.out;
}

component main = HashedClearing(16, 4);
