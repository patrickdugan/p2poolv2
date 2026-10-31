pragma circom 2.1.8;

// v1: the v0 arithmetic plus a public Poseidon commitment to the sale list.
//
// saleCommitment = Poseidon16(leaf[0..15])
// leaf[s]        = Poseidon5(activeSale[s], saleId[s], sellerId[s], price[s],
//                            buyerId of the buyer selected by selector[s])
//
// A verifier who holds the sale list recomputes saleCommitment and compares
// it with the proof's public output, so a proof for a different sale list
// with the same totals no longer passes. saleId, sellerId and buyerId are
// field encodings chosen outside the circuit (see witness.py); nothing here
// proves they name real sharechain outputs, real sellers or real escrows.

include "committed.circom";

component main {public [funding, feeBudget, refund, totalPayout, buyerId]} = CommittedClearing(16, 4);
