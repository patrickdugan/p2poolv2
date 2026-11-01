pragma circom 2.1.8;

// v2 (M4) main: 16 sales x 4 buyers. The templates live in signed_clearing.circom
// so that clearing16x4_owned.circom (M10) can include them without a second main.

include "signed_clearing.circom";

component main {public [funding, feeBudget, refund, totalPayout, buyerId, batchHeight]} = SignedClearing(16, 4);
