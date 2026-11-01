pragma circom 2.1.8;

// Pieces shared by the signed circuits (clearing16x4_signed and
// clearing_tree_signed), in a file without a main component so both can
// include it.

include "circomlib/circuits/bitify.circom";

// Domain tags keep an order signature from being replayed as escrow terms.
function ORDER_TAG() { return 1; }
function ESCROW_TAG() { return 2; }

// x <= limit for values below 2^32 (heights), via a 32-bit range check on the gap.
template AtMostHeight() {
    signal input x;
    signal input limit;
    component gap = Num2Bits(32);
    gap.in <== limit - x;
}
