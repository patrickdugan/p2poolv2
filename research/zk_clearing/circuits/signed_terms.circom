pragma circom 2.1.8;

// Pieces shared by the signed circuits (clearing16x4_signed and
// clearing_tree_signed), in a file without a main component so both can
// include it.

include "circomlib/circuits/bitify.circom";

// Domain tags keep an order signature from being replayed as escrow terms.
function ORDER_TAG() { return 1; }
function ESCROW_TAG() { return 2; }

// Heights from M13's bound graph (bitvm/m2/src/graph.rs). The kickoff confirms by batchHeight +
// DEADLINE_AFTER_BATCH or anyone sweeps its deadline connector, so a seller's order has to
// hold until then. The latest payout is valid from batchHeight + DEADLINE_AFTER_BATCH +
// (T_ASSERT - 1) + T_DISPROVE = batchHeight + 21; an escrow's CLTV refund opens the block after
// its expiry, and has to leave that payout MARGIN = 2 blocks.
function DEADLINE_AFTER_BATCH() { return 4; }
function ESCROW_AFTER_BATCH() { return 22; }

// x <= limit for values below 2^32 (heights), via a 32-bit range check on the gap.
template AtMostHeight() {
    signal input x;
    signal input limit;
    component gap = Num2Bits(32);
    gap.in <== limit - x;
}
