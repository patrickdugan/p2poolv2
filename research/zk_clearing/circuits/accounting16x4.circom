pragma circom 2.1.8;

// v0: arithmetic only. The public inputs alone already fix totalPayout and
// each buyer's total cost, and the private sale list is bound to nothing, so
// any re-split of the same totals proves the same statement. Kept as the
// baseline; accounting16x4_committed.circom binds the sale list.

include "clearing.circom";

component main {public [funding, feeBudget, refund, totalPayout]} = ClearingAmounts(16, 4);
