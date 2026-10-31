pragma circom 2.1.8;

include "../../circuits/clearing_tree.circom";

component main {public [funding, feeBudget, refund, totalPayout, buyerId]} = CommittedClearingTree(256, 8, 8);
