pragma circom 2.1.8;

include "../../circuits/clearing_tree.circom";

component main {public [funding, feeBudget, refund, totalPayout, buyerId]} = CommittedClearingTree(1024, 8, 10);
