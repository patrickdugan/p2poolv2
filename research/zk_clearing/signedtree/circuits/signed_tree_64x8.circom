pragma circom 2.1.8;

include "../../circuits/clearing_tree_signed.circom";

component main {public [statementHash]} = SignedClearingTree(64, 8, 6, 0);
