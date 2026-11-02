pragma circom 2.1.8;

include "../../circuits/clearing_tree_owned.circom";

component main {public [statementHash]} = OwnedSignedTreePacked(64, 8, 6, 2, 3, 5);
