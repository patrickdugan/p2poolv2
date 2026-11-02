pragma circom 2.1.8;

include "../../circuits/clearing_tree_owned.circom";

component main {public [statementHash]} = OwnedSignedTreePacked(16, 4, 4, 2, 3, 5);
