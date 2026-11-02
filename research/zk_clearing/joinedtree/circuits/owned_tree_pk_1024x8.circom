pragma circom 2.1.8;

include "../../circuits/clearing_tree_owned.circom";

component main {public [statementHash]} = OwnedSignedTreePacked(1024, 8, 10, 2, 3, 5);
