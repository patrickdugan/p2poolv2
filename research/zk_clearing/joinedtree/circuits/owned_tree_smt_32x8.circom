pragma circom 2.1.8;

include "../../circuits/clearing_tree_owned.circom";

component main {public [statementHash]} = OwnedSignedTreeSmt(32, 8, 5, 40);
