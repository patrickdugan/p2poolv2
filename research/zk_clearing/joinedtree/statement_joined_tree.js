// Reference implementation of the joined circuits' statement hash (clearing_tree_owned.circom),
// with circomlibjs's Poseidon: M11's statement with the ownership root appended.
//
//   statement     = [saleCommitment, escrowCommitment, batchHeight, totalPayout,
//                    funding[], feeBudget[], refund[], buyerId[], ownershipRoot]   (5 + 4B values)
//   statementHash = PoseidonChunked(statement)
//
// The first 4 + 4B values and their commitments are signedtree/statement_signed_tree.js's.
// The ownership root is the input `windowRoot` (dense window tree) or `utxoRoot` (M5's tree).
//
// Usage: node statement_joined_tree.js <node_modules dir> <inputs.json>
// Prints {"saleCommitment", "escrowCommitment", "ownershipRoot", "statement": [decimals],
// "statementHash", "withoutRootStatementHash"} as JSON. The inputs' own statementHash is ignored.
const path = require("path");
const fs = require("fs");
const { computeStatement, hashChunked } = require("../signedtree/statement_signed_tree.js");

function ownershipRootOf(inputs) {
  const root = inputs.windowRoot !== undefined ? inputs.windowRoot : inputs.utxoRoot;
  if (root === undefined) throw new Error("the inputs carry neither windowRoot nor utxoRoot");
  return root;
}

// {saleCommitment, escrowCommitment, ownershipRoot, statement, statementHash,
// withoutRootStatementHash}, all field elements. withoutRootStatementHash is M11's hash.
function computeJoinedStatement(poseidon, inputs) {
  const F = poseidon.F;
  const base = computeStatement(poseidon, inputs);
  const ownershipRoot = F.e(ownershipRootOf(inputs));
  const statement = [...base.statement, ownershipRoot];
  const expected = 5 + 4 * inputs.funding.length;
  if (statement.length !== expected) throw new Error(`statement has ${statement.length} values, expected ${expected}`);
  return {
    saleCommitment: base.saleCommitment,
    escrowCommitment: base.escrowCommitment,
    ownershipRoot,
    statement,
    statementHash: hashChunked(poseidon, statement),
    withoutRootStatementHash: base.statementHash,
  };
}

async function main() {
  const [modules, inputsPath] = process.argv.slice(2);
  const { buildPoseidon } = require(path.join(modules, "circomlibjs"));
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const result = computeJoinedStatement(poseidon, JSON.parse(fs.readFileSync(inputsPath, "utf8")));
  console.log(JSON.stringify({
    saleCommitment: F.toString(result.saleCommitment),
    escrowCommitment: F.toString(result.escrowCommitment),
    ownershipRoot: F.toString(result.ownershipRoot),
    statement: result.statement.map((v) => F.toString(v)),
    statementHash: F.toString(result.statementHash),
    withoutRootStatementHash: F.toString(result.withoutRootStatementHash),
  }));
  process.exit(0);
}

module.exports = { computeJoinedStatement, ownershipRootOf };

if (require.main === module) {
  main().catch((error) => { console.error(error); process.exit(1); });
}
