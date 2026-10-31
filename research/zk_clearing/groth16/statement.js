// Recompute accounting16x4_hashed's statement and statementHash outside the circuit, with
// circomlibjs's Poseidon, from a committed-circuit input JSON.
//
// statement     = [saleCommitment, funding[0..3], feeBudget[0..3], refund[0..3],
//                  totalPayout, buyerId[0..3]]  (accounting16x4_committed's public signals)
// statementHash = Poseidon2(Poseidon9(statement[0..8]), Poseidon9(statement[9..17]))
//
// Usage: node statement.js <node_modules dir> <inputs.json>
// Prints {"statement": [18 decimals], "statementHash": decimal} as JSON.
const path = require("path");
const fs = require("fs");
const { saleCommitment } = require("./commit.js");

async function main() {
  const [modules, inputsPath] = process.argv.slice(2);
  const { buildPoseidon } = require(path.join(modules, "circomlibjs"));
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const inputs = JSON.parse(fs.readFileSync(inputsPath, "utf8"));
  const statement = [
    saleCommitment(poseidon, inputs),
    ...inputs.funding.map((v) => F.e(v)),
    ...inputs.feeBudget.map((v) => F.e(v)),
    ...inputs.refund.map((v) => F.e(v)),
    F.e(inputs.totalPayout),
    ...inputs.buyerId.map((v) => F.e(v)),
  ];
  if (statement.length !== 18) throw new Error(`statement has ${statement.length} values, expected 18`);
  const half = statement.length / 2;
  const hash = poseidon([poseidon(statement.slice(0, half)), poseidon(statement.slice(half))]);
  console.log(JSON.stringify({ statement: statement.map((v) => F.toString(v)), statementHash: F.toString(hash) }));
  process.exit(0);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
