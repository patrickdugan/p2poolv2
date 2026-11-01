// Reference implementation of clearing_tree_signed.circom's commitments and statement hash,
// with circomlibjs's Poseidon.
//
//   saleLeaf[s]    = Poseidon6(activeSale, saleId, sellerId, price, selected buyerId, sellerPayoutId)
//   saleCommitment = root of the binary Poseidon2 tree over saleLeaf[0 .. saleSlots - 1]
//   escrowLeaf[b]  = Poseidon5(activeBuyer, escrowId, funding, feeCap, refundScriptId)
//   escrowCommitment = PoseidonChunked(escrowLeaf[0 .. buyerSlots - 1])
//   statement      = [saleCommitment, escrowCommitment, batchHeight, totalPayout,
//                     funding[], feeBudget[], refund[], buyerId[]]    (4 + 4B values)
//   statementHash  = PoseidonChunked(statement)
//
// PoseidonChunked(values): at most 12 values -> one Poseidon call. Otherwise chunks of 12
// (the last may be shorter), one Poseidon per chunk, then one Poseidon over the chunk digests
// (at most 12 of them). No Poseidon call here has more than 12 inputs, the cap of the Rust
// side (light-poseidon).
//
// Usage: node statement_signed_tree.js <node_modules dir> <inputs.json>
// Prints {"saleCommitment", "escrowCommitment", "statement": [decimals], "statementHash"} as
// JSON. The inputs' own statementHash field is ignored: this recomputes it.
const path = require("path");
const fs = require("fs");

const WIDTH = 12;

function hashChunked(poseidon, values) {
  if (values.length < 1) throw new Error("nothing to hash");
  if (values.length <= WIDTH) return poseidon(values);
  const chunks = Math.ceil(values.length / WIDTH);
  if (chunks > WIDTH) throw new Error(`${values.length} values need more than two levels`);
  const digests = [];
  for (let c = 0; c < chunks; c++) digests.push(poseidon(values.slice(c * WIDTH, (c + 1) * WIDTH)));
  return poseidon(digests);
}

function selectedBuyerId(F, i, sale) {
  let selected = F.zero;
  i.selector[sale].forEach((bit, buyer) => {
    selected = F.add(selected, F.mul(F.e(bit), F.e(i.buyerId[buyer])));
  });
  return selected;
}

function saleCommitment(poseidon, i) {
  const F = poseidon.F;
  let level = i.price.map((price, sale) =>
    poseidon([
      F.e(i.activeSale[sale]), F.e(i.saleId[sale]), F.e(i.sellerId[sale]), F.e(price),
      selectedBuyerId(F, i, sale), F.e(i.sellerPayoutId[sale]),
    ]));
  if (level.length & (level.length - 1)) throw new Error("sale slots must be a power of two");
  while (level.length > 1) {
    const next = [];
    for (let k = 0; k < level.length; k += 2) next.push(poseidon([level[k], level[k + 1]]));
    level = next;
  }
  return level[0];
}

function escrowCommitment(poseidon, i) {
  const F = poseidon.F;
  const leaves = i.funding.map((funding, buyer) =>
    poseidon([
      F.e(i.activeBuyer[buyer]), F.e(i.escrowId[buyer]), F.e(funding),
      F.e(i.feeCap[buyer]), F.e(i.refundScriptId[buyer]),
    ]));
  return hashChunked(poseidon, leaves);
}

// {saleCommitment, escrowCommitment, statement, statementHash}, all field elements.
function computeStatement(poseidon, i) {
  const F = poseidon.F;
  const sale = saleCommitment(poseidon, i);
  const escrow = escrowCommitment(poseidon, i);
  const statement = [
    sale, escrow, F.e(i.batchHeight), F.e(i.totalPayout),
    ...i.funding.map((v) => F.e(v)),
    ...i.feeBudget.map((v) => F.e(v)),
    ...i.refund.map((v) => F.e(v)),
    ...i.buyerId.map((v) => F.e(v)),
  ];
  const expected = 4 + 4 * i.funding.length;
  if (statement.length !== expected) throw new Error(`statement has ${statement.length} values, expected ${expected}`);
  return { saleCommitment: sale, escrowCommitment: escrow, statement, statementHash: hashChunked(poseidon, statement) };
}

async function main() {
  const [modules, inputsPath] = process.argv.slice(2);
  const { buildPoseidon } = require(path.join(modules, "circomlibjs"));
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const inputs = JSON.parse(fs.readFileSync(inputsPath, "utf8"));
  const result = computeStatement(poseidon, inputs);
  console.log(JSON.stringify({
    saleCommitment: F.toString(result.saleCommitment),
    escrowCommitment: F.toString(result.escrowCommitment),
    statement: result.statement.map((v) => F.toString(v)),
    statementHash: F.toString(result.statementHash),
  }));
  process.exit(0);
}

module.exports = { computeStatement, hashChunked, saleCommitment, escrowCommitment };

if (require.main === module) {
  main().catch((error) => { console.error(error); process.exit(1); });
}
