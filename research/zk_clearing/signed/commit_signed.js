// Recompute clearing16x4_signed's saleCommitment outside the circuit with
// circomlibjs: Poseidon16 over Poseidon6(activeSale, saleId, sellerId, price,
// selected buyerId, sellerPayoutId) per slot.
//
// Usage: node commit_signed.js <node_modules dir> <inputs.json>
const path = require("path");
const fs = require("fs");

async function main() {
  const [modules, inputsPath] = process.argv.slice(2);
  const { buildPoseidon } = require(path.join(modules, "circomlibjs"));
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const i = JSON.parse(fs.readFileSync(inputsPath, "utf8"));
  const leaves = i.price.map((price, s) => {
    let selected = F.zero;
    i.selector[s].forEach((bit, b) => { selected = F.add(selected, F.mul(F.e(bit), F.e(i.buyerId[b]))); });
    return poseidon([F.e(i.activeSale[s]), F.e(i.saleId[s]), F.e(i.sellerId[s]), F.e(price), selected, F.e(i.sellerPayoutId[s])]);
  });
  console.log(F.toString(poseidon(leaves)));
  process.exit(0);
}

main().catch((error) => { console.error(error); process.exit(1); });
