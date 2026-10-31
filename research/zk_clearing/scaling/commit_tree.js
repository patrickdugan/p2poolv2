// Recompute CommittedClearingTree's saleCommitment with circomlibjs:
// Poseidon5 leaves, then a binary Poseidon2 tree to the root.
//
// Usage: node commit_tree.js <node_modules dir> <inputs.json>
const path = require("path");
const fs = require("fs");

async function main() {
  const [modules, inputsPath] = process.argv.slice(2);
  const { buildPoseidon } = require(path.join(modules, "circomlibjs"));
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const i = JSON.parse(fs.readFileSync(inputsPath, "utf8"));
  let level = i.price.map((price, s) => {
    let selected = F.zero;
    i.selector[s].forEach((bit, b) => { selected = F.add(selected, F.mul(F.e(bit), F.e(i.buyerId[b]))); });
    return poseidon([F.e(i.activeSale[s]), F.e(i.saleId[s]), F.e(i.sellerId[s]), F.e(price), selected]);
  });
  while (level.length > 1) {
    const next = [];
    for (let k = 0; k < level.length; k += 2) next.push(poseidon([level[k], level[k + 1]]));
    level = next;
  }
  console.log(F.toString(level[0]));
  process.exit(0);
}

main().catch((error) => { console.error(error); process.exit(1); });
