// Recompute accounting16x4_committed's saleCommitment outside the circuit,
// with circomlibjs's Poseidon, from a committed-circuit input JSON.
//
// Usage: node commit.js <node_modules dir> <inputs.json>
// Prints the commitment as a decimal field element.
const path = require("path");
const fs = require("fs");

// saleCommitment of `inputs` as a field element of circomlibjs's `poseidon`.
function saleCommitment(poseidon, inputs) {
  const F = poseidon.F;
  const leaves = inputs.price.map((price, sale) => {
    let selectedBuyerId = F.zero;
    inputs.selector[sale].forEach((bit, buyer) => {
      selectedBuyerId = F.add(selectedBuyerId, F.mul(F.e(bit), F.e(inputs.buyerId[buyer])));
    });
    return poseidon([
      F.e(inputs.activeSale[sale]),
      F.e(inputs.saleId[sale]),
      F.e(inputs.sellerId[sale]),
      F.e(price),
      selectedBuyerId,
    ]);
  });
  return poseidon(leaves);
}

async function main() {
  const [modules, inputsPath] = process.argv.slice(2);
  const { buildPoseidon } = require(path.join(modules, "circomlibjs"));
  const poseidon = await buildPoseidon();
  const inputs = JSON.parse(fs.readFileSync(inputsPath, "utf8"));
  console.log(poseidon.F.toString(saleCommitment(poseidon, inputs)));
  process.exit(0);
}

module.exports = { saleCommitment };

if (require.main === module) {
  main().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
