// Extract the Poseidon round constants and MDS matrices for t = 3 and t = 4
// (two- and three-input hashes) from the pinned circomlibjs, which are the
// constants circomlib's Poseidon circuit uses. Writes poseidon_bn254.json.
//
// Usage: node extract_poseidon_constants.js <node_modules dir> <output json>
const fs = require("fs");
const path = require("path");

const [modules, out] = process.argv.slice(2);
const pkg = JSON.parse(fs.readFileSync(path.join(modules, "circomlibjs/package.json"), "utf8"));
const constants = JSON.parse(
  fs.readFileSync(path.join(modules, "circomlibjs/src/poseidon_constants.json"), "utf8")
);
const N_ROUNDS_F = 8;
const N_ROUNDS_P = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68];
const toDec = (hex) => BigInt(hex).toString();
const result = {
  source: `circomlibjs ${pkg.version} src/poseidon_constants.json`,
  prime: "21888242871839275222246405745257275088548364400416034343698204186575808495617",
  nRoundsF: N_ROUNDS_F,
  params: {},
};
for (const t of [3, 4]) {
  result.params[t] = {
    nRoundsP: N_ROUNDS_P[t - 2],
    C: constants.C[t - 2].map(toDec),
    M: constants.M[t - 2].map((row) => row.map(toDec)),
  };
}
fs.writeFileSync(out, JSON.stringify(result));
console.log(`wrote ${out}`);
