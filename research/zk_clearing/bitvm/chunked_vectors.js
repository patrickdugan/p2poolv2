// Test vectors for the Rust PoseidonChunked (m1/src/template.rs): statement_signed_tree.js's
// hashChunked with circomlibjs's Poseidon over deterministic values. The values mix small
// numbers with numbers just below r; the lengths cover one Poseidon (1 to 12 values), two
// levels with a short last chunk, exact multiples of 12, and the 144-value maximum.
//
// Usage: node chunked_vectors.js <node_modules dir> > vectors/chunked-hash-vectors.json
const path = require("path");
const { hashChunked } = require("../signedtree/statement_signed_tree.js");

const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const LENGTHS = [1, 2, 8, 11, 12, 13, 18, 20, 23, 24, 25, 36, 37, 72, 143, 144];

async function main() {
  const { buildPoseidon } = require(path.join(process.argv[2], "circomlibjs"));
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const cases = LENGTHS.map((n) => {
    const values = Array.from({ length: n }, (_, i) => (i % 3 === 2 ? R - 1n - BigInt(i) : BigInt(i + 1) * 1000003n + 7n));
    return { values: values.map(String), hash: F.toString(hashChunked(poseidon, values.map((v) => F.e(v)))) };
  });
  console.log(JSON.stringify({ cases }));
  process.exit(0);
}

main().catch((error) => { console.error(error); process.exit(1); });
