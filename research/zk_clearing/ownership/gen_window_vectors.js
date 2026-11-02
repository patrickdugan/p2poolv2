// Generate circomlibjs reference vectors for test_window_tree.py: Poseidon outputs for 4 and 8
// inputs, and dense window trees (leaf hashes, roots, and the children along chosen paths)
// built with circomlibjs's own Poseidon, independently of window_tree.py.
//
// Usage: node gen_window_vectors.js <node_modules dir> <output json>
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

async function main() {
  const [modules, out] = process.argv.slice(2);
  const lib = require(path.join(modules, "circomlibjs"));
  const pkg = JSON.parse(fs.readFileSync(path.join(modules, "circomlibjs/package.json"), "utf8"));
  const poseidon = await lib.buildPoseidon();
  const F = poseidon.F;
  const H = (values) => F.toString(poseidon(values.map((v) => BigInt(v))));
  const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  const element = (label) => BigInt("0x" + crypto.createHash("sha256").update(label).digest("hex")) >> 3n;

  const result = { source: `circomlibjs ${pkg.version}`, poseidon: [], trees: [], packedTrees: [] };
  const inputs = [
    [1n, 2n, 3n, 4n],
    [0n, 0n, 0n, 0n],
    [P - 1n, P - 2n, 0n, 1n],
    [element("a"), element("b"), element("c"), element("d")],
    [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n],
    [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n],
    [P - 1n, 1n, P - 3n, 2n, P - 5n, 3n, P - 7n, 4n],
    [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n].map((_, i) => element(`w${i}`)),
  ];
  for (const values of inputs) result.poseidon.push({ inputs: values.map(String), out: H(values) });

  // A dense tree of `radixBits`/`levels` over `count` leaves sorted by key. `probes` are positions
  // whose children (the r nodes hashed at every level along the path) are recorded.
  function tree(name, radixBits, levels, count, probes) {
    const radix = 1 << radixBits;
    const keys = [];
    for (let i = 0; i < count; i++) keys.push(element(`${name}-key-${i}`));
    keys.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const leaves = keys.map((key, i) => ({
      key, owner: element(`${name}-owner-${i}`), units: BigInt(1 + ((i * 7919) % 100000000)), rootHeight: BigInt(300000 + i),
    }));
    const capacity = radix ** levels;
    const row0 = [];
    for (let i = 0; i < capacity; i++) {
      row0.push(i < leaves.length ? BigInt(H([leaves[i].key, leaves[i].owner, leaves[i].units, leaves[i].rootHeight])) : 0n);
    }
    const rows = [row0];
    for (let level = 1; level <= levels; level++) {
      const below = rows[level - 1];
      const row = [];
      for (let g = 0; g < below.length / radix; g++) row.push(BigInt(H(below.slice(g * radix, (g + 1) * radix))));
      rows.push(row);
    }
    const paths = probes.map((position) => {
      const children = [];
      for (let level = 0; level < levels; level++) {
        const first = Math.floor(position / radix ** (level + 1)) * radix;
        children.push(rows[level].slice(first, first + radix).map(String));
      }
      return { position, children };
    });
    result.trees.push({
      name, radixBits, levels,
      leaves: leaves.map((l) => ({ key: String(l.key), owner: String(l.owner), units: String(l.units), rootHeight: String(l.rootHeight) })),
      leafHashes: row0.slice(0, leaves.length).map(String),
      root: String(rows[levels][0]),
      paths,
    });
  }

  tree("binary-empty", 1, 3, 0, [0, 5]);
  tree("binary-one", 1, 4, 1, [0, 1, 15]);
  tree("binary-full", 1, 4, 16, [0, 7, 15]);
  tree("binary-partial", 1, 5, 11, [0, 10, 11, 31]);
  tree("binary-production-depth", 1, 17, 9, [0, 8, 9, 131071]);
  tree("radix4-partial", 2, 3, 20, [0, 19, 20, 63]);
  tree("radix8-partial", 3, 3, 37, [0, 36, 37, 511]);
  tree("radix8-six-levels", 3, 6, 5, [0, 4, 5, 262143]);

  // The packed layout (window_tree.PackedWindowTree): bottom nodes hash 2^groupBits (key, owner)
  // records, `levels` levels of radix-way nodes sit above them. `probes` are positions whose bottom
  // node fields and upper children are recorded.
  function packedTree(name, groupBits, radixBits, levels, count, probes) {
    const records = 1 << groupBits;
    const radix = 1 << radixBits;
    const keys = [];
    for (let i = 0; i < count; i++) keys.push(element(`${name}-key-${i}`));
    keys.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const leaves = keys.map((key, i) => ({ key, owner: element(`${name}-owner-${i}`) }));
    const capacity = records * radix ** levels;
    const fieldsOf = (g) => {
      const out = [];
      for (let r = 0; r < records; r++) {
        const i = g * records + r;
        out.push(i < leaves.length ? leaves[i].key : 0n, i < leaves.length ? leaves[i].owner : 0n);
      }
      return out;
    };
    const row0 = [];
    for (let g = 0; g < capacity / records; g++) row0.push(BigInt(H(fieldsOf(g))));
    const rows = [row0];
    for (let level = 1; level <= levels; level++) {
      const below = rows[level - 1];
      const row = [];
      for (let g = 0; g < below.length / radix; g++) row.push(BigInt(H(below.slice(g * radix, (g + 1) * radix))));
      rows.push(row);
    }
    const paths = probes.map((position) => {
      const groupIndex = Math.floor(position / records);
      const children = [];
      for (let level = 0; level < levels; level++) {
        const first = Math.floor(groupIndex / radix ** (level + 1)) * radix;
        children.push(rows[level].slice(first, first + radix).map(String));
      }
      return { position, group: fieldsOf(groupIndex).map(String), children };
    });
    result.packedTrees.push({
      name, groupBits, radixBits, levels,
      leaves: leaves.map((l) => ({ key: String(l.key), owner: String(l.owner) })),
      groupHashes: row0.slice(0, Math.ceil(leaves.length / records)).map(String),
      root: String(rows[levels][0]),
      paths,
    });
  }

  packedTree("packed-empty", 1, 1, 2, 0, [0, 3]);
  packedTree("packed-one", 1, 1, 3, 1, [0, 1, 15]);
  packedTree("packed-partial-binary", 1, 1, 3, 11, [0, 10, 11, 15]);
  packedTree("packed-four-records", 2, 3, 2, 70, [0, 69, 70, 255]);
  packedTree("packed-production-shape", 2, 3, 5, 37, [0, 36, 37, 131071]);

  fs.writeFileSync(out, JSON.stringify(result, null, 1));
  console.log(`wrote ${out}: ${result.poseidon.length} hashes, ${result.trees.length} trees, ${result.packedTrees.length} packed trees`);
  process.exit(0);
}

main().catch((error) => { console.error(error); process.exit(1); });
