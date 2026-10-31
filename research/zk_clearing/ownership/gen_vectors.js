// Generate circomlibjs reference vectors for test_smt.py: Poseidon outputs and a
// scripted sequence of SMT operations (roots after every step, then membership
// and exclusion proofs from circomlibjs's own `find`).
//
// Usage: node gen_vectors.js <node_modules dir> <output json>
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

async function main() {
  const [modules, out] = process.argv.slice(2);
  const lib = require(path.join(modules, "circomlibjs"));
  const pkg = JSON.parse(fs.readFileSync(path.join(modules, "circomlibjs/package.json"), "utf8"));
  const poseidon = await lib.buildPoseidon();
  const F = poseidon.F;
  const dec = (x) => F.toString(x);
  const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

  // Deterministic field elements from SHA-256 of a counter, below 2^253.
  const element = (label) =>
    BigInt("0x" + crypto.createHash("sha256").update(label).digest("hex")) >> 3n;

  const result = { source: `circomlibjs ${pkg.version}`, poseidon: [], smt: {} };

  const poseidonInputs = [
    [1n, 2n],
    [0n, 0n],
    [P - 1n, P - 2n],
    [element("a"), element("b")],
    [1n, 2n, 3n],
    [0n, 0n, 0n],
    [P - 1n, 1n, P - 3n],
    [element("c"), element("d"), element("e")],
    [element("key"), element("value"), 1n],
  ];
  for (const inputs of poseidonInputs) {
    result.poseidon.push({ inputs: inputs.map(String), out: dec(poseidon(inputs)) });
  }

  const smt = await lib.newMemEmptyTrie();
  const ops = [];
  const record = (op, key, value) => ops.push({ op, key: String(key), value: value === undefined ? null : String(value), root: dec(smt.root) });

  const keys = [];
  for (let i = 0; i < 40; i++) keys.push(element(`key-${i}`));
  // Pairs sharing their low `shared` bits, so the tree grows chains of zero siblings.
  for (const shared of [1, 7, 20, 33]) {
    const base = element(`pair-${shared}`);
    keys.push(base, base ^ (1n << BigInt(shared)));
  }
  // A key of all zeros and a key that is the field maximum minus one, as edge cases.
  keys.push(0n, P - 1n);

  const values = new Map();
  for (const [i, key] of keys.entries()) {
    const value = element(`value-${i}`);
    values.set(key, value);
    await smt.insert(key, value);
    record("insert", key, value);
  }
  // Update two values, delete a mix: a plain leaf, one half of a deep pair, a chain pair.
  for (const key of [keys[3], keys[41]]) {
    const value = element(`updated-${key}`);
    values.set(key, value);
    await smt.update(key, value);
    record("update", key, value);
  }
  const deletions = [keys[0], keys[40 + 1], keys[40 + 3], keys[40 + 4], keys[40 + 5]];
  for (const key of deletions) {
    values.delete(key);
    await smt.delete(key);
    record("delete", key);
  }
  result.smt.ops = ops;
  result.smt.finalRoot = dec(smt.root);

  const proofs = [];
  const probe = [...values.keys()].slice(0, 60);
  for (const key of probe) {
    const found = await smt.find(key);
    proofs.push({ key: String(key), found: true, value: dec(found.foundValue), siblings: found.siblings.map(dec) });
  }
  // Non-members: random keys, a key sharing a long prefix with a member, and a deleted key.
  const absent = [element("absent-0"), element("absent-1"), element("absent-2"), element("absent-3"),
    keys[40 + 2] ^ (1n << 50n), deletions[1],
    // Flipping a bit of the deep pair sends the path into an empty slot of its chain.
    keys[40 + 6] ^ (1n << 10n), keys[40 + 6] ^ (1n << 25n)];
  for (const key of absent) {
    const found = await smt.find(key);
    if (found.found) throw new Error("expected an absent key");
    proofs.push({
      key: String(key), found: false, siblings: found.siblings.map(dec),
      notFoundKey: dec(found.notFoundKey), notFoundValue: dec(found.notFoundValue), isOld0: !!found.isOld0,
    });
  }
  result.smt.proofs = proofs;
  fs.writeFileSync(out, JSON.stringify(result, null, 1));
  console.log(`wrote ${out}: ${ops.length} ops, ${proofs.length} proofs, final root ${result.smt.finalRoot}`);
  process.exit(0);
}

main().catch((error) => { console.error(error); process.exit(1); });
