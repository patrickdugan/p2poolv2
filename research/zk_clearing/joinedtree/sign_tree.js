// Sign the joined signed-tree fixtures' batches and join each with its membership witness.
//
//   node sign_tree.js sign <node_modules dir> <variants dir> <out dir>
//       for each variant in <variants dir>/manifest.json: sign the batch spec (signed/sign.js,
//       which works for any slot counts), add the membership witness (<name>.own.json), apply the
//       variant's post operations, set the public statementHash (the statement of
//       statement_joined_tree.js, root included) and write the circuit inputs:
//           valid.json, resplit.json, padded.json, valid_<name>.json, invalid/<name>.json
//
// The order keys' hashes come from `node ../joined/sign_joined.js keyhashes`. Order keys are the
// demo keys of signed/sign.js: sha256("p2poolv2 zk_clearing demo key/seller/" + label), public and
// for tests only.
const path = require("path");
const fs = require("fs");
const { createSigner } = require("../signed/sign.js");
const { computeJoinedStatement } = require("./statement_joined_tree.js");

const readJson = (file) => JSON.parse(fs.readFileSync(file, "utf8"));

async function sign(modules, variantsDir, outDir) {
  const { build, write } = await createSigner(modules);
  const poseidon = await require(path.join(modules, "circomlibjs")).buildPoseidon();
  const F = poseidon.F;
  fs.mkdirSync(path.join(outDir, "invalid"), { recursive: true });
  const fixed = { valid: "valid.json", resplit: "resplit.json", padded: "padded.json" };
  let count = 0;
  for (const entry of readJson(path.join(variantsDir, "manifest.json"))) {
    const built = build(readJson(path.join(variantsDir, entry.name + ".spec.json")));
    const inputs = Object.assign(built.inputs, readJson(path.join(variantsDir, entry.name + ".own.json")));
    for (const post of entry.post) {
      if (post.op === "orderS_plus_one") {
        inputs.orderS[post.slot] = (BigInt(inputs.orderS[post.slot]) + 1n).toString();
      } else if (post.op !== "statement_hash_without_root") {
        throw new Error("unknown post operation " + post.op);
      }
    }
    const joined = computeJoinedStatement(poseidon, inputs);
    inputs.statementHash = F.toString(joined.statementHash);
    for (const post of entry.post) {
      if (post.op === "statement_hash_without_root") inputs.statementHash = F.toString(joined.withoutRootStatementHash);
    }
    const file = entry.kind === "invalid" ? path.join("invalid", entry.name + ".json")
      : entry.kind === "valid_extra" ? "valid_" + entry.name + ".json"
      : fixed[entry.kind];
    write(path.join(outDir, file), inputs);
    count += 1;
  }
  console.log(`wrote ${count} joined inputs to ${outDir}`);
}

async function main() {
  const [mode, ...args] = process.argv.slice(2);
  if (mode === "sign" && args.length === 3) await sign(...args);
  else throw new Error("usage: sign_tree.js sign <node_modules dir> <variants dir> <out dir>");
  process.exit(0);
}

main().catch((error) => { console.error(error); process.exit(1); });
