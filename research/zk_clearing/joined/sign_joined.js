// Sign the joined fixtures' batches and join each with its ownership witness.
//
//   node sign_joined.js keyhashes <node_modules dir> <labels.json>
//       prints {label: Poseidon(Ax, Ay)} for the demo order keys named by the labels
//   node sign_joined.js sign <node_modules dir> <variants dir> <out dir>
//       for each variant in <variants dir>/manifest.json: sign the M4 spec (signed/sign.js),
//       add the ownership witness (<name>.own.json), apply the variant's post operations and
//       write the inputs of clearing16x4_owned.circom:
//           valid.json, resplit.json, valid_<name>.json, invalid/<name>.json
//
// Order keys are the demo keys of signed/sign.js: sha256("p2poolv2 zk_clearing demo key/seller/"
// + label), public and for tests only.
const path = require("path");
const fs = require("fs");
const { createSigner } = require("../signed/sign.js");

const readJson = (file) => JSON.parse(fs.readFileSync(file, "utf8"));

async function keyHashes(modules, labelsPath) {
  const { sellerKey, H } = await createSigner(modules);
  const hashes = {};
  for (const label of readJson(labelsPath)) {
    const key = sellerKey(label, 0);
    hashes[label] = H([key.Ax, key.Ay]).toString();
  }
  console.log(JSON.stringify(hashes));
}

async function sign(modules, variantsDir, outDir) {
  const { build, write } = await createSigner(modules);
  fs.mkdirSync(path.join(outDir, "invalid"), { recursive: true });
  const files = { valid: () => "valid.json", resplit: () => "resplit.json" };
  let count = 0;
  for (const entry of readJson(path.join(variantsDir, "manifest.json"))) {
    const built = build(readJson(path.join(variantsDir, entry.name + ".spec.json")));
    const inputs = Object.assign(built.inputs, readJson(path.join(variantsDir, entry.name + ".own.json")));
    for (const post of entry.post) {
      if (post.op === "orderS_plus_one") {
        inputs.orderS[post.slot] = (BigInt(inputs.orderS[post.slot]) + 1n).toString();
      } else {
        throw new Error("unknown post operation " + post.op);
      }
    }
    const file = entry.kind === "invalid" ? path.join("invalid", entry.name + ".json")
      : entry.kind === "valid_extra" ? "valid_" + entry.name + ".json"
      : files[entry.kind]();
    write(path.join(outDir, file), inputs);
    count += 1;
  }
  console.log(`wrote ${count} joined inputs to ${outDir}`);
}

async function main() {
  const [mode, ...args] = process.argv.slice(2);
  if (mode === "keyhashes" && args.length === 2) await keyHashes(...args);
  else if (mode === "sign" && args.length === 3) await sign(...args);
  else throw new Error("usage: sign_joined.js keyhashes <modules> <labels.json> | sign <modules> <variants dir> <out dir>");
  process.exit(0);
}

main().catch((error) => { console.error(error); process.exit(1); });
