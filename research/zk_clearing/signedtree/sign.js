// Turn gen_batch.py specs into clearing_tree_signed.circom inputs: derive demo BabyJubjub
// keys, set sellerId/buyerId to Poseidon(Ax, Ay), sign the seller orders and buyer escrow
// terms, compute the public statementHash with the circomlibjs reference
// (statement_signed_tree.js), and write valid.json, resplit.json, padded.json and one
// invalid fixture per rule under invalid/.
//
// Demo keys are sha256("p2poolv2 zk_clearing demo key/" + label): public, for tests only.
// Padding slots get a valid signature by a padding key over message 0, so the verifier never
// sees degenerate points.
//
// Usage: node sign.js <node_modules dir> <out dir> <valid spec> <resplit spec> [padded spec]
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { computeStatement } = require("./statement_signed_tree.js");

const ORDER_TAG = 1n;
const ESCROW_TAG = 2n;
const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

async function main() {
  const [modules, outDir, validSpecPath, resplitSpecPath, paddedSpecPath] = process.argv.slice(2);
  const { buildEddsa, buildPoseidon } = require(path.join(modules, "circomlibjs"));
  const eddsa = await buildEddsa();
  const poseidonHash = await buildPoseidon();
  const F = eddsa.F;
  const H = (values) => poseidonHash.F.toObject(poseidonHash(values.map((v) => BigInt(v))));

  const keyCache = new Map();
  function key(label) {
    if (!keyCache.has(label)) {
      const prv = crypto.createHash("sha256").update("p2poolv2 zk_clearing demo key/" + label).digest();
      const A = eddsa.prv2pub(prv);
      keyCache.set(label, { prv, Ax: F.toObject(A[0]), Ay: F.toObject(A[1]) });
    }
    return keyCache.get(label);
  }

  function sign(k, message) {
    const signature = eddsa.signPoseidon(k.prv, F.e(message));
    if (!eddsa.verifyPoseidon(F.e(message), signature, [F.e(k.Ax), F.e(k.Ay)])) {
      throw new Error("self-check of a fresh signature failed");
    }
    return { R8x: F.toObject(signature.R8[0]), R8y: F.toObject(signature.R8[1]), S: signature.S };
  }

  function selectedBuyerId(i, s) {
    let total = 0n;
    i.selector[s].forEach((bit, b) => { total += BigInt(bit) * BigInt(i.buyerId[b]); });
    return total;
  }

  const isActive = (flag) => String(flag) === "1";

  function orderMessage(i, s) {
    return H([ORDER_TAG, i.saleId[s], i.price[s], selectedBuyerId(i, s), i.sellerPayoutId[s], i.orderExpiry[s]]);
  }

  function escrowMessage(i, b) {
    return H([ESCROW_TAG, i.escrowId[b], i.funding[b], i.feeCap[b], i.refundScriptId[b], i.escrowExpiry[b]]);
  }

  function signOrder(i, s, k) {
    const signature = sign(k, isActive(i.activeSale[s]) ? orderMessage(i, s) : 0n);
    i.sellerAx[s] = k.Ax; i.sellerAy[s] = k.Ay;
    i.orderR8x[s] = signature.R8x; i.orderR8y[s] = signature.R8y; i.orderS[s] = signature.S;
  }

  function signEscrow(i, b, k) {
    const signature = sign(k, isActive(i.activeBuyer[b]) ? escrowMessage(i, b) : 0n);
    i.buyerAx[b] = k.Ax; i.buyerAy[b] = k.Ay;
    i.escrowR8x[b] = signature.R8x; i.escrowR8y[b] = signature.R8y; i.escrowS[b] = signature.S;
  }

  const toStrings = (_, v) => (typeof v === "bigint" ? v.toString() : v);
  const clone = (i) => JSON.parse(JSON.stringify(i, toStrings));
  const write = (file, i) => fs.writeFileSync(file, JSON.stringify(i, toStrings));

  // Set the public statementHash from the circomlibjs reference.
  function finish(i) {
    i.statementHash = poseidonHash.F.toString(computeStatement(poseidonHash, i).statementHash);
    return i;
  }

  function build(spec) {
    const i = JSON.parse(JSON.stringify(spec.inputs));
    const sales = i.price.length, buyers = i.funding.length;
    for (const name of ["sellerAx", "sellerAy", "orderR8x", "orderR8y", "orderS"]) i[name] = new Array(sales).fill(0n);
    for (const name of ["buyerAx", "buyerAy", "escrowR8x", "escrowR8y", "escrowS"]) i[name] = new Array(buyers).fill(0n);
    const sellerKeys = [], buyerKeys = [];
    for (let b = 0; b < buyers; b++) {
      const label = spec.buyerKeyLabels[b];
      buyerKeys[b] = key(label === null ? "padding-buyer-" + b : "buyer/" + label);
      i.buyerId[b] = label === null ? "0" : H([buyerKeys[b].Ax, buyerKeys[b].Ay]);
    }
    for (let s = 0; s < sales; s++) {
      const label = spec.sellerKeyLabels[s];
      sellerKeys[s] = key(label === null ? "padding-seller-" + s : "seller/" + label);
      i.sellerId[s] = label === null ? "0" : H([sellerKeys[s].Ax, sellerKeys[s].Ay]);
    }
    for (let b = 0; b < buyers; b++) signEscrow(i, b, buyerKeys[b]);
    for (let s = 0; s < sales; s++) signOrder(i, s, sellerKeys[s]);
    return { inputs: finish(i), sellerKeys, buyerKeys };
  }

  const inverse = (x) => {
    let [a, m, x0, x1] = [((BigInt(x) % R) + R) % R, R, 0n, 1n];
    while (a > 1n) { const q = a / m; [a, m] = [m, a % m]; [x0, x1] = [x1 - q * x0, x0]; }
    return ((x1 % R) + R) % R;
  };
  const buyerOf = (i, s) => i.selector[s].findIndex((bit) => String(bit) === "1");

  fs.mkdirSync(path.join(outDir, "invalid"), { recursive: true });
  const read = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
  const validSpec = read(validSpecPath);
  const valid = build(validSpec);
  write(path.join(outDir, "valid.json"), valid.inputs);
  write(path.join(outDir, "resplit.json"), build(read(resplitSpecPath)).inputs);
  if (paddedSpecPath) write(path.join(outDir, "padded.json"), build(read(paddedSpecPath)).inputs);

  // An invalid fixture: a mutation of the valid inputs, with the statementHash recomputed so
  // the rule it breaks is the only failing one.
  const invalid = {};
  const mutate = (name, change) => { const i = clone(valid.inputs); change(i); invalid[name] = finish(i); };

  mutate("bad_order_signature", (i) => { i.orderS[0] = (BigInt(i.orderS[0]) + 1n).toString(); });
  mutate("bad_escrow_signature", (i) => { i.escrowS[0] = (BigInt(i.escrowS[0]) + 1n).toString(); });
  // The arithmetic still balances (refund absorbs the change); only the order signature breaks.
  mutate("price_changed_after_signing", (i) => {
    const b = buyerOf(i, 0);
    if (BigInt(i.refund[b]) < 1n) throw new Error("no refund to absorb the price change");
    i.price[0] = (BigInt(i.price[0]) + 1n).toString();
    i.priceInverse[0] = inverse(i.price[0]).toString();
    i.refund[b] = (BigInt(i.refund[b]) - 1n).toString();
    i.totalPayout = (BigInt(i.totalPayout) + 1n).toString();
  });
  mutate("payout_script_swapped", (i) => { i.sellerPayoutId[0] = i.sellerPayoutId[1]; });
  mutate("seller_id_not_signer", (i) => { i.sellerId[0] = i.sellerId[1]; });
  // feeBudget one over the signed cap; a refund absorbs the change so funding still balances.
  mutate("fee_over_cap", (i) => {
    const b = i.refund.findIndex((refund, k) => BigInt(refund) >= BigInt(i.feeCap[k]) + 1n - BigInt(i.feeBudget[k]));
    if (b < 0) throw new Error("no buyer has a refund large enough to absorb the fee change");
    const raise = BigInt(i.feeCap[b]) + 1n - BigInt(i.feeBudget[b]);
    i.feeBudget[b] = (BigInt(i.feeBudget[b]) + raise).toString();
    i.refund[b] = (BigInt(i.refund[b]) - raise).toString();
  });
  mutate("order_r8_off_curve", (i) => { i.orderR8x[0] = (BigInt(i.orderR8x[0]) + 1n).toString(); });
  // Correctly signed terms that expired before the batch height.
  {
    const i = clone(valid.inputs);
    i.orderExpiry[0] = (BigInt(i.batchHeight) - 1n).toString();
    signOrder(i, 0, valid.sellerKeys[0]);
    invalid["expired_order"] = finish(clone(i));
  }
  {
    const i = clone(valid.inputs);
    i.escrowExpiry[0] = (BigInt(i.batchHeight) - 1n).toString();
    signEscrow(i, 0, valid.buyerKeys[0]);
    invalid["expired_escrow"] = finish(clone(i));
  }
  // The claimed public hash is not the hash of the statement.
  {
    const i = clone(valid.inputs);
    i.statementHash = ((BigInt(i.statementHash) + 1n) % R).toString();
    invalid["wrong_statement_hash"] = i;
  }

  for (const [name, i] of Object.entries(invalid)) write(path.join(outDir, "invalid", name + ".json"), i);
  console.log(`wrote valid.json, resplit.json${paddedSpecPath ? ", padded.json" : ""} and ${Object.keys(invalid).length} invalid fixtures to ${outDir}`);
  process.exit(0);
}

main().catch((error) => { console.error(error); process.exit(1); });
