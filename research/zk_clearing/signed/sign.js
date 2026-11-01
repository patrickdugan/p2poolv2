// Turn make_batch.py specs into clearing16x4_signed.circom inputs: derive
// demo BabyJubjub keys, set sellerId/buyerId to Poseidon(Ax, Ay), sign the
// seller orders and buyer escrow terms, and write valid.json, resplit.json
// and one invalid fixture per M4 rule under invalid/.
//
// Demo keys are sha256("p2poolv2 zk_clearing demo key/" + label): public,
// for tests only. Padding slots get a valid signature by a padding key over
// message 0, so the verifier never sees degenerate points.
//
// Usage: node sign.js <node_modules dir> <valid spec> <resplit spec> <out dir>
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const ORDER_TAG = 1n;
const ESCROW_TAG = 2n;

// The signing kit: demo keys, EdDSA-Poseidon signatures, Poseidon over BN254 and the builder that
// turns a spec into signed inputs. main() below uses it, and so does joined/sign_joined.js.
async function createSigner(modules) {
  const { buildEddsa, buildPoseidon } = require(path.join(modules, "circomlibjs"));
  const eddsa = await buildEddsa();
  const poseidonHash = await buildPoseidon();
  const F = eddsa.F;
  const H = (values) => poseidonHash.F.toObject(poseidonHash(values.map((v) => BigInt(v))));

  function key(label) {
    const prv = crypto.createHash("sha256").update("p2poolv2 zk_clearing demo key/" + label).digest();
    const A = eddsa.prv2pub(prv);
    return { prv, Ax: F.toObject(A[0]), Ay: F.toObject(A[1]) };
  }

  function sign(k, message) {
    const signature = eddsa.signPoseidon(k.prv, F.e(message));
    if (!eddsa.verifyPoseidon(F.e(message), signature, [F.e(k.Ax), F.e(k.Ay)])) {
      throw new Error("self-check of a fresh signature failed");
    }
    return { R8x: F.toObject(signature.R8[0]), R8y: F.toObject(signature.R8[1]), S: signature.S };
  }

  function orderMessage(i, s) {
    return H([ORDER_TAG, i.saleId[s], i.price[s], selectedBuyerId(i, s), i.sellerPayoutId[s], i.orderExpiry[s]]);
  }

  function escrowMessage(i, b) {
    return H([ESCROW_TAG, i.escrowId[b], i.funding[b], i.feeCap[b], i.refundScriptId[b], i.escrowExpiry[b]]);
  }

  function selectedBuyerId(i, s) {
    let total = 0n;
    i.selector[s].forEach((bit, b) => { total += BigInt(bit) * BigInt(i.buyerId[b]); });
    return total;
  }

  function signOrder(i, s, k) {
    const signature = sign(k, i.activeSale[s] === "1" || i.activeSale[s] === 1n ? orderMessage(i, s) : 0n);
    i.sellerAx[s] = k.Ax; i.sellerAy[s] = k.Ay;
    i.orderR8x[s] = signature.R8x; i.orderR8y[s] = signature.R8y; i.orderS[s] = signature.S;
  }

  function signEscrow(i, b, k) {
    const signature = sign(k, i.activeBuyer[b] === "1" || i.activeBuyer[b] === 1n ? escrowMessage(i, b) : 0n);
    i.buyerAx[b] = k.Ax; i.buyerAy[b] = k.Ay;
    i.escrowR8x[b] = signature.R8x; i.escrowR8y[b] = signature.R8y; i.escrowS[b] = signature.S;
  }

  const sellerKey = (label, slot) => key(label === null ? "padding-seller-" + slot : "seller/" + label);
  const buyerKey = (label, slot) => key(label === null ? "padding-buyer-" + slot : "buyer/" + label);

  function build(spec) {
    const i = JSON.parse(JSON.stringify(spec.inputs));
    const sales = i.price.length, buyers = i.funding.length;
    for (const name of ["sellerAx", "sellerAy", "orderR8x", "orderR8y", "orderS"]) i[name] = new Array(sales).fill(0n);
    for (const name of ["buyerAx", "buyerAy", "escrowR8x", "escrowR8y", "escrowS"]) i[name] = new Array(buyers).fill(0n);
    const sellerKeys = [], buyerKeys = [];
    for (let b = 0; b < buyers; b++) {
      const label = spec.buyerKeyLabels[b];
      buyerKeys[b] = buyerKey(label, b);
      i.buyerId[b] = label === null ? "0" : H([buyerKeys[b].Ax, buyerKeys[b].Ay]);
    }
    for (let s = 0; s < sales; s++) {
      const label = spec.sellerKeyLabels[s];
      sellerKeys[s] = sellerKey(label, s);
      i.sellerId[s] = label === null ? "0" : H([sellerKeys[s].Ax, sellerKeys[s].Ay]);
    }
    for (let b = 0; b < buyers; b++) signEscrow(i, b, buyerKeys[b]);
    for (let s = 0; s < sales; s++) signOrder(i, s, sellerKeys[s]);
    return { inputs: i, sellerKeys, buyerKeys };
  }

  const r = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  const inverse = (x) => {
    let [a, m, x0, x1] = [((BigInt(x) % r) + r) % r, r, 0n, 1n];
    while (a > 1n) { const q = a / m; [a, m] = [m, a % m]; [x0, x1] = [x1 - q * x0, x0]; }
    return ((x1 % r) + r) % r;
  };
  const write = (file, i) => fs.writeFileSync(file, JSON.stringify(i, (_, v) => (typeof v === "bigint" ? v.toString() : v)));
  const clone = (i) => JSON.parse(JSON.stringify(i, (_, v) => (typeof v === "bigint" ? v.toString() : v)));
  const buyerOf = (i, s) => i.selector[s].findIndex((bit) => String(bit) === "1");

  return { H, sellerKey, build, signOrder, signEscrow, inverse, write, clone, buyerOf };
}

async function main() {
  const [modules, validSpecPath, resplitSpecPath, outDir] = process.argv.slice(2);
  const { build, signOrder, inverse, write, clone, buyerOf } = await createSigner(modules);

  fs.mkdirSync(path.join(outDir, "invalid"), { recursive: true });
  const valid = build(JSON.parse(fs.readFileSync(validSpecPath, "utf8")));
  write(path.join(outDir, "valid.json"), valid.inputs);
  write(path.join(outDir, "resplit.json"), build(JSON.parse(fs.readFileSync(resplitSpecPath, "utf8"))).inputs);

  const invalid = {};
  const mutate = (name, change) => { const i = clone(valid.inputs); change(i); invalid[name] = i; };

  mutate("bad_order_signature", (i) => { i.orderS[0] = (BigInt(i.orderS[0]) + 1n).toString(); });
  mutate("bad_escrow_signature", (i) => { i.escrowS[0] = (BigInt(i.escrowS[0]) + 1n).toString(); });
  // Arithmetic still balances (refund absorbs the change); only the order signature breaks.
  mutate("price_changed_after_signing", (i) => {
    const b = buyerOf(i, 0);
    i.price[0] = (BigInt(i.price[0]) + 1n).toString();
    i.priceInverse[0] = inverse(i.price[0]).toString();
    i.refund[b] = (BigInt(i.refund[b]) - 1n).toString();
    i.totalPayout = (BigInt(i.totalPayout) + 1n).toString();
  });
  mutate("payout_script_swapped", (i) => { i.sellerPayoutId[0] = i.sellerPayoutId[1]; });
  mutate("seller_id_not_signer", (i) => { i.sellerId[0] = i.sellerId[1]; });
  mutate("fee_over_cap", (i) => {
    const raise = BigInt(i.feeCap[0]) + 1n - BigInt(i.feeBudget[0]);
    i.feeBudget[0] = (BigInt(i.feeBudget[0]) + raise).toString();
    i.refund[0] = (BigInt(i.refund[0]) - raise).toString();
  });
  mutate("order_r8_off_curve", (i) => { i.orderR8x[0] = (BigInt(i.orderR8x[0]) + 1n).toString(); });
  // A correctly signed order that expired before the batch height.
  {
    const rebuilt = build(JSON.parse(fs.readFileSync(validSpecPath, "utf8")));
    const i = rebuilt.inputs;
    i.orderExpiry[0] = (BigInt(i.batchHeight) - 1n).toString();
    signOrder(i, 0, rebuilt.sellerKeys[0]);
    invalid["expired_order"] = clone(i);
  }

  for (const [name, i] of Object.entries(invalid)) write(path.join(outDir, "invalid", name + ".json"), i);
  console.log(`wrote valid.json, resplit.json and ${Object.keys(invalid).length} invalid fixtures to ${outDir}`);
  process.exit(0);
}

module.exports = { createSigner };

if (require.main === module) {
  main().catch((error) => { console.error(error); process.exit(1); });
}
