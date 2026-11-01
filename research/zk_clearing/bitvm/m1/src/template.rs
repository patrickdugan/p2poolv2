//! The payout template: transaction outputs as a deterministic function of the 18 public
//! signals of accounting16x4_committed and the opened sale list.
//!
//! M3 (accounting16x4_hashed) proves the same 18 values as a private statement whose
//! Poseidon hash is the only public signal; `build_hashed` checks that preimage and then
//! builds exactly the M1 template.
//!
//! Public signal layout (snarkjs order: outputs, then public inputs in declaration order):
//!   0 saleCommitment | 1..=4 funding[b] | 5..=8 feeBudget[b] | 9..=12 refund[b]
//!   13 totalPayout | 14..=17 buyerId[b]
//!
//! The template checks only what building the transaction needs: canonical signals, the
//! sale-list opening against saleCommitment, sum of prices = totalPayout, conservation of
//! the escrowed value, and no dust output. The per-buyer equation
//! funding[b] = cost[b] + feeBudget[b] + refund[b] is the proof's job, not the template's.
//!
//! M14 (signed_tree_SxB, M11's circuit) has a 4 + 4B value statement hashed by PoseidonChunked:
//!   0 saleCommitment | 1 escrowCommitment | 2 batchHeight | 3 totalPayout
//!   then funding[b], feeBudget[b], refund[b], buyerId[b] for b in 0..B
//! `build_signed` checks the preimage, opens both commitments from the committee's copy of the
//! sale list and escrow terms, and requires every payout script, refund script and escrow the
//! graph uses to be the one the signed terms name (the commitments contain those ids). Then it
//! builds the same outputs as M1's template. `Kind` selects between the two layouts.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use light_poseidon::{Poseidon, PoseidonHasher};
use num_bigint::BigUint;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const BUYER_SLOTS: usize = 4;
pub const NUM_SIGNALS: usize = 18;
pub const MAX_SATS: u64 = 21_000_000 * 100_000_000;
/// Bitcoin Core's dust threshold for a P2TR output at the default dust relay fee.
pub const P2TR_DUST: u64 = 330;
/// accounting16x4_hashed hashes the statement as two Poseidon sponges of this many values.
pub const STATEMENT_SPLIT: usize = 9;

pub const SALE_COMMITMENT: usize = 0;
pub const fn funding(b: usize) -> usize { 1 + b }
pub const fn fee_budget(b: usize) -> usize { 5 + b }
pub const fn refund(b: usize) -> usize { 9 + b }
pub const TOTAL_PAYOUT: usize = 13;
pub const fn buyer_id(b: usize) -> usize { 14 + b }

pub fn signal_name(index: usize) -> String {
    match index {
        0 => "saleCommitment".into(),
        1..=4 => format!("funding[{}]", index - 1),
        5..=8 => format!("feeBudget[{}]", index - 5),
        9..=12 => format!("refund[{}]", index - 9),
        13 => "totalPayout".into(),
        14..=17 => format!("buyerId[{}]", index - 14),
        _ => format!("signal[{index}]"),
    }
}

/// One escrow per active buyer slot: (slot, buyer label, amount).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EscrowSpec {
    pub slot: usize,
    pub buyer: String,
    pub amount: u64,
}

/// A payout output by payee label, in template order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutSpec {
    pub role: &'static str,
    pub payee: String,
    pub amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Template {
    pub escrows: Vec<EscrowSpec>,
    pub outputs: Vec<PayoutSpec>,
}

fn decimal(value: &Value) -> Result<BigUint, String> {
    zkc_convert::parse_decimal(value, "input").map_err(|e| e.0)
}

fn small(n: &BigUint, what: &str) -> Result<u64, String> {
    let digits = n.to_u64_digits();
    match digits.len() {
        0 => Ok(0),
        1 => Ok(digits[0]),
        _ => Err(format!("{what} does not fit in u64")),
    }
}

/// `signals`: the 18 public signals as integers. `input`: the circuit input JSON (the sale list
/// fields price, activeSale, saleId, sellerId, selector and buyerId). `opening`: payee labels per
/// slot. `opening_commitment`: Poseidon of that sale list, computed outside (commit.js).
pub fn build(signals: &[BigUint], input: &Value, opening: &Value, opening_commitment: &BigUint) -> Result<Template, String> {
    if signals.len() != NUM_SIGNALS {
        return Err(format!("{} public signals, expected {NUM_SIGNALS}", signals.len()));
    }
    let r = zkc_convert::fr_modulus();
    for (i, s) in signals.iter().enumerate() {
        if s >= &r {
            return Err(format!("{} is not below r", signal_name(i)));
        }
    }
    let amount = |i: usize| -> Result<u64, String> {
        let v = small(&signals[i], &signal_name(i))?;
        if v > MAX_SATS {
            return Err(format!("{} exceeds MAX_SATS", signal_name(i)));
        }
        Ok(v)
    };
    if &signals[SALE_COMMITMENT] != opening_commitment {
        return Err("saleCommitment does not open to the given sale list".into());
    }
    for b in 0..BUYER_SLOTS {
        if signals[buyer_id(b)] != decimal(&input["buyerId"][b])? {
            return Err(format!("buyerId[{b}] differs from the sale list the commitment opens to"));
        }
    }
    let amounts = Amounts {
        total_payout: amount(TOTAL_PAYOUT)?,
        funding: (0..BUYER_SLOTS).map(|b| amount(funding(b))).collect::<Result<_, _>>()?,
        fee_budget: (0..BUYER_SLOTS).map(|b| amount(fee_budget(b))).collect::<Result<_, _>>()?,
        refund: (0..BUYER_SLOTS).map(|b| amount(refund(b))).collect::<Result<_, _>>()?,
    };
    assemble(input, opening, &amounts)
}

/// The amounts of a statement, in sats, per buyer slot.
struct Amounts {
    total_payout: u64,
    funding: Vec<u64>,
    fee_budget: Vec<u64>,
    refund: Vec<u64>,
}

/// How many entries the list `input[field]` has.
fn array_len(input: &Value, field: &str) -> Result<usize, String> {
    input[field].as_array().map(Vec::len).ok_or(format!("the input has no {field} list"))
}

/// The outputs and escrows for checked amounts: the sale list gives the seller payouts, the
/// opening the payee labels.
fn assemble(input: &Value, opening: &Value, amounts: &Amounts) -> Result<Template, String> {
    // Seller payouts: active sale slots in order, merged by payee at first appearance.
    let mut outputs: Vec<PayoutSpec> = vec![];
    let mut price_sum: u64 = 0;
    for s in 0..array_len(input, "activeSale")? {
        let active = small(&decimal(&input["activeSale"][s])?, "activeSale")?;
        let price = small(&decimal(&input["price"][s])?, "price")?;
        if active == 0 {
            continue;
        }
        let payee = opening["sale_slots"][s]["seller_payee"]
            .as_str()
            .ok_or(format!("sale slot {s} is active but has no seller payee"))?;
        price_sum = price_sum.checked_add(price).ok_or("price overflow")?;
        match outputs.iter_mut().find(|o| o.payee == payee) {
            Some(existing) => existing.amount += price,
            None => outputs.push(PayoutSpec { role: "seller", payee: payee.to_string(), amount: price }),
        }
    }
    if price_sum != amounts.total_payout {
        return Err(format!("sale prices sum to {price_sum}, totalPayout is {}", amounts.total_payout));
    }

    let mut escrows = vec![];
    let mut funding_sum: u64 = 0;
    let mut fee_sum: u64 = 0;
    for b in 0..amounts.funding.len() {
        let fund = amounts.funding[b];
        if fund == 0 {
            if amounts.refund[b] != 0 || amounts.fee_budget[b] != 0 {
                return Err(format!("unfunded buyer slot {b} carries a refund or fee"));
            }
            continue;
        }
        let buyer = opening["buyer_slots"][b]["buyer"].as_str().ok_or(format!("buyer slot {b} has no buyer"))?;
        let refund_payee = opening["buyer_slots"][b]["refund_payee"].as_str().ok_or(format!("buyer slot {b} has no refund payee"))?;
        escrows.push(EscrowSpec { slot: b, buyer: buyer.to_string(), amount: fund });
        funding_sum += fund;
        fee_sum += amounts.fee_budget[b];
        let back = amounts.refund[b];
        if back > 0 {
            outputs.push(PayoutSpec { role: "refund", payee: refund_payee.to_string(), amount: back });
        }
    }
    if fee_sum > 0 {
        let payee = opening["fee_payee"].as_str().ok_or("no fee payee")?;
        outputs.push(PayoutSpec { role: "fee", payee: payee.to_string(), amount: fee_sum });
    }
    let paid: u64 = outputs.iter().map(|o| o.amount).sum();
    if paid != funding_sum {
        return Err(format!("outputs pay {paid}, escrows hold {funding_sum}"));
    }
    if let Some(dust) = outputs.iter().find(|o| o.amount < P2TR_DUST) {
        return Err(format!("{} output to {} is dust ({} sats)", dust.role, dust.payee, dust.amount));
    }
    Ok(Template { escrows, outputs })
}

fn poseidon(inputs: &[Fr]) -> Result<Fr, String> {
    Poseidon::<Fr>::new_circom(inputs.len())
        .and_then(|mut h| h.hash(inputs))
        .map_err(|e| format!("poseidon: {e}"))
}

/// statementHash = Poseidon2(Poseidon9(statement[0..9]), Poseidon9(statement[9..18])) with
/// circomlib's parameters, as accounting16x4_hashed.circom and groth16/statement.js compute
/// it. Values >= r are refused, so x + r cannot stand in for x in the preimage.
pub fn statement_hash(statement: &[BigUint]) -> Result<BigUint, String> {
    if statement.len() != NUM_SIGNALS {
        return Err(format!("statement has {} values, expected {NUM_SIGNALS}", statement.len()));
    }
    let r = zkc_convert::fr_modulus();
    if let Some(i) = statement.iter().position(|v| v >= &r) {
        return Err(format!("{} is not below r", signal_name(i)));
    }
    let fr: Vec<Fr> = statement.iter().map(|v| Fr::from(v.clone())).collect();
    let low = poseidon(&fr[..STATEMENT_SPLIT])?;
    let high = poseidon(&fr[STATEMENT_SPLIT..])?;
    Ok(poseidon(&[low, high])?.into_bigint().into())
}

/// The M3 template. `statement_hash` is the proof's single public signal and `statement` the
/// 18 values the operator publishes with the sale list: they must hash to it, and the outputs
/// are then `build(statement, ...)`.
pub fn build_hashed(
    statement_hash: &BigUint,
    statement: &[BigUint],
    input: &Value,
    opening: &Value,
    opening_commitment: &BigUint,
) -> Result<Template, String> {
    if statement_hash >= &zkc_convert::fr_modulus() {
        return Err("statementHash is not below r".into());
    }
    if &self::statement_hash(statement)? != statement_hash {
        return Err("the statement does not hash to statementHash".into());
    }
    build(statement, input, opening, opening_commitment)
}

// ---------------------------------------------------------------------------------------------
// M14: M11's signed-tree statement, hashed by PoseidonChunked.
// ---------------------------------------------------------------------------------------------

/// The identity domain of model.py: every id the circuit signs is `field_id(kind, label)`.
pub const DOMAIN: &str = "p2poolv2/proposed-share-clearing/v0";
/// Poseidon calls in PoseidonChunked take at most this many values: light-poseidon's limit,
/// and the cap clearing_tree_signed.circom keeps.
pub const CHUNK_WIDTH: usize = 12;
/// PoseidonChunked takes at most CHUNK_WIDTH chunks of CHUNK_WIDTH values: 4 + 4B <= 144.
pub const MAX_CHUNKED_VALUES: usize = CHUNK_WIDTH * CHUNK_WIDTH;

pub const SIGNED_SALE_COMMITMENT: usize = 0;
pub const SIGNED_ESCROW_COMMITMENT: usize = 1;
pub const SIGNED_BATCH_HEIGHT: usize = 2;
pub const SIGNED_TOTAL_PAYOUT: usize = 3;
pub const fn signed_funding(b: usize) -> usize { 4 + b }
pub const fn signed_fee_budget(buyers: usize, b: usize) -> usize { 4 + buyers + b }
pub const fn signed_refund(buyers: usize, b: usize) -> usize { 4 + 2 * buyers + b }
pub const fn signed_buyer_id(buyers: usize, b: usize) -> usize { 4 + 3 * buyers + b }

pub fn signed_value_name(buyers: usize, index: usize) -> String {
    match index {
        SIGNED_SALE_COMMITMENT => "saleCommitment".into(),
        SIGNED_ESCROW_COMMITMENT => "escrowCommitment".into(),
        SIGNED_BATCH_HEIGHT => "batchHeight".into(),
        SIGNED_TOTAL_PAYOUT => "totalPayout".into(),
        _ if index < 4 + buyers => format!("funding[{}]", index - 4),
        _ if index < 4 + 2 * buyers => format!("feeBudget[{}]", index - 4 - buyers),
        _ if index < 4 + 3 * buyers => format!("refund[{}]", index - 4 - 2 * buyers),
        _ if index < 4 + 4 * buyers => format!("buyerId[{}]", index - 4 - 3 * buyers),
        _ => format!("statement[{index}]"),
    }
}

/// The statement layout a proof is about. `Accounting` is M1's 18 public signals, hashed by M3;
/// `SignedTree` is M11's circuit at `sales` x `buyers` slots, hashed by PoseidonChunked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Accounting,
    SignedTree { sales: usize, buyers: usize },
}

impl Kind {
    /// The kind a circuit name selects: `accounting16x4_committed`, `accounting16x4_hashed` or
    /// `signed_tree_<sales>x<buyers>` (the name prove-batch.sh writes to <batch>/circuit.txt).
    pub fn from_circuit(name: &str) -> Result<Kind, String> {
        if name == "accounting16x4_committed" || name == "accounting16x4_hashed" {
            return Ok(Kind::Accounting);
        }
        let shape = name.strip_prefix("signed_tree_").ok_or(format!("unknown circuit {name:?}"))?;
        let (sales, buyers) = shape.split_once('x').ok_or(format!("circuit {name:?} has no <sales>x<buyers> shape"))?;
        let parse = |s: &str| s.parse::<usize>().map_err(|_| format!("circuit {name:?} has no <sales>x<buyers> shape"));
        let (sales, buyers) = (parse(sales)?, parse(buyers)?);
        if sales < 2 || !sales.is_power_of_two() || buyers == 0 || 4 + 4 * buyers > MAX_CHUNKED_VALUES {
            return Err(format!("circuit {name:?}: {sales} sale slots and {buyers} buyer slots are not a signed-tree shape"));
        }
        Ok(Kind::SignedTree { sales, buyers })
    }

    /// Number of values in the statement the public hash commits to.
    pub fn statement_len(self) -> usize {
        match self {
            Kind::Accounting => NUM_SIGNALS,
            Kind::SignedTree { buyers, .. } => 4 + 4 * buyers,
        }
    }

    pub fn value_name(self, index: usize) -> String {
        match self {
            Kind::Accounting => signal_name(index),
            Kind::SignedTree { buyers, .. } => signed_value_name(buyers, index),
        }
    }

    /// Index of `refund[b]` in the statement.
    pub fn refund_index(self, b: usize) -> usize {
        match self {
            Kind::Accounting => refund(b),
            Kind::SignedTree { buyers, .. } => signed_refund(buyers, b),
        }
    }

    /// The tampered scenario moves this many sats of refund from buyer slot 1 to buyer slot 0:
    /// 50,000 in M1 and M3, 10,000 in M14 (buyer slot 1 holds 31,000 there).
    pub fn moved_sats(self) -> u64 {
        match self {
            Kind::Accounting => 50_000,
            Kind::SignedTree { .. } => 10_000,
        }
    }

    pub fn statement_hash(self, statement: &[BigUint]) -> Result<BigUint, String> {
        match self {
            Kind::Accounting => statement_hash(statement),
            Kind::SignedTree { .. } => signed_statement_hash(statement),
        }
    }

    /// The template for `statement`, which must hash to `statement_hash`. `sale_commitment` is
    /// an independently computed commitment to the sale list; M14 recomputes both commitments
    /// itself and ignores it.
    pub fn build_hashed(self, statement_hash: &BigUint, statement: &[BigUint], input: &Value, opening: &Value, sale_commitment: &BigUint) -> Result<Template, String> {
        match self {
            Kind::Accounting => build_hashed(statement_hash, statement, input, opening, sale_commitment),
            Kind::SignedTree { sales, buyers } => {
                if array_len(input, "price")? != sales || array_len(input, "buyerId")? != buyers {
                    return Err(format!("the input is not a {sales}x{buyers} batch"));
                }
                build_signed(statement_hash, statement, input, opening)
            }
        }
    }
}

/// Maps an identity string to a nonzero field element below r, as witness.py's `field_id`:
/// SHA-256 of "<DOMAIN>/<kind>/<value>", truncated to 253 bits.
pub fn field_id(kind: &str, value: &str) -> BigUint {
    let digest = Sha256::digest(format!("{DOMAIN}/{kind}/{value}").as_bytes());
    BigUint::from_bytes_be(&digest) >> 3u32
}

fn to_fr(value: &BigUint, what: &str) -> Result<Fr, String> {
    if value >= &zkc_convert::fr_modulus() {
        return Err(format!("{what} is not below r"));
    }
    Ok(Fr::from(value.clone()))
}

fn field(value: &Value, what: &str) -> Result<Fr, String> {
    to_fr(&decimal(value)?, what)
}

fn big(value: Fr) -> BigUint {
    value.into_bigint().into()
}

/// PoseidonChunked with circomlib's parameters, as clearing_tree_signed.circom defines it: up to
/// 12 values go through one Poseidon call; longer lists are cut into chunks of 12 (the last may
/// be shorter), each chunk is hashed, and the chunk digests are hashed together. Every call has at
/// most 12 inputs, so light-poseidon can evaluate it. More than 144 values would need a third
/// level, which the circuit does not have.
fn poseidon_chunked_fr(values: &[Fr]) -> Result<Fr, String> {
    if values.is_empty() {
        return Err("nothing to hash".into());
    }
    if values.len() <= CHUNK_WIDTH {
        return poseidon(values);
    }
    if values.len() > MAX_CHUNKED_VALUES {
        return Err(format!("{} values need more than two levels (the limit is {MAX_CHUNKED_VALUES})", values.len()));
    }
    let digests = values.chunks(CHUNK_WIDTH).map(poseidon).collect::<Result<Vec<_>, _>>()?;
    poseidon(&digests)
}

/// `poseidon_chunked_fr` over integers; a value >= r is refused rather than reduced. The unit
/// tests compare it with circomlibjs at every arity.
#[cfg(test)]
pub fn poseidon_chunked(values: &[BigUint]) -> Result<BigUint, String> {
    let fr = values.iter().enumerate().map(|(i, v)| to_fr(v, &format!("value {i}"))).collect::<Result<Vec<_>, _>>()?;
    Ok(big(poseidon_chunked_fr(&fr)?))
}

/// The number of buyer slots B of a signed-tree statement of `len` values (4 + 4B).
fn signed_buyers(len: usize) -> Result<usize, String> {
    if len < 8 || len % 4 != 0 || len > MAX_CHUNKED_VALUES {
        return Err(format!("a signed-tree statement has 4 + 4B values (at most {MAX_CHUNKED_VALUES}), got {len}"));
    }
    Ok((len - 4) / 4)
}

/// statementHash = PoseidonChunked(statement) for M11's statement. Values >= r are refused, so
/// x + r cannot stand in for x in the preimage.
pub fn signed_statement_hash(statement: &[BigUint]) -> Result<BigUint, String> {
    let buyers = signed_buyers(statement.len())?;
    let fr = statement.iter().enumerate().map(|(i, v)| to_fr(v, &signed_value_name(buyers, i))).collect::<Result<Vec<_>, _>>()?;
    Ok(big(poseidon_chunked_fr(&fr)?))
}

/// M6's sale tree as clearing_tree_signed.circom builds it: a binary Poseidon2 tree over
/// Poseidon6(activeSale, saleId, sellerId, price, selected buyerId, sellerPayoutId), where the
/// selected buyer ID is the selector-weighted sum of the buyer IDs. Reads the circuit input.
pub fn sale_commitment(input: &Value) -> Result<BigUint, String> {
    let sales = array_len(input, "price")?;
    let buyers = array_len(input, "buyerId")?;
    if sales < 2 || !sales.is_power_of_two() {
        return Err(format!("{sales} sale slots are not a power of two"));
    }
    let mut level = Vec::with_capacity(sales);
    for s in 0..sales {
        let mut selected = Fr::from(0u64);
        for b in 0..buyers {
            selected += field(&input["selector"][s][b], "selector")? * field(&input["buyerId"][b], "buyerId")?;
        }
        level.push(poseidon(&[
            field(&input["activeSale"][s], "activeSale")?,
            field(&input["saleId"][s], "saleId")?,
            field(&input["sellerId"][s], "sellerId")?,
            field(&input["price"][s], "price")?,
            selected,
            field(&input["sellerPayoutId"][s], "sellerPayoutId")?,
        ])?);
    }
    while level.len() > 1 {
        level = level.chunks(2).map(|pair| poseidon(&[pair[0], pair[1]])).collect::<Result<_, _>>()?;
    }
    Ok(big(level[0]))
}

/// PoseidonChunked over each buyer slot's Poseidon5(activeBuyer, escrowId, funding, feeCap,
/// refundScriptId). `funding` is the statement's, so the commitment binds the escrowed amounts.
pub fn escrow_commitment(input: &Value, funding: &[BigUint]) -> Result<BigUint, String> {
    let mut leaves = Vec::with_capacity(funding.len());
    for (b, fund) in funding.iter().enumerate() {
        leaves.push(poseidon(&[
            field(&input["activeBuyer"][b], "activeBuyer")?,
            field(&input["escrowId"][b], "escrowId")?,
            to_fr(fund, &format!("funding[{b}]"))?,
            field(&input["feeCap"][b], "feeCap")?,
            field(&input["refundScriptId"][b], "refundScriptId")?,
        ])?);
    }
    Ok(big(poseidon_chunked_fr(&leaves)?))
}

/// The M14 template. `statement_hash` is the proof's single public signal and `statement` the
/// 4 + 4B values the operator publishes with the sale list and escrow terms (`input`, the
/// circuit input, whose signature fields the template does not read) and the payee labels
/// (`opening`). Checks, in order:
///   1. the statement hashes to `statement_hash` (PoseidonChunked), every value below r;
///   2. saleCommitment and escrowCommitment open to `input`, and buyerId[b] is the sale list's;
///   3. every active sale slot's sellerPayoutId is the id of its payee label, and every active
///      buyer's escrowId and refundScriptId are the ids of its escrow and refund labels: the
///      scripts the graph pays are the ones the signed terms name;
///   4. M1's checks: prices sum to totalPayout, outputs conserve the escrowed value, no dust.
/// Signatures, expiries, `feeBudget <= feeCap` and each buyer's equation
/// funding = cost + fee + refund are the proof's job.
pub fn build_signed(statement_hash: &BigUint, statement: &[BigUint], input: &Value, opening: &Value) -> Result<Template, String> {
    if statement_hash >= &zkc_convert::fr_modulus() {
        return Err("statementHash is not below r".into());
    }
    if &signed_statement_hash(statement)? != statement_hash {
        return Err("the statement does not hash to statementHash".into());
    }
    let buyers = signed_buyers(statement.len())?;
    let sats = |i: usize| -> Result<u64, String> {
        let name = signed_value_name(buyers, i);
        let v = small(&statement[i], &name)?;
        if v > MAX_SATS {
            return Err(format!("{name} exceeds MAX_SATS"));
        }
        Ok(v)
    };
    let amounts = Amounts {
        total_payout: sats(SIGNED_TOTAL_PAYOUT)?,
        funding: (0..buyers).map(|b| sats(signed_funding(b))).collect::<Result<_, _>>()?,
        fee_budget: (0..buyers).map(|b| sats(signed_fee_budget(buyers, b))).collect::<Result<_, _>>()?,
        refund: (0..buyers).map(|b| sats(signed_refund(buyers, b))).collect::<Result<_, _>>()?,
    };

    if array_len(input, "buyerId")? != buyers {
        return Err(format!("the statement has {buyers} buyer slots, the input {}", array_len(input, "buyerId")?));
    }
    if sale_commitment(input)? != statement[SIGNED_SALE_COMMITMENT] {
        return Err("saleCommitment does not open to the given sale list".into());
    }
    if escrow_commitment(input, &statement[signed_funding(0)..signed_funding(buyers)])? != statement[SIGNED_ESCROW_COMMITMENT] {
        return Err("escrowCommitment does not open to the given escrow terms".into());
    }
    for b in 0..buyers {
        if statement[signed_buyer_id(buyers, b)] != decimal(&input["buyerId"][b])? {
            return Err(format!("buyerId[{b}] differs from the sale list the commitment opens to"));
        }
    }

    let label = |value: &Value, what: String| -> Result<String, String> { value.as_str().map(str::to_string).ok_or(what) };
    for s in 0..array_len(input, "activeSale")? {
        if small(&decimal(&input["activeSale"][s])?, "activeSale")? == 0 {
            continue;
        }
        let payee = label(&opening["sale_slots"][s]["seller_payee"], format!("sale slot {s} is active but has no seller payee"))?;
        if decimal(&input["sellerPayoutId"][s])? != field_id("seller_payout_script", &payee) {
            return Err(format!("sale slot {s}: sellerPayoutId is not the script id of payee {payee}"));
        }
    }
    for b in 0..buyers {
        let active = small(&decimal(&input["activeBuyer"][b])?, "activeBuyer")? != 0;
        if active != (amounts.funding[b] > 0) {
            return Err(format!("buyer slot {b}: activeBuyer and funding disagree"));
        }
        if !active {
            continue;
        }
        let escrow = label(&opening["buyer_slots"][b]["escrow"], format!("buyer slot {b} has no escrow label"))?;
        if decimal(&input["escrowId"][b])? != field_id("escrow_outpoint", &escrow) {
            return Err(format!("buyer slot {b}: escrowId is not the id of escrow {escrow}"));
        }
        let refund_payee = label(&opening["buyer_slots"][b]["refund_payee"], format!("buyer slot {b} has no refund payee"))?;
        if decimal(&input["refundScriptId"][b])? != field_id("refund_script", &refund_payee) {
            return Err(format!("buyer slot {b}: refundScriptId is not the script id of payee {refund_payee}"));
        }
    }
    assemble(input, opening, &amounts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> (Vec<BigUint>, Value, Value, BigUint) {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/");
        let read = |name: &str| std::fs::read_to_string(format!("{dir}{name}")).unwrap();
        let public: Value = serde_json::from_str(&read("batch-public.json")).unwrap();
        let signals = zkc_convert::public_integers(&public).unwrap();
        let input: Value = serde_json::from_str(&read("batch-input.json")).unwrap();
        let opening: Value = serde_json::from_str(&read("batch-opening.json")).unwrap();
        let commitment: BigUint = read("batch-sale-commitment.txt").trim().parse().unwrap();
        (signals, input, opening, commitment)
    }

    #[test]
    fn honest_batch_pays_sale_list_refunds_and_fee() {
        let (signals, input, opening, commitment) = vectors();
        let t = build(&signals, &input, &opening, &commitment).unwrap();
        let amounts: Vec<(&str, u64)> = t.outputs.iter().map(|o| (o.payee.as_str(), o.amount)).collect();
        assert_eq!(
            amounts,
            vec![
                ("seller-alice", 1_900_000),
                ("seller-bob", 1_800_000),
                ("seller-carol", 450_000),
                ("refund-buyer1", 330_000),
                ("refund-buyer2", 82_000),
                ("refund-buyer3", 43_000),
                ("operator-fee", 45_000),
            ]
        );
        let escrow: Vec<u64> = t.escrows.iter().map(|e| e.amount).collect();
        assert_eq!(escrow, vec![2_000_000, 1_900_000, 750_000]);
    }

    #[test]
    fn signal_layout_matches_the_witness_input() {
        let (signals, input, _, _) = vectors();
        for b in 0..BUYER_SLOTS {
            assert_eq!(signals[funding(b)], decimal(&input["funding"][b]).unwrap());
            assert_eq!(signals[fee_budget(b)], decimal(&input["feeBudget"][b]).unwrap());
            assert_eq!(signals[refund(b)], decimal(&input["refund"][b]).unwrap());
            assert_eq!(signals[buyer_id(b)], decimal(&input["buyerId"][b]).unwrap());
        }
        assert_eq!(signals[TOTAL_PAYOUT], decimal(&input["totalPayout"]).unwrap());
    }

    #[test]
    fn template_is_a_function_of_the_signals() {
        let (signals, input, opening, commitment) = vectors();
        let honest = build(&signals, &input, &opening, &commitment).unwrap();
        // Moving 50,000 sats of refund from buyer slot 1 to slot 0 keeps total conservation,
        // so the template accepts it, but the outputs differ.
        let mut moved = signals.clone();
        moved[refund(0)] += 50_000u64;
        moved[refund(1)] -= 50_000u64;
        let other = build(&moved, &input, &opening, &commitment).unwrap();
        assert_ne!(honest, other);
        assert_eq!(other.outputs[3].amount, 380_000);
        assert_eq!(other.outputs[4].amount, 32_000);
    }

    fn hashed_vectors() -> (BigUint, Vec<BigUint>) {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/");
        let read = |name: &str| -> Value { serde_json::from_str(&std::fs::read_to_string(format!("{dir}{name}")).unwrap()).unwrap() };
        let hash = zkc_convert::public_integers(&read("hashed-batch-public.json")).unwrap().remove(0);
        let statement = zkc_convert::public_integers(&read("hashed-batch-statement.json")["statement"]).unwrap();
        (hash, statement)
    }

    #[test]
    fn statement_hash_matches_the_circuit() {
        // light-poseidon with circomlib parameters reproduces the hashed proof's public signal.
        let (hash, statement) = hashed_vectors();
        assert_eq!(statement_hash(&statement).unwrap(), hash);
        let (signals, ..) = vectors();
        assert_eq!(statement, signals);
    }

    #[test]
    fn hashed_template_checks_the_preimage() {
        let (signals, input, opening, commitment) = vectors();
        let (hash, statement) = hashed_vectors();
        let m1 = build(&signals, &input, &opening, &commitment).unwrap();
        assert_eq!(build_hashed(&hash, &statement, &input, &opening, &commitment).unwrap(), m1);

        // A different statement does not open the honest hash, and builds a different template
        // under its own hash.
        let mut moved = statement.clone();
        moved[refund(0)] += 50_000u64;
        moved[refund(1)] -= 50_000u64;
        let err = build_hashed(&hash, &moved, &input, &opening, &commitment).unwrap_err();
        assert!(err.contains("does not hash"), "{err}");
        let other_hash = statement_hash(&moved).unwrap();
        assert_ne!(other_hash, hash);
        assert_ne!(build_hashed(&other_hash, &moved, &input, &opening, &commitment).unwrap(), m1);

        // Non-canonical encodings: the hash itself, and any statement value, written as x + r.
        let r = zkc_convert::fr_modulus();
        assert!(build_hashed(&(&hash + &r), &statement, &input, &opening, &commitment).unwrap_err().contains("not below r"));
        for i in 0..NUM_SIGNALS {
            let mut plus_r = statement.clone();
            plus_r[i] += &r;
            assert!(build_hashed(&hash, &plus_r, &input, &opening, &commitment).unwrap_err().contains("not below r"));
        }
    }

    #[test]
    fn rejects_non_canonical_and_inconsistent_signals() {
        let (signals, input, opening, commitment) = vectors();
        for i in 0..NUM_SIGNALS {
            let mut plus_r = signals.clone();
            plus_r[i] += zkc_convert::fr_modulus();
            assert!(build(&plus_r, &input, &opening, &commitment).unwrap_err().contains("not below r"));
        }
        let mut wrong_commitment = signals.clone();
        wrong_commitment[SALE_COMMITMENT] += 1u64;
        assert!(build(&wrong_commitment, &input, &opening, &commitment).is_err());
        let mut wrong_total = signals.clone();
        wrong_total[TOTAL_PAYOUT] += 1u64;
        assert!(build(&wrong_total, &input, &opening, &commitment).is_err());
        let mut inflated = signals.clone();
        inflated[refund(2)] += 1u64;
        assert!(build(&inflated, &input, &opening, &commitment).unwrap_err().contains("escrows hold"));
        let mut dust = signals.clone();
        dust[refund(2)] -= 42_800u64;
        dust[refund(0)] += 42_800u64;
        assert!(build(&dust, &input, &opening, &commitment).unwrap_err().contains("dust"));
    }

    // ---- M14: the signed-tree statement ----

    fn vector(name: &str) -> Value {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/");
        serde_json::from_str(&std::fs::read_to_string(format!("{dir}{name}")).unwrap()).unwrap()
    }

    fn integers(value: &Value) -> Vec<BigUint> {
        zkc_convert::public_integers(value).unwrap()
    }

    /// The regtest batch of batch_signed.py: (statement hash, statement, circuit input, opening,
    /// the circomlibjs saleCommitment and escrowCommitment).
    fn signed_vectors() -> (BigUint, Vec<BigUint>, Value, Value, BigUint, BigUint) {
        let reference = vector("signed-batch-statement.json");
        let hash = integers(&vector("signed-batch-public.json")).remove(0);
        let statement = integers(&reference["statement"]);
        let sale: BigUint = reference["saleCommitment"].as_str().unwrap().parse().unwrap();
        let escrow: BigUint = reference["escrowCommitment"].as_str().unwrap().parse().unwrap();
        (hash, statement, vector("signed-batch-input.json"), vector("signed-batch-opening.json"), sale, escrow)
    }

    fn signed(statement: &[BigUint], input: &Value, opening: &Value) -> Result<Template, String> {
        build_signed(&signed_statement_hash(statement).unwrap(), statement, input, opening)
    }

    #[test]
    fn chunked_hash_equals_circomlibjs_at_every_arity() {
        // statement_signed_tree.js's hashChunked over deterministic values, including values
        // just below r: one Poseidon up to 12 values, then chunks of 12 and a top-level hash,
        // up to 144 values (12 chunks).
        let cases = vector("chunked-hash-vectors.json");
        let cases = cases["cases"].as_array().unwrap();
        assert!(cases.len() >= 10);
        let mut lengths = vec![];
        for case in cases {
            let values = integers(&case["values"]);
            let expected: BigUint = case["hash"].as_str().unwrap().parse().unwrap();
            assert_eq!(poseidon_chunked(&values).unwrap(), expected, "{} values", values.len());
            lengths.push(values.len());
        }
        for needed in [1, 12, 13, 20, 24, 25, 36, 144] {
            assert!(lengths.contains(&needed), "no vector with {needed} values");
        }
    }

    #[test]
    fn chunked_hash_limits() {
        let values: Vec<BigUint> = (1..=145u64).map(BigUint::from).collect();
        assert!(poseidon_chunked(&values[..144]).is_ok());
        assert!(poseidon_chunked(&values).unwrap_err().contains("more than two levels"));
        assert!(poseidon_chunked(&[]).is_err());
        let mut plus_r = values[..13].to_vec();
        plus_r[5] += zkc_convert::fr_modulus();
        assert!(poseidon_chunked(&plus_r).unwrap_err().contains("not below r"));
    }

    #[test]
    fn statement_hash_equals_circomlibjs_on_the_m11_fixtures() {
        // M11's own run.sh statements (statement_signed_tree.js): 16x4 has 20 values (chunks of
        // 12 and 8), 128x8 has 36 (three chunks); then the regtest batch.
        for (name, values) in [
            ("signed-m11-16x4-statement.json", 20),
            ("signed-m11-128x8-statement.json", 36),
            ("signed-batch-statement.json", 20),
        ] {
            let fixture = vector(name);
            let statement = integers(&fixture["statement"]);
            assert_eq!(statement.len(), values, "{name}");
            let expected: BigUint = fixture["statementHash"].as_str().unwrap().parse().unwrap();
            assert_eq!(signed_statement_hash(&statement).unwrap(), expected, "{name}");
        }
        // The regtest batch's proof carries that hash as its public signal.
        let (hash, statement, ..) = signed_vectors();
        assert_eq!(signed_statement_hash(&statement).unwrap(), hash);
    }

    #[test]
    fn commitments_equal_circomlibjs_on_the_regtest_batch() {
        let (_, statement, input, _, sale, escrow) = signed_vectors();
        assert_eq!(sale_commitment(&input).unwrap(), sale);
        assert_eq!(statement[SIGNED_SALE_COMMITMENT], sale);
        assert_eq!(escrow_commitment(&input, &statement[signed_funding(0)..signed_funding(4)]).unwrap(), escrow);
        assert_eq!(statement[SIGNED_ESCROW_COMMITMENT], escrow);
    }

    #[test]
    fn signed_statement_layout_matches_the_witness_input() {
        let (_, statement, input, ..) = signed_vectors();
        assert_eq!(statement.len(), Kind::SignedTree { sales: 16, buyers: 4 }.statement_len());
        assert_eq!(statement[SIGNED_BATCH_HEIGHT], decimal(&input["batchHeight"]).unwrap());
        assert_eq!(statement[SIGNED_TOTAL_PAYOUT], decimal(&input["totalPayout"]).unwrap());
        for b in 0..4 {
            assert_eq!(statement[signed_funding(b)], decimal(&input["funding"][b]).unwrap());
            assert_eq!(statement[signed_fee_budget(4, b)], decimal(&input["feeBudget"][b]).unwrap());
            assert_eq!(statement[signed_refund(4, b)], decimal(&input["refund"][b]).unwrap());
            assert_eq!(statement[signed_buyer_id(4, b)], decimal(&input["buyerId"][b]).unwrap());
        }
        assert_eq!(signed_value_name(4, signed_refund(4, 2)), "refund[2]");
        assert_eq!(signed_value_name(4, SIGNED_ESCROW_COMMITMENT), "escrowCommitment");
    }

    #[test]
    fn signed_template_pays_sellers_refunds_and_fee() {
        let (hash, statement, input, opening, ..) = signed_vectors();
        let t = Kind::SignedTree { sales: 16, buyers: 4 }.build_hashed(&hash, &statement, &input, &opening, &BigUint::from(0u8)).unwrap();
        let outputs: Vec<(&str, u64)> = t.outputs.iter().map(|o| (o.payee.as_str(), o.amount)).collect();
        let prices = [61_158u64, 90_377, 79_381, 39_657, 69_679, 4_521, 68_986, 4_828, 24_815, 23_299, 17_859, 45_872, 30_701, 16_098, 1_884, 79_187];
        let mut expected: Vec<(String, u64)> = prices.iter().enumerate().map(|(s, p)| (format!("scale-payout:{s}"), *p)).collect();
        for (b, back) in [38_000u64, 31_000, 12_000, 17_000].iter().enumerate() {
            expected.push((format!("scale-refund:{b}"), *back));
        }
        expected.push(("operator-fee".into(), 1_082 + 380 + 4_231 + 4_600));
        let expected: Vec<(&str, u64)> = expected.iter().map(|(p, a)| (p.as_str(), *a)).collect();
        assert_eq!(outputs, expected);
        let escrows: Vec<(usize, &str, u64)> = t.escrows.iter().map(|e| (e.slot, e.buyer.as_str(), e.amount)).collect();
        assert_eq!(escrows.len(), 4);
        assert_eq!(escrows.iter().map(|e| e.2).collect::<Vec<_>>(), vec![225_435, 165_675, 184_341, 191_144]);
        assert_eq!(escrows[2], (2, "scale-buyer:2", 184_341));
        assert_eq!(t.outputs.iter().map(|o| o.amount).sum::<u64>(), t.escrows.iter().map(|e| e.amount).sum::<u64>());
    }

    #[test]
    fn signed_template_is_rejected_when_the_statement_does_not_hash_to_the_public_input() {
        let (hash, statement, input, opening, ..) = signed_vectors();
        let kind = Kind::SignedTree { sales: 16, buyers: 4 };
        let none = BigUint::from(0u8);
        let honest = kind.build_hashed(&hash, &statement, &input, &opening, &none).unwrap();

        // S': 10,000 sats of refund moved from buyer slot 1 to slot 0. It conserves the total, so
        // under its own hash it builds a different template; under the proven hash it is refused.
        let mut moved = statement.clone();
        moved[signed_refund(4, 0)] += 10_000u64;
        moved[signed_refund(4, 1)] -= 10_000u64;
        let err = kind.build_hashed(&hash, &moved, &input, &opening, &none).unwrap_err();
        assert!(err.contains("does not hash"), "{err}");
        let other = signed_statement_hash(&moved).unwrap();
        assert_ne!(other, hash);
        let tampered = kind.build_hashed(&other, &moved, &input, &opening, &none).unwrap();
        assert_ne!(tampered, honest);
        assert_eq!(tampered.outputs[16].amount, 48_000);
        assert_eq!(tampered.outputs[17].amount, 21_000);

        // One value off, a wrong hash, and a statement of the wrong length.
        for i in 0..statement.len() {
            let mut one_off = statement.clone();
            one_off[i] += 1u64;
            assert!(kind.build_hashed(&hash, &one_off, &input, &opening, &none).unwrap_err().contains("does not hash"), "value {i}");
        }
        assert!(kind.build_hashed(&(&hash + 1u64), &statement, &input, &opening, &none).unwrap_err().contains("does not hash"));
        assert!(kind.build_hashed(&hash, &statement[..19], &input, &opening, &none).is_err());
    }

    #[test]
    fn signed_template_refuses_non_canonical_encodings() {
        let (hash, statement, input, opening, ..) = signed_vectors();
        let r = zkc_convert::fr_modulus();
        assert!(build_signed(&(&hash + &r), &statement, &input, &opening).unwrap_err().contains("not below r"));
        for i in 0..statement.len() {
            let mut plus_r = statement.clone();
            plus_r[i] += &r;
            assert!(build_signed(&hash, &plus_r, &input, &opening).unwrap_err().contains("not below r"), "value {i}");
        }
    }

    #[test]
    fn signed_template_opens_both_commitments() {
        let (_, statement, input, opening, ..) = signed_vectors();
        // A sale list with one price changed hashes the statement correctly (same statement) but
        // does not open saleCommitment.
        let mut other_price = input.clone();
        other_price["price"][3] = "39658".into();
        let err = signed(&statement, &other_price, &opening).unwrap_err();
        assert!(err.contains("saleCommitment"), "{err}");
        // A different payout id in the sale list is a different leaf.
        let mut other_payout = input.clone();
        other_payout["sellerPayoutId"][0] = other_payout["sellerPayoutId"][1].clone();
        assert!(signed(&statement, &other_payout, &opening).unwrap_err().contains("saleCommitment"));
        // Escrow terms: the fee cap, the refund script and the escrow id are in the leaf.
        for field in ["feeCap", "refundScriptId", "escrowId"] {
            let mut other = input.clone();
            other[field][1] = other[field][2].clone();
            let err = signed(&statement, &other, &opening).unwrap_err();
            assert!(err.contains("escrowCommitment"), "{field}: {err}");
        }
        // A statement carrying another buyer's escrowCommitment (and its own hash) is refused.
        let mut wrong_escrow = statement.clone();
        wrong_escrow[SIGNED_ESCROW_COMMITMENT] += 1u64;
        assert!(signed(&wrong_escrow, &input, &opening).unwrap_err().contains("escrowCommitment"));
        // buyerId[b] of the statement must be the sale list's.
        let mut wrong_buyer = statement.clone();
        wrong_buyer[signed_buyer_id(4, 2)] += 1u64;
        let err = signed(&wrong_buyer, &input, &opening).unwrap_err();
        assert!(err.contains("saleCommitment") || err.contains("buyerId"), "{err}");
    }

    #[test]
    fn signed_template_binds_labels_to_the_signed_ids() {
        let (_, statement, input, opening, ..) = signed_vectors();
        let base = signed(&statement, &input, &opening).unwrap();
        // The payee labels are the ones the ids were derived from; swapping any of them changes
        // where the committee would pay, and is refused.
        let mut swapped_seller = opening.clone();
        swapped_seller["sale_slots"][4]["seller_payee"] = "scale-payout:5".into();
        assert!(signed(&statement, &input, &swapped_seller).unwrap_err().contains("sellerPayoutId"));
        let mut swapped_refund = opening.clone();
        swapped_refund["buyer_slots"][1]["refund_payee"] = "operator-fee".into();
        assert!(signed(&statement, &input, &swapped_refund).unwrap_err().contains("refundScriptId"));
        let mut swapped_escrow = opening.clone();
        swapped_escrow["buyer_slots"][3]["escrow"] = "scale-escrow:3:1".into();
        assert!(signed(&statement, &input, &swapped_escrow).unwrap_err().contains("escrowId"));
        // The fee payee and the buyer's own label are not signed; they do not change the checks.
        let mut other_fee = opening.clone();
        other_fee["fee_payee"] = "other-fee".into();
        assert_ne!(signed(&statement, &input, &other_fee).unwrap(), base);
        // field_id agrees with witness.py: the ids in the input are Python's.
        assert_eq!(decimal(&input["sellerPayoutId"][7]).unwrap(), field_id("seller_payout_script", "scale-payout:7"));
    }

    #[test]
    fn signed_template_keeps_the_money_checks() {
        let (_, statement, input, opening, ..) = signed_vectors();
        // The refund of buyer slot 2 is 12,000; leaving 100 of it is dust.
        let mut dust = statement.clone();
        dust[signed_refund(4, 2)] -= 11_900u64;
        dust[signed_refund(4, 0)] += 11_900u64;
        assert!(signed(&dust, &input, &opening).unwrap_err().contains("dust"));
        // Outputs must conserve the escrowed value (no proof exists for this either).
        let mut inflated = statement.clone();
        inflated[signed_refund(4, 3)] += 1u64;
        assert!(signed(&inflated, &input, &opening).unwrap_err().contains("escrows hold"));
        let mut wrong_total = statement.clone();
        wrong_total[SIGNED_TOTAL_PAYOUT] += 1u64;
        assert!(signed(&wrong_total, &input, &opening).unwrap_err().contains("totalPayout"));
    }

    #[test]
    fn circuit_names_select_the_statement_layout() {
        assert_eq!(Kind::from_circuit("accounting16x4_hashed").unwrap(), Kind::Accounting);
        assert_eq!(Kind::from_circuit("accounting16x4_committed").unwrap(), Kind::Accounting);
        assert_eq!(Kind::from_circuit("signed_tree_16x4").unwrap(), Kind::SignedTree { sales: 16, buyers: 4 });
        assert_eq!(Kind::from_circuit("signed_tree_128x8").unwrap().statement_len(), 36);
        for bad in ["", "signed_tree_", "signed_tree_16", "signed_tree_15x4", "signed_tree_16x0", "signed_tree_16x36", "clearing16x4_signed"] {
            assert!(Kind::from_circuit(bad).is_err(), "{bad:?}");
        }
        let kind = Kind::SignedTree { sales: 16, buyers: 4 };
        assert_eq!(kind.refund_index(1), 4 + 8 + 1);
        assert_eq!(Kind::Accounting.refund_index(1), refund(1));
        assert_eq!(kind.value_name(kind.refund_index(0)), "refund[0]");
    }
}
