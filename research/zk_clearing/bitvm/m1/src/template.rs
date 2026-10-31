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

use ark_bn254::Fr;
use ark_ff::PrimeField;
use light_poseidon::{Poseidon, PoseidonHasher};
use num_bigint::BigUint;
use serde_json::Value;

pub const SALE_SLOTS: usize = 16;
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

    // Seller payouts: active sale slots in order, merged by payee at first appearance.
    let mut outputs: Vec<PayoutSpec> = vec![];
    let mut price_sum: u64 = 0;
    for s in 0..SALE_SLOTS {
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
    if price_sum != amount(TOTAL_PAYOUT)? {
        return Err(format!("sale prices sum to {price_sum}, totalPayout is {}", amount(TOTAL_PAYOUT)?));
    }

    let mut escrows = vec![];
    let mut funding_sum: u64 = 0;
    let mut fee_sum: u64 = 0;
    for b in 0..BUYER_SLOTS {
        let fund = amount(funding(b))?;
        if fund == 0 {
            if amount(refund(b))? != 0 || amount(fee_budget(b))? != 0 {
                return Err(format!("unfunded buyer slot {b} carries a refund or fee"));
            }
            continue;
        }
        let buyer = opening["buyer_slots"][b]["buyer"].as_str().ok_or(format!("buyer slot {b} has no buyer"))?;
        let refund_payee = opening["buyer_slots"][b]["refund_payee"].as_str().ok_or(format!("buyer slot {b} has no refund payee"))?;
        escrows.push(EscrowSpec { slot: b, buyer: buyer.to_string(), amount: fund });
        funding_sum += fund;
        fee_sum += amount(fee_budget(b))?;
        let back = amount(refund(b))?;
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
}
