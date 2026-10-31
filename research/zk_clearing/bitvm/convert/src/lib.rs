//! snarkjs Groth16 JSON (BN254, `bn128`) into the arkworks 0.5 types that BitVM's chunked
//! Groth16 verifier consumes (`ark_groth16::{Proof, VerifyingKey}<Bn254>`).
//!
//! Every field element must be canonical: a decimal integer below its modulus. snarkjs writes
//! points in projective form with z = 1 (G1 `[x, y, "1"]`, G2 `[[x.c0, x.c1], [y.c0, y.c1],
//! ["1", "0"]]`), and anything else is rejected rather than normalised. Points must be on the
//! curve and in the prime-order subgroup.

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::CanonicalSerialize;
use num_bigint::BigUint;
use serde_json::Value;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConvertError(pub String);

impl fmt::Display for ConvertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConvertError {}

type Result<T> = std::result::Result<T, ConvertError>;

fn err<T>(message: impl Into<String>) -> Result<T> {
    Err(ConvertError(message.into()))
}

/// A decimal string as an integer, without leading zeros, signs or whitespace.
pub fn parse_decimal(value: &Value, what: &str) -> Result<BigUint> {
    let Some(text) = value.as_str() else {
        return err(format!("{what}: expected a decimal string, got {value}"));
    };
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) || (text.len() > 1 && text.starts_with('0')) {
        return err(format!("{what}: {text:?} is not a canonical decimal integer"));
    }
    Ok(text.parse::<BigUint>().expect("checked digits"))
}

fn canonical<F: PrimeField>(value: &Value, what: &str) -> Result<F> {
    let n = parse_decimal(value, what)?;
    let modulus: BigUint = F::MODULUS.into();
    if n >= modulus {
        return err(format!("{what}: {n} is not below the field modulus"));
    }
    Ok(F::from(n))
}

/// A scalar-field element (a public signal); values >= r are rejected, never reduced.
pub fn parse_fr(value: &Value, what: &str) -> Result<Fr> {
    canonical::<Fr>(value, what)
}

pub fn parse_fq(value: &Value, what: &str) -> Result<Fq> {
    canonical::<Fq>(value, what)
}

fn array<'a>(value: &'a Value, len: usize, what: &str) -> Result<&'a Vec<Value>> {
    match value.as_array() {
        Some(items) if items.len() == len => Ok(items),
        _ => err(format!("{what}: expected an array of {len}, got {value}")),
    }
}

fn expect_literal(value: &Value, literal: &str, what: &str) -> Result<()> {
    if value.as_str() == Some(literal) {
        Ok(())
    } else {
        err(format!("{what}: expected {literal:?}, got {value}"))
    }
}

/// A G1 point written by snarkjs as `[x, y, "1"]`.
pub fn parse_g1(value: &Value, what: &str) -> Result<G1Affine> {
    let items = array(value, 3, what)?;
    expect_literal(&items[2], "1", &format!("{what}.z"))?;
    let point = G1Affine::new_unchecked(parse_fq(&items[0], &format!("{what}.x"))?, parse_fq(&items[1], &format!("{what}.y"))?);
    if !point.is_on_curve() {
        return err(format!("{what}: not on the BN254 G1 curve"));
    }
    if !point.is_in_correct_subgroup_assuming_on_curve() {
        return err(format!("{what}: not in the G1 subgroup"));
    }
    Ok(point)
}

/// A G2 point written by snarkjs as `[[x.c0, x.c1], [y.c0, y.c1], ["1", "0"]]`.
pub fn parse_g2(value: &Value, what: &str) -> Result<G2Affine> {
    let items = array(value, 3, what)?;
    let coord = |index: usize, name: &str| -> Result<Fq2> {
        let pair = array(&items[index], 2, &format!("{what}.{name}"))?;
        Ok(Fq2::new(
            parse_fq(&pair[0], &format!("{what}.{name}.c0"))?,
            parse_fq(&pair[1], &format!("{what}.{name}.c1"))?,
        ))
    };
    let z = array(&items[2], 2, &format!("{what}.z"))?;
    expect_literal(&z[0], "1", &format!("{what}.z.c0"))?;
    expect_literal(&z[1], "0", &format!("{what}.z.c1"))?;
    let point = G2Affine::new_unchecked(coord(0, "x")?, coord(1, "y")?);
    if !point.is_on_curve() {
        return err(format!("{what}: not on the BN254 G2 twist"));
    }
    if !point.is_in_correct_subgroup_assuming_on_curve() {
        return err(format!("{what}: not in the G2 subgroup"));
    }
    Ok(point)
}

/// snarkjs `proof.json` (protocol groth16, curve bn128) as an arkworks proof.
pub fn proof_from_snarkjs(json: &Value) -> Result<Proof<Bn254>> {
    expect_literal(&json["protocol"], "groth16", "proof.protocol")?;
    expect_literal(&json["curve"], "bn128", "proof.curve")?;
    Ok(Proof {
        a: parse_g1(&json["pi_a"], "pi_a")?,
        b: parse_g2(&json["pi_b"], "pi_b")?,
        c: parse_g1(&json["pi_c"], "pi_c")?,
    })
}

/// snarkjs `verification_key.json` as an arkworks verifying key. `IC` becomes `gamma_abc_g1`,
/// in the same order as the public signals (IC[0] is the constant term).
pub fn vk_from_snarkjs(json: &Value) -> Result<VerifyingKey<Bn254>> {
    expect_literal(&json["protocol"], "groth16", "vk.protocol")?;
    expect_literal(&json["curve"], "bn128", "vk.curve")?;
    let Some(n_public) = json["nPublic"].as_u64() else {
        return err("vk.nPublic missing");
    };
    let Some(ic) = json["IC"].as_array() else {
        return err("vk.IC missing");
    };
    if ic.len() as u64 != n_public + 1 {
        return err(format!("vk: {} IC points for nPublic {n_public}", ic.len()));
    }
    let gamma_abc_g1 = ic
        .iter()
        .enumerate()
        .map(|(i, point)| parse_g1(point, &format!("IC[{i}]")))
        .collect::<Result<Vec<_>>>()?;
    Ok(VerifyingKey {
        alpha_g1: parse_g1(&json["vk_alpha_1"], "vk_alpha_1")?,
        beta_g2: parse_g2(&json["vk_beta_2"], "vk_beta_2")?,
        gamma_g2: parse_g2(&json["vk_gamma_2"], "vk_gamma_2")?,
        delta_g2: parse_g2(&json["vk_delta_2"], "vk_delta_2")?,
        gamma_abc_g1,
    })
}

/// snarkjs `public.json`: every signal must be a canonical decimal below r.
pub fn public_from_snarkjs(json: &Value) -> Result<Vec<Fr>> {
    let Some(items) = json.as_array() else {
        return err("public.json: expected an array");
    };
    items
        .iter()
        .enumerate()
        .map(|(i, value)| parse_fr(value, &format!("public[{i}]")))
        .collect()
}

/// The raw public signals as integers, for callers that must see non-canonical values.
pub fn public_integers(json: &Value) -> Result<Vec<BigUint>> {
    let Some(items) = json.as_array() else {
        return err("public.json: expected an array");
    };
    items
        .iter()
        .enumerate()
        .map(|(i, value)| parse_decimal(value, &format!("public[{i}]")))
        .collect()
}

/// arkworks Groth16 verification. A public-input count that does not match the key is an
/// error, not a rejection.
pub fn verify(vk: &VerifyingKey<Bn254>, proof: &Proof<Bn254>, public: &[Fr]) -> Result<bool> {
    if public.len() + 1 != vk.gamma_abc_g1.len() {
        return err(format!("{} public inputs for a key with {}", public.len(), vk.gamma_abc_g1.len() - 1));
    }
    let pvk = ark_groth16::prepare_verifying_key(vk);
    Groth16::<Bn254>::verify_proof(&pvk, proof, public).map_err(|e| ConvertError(format!("verify: {e}")))
}

pub fn compressed_hex<T: CanonicalSerialize>(value: &T) -> String {
    let mut bytes = Vec::new();
    value.serialize_compressed(&mut bytes).expect("serialize to Vec");
    hex::encode(bytes)
}

pub fn fr_decimal(value: &Fr) -> String {
    BigUint::from_bytes_be(&value.into_bigint().to_bytes_be()).to_string()
}

pub fn fr_modulus() -> BigUint {
    Fr::MODULUS.into()
}
