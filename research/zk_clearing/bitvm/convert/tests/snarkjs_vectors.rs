//! The conversion is faithful on the committed snarkjs vectors (insecure deterministic setup,
//! verifying key sha256 3d5030f9...b8533494ec): both proofs verify under ark-groth16, any
//! changed signal, swapped proof element or wrong key fails, and malformed encodings are refused.

use ark_bn254::Fr;
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde_json::Value;
use zkc_convert::*;

fn vector(name: &str) -> Value {
    let path = format!("{}/../vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

fn load(prefix: &str) -> (ark_groth16::VerifyingKey<ark_bn254::Bn254>, ark_groth16::Proof<ark_bn254::Bn254>, Vec<Fr>) {
    (
        vk_from_snarkjs(&vector("verification_key.json")).unwrap(),
        proof_from_snarkjs(&vector(&format!("{prefix}-proof.json"))).unwrap(),
        public_from_snarkjs(&vector(&format!("{prefix}-public.json"))).unwrap(),
    )
}

#[test]
fn converted_proofs_verify() {
    for prefix in ["example", "batch"] {
        let (vk, proof, public) = load(prefix);
        assert_eq!(public.len(), 18);
        assert_eq!(vk.gamma_abc_g1.len(), 19);
        assert!(verify(&vk, &proof, &public).unwrap(), "{prefix} proof");
    }
}

#[test]
fn every_shifted_signal_fails() {
    for prefix in ["example", "batch"] {
        let (vk, proof, public) = load(prefix);
        for i in 0..public.len() {
            let mut tampered = public.clone();
            tampered[i] += Fr::from(1u64);
            assert!(!verify(&vk, &proof, &tampered).unwrap(), "{prefix} signal {i}");
        }
    }
}

#[test]
fn proof_for_one_statement_does_not_verify_another() {
    let (vk, example_proof, example_public) = load("example");
    let (_, batch_proof, batch_public) = load("batch");
    assert!(!verify(&vk, &example_proof, &batch_public).unwrap());
    assert!(!verify(&vk, &batch_proof, &example_public).unwrap());
}

#[test]
fn swapped_or_negated_elements_fail() {
    let (vk, proof, public) = load("batch");
    let mut swapped = proof.clone();
    std::mem::swap(&mut swapped.a, &mut swapped.c);
    assert!(!verify(&vk, &swapped, &public).unwrap());
    let mut negated = proof.clone();
    negated.a = (-negated.a.into_group()).into();
    assert!(!verify(&vk, &negated, &public).unwrap());
    let mut wrong_key = vk.clone();
    wrong_key.gamma_abc_g1.swap(1, 2);
    assert!(!verify(&wrong_key, &proof, &public).unwrap());
    assert!(verify(&vk, &proof, &public[..17]).is_err(), "wrong input count is an error");
}

#[test]
fn g2_coordinate_order_matters() {
    // snarkjs writes Fq2 as [c0, c1]; reading it as [c1, c0] gives a point off the twist.
    let mut json = vector("batch-proof.json");
    let x = json["pi_b"][0].as_array().unwrap().clone();
    json["pi_b"][0] = Value::Array(vec![x[1].clone(), x[0].clone()]);
    assert!(proof_from_snarkjs(&json).is_err());
}

#[test]
fn non_canonical_encodings_are_refused() {
    let public = vector("batch-public.json");
    let raw = public_integers(&public).unwrap();
    for i in 0..raw.len() {
        let mut plus_r = public.clone();
        plus_r[i] = Value::String((&raw[i] + fr_modulus()).to_string());
        assert!(public_from_snarkjs(&plus_r).unwrap_err().0.contains("not below the field modulus"));
    }
    for bad in ["", "01", "-1", "1e3", " 1", "0x10"] {
        let mut p = public.clone();
        p[0] = Value::String(bad.to_string());
        assert!(public_from_snarkjs(&p).is_err(), "{bad:?}");
    }
    let mut p = public.clone();
    p[0] = Value::from(5u64);
    assert!(public_from_snarkjs(&p).is_err(), "numbers must be strings");

    let mut proof = vector("batch-proof.json");
    proof["pi_a"][2] = Value::String("2".into());
    assert!(proof_from_snarkjs(&proof).is_err(), "z must be 1");
    let mut proof = vector("batch-proof.json");
    let y = parse_decimal(&proof["pi_a"][1], "y").unwrap();
    proof["pi_a"][1] = Value::String((y + 1u32).to_string());
    assert!(proof_from_snarkjs(&proof).unwrap_err().0.contains("not on the BN254 G1 curve"));
}

#[test]
fn arkworks_serialization_round_trips() {
    let (vk, proof, _) = load("batch");
    let mut bytes = vec![];
    proof.serialize_compressed(&mut bytes).unwrap();
    assert_eq!(bytes.len(), 128);
    assert_eq!(ark_groth16::Proof::<ark_bn254::Bn254>::deserialize_compressed(&bytes[..]).unwrap(), proof);
    let mut bytes = vec![];
    vk.serialize_compressed(&mut bytes).unwrap();
    assert_eq!(ark_groth16::VerifyingKey::<ark_bn254::Bn254>::deserialize_compressed(&bytes[..]).unwrap(), vk);
}
