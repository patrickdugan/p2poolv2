//! The conversion on accounting16x4_hashed (M3, verifying key sha256 3264f607...530ae009fc):
//! one public signal, statementHash. Both proofs verify under ark-groth16, a shifted hash or
//! the other proof's hash fails, and statementHash + r is refused.

use ark_bn254::Fr;
use serde_json::{json, Value};
use zkc_convert::*;

fn vector(name: &str) -> Value {
    let path = format!("{}/../vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

fn load(prefix: &str) -> (ark_groth16::VerifyingKey<ark_bn254::Bn254>, ark_groth16::Proof<ark_bn254::Bn254>, Vec<Fr>) {
    (
        vk_from_snarkjs(&vector("hashed-verification_key.json")).unwrap(),
        proof_from_snarkjs(&vector(&format!("hashed-{prefix}-proof.json"))).unwrap(),
        public_from_snarkjs(&vector(&format!("hashed-{prefix}-public.json"))).unwrap(),
    )
}

#[test]
fn hashed_proofs_verify_with_one_public_signal() {
    for prefix in ["example", "batch"] {
        let (vk, proof, public) = load(prefix);
        assert_eq!(public.len(), 1);
        assert_eq!(vk.gamma_abc_g1.len(), 2);
        assert!(verify(&vk, &proof, &public).unwrap(), "{prefix} proof");
        assert!(!verify(&vk, &proof, &[public[0] + Fr::from(1u64)]).unwrap(), "{prefix} shifted hash");
    }
}

#[test]
fn hashed_proof_for_one_statement_does_not_verify_another() {
    let (vk, example_proof, example_public) = load("example");
    let (_, batch_proof, batch_public) = load("batch");
    assert_ne!(example_public, batch_public);
    assert!(!verify(&vk, &example_proof, &batch_public).unwrap());
    assert!(!verify(&vk, &batch_proof, &example_public).unwrap());
}

#[test]
fn statement_hash_plus_r_is_refused() {
    let public = vector("hashed-batch-public.json");
    let hash: num_bigint::BigUint = public[0].as_str().unwrap().parse().unwrap();
    let plus_r = json!([(hash + fr_modulus()).to_string()]);
    assert!(public_from_snarkjs(&plus_r).is_err());
}

#[test]
fn batch_statement_is_the_committed_circuits_public_signals() {
    // The M3 batch proves the same clearing statement as the M1 batch proof.
    let statement = vector("hashed-batch-statement.json");
    assert_eq!(statement["statement"], vector("batch-public.json"));
    assert_eq!(statement["statementHash"], vector("hashed-batch-public.json")[0]);
}
