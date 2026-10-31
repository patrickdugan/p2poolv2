//! Convert one snarkjs proof and verifying key to arkworks and check that the conversion is
//! faithful: the proof verifies under ark-groth16, every public signal shifted by one fails,
//! and a signal written as x + r is refused. Writes a JSON report and exits non-zero if any
//! check goes the wrong way.
//!
//! Usage: zkc-convert <verification_key.json> <proof.json> <public.json> <report.json>

use ark_bn254::Fr;
use serde_json::{json, Value};
use std::process::ExitCode;
use zkc_convert::*;

fn read(path: &str) -> Value {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {path}: {e}"))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        eprintln!("usage: zkc-convert <verification_key.json> <proof.json> <public.json> <report.json>");
        return ExitCode::from(2);
    }
    let (vk_json, proof_json, public_json) = (read(&args[1]), read(&args[2]), read(&args[3]));
    let vk = vk_from_snarkjs(&vk_json).expect("verifying key");
    let proof = proof_from_snarkjs(&proof_json).expect("proof");
    let public = public_from_snarkjs(&public_json).expect("public signals");

    let mut ok = true;
    let verifies = verify(&vk, &proof, &public).expect("verify");
    ok &= verifies;

    let mut shifted_rejected = vec![];
    for i in 0..public.len() {
        let mut tampered = public.clone();
        tampered[i] += Fr::from(1u64);
        let accepted = verify(&vk, &proof, &tampered).expect("verify tampered");
        ok &= !accepted;
        shifted_rejected.push(!accepted);
    }

    let mut plus_r = public_json.clone();
    let raw = public_integers(&public_json).expect("integers");
    plus_r[0] = Value::String((&raw[0] + fr_modulus()).to_string());
    let plus_r_result = public_from_snarkjs(&plus_r);
    ok &= plus_r_result.is_err();

    let report = json!({
        "verifying_key_ark_compressed": compressed_hex(&vk),
        "proof_ark_compressed": compressed_hex(&proof),
        "proof_ark_compressed_bytes": compressed_hex(&proof).len() / 2,
        "public_signals": public.iter().map(fr_decimal).collect::<Vec<_>>(),
        "ark_groth16_verifies": verifies,
        "each_signal_plus_one_rejected": shifted_rejected,
        "signal0_plus_r": match &plus_r_result {
            Ok(_) => "ACCEPTED".to_string(),
            Err(e) => format!("refused: {e}"),
        },
        "all_checks_pass": ok,
    });
    std::fs::write(&args[4], serde_json::to_string_pretty(&report).unwrap()).expect("write report");
    println!(
        "ark-groth16 verifies: {verifies}; {} of {} shifted signals rejected; x + r refused: {}",
        shifted_rejected.iter().filter(|r| **r).count(),
        public.len(),
        plus_r_result.is_err()
    );
    if ok {
        ExitCode::SUCCESS
    } else {
        eprintln!("conversion check FAILED");
        ExitCode::FAILURE
    }
}
