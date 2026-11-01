//! Glue to BitVM's chunked Groth16 verifier (patched to 18 public inputs for M1, or 1 for M3)
//! and the Winternitz scripts around it: commit leaves for the assert transactions, binding leaves that tie the
//! asserted public signals to the payout template, and witness helpers.

use ark_bn254::{Bn254, Fr};
use ark_ff::BigInt;
use ark_groth16::{Proof, VerifyingKey};
use bitcoin::ScriptBuf;
use bitvm::chunk::api::{
    api_disprove_witness_for_leaf, api_disprove_witnesses_for_all_leaves, api_generate_full_tapscripts, api_generate_partial_script,
    api_get_assertions_from_signature, api_get_pubkeys, api_get_signature_from_assertion,
    api_u256_assertion_bytes, generate_assertions, generate_signatures_for_any_proof,
    validate_assertions, Assertions, PublicKeys, Signatures, NUM_HASH, NUM_PUBS, NUM_TAPS, NUM_U256,
};
use bitvm::signatures::{CompactWots, Wots, Wots16, Wots32};
use bitvm::treepp::{script, Script};
use num_bigint::BigUint;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Values the operator commits with Winternitz signatures: NUM_PUBS public signals (18 in M1,
/// 1 in M3) and 14 proof field elements (Wots32 each), then NUM_HASH intermediate hashes
/// (Wots16 each; 431 in M1, 363 in M3).
pub const NUM_VALUES: usize = NUM_PUBS + NUM_U256 + NUM_HASH;

/// The operator's one-time Winternitz secrets for one graph. Derived from a public seed: the
/// demo's operator is not secret.
pub fn secrets(seed: &str) -> Vec<String> {
    let base = hex::encode(&Sha256::digest(format!("p2poolv2/zk_clearing/bitvm-m1/wots/{seed}").as_bytes())[..20]);
    (0..NUM_VALUES).map(|i| format!("{base}{i:04x}")).collect()
}

pub fn pubkeys(secrets: &[String]) -> PublicKeys {
    api_get_pubkeys(secrets.to_vec())
}

/// BitVM keeps public inputs in reverse order (`msm_scalar.reverse()`), so the assertion,
/// Winternitz key and signature of public signal `i` sit at slot NUM_PUBS - 1 - i.
pub fn pub_slot(signal: usize) -> usize {
    NUM_PUBS - 1 - signal
}

pub fn is_wots32(j: usize) -> bool {
    j < NUM_PUBS + NUM_U256
}

/// The full (digit-carrying) Winternitz signature of value `j` as witness items.
pub fn raw_witness(sigs: &Signatures, j: usize) -> Vec<Vec<u8>> {
    let w = if j < NUM_PUBS {
        Wots32::signature_to_raw_witness(&sigs.0[j])
    } else if j < NUM_PUBS + NUM_U256 {
        Wots32::signature_to_raw_witness(&sigs.1[j - NUM_PUBS])
    } else {
        Wots16::signature_to_raw_witness(&sigs.2[j - NUM_PUBS - NUM_U256])
    };
    w.iter().map(|item| item.to_vec()).collect()
}

pub fn raw_witness_len(j: usize) -> usize {
    2 * if is_wots32(j) { Wots32::TOTAL_DIGIT_LEN } else { Wots16::TOTAL_DIGIT_LEN } as usize
}

/// Rebuilds the operator's signatures from the raw witness items of every value, as a
/// challenger does from the assert transactions on chain.
pub fn signatures_from_raw(items: &[Vec<Vec<u8>>]) -> Signatures {
    assert_eq!(items.len(), NUM_VALUES);
    let witness = |j: usize| bitcoin::Witness::from_slice(&items[j]);
    let pubs: Vec<_> = (0..NUM_PUBS).map(|j| Wots32::raw_witness_to_signature(&witness(j))).collect();
    let fqs: Vec<_> = (NUM_PUBS..NUM_PUBS + NUM_U256).map(|j| Wots32::raw_witness_to_signature(&witness(j))).collect();
    let hashes: Vec<_> = (NUM_PUBS + NUM_U256..NUM_VALUES).map(|j| Wots16::raw_witness_to_signature(&witness(j))).collect();
    (
        Box::new(pubs.try_into().unwrap_or_else(|_| unreachable!())),
        Box::new(fqs.try_into().unwrap_or_else(|_| unreachable!())),
        Box::new(hashes.try_into().unwrap_or_else(|_| unreachable!())),
    )
}

fn verify_and_clear(pubkeys: &PublicKeys, j: usize) -> Script {
    if j < NUM_PUBS {
        Wots32::checksig_verify_and_clear_stack(&pubkeys.0[j])
    } else if j < NUM_PUBS + NUM_U256 {
        Wots32::checksig_verify_and_clear_stack(&pubkeys.1[j - NUM_PUBS])
    } else {
        Wots16::checksig_verify_and_clear_stack(&pubkeys.2[j - NUM_PUBS - NUM_U256])
    }
}

/// The Winternitz part of a commit leaf: every signature in the batch must verify against
/// the operator's key for that value. Leaves the stack as it found it.
pub fn commit_wots_part(pubkeys: &PublicKeys, batch: &[usize]) -> Script {
    script! {
        for j in batch {
            { verify_and_clear(pubkeys, *j) }
        }
    }
}

/// Commit leaf for a batch of values: the Winternitz part, then the operator's Schnorr
/// signature binds the spending transaction.
pub fn commit_leaf(pubkeys: &PublicKeys, batch: &[usize], operator: &bitcoin::secp256k1::XOnlyPublicKey) -> ScriptBuf {
    script! {
        { commit_wots_part(pubkeys, batch) }
        { operator.serialize().to_vec() }
        OP_CHECKSIG
    }
    .compile()
}

/// Witness items (bottom to top, before the Schnorr signature) for `commit_leaf(batch)`:
/// the first value's signature ends on top of the stack.
pub fn commit_witness(sigs: &Signatures, batch: &[usize]) -> Vec<Vec<u8>> {
    batch.iter().rev().flat_map(|j| raw_witness(sigs, *j)).collect()
}

/// Splits the values into commit batches whose witnesses stay under `max_items` stack items.
pub fn commit_batches(max_items: usize) -> Vec<Vec<usize>> {
    let mut batches: Vec<Vec<usize>> = vec![vec![]];
    let mut items = 0;
    for j in 0..NUM_VALUES {
        let len = raw_witness_len(j);
        if items + len > max_items {
            batches.push(vec![]);
            items = 0;
        }
        batches.last_mut().unwrap().push(j);
        items += len;
    }
    batches
}

/// Assertion bytes the operator commits for public signal value `n` (any 256-bit integer).
pub fn u256_assertion(n: &BigUint) -> [u8; 32] {
    let digits = n.to_u64_digits();
    assert!(digits.len() <= 4, "value wider than 256 bits");
    let mut limbs = [0u64; 4];
    limbs[..digits.len()].copy_from_slice(&digits);
    api_u256_assertion_bytes(BigInt::<4>(limbs))
}

/// The digits `compact_checksig_verify` leaves for a public-signal commitment to `n`, listed
/// from the top of the stack down. Digits depend only on the message, so a throwaway key is
/// used.
fn message_digits_top_down(n: &BigUint) -> Vec<i64> {
    let secret = b"p2poolv2-zkc-m1-binding-probe".to_vec();
    let pk = Wots32::generate_public_key(&secret);
    let sig: Vec<Vec<u8>> = Wots32::compact_sign_to_raw_witness(&secret, &u256_assertion(n)).iter().map(|i| i.to_vec()).collect();
    let exec = run_leaf(&Wots32::compact_checksig_verify(&pk).compile(), &sig);
    let stack = &exec.final_stack;
    assert_eq!(stack.len(), 64, "compact_checksig_verify should leave 64 message digits");
    // FmtStack::get(0) is the bottom item (probe_stack_order checks this).
    (0..stack.len())
        .rev()
        .map(|i| {
            let item = stack.get(i);
            assert!(item.len() <= 1 && item.first().is_none_or(|d| *d < 16), "digit item {item:?}");
            item.first().copied().unwrap_or(0) as i64
        })
        .collect()
}

/// Confirms that `FmtStack::get(0)` is the bottom of the stack.
pub fn probe_stack_order() {
    let exec = run_leaf(&script! { 1 2 3 }.compile(), &[]);
    assert_eq!(exec.final_stack.get(0), vec![1u8]);
    assert_eq!(exec.final_stack.get(2), vec![3u8]);
}

/// Binding leaf for public signal `i`: succeeds iff the operator's Winternitz commitment to
/// signal i decodes to anything other than `expected`, the value the payout template was built
/// from. Covers a different value and the non-canonical `expected + r` alike.
pub fn binding_leaf(pubkeys: &PublicKeys, i: usize, expected: &BigUint) -> ScriptBuf {
    let digits = message_digits_top_down(expected);
    script! {
        { Wots32::compact_checksig_verify(&pubkeys.0[pub_slot(i)]) }
        for digit in &digits {
            { *digit } OP_NUMEQUAL OP_TOALTSTACK
        }
        OP_FROMALTSTACK
        for _ in 1..digits.len() {
            OP_FROMALTSTACK OP_BOOLAND
        }
        OP_NOT
    }
    .compile()
}

/// Witness items for a binding leaf: the compact signature of public signal `i`.
pub fn binding_witness(sigs: &Signatures, i: usize) -> Vec<Vec<u8>> {
    Wots32::compact_signature_to_raw_witness(&Wots32::signature_to_compact_signature(&sigs.0[pub_slot(i)]))
        .iter()
        .map(|item| item.to_vec())
        .collect()
}

/// Turns a push-only BitVM hint script into witness items.
pub fn push_script_to_items(hint: &Script) -> Vec<Vec<u8>> {
    use bitcoin::opcodes::all::*;
    use bitcoin::script::Instruction;
    let compiled = hint.clone().compile();
    compiled
        .instructions()
        .map(|ins| match ins.expect("hint script parses") {
            Instruction::PushBytes(bytes) => bytes.as_bytes().to_vec(),
            Instruction::Op(op) if op == OP_PUSHNUM_NEG1 => vec![0x81],
            Instruction::Op(op) if (OP_PUSHNUM_1.to_u8()..=OP_PUSHNUM_16.to_u8()).contains(&op.to_u8()) => {
                vec![op.to_u8() - OP_PUSHNUM_1.to_u8() + 1]
            }
            Instruction::Op(op) => panic!("hint script is not push-only: {op:?}"),
        })
        .collect()
}

/// BitVM's tapscript interpreter on a witness stack (`items`, bottom to top) and a leaf.
pub fn run_leaf(leaf: &ScriptBuf, items: &[Vec<u8>]) -> bitvm::ExecuteInfo {
    bitvm::execute_raw_script_with_inputs(leaf.to_bytes(), items.to_vec())
}

/// True iff `leaf` succeeds on `items` within consensus's 1,000-item stack limit (stack and
/// altstack together, the witness included).
pub fn leaf_succeeds(leaf: &ScriptBuf, items: &[Vec<u8>]) -> bool {
    let exec = run_leaf(leaf, items);
    exec.success && exec.stats.max_nb_stack_items <= 1000
}

pub fn fr_list(signals: &[BigUint]) -> Vec<Fr> {
    signals.iter().map(|s| Fr::from(s.clone())).collect()
}

/// The vk-dependent part of every disprove leaf, cached in `dir` (one file per leaf).
pub fn partial_scripts(vk: &VerifyingKey<Bn254>, dir: &Path) -> Vec<ScriptBuf> {
    let done = dir.join("done");
    if done.exists() {
        return (0..NUM_TAPS)
            .map(|k| ScriptBuf::from_bytes(std::fs::read(dir.join(format!("{k:04}.bin"))).unwrap()))
            .collect();
    }
    std::fs::create_dir_all(dir).unwrap();
    let scripts = api_generate_partial_script(vk);
    assert_eq!(scripts.len(), NUM_TAPS);
    for (k, s) in scripts.iter().enumerate() {
        std::fs::write(dir.join(format!("{k:04}.bin")), s.as_bytes()).unwrap();
    }
    std::fs::write(done, b"").unwrap();
    scripts
}

pub fn full_tapscripts(pubkeys: &PublicKeys, partial: &[ScriptBuf]) -> Vec<ScriptBuf> {
    api_generate_full_tapscripts(*pubkeys, partial)
}

pub fn honest_assertions(proof: &Proof<Bn254>, signals: &[BigUint], vk: &VerifyingKey<Bn254>) -> Assertions {
    generate_assertions(proof.clone(), fr_list(signals), vk).expect("honest proof yields valid assertions")
}

/// Assertions an operator computes from a proof that does not verify for `signals`.
pub fn any_assertions(proof: &Proof<Bn254>, signals: &[BigUint], vk: &VerifyingKey<Bn254>) -> Assertions {
    let throwaway = secrets("assertion-generation");
    api_get_assertions_from_signature(generate_signatures_for_any_proof(proof.clone(), fr_list(signals), vk, throwaway))
}

pub fn sign(assertions: Assertions, secrets: &[String]) -> Signatures {
    api_get_signature_from_assertion(assertions, secrets.to_vec())
}

/// First disprove leaf that the signed assertions open, with its witness.
pub fn validate(vk: &VerifyingKey<Bn254>, sigs: &Signatures, pubkeys: &PublicKeys, leaves: &[ScriptBuf]) -> Option<(usize, Vec<Vec<u8>>)> {
    let leaves: &[ScriptBuf; NUM_TAPS] = leaves.try_into().expect("NUM_TAPS leaves");
    validate_assertions(vk, sigs.clone(), *pubkeys, leaves).map(|(k, hint)| (k, push_script_to_items(&hint)))
}

pub fn witness_for_leaf(vk: &VerifyingKey<Bn254>, sigs: &Signatures, leaf: usize) -> Option<Vec<Vec<u8>>> {
    api_disprove_witness_for_leaf(vk, sigs.clone(), leaf).map(|hint| push_script_to_items(&hint))
}

/// The witness of every disprove leaf, in leaf order (M12), from one pass over the segments.
pub fn witnesses_for_all_leaves(vk: &VerifyingKey<Bn254>, sigs: &Signatures) -> Vec<Vec<Vec<u8>>> {
    api_disprove_witnesses_for_all_leaves(vk, sigs.clone()).iter().map(push_script_to_items).collect()
}

pub fn assertions_to_json(a: &Assertions) -> Value {
    json!({
        "pubs": a.0.iter().map(hex::encode).collect::<Vec<_>>(),
        "fqs": a.1.iter().map(hex::encode).collect::<Vec<_>>(),
        "hashes": a.2.iter().map(hex::encode).collect::<Vec<_>>(),
    })
}

pub fn assertions_from_json(v: &Value) -> Assertions {
    fn list<const N: usize, const L: usize>(v: &Value) -> [[u8; L]; N] {
        let items: Vec<[u8; L]> = v
            .as_array()
            .unwrap()
            .iter()
            .map(|h| hex::decode(h.as_str().unwrap()).unwrap().try_into().unwrap())
            .collect();
        items.try_into().unwrap_or_else(|_| panic!("expected {N} items"))
    }
    (list::<NUM_PUBS, 32>(&v["pubs"]), list::<NUM_U256, 32>(&v["fqs"]), list::<NUM_HASH, 16>(&v["hashes"]))
}
