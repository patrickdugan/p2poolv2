//! BitVM M1 for zk_clearing: assert the 18 public signals of an accounting16x4_committed
//! Groth16 proof on Bitcoin regtest, and settle by a payout template, a disprove, or a timeout.
//!
//! Built against BitVM with NUM_PUBS = 1 (patches/0002, M3), the same harness asserts the
//! single public signal of accounting16x4_hashed, statementHash, and the payout template is
//! built from the statement that hashes to it (<work>/batch/statement.json).
//!
//! M14: the same build settles M11's signed-tree proof. The statement layout is chosen by the
//! circuit name in <work>/batch/circuit.txt (written by prove-batch.sh): `signed_tree_16x4`
//! selects the 20-value signed-tree statement, hashed by PoseidonChunked, whose template
//! (template::build_signed) also opens saleCommitment and escrowCommitment from
//! <work>/batch/input.json and checks the payee labels in opening.json against the signed ids.
//! Without circuit.txt (the M1 and M3 batches) the statement is the 18 accounting values.
//!
//! Usage:
//!   zkc-m1 prepare  <work>             disprove scripts and assertions (cached under <work>/m1)
//!   zkc-m1 disproves <work>            M12: every disprove transaction's weight (<work>/m12)
//!   zkc-m1 selftest <work>             script-level checks, no node
//!   zkc-m1 scenario <work> <name>      honest | tampered | mismatch | plus-r | stall, on regtest
//!
//! <work> is the directory prove-batch.sh filled (<work>/batch). The node is reached through
//! ZKC_RPC_URL, ZKC_RPC_USER, ZKC_RPC_PASS and ZKC_WALLET.

mod chunked;
mod graph;
mod rpc;
mod taproot;
mod template;

use ark_bn254::Bn254;
use ark_groth16::{Proof, VerifyingKey};
use bitcoin::hashes::Hash;
use bitcoin::{Address, OutPoint, ScriptBuf, Transaction, TxOut, Witness};
use bitvm::chunk::api::{Assertions, NUM_PUBS, NUM_TAPS};
use bitvm::signatures::{Wots, Wots32};
use graph::*;
use num_bigint::BigUint;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::Instant;
use taproot::{key_path_script, leaf_hash, ScriptTree};

/// Stack items allowed per commit input; consensus allows 1,000 including temporaries.
const COMMIT_MAX_ITEMS: usize = 900;
/// M3: the proof's only public signal is statementHash. M1: the 18 statement values are public.
const HASHED: bool = NUM_PUBS == 1;
const _: () = assert!(NUM_PUBS == 1 || NUM_PUBS == template::NUM_SIGNALS);
/// The public signal the plus-r scenario re-encodes as x + r: refund[1] (M1), statementHash (M3).
const PLUS_R_SIGNAL: usize = if HASHED { 0 } else { template::refund(1) };
/// The public signal whose binding leaf the mismatch scenario opens: refund[0] (M1),
/// statementHash (M3).
const MISMATCH_SIGNAL: usize = if HASHED { 0 } else { template::refund(0) };

struct Inputs {
    work: PathBuf,
    /// The statement layout (`circuit.txt`): M1's and M3's 18 accounting values, or M11's
    /// signed-tree statement.
    kind: template::Kind,
    vk: VerifyingKey<Bn254>,
    proof: Proof<Bn254>,
    /// The proof's public signals (NUM_PUBS of them).
    signals: Vec<BigUint>,
    /// The clearing statement: `signals` itself in M1, its hash preimage in M3 (18 values) and
    /// M14 (4 + 4B values).
    statement: Vec<BigUint>,
    input: Value,
    opening: Value,
    commitment: BigUint,
}

fn read_json(path: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))).unwrap()
}

/// The statement layout of the batch: the circuit name in `<batch>/circuit.txt`. M1 and M3 batches
/// have no such file and use the 18 accounting values.
fn batch_kind(batch: &Path) -> template::Kind {
    match std::fs::read_to_string(batch.join("circuit.txt")) {
        Ok(name) => template::Kind::from_circuit(name.trim()).unwrap_or_else(|e| panic!("{}: {e}", batch.join("circuit.txt").display())),
        Err(_) => template::Kind::Accounting,
    }
}

fn load(work: &Path) -> Inputs {
    let batch = work.join("batch");
    let kind = batch_kind(&batch);
    assert!(kind == template::Kind::Accounting || HASHED, "a signed-tree statement needs the 1-public-input build (ZKC_PUBS=1)");
    let vk = zkc_convert::vk_from_snarkjs(&read_json(&batch.join("verification_key.json"))).unwrap();
    let proof = zkc_convert::proof_from_snarkjs(&read_json(&batch.join("proof.json"))).unwrap();
    let public = read_json(&batch.join("public.json"));
    let fr = zkc_convert::public_from_snarkjs(&public).unwrap();
    assert!(zkc_convert::verify(&vk, &proof, &fr).unwrap(), "batch proof must verify under ark-groth16");
    let signals = zkc_convert::public_integers(&public).unwrap();
    assert_eq!(signals.len(), NUM_PUBS, "public signals of the batch proof");
    let statement = if HASHED {
        zkc_convert::public_integers(&read_json(&batch.join("statement.json"))["statement"]).unwrap()
    } else {
        signals.clone()
    };
    assert_eq!(statement.len(), kind.statement_len(), "statement length for {kind:?}");
    let inp = Inputs {
        work: work.to_path_buf(),
        kind,
        vk,
        proof,
        signals,
        statement,
        input: read_json(&batch.join("input.json")),
        opening: read_json(&batch.join("opening.json")),
        commitment: std::fs::read_to_string(batch.join("sale_commitment.txt")).unwrap().trim().parse().unwrap(),
    };
    assert_eq!(public_of(kind, &inp.statement), inp.signals, "the statement does not match the proof's public signals");
    if let template::Kind::SignedTree { buyers, .. } = kind {
        // Two implementations of the commitments agree: circomlibjs (prove-batch.sh) and the Rust
        // template (light-poseidon), which recomputes both from the circuit input.
        let escrow: BigUint = std::fs::read_to_string(batch.join("escrow_commitment.txt")).unwrap().trim().parse().unwrap();
        assert_eq!(template::sale_commitment(&inp.input).expect("sale commitment"), inp.commitment, "saleCommitment: Rust against circomlibjs");
        let funding = &inp.statement[template::signed_funding(0)..template::signed_funding(buyers)];
        assert_eq!(template::escrow_commitment(&inp.input, funding).expect("escrow commitment"), escrow, "escrowCommitment: Rust against circomlibjs");
    }
    inp
}

/// The public signals a proof of `statement` carries.
fn public_of(kind: template::Kind, statement: &[BigUint]) -> Vec<BigUint> {
    if HASHED {
        vec![kind.statement_hash(statement).expect("statement hash")]
    } else {
        statement.to_vec()
    }
}

fn public_name(i: usize) -> String {
    if HASHED {
        "statementHash".into()
    } else {
        template::signal_name(i)
    }
}

/// The committee's payout template for `statement`; in M3 and M14 it also checks the hash preimage.
fn template_for(inp: &Inputs, statement: &[BigUint]) -> template::Template {
    let built = if HASHED {
        inp.kind.build_hashed(&public_of(inp.kind, statement)[0], statement, &inp.input, &inp.opening, &inp.commitment)
    } else {
        template::build(statement, &inp.input, &inp.opening, &inp.commitment)
    };
    built.expect("template")
}

/// The tampered statement: `Kind::moved_sats` of refund moved from buyer slot 1 to slot 0. Total
/// conservation still holds, so the template accepts it; buyer slot 0's own equation
/// funding = cost + fee + refund fails, so no valid proof exists for it.
fn tampered(kind: template::Kind, statement: &[BigUint]) -> Vec<BigUint> {
    let mut s = statement.to_vec();
    let moved = kind.moved_for(statement);
    s[kind.refund_index(0)] += moved;
    s[kind.refund_index(1)] -= moved;
    s
}

fn m1_dir(inp: &Inputs) -> PathBuf {
    let dir = inp.work.join("m1");
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn timed<T>(label: &str, f: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let out = f();
    eprintln!("[time] {label}: {:.1} s", start.elapsed().as_secs_f64());
    out
}

fn partial(inp: &Inputs) -> Vec<ScriptBuf> {
    timed("partial disprove scripts", || chunked::partial_scripts(&inp.vk, &m1_dir(inp).join("partial")))
}

fn cached_assertions(inp: &Inputs, name: &str, make: impl FnOnce() -> Assertions) -> Assertions {
    let path = m1_dir(inp).join(format!("assertions-{name}.json"));
    if path.exists() {
        return chunked::assertions_from_json(&read_json(&path));
    }
    let a = timed(&format!("assertions {name}"), make);
    std::fs::write(&path, serde_json::to_string(&chunked::assertions_to_json(&a)).unwrap()).unwrap();
    a
}

fn honest_assertions(inp: &Inputs) -> Assertions {
    cached_assertions(inp, "honest", || chunked::honest_assertions(&inp.proof, &inp.signals, &inp.vk))
}

fn tampered_assertions(inp: &Inputs) -> Assertions {
    cached_assertions(inp, "tampered", || chunked::any_assertions(&inp.proof, &public_of(inp.kind, &tampered(inp.kind, &inp.statement)), &inp.vk))
}

fn plus_r_assertions(inp: &Inputs, signal: usize) -> Assertions {
    let mut a = honest_assertions(inp);
    for i in 0..NUM_PUBS {
        assert_eq!(a.0[chunked::pub_slot(i)], chunked::u256_assertion(&inp.signals[i]), "assertion encoding of {}", public_name(i));
    }
    a.0[chunked::pub_slot(signal)] = chunked::u256_assertion(&(&inp.signals[signal] + zkc_convert::fr_modulus()));
    a
}

fn write_result(inp: &Inputs, name: &str, value: &Value) {
    let path = m1_dir(inp).join(format!("{name}.json"));
    std::fs::write(&path, serde_json::to_string_pretty(value).unwrap()).unwrap();
    eprintln!("wrote {}", path.display());
}

fn prepare(inp: &Inputs) {
    let partial = partial(inp);
    let secrets = chunked::secrets("leaf-size-survey");
    let full = timed("full tapscripts", || chunked::full_tapscripts(&chunked::pubkeys(&secrets), &partial));
    let sizes: Vec<usize> = full.iter().map(|s| s.len()).collect();
    let mut sorted = sizes.clone();
    sorted.sort();
    honest_assertions(inp);
    tampered_assertions(inp);
    write_result(
        inp,
        "leaves",
        &json!({
            "num_pubs": NUM_PUBS,
            "num_u256": bitvm::chunk::api::NUM_U256,
            "num_hash": bitvm::chunk::api::NUM_HASH,
            "winternitz_values": chunked::NUM_VALUES,
            "commit_batches": chunked::commit_batches(COMMIT_MAX_ITEMS).len(),
            "disprove_leaves": NUM_TAPS,
            "total_bytes": sizes.iter().sum::<usize>(),
            "min_bytes": sorted[0],
            "median_bytes": sorted[sorted.len() / 2],
            "max_bytes": sorted[sorted.len() - 1],
            "max_leaf_index": sizes.iter().position(|s| *s == sorted[sorted.len() - 1]),
            "over_400k_weight": sizes.iter().filter(|s| **s > 400_000).count(),
            "sizes": sizes,
        }),
    );
}

/// M12: the weight of every disprove transaction, against relay policy and the block limit.
/// Each BitVM leaf is spent with its witness for the honest assertion (a disproving witness has
/// the same items, except that a zero Winternitz digit is an empty item) and a control block for
/// A's tree. Two shapes are weighed: M1's (A alone, one P2TR output) and M2's (KB with its
/// committee signature, then A; a burn output and a P2TR reward output).
fn disproves(inp: &Inputs) {
    let partial = partial(inp);
    let secrets = chunked::secrets("leaf-size-survey");
    let pubkeys = chunked::pubkeys(&secrets);
    let full = timed("full tapscripts", || chunked::full_tapscripts(&pubkeys, &partial));
    let sigs = chunked::sign(honest_assertions(inp), &secrets);
    // A's tree holds the BitVM leaves, one binding leaf per public signal and the payout leaf.
    let tree_leaves = NUM_TAPS + NUM_PUBS + 1;
    let depth = (usize::BITS - (tree_leaves - 1).leading_zeros()) as usize;
    let control = vec![0u8; 33 + 32 * depth];
    let p2tr = ScriptBuf::from_bytes([vec![0x51, 0x20], vec![0u8; 32]].concat());
    let burn = ScriptBuf::from_bytes(vec![0x6a]);
    let input = |vout: u32, witness: Witness| bitcoin::TxIn {
        previous_output: OutPoint { txid: bitcoin::Txid::all_zeros(), vout },
        script_sig: ScriptBuf::new(),
        sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness,
    };
    let spend = |inputs: Vec<bitcoin::TxIn>, outputs: Vec<TxOut>| Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: inputs,
        output: outputs,
    };
    let out = |script: &ScriptBuf| TxOut { value: bitcoin::Amount::from_sat(1_000), script_pubkey: script.clone() };

    let witnesses = timed("witnesses for every leaf", || chunked::witnesses_for_all_leaves(&inp.vk, &sigs));
    assert_eq!(witnesses.len(), full.len(), "one witness per disprove leaf");
    let mut rows = vec![];
    for (i, (leaf, items)) in full.iter().zip(&witnesses).enumerate() {
        let mut stack = items.clone();
        stack.push(leaf.to_bytes());
        stack.push(control.clone());
        let a_witness = Witness::from_slice(&stack);
        let m1 = spend(vec![input(0, a_witness.clone())], vec![out(&p2tr)]);
        let m2 = spend(vec![input(0, Witness::from_slice(&[vec![0u8; 65]])), input(1, a_witness)], vec![out(&burn), out(&p2tr)]);
        rows.push(json!({
            "leaf": i, "script_bytes": leaf.len(), "witness_items": items.len(),
            "empty_items": items.iter().filter(|x| x.is_empty()).count(),
            "witness_item_bytes": items.iter().map(Vec::len).sum::<usize>(),
            "m1_weight": m1.weight().to_wu(), "m2_weight": m2.weight().to_wu(),
        }));
    }
    let weight = |r: &Value| r["m2_weight"].as_u64().unwrap();
    let heaviest = rows.iter().max_by_key(|r| weight(r)).unwrap().clone();
    // Core's default template (-blockmaxweight 3,996,000) keeps 4,000 WU for the coinbase.
    let over = |limit: u64| rows.iter().filter(|r| weight(r) > limit).count();
    // What a chunk pays to hash an intermediate state, by its size in bytes: 2, 4, 6, 12 and
    // 14 field elements. Splitting a chunk hashes the state at the split twice, once per side.
    let blake3: serde_json::Map<String, Value> = [64usize, 128, 192, 384, 448]
        .iter()
        .map(|n| (n.to_string(), json!(bitvm::hash::blake3::blake3_compute_script(*n).compile().len())))
        .collect();
    let dir = inp.work.join("m12");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("disproves-{NUM_PUBS}pub.json"));
    let report = json!({
        "num_pubs": NUM_PUBS, "disprove_leaves": NUM_TAPS, "a_tree_leaves": tree_leaves, "a_tree_depth": depth,
        "blake3_script_bytes_by_message_bytes": blake3,
        "heaviest_m2": heaviest,
        "m2_over_400000_wu_standard_limit": over(400_000),
        "m2_over_3992000_wu_default_template": over(3_992_000),
        "m2_over_4000000_wu_block_limit": over(4_000_000),
        "leaves": rows,
    });
    std::fs::write(&path, serde_json::to_string_pretty(&report).unwrap()).unwrap();
    eprintln!("wrote {}", path.display());
}

/// Script-level checks that need no node.
fn selftest(inp: &Inputs, all_plus_r: bool) {
    chunked::probe_stack_order();
    let partial = partial(inp);
    let secrets = chunked::secrets("selftest");
    let pubkeys = chunked::pubkeys(&secrets);
    let honest = chunked::sign(honest_assertions(inp), &secrets);
    let mut report = json!({});

    // Commit leaves: every batch verifies on the honest signatures within the stack limit.
    let batches = chunked::commit_batches(COMMIT_MAX_ITEMS);
    let mut max_stack = 0;
    for batch in &batches {
        let part = bitvm::treepp::script! { { chunked::commit_wots_part(&pubkeys, batch) } OP_TRUE }.compile();
        let items = chunked::commit_witness(&honest, batch);
        let exec = chunked::run_leaf(&part, &items);
        assert!(exec.success, "commit batch {batch:?} fails on honest signatures");
        max_stack = max_stack.max(exec.stats.max_nb_stack_items);
        // A signature for a different message under the same key fails.
        let mut bad = items.clone();
        let top = bad.len() - 1;
        bad[top] = if bad[top].is_empty() { vec![1] } else { vec![] };
        assert!(!chunked::run_leaf(&part, &bad).success, "commit batch accepts a corrupted digit");
    }
    report["commit_batches"] = json!(batches.len());
    report["commit_max_stack_items"] = json!(max_stack);

    // Binding leaves: fail on the honest commitment, succeed on any other value.
    let s_prime = public_of(inp.kind, &tampered(inp.kind, &inp.statement));
    let mut binding = vec![];
    for i in 0..NUM_PUBS {
        let leaf = chunked::binding_leaf(&pubkeys, i, &inp.signals[i]);
        let honest_opens = chunked::leaf_succeeds(&leaf, &chunked::binding_witness(&honest, i));
        let leaf_for_s_prime = chunked::binding_leaf(&pubkeys, i, &s_prime[i]);
        let mismatch_opens = chunked::leaf_succeeds(&leaf_for_s_prime, &chunked::binding_witness(&honest, i));
        let plus_r = chunked::sign(plus_r_assertions(inp, i), &secrets);
        let plus_r_opens = chunked::leaf_succeeds(&leaf, &chunked::binding_witness(&plus_r, i));
        assert!(!honest_opens, "binding leaf {i} opens on the honest commitment");
        assert_eq!(mismatch_opens, inp.signals[i] != s_prime[i], "binding leaf {i} against S'");
        assert!(plus_r_opens, "binding leaf {i} misses x + r");
        binding.push(json!({"signal": public_name(i), "leaf_bytes": leaf.len(), "honest_opens": honest_opens,
            "opens_when_template_is_S_prime": mismatch_opens, "opens_on_x_plus_r": plus_r_opens}));
    }
    report["binding_leaves"] = json!(binding);

    // BitVM's own range check: an x + r public input opens an MSM chunk.
    if all_plus_r {
        let full = timed("full tapscripts (selftest)", || chunked::full_tapscripts(&pubkeys, &partial));
        let mut sweep = vec![];
        for i in 0..NUM_PUBS {
            let sigs = chunked::sign(plus_r_assertions(inp, i), &secrets);
            let found = timed(&format!("validate x + r on {}", public_name(i)), || chunked::validate(&inp.vk, &sigs, &pubkeys, &full));
            let (leaf, items) = found.unwrap_or_else(|| panic!("x + r on signal {i} not disprovable"));
            assert!(chunked::leaf_succeeds(&full[leaf], &items), "disprove witness does not open leaf {leaf}");
            sweep.push(json!({"signal": public_name(i), "disprove_leaf": leaf, "leaf_bytes": full[leaf].len(), "witness_items": items.len()}));
            write_result(inp, "selftest-plus-r-partial", &json!(sweep));
        }
        report["plus_r_sweep"] = json!(sweep);
    }
    write_result(inp, "selftest", &report);
}

/// One transaction's measurement and fate.
struct Trace {
    rows: Vec<Value>,
}

impl Trace {
    fn record(&mut self, rpc: &rpc::Rpc, name: &str, t: &Transaction, note: &str) -> Result<(), String> {
        let standard = rpc.test_accept(t);
        let row = json!({
            "tx": name, "txid": t.compute_txid().to_string(), "vbytes": t.vsize(), "weight": t.weight().to_wu(),
            "inputs": t.input.len(), "outputs": t.output.len(),
            "mempool_now": match &standard { Ok(()) => "accepted".to_string(), Err(e) => e.clone() },
            "note": note,
        });
        eprintln!("  {name:<22} {:>9} vB  {}", t.vsize(), row["mempool_now"]);
        self.rows.push(row);
        standard
    }

    /// Mines `txs` in one block: through the mempool if all are standard, else generateblock.
    fn mine(&mut self, rpc: &rpc::Rpc, miner: &Address, named: &[(&str, &Transaction)]) {
        let all_standard = named.iter().all(|(_, t)| rpc.test_accept(t).is_ok());
        let how = if all_standard {
            for (_, t) in named {
                rpc.send(t).unwrap();
            }
            rpc.mine(1, miner);
            "mempool"
        } else {
            let txs: Vec<&Transaction> = named.iter().map(|(_, t)| *t).collect();
            rpc.mine_raw(&txs, miner).unwrap_or_else(|e| panic!("block with {:?} rejected: {e}", named.iter().map(|n| n.0).collect::<Vec<_>>()));
            "generateblock"
        };
        let height = rpc.height();
        for (name, t) in named {
            assert!(rpc.confirmations(&t.compute_txid()).is_some(), "{name} not confirmed");
            if let Some(row) = self.rows.iter_mut().rev().find(|r| r["tx"] == *name) {
                row["mined_height"] = json!(height);
                row["mined_via"] = json!(how);
            }
        }
    }

    /// Expected rejection, recorded with the node's reason from both the mempool and a block.
    fn reject(&mut self, rpc: &rpc::Rpc, miner: &Address, name: &str, t: &Transaction, note: &str) -> Value {
        let mempool = rpc.test_accept(t).err().expect("expected a mempool rejection");
        let block = rpc.mine_raw(&[t], miner).err().unwrap_or_else(|| panic!("{name} was mined, expected a rejection"));
        eprintln!("  {name:<22} rejected: mempool {mempool}; block {block}");
        let row = json!({"tx": name, "txid": t.compute_txid().to_string(), "vbytes": t.vsize(), "weight": t.weight().to_wu(),
            "rejected_mempool": mempool, "rejected_block": block, "note": note});
        self.rows.push(row.clone());
        row
    }
}

fn rpc_from_env() -> rpc::Rpc {
    let var = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
    let node = rpc::Rpc::new(&var("ZKC_RPC_URL", "http://127.0.0.1:18743"), &var("ZKC_RPC_USER", "zkc"), &var("ZKC_RPC_PASS", "zkc-m1-regtest"));
    node.wallet(&var("ZKC_WALLET", "m1"))
}

fn payee_script(keys: &Keys, label: &str) -> ScriptBuf {
    key_path_script(&keys.secp, label)
}

fn outputs_of(keys: &Keys, t: &template::Template) -> Vec<TxOut> {
    t.outputs.iter().map(|o| txout(o.amount, payee_script(keys, &o.payee))).collect()
}

fn scenario(inp: &Inputs, name: &str) {
    let rpc = rpc_from_env();
    let miner = rpc.new_address();
    let keys = Keys::new();
    let mut trace = Trace { rows: vec![] };
    let mut facts = json!({"scenario": name, "num_pubs": NUM_PUBS, "statement_hashed": HASHED, "statement_kind": format!("{:?}", inp.kind), "fee_rate_sat_per_vb": FEE_RATE,
        "t_challenge": T_CHALLENGE, "t_refund": T_REFUND, "bond_sats": BOND});

    let template_statement = match name {
        "tampered" | "mismatch" => tampered(inp.kind, &inp.statement),
        _ => inp.statement.clone(),
    };
    let template_signals = public_of(inp.kind, &template_statement);
    let tpl = template_for(inp, &template_statement);
    let template_outputs = outputs_of(&keys, &tpl);
    facts["template_outputs"] = json!(tpl.outputs.iter().map(|o| json!({"role": o.role, "payee": o.payee, "sats": o.amount})).collect::<Vec<_>>());
    facts["template_signals_differ_from_proof"] = json!((0..NUM_PUBS).filter(|i| template_signals[*i] != inp.signals[*i]).map(public_name).collect::<Vec<_>>());
    facts["template_statement_differs_from_proof"] = json!((0..inp.kind.statement_len())
        .filter(|i| template_statement[*i] != inp.statement[*i])
        .map(|i| inp.kind.value_name(i))
        .collect::<Vec<_>>());

    // Escrows, one per active buyer, and the operator's bond.
    let mut escrows = vec![];
    for spec in &tpl.escrows {
        let mut e = Escrow::new(&keys, &spec.buyer);
        let (outpoint, out) = rpc.fund(&e.tree.script_pubkey(), bitcoin::Amount::from_sat(spec.amount), &miner);
        e.outpoint = outpoint;
        e.txout = out;
        escrows.push(e);
    }
    let escrow_height = rpc.height();
    let (bond_outpoint, bond_out) = rpc.fund(&payee_script(&keys, "operator"), bitcoin::Amount::from_sat(BOND), &miner);
    facts["escrows"] = json!(escrows.iter().map(|e| json!({"buyer": e.buyer, "outpoint": e.outpoint.to_string(), "sats": e.txout.value.to_sat()})).collect::<Vec<_>>());
    facts["escrow_last_funded_height"] = json!(escrow_height);

    let refund_payee = |e: &Escrow| -> ScriptBuf {
        let slot = tpl.escrows.iter().find(|s| s.buyer == e.buyer).unwrap().slot;
        payee_script(&keys, inp.opening["buyer_slots"][slot]["refund_payee"].as_str().unwrap())
    };

    if name == "stall" {
        // The operator never posts the assert. Buyers wait out T_refund, then take their escrow back.
        refunds(&rpc, &miner, &keys, &mut trace, &escrows, &refund_payee, &mut facts);
        facts["transactions"] = json!(trace.rows);
        write_result(inp, &format!("scenario-{name}"), &facts);
        return;
    }

    // The A output: BitVM disprove leaves, binding leaves for the template's signals, payout leaf.
    let partial = partial(inp);
    let secrets = chunked::secrets(&format!("graph-{name}"));
    let pubkeys = chunked::pubkeys(&secrets);
    let full = timed("full tapscripts", || chunked::full_tapscripts(&pubkeys, &partial));
    let binding: Vec<ScriptBuf> = (0..NUM_PUBS).map(|i| chunked::binding_leaf(&pubkeys, i, &template_signals[i])).collect();
    let payout_leaf = csv_checksig(T_CHALLENGE, &keys.x(&keys.committee));
    let mut leaf_hashes: Vec<_> = full.iter().map(leaf_hash).collect();
    leaf_hashes.extend(binding.iter().map(leaf_hash));
    leaf_hashes.push(leaf_hash(&payout_leaf));
    let a_tree = ScriptTree::new(&keys.secp, leaf_hashes);
    let binding_index = |i: usize| NUM_TAPS + i;
    let payout_index = NUM_TAPS + NUM_PUBS;
    facts["a_tree"] = json!({"leaves": a_tree.leaves.len(), "depth": a_tree.depth(), "bitvm_leaves": NUM_TAPS, "binding_leaves": NUM_PUBS,
        "bitvm_leaf_bytes_total": full.iter().map(|s| s.len()).sum::<usize>()});

    // What the operator asserts.
    let assertions = match name {
        "honest" | "mismatch" => honest_assertions(inp),
        "tampered" => tampered_assertions(inp),
        "plus-r" => plus_r_assertions(inp, PLUS_R_SIGNAL),
        other => panic!("unknown scenario {other}"),
    };
    let sigs = chunked::sign(assertions, &secrets);

    let batches = chunked::commit_batches(COMMIT_MAX_ITEMS);
    let operator_x = keys.x(&keys.operator);
    let commit_leaves: Vec<ScriptBuf> = batches.iter().map(|b| chunked::commit_leaf(&pubkeys, b, &operator_x)).collect();
    let commit_trees: Vec<ScriptTree> = commit_leaves.iter().map(|l| ScriptTree::new(&keys.secp, vec![leaf_hash(l)])).collect();
    let commit_items: Vec<Vec<Vec<u8>>> = batches.iter().map(|b| chunked::commit_witness(&sigs, b)).collect();
    let plan = CommitPlan { batches: &batches, leaves: &commit_leaves, trees: &commit_trees, items: &commit_items };
    let chain = build_assert_chain(&keys, (bond_outpoint, &bond_out), &plan, a_tree.script_pubkey());
    let a_outpoint = OutPoint { txid: chain.assert_final.compute_txid(), vout: 0 };
    let a_out = chain.assert_final.output[0].clone();

    // The committee presigns the payout before any assertion exists.
    let payout = payout_tx(&keys, (a_outpoint, &a_out), &a_tree, payout_index, &payout_leaf, &escrows, template_outputs.clone());
    facts["payout_presigned_txid"] = json!(payout.compute_txid().to_string());

    // The operator posts the assert chain.
    trace.record(&rpc, "assert_init", &chain.assert_init, "bond -> K + commit outputs").ok();
    trace.mine(&rpc, &miner, &[("assert_init", &chain.assert_init)]);
    let mut pending: Vec<(String, &Transaction)> = vec![];
    for (k, c) in chain.commits.iter().enumerate() {
        let label = format!("commit[{k}]");
        trace.record(&rpc, &label, c, &format!("{} Winternitz batches", chain.commit_groups[k].len())).ok();
        pending.push((label, c));
    }
    // Commit transactions are independent; mine them a few per block.
    for chunk in pending.chunks(8) {
        let named: Vec<(&str, &Transaction)> = chunk.iter().map(|(n, t)| (n.as_str(), *t)).collect();
        trace.mine(&rpc, &miner, &named);
    }
    trace.record(&rpc, "assert_final", &chain.assert_final, "K + connectors -> A").ok();
    trace.mine(&rpc, &miner, &[("assert_final", &chain.assert_final)]);
    let a_height = rpc.height();
    facts["a_confirmed_height"] = json!(a_height);

    // Anyone can now read the assertion from chain.
    let on_chain: Vec<Transaction> = chain.commits.iter().map(|c| rpc.transaction(&c.compute_txid())).collect();
    let chain_sigs = chunked::signatures_from_raw(&{
        let per_batch = items_from_commits(&on_chain, &chain.commit_groups);
        let mut per_value = vec![vec![]; chunked::NUM_VALUES];
        for (b, items) in batches.iter().zip(per_batch) {
            let mut rest = &items[..];
            for j in b.iter().rev() {
                let n = chunked::raw_witness_len(*j);
                per_value[*j] = rest[..n].to_vec();
                rest = &rest[n..];
            }
            assert!(rest.is_empty());
        }
        per_value
    });
    let asserted: Vec<String> = (0..NUM_PUBS)
        .map(|i| hex::encode(Wots32::signature_to_message(&chain_sigs.0[chunked::pub_slot(i)])))
        .collect();
    facts["asserted_public_signal_bytes"] = json!(asserted);
    facts["asserted_differs_from_template"] = json!((0..NUM_PUBS)
        .filter(|i| hex::decode(&asserted[*i]).unwrap() != chunked::u256_assertion(&template_signals[*i]))
        .map(public_name)
        .collect::<Vec<_>>());

    let challenger = payee_script(&keys, "challenger");
    match name {
        "honest" => {
            let found = timed("challenger validates the honest assertion", || chunked::validate(&inp.vk, &chain_sigs, &pubkeys, &full));
            assert!(found.is_none(), "honest assertion is disprovable at {:?}", found.map(|f| f.0));
            facts["bitvm_validate"] = json!("no disprovable chunk");
            // The disprove paths cannot be used against an honest operator.
            let last = NUM_TAPS - 1;
            let items = chunked::witness_for_leaf(&inp.vk, &chain_sigs, last).expect("witness for the final leaf");
            assert!(!chunked::leaf_succeeds(&full[last], &items));
            let fake = disprove_tx(&keys, (a_outpoint, &a_out), &a_tree, last, &full[last], items, challenger.clone());
            facts["negative_final_chunk"] = trace.reject(&rpc, &miner, "disprove(final chunk)", &fake, "honest witness for the validating leaf");
            let bind = binding_index(MISMATCH_SIGNAL);
            let items = chunked::binding_witness(&chain_sigs, MISMATCH_SIGNAL);
            assert!(!chunked::leaf_succeeds(&binding[MISMATCH_SIGNAL], &items));
            let fake = disprove_tx(&keys, (a_outpoint, &a_out), &a_tree, bind, &binding[MISMATCH_SIGNAL], items, challenger.clone());
            let label = format!("disprove(binding {})", public_name(MISMATCH_SIGNAL));
            facts["negative_binding"] = trace.reject(&rpc, &miner, &label, &fake, "honest commitment against its own binding leaf");

            // Too early: A has fewer than T_challenge confirmations.
            facts["negative_early_payout"] = trace.reject(&rpc, &miner, "payout(early)", &payout, "before T_challenge");
            let wait = u64::from(T_CHALLENGE) - 1 - (rpc.height() - a_height);
            rpc.mine(wait, &miner);
            trace.record(&rpc, "payout", &payout, "A after T_challenge + every escrow").expect("payout standard");
            trace.mine(&rpc, &miner, &[("payout", &payout)]);
            let mined = rpc.transaction(&payout.compute_txid());
            assert_eq!(&mined.output[..template_outputs.len()], &template_outputs[..], "payout outputs differ from the template");
            facts["payout_outputs_equal_template"] = json!(true);
            facts["payout_height_minus_a_height"] = json!(rpc.height() - a_height);
        }
        "tampered" | "plus-r" | "mismatch" => {
            let found = timed("challenger validates", || chunked::validate(&inp.vk, &chain_sigs, &pubkeys, &full));
            let (index, leaf, items, kind) = match (name, found) {
                ("mismatch", None) => {
                    // The proof verifies for what was asserted; the assertion just is not what
                    // the payout was presigned for.
                    let i = MISMATCH_SIGNAL;
                    let items = chunked::binding_witness(&chain_sigs, i);
                    (binding_index(i), binding[i].clone(), items, format!("binding leaf for {}", public_name(i)))
                }
                ("mismatch", Some(f)) => panic!("honest proof disprovable at BitVM leaf {}", f.0),
                (_, Some((k, items))) => (k, full[k].clone(), items, format!("BitVM chunk {k} of {NUM_TAPS}")),
                (_, None) => panic!("{name}: no disprovable chunk"),
            };
            assert!(chunked::leaf_succeeds(&leaf, &items), "challenger witness does not open the leaf");
            facts["bitvm_validate"] = json!(if name == "mismatch" { "no disprovable chunk (the proof verifies for the asserted signals)".to_string() } else { format!("chunk {index} disprovable") });
            facts["disprove_leaf"] = json!({"index": index, "kind": kind, "leaf_bytes": leaf.len(), "witness_items": items.len()});
            if name != "mismatch" {
                // The disprove leaf fails on an honest operator's data.
                let honest = chunked::sign(honest_assertions(inp), &secrets);
                if let Some(h) = chunked::witness_for_leaf(&inp.vk, &honest, index) {
                    facts["disprove_leaf_opens_on_honest_assertion"] = json!(chunked::leaf_succeeds(&leaf, &h));
                }
            }
            let binding_opens: Vec<String> = (0..NUM_PUBS)
                .filter(|i| chunked::leaf_succeeds(&binding[*i], &chunked::binding_witness(&chain_sigs, *i)))
                .map(public_name)
                .collect();
            facts["binding_leaves_that_open"] = json!(binding_opens);

            let d = disprove_tx(&keys, (a_outpoint, &a_out), &a_tree, index, &leaf, items, challenger.clone());
            trace.record(&rpc, "disprove", &d, &kind).ok();
            trace.mine(&rpc, &miner, &[("disprove", &d)]);
            facts["slashed_sats"] = json!(a_out.value.to_sat());
            facts["challenger_receives_sats"] = json!(d.output[0].value.to_sat());
            let wait = u64::from(T_CHALLENGE).saturating_sub(rpc.height() - a_height + 1);
            rpc.mine(wait, &miner);
            facts["negative_payout_after_disprove"] = trace.reject(&rpc, &miner, "payout(after disprove)", &payout, "A already spent");
            refunds(&rpc, &miner, &keys, &mut trace, &escrows, &refund_payee, &mut facts);
        }
        other => panic!("unknown scenario {other}"),
    }
    facts["transactions"] = json!(trace.rows);
    write_result(inp, &format!("scenario-{name}"), &facts);
}

/// Buyers' timeout path: rejected one block early, accepted at T_refund.
fn refunds(rpc: &rpc::Rpc, miner: &Address, keys: &Keys, trace: &mut Trace, escrows: &[Escrow], payee: &dyn Fn(&Escrow) -> ScriptBuf, facts: &mut Value) {
    let txs: Vec<Transaction> = escrows.iter().map(|e| refund_tx(keys, e, payee(e))).collect();
    let funded: Vec<u64> = escrows.iter().map(|e| rpc.confirmations(&e.outpoint.txid).unwrap()).collect();
    let youngest = *funded.iter().min().unwrap();
    // A refund enters the next block once its escrow has T_refund confirmations at the tip.
    if youngest + 1 < u64::from(T_REFUND) {
        rpc.mine(u64::from(T_REFUND) - 1 - youngest, miner);
        let young = escrows.iter().position(|e| rpc.confirmations(&e.outpoint.txid).unwrap() < u64::from(T_REFUND)).unwrap();
        facts["negative_early_refund"] = trace.reject(rpc, miner, "refund(early)", &txs[young], "one block before T_refund");
        rpc.mine(1, miner);
    }
    let named: Vec<(String, &Transaction)> = escrows.iter().zip(&txs).map(|(e, t)| (format!("refund[{}]", e.buyer), t)).collect();
    for (n, t) in &named {
        trace.record(rpc, n, t, "escrow refund leaf after T_refund").expect("refund standard");
    }
    let named: Vec<(&str, &Transaction)> = named.iter().map(|(n, t)| (n.as_str(), *t)).collect();
    trace.mine(rpc, miner, &named);
    facts["refunded_sats"] = json!(txs.iter().map(|t| t.output[0].value.to_sat()).collect::<Vec<_>>());
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: zkc-m1 prepare|selftest|scenario <work> [scenario] [--all-plus-r]");
        std::process::exit(2);
    }
    let inp = load(Path::new(&args[2]));
    match args[1].as_str() {
        "prepare" => prepare(&inp),
        "disproves" => disproves(&inp),
        "selftest" => selftest(&inp, args.iter().any(|a| a == "--all-plus-r")),
        "scenario" => scenario(&inp, args.get(3).expect("scenario name")),
        other => panic!("unknown command {other}"),
    }
}
