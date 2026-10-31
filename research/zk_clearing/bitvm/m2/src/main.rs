//! BitVM M2 for zk_clearing: the optimistic BitVM2 graph around an accounting16x4_committed
//! Groth16 proof on Bitcoin regtest. The operator kicks off; anyone may challenge, which forces
//! the assert; without a challenge the payout spends with no assert at all.
//!
//! Usage:
//!   zkc-m2 timing                   the timeouts and their worst-case slack
//!   zkc-m2 scenario <work> <name>   unchallenged | challenged | tampered | silent | incomplete | stall
//!
//! <work> is the directory prove-batch.sh filled (<work>/batch). Disprove scripts and
//! assertions come from the cache `zkc-m1 prepare` wrote under <work>/m1; results go to
//! <work>/m2. The node is reached through ZKC_RPC_URL, ZKC_RPC_USER, ZKC_RPC_PASS and ZKC_WALLET.

#[allow(dead_code)]
#[path = "../../m1/src/chunked.rs"]
mod chunked;
#[allow(dead_code)]
#[path = "../../m1/src/rpc.rs"]
mod rpc;
#[allow(dead_code)]
#[path = "../../m1/src/taproot.rs"]
mod taproot;
#[allow(dead_code)]
#[path = "../../m1/src/template.rs"]
mod template;
mod graph;

use ark_bn254::Bn254;
use ark_groth16::{Proof, VerifyingKey};
use bitcoin::{Address, ScriptBuf, Sequence, Transaction, TxOut, Witness};
use bitvm::chunk::api::{Assertions, NUM_PUBS, NUM_TAPS};
use bitvm::signatures::{Wots, Wots32};
use graph::*;
use num_bigint::BigUint;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::Instant;
use taproot::{key_path_script, keypair, leaf_hash, ScriptTree};

/// Stack items allowed per commit input; consensus allows 1,000 including temporaries.
const COMMIT_MAX_ITEMS: usize = 900;
/// The tampered statement, as in M1: 50,000 sats of refund moved from buyer slot 1 to slot 0.
const MOVED: u64 = 50_000;
/// The challenger's coin: the challenge amount plus room for its fee.
const CHALLENGER_COIN_EXTRA: u64 = 20_000;

struct Inputs {
    work: PathBuf,
    vk: VerifyingKey<Bn254>,
    proof: Proof<Bn254>,
    signals: Vec<BigUint>,
    input: Value,
    opening: Value,
    commitment: BigUint,
}

fn read_json(path: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))).unwrap()
}

fn load(work: &Path) -> Inputs {
    let batch = work.join("batch");
    let vk = zkc_convert::vk_from_snarkjs(&read_json(&batch.join("verification_key.json"))).unwrap();
    let proof = zkc_convert::proof_from_snarkjs(&read_json(&batch.join("proof.json"))).unwrap();
    let public = read_json(&batch.join("public.json"));
    let fr = zkc_convert::public_from_snarkjs(&public).unwrap();
    assert!(zkc_convert::verify(&vk, &proof, &fr).unwrap(), "batch proof must verify under ark-groth16");
    Inputs {
        work: work.to_path_buf(),
        vk,
        proof,
        signals: zkc_convert::public_integers(&public).unwrap(),
        input: read_json(&batch.join("input.json")),
        opening: read_json(&batch.join("opening.json")),
        commitment: std::fs::read_to_string(batch.join("sale_commitment.txt")).unwrap().trim().parse().unwrap(),
    }
}

fn tampered(signals: &[BigUint]) -> Vec<BigUint> {
    let mut s = signals.to_vec();
    s[template::refund(0)] += MOVED;
    s[template::refund(1)] -= MOVED;
    s
}

fn timed<T>(label: &str, f: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let out = f();
    eprintln!("[time] {label}: {:.1} s", start.elapsed().as_secs_f64());
    out
}

/// M1's cache: the vk-dependent disprove scripts and the assertions, made by `zkc-m1 prepare`.
fn m1_cache(inp: &Inputs, name: &str) -> PathBuf {
    let path = inp.work.join("m1").join(name);
    assert!(path.exists(), "{} missing: run `zkc-m1 prepare {}` first", path.display(), inp.work.display());
    path
}

fn partial(inp: &Inputs) -> Vec<ScriptBuf> {
    timed("partial disprove scripts", || chunked::partial_scripts(&inp.vk, &m1_cache(inp, "partial")))
}

fn assertions(inp: &Inputs, which: &str) -> Assertions {
    chunked::assertions_from_json(&read_json(&m1_cache(inp, &format!("assertions-{which}.json"))))
}

fn write_result(inp: &Inputs, name: &str, value: &Value) {
    let dir = inp.work.join("m2");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{name}.json"));
    std::fs::write(&path, serde_json::to_string_pretty(value).unwrap()).unwrap();
    eprintln!("wrote {}", path.display());
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
        eprintln!("  {name:<28} {:>9} vB  {}", t.vsize(), row["mempool_now"]);
        self.rows.push(row);
        standard
    }

    fn mark_mined(&mut self, rpc: &rpc::Rpc, named: &[(&str, &Transaction)], how: &str) {
        let height = rpc.height();
        for (name, t) in named {
            assert!(rpc.confirmations(&t.compute_txid()).is_some(), "{name} not confirmed");
            if let Some(row) = self.rows.iter_mut().rev().find(|r| r["tx"] == *name) {
                row["mined_height"] = json!(height);
                row["mined_via"] = json!(how);
            }
        }
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
        self.mark_mined(rpc, named, how);
    }

    /// Expected rejection, recorded with the node's reason from both the mempool and a block.
    fn reject(&mut self, rpc: &rpc::Rpc, miner: &Address, name: &str, t: &Transaction, note: &str) -> Value {
        let mempool = rpc.test_accept(t).err().expect("expected a mempool rejection");
        let block = rpc.mine_raw(&[t], miner).err().unwrap_or_else(|| panic!("{name} was mined, expected a rejection"));
        eprintln!("  {name:<28} rejected: mempool {mempool}; block {block}");
        let row = json!({"tx": name, "txid": t.compute_txid().to_string(), "vbytes": t.vsize(), "weight": t.weight().to_wu(),
            "tip_height": rpc.height(), "rejected_mempool": mempool, "rejected_block": block, "note": note});
        self.rows.push(row.clone());
        row
    }

    /// Total vbytes of the transactions this trace saw mined.
    fn mined_vbytes(&self) -> u64 {
        self.rows.iter().filter(|r| r.get("mined_height").is_some()).map(|r| r["vbytes"].as_u64().unwrap()).sum()
    }
}

fn rpc_from_env() -> rpc::Rpc {
    let var = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
    let node = rpc::Rpc::new(&var("ZKC_RPC_URL", "http://127.0.0.1:18743"), &var("ZKC_RPC_USER", "zkc"), &var("ZKC_RPC_PASS", "zkc-m1-regtest"));
    node.wallet(&var("ZKC_WALLET", "m1"))
}

/// Mines empty blocks until the tip is at `tip`.
fn mine_to_tip(rpc: &rpc::Rpc, miner: &Address, tip: u64) {
    let now = rpc.height();
    assert!(now <= tip, "tip {now} is already past {tip}");
    if tip > now {
        rpc.mine(tip - now, miner);
    }
}

/// Pays every (script, sats) from the wallet in one transaction, mines it, and returns the outputs.
fn fund_many(rpc: &rpc::Rpc, outs: &[(ScriptBuf, u64)], miner: &Address) -> Vec<Utxo> {
    let mut amounts = serde_json::Map::new();
    for (script, sats) in outs {
        let address = Address::from_script(script, bitcoin::Network::Regtest).unwrap().to_string();
        assert!(!amounts.contains_key(&address), "fund_many needs distinct scripts");
        amounts.insert(address, json!(bitcoin::Amount::from_sat(*sats).to_btc()));
    }
    let txid = rpc.call("sendmany", json!(["", amounts]));
    let txid: bitcoin::Txid = txid.as_str().unwrap().parse().unwrap();
    rpc.mine(1, miner);
    let t = rpc.transaction(&txid);
    outs.iter().map(|(script, _)| Utxo::of(&t, t.output.iter().position(|o| &o.script_pubkey == script).unwrap())).collect()
}

fn payee_script(keys: &Keys, label: &str) -> ScriptBuf {
    key_path_script(&keys.secp, label)
}

fn outputs_of(keys: &Keys, t: &template::Template) -> Vec<TxOut> {
    t.outputs.iter().map(|o| txout(o.amount, payee_script(keys, &o.payee))).collect()
}

/// The signed values, read back from the mined commit transactions the way a challenger does.
fn signatures_from_chain(rpc: &rpc::Rpc, chain: &AssertChain, batches: &[Vec<usize>]) -> bitvm::chunk::api::Signatures {
    let on_chain: Vec<Transaction> = chain.commits.iter().map(|c| rpc.transaction(&c.compute_txid())).collect();
    let per_batch = items_from_commits(&on_chain, &chain.groups);
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
    chunked::signatures_from_raw(&per_value)
}

/// Everything the committee and operator fix before the kickoff.
struct Setup {
    kickoff: Kickoff,
    challenge_amount: u64,
    challenge_sig: Vec<u8>,
    payout_unchallenged: Transaction,
    chain: AssertChain,
    a_tree: ScriptTree,
    full: Vec<ScriptBuf>,
    binding: Vec<ScriptBuf>,
    payout_asserted: Transaction,
    disprove_kb_sig: Vec<u8>,
    timeout_kb_sig: Vec<u8>,
    timeout_ka_sig: Vec<u8>,
}

/// The timeout as anyone completes it from the presigned signatures.
fn timeout_tx(s: &Setup, reward_to: ScriptBuf) -> Transaction {
    let ka_witness = Witness::from_slice(&[s.timeout_ka_sig.clone()]);
    slash_tx(&s.kickoff.kb, &s.timeout_kb_sig, &s.kickoff.ka, Sequence::from_height(T_ASSERT), ka_witness, reward_to)
}

/// A disprove through A's leaf `index` with the challenger's witness `items`.
fn disprove_tx(keys: &Keys, s: &Setup, index: usize, leaf: &ScriptBuf, items: Vec<Vec<u8>>, reward_to: ScriptBuf) -> Transaction {
    let a_witness = script_path_witness(items, leaf, &s.a_tree, index, keys);
    slash_tx(&s.kickoff.kb, &s.disprove_kb_sig, &s.chain.a, RBF, a_witness, reward_to)
}

fn timing() -> Value {
    let slack = timing_slack();
    for (name, blocks) in &slack {
        eprintln!("  {blocks:>3} blocks  {name}");
        assert!(*blocks >= i64::from(MARGIN), "timeouts leave {blocks} < MARGIN = {MARGIN} blocks: {name}");
    }
    json!({
        "t_kickoff": T_KICKOFF, "t_challenge": T_CHALLENGE, "t_assert": T_ASSERT, "t_disprove": T_DISPROVE, "t_refund": T_REFUND,
        "assert_blocks": ASSERT_BLOCKS, "margin": MARGIN,
        "slack_blocks": slack.iter().map(|(n, b)| json!({"constraint": n, "blocks": b})).collect::<Vec<_>>(),
    })
}

fn scenario(inp: &Inputs, name: &str) {
    const NAMES: [&str; 6] = ["unchallenged", "challenged", "tampered", "silent", "incomplete", "stall"];
    assert!(NAMES.contains(&name), "unknown scenario {name}; one of {NAMES:?}");
    let rpc = rpc_from_env();
    let miner = rpc.new_address();
    let keys = Keys::new();
    let mut trace = Trace { rows: vec![] };
    let mut facts = json!({"scenario": name, "fee_rate_sat_per_vb": FEE_RATE, "timing": timing(),
        "bond_sats": BOND, "burn_sats": BURN, "connector_sats": CONNECTOR});

    // The committee presigns payouts for the operator's proposed statement. In `tampered` that
    // statement is S' (refund moved between buyers), which the batch proof does not prove.
    let template_signals = if name == "tampered" { tampered(&inp.signals) } else { inp.signals.clone() };
    let tpl = template::build(&template_signals, &inp.input, &inp.opening, &inp.commitment).expect("template");
    let template_outputs = outputs_of(&keys, &tpl);
    facts["template_outputs"] = json!(tpl.outputs.iter().map(|o| json!({"role": o.role, "payee": o.payee, "sats": o.amount})).collect::<Vec<_>>());
    facts["template_signals_differ_from_proof"] = json!((0..NUM_PUBS).filter(|i| template_signals[*i] != inp.signals[*i]).map(template::signal_name).collect::<Vec<_>>());

    // The operator's one-time Winternitz keys for this graph and its commit leaves. The assert
    // chain is sized for the largest witness any assertion can have.
    let secrets = chunked::secrets(&format!("m2-graph-{name}"));
    let pubkeys = chunked::pubkeys(&secrets);
    let batches = chunked::commit_batches(COMMIT_MAX_ITEMS);
    let operator_x = keys.x(&keys.operator);
    let commit_leaves: Vec<ScriptBuf> = batches.iter().map(|b| chunked::commit_leaf(&pubkeys, b, &operator_x)).collect();
    let commit_trees: Vec<ScriptTree> = commit_leaves.iter().map(|l| ScriptTree::new(&keys.secp, vec![leaf_hash(l)])).collect();
    let sample = chunked::sign(assertions(inp, "honest"), &secrets);
    let worst_items: Vec<Vec<Vec<u8>>> = batches.iter().map(|b| worst_case_items(&chunked::commit_witness(&sample, b))).collect();
    let worst_plan = CommitPlan { batches: &batches, leaves: &commit_leaves, trees: &commit_trees, items: &worst_items };
    let layout = commit_layout(&keys, &worst_plan);
    // A challenger pays the operator the whole assert chain's cost, rounded up to 1,000 sats.
    let challenge_amount = layout.reserve().div_ceil(1000) * 1000;

    // Funding, in one block: an escrow per active buyer, the operator's bond and assert
    // reserve, and a coin a challenger will spend.
    let mut escrows: Vec<Escrow> = tpl.escrows.iter().map(|s| Escrow::new(&keys, &s.buyer)).collect();
    let challenger = keypair(&keys.secp, "challenger");
    let challenger_script = payee_script(&keys, "challenger");
    let mut outs: Vec<(ScriptBuf, u64)> = escrows.iter().zip(&tpl.escrows).map(|(e, s)| (e.tree.script_pubkey(), s.amount)).collect();
    outs.push((keys.operator_script(), BOND));
    outs.push((key_path_script(&keys.secp, "operator-reserve"), layout.reserve()));
    outs.push((challenger_script.clone(), challenge_amount + CHALLENGER_COIN_EXTRA));
    let funded = fund_many(&rpc, &outs, &miner);
    for (e, u) in escrows.iter_mut().zip(&funded) {
        e.utxo = u.clone();
    }
    let n = escrows.len();
    let (bond, reserve, challenger_coin) = (funded[n].clone(), funded[n + 1].clone(), funded[n + 2].clone());
    let h_e = rpc.height();
    facts["escrows"] = json!(escrows.iter().map(|e| json!({"buyer": e.buyer, "outpoint": e.utxo.outpoint.to_string(), "sats": e.utxo.sats()})).collect::<Vec<_>>());
    facts["funded_height"] = json!(h_e);
    facts["bond_outpoint"] = json!(bond.outpoint.to_string());
    facts["reserve"] = json!({"outpoint": reserve.outpoint.to_string(), "sats": reserve.sats()});
    facts["challenge_amount_sats"] = json!(challenge_amount);

    let refund_payee = |e: &Escrow| -> ScriptBuf {
        let slot = tpl.escrows.iter().find(|s| s.buyer == e.buyer).unwrap().slot;
        payee_script(&keys, inp.opening["buyer_slots"][slot]["refund_payee"].as_str().unwrap())
    };

    if name == "stall" {
        // The operator never kicks off. Buyers wait out T_refund and take their escrow back;
        // the bond was never committed, so nothing is slashed.
        refunds(&rpc, &miner, &keys, &mut trace, &escrows, &refund_payee, &mut facts);
        let unspent = |u: &Utxo| !rpc.call("gettxout", json!([u.outpoint.txid.to_string(), u.outpoint.vout])).is_null();
        facts["bond_unspent"] = json!(unspent(&bond));
        facts["reserve_unspent"] = json!(unspent(&reserve));
        finish(inp, name, &trace, &mut facts);
        return;
    }

    // Setup, all off chain: the kickoff, A's script tree, the assert chain and every presigned
    // committee signature.
    let kickoff = kickoff_tx(&keys, &bond);
    let challenge_sig = challenge_signature(&keys, &kickoff.kc, challenge_amount);
    let escrow_inputs = |inputs: &mut Vec<PayoutInput>| {
        for e in &escrows {
            inputs.push(PayoutInput { utxo: e.utxo.clone(), sequence: RBF, spend: Spend::KeyPath(Some(e.tree.merkle_root())) });
        }
    };
    let mut inputs = vec![
        PayoutInput { utxo: kickoff.kc.clone(), sequence: Sequence::from_height(T_CHALLENGE), spend: Spend::KeyPath(None) },
        PayoutInput { utxo: kickoff.ka.clone(), sequence: RBF, spend: Spend::KeyPath(None) },
        PayoutInput { utxo: kickoff.kb.clone(), sequence: RBF, spend: Spend::KeyPath(None) },
    ];
    escrow_inputs(&mut inputs);
    let payout_unchallenged = committee_payout(&keys, &inputs, template_outputs.clone());

    let partial = partial(inp);
    let full = timed("full tapscripts", || chunked::full_tapscripts(&pubkeys, &partial));
    let binding: Vec<ScriptBuf> = (0..NUM_PUBS).map(|i| chunked::binding_leaf(&pubkeys, i, &template_signals[i])).collect();
    let payout_leaf = csv_checksig(T_DISPROVE, &keys.x(&keys.committee));
    let mut leaf_hashes: Vec<_> = timed("hash disprove leaves", || full.iter().map(leaf_hash).collect());
    leaf_hashes.extend(binding.iter().map(leaf_hash));
    leaf_hashes.push(leaf_hash(&payout_leaf));
    let a_tree = ScriptTree::new(&keys.secp, leaf_hashes);
    let binding_index = |i: usize| NUM_TAPS + i;
    let payout_index = NUM_TAPS + NUM_PUBS;
    let chain = build_assert_chain(&keys, &reserve, &layout, &worst_plan, &kickoff.ka, a_tree.script_pubkey());

    let mut inputs = vec![
        PayoutInput { utxo: chain.a.clone(), sequence: Sequence::from_height(T_DISPROVE), spend: Spend::Leaf { leaf: &payout_leaf, tree: &a_tree, index: payout_index } },
        PayoutInput { utxo: kickoff.kb.clone(), sequence: RBF, spend: Spend::KeyPath(None) },
    ];
    escrow_inputs(&mut inputs);
    let payout_asserted = committee_payout(&keys, &inputs, template_outputs.clone());
    let (disprove_kb_sig, _) = slash_signatures(&keys, &kickoff.kb, &chain.a, RBF, false);
    let (timeout_kb_sig, timeout_ka_sig) = slash_signatures(&keys, &kickoff.kb, &kickoff.ka, Sequence::from_height(T_ASSERT), true);
    let s = Setup {
        kickoff,
        challenge_amount,
        challenge_sig,
        payout_unchallenged,
        chain,
        a_tree,
        full,
        binding,
        payout_asserted,
        disprove_kb_sig,
        timeout_kb_sig,
        timeout_ka_sig: timeout_ka_sig.unwrap(),
    };
    facts["setup"] = json!({
        "kickoff_txid": s.kickoff.tx.compute_txid().to_string(),
        "kb_sats": s.kickoff.kb.sats(),
        "a_outpoint": s.chain.a.outpoint.to_string(), "a_sats": s.chain.a.sats(),
        "a_tree": {"leaves": s.a_tree.leaves.len(), "depth": s.a_tree.depth(), "bitvm_leaves": NUM_TAPS, "binding_leaves": NUM_PUBS,
            "bitvm_leaf_bytes_total": s.full.iter().map(|l| l.len()).sum::<usize>()},
        "commit_groups": s.chain.groups.iter().map(|g| g.len()).collect::<Vec<_>>(),
        "commit_fees_sats": s.chain.commit_fees,
        "assert_init_fee_sats": layout.init_fee,
        "presigned_payout_unchallenged_txid": s.payout_unchallenged.compute_txid().to_string(),
        "presigned_payout_asserted_txid": s.payout_asserted.compute_txid().to_string(),
        "committee_signatures": {
            "payout_unchallenged": s.payout_unchallenged.input.len(), "payout_asserted": s.payout_asserted.input.len(),
            "challenge (SINGLE|ANYONECANPAY)": 1, "assert_final (KA)": 1, "disprove (SINGLE on KB, any leaf of A)": 1,
            "timeout (SINGLE on KB, NONE on KA)": 2,
        },
        "challenge_signature_bytes": s.challenge_sig.len(),
    });

    // The kickoff.
    trace.record(&rpc, "kickoff", &s.kickoff.tx, "bond -> KC + KA + KB").expect("kickoff standard");
    trace.mine(&rpc, &miner, &[("kickoff", &s.kickoff.tx)]);
    let h_k = rpc.height();
    assert!(h_k - h_e <= u64::from(T_KICKOFF), "kickoff later than T_kickoff");
    facts["kickoff_height"] = json!(h_k);

    // A watcher checks the operator's (S, π) off chain and challenges if π does not verify.
    let pi_verifies = zkc_convert::verify(&inp.vk, &inp.proof, &chunked::fr_list(&template_signals)).unwrap();
    facts["watcher_check_pi_verifies_for_template"] = json!(pi_verifies);
    assert_eq!(pi_verifies, name != "tampered");
    let challenge = challenge_tx(&keys, &s.kickoff.kc, &s.challenge_sig, s.challenge_amount, &challenger_coin, &challenger, challenger_script.clone());

    match name {
        "unchallenged" => {
            mine_to_tip(&rpc, &miner, h_k + u64::from(T_CHALLENGE) - 2);
            facts["negative_early_payout"] = trace.reject(&rpc, &miner, "payout_unchallenged(early)", &s.payout_unchallenged, "one block before T_challenge");
            facts["negative_early_timeout"] = trace.reject(&rpc, &miner, "timeout(early)", &timeout_tx(&s, challenger_script.clone()), "before T_assert");
            mine_to_tip(&rpc, &miner, h_k + u64::from(T_CHALLENGE) - 1);
            trace.record(&rpc, "payout_unchallenged", &s.payout_unchallenged, "KC after T_challenge + KA + KB + every escrow").expect("payout standard");
            trace.mine(&rpc, &miner, &[("payout_unchallenged", &s.payout_unchallenged)]);
            let mined = rpc.transaction(&s.payout_unchallenged.compute_txid());
            assert_eq!(&mined.output[..template_outputs.len()], &template_outputs[..], "payout outputs differ from the template");
            facts["payout_outputs_equal_template"] = json!(true);
            facts["payout_height_minus_kickoff_height"] = json!(rpc.height() - h_k);
            facts["operator_back_sats"] = json!(mined.output.last().unwrap().value.to_sat());
            facts["negative_challenge_after_payout"] = trace.reject(&rpc, &miner, "challenge(after payout)", &challenge, "KC already spent");
            mine_to_tip(&rpc, &miner, h_k + u64::from(T_ASSERT) - 1);
            facts["negative_timeout_after_payout"] = trace.reject(&rpc, &miner, "timeout(after payout)", &timeout_tx(&s, challenger_script.clone()), "T_assert reached; KA and KB already spent");
        }
        "challenged" | "tampered" => {
            // The honest operator is challenged in the last block it can be; the tampered one at once.
            if name == "challenged" {
                mine_to_tip(&rpc, &miner, h_k + u64::from(T_CHALLENGE) - 2);
            }
            trace.record(&rpc, "challenge", &challenge, "KC (presigned SINGLE|ANYONECANPAY) + challenger's coin").expect("challenge standard");
            trace.mine(&rpc, &miner, &[("challenge", &challenge)]);
            let h_c = rpc.height();
            facts["challenge_height_minus_kickoff_height"] = json!(h_c - h_k);
            if name == "challenged" {
                assert_eq!(h_c, h_k + u64::from(T_CHALLENGE) - 1);
                facts["negative_payout_unchallenged_after_challenge"] =
                    trace.reject(&rpc, &miner, "payout_unchallenged(challenged)", &s.payout_unchallenged, "T_challenge reached; KC spent by the challenge");
            }

            // The operator asserts: the honest proof, or in `tampered` the assertion of S' with π.
            let asserted = chunked::sign(assertions(inp, if name == "tampered" { "tampered" } else { "honest" }), &secrets);
            let items: Vec<Vec<Vec<u8>>> = batches.iter().map(|b| chunked::commit_witness(&asserted, b)).collect();
            let plan = CommitPlan { batches: &batches, leaves: &commit_leaves, trees: &commit_trees, items: &items };
            let commits = signed_commits(&keys, &s.chain, &plan);
            post_assert_chain(&rpc, &miner, &mut trace, &s.chain, &commits, name == "challenged", &mut facts);
            trace.record(&rpc, "assert_final", &s.chain.assert_final, "KA + every D_k -> A").expect("assert_final standard");
            trace.mine(&rpc, &miner, &[("assert_final", &s.chain.assert_final)]);
            let h_a = rpc.height();
            facts["a_height_minus_kickoff_height"] = json!(h_a - h_k);
            facts["blocks_to_spare_before_timeout"] = json!(h_k + u64::from(T_ASSERT) - 1 - h_a);

            // The challenger reads the assertion from chain and runs every disprove leaf.
            let chain_sigs = signatures_from_chain(&rpc, &s.chain, &batches);
            let asserted_pubs: Vec<String> = (0..NUM_PUBS).map(|i| hex::encode(Wots32::signature_to_message(&chain_sigs.0[chunked::pub_slot(i)]))).collect();
            facts["asserted_differs_from_template"] = json!((0..NUM_PUBS)
                .filter(|i| hex::decode(&asserted_pubs[*i]).unwrap() != chunked::u256_assertion(&template_signals[*i]))
                .map(template::signal_name)
                .collect::<Vec<_>>());
            let found = timed("challenger validates", || chunked::validate(&inp.vk, &chain_sigs, &pubkeys, &s.full));
            if name == "challenged" {
                assert!(found.is_none(), "honest assertion is disprovable at {:?}", found.map(|f| f.0));
                facts["bitvm_validate"] = json!("no disprovable chunk");
                let last = NUM_TAPS - 1;
                let items = chunked::witness_for_leaf(&inp.vk, &chain_sigs, last).expect("witness for the final leaf");
                assert!(!chunked::leaf_succeeds(&s.full[last], &items));
                let fake = disprove_tx(&keys, &s, last, &s.full[last], items, challenger_script.clone());
                facts["negative_disprove_final_chunk"] = trace.reject(&rpc, &miner, "disprove(final chunk)", &fake, "honest witness for the validating leaf");
                let i = template::refund(0);
                let items = chunked::binding_witness(&chain_sigs, i);
                assert!(!chunked::leaf_succeeds(&s.binding[i], &items));
                let fake = disprove_tx(&keys, &s, binding_index(i), &s.binding[i], items, challenger_script.clone());
                facts["negative_disprove_binding"] = trace.reject(&rpc, &miner, "disprove(binding refund[0])", &fake, "honest commitment against its own binding leaf");

                mine_to_tip(&rpc, &miner, h_a + u64::from(T_DISPROVE) - 2);
                facts["negative_early_payout"] = trace.reject(&rpc, &miner, "payout_asserted(early)", &s.payout_asserted, "one block before T_disprove");
                mine_to_tip(&rpc, &miner, h_a + u64::from(T_DISPROVE) - 1);
                trace.record(&rpc, "payout_asserted", &s.payout_asserted, "A after T_disprove + KB + every escrow").expect("payout standard");
                trace.mine(&rpc, &miner, &[("payout_asserted", &s.payout_asserted)]);
                let mined = rpc.transaction(&s.payout_asserted.compute_txid());
                assert_eq!(&mined.output[..template_outputs.len()], &template_outputs[..], "payout outputs differ from the template");
                facts["payout_outputs_equal_template"] = json!(true);
                facts["operator_back_sats"] = json!(mined.output.last().unwrap().value.to_sat());
                let tip = rpc.height().max(h_k + u64::from(T_ASSERT) - 1);
                mine_to_tip(&rpc, &miner, tip);
                facts["negative_timeout_after_assert"] = trace.reject(&rpc, &miner, "timeout(after assert)", &timeout_tx(&s, challenger_script.clone()), "T_assert reached; KA spent by assert_final");
            } else {
                let (index, items) = found.expect("tampered assertion not disprovable");
                let leaf = &s.full[index];
                assert!(chunked::leaf_succeeds(leaf, &items), "challenger witness does not open the leaf");
                facts["bitvm_validate"] = json!(format!("chunk {index} disprovable"));
                facts["disprove_leaf"] = json!({"index": index, "leaf_bytes": leaf.len(), "witness_items": items.len()});
                let d = disprove_tx(&keys, &s, index, leaf, items, challenger_script.clone());
                trace.record(&rpc, "disprove", &d, &format!("KB (presigned SINGLE) + A through BitVM chunk {index}")).ok();
                trace.mine(&rpc, &miner, &[("disprove", &d)]);
                facts["burned_sats"] = json!(d.output[0].value.to_sat());
                facts["challenger_reward_sats"] = json!(d.output[1].value.to_sat());
                mine_to_tip(&rpc, &miner, rpc.height().max(h_a + u64::from(T_DISPROVE) - 1));
                facts["negative_payout_after_disprove"] = trace.reject(&rpc, &miner, "payout_asserted(after disprove)", &s.payout_asserted, "T_disprove reached; A and KB spent");
                mine_to_tip(&rpc, &miner, rpc.height().max(h_k + u64::from(T_ASSERT) - 1));
                facts["negative_timeout_after_disprove"] = trace.reject(&rpc, &miner, "timeout(after disprove)", &timeout_tx(&s, challenger_script.clone()), "T_assert reached; KA and KB spent");
                refunds(&rpc, &miner, &keys, &mut trace, &escrows, &refund_payee, &mut facts);
            }
        }
        "silent" | "incomplete" => {
            trace.record(&rpc, "challenge", &challenge, "KC (presigned SINGLE|ANYONECANPAY) + challenger's coin").expect("challenge standard");
            trace.mine(&rpc, &miner, &[("challenge", &challenge)]);
            if name == "incomplete" {
                // The operator posts assert_init and every commit, then stops before assert_final.
                let asserted = chunked::sign(assertions(inp, "honest"), &secrets);
                let items: Vec<Vec<Vec<u8>>> = batches.iter().map(|b| chunked::commit_witness(&asserted, b)).collect();
                let plan = CommitPlan { batches: &batches, leaves: &commit_leaves, trees: &commit_trees, items: &items };
                let commits = signed_commits(&keys, &s.chain, &plan);
                post_assert_chain(&rpc, &miner, &mut trace, &s.chain, &commits, false, &mut facts);
            }
            mine_to_tip(&rpc, &miner, h_k + u64::from(T_ASSERT) - 2);
            facts["negative_early_timeout"] = trace.reject(&rpc, &miner, "timeout(early)", &timeout_tx(&s, challenger_script.clone()), "one block before T_assert");
            facts["negative_payout_unchallenged_after_challenge"] =
                trace.reject(&rpc, &miner, "payout_unchallenged(challenged)", &s.payout_unchallenged, "KC spent by the challenge");
            mine_to_tip(&rpc, &miner, h_k + u64::from(T_ASSERT) - 1);
            let t = timeout_tx(&s, challenger_script.clone());
            trace.record(&rpc, "timeout", &t, "KB (presigned SINGLE) + KA (presigned NONE) after T_assert").expect("timeout standard");
            trace.mine(&rpc, &miner, &[("timeout", &t)]);
            facts["burned_sats"] = json!(t.output[0].value.to_sat());
            facts["slasher_reward_sats"] = json!(t.output[1].value.to_sat());
            facts["negative_assert_final_after_timeout"] = trace.reject(&rpc, &miner, "assert_final(after timeout)", &s.chain.assert_final,
                if name == "incomplete" { "KA spent by the timeout" } else { "no commits, and KA spent by the timeout" });
            refunds(&rpc, &miner, &keys, &mut trace, &escrows, &refund_payee, &mut facts);
        }
        other => panic!("unknown scenario {other}"),
    }
    finish(inp, name, &trace, &mut facts);
}

/// Posts assert_init and the commits. With `probe`, first shows why the chain needs a block per
/// step: only one commit fits in the mempool beside an unconfirmed assert_init.
fn post_assert_chain(rpc: &rpc::Rpc, miner: &Address, trace: &mut Trace, chain: &AssertChain, commits: &[Transaction], probe: bool, facts: &mut Value) {
    trace.record(rpc, "assert_init", &chain.assert_init, "reserve -> commit outputs").expect("assert_init standard");
    let names: Vec<String> = (0..commits.len()).map(|k| format!("commit[{k}]")).collect();
    let mut start = 0;
    if probe {
        rpc.send(&chain.assert_init).unwrap();
        let mut mined = vec![("assert_init", &chain.assert_init)];
        let first = trace.record(rpc, &names[0], &commits[0], &format!("{} Winternitz batches; parent unconfirmed", chain.groups[0].len()));
        let verdict = |r: Result<(), String>| r.map(|()| "accepted".to_string()).unwrap_or_else(|e| e);
        facts["mempool_probe_first_commit_with_unconfirmed_parent"] = json!(verdict(first.clone()));
        if first.is_ok() {
            rpc.send(&commits[0]).unwrap();
            let second = verdict(rpc.test_accept(&commits[1]));
            eprintln!("  commit[1] beside an unconfirmed assert_init and commit[0]: {second}");
            facts["mempool_probe_second_commit_with_unconfirmed_parent"] = json!(second);
            mined.push((names[0].as_str(), &commits[0]));
            start = 1;
        }
        rpc.mine(1, miner);
        trace.mark_mined(rpc, &mined, "mempool");
    } else {
        trace.mine(rpc, miner, &[("assert_init", &chain.assert_init)]);
    }
    for k in start..commits.len() {
        trace.record(rpc, &names[k], &commits[k], &format!("{} Winternitz batches", chain.groups[k].len())).ok();
    }
    let named: Vec<(&str, &Transaction)> = (start..commits.len()).map(|k| (names[k].as_str(), &commits[k])).collect();
    trace.mine(rpc, miner, &named);
}

fn finish(inp: &Inputs, name: &str, trace: &Trace, facts: &mut Value) {
    facts["mined_vbytes_total"] = json!(trace.mined_vbytes());
    facts["transactions"] = json!(trace.rows);
    write_result(inp, &format!("scenario-{name}"), facts);
}

/// Buyers' timeout path: rejected one block early, accepted at T_refund.
fn refunds(rpc: &rpc::Rpc, miner: &Address, keys: &Keys, trace: &mut Trace, escrows: &[Escrow], payee: &dyn Fn(&Escrow) -> ScriptBuf, facts: &mut Value) {
    let txs: Vec<Transaction> = escrows.iter().map(|e| refund_tx(keys, e, payee(e))).collect();
    let funded: Vec<u64> = escrows.iter().map(|e| rpc.confirmations(&e.utxo.outpoint.txid).unwrap()).collect();
    let youngest = *funded.iter().min().unwrap();
    // A refund enters the next block once its escrow has T_refund confirmations at the tip.
    if youngest + 1 < u64::from(T_REFUND) {
        rpc.mine(u64::from(T_REFUND) - 1 - youngest, miner);
        let young = escrows.iter().position(|e| rpc.confirmations(&e.utxo.outpoint.txid).unwrap() < u64::from(T_REFUND)).unwrap();
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
    match args.get(1).map(String::as_str) {
        Some("timing") => println!("{}", serde_json::to_string_pretty(&timing()).unwrap()),
        Some("scenario") if args.len() >= 4 => scenario(&load(Path::new(&args[2])), &args[3]),
        _ => {
            eprintln!("usage: zkc-m2 timing | zkc-m2 scenario <work> <name>");
            std::process::exit(2);
        }
    }
}
