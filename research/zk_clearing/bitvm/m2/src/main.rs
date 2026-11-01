//! BitVM M2 for zk_clearing: the optimistic BitVM2 graph around an accounting16x4_committed
//! Groth16 proof on Bitcoin regtest. The operator kicks off; anyone may challenge, which forces
//! the assert; without a challenge the payout spends with no assert at all.
//!
//! Usage:
//!   zkc-m2 timing                   the timeouts and their worst-case slack
//!   zkc-m2 scenario <work> <name>   unchallenged | challenged | tampered | silent | incomplete | stall
//!
//! <work> is the directory prove-batch.sh filled (<work>/batch). Disprove scripts and
//! assertions come from the cache `zkc-m1 prepare` wrote under <work>/m1. The node is reached
//! through ZKC_RPC_URL, ZKC_RPC_USER, ZKC_RPC_PASS and ZKC_WALLET.
//!
//! M9 adds, through the environment:
//!   ZKC_GRAPH=m2|anchored     the graph (default m2, M2 as run; graph.rs has the anchored one)
//!   ZKC_MARKET_FEE_RATE=<n>   sat/vB paid by transactions signed when posted (default FEE_RATE).
//!                             Above FEE_RATE it is a fee spike: run the node with -blockmintxfee
//!                             at the same rate, and only `unchallenged` and `challenged` apply
//!   ZKC_VALIDATE=0            skip the challenger's BitVM validation in a `challenged` spike
//! Results go to <work>/m2 for the M2 graph at FEE_RATE, else to <work>/m9/<graph>-<rate>.
//!
//! M13 adds:
//!   ZKC_RISE_TO=<n> ZKC_RESTART_CMD=<script>   in a `challenged` spike, the market rises to n
//!                             after assert_init's child is posted: `bash <script> <n>` restarts
//!                             the node with -blockmintxfee at n, and the operator replaces the
//!                             child by RBF and bumps the rest at n
//!   ZKC_BIND_HEIGHT=1         the kickoff's lock time is the statement's batchHeight, it spends
//!                             a deadline connector anyone may sweep after batchHeight + 4, and
//!                             the escrows refund through CLTV at an absolute expiry. Adds the
//!                             scenario `late`: the deadline passes before any kickoff
//! Their results go to <work>/m13/<graph>-<rate>[-to-<n>][-bound].

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
use bitcoin::transaction::Version;
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
/// The operator's coins for CPFP children in a spike: one per anchored transaction it may bump.
const BUMP_COINS: usize = 9;
/// Core's default incremental relay fee, 0.1 sat/vB: what a replacement must add per vbyte.
const INCREMENTAL_RELAY_SAT_PER_KVB: u64 = 100;
/// TRUC's cap on a child of an unconfirmed version 3 transaction.
const TRUC_CHILD_MAX_VSIZE: usize = 1000;
/// Bound runs (M13): the statement's batchHeight, in blocks after the escrows' funding block.
/// The kickoff's lock time keeps it out of blocks up to this height.
const BATCH_HEIGHT_AFTER_FUNDING: u64 = 2;
/// Bound runs: the deadline connector opens to anyone this many blocks after batchHeight, so
/// the kickoff has to confirm in blocks batchHeight + 1 to batchHeight + DEADLINE_AFTER_BATCH.
const DEADLINE_AFTER_BATCH: u64 = 4;
/// The deadline connector's value: what its sweeper keeps.
const DEADLINE_SATS: u64 = 10_000;

/// How a run is configured (module docs).
struct Run {
    graph: Graph,
    market: u64,
    validate: bool,
    /// M13: the market rises to this rate (sat/vB) after assert_init's child is posted, by
    /// restarting the node through `restart`.
    rise: Option<(u64, String)>,
    /// M13: the kickoff carries the statement's batchHeight as its lock time, and each escrow
    /// refunds through CLTV at its absolute expiry.
    bound: bool,
}

impl Run {
    fn from_env() -> Run {
        let graph = match std::env::var("ZKC_GRAPH").as_deref() {
            Ok("anchored") => Graph::Anchored,
            Ok("m2") | Err(_) => Graph::M2,
            Ok(other) => panic!("ZKC_GRAPH must be m2 or anchored, not {other}"),
        };
        let market = std::env::var("ZKC_MARKET_FEE_RATE").map(|v| v.parse().expect("ZKC_MARKET_FEE_RATE")).unwrap_or(FEE_RATE);
        assert!(market >= FEE_RATE, "the market rate must be at least the presigned FEE_RATE");
        let validate = std::env::var("ZKC_VALIDATE").as_deref() != Ok("0");
        let rise = std::env::var("ZKC_RISE_TO").ok().map(|v| {
            let rate: u64 = v.parse().expect("ZKC_RISE_TO");
            assert!(rate > market, "ZKC_RISE_TO must be above the market rate");
            (rate, std::env::var("ZKC_RESTART_CMD").expect("ZKC_RISE_TO needs ZKC_RESTART_CMD"))
        });
        let bound = std::env::var("ZKC_BIND_HEIGHT").as_deref() == Ok("1");
        Run { graph, market, validate, rise, bound }
    }

    fn spike(&self) -> bool {
        self.market > FEE_RATE
    }

    fn results_dir(&self, work: &Path) -> PathBuf {
        if self.graph == Graph::M2 && !self.spike() && self.rise.is_none() && !self.bound {
            return work.join("m2");
        }
        let mut name = format!("{}-{}", self.graph.name(), self.market);
        if let Some((rate, _)) = &self.rise {
            name += &format!("-to-{rate}");
        }
        if self.bound {
            name += "-bound";
        }
        let milestone = if self.rise.is_some() || self.bound { "m13" } else { "m9" };
        work.join(milestone).join(name)
    }
}

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

fn write_result(inp: &Inputs, run: &Run, name: &str, value: &Value) {
    let dir = run.results_dir(&inp.work);
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
                send(rpc, t).unwrap();
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

    /// Sends `t` (its parents confirmed or already in the mempool) and records the node's verdict.
    fn send(&mut self, rpc: &rpc::Rpc, name: &str, t: &Transaction, note: &str) -> Result<(), String> {
        let verdict = send(rpc, t);
        let row = json!({
            "tx": name, "txid": t.compute_txid().to_string(), "vbytes": t.vsize(), "weight": t.weight().to_wu(),
            "inputs": t.input.len(), "outputs": t.output.len(), "version": t.version.0,
            "mempool_now": match &verdict { Ok(()) => "accepted".to_string(), Err(e) => e.clone() },
            "note": note,
        });
        eprintln!("  {name:<28} {:>9} vB  {}", t.vsize(), row["mempool_now"]);
        self.rows.push(row);
        verdict
    }

    /// Adds `key: value` to the latest row for `name`.
    fn annotate(&mut self, name: &str, key: &str, value: Value) {
        let row = self.rows.iter_mut().rev().find(|r| r["tx"] == name).unwrap_or_else(|| panic!("no row for {name}"));
        row[key] = value;
    }

    /// Mines one block from the mempool, which must hold every one of `named`.
    fn mine_mempool(&mut self, rpc: &rpc::Rpc, miner: &Address, named: &[(&str, &Transaction)]) {
        rpc.mine(1, miner);
        self.mark_mined(rpc, named, "mempool");
    }

    /// Total vbytes of the transactions this trace saw mined.
    fn mined_vbytes(&self) -> u64 {
        self.rows.iter().filter(|r| r.get("mined_height").is_some()).map(|r| r["vbytes"].as_u64().unwrap()).sum()
    }
}

/// Whether the node's next block template includes `t`: what a miner takes at the market rate
/// (-blockmintxfee), without mining a block. Core keeps serving its last template for a few
/// seconds after the mempool changes. Every call here follows a change, so it waits for a
/// template whose `longpollid` (tip and mempool update count) differs from the previous one.
static LAST_ID: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());

fn in_template(rpc: &rpc::Rpc, t: &Transaction) -> bool {
    let mut last = LAST_ID.lock().unwrap();
    let mut template = rpc.call("getblocktemplate", json!([{"rules": ["segwit"]}]));
    for _ in 0..30 {
        if template["longpollid"].as_str() != Some(last.as_str()) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
        template = rpc.call("getblocktemplate", json!([{"rules": ["segwit"]}]));
    }
    assert_ne!(template["longpollid"].as_str(), Some(last.as_str()), "no fresh block template after 30 s");
    *last = template["longpollid"].as_str().unwrap().to_string();
    let txid = t.compute_txid().to_string();
    template["transactions"].as_array().unwrap().iter().any(|e| e["txid"].as_str() == Some(txid.as_str()))
}

fn in_mempool(rpc: &rpc::Rpc, t: &Transaction) -> bool {
    rpc.try_call("getmempoolentry", json!([t.compute_txid().to_string()])).is_ok()
}

/// The fee of a mempool transaction, from the node.
fn mempool_fee(rpc: &rpc::Rpc, t: &Transaction) -> u64 {
    let entry = rpc.call("getmempoolentry", json!([t.compute_txid().to_string()]));
    (entry["fees"]["base"].as_f64().unwrap() * 1e8).round() as u64
}

/// What a replacement of `fee` sats must pay at least, for a replacement of `vsize` vbytes.
fn outbid(fee: u64, vsize: usize) -> u64 {
    fee + (INCREMENTAL_RELAY_SAT_PER_KVB * vsize as u64).div_ceil(1000) + 1
}

/// Restarts the node through `cmd <rate>` with -blockmintxfee at `rate` (the market rises), and
/// waits until it answers with the mempool it saved at shutdown loaded again.
fn restart_node(rpc: &rpc::Rpc, cmd: &str, rate: u64) {
    let status = std::process::Command::new("bash").arg(cmd).arg(rate.to_string()).status().expect("restart command");
    assert!(status.success(), "restart command failed: {status}");
    for _ in 0..120 {
        if let Ok(info) = rpc.try_call("getmempoolinfo", json!([])) {
            if info["loaded"].as_bool() == Some(true) {
                // A new process numbers its templates afresh.
                LAST_ID.lock().unwrap().clear();
                return;
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    panic!("the node did not come back after the restart");
}

/// The operator's confirmed coins for CPFP children, one per child.
struct Bumper {
    coins: Vec<(Utxo, bitcoin::key::Keypair)>,
    rate: u64,
    paid: u64,
    /// The coin each child spent, by the child's txid, so that RBF can reuse it.
    spent: Vec<(bitcoin::Txid, Utxo, bitcoin::key::Keypair)>,
}

impl Bumper {
    /// A child spending `handle` (an output of `parent`) and the next coin, carrying the package
    /// to the market rate and paying at least `min_fee`.
    fn child(&mut self, keys: &Keys, rpc: &rpc::Rpc, parent: &Transaction, handle: &Utxo, handle_signer: &bitcoin::key::Keypair, min_fee: u64) -> Transaction {
        let (coin, signer) = self.coins.pop().expect("out of bump coins");
        let parent_fee = mempool_fee(rpc, parent);
        let child = bump_child(keys, parent, parent_fee, handle, handle_signer, &coin, &signer, self.rate, min_fee, keys.operator_script());
        self.paid += handle.sats() + coin.sats() - child.output[0].value.to_sat();
        self.spent.push((child.compute_txid(), coin, signer));
        child
    }

    /// An RBF replacement of `old`, a child of `parent`: the same handle and coin, carrying the
    /// package to the current rate and outbidding `old` by the incremental relay fee.
    fn replace(&mut self, keys: &Keys, rpc: &rpc::Rpc, parent: &Transaction, handle: &Utxo, handle_signer: &bitcoin::key::Keypair, old: &Transaction) -> Transaction {
        let index = self.spent.iter().position(|(txid, _, _)| *txid == old.compute_txid()).expect("not a child of this bumper");
        let (_, coin, signer) = self.spent.remove(index);
        let old_fee = handle.sats() + coin.sats() - old.output[0].value.to_sat();
        let parent_fee = mempool_fee(rpc, parent);
        let child = bump_child(keys, parent, parent_fee, handle, handle_signer, &coin, &signer, self.rate, outbid(old_fee, old.vsize()), keys.operator_script());
        self.paid += handle.sats() + coin.sats() - child.output[0].value.to_sat() - old_fee;
        self.spent.push((child.compute_txid(), coin, signer));
        child
    }
}

/// Posts a presigned `parent` in a spike and the operator's CPFP child through `handle`.
/// Records whether the next block template takes the parent before and after the child, and
/// returns the child's name and transaction for mining.
#[allow(clippy::too_many_arguments)]
fn post_bumped(rpc: &rpc::Rpc, trace: &mut Trace, bumper: &mut Bumper, keys: &Keys, name: &str, parent: &Transaction, note: &str, handle: (&Utxo, &bitcoin::key::Keypair)) -> (String, Transaction) {
    trace.send(rpc, name, parent, note).unwrap_or_else(|e| panic!("{name} refused by the mempool: {e}"));
    trace.annotate(name, "in_template_alone", json!(in_template(rpc, parent)));
    let child = bumper.child(keys, rpc, parent, handle.0, handle.1, 0);
    let child_name = format!("{name}+cpfp");
    trace.send(rpc, &child_name, &child, &format!("operator's CPFP child of {name} at {} sat/vB", bumper.rate)).unwrap_or_else(|e| panic!("{child_name} refused: {e}"));
    trace.annotate(name, "in_template_with_child", json!(in_template(rpc, parent)));
    (child_name, child)
}

fn rpc_from_env() -> rpc::Rpc {
    let var = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
    let node = rpc::Rpc::new(&var("ZKC_RPC_URL", "http://127.0.0.1:18743"), &var("ZKC_RPC_USER", "zkc"), &var("ZKC_RPC_PASS", "zkc-m1-regtest"));
    node.wallet(&var("ZKC_WALLET", "m1"))
}

/// sendrawtransaction with maxburnamount set to BURN. Core refuses an OP_RETURN output with
/// value above maxburnamount (default 0) in this RPC only; testmempoolaccept and relay accept it.
fn send(rpc: &rpc::Rpc, t: &Transaction) -> Result<(), String> {
    let burn_btc = bitcoin::Amount::from_sat(BURN).to_btc();
    rpc.try_call("sendrawtransaction", json!([bitcoin::consensus::encode::serialize_hex(t), 0, burn_btc])).map(|_| ())
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

/// The timeout as anyone completes it from the presigned signatures, at the market `rate` and
/// paying at least `min_fee`.
fn timeout_tx(s: &Setup, reward_to: ScriptBuf, rate: u64, min_fee: u64) -> Transaction {
    let ka_witness = Witness::from_slice(&[s.timeout_ka_sig.clone()]);
    slash_tx(&s.kickoff.kb, &s.timeout_kb_sig, &s.kickoff.ka, Sequence::from_height(T_ASSERT), ka_witness, reward_to, rate, min_fee)
}

/// A disprove through A's leaf `index` with the challenger's witness `items`.
fn disprove_tx(keys: &Keys, s: &Setup, index: usize, leaf: &ScriptBuf, items: Vec<Vec<u8>>, reward_to: ScriptBuf, rate: u64) -> Transaction {
    let a_witness = script_path_witness(items, leaf, &s.a_tree, index, keys);
    slash_tx(&s.kickoff.kb, &s.disprove_kb_sig, &s.chain.a, RBF, a_witness, reward_to, rate, 0)
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

fn scenario(inp: &Inputs, run: &Run, name: &str) {
    const NAMES: [&str; 7] = ["unchallenged", "challenged", "tampered", "silent", "incomplete", "stall", "late"];
    assert!(name != "late" || run.bound, "`late` needs ZKC_BIND_HEIGHT=1");
    assert!(NAMES.contains(&name), "unknown scenario {name}; one of {NAMES:?}");
    assert!(!run.spike() || matches!(name, "unchallenged" | "challenged"), "a fee spike applies to `unchallenged` and `challenged` only");
    let rpc = rpc_from_env();
    let miner = rpc.new_address();
    let keys = Keys::new();
    let market = run.market;
    let mut trace = Trace { rows: vec![] };
    let mut facts = json!({"scenario": name, "graph": run.graph.name(), "fee_rate_sat_per_vb": FEE_RATE, "market_fee_rate_sat_per_vb": market,
        "max_fee_rate_sat_per_vb": MAX_FEE_RATE, "timing": timing(), "bond_sats": BOND, "burn_sats": BURN, "connector_sats": CONNECTOR,
        "anchor_sats": if run.graph.anchored() { ANCHOR } else { 0 }});
    facts["node_blockmintxfee"] = rpc.call("getmininginfo", json!([]))["blockmintxfee"].clone();

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
    let layout = commit_layout(&keys, &worst_plan, run.graph);
    let child_vsize = bump_child_vsize(&keys);
    // A challenger pays the operator the assert chain's cost: at FEE_RATE in the M2 graph; in the
    // anchored graph at MAX_FEE_RATE, CPFP children included. Rounded up to 1,000 sats.
    let challenge_amount = layout.challenge_amount(child_vsize);
    facts["bump_child_vbytes"] = json!(child_vsize);
    facts["assert_chain_bump_budget_at_max_fee_rate_sats"] = json!(layout.bump_budget(MAX_FEE_RATE, child_vsize));

    // Funding, in one block: an escrow per active buyer, the operator's bond and assert
    // reserve, a coin a challenger will spend, and in a spike the operator's bump coins.
    // Bound (M13): the funding block is the next one. Each escrow refunds through CLTV at an
    // absolute expiry that opens in the same block as M2's CSV refund (h_e + T_REFUND), and the
    // statement's batchHeight is h_e + BATCH_HEIGHT_AFTER_FUNDING.
    let h_e_expected = rpc.height() + 1;
    let escrow_expiry = run.bound.then(|| (h_e_expected + u64::from(T_REFUND) - 1) as u32);
    let batch_height = run.bound.then(|| (h_e_expected + BATCH_HEIGHT_AFTER_FUNDING) as u32);
    let mut escrows: Vec<Escrow> = tpl.escrows.iter().map(|s| Escrow::new(&keys, &s.buyer, escrow_expiry)).collect();
    let challenger = keypair(&keys.secp, "challenger");
    let challenger_script = payee_script(&keys, "challenger");
    let mut outs: Vec<(ScriptBuf, u64)> = escrows.iter().zip(&tpl.escrows).map(|(e, s)| (e.tree.script_pubkey(), s.amount)).collect();
    outs.push((keys.operator_script(), BOND));
    outs.push((key_path_script(&keys.secp, "operator-reserve"), layout.reserve()));
    outs.push((challenger_script.clone(), challenge_amount + CHALLENGER_COIN_EXTRA));
    let bump_coins = if run.spike() { BUMP_COINS } else { 0 };
    // Enough for a child that carries a 100 kvB parent to the market rate, or to the rate it
    // rises to.
    let bump_coin_sats = run.rise.as_ref().map_or(market, |(rate, _)| *rate) * 100_000 + 20_000;
    for i in 0..bump_coins {
        outs.push((key_path_script(&keys.secp, &format!("operator-bump-{i}")), bump_coin_sats));
    }
    // Bound: the deadline connector the kickoff must spend before anyone sweeps it.
    let mut deadline = batch_height.map(|h| Deadline::new(&keys, h + DEADLINE_AFTER_BATCH as u32));
    if let Some(d) = &deadline {
        outs.push((d.tree.script_pubkey(), DEADLINE_SATS));
    }
    let funded = fund_many(&rpc, &outs, &miner);
    for (e, u) in escrows.iter_mut().zip(&funded) {
        e.utxo = u.clone();
    }
    let n = escrows.len();
    let (bond, reserve, challenger_coin) = (funded[n].clone(), funded[n + 1].clone(), funded[n + 2].clone());
    if let Some(d) = deadline.as_mut() {
        d.utxo = funded[n + 3 + bump_coins].clone();
    }
    let mut bumper = Bumper {
        coins: (0..bump_coins).map(|i| (funded[n + 3 + i].clone(), keypair(&keys.secp, &format!("operator-bump-{i}")))).collect(),
        rate: market,
        paid: 0,
        spent: vec![],
    };
    let h_e = rpc.height();
    assert_eq!(h_e, h_e_expected, "funding confirmed in an unexpected block");
    facts["batch_height"] = json!(batch_height);
    facts["escrow_expiry_height"] = json!(escrow_expiry);
    facts["deadline"] = json!(deadline.as_ref().map(|d| json!({"height": d.height, "sats": d.utxo.sats(), "outpoint": d.utxo.outpoint.to_string()})));
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
        refunds(&rpc, &miner, &keys, &mut trace, &escrows, &refund_payee, &mut facts, market);
        let unspent = |u: &Utxo| !rpc.call("gettxout", json!([u.outpoint.txid.to_string(), u.outpoint.vout])).is_null();
        facts["bond_unspent"] = json!(unspent(&bond));
        facts["reserve_unspent"] = json!(unspent(&reserve));
        finish(inp, run, name, &trace, &mut facts);
        return;
    }

    // Setup, all off chain: the kickoff, A's script tree, the assert chain and every presigned
    // committee signature. The kickoff's txid is fixed before presigning, so its fee is too:
    // FEE_RATE in the anchored graph, which can bump it, and the market rate in the M2 graph.
    let lock_time = batch_height.map(|h| bitcoin::absolute::LockTime::from_height(h).unwrap()).unwrap_or(bitcoin::absolute::LockTime::ZERO);
    let kickoff = kickoff_tx(&keys, &bond, run.graph, if run.graph.anchored() { FEE_RATE } else { market }, lock_time, deadline.as_ref());
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
    let payout_unchallenged = committee_payout(&keys, &inputs, template_outputs.clone(), run.graph);

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
    let payout_asserted = committee_payout(&keys, &inputs, template_outputs.clone(), run.graph);
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
        "kickoff_vbytes": s.kickoff.tx.vsize(),
        "kb_sats": s.kickoff.kb.sats(),
        "a_outpoint": s.chain.a.outpoint.to_string(), "a_sats": s.chain.a.sats(),
        "a_tree": {"leaves": s.a_tree.leaves.len(), "depth": s.a_tree.depth(), "bitvm_leaves": NUM_TAPS, "binding_leaves": NUM_PUBS,
            "bitvm_leaf_bytes_total": s.full.iter().map(|l| l.len()).sum::<usize>()},
        "commit_groups": s.chain.groups.iter().map(|g| g.len()).collect::<Vec<_>>(),
        "commit_fees_sats": s.chain.commit_fees,
        "assert_init_fee_sats": layout.init_fee,
        "assert_final_vbytes": layout.final_vsize,
        "payout_version": s.payout_unchallenged.version.0,
        "payout_unchallenged_vbytes": s.payout_unchallenged.vsize(),
        "payout_asserted_vbytes": s.payout_asserted.vsize(),
        "presigned_payout_unchallenged_txid": s.payout_unchallenged.compute_txid().to_string(),
        "presigned_payout_asserted_txid": s.payout_asserted.compute_txid().to_string(),
        "committee_signatures": {
            "payout_unchallenged": s.payout_unchallenged.input.len(), "payout_asserted": s.payout_asserted.input.len(),
            "challenge (SINGLE|ANYONECANPAY)": 1, "assert_final (KA)": 1, "disprove (SINGLE on KB, any leaf of A)": 1,
            "timeout (SINGLE on KB, NONE on KA)": 2,
        },
        "challenge_signature_bytes": s.challenge_sig.len(),
    });

    // Bound: the kickoff cannot be mined until the block after batchHeight.
    if let Some(height) = batch_height {
        facts["negative_kickoff_before_batch_height"] =
            trace.reject(&rpc, &miner, "kickoff(before batchHeight)", &s.kickoff.tx, &format!("nLockTime {height}, the statement's batchHeight"));
        mine_to_tip(&rpc, &miner, u64::from(height));
    }

    if name == "late" {
        // The operator does not kick off by the deadline. Anyone sweeps the deadline connector
        // in the first block it may, and the kickoff can never confirm after that. Buyers
        // refund at their escrows' expiry.
        let d = deadline.as_ref().unwrap();
        let sweeper = payee_script(&keys, "deadline-sweeper");
        let sweep = sweep_deadline_tx(&keys, d, sweeper, market);
        mine_to_tip(&rpc, &miner, u64::from(d.height) - 1);
        facts["negative_sweep_before_deadline"] = trace.reject(&rpc, &miner, "sweep(before deadline)", &sweep, &format!("nLockTime {}", d.height));
        mine_to_tip(&rpc, &miner, u64::from(d.height));
        trace.record(&rpc, "sweep", &sweep, "the deadline connector through its CLTV leaf, by anyone").expect("sweep standard");
        trace.mine(&rpc, &miner, &[("sweep", &sweep)]);
        facts["sweeper_sats"] = json!(sweep.output[0].value.to_sat());
        facts["negative_kickoff_after_sweep"] = trace.reject(&rpc, &miner, "kickoff(after deadline)", &s.kickoff.tx, "the deadline connector is spent");
        refunds(&rpc, &miner, &keys, &mut trace, &escrows, &refund_payee, &mut facts, market);
        let unspent = |u: &Utxo| !rpc.call("gettxout", json!([u.outpoint.txid.to_string(), u.outpoint.vout])).is_null();
        facts["bond_unspent"] = json!(unspent(&bond));
        finish(inp, run, name, &trace, &mut facts);
        return;
    }

    // The kickoff: in a spike the anchored graph carries it with a child through its anchor.
    if run.spike() && run.graph.anchored() {
        let anchor = s.kickoff.anchor.clone().unwrap();
        let (child_name, child) = post_bumped(&rpc, &mut trace, &mut bumper, &keys, "kickoff", &s.kickoff.tx, "bond -> KC + KA + KB + anchor", (&anchor, &keys.anchor_keypair()));
        trace.mine_mempool(&rpc, &miner, &[("kickoff", &s.kickoff.tx), (&child_name, &child)]);
    } else {
        trace.record(&rpc, "kickoff", &s.kickoff.tx, if run.graph.anchored() { "bond -> KC + KA + KB + anchor" } else { "bond -> KC + KA + KB" }).expect("kickoff standard");
        trace.mine(&rpc, &miner, &[("kickoff", &s.kickoff.tx)]);
    }
    let h_k = rpc.height();
    assert!(h_k - h_e <= u64::from(T_KICKOFF), "kickoff later than T_kickoff");
    facts["kickoff_height"] = json!(h_k);

    // A watcher checks the operator's (S, π) off chain and challenges if π does not verify.
    let pi_verifies = zkc_convert::verify(&inp.vk, &inp.proof, &chunked::fr_list(&template_signals)).unwrap();
    facts["watcher_check_pi_verifies_for_template"] = json!(pi_verifies);
    assert_eq!(pi_verifies, name != "tampered");
    let challenge = challenge_tx(&keys, &s.kickoff.kc, &s.challenge_sig, s.challenge_amount, &challenger_coin, &challenger, challenger_script.clone(), market);

    match name {
        "unchallenged" => {
            mine_to_tip(&rpc, &miner, h_k + u64::from(T_CHALLENGE) - 2);
            facts["negative_early_payout"] = trace.reject(&rpc, &miner, "payout_unchallenged(early)", &s.payout_unchallenged, "one block before T_challenge");
            facts["negative_early_timeout"] = trace.reject(&rpc, &miner, "timeout(early)", &timeout_tx(&s, challenger_script.clone(), market, 0), "before T_assert");
            mine_to_tip(&rpc, &miner, h_k + u64::from(T_CHALLENGE) - 1);
            if run.spike() {
                let paid = spike_payout_unchallenged(&rpc, &miner, &keys, &mut trace, &mut bumper, &s, &tpl, &template_outputs, h_k, market, &mut facts);
                if !paid {
                    refunds(&rpc, &miner, &keys, &mut trace, &escrows, &refund_payee, &mut facts, market);
                }
            } else {
                trace.record(&rpc, "payout_unchallenged", &s.payout_unchallenged, "KC after T_challenge + KA + KB + every escrow").expect("payout standard");
                trace.mine(&rpc, &miner, &[("payout_unchallenged", &s.payout_unchallenged)]);
                let mined = rpc.transaction(&s.payout_unchallenged.compute_txid());
                assert_eq!(&mined.output[..template_outputs.len()], &template_outputs[..], "payout outputs differ from the template");
                facts["payout_outputs_equal_template"] = json!(true);
                facts["payout_height_minus_kickoff_height"] = json!(rpc.height() - h_k);
                facts["operator_back_sats"] = json!(mined.output.last().unwrap().value.to_sat());
                facts["negative_challenge_after_payout"] = trace.reject(&rpc, &miner, "challenge(after payout)", &challenge, "KC already spent");
                mine_to_tip(&rpc, &miner, h_k + u64::from(T_ASSERT) - 1);
                facts["negative_timeout_after_payout"] = trace.reject(&rpc, &miner, "timeout(after payout)", &timeout_tx(&s, challenger_script.clone(), market, 0), "T_assert reached; KA and KB already spent");
            }
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

            if run.spike() && !run.graph.anchored() {
                // M2's assert chain pays FEE_RATE and has no output to bump from: it waits below
                // the market until the timeout opens, and anyone slashes the honest operator.
                trace.send(&rpc, "assert_init", &s.chain.assert_init, "reserve -> commit outputs; presigned at FEE_RATE, no output to bump").expect("assert_init accepted");
                trace.annotate("assert_init", "in_template_alone", json!(in_template(&rpc, &s.chain.assert_init)));
                let start = rpc.height();
                mine_to_tip(&rpc, &miner, h_k + u64::from(T_ASSERT) - 1);
                facts["assert_init_blocks_waited"] = json!(rpc.height() - start);
                facts["assert_init_confirmed_before_t_assert"] = json!(rpc.confirmations(&s.chain.assert_init.compute_txid()).is_some());
                facts["assert_init_in_template_at_t_assert"] = json!(in_template(&rpc, &s.chain.assert_init));
                let t = timeout_tx(&s, challenger_script.clone(), market, 0);
                trace.record(&rpc, "timeout", &t, "KB (presigned SINGLE) + KA (presigned NONE) after T_assert; the operator was honest").expect("timeout standard");
                trace.mine(&rpc, &miner, &[("timeout", &t)]);
                facts["burned_sats"] = json!(t.output[0].value.to_sat());
                facts["slasher_reward_sats"] = json!(t.output[1].value.to_sat());
                refunds(&rpc, &miner, &keys, &mut trace, &escrows, &refund_payee, &mut facts, market);
                finish(inp, run, name, &trace, &mut facts);
                return;
            }

            // The operator asserts: the honest proof, or in `tampered` the assertion of S' with π.
            let asserted = chunked::sign(assertions(inp, if name == "tampered" { "tampered" } else { "honest" }), &secrets);
            let items: Vec<Vec<Vec<u8>>> = batches.iter().map(|b| chunked::commit_witness(&asserted, b)).collect();
            let plan = CommitPlan { batches: &batches, leaves: &commit_leaves, trees: &commit_trees, items: &items };
            let commits = signed_commits(&keys, &s.chain, &plan);
            if run.spike() {
                post_assert_chain_bumped(&rpc, &miner, &mut trace, &mut bumper, &keys, &s.chain, &commits, run.rise.as_ref(), &mut facts);
            } else {
                post_assert_chain(&rpc, &miner, &mut trace, &s.chain, &commits, name == "challenged", &mut facts);
                trace.record(&rpc, "assert_final", &s.chain.assert_final, "KA + every D_k -> A").expect("assert_final standard");
                trace.mine(&rpc, &miner, &[("assert_final", &s.chain.assert_final)]);
            }
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
            if name == "challenged" {
                if run.validate {
                    let found = timed("challenger validates", || chunked::validate(&inp.vk, &chain_sigs, &pubkeys, &s.full));
                    assert!(found.is_none(), "honest assertion is disprovable at {:?}", found.map(|f| f.0));
                    facts["bitvm_validate"] = json!("no disprovable chunk");
                    let last = NUM_TAPS - 1;
                    let items = chunked::witness_for_leaf(&inp.vk, &chain_sigs, last).expect("witness for the final leaf");
                    assert!(!chunked::leaf_succeeds(&s.full[last], &items));
                    let fake = disprove_tx(&keys, &s, last, &s.full[last], items, challenger_script.clone(), market);
                    facts["negative_disprove_final_chunk"] = trace.reject(&rpc, &miner, "disprove(final chunk)", &fake, "honest witness for the validating leaf");
                    let i = template::refund(0);
                    let items = chunked::binding_witness(&chain_sigs, i);
                    assert!(!chunked::leaf_succeeds(&s.binding[i], &items));
                    let fake = disprove_tx(&keys, &s, binding_index(i), &s.binding[i], items, challenger_script.clone(), market);
                    facts["negative_disprove_binding"] = trace.reject(&rpc, &miner, "disprove(binding refund[0])", &fake, "honest commitment against its own binding leaf");
                } else {
                    facts["bitvm_validate"] = json!("skipped (ZKC_VALIDATE=0)");
                }

                mine_to_tip(&rpc, &miner, h_a + u64::from(T_DISPROVE) - 2);
                facts["negative_early_payout"] = trace.reject(&rpc, &miner, "payout_asserted(early)", &s.payout_asserted, "one block before T_disprove");
                mine_to_tip(&rpc, &miner, h_a + u64::from(T_DISPROVE) - 1);
                if run.spike() {
                    let back = Utxo::of(&s.payout_asserted, s.payout_asserted.output.len() - 1);
                    let (child_name, child) = post_bumped(&rpc, &mut trace, &mut bumper, &keys, "payout_asserted", &s.payout_asserted, "A after T_disprove + KB + every escrow", (&back, &keys.operator));
                    trace.mine_mempool(&rpc, &miner, &[("payout_asserted", &s.payout_asserted), (&child_name, &child)]);
                } else {
                    trace.record(&rpc, "payout_asserted", &s.payout_asserted, "A after T_disprove + KB + every escrow").expect("payout standard");
                    trace.mine(&rpc, &miner, &[("payout_asserted", &s.payout_asserted)]);
                }
                let mined = rpc.transaction(&s.payout_asserted.compute_txid());
                assert_eq!(&mined.output[..template_outputs.len()], &template_outputs[..], "payout outputs differ from the template");
                facts["payout_outputs_equal_template"] = json!(true);
                facts["operator_back_sats"] = json!(mined.output.last().unwrap().value.to_sat());
                let tip = rpc.height().max(h_k + u64::from(T_ASSERT) - 1);
                mine_to_tip(&rpc, &miner, tip);
                facts["negative_timeout_after_assert"] = trace.reject(&rpc, &miner, "timeout(after assert)", &timeout_tx(&s, challenger_script.clone(), market, 0), "T_assert reached; KA spent by assert_final");
            } else {
                let found = timed("challenger validates", || chunked::validate(&inp.vk, &chain_sigs, &pubkeys, &s.full));
                let (index, items) = found.expect("tampered assertion not disprovable");
                let leaf = &s.full[index];
                assert!(chunked::leaf_succeeds(leaf, &items), "challenger witness does not open the leaf");
                facts["bitvm_validate"] = json!(format!("chunk {index} disprovable"));
                facts["disprove_leaf"] = json!({"index": index, "leaf_bytes": leaf.len(), "witness_items": items.len()});
                let d = disprove_tx(&keys, &s, index, leaf, items, challenger_script.clone(), market);
                trace.record(&rpc, "disprove", &d, &format!("KB (presigned SINGLE) + A through BitVM chunk {index}")).ok();
                trace.mine(&rpc, &miner, &[("disprove", &d)]);
                facts["burned_sats"] = json!(d.output[0].value.to_sat());
                facts["challenger_reward_sats"] = json!(d.output[1].value.to_sat());
                mine_to_tip(&rpc, &miner, rpc.height().max(h_a + u64::from(T_DISPROVE) - 1));
                facts["negative_payout_after_disprove"] = trace.reject(&rpc, &miner, "payout_asserted(after disprove)", &s.payout_asserted, "T_disprove reached; A and KB spent");
                mine_to_tip(&rpc, &miner, rpc.height().max(h_k + u64::from(T_ASSERT) - 1));
                facts["negative_timeout_after_disprove"] = trace.reject(&rpc, &miner, "timeout(after disprove)", &timeout_tx(&s, challenger_script.clone(), market, 0), "T_assert reached; KA and KB spent");
                refunds(&rpc, &miner, &keys, &mut trace, &escrows, &refund_payee, &mut facts, market);
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
            facts["negative_early_timeout"] = trace.reject(&rpc, &miner, "timeout(early)", &timeout_tx(&s, challenger_script.clone(), market, 0), "one block before T_assert");
            facts["negative_payout_unchallenged_after_challenge"] =
                trace.reject(&rpc, &miner, "payout_unchallenged(challenged)", &s.payout_unchallenged, "KC spent by the challenge");
            mine_to_tip(&rpc, &miner, h_k + u64::from(T_ASSERT) - 1);
            let t = timeout_tx(&s, challenger_script.clone(), market, 0);
            trace.record(&rpc, "timeout", &t, "KB (presigned SINGLE) + KA (presigned NONE) after T_assert").expect("timeout standard");
            trace.mine(&rpc, &miner, &[("timeout", &t)]);
            facts["burned_sats"] = json!(t.output[0].value.to_sat());
            facts["slasher_reward_sats"] = json!(t.output[1].value.to_sat());
            facts["negative_assert_final_after_timeout"] = trace.reject(&rpc, &miner, "assert_final(after timeout)", &s.chain.assert_final,
                if name == "incomplete" { "KA spent by the timeout" } else { "no commits, and KA spent by the timeout" });
            refunds(&rpc, &miner, &keys, &mut trace, &escrows, &refund_payee, &mut facts, market);
        }
        other => panic!("unknown scenario {other}"),
    }
    if run.spike() {
        facts["operator_cpfp_fees_sats"] = json!(bumper.paid);
    }
    finish(inp, run, name, &trace, &mut facts);
}

/// The unchallenged payout in a spike. It pays FEE_RATE, below the market. A payee pins it
/// first; then the operator posts a CPFP child through its back output. Returns whether the
/// payout was mined; if not, the pinning payee posts the timeout once it opens.
#[allow(clippy::too_many_arguments)]
fn spike_payout_unchallenged(
    rpc: &rpc::Rpc,
    miner: &Address,
    keys: &Keys,
    trace: &mut Trace,
    bumper: &mut Bumper,
    s: &Setup,
    tpl: &template::Template,
    template_outputs: &[TxOut],
    h_k: u64,
    market: u64,
    facts: &mut Value,
) -> bool {
    let payout = &s.payout_unchallenged;
    trace.send(rpc, "payout_unchallenged", payout, "KC after T_challenge + KA + KB + every escrow; presigned at FEE_RATE").expect("payout accepted");
    trace.annotate("payout_unchallenged", "in_template_alone", json!(in_template(rpc, payout)));
    let (pinner, pins, pin_fees) = pin_payout(rpc, keys, trace, payout, tpl, market, facts);

    let back = Utxo::of(payout, payout.output.len() - 1);
    // Under TRUC the operator's child is a sibling of the pin and must outbid it.
    let min_fee = if payout.version == Version(3) { outbid(pin_fees, bump_child_vsize(keys) as usize) } else { 0 };
    let child = bumper.child(keys, rpc, payout, &back, &keys.operator, min_fee);
    let verdict = trace.send(rpc, "payout_unchallenged+cpfp", &child, "operator's CPFP child through its back output");
    facts["operator_cpfp"] = json!(verdict.clone().map(|()| "accepted".to_string()).unwrap_or_else(|e| e));
    facts["pins_in_mempool_after_cpfp"] = json!(pins.iter().filter(|p| in_mempool(rpc, p)).count());
    let carried = verdict.is_ok() && in_template(rpc, payout);
    facts["payout_in_template_after_cpfp"] = json!(carried);
    if carried {
        trace.mine_mempool(rpc, miner, &[("payout_unchallenged", payout), ("payout_unchallenged+cpfp", &child)]);
        let mined = rpc.transaction(&payout.compute_txid());
        assert_eq!(&mined.output[..template_outputs.len()], template_outputs, "payout outputs differ from the template");
        facts["payout_outputs_equal_template"] = json!(true);
        facts["payout_height_minus_kickoff_height"] = json!(rpc.height() - h_k);
        facts["operator_back_sats"] = json!(mined.output.last().unwrap().value.to_sat());
        return true;
    }
    // The payout cannot be carried: it waits below the market until the timeout opens, and the
    // pinning payee replaces it (and the pins) with the timeout, slashing the operator.
    mine_to_tip(rpc, miner, h_k + u64::from(T_ASSERT) - 1);
    facts["payout_in_mempool_at_t_assert"] = json!(in_mempool(rpc, payout));
    let replaced = mempool_fee(rpc, payout) + pin_fees;
    let reward_to = payee_script(keys, &pinner);
    let draft = timeout_tx(s, reward_to.clone(), market, 0);
    let t = timeout_tx(s, reward_to, market, outbid(replaced, draft.vsize()));
    trace.send(rpc, "timeout", &t, &format!("posted by the pinning payee {pinner}; replaces the payout and its pins")).expect("timeout replaces the pinned payout");
    trace.mine_mempool(rpc, miner, &[("timeout", &t)]);
    facts["burned_sats"] = json!(t.output[0].value.to_sat());
    facts["slasher_reward_sats"] = json!(t.output[1].value.to_sat());
    facts["slasher"] = json!(pinner);
    false
}

/// A payee of `payout` pins it: the payee with the smallest output, who gains most if the payout
/// misses T_assert and it posts the timeout. Returns the payee, its pin transactions and their
/// total fee.
/// - TRUC payout: one version 3 child as large as TRUC allows, paying just less than would carry
///   the payout to the market rate, so that the operator's child must outbid it.
/// - Version 2 payout: a chain of small children, until the node refuses one.
fn pin_payout(rpc: &rpc::Rpc, keys: &Keys, trace: &mut Trace, payout: &Transaction, tpl: &template::Template, market: u64, facts: &mut Value) -> (String, Vec<Transaction>, u64) {
    let (index, spec) = tpl.outputs.iter().enumerate().filter(|(_, o)| o.role != "fee").min_by_key(|(_, o)| o.amount).unwrap();
    let pinner = spec.payee.clone();
    let signer = keypair(&keys.secp, &pinner);
    let script = payee_script(keys, &pinner);
    let spend = |coin: &Utxo, version: Version, outs: Vec<TxOut>| {
        let mut t = tx_version(version, vec![(coin.outpoint, RBF)], outs);
        let sig = sign_key_path(keys, &signer, &t, &bitcoin::sighash::Prevouts::All(&[coin.txout.clone()]), 0, bitcoin::TapSighashType::Default, None);
        t.input[0].witness = Witness::from_slice(&[sig]);
        t
    };
    let coin = Utxo::of(payout, index);
    facts["pinner"] = json!({"payee": pinner, "payout_output_sats": coin.sats()});

    if payout.version == Version(3) {
        let padded = |pad: usize, fee: u64| {
            let data = bitcoin::script::PushBytesBuf::try_from(vec![0x50u8; pad]).unwrap();
            let op_return = bitcoin::script::Builder::new().push_opcode(bitcoin::opcodes::all::OP_RETURN).push_slice(data).into_script();
            spend(&coin, Version(3), vec![txout(coin.sats() - fee, script.clone()), txout(0, op_return)])
        };
        let mut pad = TRUC_CHILD_MAX_VSIZE - padded(0, 0).vsize() - 8;
        while padded(pad + 1, 0).vsize() <= TRUC_CHILD_MAX_VSIZE {
            pad += 1;
        }
        let size = padded(pad, 0).vsize();
        // Just under what would carry the payout to the market rate.
        let fee = market * (payout.vsize() + size) as u64 - mempool_fee(rpc, payout) - 1;
        let pin = padded(pad, fee);
        trace.send(rpc, "pin", &pin, &format!("{pinner}'s TRUC child, just below the market with its parent")).expect("pin accepted");
        trace.annotate("pin", "fee_sats", json!(fee));
        trace.annotate("payout_unchallenged", "in_template_with_pin", json!(in_template(rpc, payout)));
        return (pinner, vec![pin], fee);
    }

    let mut pins = vec![];
    let mut fees = 0;
    let mut prev = coin;
    loop {
        let draft = spend(&prev, Version::TWO, vec![txout(prev.sats(), script.clone())]);
        let fee = draft.vsize() as u64;
        let t = spend(&prev, Version::TWO, vec![txout(prev.sats() - fee, script.clone())]);
        match send(rpc, &t) {
            Ok(()) => {
                fees += fee;
                prev = Utxo::of(&t, 0);
                pins.push(t);
            }
            Err(e) => {
                facts["pin_chain"] = json!({"accepted": pins.len(), "vbytes_each": draft.vsize(), "fee_sats_total": fees, "next_refused": e});
                eprintln!("  pin chain: {} accepted, the next refused: {e}", pins.len());
                break;
            }
        }
        assert!(pins.len() < 200, "the node accepted 200 pins");
    }
    (pinner, pins, fees)
}

/// Posts the anchored assert chain in a spike, each transaction with the operator's CPFP child
/// through its anchor, in the same three blocks as at FEE_RATE. With `rise` (M13), the market
/// rises after assert_init's child is posted: the node restarts at the new rate, and the
/// operator replaces that child by RBF and bumps the rest of the chain at the new rate.
#[allow(clippy::too_many_arguments)]
fn post_assert_chain_bumped(
    rpc: &rpc::Rpc,
    miner: &Address,
    trace: &mut Trace,
    bumper: &mut Bumper,
    keys: &Keys,
    chain: &AssertChain,
    commits: &[Transaction],
    rise: Option<&(u64, String)>,
    facts: &mut Value,
) {
    let anchor_key = keys.anchor_keypair();
    let init = &chain.assert_init;
    let (mut child_name, mut child) = post_bumped(rpc, trace, bumper, keys, "assert_init", init, "reserve -> commit outputs + anchor", (&anchor_of(init), &anchor_key));
    if let Some((rate, cmd)) = rise {
        restart_node(rpc, cmd, *rate);
        bumper.rate = *rate;
        let kept = in_mempool(rpc, init) && in_mempool(rpc, &child);
        let carried = in_template(rpc, init);
        eprintln!("  market now {rate} sat/vB: assert_init and child in the mempool {kept}, in the template {carried}");
        let replacement = bumper.replace(keys, rpc, init, &anchor_of(init), &anchor_key, &child);
        let name = "assert_init+cpfp(rbf)";
        let verdict = trace.send(rpc, name, &replacement, &format!("RBF of the operator's child at {rate} sat/vB"));
        facts["rise"] = json!({
            "to_sat_per_vb": rate,
            "assert_init_and_child_in_mempool_after_restart": kept,
            "assert_init_in_template_with_old_child": carried,
            "replacement": verdict.clone().map(|()| "accepted".to_string()).unwrap_or_else(|e| e),
            "old_child_in_mempool_after_replacement": in_mempool(rpc, &child),
            "assert_init_in_template_with_replacement": in_template(rpc, init),
        });
        verdict.unwrap_or_else(|e| panic!("{name} refused: {e}"));
        (child_name, child) = (name.to_string(), replacement);
    }
    trace.mine_mempool(rpc, miner, &[("assert_init", init), (&child_name, &child)]);

    let names: Vec<String> = (0..commits.len()).map(|k| format!("commit[{k}]")).collect();
    let mut children = vec![];
    for ((t, name), group) in commits.iter().zip(&names).zip(&chain.groups) {
        children.push(post_bumped(rpc, trace, bumper, keys, name, t, &format!("{} Winternitz batches + anchor", group.len()), (&anchor_of(t), &anchor_key)));
    }
    let mut named: Vec<(&str, &Transaction)> = names.iter().map(String::as_str).zip(commits).collect();
    named.extend(children.iter().map(|(n, c)| (n.as_str(), c)));
    trace.mine_mempool(rpc, miner, &named);

    let last = &chain.assert_final;
    let (child_name, child) = post_bumped(rpc, trace, bumper, keys, "assert_final", last, "KA + every D_k -> A + anchor", (&anchor_of(last), &anchor_key));
    trace.mine_mempool(rpc, miner, &[("assert_final", last), (&child_name, &child)]);
}

/// Posts assert_init and the commits. With `probe`, first shows why the chain needs a block per
/// step: only one commit fits in the mempool beside an unconfirmed assert_init.
fn post_assert_chain(rpc: &rpc::Rpc, miner: &Address, trace: &mut Trace, chain: &AssertChain, commits: &[Transaction], probe: bool, facts: &mut Value) {
    trace.record(rpc, "assert_init", &chain.assert_init, "reserve -> commit outputs").expect("assert_init standard");
    let names: Vec<String> = (0..commits.len()).map(|k| format!("commit[{k}]")).collect();
    let mut start = 0;
    if probe {
        send(rpc, &chain.assert_init).unwrap();
        let mut mined = vec![("assert_init", &chain.assert_init)];
        let first = trace.record(rpc, &names[0], &commits[0], &format!("{} Winternitz batches; parent unconfirmed", chain.groups[0].len()));
        let verdict = |r: Result<(), String>| r.map(|()| "accepted".to_string()).unwrap_or_else(|e| e);
        facts["mempool_probe_first_commit_with_unconfirmed_parent"] = json!(verdict(first.clone()));
        if first.is_ok() {
            send(rpc, &commits[0]).unwrap();
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

fn finish(inp: &Inputs, run: &Run, name: &str, trace: &Trace, facts: &mut Value) {
    facts["mined_vbytes_total"] = json!(trace.mined_vbytes());
    facts["transactions"] = json!(trace.rows);
    write_result(inp, run, &format!("scenario-{name}"), facts);
}

/// Buyers' timeout path: rejected one block early, accepted at T_refund. Each buyer signs its
/// refund when posting, at the market `rate`.
#[allow(clippy::too_many_arguments)]
fn refunds(rpc: &rpc::Rpc, miner: &Address, keys: &Keys, trace: &mut Trace, escrows: &[Escrow], payee: &dyn Fn(&Escrow) -> ScriptBuf, facts: &mut Value, rate: u64) {
    let txs: Vec<Transaction> = escrows.iter().map(|e| refund_tx(keys, e, payee(e), rate)).collect();
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
        Some("scenario") if args.len() >= 4 => scenario(&load(Path::new(&args[2])), &Run::from_env(), &args[3]),
        _ => {
            eprintln!("usage: zkc-m2 timing | zkc-m2 scenario <work> <name>");
            std::process::exit(2);
        }
    }
}
