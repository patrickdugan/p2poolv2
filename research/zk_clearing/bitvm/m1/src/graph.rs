//! The M1 transaction graph on regtest.
//!
//!   escrow[b]     buyer funding, P2TR {payout: committee CHECKSIG | refund: T_refund CSV, buyer CHECKSIG}
//!   bond          operator key path
//!   assert_init   bond -> K (operator) + one commit output C_j per Winternitz batch
//!   commit[k]     C_j inputs, each through its commit leaf (Winternitz batch + operator CHECKSIG) -> D_k
//!   assert_final  K + every D_k -> A, P2TR {432 BitVM disprove leaves | 18 binding leaves |
//!                 payout: T_challenge CSV, committee CHECKSIG}
//!   payout        A (payout leaf) + every escrow (committee leaf) -> template outputs + bond back
//!   disprove      A through one disprove or binding leaf -> challenger (the bond is slashed)
//!   refund[b]     escrow[b] through its refund leaf after T_refund
//!
//! The committee is one demo key standing in for BitVM2's n-of-n presigning committee: it
//! signs the payout before any assertion is posted, and is assumed to sign nothing else.

use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, Secp256k1, TapTweak};
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP};
use bitcoin::script::Builder;
use bitcoin::secp256k1::{All, Message, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash};
use bitcoin::transaction::Version;
use bitcoin::{absolute::LockTime, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

use crate::taproot::{key_path_script, keypair, leaf_hash, ScriptTree};

pub const FEE_RATE: u64 = 2; // sat/vB
pub const T_CHALLENGE: u16 = 6;
pub const T_REFUND: u16 = 30;
pub const BOND: u64 = 10_000_000;
pub const CONNECTOR: u64 = 330;

pub struct Keys {
    pub secp: Secp256k1<All>,
    pub operator: Keypair,
    pub committee: Keypair,
}

impl Keys {
    pub fn new() -> Keys {
        let secp = Secp256k1::new();
        let operator = keypair(&secp, "operator");
        let committee = keypair(&secp, "committee");
        Keys { secp, operator, committee }
    }

    pub fn x(&self, kp: &Keypair) -> XOnlyPublicKey {
        kp.x_only_public_key().0
    }
}

pub fn csv_checksig(blocks: u16, key: &XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_int(i64::from(blocks))
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_x_only_key(key)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

pub fn checksig(key: &XOnlyPublicKey) -> ScriptBuf {
    Builder::new().push_x_only_key(key).push_opcode(OP_CHECKSIG).into_script()
}

pub fn tx(inputs: Vec<(OutPoint, Sequence)>, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs
            .into_iter()
            .map(|(previous_output, sequence)| TxIn { previous_output, script_sig: ScriptBuf::new(), sequence, witness: Witness::new() })
            .collect(),
        output: outputs,
    }
}

pub fn txout(sats: u64, script_pubkey: ScriptBuf) -> TxOut {
    TxOut { value: Amount::from_sat(sats), script_pubkey }
}

pub fn fee_for(tx: &Transaction) -> u64 {
    tx.vsize() as u64 * FEE_RATE
}

/// Schnorr signature (SIGHASH_DEFAULT) for a script-path spend of input `index`.
pub fn sign_script_path(keys: &Keys, signer: &Keypair, tx: &Transaction, prevouts: &[TxOut], index: usize, leaf: &ScriptBuf) -> Vec<u8> {
    let leaf_hash = TapLeafHash::from_script(leaf, LeafVersion::TapScript);
    let sighash = SighashCache::new(tx)
        .taproot_script_spend_signature_hash(index, &Prevouts::All(prevouts), leaf_hash, TapSighashType::Default)
        .expect("sighash");
    let sig = keys.secp.sign_schnorr_no_aux_rand(&Message::from_digest(sighash.to_byte_array()), signer);
    sig.as_ref().to_vec()
}

/// Key-path signature for an output made by `key_path_script(label)`.
pub fn sign_key_path(keys: &Keys, signer: &Keypair, tx: &Transaction, prevouts: &[TxOut], index: usize) -> Vec<u8> {
    let sighash = SighashCache::new(tx)
        .taproot_key_spend_signature_hash(index, &Prevouts::All(prevouts), TapSighashType::Default)
        .expect("sighash");
    let tweaked = signer.tap_tweak(&keys.secp, None).to_keypair();
    let sig = keys.secp.sign_schnorr_no_aux_rand(&Message::from_digest(sighash.to_byte_array()), &tweaked);
    sig.as_ref().to_vec()
}

/// Witness for a script-path spend: stack items, then the leaf and its control block.
pub fn script_path_witness(items: Vec<Vec<u8>>, leaf: &ScriptBuf, tree: &ScriptTree, index: usize, keys: &Keys) -> Witness {
    let control = tree.checked_control_block(&keys.secp, index, leaf);
    let mut all = items;
    all.push(leaf.to_bytes());
    all.push(control.serialize());
    Witness::from_slice(&all)
}

/// Escrow output for one buyer.
pub struct Escrow {
    pub buyer: String,
    pub payout_leaf: ScriptBuf,
    pub refund_leaf: ScriptBuf,
    pub tree: ScriptTree,
    pub outpoint: OutPoint,
    pub txout: TxOut,
}

impl Escrow {
    pub fn new(keys: &Keys, buyer: &str) -> Escrow {
        let payout_leaf = checksig(&keys.x(&keys.committee));
        let refund_leaf = csv_checksig(T_REFUND, &keys.x(&keypair(&keys.secp, &format!("buyer:{buyer}"))));
        let tree = ScriptTree::new(&keys.secp, vec![leaf_hash(&payout_leaf), leaf_hash(&refund_leaf)]);
        Escrow { buyer: buyer.to_string(), payout_leaf, refund_leaf, tree, outpoint: OutPoint::null(), txout: txout(0, ScriptBuf::new()) }
    }
}

/// The buyer's refund after T_refund, paying `to` (the buyer's refund payee).
pub fn refund_tx(keys: &Keys, escrow: &Escrow, to: ScriptBuf) -> Transaction {
    let buyer = keypair(&keys.secp, &format!("buyer:{}", escrow.buyer));
    let build = |value: u64| {
        let mut t = tx(vec![(escrow.outpoint, Sequence::from_height(T_REFUND))], vec![txout(value, to.clone())]);
        let sig = sign_script_path(keys, &buyer, &t, &[escrow.txout.clone()], 0, &escrow.refund_leaf);
        t.input[0].witness = script_path_witness(vec![sig], &escrow.refund_leaf, &escrow.tree, 1, keys);
        t
    };
    let draft = build(escrow.txout.value.to_sat());
    build(escrow.txout.value.to_sat() - fee_for(&draft))
}

/// The payout: A through its payout leaf plus every escrow through the committee leaf, signed
/// by the committee. `outputs` are the template's; the bond (less the fee) returns to the operator.
pub fn payout_tx(keys: &Keys, a: (OutPoint, &TxOut), a_tree: &ScriptTree, a_payout_index: usize, a_payout_leaf: &ScriptBuf, escrows: &[Escrow], outputs: Vec<TxOut>) -> Transaction {
    let mut inputs = vec![(a.0, Sequence::from_height(T_CHALLENGE))];
    inputs.extend(escrows.iter().map(|e| (e.outpoint, Sequence::ENABLE_RBF_NO_LOCKTIME)));
    let mut prevouts = vec![a.1.clone()];
    prevouts.extend(escrows.iter().map(|e| e.txout.clone()));
    let operator_back = key_path_script(&keys.secp, "operator");
    let build = |back: u64| {
        let mut outs = outputs.clone();
        outs.push(txout(back, operator_back.clone()));
        let mut t = tx(inputs.clone(), outs);
        let sig = sign_script_path(keys, &keys.committee, &t, &prevouts, 0, a_payout_leaf);
        let mut witnesses = vec![script_path_witness(vec![sig], a_payout_leaf, a_tree, a_payout_index, keys)];
        for (i, e) in escrows.iter().enumerate() {
            let sig = sign_script_path(keys, &keys.committee, &t, &prevouts, i + 1, &e.payout_leaf);
            witnesses.push(script_path_witness(vec![sig], &e.payout_leaf, &e.tree, 0, keys));
        }
        for (input, w) in t.input.iter_mut().zip(witnesses) {
            input.witness = w;
        }
        t
    };
    let draft = build(a.1.value.to_sat());
    build(a.1.value.to_sat() - fee_for(&draft))
}

/// A disprove: anyone spends A through leaf `index` with `items` and takes the bond.
pub fn disprove_tx(keys: &Keys, a: (OutPoint, &TxOut), a_tree: &ScriptTree, index: usize, leaf: &ScriptBuf, items: Vec<Vec<u8>>, to: ScriptBuf) -> Transaction {
    let witness = script_path_witness(items, leaf, a_tree, index, keys);
    let build = |value: u64| {
        let mut t = tx(vec![(a.0, Sequence::ENABLE_RBF_NO_LOCKTIME)], vec![txout(value, to.clone())]);
        t.input[0].witness = witness.clone();
        t
    };
    let draft = build(a.1.value.to_sat());
    build(a.1.value.to_sat() - fee_for(&draft))
}

/// The assert chain, built and signed before anything is broadcast. Segwit txids do not
/// cover witnesses, so A's outpoint is fixed before the Winternitz data exists and the
/// committee can presign the payout against it.
pub struct AssertChain {
    pub assert_init: Transaction,
    pub commits: Vec<Transaction>,
    /// For each commit transaction, the batch indices it spends (one input per batch).
    pub commit_groups: Vec<Vec<usize>>,
    pub assert_final: Transaction,
}

pub struct CommitPlan<'a> {
    pub batches: &'a [Vec<usize>],
    pub leaves: &'a [ScriptBuf],
    pub trees: &'a [ScriptTree],
    /// Witness items (without the Schnorr signature) for each batch.
    pub items: &'a [Vec<Vec<u8>>],
}

/// Weight budget per commit transaction; Core's standardness limit is 400,000 WU.
pub const COMMIT_TX_WEIGHT: u64 = 390_000;

fn commit_input_weight(plan: &CommitPlan, batch: usize, depth: usize) -> u64 {
    let items: u64 = plan.items[batch].iter().map(|i| i.len() as u64 + 3).sum();
    let witness = items + 66 + plan.leaves[batch].len() as u64 + 5 + 33 + 32 * depth as u64 + 3;
    41 * 4 + witness
}

pub fn build_assert_chain(keys: &Keys, bond: (OutPoint, &TxOut), plan: &CommitPlan, a_script: ScriptBuf) -> AssertChain {
    let op = &keys.operator;
    let op_script = key_path_script(&keys.secp, "operator");

    // Group batches into commit transactions under the weight budget.
    let mut groups: Vec<Vec<usize>> = vec![vec![]];
    let mut weight = 4 * 60;
    for b in 0..plan.batches.len() {
        let w = commit_input_weight(plan, b, plan.trees[b].depth());
        if weight + w > COMMIT_TX_WEIGHT && !groups.last().unwrap().is_empty() {
            groups.push(vec![]);
            weight = 4 * 60;
        }
        groups.last_mut().unwrap().push(b);
        weight += w;
    }

    let sign_commit = |t: &mut Transaction, group: &[usize], prevouts: &[TxOut]| {
        for (i, b) in group.iter().enumerate() {
            let sig = sign_script_path(keys, op, t, prevouts, i, &plan.leaves[*b]);
            let mut items = vec![sig];
            items.extend(plan.items[*b].iter().cloned());
            t.input[i].witness = script_path_witness(items, &plan.leaves[*b], &plan.trees[*b], 0, keys);
        }
    };

    // Pass 1: sizes with placeholder outpoints, which do not change the size.
    let mut commit_fee = vec![];
    for group in &groups {
        let inputs = group.iter().map(|b| (OutPoint { txid: Txid::all_zeros(), vout: *b as u32 }, Sequence::ENABLE_RBF_NO_LOCKTIME)).collect();
        let prevouts: Vec<TxOut> = group.iter().map(|b| txout(100_000, plan.trees[*b].script_pubkey())).collect();
        let mut t = tx(inputs, vec![txout(CONNECTOR, op_script.clone())]);
        sign_commit(&mut t, group, &prevouts);
        commit_fee.push(fee_for(&t));
    }
    // Each C_j carries an equal share of its commit transaction's fee plus the connector.
    let mut c_value = vec![0u64; plan.batches.len()];
    for (group, fee) in groups.iter().zip(&commit_fee) {
        let share = (fee + CONNECTOR).div_ceil(group.len() as u64);
        for b in group {
            c_value[*b] = share;
        }
    }

    // assert_init: bond -> K + C_j.
    let build_init = |k_value: u64| {
        let mut outs = vec![txout(k_value, op_script.clone())];
        outs.extend((0..plan.batches.len()).map(|b| txout(c_value[b], plan.trees[b].script_pubkey())));
        let mut t = tx(vec![(bond.0, Sequence::ENABLE_RBF_NO_LOCKTIME)], outs);
        t.input[0].witness = Witness::from_slice(&[sign_key_path(keys, op, &t, &[bond.1.clone()], 0)]);
        t
    };
    let c_total: u64 = c_value.iter().sum();
    let draft = build_init(bond.1.value.to_sat() - c_total);
    let assert_init = build_init(bond.1.value.to_sat() - c_total - fee_for(&draft));
    let init_txid = assert_init.compute_txid();

    // commit[k]: spends its C_j outputs, leaves one connector D_k.
    let mut commits = vec![];
    for (group, fee) in groups.iter().zip(&commit_fee) {
        let inputs = group.iter().map(|b| (OutPoint { txid: init_txid, vout: *b as u32 + 1 }, Sequence::ENABLE_RBF_NO_LOCKTIME)).collect();
        let prevouts: Vec<TxOut> = group.iter().map(|b| assert_init.output[*b + 1].clone()).collect();
        let total: u64 = prevouts.iter().map(|o| o.value.to_sat()).sum();
        let mut t = tx(inputs, vec![txout(total - fee, op_script.clone())]);
        sign_commit(&mut t, group, &prevouts);
        assert!(fee_for(&t) <= *fee, "commit fee grew between passes");
        commits.push(t);
    }

    // assert_final: K + every D_k -> A.
    let mut inputs = vec![(OutPoint { txid: init_txid, vout: 0 }, Sequence::ENABLE_RBF_NO_LOCKTIME)];
    let mut prevouts = vec![assert_init.output[0].clone()];
    for c in &commits {
        inputs.push((OutPoint { txid: c.compute_txid(), vout: 0 }, Sequence::ENABLE_RBF_NO_LOCKTIME));
        prevouts.push(c.output[0].clone());
    }
    let in_total: u64 = prevouts.iter().map(|o| o.value.to_sat()).sum();
    let build_final = |value: u64| {
        let mut t = tx(inputs.clone(), vec![txout(value, a_script.clone())]);
        let sigs: Vec<Vec<u8>> = (0..t.input.len()).map(|i| sign_key_path(keys, op, &t, &prevouts, i)).collect();
        for (input, sig) in t.input.iter_mut().zip(sigs) {
            input.witness = Witness::from_slice(&[sig]);
        }
        t
    };
    let draft = build_final(in_total);
    let assert_final = build_final(in_total - fee_for(&draft));
    AssertChain { assert_init, commits, commit_groups: groups, assert_final }
}

/// The challenger's view: every batch's Winternitz items, read back from the commit
/// transactions' witnesses (Schnorr signature first, leaf and control block last).
pub fn items_from_commits(commits: &[Transaction], groups: &[Vec<usize>]) -> Vec<Vec<Vec<u8>>> {
    let mut per_batch = vec![];
    for (t, group) in commits.iter().zip(groups) {
        for (i, b) in group.iter().enumerate() {
            let w: Vec<Vec<u8>> = t.input[i].witness.iter().map(|x| x.to_vec()).collect();
            per_batch.push((*b, w[1..w.len() - 2].to_vec()));
        }
    }
    per_batch.sort_by_key(|(b, _)| *b);
    per_batch.into_iter().map(|(_, items)| items).collect()
}
