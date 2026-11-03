//! The M2 optimistic graph on regtest (the BitVM2 shape).
//!
//!   escrow[b]            P2TR(committee key; {refund: T_refund CSV, buyer CHECKSIG})
//!   bond, reserve        operator key path; the reserve pays for the assert chain if challenged
//!   kickoff              bond -> KC, KA (connectors) + KB (the bond), each committee key path
//!   challenge            KC, committee SIGHASH_SINGLE|ANYONECANPAY: output 0 pays the operator
//!                        the assert chain's cost; the challenger adds its own inputs and change
//!   payout_unchallenged  KC (nSequence T_challenge) + KA + KB + every escrow
//!                        -> the template's outputs + the bond back to the operator
//!   assert_init          reserve -> one commit output C_j per Winternitz batch
//!   commit[k]            C_j inputs through their commit leaves -> connector D_k
//!   assert_final         KA + every D_k -> A, P2TR(NUMS; {432 BitVM disprove leaves |
//!                        18 binding leaves | payout: T_disprove CSV, committee CHECKSIG})
//!   payout_asserted      A (payout leaf) + KB + every escrow -> template outputs + the bond back
//!   disprove             KB (committee SIGHASH_SINGLE: output 0 burns BURN) + A through one
//!                        disprove or binding leaf -> burn + the rest to whoever posts it
//!   timeout              KB (committee SIGHASH_SINGLE: output 0 burns BURN) + KA (committee
//!                        SIGHASH_NONE, nSequence T_assert) -> burn + the rest to whoever posts it
//!   refund[b]            escrow[b] through its refund leaf after T_refund
//!
//! The committee is one demo key standing in for BitVM2's n-of-n presigning committee (a MuSig2
//! aggregate key spends the same way on chain). It signs everything above that spends a
//! committee output before the kickoff, and is assumed to sign nothing else. Relative
//! timelocks on committee key-path inputs are nSequence values its signatures commit to, which
//! BIP68 enforces.
//!
//! Why two connectors: a challenge's txid is unknown in advance (the challenger adds inputs),
//! so no presigned transaction can spend a challenge output. The challenge therefore only
//! consumes KC, which payout_unchallenged needs. KA is consumed only by assert_final,
//! payout_unchallenged or timeout, so a challenged operator must have A confirmed within
//! T_assert of the kickoff, however much of the assert chain it posted, or anyone can slash.
//!
//! M9 (`Graph::Anchored`) keeps every presigned fee at the presigned rate and adds a way to raise it:
//! - both payouts are TRUC (version 3); the operator's back output is the CPFP handle, and
//!   TRUC's one-child rule with sibling eviction bounds what a payee can pin;
//! - the kickoff, assert_init, every commit and assert_final get an anchor output keyed to the
//!   operator, ANCHOR sats, which only the operator can spend into a CPFP child;
//! - the challenge pays the operator the assert chain's cost at `max_fee_rate()`, children included.

use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, Secp256k1, TapTweak};
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CLTV, OP_CSV, OP_DROP, OP_RETURN};
use bitcoin::script::Builder;
use bitcoin::secp256k1::{All, Message, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TapNodeHash};
use bitcoin::transaction::Version;
use bitcoin::{absolute::LockTime, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

use crate::taproot::{key_path_script, keypair, leaf_hash, xonly, ScriptTree};

/// Fee rates are in sat/kvB throughout, so a graph can presign below 1 sat/vB (M16 runs at
/// testnet4's relay floor of 100 sat/kvB).
///
/// The presigned fee rate: 2,000 sat/kvB (2 sat/vB) unless ZKC_PRESIGN_SAT_PER_KVB says otherwise.
pub fn presign_rate() -> u64 {
    env_u64("ZKC_PRESIGN_SAT_PER_KVB", 2_000)
}

/// The highest market fee rate the anchored graph is built to settle at: 10,000 sat/kvB unless
/// ZKC_MAX_SAT_PER_KVB says otherwise. The challenge pays the operator the assert chain's cost at
/// this rate, CPFP children included.
pub fn max_fee_rate() -> u64 {
    env_u64("ZKC_MAX_SAT_PER_KVB", 10_000)
}

/// The bond output before the kickoff (ZKC_BOND_SATS, default 0.1 BTC); KB carries it less the
/// connectors and the kickoff fee.
pub fn bond_sats() -> u64 {
    env_u64("ZKC_BOND_SATS", 10_000_000)
}

/// Burned by every slash, disprove or timeout (ZKC_BURN_SATS, default half the default bond);
/// the poster takes what is left of KB.
pub fn burn_sats() -> u64 {
    env_u64("ZKC_BURN_SATS", 5_000_000)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).map(|v| v.parse().unwrap_or_else(|_| panic!("{name} must be an integer"))).unwrap_or(default)
}

pub const CONNECTOR: u64 = 330;
/// Value of each operator-keyed anchor output (the P2TR dust limit).
pub const ANCHOR: u64 = 330;

/// Which graph to build.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Graph {
    /// M2 as run: version 2 payouts, no anchors; the challenge pays the assert chain at the presigned rate.
    M2,
    /// M9: TRUC payouts and operator-keyed anchors (module docs).
    Anchored,
}

impl Graph {
    pub fn anchored(self) -> bool {
        self == Graph::Anchored
    }

    pub fn payout_version(self) -> Version {
        if self.anchored() {
            Version(3)
        } else {
            Version::TWO
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Graph::M2 => "m2",
            Graph::Anchored => "anchored",
        }
    }
}

/// The graph's clocks, derived from two measured chain parameters (TIMING.md):
///
/// - `gap` G: the most blocks in a row that may include none of our transactions, so a
///   transaction posted at tip t is mined by block t + W with W = G + 1 (one inclusion step);
/// - `reorg` R: the deepest reorganization to survive. A transaction first mined at block x may
///   be mined again as late as x + R, so each window needs W per sequential step plus R.
///
/// A window that ends at block D (a competing transaction becomes valid in D) has D - 1 as its
/// last safe block. `disprove_gap` is G for the disprove, which is non-standard and so needs a
/// miner that accepts it (M12); it equals G unless set.
///
/// T_KICKOFF is policy: the operator kicks off within `t_kickoff` blocks of the escrows'
/// confirmation. The rest are relative locktimes that consensus enforces (BIP68: at most 65,535).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Timing {
    /// Display name: "regtest", "testnet4" or "custom".
    pub profile: String,
    /// Suffix of the results directory: empty for the default regtest profile.
    pub tag: String,
    pub gap: u32,
    pub reorg: u32,
    pub disprove_gap: u32,
    /// The operator kicks off within this many blocks of the escrows' confirmation.
    pub t_kickoff: u16,
    /// payout_unchallenged spends KC no earlier than this many blocks after the kickoff.
    pub t_challenge: u16,
    /// timeout spends KA no earlier than this many blocks after the kickoff.
    pub t_assert: u16,
    /// payout_asserted spends A no earlier than this many blocks after assert_final.
    pub t_disprove: u16,
    /// A buyer's refund leaf opens this many blocks after its escrow confirms (unbound graphs).
    pub t_refund: u16,
    /// The assert chain needs three blocks in sequence: assert_init, the commits (only one fits
    /// in the mempool beside an unconfirmed assert_init; the challenged scenario probes it), then
    /// assert_final.
    pub assert_blocks: u16,
    /// Bound graphs (M13): the deadline connector opens to anyone after batchHeight + this, so
    /// the kickoff has to confirm in blocks batchHeight + 1 to batchHeight + deadline_after_batch.
    /// The batch proof holds every order expiry to at least batchHeight + this
    /// (signed_terms.circom's DEADLINE_AFTER_BATCH), which only the circuit enforces for sellers.
    pub deadline_after_batch: u64,
    /// Bound graphs: the batch proof holds every escrowExpiry to at least batchHeight + this
    /// (signed_terms.circom's ESCROW_AFTER_BATCH), and each escrow refunds through CLTV at the
    /// expiry its buyer signed. The smallest that leaves the latest payout W + R blocks.
    pub escrow_after_batch: u64,
}

/// The assert chain's sequential steps.
pub const ASSERT_BLOCKS: u16 = 3;

/// One timing constraint: the blocks a window has, and the blocks its worst case needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Constraint {
    pub name: &'static str,
    pub available: i64,
    pub required: i64,
}

impl Constraint {
    pub fn slack(&self) -> i64 {
        self.available - self.required
    }
}

/// The circuit constants of signed_terms.circom, which are the regtest profile's. A deployment
/// on a profile with larger values has to recompile the circuit (TIMING.md section 6).
pub const CIRCUIT_DEADLINE_AFTER_BATCH: u64 = 4;
pub const CIRCUIT_ESCROW_AFTER_BATCH: u64 = 22;

impl Timing {
    /// The regtest profile: the numbers M2 to M17 ran with. They dominate `from_chain(0, 1)`.
    pub fn regtest() -> Timing {
        Timing {
            profile: "regtest".into(),
            tag: String::new(),
            gap: 0,
            reorg: 1,
            disprove_gap: 0,
            t_kickoff: 6,
            t_challenge: 6,
            t_assert: 12,
            t_disprove: 6,
            t_refund: 30,
            assert_blocks: ASSERT_BLOCKS,
            deadline_after_batch: CIRCUIT_DEADLINE_AFTER_BATCH,
            escrow_after_batch: CIRCUIT_ESCROW_AFTER_BATCH,
        }
    }

    /// The smallest clocks that satisfy every constraint for gap `gap` and reorg depth `reorg`;
    /// `disprove_gap` sizes the disprove window (None: `gap`). Errors if a clock exceeds BIP68's
    /// 65,535 blocks.
    pub fn from_chain(gap: u32, reorg: u32, disprove_gap: Option<u32>) -> Result<Timing, String> {
        let gd = disprove_gap.unwrap_or(gap);
        let (w, wd, r) = (u64::from(gap) + 1, u64::from(gd) + 1, u64::from(reorg));
        let m = w + r;
        let t_challenge = m + 1;
        let t_assert = t_challenge + u64::from(ASSERT_BLOCKS) * w + r;
        let t_disprove = wd + r + 1;
        let deadline = m;
        let t_kickoff = m;
        let escrow = deadline + (t_assert - 1) + t_disprove + m - 1;
        let t_refund = t_kickoff + (t_assert - 1) + t_disprove + m;
        let fit = |name: &str, v: u64| u16::try_from(v).ok().filter(|v| *v <= 65_535).ok_or_else(|| format!("{name} = {v} blocks exceeds BIP68's 65,535"));
        let tag = format!("g{gap}r{reorg}{}", disprove_gap.map(|d| format!("d{d}")).unwrap_or_default());
        Ok(Timing {
            profile: "custom".into(),
            tag,
            gap,
            reorg,
            disprove_gap: gd,
            t_kickoff: fit("T_KICKOFF", t_kickoff)?,
            t_challenge: fit("T_CHALLENGE", t_challenge)?,
            t_assert: fit("T_ASSERT", t_assert)?,
            t_disprove: fit("T_DISPROVE", t_disprove)?,
            t_refund: fit("T_REFUND", t_refund)?,
            assert_blocks: ASSERT_BLOCKS,
            deadline_after_batch: deadline,
            escrow_after_batch: escrow,
        })
    }

    /// A named profile: "regtest" or "testnet4" (G = 90, R = 16, from the testnet4 record in
    /// TIMING.md).
    pub fn named(name: &str) -> Result<Timing, String> {
        match name {
            "regtest" => Ok(Timing::regtest()),
            "testnet4" => Timing::from_chain(90, 16, None).map(|t| Timing { profile: "testnet4".into(), tag: "testnet4".into(), ..t }),
            other => Err(format!("ZKC_TIMING must be regtest or testnet4, not {other}")),
        }
    }

    /// The profile a run uses: ZKC_INCLUSION_GAP and ZKC_REORG_DEPTH together (and optionally
    /// ZKC_DISPROVE_GAP) name a custom one; else ZKC_TIMING=regtest|testnet4; else regtest.
    pub fn from_env() -> Timing {
        let var = |name: &str| std::env::var(name).ok().map(|v| v.parse::<u32>().unwrap_or_else(|_| panic!("{name} must be an integer")));
        let t = match (var("ZKC_INCLUSION_GAP"), var("ZKC_REORG_DEPTH")) {
            (Some(g), Some(r)) => Timing::from_chain(g, r, var("ZKC_DISPROVE_GAP")),
            (None, None) => Timing::named(std::env::var("ZKC_TIMING").as_deref().unwrap_or("regtest")),
            _ => Err("ZKC_INCLUSION_GAP and ZKC_REORG_DEPTH must be set together".into()),
        };
        let t = t.unwrap_or_else(|e| panic!("{e}"));
        t.check().unwrap_or_else(|e| panic!("{e}"));
        t
    }

    /// W = G + 1: blocks one inclusion step takes in the worst case.
    pub fn step(&self) -> i64 {
        i64::from(self.gap) + 1
    }

    /// W + R, the least any window can have: one inclusion step and a reorg. It generalises the
    /// regtest MARGIN of 2.
    pub fn margin(&self) -> i64 {
        self.step() + i64::from(self.reorg)
    }

    /// Every constraint with the blocks its window has and the blocks the worst case needs.
    pub fn constraints(&self) -> Vec<Constraint> {
        let (k, c, a, d, r) = (i64::from(self.t_kickoff), i64::from(self.t_challenge), i64::from(self.t_assert), i64::from(self.t_disprove), i64::from(self.t_refund));
        let (w, wd, rd, m) = (self.step(), i64::from(self.disprove_gap) + 1, i64::from(self.reorg), self.margin());
        let (dl, esc) = (self.deadline_after_batch as i64, self.escrow_after_batch as i64);
        let steps = i64::from(self.assert_blocks);
        let at = |name, available, required| Constraint { name, available, required };
        vec![
            // The kickoff is mined at h_k; a watcher posts its challenge then. It is mined by
            // h_k + W, can be mined again by h_k + W + R, and must be in by h_k + c - 1.
            at("challenge: blocks to get a challenge mined after the kickoff", c - 1, m),
            // Unchallenged: posted when the payout opens (tip h_k + c - 1), mined by h_k + c - 1 + W,
            // again by + R; only the payout can spend KB from h_k + c until the timeout at h_k + a.
            at("unchallenged payout: blocks before the timeout opens", a - c, m),
            // Challenged in the last block, h_k + c - 1: the three steps land by h_k + c - 1 + 3W,
            // assert_final again by + R, and the timeout opens at h_k + a.
            at("assert: blocks for the chain after a last-block challenge", a - c, steps * w + rd),
            // A is mined at h_a; a disprove is posted then, mined by h_a + W_d, again by + R, and
            // must be in by h_a + d - 1 (payout_asserted opens at h_a + d).
            at("disprove: blocks to get a disprove mined after A", d - 1, wd + rd),
            // The latest payout_asserted is valid from h_e + k + (a - 1) + d, mined by W - 1
            // blocks after that, again by + R; refunds open at h_e + r.
            at("refund: blocks the latest payout has before refunds open", r - (k + a - 1 + d), m),
            // Bound: the latest kickoff is at batchHeight + deadline, its payout_asserted valid
            // (a - 1) + d blocks later; the earliest refund enters the block after
            // batchHeight + ESCROW_AFTER_BATCH.
            at("bound refund: blocks the latest payout has before the earliest signed expiry opens", esc + 1 - (dl + a - 1 + d), m),
            // The operator posts the kickoff at batchHeight (bound), or when the escrows confirm
            // (unbound, policy).
            at("kickoff: blocks to get the kickoff mined after batchHeight", dl, m),
            at("kickoff policy: blocks after the escrows confirm", k, m),
        ]
    }

    /// Blocks to spare at each constraint (available minus required), by the constraint's name.
    pub fn slack(&self) -> Vec<(&'static str, i64)> {
        self.constraints().iter().map(|c| (c.name, c.slack())).collect()
    }

    /// Ok if every clock fits BIP68 and every constraint has what it needs.
    pub fn check(&self) -> Result<(), String> {
        for (name, v) in [("T_KICKOFF", self.t_kickoff), ("T_CHALLENGE", self.t_challenge), ("T_ASSERT", self.t_assert), ("T_DISPROVE", self.t_disprove), ("T_REFUND", self.t_refund)] {
            if v == 0 {
                return Err(format!("{name} = 0: BIP68 allows 1 to 65,535 blocks"));
            }
        }
        for c in self.constraints() {
            if c.required < self.margin() || c.available < c.required {
                return Err(format!("{}: {} blocks, {} needed (profile {}, W + R = {})", c.name, c.available, c.required, self.profile, self.margin()));
            }
        }
        Ok(())
    }

    /// The escrow expiry the driver has buyers sign, in blocks after batchHeight: the profile's
    /// bound, or where the refunds open in the block the unbound graph's CSV refunds do
    /// (h_e + T_REFUND, batchHeight = h_e + `batch_after_funding`), whichever is later.
    pub fn signed_escrow_after_batch(&self, batch_after_funding: u64) -> u64 {
        self.escrow_after_batch.max(u64::from(self.t_refund) - 1 - batch_after_funding)
    }

    /// Whether signed_terms.circom's compiled constants cover this profile: (orders hold until
    /// the latest kickoff, escrows until the latest payout).
    pub fn circuit_covers(&self) -> (bool, bool) {
        (CIRCUIT_DEADLINE_AFTER_BATCH >= self.deadline_after_batch, CIRCUIT_ESCROW_AFTER_BATCH >= self.escrow_after_batch)
    }

    /// The profile for result files.
    pub fn json(&self) -> serde_json::Value {
        let (orders, escrows) = self.circuit_covers();
        serde_json::json!({
            "profile": self.profile, "inclusion_gap_blocks": self.gap, "reorg_depth_blocks": self.reorg, "disprove_gap_blocks": self.disprove_gap,
            "step_blocks": self.step(), "margin": self.margin(),
            "t_kickoff": self.t_kickoff, "t_challenge": self.t_challenge, "t_assert": self.t_assert, "t_disprove": self.t_disprove, "t_refund": self.t_refund,
            "assert_blocks": self.assert_blocks, "deadline_after_batch": self.deadline_after_batch, "escrow_after_batch": self.escrow_after_batch,
            "circuit": {"deadline_after_batch": CIRCUIT_DEADLINE_AFTER_BATCH, "escrow_after_batch": CIRCUIT_ESCROW_AFTER_BATCH,
                "orders_covered": orders, "escrows_covered": escrows},
            "constraints": self.constraints().iter().map(|c| serde_json::json!({"constraint": c.name, "available": c.available, "required": c.required, "slack": c.slack()})).collect::<Vec<_>>(),
        })
    }
}

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

    pub fn committee_script(&self) -> ScriptBuf {
        key_path_script(&self.secp, "committee")
    }

    pub fn operator_script(&self) -> ScriptBuf {
        key_path_script(&self.secp, "operator")
    }

    /// The operator's anchor key: only the operator can spend an anchor into a CPFP child.
    pub fn anchor_keypair(&self) -> Keypair {
        keypair(&self.secp, "operator-anchor")
    }

    pub fn anchor_script(&self) -> ScriptBuf {
        key_path_script(&self.secp, "operator-anchor")
    }
}

pub const RBF: Sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;

pub fn csv_checksig(blocks: u16, key: &XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_int(i64::from(blocks))
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_x_only_key(key)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// `<height> OP_CLTV OP_DROP <key> OP_CHECKSIG`: spendable by `key` from block `height + 1`.
pub fn cltv_checksig(height: u32, key: &XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_int(i64::from(height))
        .push_opcode(OP_CLTV)
        .push_opcode(OP_DROP)
        .push_x_only_key(key)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// The burn output's script: a bare OP_RETURN, unspendable.
pub fn burn_script() -> ScriptBuf {
    Builder::new().push_opcode(OP_RETURN).into_script()
}

pub fn tx(inputs: Vec<(OutPoint, Sequence)>, outputs: Vec<TxOut>) -> Transaction {
    tx_version(Version::TWO, inputs, outputs)
}

pub fn tx_version(version: Version, inputs: Vec<(OutPoint, Sequence)>, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version,
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

/// The presigned fee of `tx`.
pub fn fee_for(tx: &Transaction) -> u64 {
    fee_at(tx, presign_rate())
}

/// The fee of `tx` at `rate` sat/kvB, rounded up.
pub fn fee_at(tx: &Transaction, rate: u64) -> u64 {
    fee_of(tx.vsize() as u64, rate)
}

/// The fee of `vsize` vbytes at `rate` sat/kvB, rounded up.
pub fn fee_of(vsize: u64, rate: u64) -> u64 {
    (vsize * rate).div_ceil(1000)
}

fn schnorr(keys: &Keys, signer: &Keypair, sighash: [u8; 32], sighash_type: TapSighashType) -> Vec<u8> {
    let signature = keys.secp.sign_schnorr_no_aux_rand(&Message::from_digest(sighash), signer);
    bitcoin::taproot::Signature { signature, sighash_type }.to_vec()
}

/// Key-path signature for input `index`. `merkle_root` is the output's script tree, if any.
pub fn sign_key_path(keys: &Keys, signer: &Keypair, tx: &Transaction, prevouts: &Prevouts<TxOut>, index: usize, ty: TapSighashType, merkle_root: Option<TapNodeHash>) -> Vec<u8> {
    let sighash = SighashCache::new(tx).taproot_key_spend_signature_hash(index, prevouts, ty).expect("sighash");
    let tweaked = signer.tap_tweak(&keys.secp, merkle_root).to_keypair();
    schnorr(keys, &tweaked, sighash.to_byte_array(), ty)
}

/// Schnorr signature (SIGHASH_DEFAULT) for a script-path spend of input `index`.
pub fn sign_script_path(keys: &Keys, signer: &Keypair, tx: &Transaction, prevouts: &[TxOut], index: usize, leaf: &ScriptBuf) -> Vec<u8> {
    let leaf_hash = TapLeafHash::from_script(leaf, LeafVersion::TapScript);
    let sighash = SighashCache::new(tx)
        .taproot_script_spend_signature_hash(index, &Prevouts::All(prevouts), leaf_hash, TapSighashType::Default)
        .expect("sighash");
    schnorr(keys, signer, sighash.to_byte_array(), TapSighashType::Default)
}

/// Witness for a script-path spend: stack items, then the leaf and its control block.
pub fn script_path_witness(items: Vec<Vec<u8>>, leaf: &ScriptBuf, tree: &ScriptTree, index: usize, keys: &Keys) -> Witness {
    let control = tree.checked_control_block(&keys.secp, index, leaf);
    let mut all = items;
    all.push(leaf.to_bytes());
    all.push(control.serialize());
    Witness::from_slice(&all)
}

/// An output and what it holds.
#[derive(Clone)]
pub struct Utxo {
    pub outpoint: OutPoint,
    pub txout: TxOut,
}

impl Utxo {
    pub fn of(t: &Transaction, vout: usize) -> Utxo {
        Utxo { outpoint: OutPoint { txid: t.compute_txid(), vout: vout as u32 }, txout: t.output[vout].clone() }
    }

    pub fn sats(&self) -> u64 {
        self.txout.value.to_sat()
    }
}

/// Escrow output for one buyer: the committee's key path pays out, the buyer's leaf refunds.
/// The refund opens `t_refund` blocks after funding (CSV), or with `expiry` (M13) after an
/// absolute height: the escrow expiry the buyer signed, enforced by CLTV.
pub struct Escrow {
    pub buyer: String,
    pub refund_leaf: ScriptBuf,
    pub expiry: Option<u32>,
    /// The CSV refund delay of an unbound escrow (the profile's T_REFUND).
    pub t_refund: u16,
    pub tree: ScriptTree,
    pub utxo: Utxo,
}

impl Escrow {
    pub fn new(keys: &Keys, buyer: &str, expiry: Option<u32>, t_refund: u16) -> Escrow {
        let key = xonly(&keys.secp, &format!("buyer:{buyer}"));
        let refund_leaf = match expiry {
            Some(height) => cltv_checksig(height, &key),
            None => csv_checksig(t_refund, &key),
        };
        let tree = ScriptTree::with_internal_key(&keys.secp, keys.x(&keys.committee), vec![leaf_hash(&refund_leaf)]);
        Escrow { buyer: buyer.to_string(), refund_leaf, expiry, t_refund, tree, utxo: Utxo { outpoint: OutPoint::null(), txout: txout(0, ScriptBuf::new()) } }
    }
}

/// The buyer's refund after `t_refund` or the escrow's expiry, paying `to` (the buyer's refund
/// payee). The buyer signs it when posting, at the market fee `rate`.
pub fn refund_tx(keys: &Keys, escrow: &Escrow, to: ScriptBuf, rate: u64) -> Transaction {
    let buyer = keypair(&keys.secp, &format!("buyer:{}", escrow.buyer));
    let build = |value: u64| {
        let mut t = match escrow.expiry {
            Some(height) => {
                let mut t = tx(vec![(escrow.utxo.outpoint, RBF)], vec![txout(value, to.clone())]);
                t.lock_time = LockTime::from_height(height).expect("block height lock time");
                t
            }
            None => tx(vec![(escrow.utxo.outpoint, Sequence::from_height(escrow.t_refund))], vec![txout(value, to.clone())]),
        };
        let sig = sign_script_path(keys, &buyer, &t, &[escrow.utxo.txout.clone()], 0, &escrow.refund_leaf);
        t.input[0].witness = script_path_witness(vec![sig], &escrow.refund_leaf, &escrow.tree, 0, keys);
        t
    };
    let draft = build(escrow.utxo.sats());
    build(escrow.utxo.sats() - fee_at(&draft, rate))
}

/// M13's deadline connector: an output the kickoff must spend (operator key path), which anyone
/// may spend after `height` through the leaf `<height> OP_CLTV`. Once someone has, the kickoff
/// can no longer confirm, so the graph has to start by `height`. Whoever sweeps it keeps its
/// value, which is what pays miners and watchers to do so.
pub struct Deadline {
    pub height: u32,
    pub leaf: ScriptBuf,
    pub tree: ScriptTree,
    pub utxo: Utxo,
}

impl Deadline {
    pub fn new(keys: &Keys, height: u32) -> Deadline {
        let leaf = Builder::new().push_int(i64::from(height)).push_opcode(OP_CLTV).into_script();
        let tree = ScriptTree::with_internal_key(&keys.secp, keys.x(&keys.operator), vec![leaf_hash(&leaf)]);
        Deadline { height, leaf, tree, utxo: Utxo { outpoint: OutPoint::null(), txout: txout(0, ScriptBuf::new()) } }
    }
}

/// Anyone's sweep of a deadline connector after its height, paying `to` at the fee `rate`.
pub fn sweep_deadline_tx(keys: &Keys, deadline: &Deadline, to: ScriptBuf, rate: u64) -> Transaction {
    let build = |value: u64| {
        let mut t = tx(vec![(deadline.utxo.outpoint, RBF)], vec![txout(value, to.clone())]);
        t.lock_time = LockTime::from_height(deadline.height).expect("block height lock time");
        t.input[0].witness = script_path_witness(vec![], &deadline.leaf, &deadline.tree, 0, keys);
        t
    };
    let draft = build(deadline.utxo.sats());
    build(deadline.utxo.sats() - fee_at(&draft, rate))
}

/// The operator's kickoff: bond -> KC, KA, KB, and in the anchored graph an operator-keyed
/// anchor. Its txid is fixed before the committee presigns, so its fee is fixed too.
/// M13: a nonzero `lock_time` (the statement's batchHeight) keeps it, and so the whole graph,
/// out of every block up to that height, and spending a `deadline` connector keeps it out of
/// every block after someone has swept the connector.
pub struct Kickoff {
    pub tx: Transaction,
    pub kc: Utxo,
    pub ka: Utxo,
    pub kb: Utxo,
    pub anchor: Option<Utxo>,
}

pub fn kickoff_tx(keys: &Keys, bond: &Utxo, graph: Graph, rate: u64, lock_time: LockTime, deadline: Option<&Deadline>) -> Kickoff {
    let committee = keys.committee_script();
    let anchor = if graph.anchored() { ANCHOR } else { 0 };
    let mut inputs = vec![bond.clone()];
    inputs.extend(deadline.map(|d| d.utxo.clone()));
    let prevouts: Vec<TxOut> = inputs.iter().map(|u| u.txout.clone()).collect();
    let total: u64 = inputs.iter().map(Utxo::sats).sum();
    let build = |kb_value: u64| {
        let mut outs = vec![txout(CONNECTOR, committee.clone()), txout(CONNECTOR, committee.clone()), txout(kb_value, committee.clone())];
        if graph.anchored() {
            outs.push(txout(ANCHOR, keys.anchor_script()));
        }
        let mut t = tx(inputs.iter().map(|u| (u.outpoint, RBF)).collect(), outs);
        t.lock_time = lock_time;
        let sigs: Vec<Vec<u8>> = (0..inputs.len())
            .map(|i| {
                let root = if i == 0 { None } else { Some(deadline.unwrap().tree.merkle_root()) };
                sign_key_path(keys, &keys.operator, &t, &Prevouts::All(&prevouts), i, TapSighashType::Default, root)
            })
            .collect();
        for (input, sig) in t.input.iter_mut().zip(sigs) {
            input.witness = Witness::from_slice(&[sig]);
        }
        t
    };
    let draft = build(total - 2 * CONNECTOR - anchor);
    let t = build(total - 2 * CONNECTOR - anchor - fee_at(&draft, rate));
    Kickoff { kc: Utxo::of(&t, 0), ka: Utxo::of(&t, 1), kb: Utxo::of(&t, 2), anchor: graph.anchored().then(|| Utxo::of(&t, 3)), tx: t }
}

/// A CPFP child for a presigned `parent` whose fee is `parent_fee`: it spends `handle`, an
/// output of the parent (key path of `handle_signer`), and the payer's confirmed `coin`, and
/// pays the rest to `change_to`. Parent and child together pay `rate`, and the child pays at
/// least `min_fee` (to outbid a sibling under TRUC). The child takes the parent's version.
#[allow(clippy::too_many_arguments)]
pub fn bump_child(
    keys: &Keys,
    parent: &Transaction,
    parent_fee: u64,
    handle: &Utxo,
    handle_signer: &Keypair,
    coin: &Utxo,
    coin_signer: &Keypair,
    rate: u64,
    min_fee: u64,
    change_to: ScriptBuf,
) -> Transaction {
    let prevouts = [handle.txout.clone(), coin.txout.clone()];
    let total = handle.sats() + coin.sats();
    let build = |change: u64| {
        let mut t = tx_version(parent.version, vec![(handle.outpoint, RBF), (coin.outpoint, RBF)], vec![txout(change, change_to.clone())]);
        let sigs: Vec<Vec<u8>> = [handle_signer, coin_signer]
            .iter()
            .enumerate()
            .map(|(i, signer)| sign_key_path(keys, signer, &t, &Prevouts::All(&prevouts), i, TapSighashType::Default, None))
            .collect();
        for (input, sig) in t.input.iter_mut().zip(sigs) {
            input.witness = Witness::from_slice(&[sig]);
        }
        t
    };
    let draft = build(total);
    let package = fee_of((parent.vsize() + draft.vsize()) as u64, rate);
    let fee = package.saturating_sub(parent_fee).max(fee_at(&draft, rate)).max(min_fee);
    assert!(fee + 330 <= total, "bump coin too small: fee {fee}, coin and handle {total}");
    build(total - fee)
}

/// vbytes of a bump child (two key-path inputs, one P2TR output); signatures are fixed size.
pub fn bump_child_vsize(keys: &Keys) -> u64 {
    let placeholder = |vout: u32, label: &str| Utxo { outpoint: OutPoint { txid: Txid::all_zeros(), vout }, txout: txout(1_000_000, key_path_script(&keys.secp, label)) };
    let parent = tx(vec![], vec![]);
    let t = bump_child(keys, &parent, 0, &placeholder(0, "operator-anchor"), &keys.anchor_keypair(), &placeholder(1, "operator"), &keys.operator, 1, 0, keys.operator_script());
    t.vsize() as u64
}

/// How the committee spends one input of a payout.
pub enum Spend<'a> {
    /// Key path of an output whose script tree has this root (None: no tree).
    KeyPath(Option<TapNodeHash>),
    /// Script path through `leaf`, leaf `index` of `tree`.
    Leaf { leaf: &'a ScriptBuf, tree: &'a ScriptTree, index: usize },
}

pub struct PayoutInput<'a> {
    pub utxo: Utxo,
    pub sequence: Sequence,
    pub spend: Spend<'a>,
}

/// A payout signed by the committee on every input (SIGHASH_DEFAULT): the template's outputs,
/// then whatever the inputs hold beyond them, less the fee, back to the operator. In the
/// anchored graph it is TRUC (version 3), and the back output is the operator's CPFP handle.
pub fn committee_payout(keys: &Keys, inputs: &[PayoutInput], outputs: Vec<TxOut>, graph: Graph) -> Transaction {
    let prevouts: Vec<TxOut> = inputs.iter().map(|i| i.utxo.txout.clone()).collect();
    let back_total = prevouts.iter().map(|o| o.value.to_sat()).sum::<u64>() - outputs.iter().map(|o| o.value.to_sat()).sum::<u64>();
    let operator_back = keys.operator_script();
    let build = |back: u64| {
        let mut outs = outputs.clone();
        outs.push(txout(back, operator_back.clone()));
        let mut t = tx_version(graph.payout_version(), inputs.iter().map(|i| (i.utxo.outpoint, i.sequence)).collect(), outs);
        let witnesses: Vec<Witness> = inputs
            .iter()
            .enumerate()
            .map(|(n, i)| match &i.spend {
                Spend::KeyPath(root) => Witness::from_slice(&[sign_key_path(keys, &keys.committee, &t, &Prevouts::All(&prevouts), n, TapSighashType::Default, *root)]),
                Spend::Leaf { leaf, tree, index } => {
                    let sig = sign_script_path(keys, &keys.committee, &t, &prevouts, n, leaf);
                    script_path_witness(vec![sig], leaf, tree, *index, keys)
                }
            })
            .collect();
        for (input, w) in t.input.iter_mut().zip(witnesses) {
            input.witness = w;
        }
        t
    };
    let draft = build(back_total);
    build(back_total - fee_for(&draft))
}

/// The committee's SIGHASH_SINGLE|ANYONECANPAY signature on KC: it commits to KC and to output
/// 0 paying the operator `amount`, and to nothing the challenger adds.
pub fn challenge_signature(keys: &Keys, kc: &Utxo, amount: u64) -> Vec<u8> {
    let skeleton = tx(vec![(kc.outpoint, RBF)], vec![txout(amount, keys.operator_script())]);
    sign_key_path(keys, &keys.committee, &skeleton, &Prevouts::One(0, kc.txout.clone()), 0, TapSighashType::SinglePlusAnyoneCanPay, None)
}

/// A challenge as anyone builds it: KC with the committee's presigned signature, plus the
/// challenger's own coin (key path of `funder`), with change back to the challenger, at the
/// market fee `rate`.
#[allow(clippy::too_many_arguments)]
pub fn challenge_tx(keys: &Keys, kc: &Utxo, committee_sig: &[u8], amount: u64, coin: &Utxo, funder: &Keypair, change_to: ScriptBuf, rate: u64) -> Transaction {
    let prevouts = vec![kc.txout.clone(), coin.txout.clone()];
    let build = |change: u64| {
        let mut t = tx(vec![(kc.outpoint, RBF), (coin.outpoint, RBF)], vec![txout(amount, keys.operator_script()), txout(change, change_to.clone())]);
        let sig = sign_key_path(keys, funder, &t, &Prevouts::All(&prevouts), 1, TapSighashType::Default, None);
        t.input[0].witness = Witness::from_slice(&[committee_sig.to_vec()]);
        t.input[1].witness = Witness::from_slice(&[sig]);
        t
    };
    let total = kc.sats() + coin.sats() - amount;
    let draft = build(total);
    build(total - fee_at(&draft, rate))
}

/// Inputs of a slash, in order: KB first, so that the committee's SIGHASH_SINGLE signature on
/// it fixes output 0, the burn.
fn slash_inputs(kb: &Utxo, other: &Utxo, other_sequence: Sequence) -> Vec<(OutPoint, Sequence)> {
    vec![(kb.outpoint, RBF), (other.outpoint, other_sequence)]
}

/// The committee's signatures for a slash spending KB together with `other`: SIGHASH_SINGLE on
/// KB (all inputs, output 0 = burn of BURN) and, if `other` is a committee key-path output,
/// SIGHASH_NONE on it (all inputs, no outputs). Output 1 onwards is left to the poster.
pub fn slash_signatures(keys: &Keys, kb: &Utxo, other: &Utxo, other_sequence: Sequence, sign_other: bool) -> (Vec<u8>, Option<Vec<u8>>) {
    let skeleton = tx(slash_inputs(kb, other, other_sequence), vec![txout(burn_sats(), burn_script())]);
    let prevouts = [kb.txout.clone(), other.txout.clone()];
    let kb_sig = sign_key_path(keys, &keys.committee, &skeleton, &Prevouts::All(&prevouts), 0, TapSighashType::Single, None);
    let other_sig = sign_other.then(|| sign_key_path(keys, &keys.committee, &skeleton, &Prevouts::All(&prevouts), 1, TapSighashType::None, None));
    (kb_sig, other_sig)
}

/// A slash as its poster completes it: output 0 burns BURN, output 1 takes the rest less the fee.
/// The poster pays the market `rate`, and at least `min_fee` (to replace what it conflicts with).
#[allow(clippy::too_many_arguments)]
pub fn slash_tx(kb: &Utxo, kb_sig: &[u8], other: &Utxo, other_sequence: Sequence, other_witness: Witness, reward_to: ScriptBuf, rate: u64, min_fee: u64) -> Transaction {
    let build = |reward: u64| {
        let mut t = tx(slash_inputs(kb, other, other_sequence), vec![txout(burn_sats(), burn_script()), txout(reward, reward_to.clone())]);
        t.input[0].witness = Witness::from_slice(&[kb_sig.to_vec()]);
        t.input[1].witness = other_witness.clone();
        t
    };
    let total = kb.sats() + other.sats() - burn_sats();
    let draft = build(total);
    build(total - fee_at(&draft, rate).max(min_fee))
}

/// Winternitz batches, their commit leaves and witness items (without the operator's
/// Schnorr signature), for sizing or for posting.
pub struct CommitPlan<'a> {
    pub batches: &'a [Vec<usize>],
    pub leaves: &'a [ScriptBuf],
    pub trees: &'a [ScriptTree],
    pub items: &'a [Vec<Vec<u8>>],
}

/// Weight budget per commit transaction; Core's standardness limit is 400,000 WU.
pub const COMMIT_TX_WEIGHT: u64 = 390_000;

fn commit_input_weight(plan: &CommitPlan, batch: usize) -> u64 {
    let items: u64 = plan.items[batch].iter().map(|i| i.len() as u64 + 3).sum();
    let witness = items + 66 + plan.leaves[batch].len() as u64 + 5 + 33 + 32 * plan.trees[batch].depth() as u64 + 3;
    41 * 4 + witness
}

fn sign_commit(keys: &Keys, t: &mut Transaction, group: &[usize], prevouts: &[TxOut], plan: &CommitPlan) {
    for (i, b) in group.iter().enumerate() {
        let sig = sign_script_path(keys, &keys.operator, t, prevouts, i, &plan.leaves[*b]);
        let mut items = vec![sig];
        items.extend(plan.items[*b].iter().cloned());
        t.input[i].witness = script_path_witness(items, &plan.leaves[*b], &plan.trees[*b], 0, keys);
    }
}

/// The assert chain's shape and cost, fixed before any assertion exists. `plan` holds the
/// largest witness an assertion can have, so every real assertion fits the fees set here.
pub struct CommitLayout {
    pub groups: Vec<Vec<usize>>,
    pub commit_fees: Vec<u64>,
    /// Value of each commit output C_j: its share of its commit transaction's fee plus D_k
    /// (and the commit's anchor, when anchored).
    pub c_values: Vec<u64>,
    pub init_fee: u64,
    /// vbytes of assert_init and of each commit, sized with the largest witness.
    pub init_vsize: u64,
    pub commit_vsizes: Vec<u64>,
    /// vbytes of assert_final, sized with placeholders.
    pub final_vsize: u64,
    pub anchored: bool,
}

impl CommitLayout {
    /// What the operator's reserve must hold: every C_j, assert_init's fee and its anchor.
    pub fn reserve(&self) -> u64 {
        self.c_values.iter().sum::<u64>() + self.init_fee + if self.anchored { ANCHOR } else { 0 }
    }

    /// vbytes and presigned fee of each assert-chain transaction, in posting order.
    pub fn sizes(&self) -> Vec<(u64, u64)> {
        let mut out = vec![(self.init_vsize, self.init_fee)];
        out.extend(self.commit_vsizes.iter().copied().zip(self.commit_fees.iter().copied()));
        out.push((self.final_vsize, fee_of(self.final_vsize, presign_rate())));
        out
    }

    /// What CPFP children cost to carry every assert-chain transaction to `rate` sat/kvB.
    pub fn bump_budget(&self, rate: u64, child_vsize: u64) -> u64 {
        self.sizes().iter().map(|(vsize, fee)| fee_of(vsize + child_vsize, rate).saturating_sub(*fee)).sum()
    }

    /// What a challenge pays the operator: the reserve, and in the anchored graph the children
    /// that carry the chain to `max_fee_rate()`; rounded up to 1,000 sats.
    pub fn challenge_amount(&self, child_vsize: u64) -> u64 {
        let bump = if self.anchored { self.bump_budget(max_fee_rate(), child_vsize) } else { 0 };
        (self.reserve() + bump).div_ceil(1000) * 1000
    }
}

pub fn commit_layout(keys: &Keys, plan: &CommitPlan, graph: Graph) -> CommitLayout {
    let anchored = graph.anchored();
    let anchor = if anchored { ANCHOR } else { 0 };
    // A commit's fixed part: version, counts, locktime and its outputs.
    let base = 4 * 60 + if anchored { 4 * 43 } else { 0 };
    let mut groups: Vec<Vec<usize>> = vec![vec![]];
    let mut weight = base;
    for b in 0..plan.batches.len() {
        let w = commit_input_weight(plan, b);
        if weight + w > COMMIT_TX_WEIGHT && !groups.last().unwrap().is_empty() {
            groups.push(vec![]);
            weight = base;
        }
        groups.last_mut().unwrap().push(b);
        weight += w;
    }
    // Sizes with placeholder outpoints, which do not change the size.
    let mut commit_fees = vec![];
    let mut commit_vsizes = vec![];
    for group in &groups {
        let inputs = group.iter().map(|b| (OutPoint { txid: Txid::all_zeros(), vout: *b as u32 }, RBF)).collect();
        let prevouts: Vec<TxOut> = group.iter().map(|b| txout(100_000, plan.trees[*b].script_pubkey())).collect();
        let mut t = tx(inputs, commit_outputs(keys, CONNECTOR, anchored));
        sign_commit(keys, &mut t, group, &prevouts, plan);
        commit_vsizes.push(t.vsize() as u64);
        commit_fees.push(fee_for(&t));
    }
    let mut c_values = vec![0u64; plan.batches.len()];
    for (group, fee) in groups.iter().zip(&commit_fees) {
        let share = (fee + CONNECTOR + anchor).div_ceil(group.len() as u64);
        for b in group {
            c_values[*b] = share;
        }
    }
    let placeholder = Utxo { outpoint: OutPoint { txid: Txid::all_zeros(), vout: 0 }, txout: txout(c_values.iter().sum(), key_path_script(&keys.secp, "operator-reserve")) };
    let draft = assert_init_tx(keys, &placeholder, &c_values, plan, anchored);
    let init_fee = fee_for(&draft);
    let init_vsize = draft.vsize() as u64;
    let connector = |vout: usize| Utxo { outpoint: OutPoint { txid: Txid::all_zeros(), vout: vout as u32 }, txout: txout(CONNECTOR, keys.operator_script()) };
    let connectors: Vec<Utxo> = (0..groups.len()).map(connector).collect();
    let final_vsize = assert_final_tx(keys, &connector(groups.len()), &connectors, keys.operator_script(), anchored).vsize() as u64;
    CommitLayout { groups, commit_fees, c_values, init_fee, init_vsize, commit_vsizes, final_vsize, anchored }
}

/// A commit's outputs: D_k, and in the anchored graph the operator's anchor.
fn commit_outputs(keys: &Keys, d_value: u64, anchored: bool) -> Vec<TxOut> {
    let mut outs = vec![txout(d_value, keys.operator_script())];
    if anchored {
        outs.push(txout(ANCHOR, keys.anchor_script()));
    }
    outs
}

/// assert_final: KA (committee) + every D_k (operator) -> A, and the anchor when anchored.
fn assert_final_tx(keys: &Keys, ka: &Utxo, connectors: &[Utxo], a_script: ScriptBuf, anchored: bool) -> Transaction {
    let mut inputs = vec![(ka.outpoint, RBF)];
    let mut prevouts = vec![ka.txout.clone()];
    for d in connectors {
        inputs.push((d.outpoint, RBF));
        prevouts.push(d.txout.clone());
    }
    let in_total: u64 = prevouts.iter().map(|o| o.value.to_sat()).sum::<u64>() - if anchored { ANCHOR } else { 0 };
    let build = |value: u64| {
        let mut outs = vec![txout(value, a_script.clone())];
        if anchored {
            outs.push(txout(ANCHOR, keys.anchor_script()));
        }
        let mut t = tx(inputs.clone(), outs);
        let sigs: Vec<Vec<u8>> = (0..t.input.len())
            .map(|i| {
                let signer = if i == 0 { &keys.committee } else { &keys.operator };
                sign_key_path(keys, signer, &t, &Prevouts::All(&prevouts), i, TapSighashType::Default, None)
            })
            .collect();
        for (input, sig) in t.input.iter_mut().zip(sigs) {
            input.witness = Witness::from_slice(&[sig]);
        }
        t
    };
    let draft = build(in_total);
    build(in_total - fee_for(&draft))
}

fn assert_init_tx(keys: &Keys, reserve: &Utxo, c_values: &[u64], plan: &CommitPlan, anchored: bool) -> Transaction {
    let mut outs: Vec<TxOut> = (0..plan.batches.len()).map(|b| txout(c_values[b], plan.trees[b].script_pubkey())).collect();
    if anchored {
        outs.push(txout(ANCHOR, keys.anchor_script()));
    }
    let mut t = tx(vec![(reserve.outpoint, RBF)], outs);
    let signer = keypair(&keys.secp, "operator-reserve");
    t.input[0].witness = Witness::from_slice(&[sign_key_path(keys, &signer, &t, &Prevouts::All(&[reserve.txout.clone()]), 0, TapSighashType::Default, None)]);
    t
}

/// The assert chain, fixed and signed (all but the commits' witnesses) before the kickoff.
/// Segwit txids exclude witnesses, so A's outpoint is known before any Winternitz data
/// exists and the committee can presign assert_final and everything that spends A.
pub struct AssertChain {
    pub assert_init: Transaction,
    /// Commit transactions without witnesses; `signed_commits` fills them in.
    pub commits: Vec<Transaction>,
    pub groups: Vec<Vec<usize>>,
    pub commit_fees: Vec<u64>,
    pub assert_final: Transaction,
    pub a: Utxo,
}

pub fn build_assert_chain(keys: &Keys, reserve: &Utxo, layout: &CommitLayout, plan: &CommitPlan, ka: &Utxo, a_script: ScriptBuf) -> AssertChain {
    let anchored = layout.anchored;
    let anchor = if anchored { ANCHOR } else { 0 };
    let assert_init = assert_init_tx(keys, reserve, &layout.c_values, plan, anchored);
    assert_eq!(reserve.sats(), layout.reserve(), "reserve must hold exactly the assert chain's cost");
    assert_eq!(fee_for(&assert_init), layout.init_fee);
    let init_txid = assert_init.compute_txid();

    let mut commits = vec![];
    for (group, fee) in layout.groups.iter().zip(&layout.commit_fees) {
        let inputs = group.iter().map(|b| (OutPoint { txid: init_txid, vout: *b as u32 }, RBF)).collect();
        let total: u64 = group.iter().map(|b| layout.c_values[*b]).sum();
        commits.push(tx(inputs, commit_outputs(keys, total - fee - anchor, anchored)));
    }
    let connectors: Vec<Utxo> = commits.iter().map(|c| Utxo::of(c, 0)).collect();
    let assert_final = assert_final_tx(keys, ka, &connectors, a_script, anchored);
    assert_eq!(assert_final.vsize() as u64, layout.final_vsize);
    let a = Utxo::of(&assert_final, 0);
    AssertChain { assert_init, commits, groups: layout.groups.clone(), commit_fees: layout.commit_fees.clone(), assert_final, a }
}

/// The operator-keyed anchor of an anchored assert-chain transaction: its last output.
pub fn anchor_of(t: &Transaction) -> Utxo {
    Utxo::of(t, t.output.len() - 1)
}

/// The commit transactions with the operator's Winternitz data (`plan.items`) and Schnorr
/// signatures. Their txids are the ones assert_final was signed against.
pub fn signed_commits(keys: &Keys, chain: &AssertChain, plan: &CommitPlan) -> Vec<Transaction> {
    chain
        .commits
        .iter()
        .zip(&chain.groups)
        .zip(&chain.commit_fees)
        .map(|((skeleton, group), fee)| {
            let mut t = skeleton.clone();
            let prevouts: Vec<TxOut> = group.iter().map(|b| chain.assert_init.output[*b].clone()).collect();
            sign_commit(keys, &mut t, group, &prevouts, plan);
            assert_eq!(t.compute_txid(), skeleton.compute_txid());
            assert!(fee_for(&t) <= *fee, "commit witness larger than the presigned layout allows");
            t
        })
        .collect()
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

/// The largest witness any assertion can put in a batch: a Winternitz digit is an empty item
/// when zero and one byte otherwise; every other item has a fixed length.
pub fn worst_case_items(items: &[Vec<u8>]) -> Vec<Vec<u8>> {
    items.iter().map(|i| if i.is_empty() { vec![1] } else { i.clone() }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profiles() -> Vec<Timing> {
        let mut all = vec![Timing::regtest(), Timing::named("testnet4").unwrap()];
        for (g, r) in [(0, 1), (0, 2), (1, 1), (3, 2), (6, 6), (20, 4), (90, 16), (200, 30)] {
            all.push(Timing::from_chain(g, r, None).unwrap());
        }
        all.push(Timing::from_chain(3, 2, Some(40)).unwrap());
        all
    }

    #[test]
    fn timeouts_leave_the_margin() {
        for t in profiles() {
            t.check().unwrap();
            for c in t.constraints() {
                assert!(c.required >= t.margin(), "{} {}: needs {} < W + R = {}", t.profile, c.name, c.required, t.margin());
                assert!(c.available >= t.margin(), "{} {}: {} blocks < W + R = {}", t.profile, c.name, c.available, t.margin());
                assert!(c.slack() >= 0, "{} {}: {} blocks, {} needed", t.profile, c.name, c.available, c.required);
            }
        }
    }

    #[test]
    fn regtest_profile_is_the_numbers_m2_to_m17_ran_with() {
        let t = Timing::regtest();
        assert_eq!((t.t_kickoff, t.t_challenge, t.t_assert, t.t_disprove, t.t_refund, t.assert_blocks), (6, 6, 12, 6, 30, 3));
        assert_eq!((t.deadline_after_batch, t.escrow_after_batch), (4, 22));
        assert_eq!(t.margin(), 2);
        assert_eq!(t.circuit_covers(), (true, true));
        assert_eq!(t.signed_escrow_after_batch(2), 27);
        assert!(t.tag.is_empty());
        // The default Escrow refund delay and the CSV in the refund leaf are the profile's.
        let keys = Keys::new();
        assert_eq!(Escrow::new(&keys, "b", None, t.t_refund).refund_leaf, csv_checksig(30, &xonly(&keys.secp, "buyer:b")));
    }

    #[test]
    fn regtest_dominates_what_the_formulas_derive() {
        // The formulas give the least clocks for (G, R) = (0, 1); regtest's are at least those.
        let (reg, min) = (Timing::regtest(), Timing::from_chain(0, 1, None).unwrap());
        assert_eq!((min.t_kickoff, min.t_challenge, min.t_assert, min.t_disprove, min.t_refund), (2, 3, 7, 3, 13));
        assert_eq!((min.deadline_after_batch, min.escrow_after_batch), (2, 12));
        assert!(reg.t_kickoff >= min.t_kickoff && reg.t_challenge >= min.t_challenge && reg.t_assert >= min.t_assert);
        assert!(reg.t_disprove >= min.t_disprove && reg.t_refund >= min.t_refund);
        assert!(reg.deadline_after_batch >= min.deadline_after_batch && reg.escrow_after_batch >= min.escrow_after_batch);
        // At regtest's own deadline and clocks the escrow formula gives exactly 22.
        let m = reg.margin() as u64;
        assert_eq!(reg.deadline_after_batch + u64::from(reg.t_assert - 1) + u64::from(reg.t_disprove) + m - 1, reg.escrow_after_batch);
    }

    #[test]
    fn derived_profiles_are_tight_and_fit_bip68() {
        let t = Timing::from_chain(90, 16, None).unwrap();
        assert_eq!(t.margin(), 107);
        assert_eq!((t.t_kickoff, t.t_challenge, t.t_assert, t.t_disprove, t.t_refund), (107, 108, 397, 108, 718));
        assert_eq!((t.deadline_after_batch, t.escrow_after_batch), (107, 717));
        // Each derived clock is the least that passes: one block less fails.
        for shrink in 0..7 {
            let mut u = t.clone();
            match shrink {
                0 => u.t_challenge -= 1,
                1 => u.t_assert -= 1,
                2 => u.t_disprove -= 1,
                3 => u.t_refund -= 1,
                4 => u.t_kickoff -= 1,
                5 => u.deadline_after_batch -= 1,
                _ => u.escrow_after_batch -= 1,
            }
            assert!(u.check().is_err(), "clock {shrink} is not tight");
        }
        assert!(Timing::from_chain(30_000, 30_000, None).is_err());
    }

    #[test]
    fn a_wider_disprove_gap_widens_only_what_depends_on_it() {
        let (a, b) = (Timing::from_chain(3, 2, None).unwrap(), Timing::from_chain(3, 2, Some(40)).unwrap());
        assert_eq!((a.t_challenge, a.t_assert, a.t_kickoff, a.deadline_after_batch), (b.t_challenge, b.t_assert, b.t_kickoff, b.deadline_after_batch));
        assert_eq!(b.t_disprove, a.t_disprove + 37);
        assert_eq!(b.escrow_after_batch, a.escrow_after_batch + 37);
    }

    #[test]
    fn signed_escrow_expiry_covers_the_bound() {
        for t in profiles() {
            assert!(t.signed_escrow_after_batch(2) >= t.escrow_after_batch);
        }
    }

    #[test]
    fn bump_child_carries_the_package_to_the_rate() {
        let keys = Keys::new();
        let coin = |vout: u32, label: &str, sats: u64| Utxo { outpoint: OutPoint { txid: Txid::all_zeros(), vout }, txout: txout(sats, key_path_script(&keys.secp, label)) };
        let (handle, payer) = (coin(0, "operator-anchor", ANCHOR), coin(1, "operator", 1_000_000));
        let mut parent = tx(vec![(OutPoint::null(), RBF)], vec![txout(ANCHOR, keys.anchor_script()); 20]);
        parent.version = Version(3);
        let parent_fee = fee_for(&parent);
        let paid = |child: &Transaction| ANCHOR + 1_000_000 - child.output[0].value.to_sat();

        let child = bump_child(&keys, &parent, parent_fee, &handle, &keys.anchor_keypair(), &payer, &keys.operator, 10_000, 0, keys.operator_script());
        assert_eq!(child.version, Version(3));
        assert_eq!(child.vsize() as u64, bump_child_vsize(&keys));
        assert_eq!(paid(&child), 10 * (parent.vsize() + child.vsize()) as u64 - parent_fee);

        let outbid = bump_child(&keys, &parent, parent_fee, &handle, &keys.anchor_keypair(), &payer, &keys.operator, 10_000, 50_000, keys.operator_script());
        assert_eq!(paid(&outbid), 50_000);
    }

    #[test]
    fn worst_case_items_bound_every_digit() {
        let items = vec![vec![7u8; 20], vec![], vec![7u8; 20], vec![15]];
        let worst = worst_case_items(&items);
        assert_eq!(worst, vec![vec![7u8; 20], vec![1], vec![7u8; 20], vec![15]]);
        assert!(worst.iter().zip(&items).all(|(w, i)| w.len() >= i.len()));
    }
}
