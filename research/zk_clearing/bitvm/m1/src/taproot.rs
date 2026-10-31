//! Deterministic regtest keys and a taproot tree built from leaf hashes, so that leaves of
//! several megabytes are hashed once and only the leaf being spent is kept in memory.

use bitcoin::key::{Keypair, Secp256k1, TapTweak, UntweakedPublicKey};
use bitcoin::secp256k1::{All, SecretKey, XOnlyPublicKey};
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash, TapNodeHash, TaprootMerkleBranch};
use bitcoin::ScriptBuf;
use sha2::{Digest, Sha256};

/// Demo keys are SHA-256 of a public label: anyone can spend them. Regtest only.
pub const KEY_DOMAIN: &str = "p2poolv2/zk_clearing/bitvm-m1/regtest-demo-key/";

pub fn keypair(secp: &Secp256k1<All>, label: &str) -> Keypair {
    let secret = Sha256::digest(format!("{KEY_DOMAIN}{label}").as_bytes());
    Keypair::from_secret_key(secp, &SecretKey::from_slice(&secret).expect("hash is a valid key"))
}

pub fn xonly(secp: &Secp256k1<All>, label: &str) -> XOnlyPublicKey {
    keypair(secp, label).x_only_public_key().0
}

/// P2TR output spendable only by the key path of `label` (BIP86-style tweak, no script tree).
pub fn key_path_script(secp: &Secp256k1<All>, label: &str) -> ScriptBuf {
    ScriptBuf::new_p2tr(secp, xonly(secp, label), None)
}

/// BIP341's provably unspendable internal key H.
pub fn nums_key() -> UntweakedPublicKey {
    XOnlyPublicKey::from_slice(&hex::decode("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0").unwrap()).unwrap()
}

pub fn leaf_hash(script: &ScriptBuf) -> TapLeafHash {
    TapLeafHash::from_script(script, LeafVersion::TapScript)
}

/// A script tree with a NUMS internal key (script-path spends only), or with a real internal
/// key that can also spend by the key path (`with_internal_key`).
pub struct ScriptTree {
    pub leaves: Vec<TapLeafHash>,
    levels: Vec<Vec<TapNodeHash>>,
    pub internal_key: UntweakedPublicKey,
    pub output_key: bitcoin::key::TweakedPublicKey,
    parity: bitcoin::key::Parity,
}

impl ScriptTree {
    /// Leaves are paired left to right; an odd node moves up a level unchanged.
    pub fn new(secp: &Secp256k1<All>, leaves: Vec<TapLeafHash>) -> ScriptTree {
        ScriptTree::with_internal_key(secp, nums_key(), leaves)
    }

    pub fn with_internal_key(secp: &Secp256k1<All>, internal_key: UntweakedPublicKey, leaves: Vec<TapLeafHash>) -> ScriptTree {
        assert!(!leaves.is_empty());
        let mut levels = vec![leaves.iter().map(|leaf| TapNodeHash::from(*leaf)).collect::<Vec<_>>()];
        while levels.last().unwrap().len() > 1 {
            let level = levels.last().unwrap();
            let next = level
                .chunks(2)
                .map(|pair| if pair.len() == 2 { TapNodeHash::from_node_hashes(pair[0], pair[1]) } else { pair[0] })
                .collect();
            levels.push(next);
        }
        let root = levels.last().unwrap()[0];
        let (output_key, parity) = internal_key.tap_tweak(secp, Some(root));
        ScriptTree { leaves, levels, internal_key, output_key, parity }
    }

    #[allow(dead_code)] // M2's escrows sign their key path with it
    pub fn merkle_root(&self) -> TapNodeHash {
        self.levels.last().unwrap()[0]
    }

    pub fn script_pubkey(&self) -> ScriptBuf {
        ScriptBuf::new_p2tr_tweaked(self.output_key)
    }

    pub fn depth(&self) -> usize {
        self.levels.len() - 1
    }

    pub fn control_block(&self, index: usize) -> ControlBlock {
        let mut path = vec![];
        let mut position = index;
        for level in &self.levels[..self.levels.len() - 1] {
            let sibling = position ^ 1;
            if sibling < level.len() {
                path.push(level[sibling]);
            }
            position /= 2;
        }
        ControlBlock {
            leaf_version: LeafVersion::TapScript,
            output_key_parity: self.parity,
            internal_key: self.internal_key,
            merkle_branch: TaprootMerkleBranch::try_from(path).expect("depth <= 128"),
        }
    }

    /// The control block for `index`, checked against the output key with `script`.
    pub fn checked_control_block(&self, secp: &Secp256k1<All>, index: usize, script: &ScriptBuf) -> ControlBlock {
        assert_eq!(leaf_hash(script), self.leaves[index], "script does not match leaf {index}");
        let control = self.control_block(index);
        assert!(control.verify_taproot_commitment(secp, self.output_key.to_x_only_public_key(), script), "bad control block for leaf {index}");
        control
    }
}
