//! Minimal Bitcoin Core JSON-RPC client (HTTP basic auth, no TLS; regtest on localhost only).

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::{Address, Amount, OutPoint, ScriptBuf, Transaction, TxOut, Txid};
use serde_json::{json, Value};
use std::str::FromStr;

pub struct Rpc {
    url: String,
    auth: String,
}

fn base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(TABLE[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

impl Rpc {
    pub fn new(url: &str, user: &str, password: &str) -> Rpc {
        Rpc { url: url.to_string(), auth: format!("Basic {}", base64(format!("{user}:{password}").as_bytes())) }
    }

    pub fn wallet(&self, name: &str) -> Rpc {
        Rpc { url: format!("{}/wallet/{name}", self.url.trim_end_matches('/')), auth: self.auth.clone() }
    }

    /// The call's result, or the node's error message.
    pub fn try_call(&self, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({"jsonrpc": "1.0", "id": "zkc-m1", "method": method, "params": params});
        let response = minreq::post(&self.url)
            .with_header("Authorization", &self.auth)
            .with_header("Content-Type", "application/json")
            .with_body(body.to_string())
            .with_timeout(600)
            .send()
            .map_err(|e| format!("{method}: transport: {e}"))?;
        let reply: Value = serde_json::from_slice(response.as_bytes())
            .map_err(|e| format!("{method}: HTTP {} with unparseable body: {e}", response.status_code))?;
        if !reply["error"].is_null() {
            return Err(reply["error"]["message"].as_str().unwrap_or("unknown error").to_string());
        }
        Ok(reply["result"].clone())
    }

    pub fn call(&self, method: &str, params: Value) -> Value {
        self.try_call(method, params).unwrap_or_else(|e| panic!("rpc {method}: {e}"))
    }

    pub fn height(&self) -> u64 {
        self.call("getblockcount", json!([])).as_u64().unwrap()
    }

    pub fn new_address(&self) -> Address {
        let text = self.call("getnewaddress", json!(["", "bech32m"]));
        Address::from_str(text.as_str().unwrap()).unwrap().assume_checked()
    }

    pub fn mine(&self, blocks: u64, to: &Address) -> Vec<String> {
        let hashes = self.call("generatetoaddress", json!([blocks, to.to_string()]));
        hashes.as_array().unwrap().iter().map(|h| h.as_str().unwrap().to_string()).collect()
    }

    /// Pays `amount` to `script` from the wallet, mines it, and returns the outpoint.
    pub fn fund(&self, script: &ScriptBuf, amount: Amount, miner: &Address) -> (OutPoint, TxOut) {
        let address = Address::from_script(script, bitcoin::Network::Regtest).unwrap();
        let txid = self.call("sendtoaddress", json!([address.to_string(), amount.to_btc()]));
        let txid = Txid::from_str(txid.as_str().unwrap()).unwrap();
        self.mine(1, miner);
        let tx = self.transaction(&txid);
        let vout = tx.output.iter().position(|out| &out.script_pubkey == script).unwrap();
        (OutPoint { txid, vout: vout as u32 }, tx.output[vout].clone())
    }

    pub fn transaction(&self, txid: &Txid) -> Transaction {
        let hex_tx = self.call("getrawtransaction", json!([txid.to_string(), false]));
        bitcoin::consensus::encode::deserialize_hex(hex_tx.as_str().unwrap()).unwrap()
    }

    /// Mempool policy verdict: Ok(()) if standard and valid now, Err(reason) otherwise.
    pub fn test_accept(&self, tx: &Transaction) -> Result<(), String> {
        let result = self.call("testmempoolaccept", json!([[serialize_hex(tx)], 0]));
        let entry = &result[0];
        if entry["allowed"].as_bool() == Some(true) {
            Ok(())
        } else {
            Err(entry["reject-reason"].as_str().unwrap_or("rejected").to_string())
        }
    }

    pub fn send(&self, tx: &Transaction) -> Result<Txid, String> {
        self.try_call("sendrawtransaction", json!([serialize_hex(tx), 0]))
            .map(|txid| Txid::from_str(txid.as_str().unwrap()).unwrap())
    }

    /// Mines one block holding exactly `txs` (bypassing mempool policy, not consensus).
    /// Returns the block hash or the node's consensus error.
    pub fn mine_raw(&self, txs: &[&Transaction], miner: &Address) -> Result<String, String> {
        let raw: Vec<String> = txs.iter().map(|tx| serialize_hex(*tx)).collect();
        self.try_call("generateblock", json!([miner.to_string(), raw]))
            .map(|result| result["hash"].as_str().unwrap().to_string())
    }

    pub fn confirmations(&self, txid: &Txid) -> Option<u64> {
        self.try_call("getrawtransaction", json!([txid.to_string(), true]))
            .ok()
            .and_then(|v| v["confirmations"].as_u64())
    }
}
