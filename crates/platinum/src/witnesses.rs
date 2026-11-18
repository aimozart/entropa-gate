//! The node's witness client. After new checkpoints exist it sends the latest one, with a consistency proof from the
//! last checkpoint that witness accepted, to each configured witness, and keeps the signed statements it gets back.
//! Best effort: a witness being down is reported to the caller and never affects the ledger.

use crate::Res;
use entropa_core::merkle::{consistency_proof, leaf_hash};
use entropa_ledger::{FileStore, LedgerStore};
use entropa_witness::{log_id_for, verify_statement};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(10);

fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(TIMEOUT)
        .build()
        .unwrap_or_default()
}

fn load_state(p: &Path) -> BTreeMap<String, (String, usize)> {
    let v: Value = std::fs::read_to_string(p)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or(Value::Null);
    v.as_object()
        .map(|m| {
            m.iter()
                .filter_map(|(k, e)| {
                    Some((
                        k.clone(),
                        (
                            e["pubkey"].as_str()?.to_string(),
                            e["size"].as_u64()? as usize,
                        ),
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn save_state(p: &Path, s: &BTreeMap<String, (String, usize)>) -> Res<()> {
    let v: Value = s
        .iter()
        .map(|(k, (pk, n))| (k.clone(), json!({"pubkey": pk, "size": n})))
        .collect::<serde_json::Map<_, _>>()
        .into();
    std::fs::write(p, v.to_string()).map_err(|_| "cannot save the witness state".to_string())
}

/// Send the latest checkpoint of the ledger in `dir/sub` to every witness in `urls`. One result per URL.
pub fn sync_witnesses(dir: &Path, sub: &str, urls: &[String]) -> Vec<Res<()>> {
    let ledger = dir.join(sub);
    let state_path = ledger.join("witness-state.json");
    let stmts_path = ledger.join("witness-statements.jsonl");
    // read the ledger once (the store lock is held only while reading)
    let (leaves, cp) = match FileStore::open(&ledger) {
        Ok(store) => {
            let leaves: Vec<_> = (0..store.len())
                .filter_map(|i| store.record(i))
                .map(|r| leaf_hash(&r))
                .collect();
            (leaves, store.checkpoints().last().cloned())
        }
        Err(_) => {
            return urls
                .iter()
                .map(|_| Err("cannot read the ledger".to_string()))
                .collect()
        }
    };
    let Some(cp) = cp else {
        return urls.iter().map(|_| Ok(())).collect();
    };
    let mut state = load_state(&state_path);
    let mut out = Vec::new();
    for url in urls {
        out.push((|| -> Res<()> {
            let base = url.trim_end_matches('/');
            let (pubkey, done) = match state.get(base) {
                Some((pk, n)) => (pk.clone(), *n),
                None => {
                    let pk = client().get(format!("{base}/v1/pubkey")).send().map_err(|_| "witness unreachable".to_string())?.text().map_err(|_| "witness reply".to_string())?;
                    (pk.trim().to_string(), 0)
                }
            };
            if done == cp.size {
                return Ok(());
            }
            if cp.size > leaves.len() || done > cp.size {
                return Err("witness state does not fit this ledger".to_string());
            }
            let proof: Vec<String> = if done == 0 { vec![] } else { consistency_proof(&leaves[..cp.size], done).ok_or_else(|| "cannot build the proof".to_string())?.iter().map(hex::encode).collect() };
            let body = json!({"v":1,"log_id":log_id_for(&cp.proposer_pubkey),"checkpoint":{"root":hex::encode(cp.root),"size":cp.size,"timestamp":cp.timestamp,"proposer_pubkey":cp.proposer_pubkey,"signature":cp.signature},"consistency":proof});
            let resp = client().post(format!("{base}/v1/cosign")).header("Content-Type", "application/json").body(body.to_string()).send().map_err(|_| "witness unreachable".to_string())?;
            let status = resp.status();
            let text = resp.text().map_err(|_| "witness reply".to_string())?;
            if !status.is_success() {
                return Err(format!("witness refused (HTTP {})", status.as_u16()));
            }
            verify_statement(&text, &pubkey).map_err(|_| "witness statement does not verify".to_string())?;
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&stmts_path).map_err(|_| "cannot save the statement".to_string())?;
            writeln!(f, "{}", text.trim()).map_err(|_| "cannot save the statement".to_string())?;
            state.insert(base.to_string(), (pubkey, cp.size));
            save_state(&state_path, &state)
        })());
    }
    out
}

/// The kept statements of the ledger in `dir/sub`, newest last, each with the witness key that signed it.
pub fn kept_statements(dir: &Path, sub: &str) -> Vec<Value> {
    let p = dir.join(sub).join("witness-statements.jsonl");
    let text = std::fs::read_to_string(p).unwrap_or_default();
    let mut v: Vec<Value> = text
        .lines()
        .filter_map(|l| {
            let st: Value = serde_json::from_str(l).ok()?;
            Some(json!({"witness_pubkey": st["witness_pubkey"], "size": st["size"], "root": st["root"], "witness_time": st["witness_time"], "previous_size": st["previous_size"], "statement": l}))
        })
        .collect();
    let n = v.len();
    if n > 200 {
        v.drain(..n - 200);
    }
    v
}
