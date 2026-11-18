#![no_main]
use entropa_core::merkle::{consistency_proof, leaf_hash, Hash};
use entropa_core::transparency_log::{Checkpoint, TransparencyLog};
use entropa_core::{CheckpointSigner, Probe, SignError};
use entropa_witness::*;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

const N: usize = 40;

struct Env {
    log: Probe,
    witness_key: Probe,
    leaves: Vec<Hash>,
    cps: Vec<Checkpoint>,
}

fn env() -> &'static Env {
    static E: OnceLock<Env> = OnceLock::new();
    E.get_or_init(|| {
        let log = Probe::spawn();
        let leaves: Vec<Hash> = (0..N).map(|i| leaf_hash(format!("rec-{i}").as_bytes())).collect();
        let cps = (0..=N)
            .map(|n| {
                let mut l = TransparencyLog::new();
                for i in 0..n {
                    l.append(format!("rec-{i}").as_bytes());
                }
                l.checkpoint(&log, 1_700_000_000 + n as u64)
            })
            .collect();
        Env { log, witness_key: Probe::spawn(), leaves, cps }
    })
}

struct Signer(&'static Probe);
impl CheckpointSigner for Signer {
    fn algorithm(&self) -> &'static str {
        "ML-DSA-65"
    }
    fn pubkey_hex(&self) -> String {
        self.0.pubkey_hex()
    }
    fn try_sign_hex(&self, m: &[u8]) -> Result<String, SignError> {
        Ok(self.0.sign_hex(m))
    }
}

#[derive(Default)]
struct Store(Mutex<(HashMap<String, (State, u64)>, usize)>);
impl StateStore for Store {
    fn get(&self, id: &str) -> Result<Option<(State, String)>, StoreError> {
        Ok(self.0.lock().unwrap().0.get(id).map(|(s, v)| (*s, v.to_string())))
    }
    fn compare_and_swap(&self, id: &str, expected: Option<&str>, new: &State) -> Result<(), StoreError> {
        let mut g = self.0.lock().unwrap();
        let cur = g.0.get(id).map(|(_, v)| v.to_string());
        if cur.as_deref() != expected {
            return Err(StoreError::Conflict);
        }
        let v = g.0.get(id).map_or(1, |(_, v)| v + 1);
        g.0.insert(id.to_string(), (*new, v));
        Ok(())
    }
    fn record_equivocation(&self, _id: &str, _e: &str) -> Result<(), StoreError> {
        self.0.lock().unwrap().1 += 1;
        Ok(())
    }
}

fn body(log_id: &str, cp: &Checkpoint, proof: &[Hash]) -> String {
    serde_json::json!({"v": 1, "log_id": log_id, "checkpoint": serde_json::to_value(cp).unwrap(),
        "consistency": proof.iter().map(hex::encode).collect::<Vec<_>>()})
    .to_string()
}

// A real history: the first checkpoint is accepted, then a second one with a proof that is intact or has one bit flipped.
// Invariant: a statement is returned exactly when the history is consistent, and the state then equals the new checkpoint;
// otherwise the state is unchanged.
fuzz_target!(|data: &[u8]| {
    if data.len() < 5 {
        return;
    }
    let e = env();
    let a = 1 + data[0] as usize % N;
    let b = 1 + data[1] as usize % N;
    let corrupt = data[2] % 3 == 0;
    let (pick, bit) = (data[3] as usize, data[4] % 8);
    let store = Arc::new(Store::default());
    let cfg = LogConfig { log_id: log_id_for(&e.log.pubkey_hex()), pubkey_hex: e.log.pubkey_hex(), allow_first: true };
    let w = Witness::new(vec![cfg.clone()], store.clone(), Signer(&e.witness_key)).unwrap();
    w.cosign(&body(&cfg.log_id, &e.cps[a], &[]), 1).unwrap();
    let mut proof = if b > a { consistency_proof(&e.leaves[..b], a).unwrap() } else { Vec::new() };
    let mut changed = false;
    if corrupt && !proof.is_empty() {
        let k = pick % proof.len();
        proof[k][pick % 32] ^= 1 << bit;
        changed = true;
    }
    let r = w.cosign(&body(&cfg.log_id, &e.cps[b], &proof), 2);
    let stored = store.get(&cfg.log_id).unwrap().unwrap().0;
    if b < a {
        assert_eq!(r, Err(WitnessError::Rollback));
        assert_eq!(stored.size, a);
    } else if changed {
        assert_eq!(r, Err(WitnessError::BadConsistency));
        assert_eq!(stored.size, a);
    } else {
        assert!(r.is_ok());
        assert_eq!(stored.size, b);
    }
});

