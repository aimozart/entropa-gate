//! Shared helpers. All data is synthetic.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use entropa_core::merkle::{consistency_proof, leaf_hash, root as merkle_root, Hash};
use entropa_core::transparency_log::{Checkpoint, TransparencyLog};
use entropa_core::{CheckpointSigner, Probe, SignError};
use entropa_witness::*;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub const NOW: u64 = 1_700_000_000;
pub const TS: u64 = 1_699_999_000;

/// A synthetic log: a signing key and records `rec-0`, `rec-1`, ... (or `alt-...` for a forked history).
pub struct SynthLog {
    pub probe: Probe,
    pub prefix: &'static str,
    pub leaves: Vec<Hash>,
}

impl SynthLog {
    pub fn new(probe: Probe, prefix: &'static str, n: usize) -> SynthLog {
        let leaves = (0..n)
            .map(|i| leaf_hash(format!("{prefix}-{i}").as_bytes()))
            .collect();
        SynthLog {
            probe,
            prefix,
            leaves,
        }
    }
    pub fn pubkey(&self) -> String {
        self.probe.pubkey_hex()
    }
    pub fn log_id(&self) -> String {
        hex::encode(blake3::hash(&hex::decode(self.pubkey()).unwrap()).as_bytes())
    }
    /// The signed checkpoint of the first `n` records.
    pub fn checkpoint(&self, n: usize, ts: u64) -> Checkpoint {
        assert!(n <= self.leaves.len());
        let mut log = TransparencyLog::new();
        for i in 0..n {
            log.append(format!("{}-{i}", self.prefix).as_bytes());
        }
        let cp = log.checkpoint(&self.probe, ts);
        let expected = if n == 0 {
            None
        } else {
            merkle_root(&self.leaves[..n])
        };
        if let Some(r) = expected {
            assert_eq!(cp.root, r, "helper: leaves and log disagree");
        }
        cp
    }
    /// Consistency proof from `old` to `new` records (empty when `old` is 0 or equal to `new`).
    pub fn proof(&self, old: usize, new: usize) -> Vec<Hash> {
        if old == 0 || old == new {
            return Vec::new();
        }
        consistency_proof(&self.leaves[..new], old).unwrap()
    }
}

pub fn log_with(n: usize) -> SynthLog {
    SynthLog::new(Probe::spawn(), "rec", n)
}

/// Build the request body for a checkpoint and proof.
pub fn body(log_id: &str, cp: &Checkpoint, proof: &[Hash]) -> String {
    request_value(log_id, cp, proof).to_string()
}

pub fn request_value(log_id: &str, cp: &Checkpoint, proof: &[Hash]) -> Value {
    json!({"v": 1, "log_id": log_id, "checkpoint": serde_json::to_value(cp).unwrap(),
           "consistency": proof.iter().map(hex::encode).collect::<Vec<_>>()})
}

/// Hook run just before a compare-and-swap (to simulate another writer).
pub type CasHook = Box<dyn Fn(&mut HashMap<String, (State, u64)>) + Send>;

/// An in-memory store with fault injection and inspection.
#[derive(Default)]
pub struct Inner {
    pub states: HashMap<String, (State, u64)>,
    pub equivocations: Vec<(String, String)>,
    pub fail_get: bool,
    pub fail_cas: bool,
    pub conflict_next_cas: bool,
    pub fail_equivocation: bool,
    pub before_cas: Option<CasHook>,
    pub cas_calls: usize,
}

#[derive(Default)]
pub struct TestStore {
    pub inner: Mutex<Inner>,
}

impl TestStore {
    pub fn new() -> Arc<TestStore> {
        Arc::new(TestStore::default())
    }
    pub fn state(&self, log_id: &str) -> Option<State> {
        self.inner
            .lock()
            .unwrap()
            .states
            .get(log_id)
            .map(|(s, _)| *s)
    }
    pub fn put(&self, log_id: &str, s: State) {
        let mut g = self.inner.lock().unwrap();
        let v = g.states.get(log_id).map_or(1, |(_, v)| v + 1);
        g.states.insert(log_id.to_string(), (s, v));
    }
    pub fn equivocations(&self) -> Vec<(String, String)> {
        self.inner.lock().unwrap().equivocations.clone()
    }
}

impl StateStore for TestStore {
    fn get(&self, log_id: &str) -> Result<Option<(State, String)>, StoreError> {
        let g = self.inner.lock().unwrap();
        if g.fail_get {
            return Err(StoreError::Failed("get failed".into()));
        }
        Ok(g.states.get(log_id).map(|(s, v)| (*s, v.to_string())))
    }
    fn compare_and_swap(
        &self,
        log_id: &str,
        expected: Option<&str>,
        new: &State,
    ) -> Result<(), StoreError> {
        let mut g = self.inner.lock().unwrap();
        g.cas_calls += 1;
        if let Some(hook) = g.before_cas.take() {
            hook(&mut g.states);
        }
        if g.fail_cas {
            return Err(StoreError::Failed("cas failed".into()));
        }
        if g.conflict_next_cas {
            g.conflict_next_cas = false;
            return Err(StoreError::Conflict);
        }
        let current = g.states.get(log_id).map(|(_, v)| v.to_string());
        if current.as_deref() != expected {
            return Err(StoreError::Conflict);
        }
        let v = g.states.get(log_id).map_or(1, |(_, v)| v + 1);
        g.states.insert(log_id.to_string(), (*new, v));
        Ok(())
    }
    fn record_equivocation(&self, log_id: &str, evidence: &str) -> Result<(), StoreError> {
        let mut g = self.inner.lock().unwrap();
        if g.fail_equivocation {
            return Err(StoreError::Failed("evidence write failed".into()));
        }
        g.equivocations
            .push((log_id.to_string(), evidence.to_string()));
        Ok(())
    }
}

/// A signer whose backend always fails (the key is a real one so the witness can be built).
pub struct FailingSigner(pub Probe);
impl CheckpointSigner for FailingSigner {
    fn algorithm(&self) -> &'static str {
        "ML-DSA-65"
    }
    fn pubkey_hex(&self) -> String {
        self.0.pubkey_hex()
    }
    fn try_sign_hex(&self, _msg: &[u8]) -> Result<String, SignError> {
        Err(SignError::Backend("boom".into()))
    }
}

pub fn config(log: &SynthLog, allow_first: bool) -> LogConfig {
    LogConfig {
        log_id: log.log_id(),
        pubkey_hex: log.pubkey(),
        allow_first,
    }
}

/// A witness for one log with the given store; panics with the red marker while the stub answers.
pub fn witness_with<S: StateStore>(
    log: &SynthLog,
    allow_first: bool,
    store: S,
) -> Witness<S, Probe> {
    match Witness::new(vec![config(log, allow_first)], store, Probe::spawn()) {
        Ok(w) => w,
        Err(WitnessError::NotImplemented) => panic!("{NOT_IMPLEMENTED}"),
        Err(e) => panic!("witness did not build: {e:?}"),
    }
}

pub fn witness(
    log: &SynthLog,
    allow_first: bool,
) -> (Witness<Arc<TestStore>, Probe>, Arc<TestStore>) {
    let store = TestStore::new();
    (witness_with(log, allow_first, store.clone()), store)
}

/// Cosign and expect success; panics with the red marker while the stub answers.
pub fn cosign_ok<S: StateStore, G: CheckpointSigner>(
    w: &Witness<S, G>,
    body: &str,
    now: u64,
) -> Statement {
    match w.cosign(body, now) {
        Ok(json) => match verify_statement(&json, &w.pubkey_hex()) {
            Ok(s) => s,
            Err(WitnessError::NotImplemented) => panic!("{NOT_IMPLEMENTED}"),
            Err(e) => panic!("the returned statement does not verify: {e:?}"),
        },
        Err(WitnessError::NotImplemented) => panic!("{NOT_IMPLEMENTED}"),
        Err(e) => panic!("cosign failed: {e:?}"),
    }
}

/// Cosign and expect a refusal; panics with the red marker while the stub answers.
pub fn cosign_err<S: StateStore, G: CheckpointSigner>(
    w: &Witness<S, G>,
    body: &str,
    now: u64,
) -> WitnessError {
    match w.cosign(body, now) {
        Ok(_) => panic!("expected a refusal but a statement was signed"),
        Err(WitnessError::NotImplemented) => panic!("{NOT_IMPLEMENTED}"),
        Err(e) => e,
    }
}

pub fn zero_root() -> String {
    NO_PREVIOUS_ROOT.to_string()
}
