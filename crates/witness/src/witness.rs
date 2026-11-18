//! The witness: verify, check consistency, sign, swap, release.

use crate::decode::decode_request;
use crate::statement::{log_id_for, statement_canonical_bytes, statement_digest, statement_json};
use crate::{
    LogConfig, State, StateStore, StatementFields, StoreError, WitnessError, NO_PREVIOUS_ROOT,
};
use entropa_core::merkle::verify_consistency;
use entropa_core::CheckpointSigner;
use std::collections::HashMap;

/// The witness: configured logs, a state store and a signer.
pub struct Witness<S: StateStore, G: CheckpointSigner> {
    logs: HashMap<String, LogConfig>,
    store: S,
    signer: G,
}

impl<S: StateStore, G: CheckpointSigner> Witness<S, G> {
    /// Build a witness. Each `log_id` must equal [`log_id_for`] of its key and be unique, and at
    /// least one log is required.
    pub fn new(logs: Vec<LogConfig>, store: S, signer: G) -> Result<Self, WitnessError> {
        if logs.is_empty() {
            return Err(WitnessError::Invalid(
                "at least one log must be configured".into(),
            ));
        }
        let mut map = HashMap::new();
        for cfg in logs {
            let expected = log_id_for(&cfg.pubkey_hex);
            if expected.is_empty() || expected != cfg.log_id {
                return Err(WitnessError::Invalid(
                    "log_id is not the BLAKE3 of the log public key".into(),
                ));
            }
            if map.insert(cfg.log_id.clone(), cfg).is_some() {
                return Err(WitnessError::Invalid("duplicate log_id".into()));
            }
        }
        Ok(Witness {
            logs: map,
            store,
            signer,
        })
    }

    /// The witness public key, lowercase hex.
    pub fn pubkey_hex(&self) -> String {
        self.signer.pubkey_hex()
    }

    /// Handle one request body at witness time `now`; returns the statement JSON. Nothing is
    /// returned unless the new state was stored.
    pub fn cosign(&self, body: &str, now: u64) -> Result<String, WitnessError> {
        let req = decode_request(body)?;
        let cfg = self.logs.get(&req.log_id).ok_or(WitnessError::UnknownLog)?;
        let cp = &req.checkpoint;
        if !cp.verify_signature(&cfg.pubkey_hex) {
            return Err(WitnessError::BadSignature);
        }
        let stored = self.store.get(&req.log_id).map_err(store_failure)?;
        let (previous, version) = match stored {
            None => {
                if !cfg.allow_first {
                    return Err(WitnessError::FirstNotAllowed);
                }
                if !req.consistency.is_empty() {
                    return Err(WitnessError::BadConsistency);
                }
                (None, None)
            }
            Some((old, version)) => {
                self.check_extension(&req.log_id, &old, &req, now)?;
                (Some(old), Some(version))
            }
        };
        let fields = StatementFields {
            log_id: req.log_id.clone(),
            size: cp.size as u64,
            root: hex::encode(cp.root),
            log_timestamp: cp.timestamp,
            witness_time: now,
            previous_size: previous.map_or(0, |p| p.size as u64),
            previous_root: previous
                .map_or_else(|| NO_PREVIOUS_ROOT.to_string(), |p| hex::encode(p.root)),
            witness_pubkey: self.signer.pubkey_hex(),
        };
        let digest = statement_digest(&statement_canonical_bytes(&fields));
        let sig = self
            .signer
            .try_sign_hex(&digest)
            .map_err(|e| WitnessError::Sign(e.to_string()))?;
        if !entropa_core::verify_hex(&fields.witness_pubkey, &digest, &sig) {
            return Err(WitnessError::Sign(
                "the signature does not verify under the witness key".into(),
            ));
        }
        let new_state = State {
            size: cp.size,
            root: cp.root,
        };
        // An unchanged state needs no write: the statement only repeats what is already stored.
        if previous != Some(new_state) {
            self.store
                .compare_and_swap(&req.log_id, version.as_deref(), &new_state)
                .map_err(store_failure)?;
        }
        Ok(statement_json(&fields, &sig))
    }

    /// Rollback, equivocation and consistency checks against the stored state.
    fn check_extension(
        &self,
        log_id: &str,
        old: &State,
        req: &crate::Request,
        now: u64,
    ) -> Result<(), WitnessError> {
        let cp = &req.checkpoint;
        if cp.size < old.size {
            return Err(WitnessError::Rollback);
        }
        if cp.size == old.size {
            if cp.root != old.root {
                self.record(log_id, old, req, now);
                return Err(WitnessError::Equivocation);
            }
            return if req.consistency.is_empty() {
                Ok(())
            } else {
                Err(WitnessError::BadConsistency)
            };
        }
        if old.size == 0 {
            return if req.consistency.is_empty() {
                Ok(())
            } else {
                Err(WitnessError::BadConsistency)
            };
        }
        if verify_consistency(&old.root, old.size, &cp.root, cp.size, &req.consistency) {
            Ok(())
        } else {
            self.record(log_id, old, req, now);
            Err(WitnessError::BadConsistency)
        }
    }

    /// Best-effort evidence of a signed checkpoint that contradicts the stored one.
    fn record(&self, log_id: &str, old: &State, req: &crate::Request, now: u64) {
        let evidence = serde_json::json!({
            "type": "witness.evidence",
            "log_id": log_id,
            "witness_time": now,
            "stored": {"size": old.size, "root": hex::encode(old.root)},
            "received": serde_json::to_value(&req.checkpoint).unwrap_or_default(),
        });
        // a failed evidence write must not turn a refusal into an acceptance
        let _ = self
            .store
            .record_equivocation(log_id, &evidence.to_string());
    }
}

fn store_failure(e: StoreError) -> WitnessError {
    match e {
        StoreError::Conflict => WitnessError::StoreConflict,
        StoreError::Failed(m) => WitnessError::Store(m),
    }
}
