//! Demo keys derived from a public seed. They sign only synthetic events; production keys never
//! come from a seed in a repository.

use crate::vocab::Handle;
use crate::LedgerError;
use entropa_core::Probe;
use std::collections::BTreeMap;

/// The handles that hold a signing key (the human principal is keyless; the operator and the AWS
/// co-signer do not exist yet).
pub(crate) const KEYED: [Handle; 8] = [
    Handle::OrchestratorAgent,
    Handle::BuilderAgent,
    Handle::LogSigner,
    Handle::Generator,
    Handle::WitnessAzure,
    Handle::AgentEntropa,
    Handle::AgentBigironbank,
    Handle::AgentHippagrchealthcare,
];

/// The demo keys of one seed.
pub struct Keys {
    map: BTreeMap<Handle, Probe>,
}

impl Keys {
    /// Derive every key from `seed` and the handle.
    pub fn from_seed(seed: u64) -> Result<Keys, LedgerError> {
        let mut map = BTreeMap::new();
        for h in KEYED {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"entropa-ledger-demo-key-v1\0");
            hasher.update(&seed.to_be_bytes());
            hasher.update(h.as_str().as_bytes());
            let probe = Probe::from_signing_key_hex(&hex::encode(hasher.finalize().as_bytes()))
                .ok_or_else(|| LedgerError::Sign("could not derive a demo key".into()))?;
            map.insert(h, probe);
        }
        Ok(Keys { map })
    }

    /// The key of a handle, `None` for a handle without a key.
    pub fn probe(&self, h: Handle) -> Option<&Probe> {
        self.map.get(&h)
    }
}
