//! Actor directory operations.

use crate::{key_id, Actor, Directory, Role};

impl Directory {
    /// An empty directory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an actor with a key; returns its key id.
    pub fn add(&mut self, actor: Actor) -> String {
        let id = key_id(&actor.pubkey_hex);
        self.actors.insert(id.clone(), actor);
        id
    }

    /// Register a human who has no signing key yet (decisions for them are attestations); returns
    /// the key id derived from the name. The caller sets `may_approve` on the entry.
    pub fn add_keyless_human(&mut self, name: &str) -> String {
        let mut h = blake3::Hasher::new();
        h.update(b"entropa-keyless-actor-v1\0");
        h.update(name.as_bytes());
        let id = hex::encode(&h.finalize().as_bytes()[..8]);
        self.actors.insert(
            id.clone(),
            Actor {
                pubkey_hex: String::new(),
                role: Role::Human,
                may_approve: vec![],
                may_attest_for: vec![],
                revoked_at: None,
            },
        );
        id
    }

    /// Revoke a key from log index `at` (the earliest revocation wins).
    pub fn revoke(&mut self, key_id: &str, at: usize) {
        if let Some(a) = self.actors.get_mut(key_id) {
            a.revoked_at = Some(a.revoked_at.map_or(at, |old| old.min(at)));
        }
    }
}

impl Directory {
    /// Register an actor like [`Directory::add`], but refuse to give an already registered key a second identity: the
    /// same key with another role, another approval scope, another attestation scope or a revocation is an error and the
    /// directory is left unchanged (P3.3: one key never holds two roles; a re-registration is idempotent only if identical).
    pub fn try_add(&mut self, actor: Actor) -> Result<String, crate::ApprovalError> {
        let id = key_id(&actor.pubkey_hex);
        match self.actors.get(&id) {
            Some(existing) if *existing == actor => Ok(id),
            Some(_) => Err(crate::ApprovalError::Invalid(
                "this key is already registered with a different identity".into(),
            )),
            None => Ok(self.add(actor)),
        }
    }
}
