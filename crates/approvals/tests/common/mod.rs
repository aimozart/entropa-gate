//! Fixtures. All keys are throwaway `Probe`s and all data is synthetic.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use entropa_approvals::*;
use entropa_core::transparency_log::{encode_record, TransparencyLog};
use entropa_core::Probe;

pub const NOW: u64 = 1_700_000_000;

pub fn must<T>(r: Result<T, ApprovalError>) -> T {
    match r {
        Ok(v) => v,
        Err(ApprovalError::NotImplemented) => panic!("{NOT_IMPLEMENTED}"),
        Err(e) => panic!("unexpected error: {e}"),
    }
}

pub fn subject(word: &str) -> String {
    hex::encode(blake3::hash(word.as_bytes()).as_bytes())
}

pub struct Fx {
    pub owner: Probe,
    pub reviewer: Probe,
    pub requester: Probe,
    pub svc: Probe,
    pub owner_id: String,
    pub reviewer_id: String,
    pub requester_id: String,
    pub svc_id: String,
    pub principal_id: String,
    pub dir: Directory,
}

pub fn fx() -> Fx {
    let (owner, reviewer, requester, svc) = (
        Probe::spawn(),
        Probe::spawn(),
        Probe::spawn(),
        Probe::spawn(),
    );
    let mut dir = Directory::new();
    let principal_id = dir.add_keyless_human("principal");
    dir.actors.insert(
        principal_id.clone(),
        Actor {
            pubkey_hex: String::new(),
            role: Role::Human,
            may_approve: ActionClass::ALL.to_vec(),
            may_attest_for: vec![],
            revoked_at: None,
        },
    );
    let owner_id = dir.add(Actor {
        pubkey_hex: owner.pubkey_hex(),
        role: Role::Human,
        may_approve: ActionClass::ALL.to_vec(),
        may_attest_for: vec![],
        revoked_at: None,
    });
    let reviewer_id = dir.add(Actor {
        pubkey_hex: reviewer.pubkey_hex(),
        role: Role::Ai,
        may_approve: vec![],
        may_attest_for: vec![principal_id.clone()],
        revoked_at: None,
    });
    let requester_id = dir.add(Actor {
        pubkey_hex: requester.pubkey_hex(),
        role: Role::Ai,
        may_approve: vec![],
        may_attest_for: vec![],
        revoked_at: None,
    });
    let svc_id = dir.add(Actor {
        pubkey_hex: svc.pubkey_hex(),
        role: Role::Service,
        may_approve: vec![],
        may_attest_for: vec![],
        revoked_at: None,
    });
    Fx {
        owner,
        reviewer,
        requester,
        svc,
        owner_id,
        reviewer_id,
        requester_id,
        svc_id,
        principal_id,
        dir,
    }
}

impl Fx {
    /// A signed request by requester (the usual requester).
    pub fn request(
        &self,
        class: ActionClass,
        subject_word: &str,
        ts: u64,
        valid_for: u64,
    ) -> SignedEvent {
        must(sign(
            &self.requester,
            &Event::request(
                &self.requester_id,
                ts,
                class,
                &subject(subject_word),
                "stage:S3",
                valid_for,
            ),
        ))
    }
    pub fn approve_by(&self, who: &Probe, who_id: &str, request_id: &str, ts: u64) -> SignedEvent {
        must(sign(
            who,
            &Event::approve(who_id, ts, request_id, None, None),
        ))
    }
    pub fn deny_by(&self, who: &Probe, who_id: &str, request_id: &str, ts: u64) -> SignedEvent {
        must(sign(
            who,
            &Event::deny(who_id, ts, request_id, ReasonCode::TooRisky, None, None),
        ))
    }
    /// the reviewer's attestation on behalf of the keyless the owner.
    pub fn attest_approve(&self, request_id: &str, ts: u64) -> SignedEvent {
        let basis = subject("chat-ref");
        must(sign(
            &self.reviewer,
            &Event::approve(
                &self.reviewer_id,
                ts,
                request_id,
                Some(&self.principal_id),
                Some(&basis),
            ),
        ))
    }
    pub fn consume_by_requester(&self, request_id: &str, ts: u64) -> SignedEvent {
        must(sign(
            &self.requester,
            &Event::consume(&self.requester_id, ts, request_id),
        ))
    }
}

pub fn log_with(events: &[SignedEvent]) -> TransparencyLog {
    let mut log = TransparencyLog::new();
    for e in events {
        must(append_event(&mut log, e));
    }
    log
}

pub fn policy_all() -> AttestationPolicy {
    AttestationPolicy {
        accepted_for: ActionClass::ALL.to_vec(),
    }
}
pub fn policy_default() -> AttestationPolicy {
    AttestationPolicy {
        accepted_for: vec![ActionClass::Direction],
    }
}

pub fn note_record(log: &mut TransparencyLog) {
    log.append(&encode_record("just a note", Some("note")).unwrap());
}
