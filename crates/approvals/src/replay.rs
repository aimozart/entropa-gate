//! Deterministic replay of the log into approval state, and the pure gate.

use crate::{codec, decode, signing_digest};
use crate::{
    ActionClass, Actor, AttestationPolicy, BlockReason, Body, Directory, Event, GateDecision,
    RejectReason, Rejected, State,
};
use entropa_core::transparency_log::{decode_record, TransparencyLog};
use entropa_core::verify_hex;

/// Events more than this many seconds ahead of the replay clock are rejected.
const MAX_SKEW_SECS: u64 = 300;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Decided {
    approved: bool,
    signer: String,
    attested: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReqState {
    request_id: String,
    requester: String,
    class: ActionClass,
    subject_hash: String,
    ts: u64,
    valid_for_secs: u64,
    decision: Option<Decided>,
    consumed: bool,
}

fn reject(state: &mut State, index: usize, reason: RejectReason) {
    state.rejected.push(Rejected { index, reason });
}

/// Replay every record of the log in order. Records that are not approval events are ignored;
/// approval records that break a rule are listed in `rejected` with the reason.
pub fn replay(log: &TransparencyLog, directory: &Directory, now: u64) -> State {
    let mut state = State::default();
    for index in 0..log.len() {
        let Some(bytes) = log.record(index) else {
            continue;
        };
        let Ok((payload, Some(label))) = decode_record(bytes) else {
            continue;
        };
        if !label.starts_with("approval.") {
            continue;
        }
        let Ok(signed) = decode(&payload) else {
            reject(&mut state, index, RejectReason::Malformed);
            continue;
        };
        if label != format!("approval.{}", type_of(&signed.event)) {
            reject(&mut state, index, RejectReason::Malformed);
            continue;
        }
        if let Err(reason) = apply(
            &mut state,
            directory,
            index,
            &signed.event,
            &signed.sig,
            now,
        ) {
            reject(&mut state, index, reason);
        }
    }
    state
}

fn type_of(e: &Event) -> &'static str {
    match e.body {
        Body::Request { .. } => "request",
        Body::Approve { .. } => "approve",
        Body::Deny { .. } => "deny",
        Body::Consume => "consume",
    }
}

fn apply(
    state: &mut State,
    dir: &Directory,
    index: usize,
    e: &Event,
    sig: &str,
    now: u64,
) -> Result<(), RejectReason> {
    let signer: &Actor = dir.actors.get(&e.actor).ok_or(RejectReason::UnknownActor)?;
    if signer.pubkey_hex.is_empty() {
        return Err(RejectReason::BadSignature); // a keyless human cannot sign
    }
    if signer.revoked_at.is_some_and(|at| at <= index) {
        return Err(RejectReason::RevokedKey);
    }
    if !verify_hex(&signer.pubkey_hex, &signing_digest(e), sig) {
        return Err(RejectReason::BadSignature);
    }
    if e.ts > now.saturating_add(MAX_SKEW_SECS) {
        return Err(RejectReason::FutureTimestamp);
    }
    match &e.body {
        Body::Request {
            action_class,
            subject_hash,
            subject_ref: _,
            valid_for_secs,
        } => {
            if e.request_id != codec::derive_request_id(&e.actor, *action_class, subject_hash, e.ts)
                || state.requests.iter().any(|r| r.request_id == e.request_id)
            {
                return Err(RejectReason::Malformed);
            }
            state.requests.push(ReqState {
                request_id: e.request_id.clone(),
                requester: e.actor.clone(),
                class: *action_class,
                subject_hash: subject_hash.clone(),
                ts: e.ts,
                valid_for_secs: *valid_for_secs,
                decision: None,
                consumed: false,
            });
            Ok(())
        }
        Body::Approve { on_behalf_of, .. } | Body::Deny { on_behalf_of, .. } => {
            let approved = matches!(e.body, Body::Approve { .. });
            let req = state
                .requests
                .iter_mut()
                .find(|r| r.request_id == e.request_id)
                .ok_or(RejectReason::NoSuchRequest)?;
            if req.decision.is_some() {
                return Err(RejectReason::Superseded);
            }
            // who decides: the signer, or the keyless human the signer attests for
            let principal: &Actor = match on_behalf_of {
                Some(target) => {
                    if !signer.may_attest_for.contains(target) {
                        return Err(RejectReason::AttestationNotPermitted);
                    }
                    dir.actors
                        .get(target)
                        .ok_or(RejectReason::AttestationNotPermitted)?
                }
                None => signer,
            };
            if !principal.may_approve.contains(&req.class) {
                return Err(RejectReason::NotAllowedApprover);
            }
            if e.actor == req.requester || on_behalf_of.as_deref() == Some(req.requester.as_str()) {
                return Err(RejectReason::SelfApproval);
            }
            if e.ts > req.ts.saturating_add(req.valid_for_secs) {
                return Err(RejectReason::Expired);
            }
            req.decision = Some(Decided {
                approved,
                signer: e.actor.clone(),
                attested: on_behalf_of.is_some(),
            });
            Ok(())
        }
        Body::Consume => {
            let req = state
                .requests
                .iter_mut()
                .find(|r| r.request_id == e.request_id)
                .ok_or(RejectReason::BadConsume)?;
            match &req.decision {
                Some(d) if d.approved && !req.consumed => {
                    req.consumed = true;
                    Ok(())
                }
                _ => Err(RejectReason::BadConsume),
            }
        }
    }
}

fn evaluate(req: &ReqState, now: u64, policy: &AttestationPolicy) -> GateDecision {
    let Some(d) = &req.decision else {
        return GateDecision::Blocked(BlockReason::Pending);
    };
    if !d.approved {
        return GateDecision::Blocked(BlockReason::Denied);
    }
    if req.consumed {
        return GateDecision::Blocked(BlockReason::AlreadyUsed);
    }
    if now > req.ts.saturating_add(req.valid_for_secs) {
        return GateDecision::Blocked(BlockReason::Expired);
    }
    // An attestation opens the gate for `direction` only (the reviewer's ruling): never for the hard-rule
    // classes, and never for any other class either, whatever the policy lists. The policy can only
    // narrow this further.
    if d.attested
        && (req.class != ActionClass::Direction
            || req.class.is_hard_rule()
            || !policy.accepted_for.contains(&req.class))
    {
        return GateDecision::Blocked(BlockReason::AttestationNotAccepted);
    }
    GateDecision::Allowed {
        request_id: req.request_id.clone(),
        approver: d.signer.clone(),
        attested: d.attested,
    }
}

/// Ask the gate whether an action of `class` on exactly `subject_hash` is approved at `now`.
pub fn check(
    state: &State,
    class: ActionClass,
    subject_hash: &str,
    now: u64,
    policy: &AttestationPolicy,
) -> GateDecision {
    let of_class: Vec<&ReqState> = state.requests.iter().filter(|r| r.class == class).collect();
    if of_class.is_empty() {
        return GateDecision::Blocked(BlockReason::NoRequest);
    }
    let matching: Vec<&&ReqState> = of_class
        .iter()
        .filter(|r| r.subject_hash == subject_hash)
        .collect();
    if matching.is_empty() {
        return GateDecision::Blocked(BlockReason::SubjectMismatch);
    }
    let results: Vec<GateDecision> = matching.iter().map(|r| evaluate(r, now, policy)).collect();
    results
        .iter()
        .find(|d| matches!(d, GateDecision::Allowed { .. }))
        .or_else(|| results.last())
        .cloned()
        .unwrap_or(GateDecision::Blocked(BlockReason::NoRequest))
}
