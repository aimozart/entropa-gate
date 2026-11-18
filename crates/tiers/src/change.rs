//! AT3: change control (a stage record (not published)). A change takes effect only with a valid T3 requester, a second distinct T3 approver bound to the exact change hash, and a sealed
//! append-only version, with one hash-only record per call. Every step may only deny; nothing here reads a clock, a network or a key.

use crate::{RecordSink, TierRecord, TokenVerifier};
use entropa_tokens::{Deny, Tier};
use std::collections::HashMap;
use std::sync::Mutex;

/// Seconds a request and each approval stay valid.
pub const TTL: u64 = 3600;

/// A proposed change: only hashes and closed words, never content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// `prompt`, `corpus`, `policy` or `model` (anything else is refused).
    pub class: String,
    /// Token characters, at most 64.
    pub name: String,
    /// 64 lowercase hex: hash of the new content.
    pub content_hash: String,
    /// 64 lowercase hex: `version_hash` of the version this one follows (none for the first).
    pub parent: Option<String>,
}
impl Change {
    /// The hash every request and approval binds to.
    pub fn hash(&self) -> String {
        hash_fields(&[
            self.class.as_bytes(),
            self.name.as_bytes(),
            self.content_hash.as_bytes(),
            self.parent.as_deref().unwrap_or("").as_bytes(),
            &[u8::from(self.parent.is_some())],
        ])
    }
}

fn hash_fields(parts: &[&[u8]]) -> String {
    let mut h = blake3::Hasher::new();
    for p in parts {
        h.update(&(p.len() as u64).to_be_bytes());
        h.update(p);
    }
    hex::encode(h.finalize().as_bytes())
}
fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}
const CLASSES: [&str; 4] = ["prompt", "corpus", "policy", "model"];

/// Why a change call was refused (closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeDeny {
    /// The token verifier refused it.
    Token(Deny),
    /// Not a tier T3 token.
    NotT3,
    /// The class is not on the closed list.
    UnknownClass,
    /// A field is malformed.
    Malformed,
    /// The token does not list `change:<class>`.
    ClassNotInToken,
    /// No such pending request.
    NoSuchRequest,
    /// The approver is the requester or has the requester's subject.
    SelfApproval,
    /// The request is older than the TTL.
    RequestExpired,
    /// Every approval is older than the TTL.
    ApprovalExpired,
    /// No valid approval by a second subject.
    NotEnoughApprovals,
    /// The parent is not the current head.
    HeadMoved,
    /// The record could not be written.
    RecordFailed,
    /// The version store failed.
    StoreFailed,
    /// A step panicked.
    InternalError,
    /// A live request for this change hash exists already.
    AlreadyRequested,
}

impl ChangeDeny {
    /// The closed word written to the trail.
    pub fn as_str(self) -> &'static str {
        match self {
            ChangeDeny::Token(d) => d.as_str(),
            ChangeDeny::NotT3 => "not_t3",
            ChangeDeny::UnknownClass => "unknown_class",
            ChangeDeny::Malformed => "malformed",
            ChangeDeny::ClassNotInToken => "class_not_in_token",
            ChangeDeny::NoSuchRequest => "no_such_request",
            ChangeDeny::SelfApproval => "self_approval",
            ChangeDeny::RequestExpired => "request_expired",
            ChangeDeny::ApprovalExpired => "approval_expired",
            ChangeDeny::NotEnoughApprovals => "not_enough_approvals",
            ChangeDeny::HeadMoved => "head_moved",
            ChangeDeny::RecordFailed => "record_failed",
            ChangeDeny::StoreFailed => "store_failed",
            ChangeDeny::InternalError => "internal_error",
            ChangeDeny::AlreadyRequested => "already_requested",
        }
    }
}

/// A sealed version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionRec {
    /// Class.
    pub class: String,
    /// Name.
    pub name: String,
    /// 1 for the first version of a name.
    pub seq: u64,
    /// Hash of the content.
    pub content_hash: String,
    /// The `version_hash` of the previous version.
    pub parent_version_hash: Option<String>,
    /// The change this version came from.
    pub change_hash: String,
    /// Hash of all the fields above.
    pub version_hash: String,
}

/// A request waiting for approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    /// The change.
    pub change: Change,
    /// The requester's token subject.
    pub requester: String,
    /// When it was requested.
    pub ts: u64,
    /// Approvals, each with the evidence needed to check it again at activation.
    pub approvals: Vec<Approval>,
}

/// One approval: who, when, and the approver's token (and parent token) as presented, kept so activation can verify them again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    /// The approver's token subject.
    pub subject: String,
    /// When the approval was made.
    pub ts: u64,
    /// The approver's token bytes.
    pub token: Vec<u8>,
    /// The approver's parent token bytes, if the token names one.
    pub parent: Option<Vec<u8>>,
}

/// A held place at the head of `(class, name)`: nothing else may be prepared there until it is committed or aborted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reservation {
    /// The version to append.
    pub version: VersionRec,
    /// The head's `version_hash` the append expects.
    pub expected_head: Option<String>,
}

/// Append failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppendError {
    /// The head is not the expected one.
    HeadMoved,
    /// The store failed.
    Other(String),
}

/// Requests and approvals.
pub trait PendingStore {
    /// One pending request.
    fn get(&self, change_hash: &str) -> Option<Pending>;
    /// Create or replace it.
    fn put(&self, change_hash: &str, p: Pending) -> Result<(), String>;
}
/// Append-only versions, newest last.
pub trait VersionStore {
    /// The newest version of `(class, name)`.
    fn head(&self, class: &str, name: &str) -> Option<VersionRec>;
    /// Every version of `(class, name)`, oldest first.
    fn all(&self, class: &str, name: &str) -> Vec<VersionRec>;
    /// Append `v` only if the head's `version_hash` equals `expected_head` (compare and set).
    fn append(&self, v: VersionRec, expected_head: Option<&str>) -> Result<(), AppendError>;
    /// Check the head and hold the place (default: the check alone, which holds nothing: a store that wants a race-free lost-race answer overrides all three).
    fn prepare(
        &self,
        v: VersionRec,
        expected_head: Option<&str>,
    ) -> Result<Reservation, AppendError> {
        if self
            .head(&v.class, &v.name)
            .map(|h| h.version_hash)
            .as_deref()
            != expected_head
        {
            return Err(AppendError::HeadMoved);
        }
        Ok(Reservation {
            version: v,
            expected_head: expected_head.map(String::from),
        })
    }
    /// Append the reserved version (default: `append`).
    fn commit(&self, r: Reservation) -> Result<(), AppendError> {
        self.append(r.version, r.expected_head.as_deref())
    }
    /// Give the place back (default: nothing held, nothing to do).
    fn abort(&self, _r: &Reservation) {}
}

/// In-memory pending store.
#[derive(Default)]
pub struct MemoryPending(Mutex<HashMap<String, Pending>>);
impl PendingStore for MemoryPending {
    fn get(&self, h: &str) -> Option<Pending> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(h)
            .cloned()
    }
    fn put(&self, h: &str, p: Pending) -> Result<(), String> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(h.to_string(), p);
        Ok(())
    }
}
/// In-memory version store: versions and held reservations live under ONE lock, so the head check and the hold are atomic.
#[derive(Default)]
pub struct MemoryVersions(Mutex<MemState>);
#[derive(Default)]
struct MemState {
    lists: HashMap<(String, String), Vec<VersionRec>>,
    held: std::collections::HashSet<(String, String)>,
}
impl MemoryVersions {
    fn lock(&self) -> std::sync::MutexGuard<'_, MemState> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}
impl VersionStore for MemoryVersions {
    fn head(&self, c: &str, n: &str) -> Option<VersionRec> {
        self.all(c, n).pop()
    }
    fn all(&self, c: &str, n: &str) -> Vec<VersionRec> {
        self.lock()
            .lists
            .get(&(c.to_string(), n.to_string()))
            .cloned()
            .unwrap_or_default()
    }
    fn append(&self, v: VersionRec, expected_head: Option<&str>) -> Result<(), AppendError> {
        let mut g = self.lock();
        let list = g
            .lists
            .entry((v.class.clone(), v.name.clone()))
            .or_default();
        if list.last().map(|x| x.version_hash.as_str()) != expected_head {
            return Err(AppendError::HeadMoved);
        }
        list.push(v);
        Ok(())
    }
    fn prepare(
        &self,
        v: VersionRec,
        expected_head: Option<&str>,
    ) -> Result<Reservation, AppendError> {
        let mut g = self.lock();
        let key = (v.class.clone(), v.name.clone());
        let head = g
            .lists
            .get(&key)
            .and_then(|l| l.last())
            .map(|x| x.version_hash.as_str());
        if head != expected_head || g.held.contains(&key) {
            return Err(AppendError::HeadMoved);
        }
        g.held.insert(key);
        Ok(Reservation {
            version: v,
            expected_head: expected_head.map(String::from),
        })
    }
    fn commit(&self, r: Reservation) -> Result<(), AppendError> {
        let mut g = self.lock();
        let key = (r.version.class.clone(), r.version.name.clone());
        g.held.remove(&key);
        let list = g.lists.entry(key).or_default();
        if list.last().map(|x| x.version_hash.as_str()) != r.expected_head.as_deref() {
            return Err(AppendError::HeadMoved);
        }
        list.push(r.version);
        Ok(())
    }
    fn abort(&self, r: &Reservation) {
        self.lock()
            .held
            .remove(&(r.version.class.clone(), r.version.name.clone()));
    }
}

/// The change-control gate.
pub struct ChangeControl<'a> {
    /// Token verification.
    pub verifier: &'a dyn TokenVerifier,
    /// Requests and approvals.
    pub pending: &'a dyn PendingStore,
    /// Sealed versions.
    pub versions: &'a dyn VersionStore,
    /// One record per call.
    pub sink: &'a dyn RecordSink,
}
impl ChangeControl<'_> {
    /// Request a change with a T3 token (and its parent token, if it names one). Returns the change hash.
    pub fn request(
        &self,
        token: &[u8],
        parent: Option<&[u8]>,
        c: &Change,
        now: u64,
    ) -> Result<String, ChangeDeny> {
        self.guarded("change_request", now, || {
            let t3 = self.t3(token, parent, now)?;
            let class = c.class.as_str();
            if !CLASSES.contains(&class) {
                return Err((ChangeDeny::UnknownClass, Some(t3.hash), None));
            }
            let hash = c.hash();
            let bad = |d: ChangeDeny| Err((d, Some(t3.hash.clone()), None));
            if !t3.actions.iter().any(|a| *a == format!("change:{class}")) {
                return bad(ChangeDeny::ClassNotInToken);
            }
            if c.name.is_empty()
                || c.name.len() > 64
                || !c
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
                || !is_hex64(&c.content_hash)
                || c.parent.as_deref().is_some_and(|p| !is_hex64(p))
            {
                return bad(ChangeDeny::Malformed);
            }
            if let Some(old) = self.pending.get(&hash) {
                if now <= old.ts.saturating_add(TTL) {
                    return Err((ChangeDeny::AlreadyRequested, Some(t3.hash), Some(hash)));
                }
            }
            let ok = (hash.clone(), t3.hash.clone());
            self.record_allowed("change_request", &ok.0, Some(&ok.1), now)?;
            let p = Pending {
                change: c.clone(),
                requester: t3.subject,
                ts: now,
                approvals: vec![],
            };
            self.pending
                .put(&hash, p)
                .map_err(|_| (ChangeDeny::StoreFailed, Some(t3.hash), Some(hash.clone())))?;
            Ok(hash)
        })
    }

    /// Approve the change with this hash with another T3 token.
    pub fn approve(
        &self,
        token: &[u8],
        parent: Option<&[u8]>,
        change_hash: &str,
        now: u64,
    ) -> Result<(), ChangeDeny> {
        self.guarded("change_approve", now, || {
            let t3 = self.t3(token, parent, now)?;
            let h = Some(change_hash.to_string());
            let Some(mut p) = self.pending.get(change_hash) else {
                return Err((ChangeDeny::NoSuchRequest, Some(t3.hash), h));
            };
            if !t3
                .actions
                .iter()
                .any(|a| *a == format!("change:{}", p.change.class))
            {
                return Err((ChangeDeny::ClassNotInToken, Some(t3.hash), h));
            }
            if now > p.ts.saturating_add(TTL) {
                return Err((ChangeDeny::RequestExpired, Some(t3.hash), h));
            }
            if t3.subject == p.requester {
                return Err((ChangeDeny::SelfApproval, Some(t3.hash), h));
            }
            self.record_allowed("change_approve", change_hash, Some(&t3.hash), now)?;
            p.approvals.retain(|a| a.subject != t3.subject);
            p.approvals.push(Approval {
                subject: t3.subject,
                ts: now,
                token: token.to_vec(),
                parent: parent.map(<[u8]>::to_vec),
            });
            self.pending
                .put(change_hash, p)
                .map_err(|_| (ChangeDeny::StoreFailed, Some(t3.hash), h))?;
            Ok(())
        })
    }

    /// Activate: with a valid T3 token naming the class, seal the change as a new version if it has a valid approval by a second subject. Every stored approval is verified AGAIN at
    /// `now` (signature, expiry, audience, revocation list and its freshness); the version place is held (`prepare`) before the `allowed` record is written, so a lost race writes only a denial.
    pub fn activate(
        &self,
        token: &[u8],
        parent: Option<&[u8]>,
        change_hash: &str,
        now: u64,
    ) -> Result<VersionRec, ChangeDeny> {
        self.guarded("change_activate", now, || {
            let t3 = self.t3(token, parent, now)?;
            let h = Some(change_hash.to_string());
            let th = Some(t3.hash.clone());
            let Some(p) = self.pending.get(change_hash) else {
                return Err((ChangeDeny::NoSuchRequest, th, h));
            };
            if !t3
                .actions
                .iter()
                .any(|a| *a == format!("change:{}", p.change.class))
            {
                return Err((ChangeDeny::ClassNotInToken, th, h));
            }
            let others: Vec<&Approval> = p
                .approvals
                .iter()
                .filter(|a| a.subject != p.requester)
                .collect();
            if others.is_empty() {
                return Err((ChangeDeny::NotEnoughApprovals, th, h));
            }
            let live: Vec<&&Approval> = others
                .iter()
                .filter(|a| now <= a.ts.saturating_add(TTL))
                .collect();
            if live.is_empty() {
                return Err((ChangeDeny::ApprovalExpired, th, h));
            }
            let (mut valid, mut first_err) = (0usize, None);
            for a in live {
                match self.verifier.verify(&a.token, a.parent.as_deref(), now) {
                    Ok(v) => {
                        let listed = v
                            .claims
                            .actions
                            .iter()
                            .any(|x| *x == format!("change:{}", p.change.class));
                        if v.claims.tier == Tier::T3
                            && listed
                            && v.claims.subject == a.subject
                            && v.claims.subject != p.requester
                        {
                            valid += 1;
                        }
                    }
                    Err(d) => {
                        first_err.get_or_insert(d);
                    }
                }
            }
            if valid == 0 {
                return Err((
                    first_err.map_or(ChangeDeny::NotEnoughApprovals, ChangeDeny::Token),
                    th,
                    h,
                ));
            }
            let c = &p.change;
            let head = self.versions.head(&c.class, &c.name);
            let head_hash = head.as_ref().map(|v| v.version_hash.clone());
            if c.parent != head_hash {
                return Err((ChangeDeny::HeadMoved, th, h));
            }
            let seq = head.as_ref().map_or(1, |v| v.seq + 1);
            let mut v = VersionRec {
                class: c.class.clone(),
                name: c.name.clone(),
                seq,
                content_hash: c.content_hash.clone(),
                parent_version_hash: head_hash.clone(),
                change_hash: change_hash.to_string(),
                version_hash: String::new(),
            };
            v.version_hash = hash_fields(&[
                v.class.as_bytes(),
                v.name.as_bytes(),
                &v.seq.to_be_bytes(),
                v.content_hash.as_bytes(),
                v.parent_version_hash.as_deref().unwrap_or("").as_bytes(),
                &[u8::from(v.parent_version_hash.is_some())],
                v.change_hash.as_bytes(),
            ]);
            // hold the place first: a loser fails HERE, before any `allowed` record exists
            let res = match self.versions.prepare(v.clone(), head_hash.as_deref()) {
                Ok(r) => r,
                Err(AppendError::HeadMoved) => return Err((ChangeDeny::HeadMoved, th, h)),
                Err(AppendError::Other(_)) => return Err((ChangeDeny::StoreFailed, th, h)),
            };
            // the record is written before the version is committed: if it fails nothing is applied and the place is given back
            if let Err(e) = self.record_allowed("change_activate", change_hash, th.as_deref(), now)
            {
                self.versions.abort(&res);
                return Err(e);
            }
            match self.versions.commit(res.clone()) {
                Ok(()) => Ok(v),
                Err(e) => {
                    self.versions.abort(&res);
                    Err((
                        if e == AppendError::HeadMoved {
                            ChangeDeny::HeadMoved
                        } else {
                            ChangeDeny::StoreFailed
                        },
                        th,
                        h,
                    ))
                }
            }
        })
    }

    fn t3(&self, token: &[u8], parent: Option<&[u8]>, now: u64) -> Result<T3, Fail> {
        let v = self
            .verifier
            .verify(token, parent, now)
            .map_err(|d| (ChangeDeny::Token(d), None, None))?;
        let hash = hex::encode(blake3::hash(v.token_id.as_bytes()).as_bytes());
        if v.claims.tier != Tier::T3 {
            return Err((ChangeDeny::NotT3, Some(hash), None));
        }
        Ok(T3 {
            hash,
            subject: v.claims.subject.clone(),
            actions: v.claims.actions.clone(),
        })
    }

    fn record(
        &self,
        action: &'static str,
        ok: bool,
        reason: &str,
        change_hash: &str,
        token_hash: Option<&str>,
        now: u64,
    ) -> Result<(), String> {
        let hash = if is_hex64(change_hash) {
            change_hash.to_string()
        } else {
            "0".repeat(64)
        };
        self.sink.write(&TierRecord {
            label: if ok { "token_used" } else { "token_denied" },
            decision: if ok { "allowed" } else { "denied" },
            reason: reason.to_string(),
            tier: Some("T3"),
            action,
            token_hash: token_hash.map(String::from),
            request_hash: hash,
            policy_hash: hash_fields(&[b"at3-change-control-v1"]),
            ts: now,
        })
    }
    fn record_allowed(
        &self,
        action: &'static str,
        change_hash: &str,
        token_hash: Option<&str>,
        now: u64,
    ) -> Result<(), Fail> {
        self.record(action, true, "allowed", change_hash, token_hash, now)
            .map_err(|_| {
                (
                    ChangeDeny::RecordFailed,
                    token_hash.map(String::from),
                    Some(change_hash.to_string()),
                )
            })
    }

    /// Run one call: a panic becomes `InternalError`; every refusal is recorded (a failing sink does not turn a denial into anything else).
    fn guarded<T>(
        &self,
        action: &'static str,
        now: u64,
        f: impl FnOnce() -> Result<T, Fail>,
    ) -> Result<T, ChangeDeny> {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or(Err((
            ChangeDeny::InternalError,
            None,
            None,
        )));
        match r {
            Ok(v) => Ok(v),
            Err((d, th, ch)) => {
                // RecordFailed already means the record could not be written: do not try again
                if d != ChangeDeny::RecordFailed {
                    let _ = self.record(
                        action,
                        false,
                        d.as_str(),
                        ch.as_deref().unwrap_or(""),
                        th.as_deref(),
                        now,
                    );
                }
                Err(d)
            }
        }
    }
}

type Fail = (ChangeDeny, Option<String>, Option<String>);
struct T3 {
    hash: String,
    subject: String,
    actions: Vec<String>,
}
