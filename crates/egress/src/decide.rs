//! The decision pipeline (EG0 section 2.1): canonicalise, limits, destination, views, detectors, rules, redaction, re-check, record, bind.
//! Every step is total; any error, panic or budget overrun ends in a block (F1 to F7).
use crate::detect::{scan_kind, Det, DetectCfg, ViewKind};
use crate::policy::{parse_url, Limits, Mode, Policy, PolicyError, PolicyVerifier, Tier};
use crate::record::{EvidenceRequest, RecordSink};
use crate::views::{decoded, fold, strip, View};
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::panic::{catch_unwind, AssertUnwindSafe};

/// SHA-256 as lower-case hex.
pub fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

/// The three outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(missing_docs)]
pub enum Action {
    Allow,
    Redact,
    Block,
}

macro_rules! reasons {
    ($($v:ident => $s:literal),+ $(,)?) => {
        /// Closed reason codes.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[allow(missing_docs)]
        pub enum Reason { $($v),+ }
        impl Reason {
            /// Every code, in order.
            pub const ALL: &'static [Reason] = &[$(Reason::$v),+];
            /// The wire string.
            pub fn as_str(self) -> &'static str { match self { $(Reason::$v => $s),+ } }
            /// Parse a wire string; `None` outside the closed list.
            pub fn parse(s: &str) -> Option<Reason> { match s { $($s => Some(Reason::$v),)+ _ => None } }
        }
    };
}
reasons!(
    Clean => "clean", Redacted => "redacted", SecretFormat => "secret_format", PrivateKey => "private_key",
    CredentialStructure => "credential_structure", CardNumber => "card_number", PersonalId => "personal_id",
    PersonalContact => "personal_contact", DoNotSendTerm => "do_not_send_term", DocumentMarker => "document_marker",
    EntropyHint => "entropy_hint", ObfuscationSuspected => "obfuscation_suspected", ResidualAfterRedaction => "residual_after_redaction",
    DestinationDenied => "destination_denied", TierNoEgress => "tier_no_egress", SizeLimit => "size_limit",
    AttachmentTypeDenied => "attachment_type_denied", MalformedRequest => "malformed_request", DnsLabelSuspect => "dns_label_suspect",
    BudgetExceeded => "budget_exceeded", PolicyInvalid => "policy_invalid", InternalError => "internal_error",
    RecordFailed => "record_failed", SendMismatch => "send_mismatch",
);

fn det_reason(d: Det) -> Reason {
    match d {
        Det::D1 => Reason::SecretFormat,
        Det::D2 => Reason::PrivateKey,
        Det::D3 => Reason::CredentialStructure,
        Det::D4 => Reason::CardNumber,
        Det::D5Id | Det::D5Dob => Reason::PersonalId,
        Det::D5Email | Det::D5Phone => Reason::PersonalContact,
        Det::D6 => Reason::EntropyHint,
        Det::D7 => Reason::DoNotSendTerm,
        Det::D8 => Reason::DocumentMarker,
    }
}
/// Priority of blocking reasons (first wins).
const PRIORITY: &[Det] = &[
    Det::D2,
    Det::D1,
    Det::D3,
    Det::D4,
    Det::D5Id,
    Det::D5Dob,
    Det::D7,
    Det::D8,
    Det::D5Email,
    Det::D5Phone,
    Det::D6,
];
fn class(d: Det) -> &'static str {
    match d {
        Det::D1 => "secret",
        Det::D2 => "key",
        Det::D3 => "credential",
        Det::D4 => "card",
        Det::D5Id => "id",
        Det::D5Email => "email",
        Det::D5Phone => "phone",
        Det::D5Dob => "dob",
        Det::D6 => "entropy",
        Det::D7 => "term",
        Det::D8 => "marker",
    }
}

/// An attachment.
#[derive(Debug, Clone)]
pub struct Attachment {
    /// File name.
    pub name: String,
    /// Media type.
    pub mime: String,
    /// Content.
    pub bytes: Vec<u8>,
}

/// An outbound request.
#[derive(Debug, Clone)]
pub struct Request {
    /// Destination URL.
    pub destination: String,
    /// Body bytes.
    pub body: Vec<u8>,
    /// Parse the body as strict JSON (tool-call arguments) rather than text.
    pub body_is_json: bool,
    /// Attachments.
    pub attachments: Vec<Attachment>,
    /// Header name and value pairs.
    pub headers: Vec<(String, String)>,
}

/// Conversation state passed in by the caller (the engine keeps none, which is what makes decisions repeatable).
#[derive(Debug, Clone)]
pub struct Conversation {
    /// Key for placeholder identity (never in records).
    pub key: Vec<u8>,
    /// The last bytes of the conversation, joined to the scan so a split across messages is seen.
    pub tail: String,
    /// Placeholder identities seen so far (carry `Decision::seen_after` forward).
    pub seen: Vec<String>,
}

/// Fault injection points (tests only); each must end in a block (E3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Fault {
    Parser,
    Limits,
    Views,
    Detector,
    Redactor,
    Recheck,
    Record,
    Budget,
}
impl Fault {
    /// Every injection point.
    pub const ALL: &'static [Fault] = &[
        Fault::Parser,
        Fault::Limits,
        Fault::Views,
        Fault::Detector,
        Fault::Redactor,
        Fault::Recheck,
        Fault::Record,
        Fault::Budget,
    ];
}

/// The decision. Only this module can build one (F8).
#[derive(Debug, Clone)]
pub struct Decision {
    action: Action,
    reason: Reason,
    redacted: Option<Vec<u8>>,
    req_sha: String,
    red_sha: Option<String>,
    dets: BTreeMap<Det, u32>,
    seen_after: Vec<String>,
    views: BTreeSet<ViewKind>,
}
impl Decision {
    /// The action.
    pub fn action(&self) -> Action {
        self.action
    }
    /// The reason code.
    pub fn reason(&self) -> Reason {
        self.reason
    }
    /// The body to send after redaction (`None` for allow and block).
    pub fn redacted_body(&self) -> Option<&[u8]> {
        self.redacted.as_deref()
    }
    /// SHA-256 of the request body bytes.
    pub fn request_sha256(&self) -> String {
        self.req_sha.clone()
    }
    /// SHA-256 of the redacted body, for a redact.
    pub fn redacted_sha256(&self) -> Option<String> {
        self.red_sha.clone()
    }
    /// Placeholder identities to carry into the next request of the conversation.
    pub fn seen_after(&self) -> &[String] {
        &self.seen_after
    }
    /// Detector ids that matched, with counts.
    pub fn detectors(&self) -> &BTreeMap<Det, u32> {
        &self.dets
    }
    /// The kinds of view that produced a match.
    pub fn views(&self) -> &BTreeSet<ViewKind> {
        &self.views
    }
}

struct Out {
    action: Action,
    reason: Reason,
    redacted: Option<Vec<u8>>,
    dets: BTreeMap<Det, u32>,
    views: BTreeSet<ViewKind>,
    seen_after: Vec<String>,
    total: u64,
    flagged: u64,
    dest_id: Option<String>,
}
impl Out {
    fn block(r: Reason) -> Out {
        Out {
            action: Action::Block,
            reason: r,
            redacted: None,
            dets: BTreeMap::new(),
            views: BTreeSet::new(),
            seen_after: vec![],
            total: 0,
            flagged: 0,
            dest_id: None,
        }
    }
}

/// Decide.
pub fn decide(
    req: &Request,
    policy: &Policy,
    tier: Tier,
    conv: &Conversation,
    sink: &dyn RecordSink,
) -> Decision {
    decide_with_fault(req, policy, tier, conv, sink, None)
}

/// Decide with an injected fault (tests).
pub fn decide_with_fault(
    req: &Request,
    policy: &Policy,
    tier: Tier,
    conv: &Conversation,
    sink: &dyn RecordSink,
    fault: Option<Fault>,
) -> Decision {
    let out = catch_unwind(AssertUnwindSafe(|| core(req, policy, tier, conv, fault)))
        .unwrap_or_else(|_| Out::block(Reason::InternalError));
    finalize(req, out, &policy.hash(), tier, conv, sink, fault)
}

/// Parse and verify the policy first; an unverifiable policy blocks everything (F3), and the denial is still recorded.
pub fn decide_checked(
    policy_json: &str,
    verifier: &dyn PolicyVerifier,
    req: &Request,
    tier: Tier,
    conv: &Conversation,
    sink: &dyn RecordSink,
) -> Decision {
    match Policy::parse(policy_json, verifier) {
        Ok(p) => decide(req, &p, tier, conv, sink),
        Err(e) => {
            let _: &PolicyError = &e;
            finalize(
                req,
                Out::block(Reason::PolicyInvalid),
                "invalid",
                tier,
                conv,
                sink,
                None,
            )
        }
    }
}

fn finalize(
    req: &Request,
    mut out: Out,
    policy_hash: &str,
    tier: Tier,
    conv: &Conversation,
    sink: &dyn RecordSink,
    fault: Option<Fault>,
) -> Decision {
    let req_sha = sha256_hex(&req.body);
    let mut red_sha = out.redacted.as_ref().map(|b| sha256_hex(b));
    let label = match out.action {
        Action::Allow => "egress_allowed",
        Action::Redact => "egress_redacted",
        Action::Block => "egress_blocked",
    };
    let dets: Vec<String> = out
        .dets
        .iter()
        .map(|(d, n)| format!("{}:{n}", d.as_str()))
        .collect();
    let views: Vec<&str> = out
        .views
        .iter()
        .map(|v| v.as_str())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let detail = format!(
        "tier={} policy={} req={} red={} dest={} det={} views={} bytes_in={} bytes_out={}",
        tier.as_str(),
        policy_hash,
        req_sha,
        red_sha.clone().unwrap_or_else(|| "none".into()),
        out.dest_id.clone().unwrap_or_else(|| "none".into()),
        if dets.is_empty() {
            "none".to_string()
        } else {
            dets.join(",")
        },
        if views.is_empty() {
            "none".to_string()
        } else {
            views.join(",")
        },
        req.body.len(),
        out.redacted.as_ref().map_or(
            if out.action == Action::Allow {
                req.body.len()
            } else {
                0
            },
            Vec::len
        ),
    );
    let run = sha256_hex(
        format!(
            "{req_sha}|{policy_hash}|{}|{}|{}",
            tier.as_str(),
            out.reason.as_str(),
            red_sha.clone().unwrap_or_default()
        )
        .as_bytes(),
    );
    let rec = EvidenceRequest {
        kind: "egress.decision".into(),
        label: label.into(),
        decision: if out.action == Action::Block {
            "deny"
        } else {
            "allow"
        }
        .into(),
        reason: out.reason.as_str().into(),
        control: "egress_guard".into(),
        total: out.total,
        passed: out.total.saturating_sub(out.flagged),
        flagged: out.flagged,
        detail,
        run_id: format!("eg-{}", &run[..24]),
    };
    let written = fault != Some(Fault::Record) && sink.emit(&rec).is_ok();
    if !written {
        out.action = Action::Block;
        out.reason = Reason::RecordFailed;
        out.redacted = None;
        red_sha = None;
        out.seen_after = conv.seen.clone();
    }
    Decision {
        action: out.action,
        reason: out.reason,
        redacted: out.redacted,
        req_sha,
        red_sha,
        dets: out.dets,
        seen_after: out.seen_after,
        views: out.views,
    }
}

// ---------- the core ----------

struct Budget(usize);
impl Budget {
    fn take(&mut self, n: usize) -> Result<(), Reason> {
        if n > self.0 {
            return Err(Reason::BudgetExceeded);
        }
        self.0 -= n;
        Ok(())
    }
}

enum Node {
    Scalar(Value),
    Str(usize),
    Arr(Vec<Node>),
    Obj(Vec<(usize, Node)>),
}
struct Builder {
    strings: Vec<String>,
    keys: Vec<String>,
    scalars: Vec<String>,
    fields: usize,
    max_depth: usize,
    max_fields: usize,
}
struct Seed<'a> {
    b: &'a RefCell<Builder>,
    depth: usize,
}
impl<'de, 'a> DeserializeSeed<'de> for Seed<'a> {
    type Value = Node;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Node, D::Error> {
        {
            let mut b = self.b.borrow_mut();
            b.fields += 1;
            if self.depth > b.max_depth {
                return Err(serde::de::Error::custom("EGDEPTH"));
            }
            if b.fields > b.max_fields {
                return Err(serde::de::Error::custom("EGFIELDS"));
            }
        }
        d.deserialize_any(V {
            b: self.b,
            depth: self.depth,
        })
    }
}
struct V<'a> {
    b: &'a RefCell<Builder>,
    depth: usize,
}
impl<'de, 'a> Visitor<'de> for V<'a> {
    type Value = Node;
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a JSON value")
    }
    fn visit_unit<E>(self) -> Result<Node, E> {
        Ok(Node::Scalar(Value::Null))
    }
    fn visit_bool<E>(self, v: bool) -> Result<Node, E> {
        self.b.borrow_mut().scalars.push(v.to_string());
        Ok(Node::Scalar(Value::Bool(v)))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Node, E> {
        self.b.borrow_mut().scalars.push(v.to_string());
        Ok(Node::Scalar(Value::from(v)))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Node, E> {
        self.b.borrow_mut().scalars.push(v.to_string());
        Ok(Node::Scalar(Value::from(v)))
    }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Node, E> {
        let n = serde_json::Number::from_f64(v).ok_or_else(|| E::custom("number"))?;
        self.b.borrow_mut().scalars.push(n.to_string());
        Ok(Node::Scalar(Value::Number(n)))
    }
    fn visit_str<E>(self, v: &str) -> Result<Node, E> {
        let mut b = self.b.borrow_mut();
        b.strings.push(v.to_string());
        Ok(Node::Str(b.strings.len() - 1))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Node, A::Error> {
        let mut v = Vec::new();
        while let Some(n) = a.next_element_seed(Seed {
            b: self.b,
            depth: self.depth + 1,
        })? {
            v.push(n);
        }
        Ok(Node::Arr(v))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Node, A::Error> {
        let mut seen: HashSet<String> = HashSet::new();
        let mut v = Vec::new();
        while let Some(k) = a.next_key::<String>()? {
            if !seen.insert(k.clone()) {
                return Err(serde::de::Error::custom("EGDUP"));
            }
            let ki = {
                let mut b = self.b.borrow_mut();
                b.keys.push(k);
                b.keys.len() - 1
            };
            v.push((
                ki,
                a.next_value_seed(Seed {
                    b: self.b,
                    depth: self.depth + 1,
                })?,
            ));
        }
        Ok(Node::Obj(v))
    }
}
fn to_value(n: &Node, strings: &[String], keys: &[String]) -> Value {
    match n {
        Node::Scalar(v) => v.clone(),
        Node::Str(i) => Value::String(strings[*i].clone()),
        Node::Arr(v) => Value::Array(v.iter().map(|x| to_value(x, strings, keys)).collect()),
        Node::Obj(v) => Value::Object(
            v.iter()
                .map(|(k, x)| (keys[*k].clone(), to_value(x, strings, keys)))
                .collect(),
        ),
    }
}

struct Leaf {
    /// Joined into the cross-field view (body fields and attachments; not headers or the destination).
    join: bool,
    text: String,
    /// Index into the body strings when this leaf is a redactable body string.
    body: Option<usize>,
}
struct Found {
    det: Det,
    leaf: usize,
    raw: (usize, usize),
    view: ViewKind,
}

fn text_like(mime: &str) -> bool {
    let m = mime.to_ascii_lowercase();
    m.starts_with("text/")
        || matches!(
            m.as_str(),
            "application/json"
                | "application/xml"
                | "application/yaml"
                | "application/x-yaml"
                | "application/toml"
        )
}

fn char_of_byte(text: &str) -> Vec<usize> {
    let mut v = vec![0usize; text.len() + 1];
    for (ci, (bi, c)) in text.char_indices().enumerate() {
        for k in 0..c.len_utf8() {
            v[bi + k] = ci;
        }
    }
    v[text.len()] = text.chars().count();
    v
}
fn map_span(view: &View, s: usize, e: usize, cmap: &[usize]) -> Option<(usize, usize)> {
    let a = *cmap.get(s)?;
    let b = *cmap.get(e.saturating_sub(1).max(s))?;
    Some((view.spans.get(a)?.0, view.spans.get(b)?.1))
}

/// All hits of one text over every view, mapped to raw byte spans of that text.
type TextHit = (Det, ViewKind, (usize, usize), bool);

fn scan_text(
    text: &str,
    cfg: &DetectCfg,
    budget: &mut Budget,
    decode: bool,
    fault: Option<Fault>,
) -> Result<Vec<TextHit>, Reason> {
    if fault == Some(Fault::Detector) {
        std::panic::resume_unwind(Box::new("injected detector fault"));
    }
    let mut out = Vec::new();
    budget.take(text.len())?;
    for h in scan_kind(text, ViewKind::Raw, cfg) {
        out.push((h.det, ViewKind::Raw, (h.start, h.end), h.checksum_ok));
    }
    let f = fold(text);
    if f.text != text {
        budget.take(f.text.len())?;
        let cm = char_of_byte(&f.text);
        for h in scan_kind(&f.text, ViewKind::Folded, cfg) {
            if let Some(sp) = map_span(&f, h.start, h.end, &cm) {
                out.push((h.det, ViewKind::Folded, sp, h.checksum_ok));
            }
        }
    }
    let s = strip(text);
    budget.take(s.text.len())?;
    let cm = char_of_byte(&s.text);
    for h in scan_kind(&s.text, ViewKind::Stripped, cfg) {
        if let Some(sp) = map_span(&s, h.start, h.end, &cm) {
            // a stripped match of a key or card shape counts only if the raw text there looks like a token split into short chunks. The
            // greedy key patterns run on into whatever text follows the token (`{36,255}`, `{16,}`), so only the FIRST characters of the match
            // are judged: the part that must be the token (EG1b: a hyphen-grouped key followed by ordinary words was rejected before)
            if matches!(h.det, Det::D1 | Det::D4) {
                let mut pe = (h.start + GUARD_PREFIX).min(h.end);
                while pe < h.end && !s.text.is_char_boundary(pe) {
                    pe += 1;
                }
                let judged = map_span(&s, h.start, pe, &cm).unwrap_or(sp);
                if !plausible_chunked(&text[judged.0..judged.1]) {
                    continue;
                }
                // EG1d: the `sk` key prefix is a two-letter word of its own: when the raw text starts with a longer word (the product code `SKU GH849-EF863...`
                // joins to `SKUGH849...` in the stripped view and looked like an `sk` key), it is not a key
                if h.det == Det::D1
                    && s.text[h.start..]
                        .get(..2)
                        .is_some_and(|p| p.eq_ignore_ascii_case("sk"))
                    && text[judged.0..judged.1]
                        .chars()
                        .take_while(|c| c.is_alphanumeric())
                        .count()
                        >= 3
                {
                    continue;
                }
            }
            out.push((h.det, ViewKind::Stripped, sp, h.checksum_ok));
        }
    }
    if decode {
        for d in decoded(text) {
            budget.take(d.text.len())?;
            let kind = if matches!(d.chain.last(), Some(&"rot13") | Some(&"reverse")) {
                ViewKind::Obfuscated
            } else {
                ViewKind::Decoded
            };
            for h in scan_kind(&d.text, kind, cfg) {
                out.push((h.det, ViewKind::Decoded, d.src, h.checksum_ok));
            }
        }
    }
    Ok(out)
}

/// How many characters (bytes of the stripped view) at the start of a stripped key or card match are judged by `plausible_chunked`.
const GUARD_PREFIX: usize = 20;

/// Does this raw text look like one token cut into short chunks by separators: at least two separator runs of one or two characters, and every
/// piece between them one to six letters or digits? Ordinary prose fails this (its words are longer and its gaps are wider).
pub fn plausible_chunked(raw: &str) -> bool {
    // no separator at all: the stripped view added nothing (for example fields joined without separators), so the match is the token itself
    // (or only token punctuation such as `_` and `-`, with no whitespace: prose always has spaces between its words)
    if !raw.is_empty() && !raw.chars().any(char::is_whitespace) {
        return true;
    }
    let mut seps = 0;
    let mut run = 0;
    let mut piece = 0;
    let mut pieces: Vec<usize> = Vec::new();
    for c in raw.chars() {
        if c.is_alphanumeric() {
            if run > 0 {
                seps += 1;
                run = 0;
            }
            if piece == 0 {
                pieces.push(0);
            }
            piece += 1;
            if let Some(last) = pieces.last_mut() {
                *last = piece;
            }
            if piece > 6 {
                return false;
            }
        } else {
            if piece == 0 && run == 0 && seps == 0 {
                return false;
            }
            piece = 0;
            run += 1;
            if run > 2 {
                return false;
            }
        }
    }
    // a mechanically chunked token has groups of one regular length; short-word prose does not. Judged on the pieces between the first and the
    // last (the first may hold a prefix such as `sk-`, the last may be cut short): three CONSECUTIVE ones share one length of 3 or more
    // (prose such as "kept up to date with" has equal-length words but not three in a row).
    let inner = pieces.get(1..pieces.len().saturating_sub(1)).unwrap_or(&[]);
    let regular = inner
        .windows(3)
        .any(|w| w[0] >= 3 && w[0] == w[1] && w[1] == w[2]);
    seps >= 2 && regular
}

fn url_findings(text: &str) -> Option<Reason> {
    let mut rest = text;
    while let Some(i) = rest.find("://") {
        let before = &rest[..i];
        // the scheme starts after the last character that is not an ASCII letter; that character may be several bytes wide (EG1b: a Cyrillic
        // letter or an em dash before `http://` made `p + 1` land inside it and panicked)
        let scheme_start = before
            .char_indices()
            .rev()
            .find(|(_, c)| !c.is_ascii_alphabetic())
            .map_or(0, |(p, c)| p + c.len_utf8());
        let scheme = before[scheme_start..].to_ascii_lowercase();
        let after = &rest[i + 3..];
        let end = after
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | ')' | ']'))
            .unwrap_or(after.len());
        let url = &after[..end];
        if matches!(scheme.as_str(), "http" | "https") {
            let auth = &url[..url.find(['/', '?', '#']).unwrap_or(url.len())];
            if auth.contains('@') {
                return Some(Reason::CredentialStructure);
            }
            let host = auth.rsplit_once(':').map_or(auth, |(h, _)| h);
            for label in host.split('.') {
                let ent = {
                    let mut c: BTreeMap<char, usize> = BTreeMap::new();
                    for ch in label.chars() {
                        *c.entry(ch).or_default() += 1;
                    }
                    let n = label.chars().count().max(1) as f64;
                    c.values()
                        .map(|v| {
                            let p = *v as f64 / n;
                            -p * p.log2()
                        })
                        .sum::<f64>()
                };
                if label.len() > 63 || (label.len() >= 24 && ent >= 3.5) {
                    return Some(Reason::DnsLabelSuspect);
                }
            }
        }
        rest = &after[end.min(after.len())..];
    }
    None
}

struct Scan {
    found: Vec<Found>,
    cross: Vec<(Det, ViewKind)>,
    url: Option<Reason>,
}

fn scan_all(
    leaves: &[Leaf],
    tail: &str,
    cfg: &DetectCfg,
    budget: &mut Budget,
    fault: Option<Fault>,
) -> Result<Scan, Reason> {
    let mut found = Vec::new();
    let mut url = None;
    for (i, l) in leaves.iter().enumerate() {
        for (det, view, raw, _) in scan_text(&l.text, cfg, budget, true, fault)? {
            found.push(Found {
                det,
                leaf: i,
                raw,
                view,
            });
        }
        if url.is_none() {
            url = url_findings(&l.text);
        }
    }
    // joined view: the tail and every body field and attachment, no separators, so a split across fields or messages is seen. A match that
    // overlaps a match of the same detector already found inside one field is that same item, not a new one.
    let mut joined = String::from(tail);
    let mut ranges = vec![(0usize, joined.len())];
    let mut starts: Vec<Option<usize>> = Vec::new();
    for l in leaves {
        if l.join {
            let s = joined.len();
            joined.push_str(&l.text);
            ranges.push((s, joined.len()));
            starts.push(Some(s));
        } else {
            starts.push(None);
        }
    }
    let known: Vec<(Det, usize, usize)> = found
        .iter()
        .filter_map(|f: &Found| {
            starts
                .get(f.leaf)
                .copied()
                .flatten()
                .map(|s| (f.det, s + f.raw.0, s + f.raw.1))
        })
        .collect();
    let mut cross = Vec::new();
    if ranges.len() > 1 {
        for (det, view, raw, _) in scan_text(&joined, cfg, budget, false, None)? {
            if det == Det::D6 {
                continue;
            }
            let inside = ranges
                .iter()
                .any(|(a, b)| raw.0 >= *a && raw.1 <= *b && b > a);
            let overlaps = known
                .iter()
                .any(|(d, a, b)| *d == det && raw.0 < *b && raw.1 > *a);
            if !inside && !overlaps {
                cross.push((det, view));
            }
        }
    }
    Ok(Scan { found, cross, url })
}

fn merge(mut v: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    v.sort();
    let mut out: Vec<(usize, usize)> = Vec::new();
    for (a, b) in v {
        match out.last_mut() {
            Some(l) if a <= l.1 => l.1 = l.1.max(b),
            _ => out.push((a, b)),
        }
    }
    out
}

fn core(
    req: &Request,
    policy: &Policy,
    tier: Tier,
    conv: &Conversation,
    fault: Option<Fault>,
) -> Out {
    let lim: Limits = policy.limits(tier);
    // egress by tier
    if !policy.allows_egress(tier) {
        return Out::block(Reason::TierNoEgress);
    }
    // destination: exact, closed list
    let Some(dest) = policy.destination(&req.destination, tier) else {
        return Out::block(Reason::DestinationDenied);
    };
    let dest_id = dest.id.clone();
    let blk = |r: Reason| Out {
        dest_id: Some(dest_id.clone()),
        ..Out::block(r)
    };
    if fault == Some(Fault::Limits) {
        return blk(Reason::InternalError);
    }
    // limits
    if req.body.len() > lim.bytes || req.attachments.len() > lim.attachments {
        return blk(Reason::SizeLimit);
    }
    if req.attachments.iter().any(|a| !text_like(&a.mime)) {
        return blk(Reason::AttachmentTypeDenied);
    }
    if req
        .attachments
        .iter()
        .any(|a| a.bytes.len() > lim.attachment_bytes)
    {
        return blk(Reason::SizeLimit);
    }
    let input_bytes = req.body.len()
        + req.attachments.iter().map(|a| a.bytes.len()).sum::<usize>()
        + conv.tail.len().min(lim.tail_bytes);
    let mut budget = Budget(if fault == Some(Fault::Budget) {
        0
    } else {
        input_bytes.saturating_mul(24).saturating_add(65_536)
    });
    if fault == Some(Fault::Parser) {
        return blk(Reason::InternalError);
    }
    // canonical request: strict parse
    let Ok(body) = std::str::from_utf8(&req.body) else {
        return blk(Reason::MalformedRequest);
    };
    if body.contains('\0') {
        return blk(Reason::MalformedRequest);
    }
    let mut leaves: Vec<Leaf> = Vec::new();
    let mut tree: Option<(Node, Builder)> = None;
    if req.body_is_json {
        let b = RefCell::new(Builder {
            strings: vec![],
            keys: vec![],
            scalars: vec![],
            fields: 0,
            max_depth: lim.depth,
            max_fields: lim.fields,
        });
        let mut de = serde_json::Deserializer::from_str(body);
        let r = Seed { b: &b, depth: 1 }
            .deserialize(&mut de)
            .and_then(|n| de.end().map(|_| n));
        match r {
            Ok(n) => {
                let b = b.into_inner();
                for (i, s) in b.strings.iter().enumerate() {
                    leaves.push(Leaf {
                        join: true,
                        text: s.clone(),
                        body: Some(i),
                    });
                }
                for s in b.keys.iter().chain(b.scalars.iter()) {
                    leaves.push(Leaf {
                        join: true,
                        text: s.clone(),
                        body: None,
                    });
                }
                tree = Some((n, b));
            }
            Err(e) => {
                let m = e.to_string();
                return blk(if m.starts_with("EGDEPTH") || m.starts_with("EGFIELDS") {
                    Reason::SizeLimit
                } else {
                    Reason::MalformedRequest
                });
            }
        }
    } else {
        leaves.push(Leaf {
            join: true,
            text: body.to_string(),
            body: Some(0),
        });
    }
    for (n, v) in &req.headers {
        leaves.push(Leaf {
            join: false,
            text: format!("{n}: {v}"),
            body: None,
        });
    }
    for a in &req.attachments {
        let Ok(t) = std::str::from_utf8(&a.bytes) else {
            return blk(Reason::MalformedRequest);
        };
        if t.contains('\0') {
            return blk(Reason::MalformedRequest);
        }
        leaves.push(Leaf {
            join: true,
            text: t.to_string(),
            body: None,
        });
    }
    leaves.push(Leaf {
        join: false,
        text: req.destination.clone(),
        body: None,
    });
    // NUL in ANY canonical text is malformed (EG0 section 4 step 1). The raw-body test above cannot see a JSON escape (`\u0000`), a header
    // value or a key: they become NUL only after parsing, so the check runs over every leaf (EG1b; the sealed run allowed 25 of 25).
    if leaves.iter().any(|l| l.text.contains('\0')) {
        return blk(Reason::MalformedRequest);
    }
    if fault == Some(Fault::Views) {
        return blk(Reason::InternalError);
    }
    let tail: String = {
        let t = &conv.tail;
        let mut s = t.len().saturating_sub(lim.tail_bytes);
        while s < t.len() && !t.is_char_boundary(s) {
            s += 1;
        }
        t[s..].to_string()
    };
    let cfg = policy.detect_cfg();
    let scan = match scan_all(&leaves, &tail, cfg, &mut budget, fault) {
        Ok(s) => s,
        Err(r) => return blk(r),
    };
    // rules
    let mut dets: BTreeMap<Det, u32> = BTreeMap::new();
    let mut views: BTreeSet<ViewKind> = BTreeSet::new();
    let mut per_det: BTreeMap<Det, Vec<(usize, usize, usize)>> = BTreeMap::new();
    for f in &scan.found {
        per_det
            .entry(f.det)
            .or_default()
            .push((f.leaf, f.raw.0, f.raw.1));
        views.insert(f.view);
    }
    let mut flagged_leaves: BTreeSet<usize> = BTreeSet::new();
    for (d, v) in &per_det {
        let mut n = 0;
        let mut by_leaf: BTreeMap<usize, Vec<(usize, usize)>> = BTreeMap::new();
        for (l, a, b) in v {
            by_leaf.entry(*l).or_default().push((*a, *b));
            flagged_leaves.insert(*l);
        }
        for (_, spans) in by_leaf {
            n += merge(spans).len() as u32;
        }
        dets.insert(*d, n);
    }
    for (d, v) in &scan.cross {
        *dets.entry(*d).or_default() += 1;
        views.insert(*v);
    }
    let total = leaves.len() as u64;
    let mut flagged = flagged_leaves.len() as u64;
    if !scan.cross.is_empty() {
        flagged += 1;
    }
    let base = |action: Action, reason: Reason| Out {
        action,
        reason,
        redacted: None,
        dets: dets.clone(),
        views: views.clone(),
        seen_after: conv.seen.clone(),
        total,
        flagged,
        dest_id: Some(dest_id.clone()),
    };
    if let Some(r) = scan.url {
        return base(Action::Block, r);
    }
    let strictest = |d: Det| policy.mode(tier, d);
    let blocking: Vec<Det> = dets
        .keys()
        .copied()
        .filter(|d| strictest(*d) == Mode::Block)
        .collect();
    let cross_active: Vec<Det> = scan
        .cross
        .iter()
        .map(|(d, _)| *d)
        .filter(|d| strictest(*d) != Mode::AllowWithRecord)
        .collect();
    if let Some(d) = PRIORITY
        .iter()
        .copied()
        .find(|d| blocking.contains(d) || cross_active.contains(d))
    {
        return base(Action::Block, det_reason(d));
    }
    // redact-mode hits: only body strings can be rewritten; anything else is a block
    let mut spans_by_leaf: BTreeMap<usize, Vec<(usize, usize, Det)>> = BTreeMap::new();
    for f in &scan.found {
        if strictest(f.det) == Mode::Redact {
            if leaves[f.leaf].body.is_none() {
                return base(Action::Block, det_reason(f.det));
            }
            spans_by_leaf
                .entry(f.leaf)
                .or_default()
                .push((f.raw.0, f.raw.1, f.det));
        }
    }
    if fault == Some(Fault::Redactor) {
        return base(Action::Block, Reason::InternalError);
    }
    if fault == Some(Fault::Recheck) {
        return base(Action::Block, Reason::InternalError);
    }
    if spans_by_leaf.is_empty() {
        let reason = PRIORITY
            .iter()
            .copied()
            .find(|d| dets.contains_key(d))
            .map_or(Reason::Clean, det_reason);
        return base(Action::Allow, reason);
    }
    // redaction with stable placeholders
    let mut list: Vec<String> = conv.seen.clone();
    let mut new_strings: BTreeMap<usize, String> = BTreeMap::new();
    for (li, spans) in &spans_by_leaf {
        let text = &leaves[*li].text;
        let merged = merge(spans.iter().map(|(a, b, _)| (*a, *b)).collect());
        let mut out = String::new();
        let mut at = 0;
        for (a, b) in merged {
            let det = spans
                .iter()
                .filter(|(x, y, _)| *x < b && *y > a)
                .map(|(_, _, d)| *d)
                .min()
                .unwrap_or(Det::D1);
            let norm: String = strip(&text[a..b]).text;
            let mut h = Sha256::new();
            h.update(&conv.key);
            h.update(class(det).as_bytes());
            h.update(norm.as_bytes());
            let entry = format!("{}:{}", class(det), &hex::encode(h.finalize())[..16]);
            if !list.contains(&entry) {
                list.push(entry.clone());
            }
            let prefix = format!("{}:", class(det));
            let n = list
                .iter()
                .filter(|e| e.starts_with(&prefix))
                .position(|e| *e == entry)
                .map_or(1, |p| p + 1);
            out.push_str(&text[at..a]);
            out.push_str(&format!("[[EG:{}:{n}]]", class(det)));
            at = b;
        }
        out.push_str(&text[at..]);
        new_strings.insert(*li, out);
    }
    let redacted_body: String = if let Some((node, b)) = &tree {
        let mut strings = b.strings.clone();
        for (li, s) in &new_strings {
            if let Some(bi) = leaves[*li].body {
                strings[bi] = s.clone();
            }
        }
        serde_json::to_string(&to_value(node, &strings, &b.keys)).unwrap_or_default()
    } else {
        new_strings.values().next().cloned().unwrap_or_default()
    };
    // re-check
    let mut leaves2: Vec<Leaf> = Vec::new();
    if let Some((node, b)) = &tree {
        let mut strings = b.strings.clone();
        for (li, s) in &new_strings {
            if let Some(bi) = leaves[*li].body {
                strings[bi] = s.clone();
            }
        }
        for s in strings.iter().chain(b.keys.iter()).chain(b.scalars.iter()) {
            leaves2.push(Leaf {
                join: true,
                text: s.clone(),
                body: None,
            });
        }
        let _ = node;
    } else {
        leaves2.push(Leaf {
            join: true,
            text: redacted_body.clone(),
            body: None,
        });
    }
    match scan_all(&leaves2, &tail, cfg, &mut budget, None) {
        Ok(s2) => {
            let residual = s2
                .found
                .iter()
                .any(|f| strictest(f.det) != Mode::AllowWithRecord)
                || s2
                    .cross
                    .iter()
                    .any(|(d, _)| strictest(*d) != Mode::AllowWithRecord);
            if residual {
                return base(Action::Block, Reason::ResidualAfterRedaction);
            }
        }
        Err(r) => return base(Action::Block, r),
    }
    Out {
        action: Action::Redact,
        reason: Reason::Redacted,
        redacted: Some(redacted_body.into_bytes()),
        dets,
        views,
        seen_after: list,
        total,
        flagged,
        dest_id: Some(dest_id),
    }
}

#[allow(dead_code)]
fn _use(_: &str) -> Option<crate::policy::ParsedUrl> {
    parse_url("")
}
