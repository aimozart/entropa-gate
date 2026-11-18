//! Design C: an append-only chain of signed blocks. The root is signed by the issuer and commits to an ephemeral public key; the holder
//! appends blocks that can only narrow, each signed by the key the previous block committed to and chained to the previous signature.

use crate::canon::{parse, write, Json};
use crate::claims::{check_narrower, is_hex, Claims, Tier, MAX_ACTIONS, MAX_CORPORA};
use crate::design_a::canon_deny;
use crate::revoke::check_revocation;
use crate::verify::{check_policy, digest, key_id_of, sig_ok, Deny, Policy, Trust, Verified, ALG};
use crate::IssueError;
use entropa_core::Probe;

/// Largest design C token accepted (bytes).
pub const MAX_C_BYTES: usize = 256 * 1024;
/// Most appended blocks (the root is not counted).
pub const MAX_BLOCKS: usize = 7;

/// A holder's token and the secret key that may sign the next block.
pub struct Wallet {
    /// The token bytes.
    pub token: Vec<u8>,
    /// The ephemeral key committed to by the last block.
    pub key: Probe,
}

/// What a block narrows. A field left `None` is inherited.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Narrowing {
    /// A lower or equal tier.
    pub tier: Option<Tier>,
    /// A subset of the corpora.
    pub corpora: Option<Vec<String>>,
    /// A subset of the actions.
    pub actions: Option<Vec<String>>,
    /// A lower or equal spend cap.
    pub spend_cap: Option<u64>,
    /// A lower or equal rate cap.
    pub rate_cap: Option<u64>,
    /// A later or equal start.
    pub not_before: Option<u64>,
    /// An earlier or equal expiry.
    pub expiry: Option<u64>,
}

const NARROW_KEYS: [&str; 7] = [
    "tier",
    "corpora",
    "actions",
    "spend_cap",
    "rate_cap",
    "not_before",
    "expiry",
];

impl Narrowing {
    fn to_json(&self) -> Json {
        let strs = |v: &[String]| Json::Array(v.iter().cloned().map(Json::Str).collect());
        let mut o: Vec<(String, Json)> = Vec::new();
        if let Some(t) = self.tier {
            o.push(("tier".into(), Json::Str(t.as_str().into())));
        }
        if let Some(c) = &self.corpora {
            o.push(("corpora".into(), strs(c)));
        }
        if let Some(a) = &self.actions {
            o.push(("actions".into(), strs(a)));
        }
        if let Some(n) = self.spend_cap {
            o.push(("spend_cap".into(), Json::Num(n)));
        }
        if let Some(n) = self.rate_cap {
            o.push(("rate_cap".into(), Json::Num(n)));
        }
        if let Some(n) = self.not_before {
            o.push(("not_before".into(), Json::Num(n)));
        }
        if let Some(n) = self.expiry {
            o.push(("expiry".into(), Json::Num(n)));
        }
        Json::Object(o)
    }

    fn from_json(j: &Json) -> Result<Narrowing, Deny> {
        if !j.has_only(&NARROW_KEYS) {
            return Err(Deny::Malformed);
        }
        let list =
            |k: &str, max: usize, ok: &dyn Fn(&str) -> bool| -> Result<Option<Vec<String>>, Deny> {
                match j.get(k) {
                    None => Ok(None),
                    Some(Json::Array(a)) if a.len() <= max => {
                        let v: Vec<String> = a
                            .iter()
                            .map(|x| x.as_str().map(String::from).ok_or(Deny::Malformed))
                            .collect::<Result<_, _>>()?;
                        if !v.iter().all(|s| ok(s)) || !v.windows(2).all(|w| w[0] < w[1]) {
                            return Err(Deny::Malformed);
                        }
                        Ok(Some(v))
                    }
                    _ => Err(Deny::Malformed),
                }
            };
        let num = |k: &str| -> Result<Option<u64>, Deny> {
            match j.get(k) {
                None => Ok(None),
                Some(Json::Num(n)) => Ok(Some(*n)),
                _ => Err(Deny::Malformed),
            }
        };
        let tier = match j.get("tier") {
            None => None,
            Some(Json::Str(s)) => Some(Tier::parse(s).ok_or(Deny::Malformed)?),
            _ => return Err(Deny::Malformed),
        };
        let name_ok = |s: &str| {
            !s.is_empty()
                && s.len() <= 64
                && s.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._:-".contains(&c))
        };
        Ok(Narrowing {
            tier,
            corpora: list("corpora", MAX_CORPORA, &|s| is_hex(s, 64))?,
            actions: list("actions", MAX_ACTIONS, &name_ok)?,
            spend_cap: num("spend_cap")?,
            rate_cap: num("rate_cap")?,
            not_before: num("not_before")?,
            expiry: num("expiry")?,
        })
    }
}

/// Apply a narrowing to the current effective claims; refuses any widening.
fn apply(cur: &Claims, n: &Narrowing) -> Result<Claims, Deny> {
    let mut next = cur.clone();
    if let Some(t) = n.tier {
        next.tier = t;
    }
    if let Some(c) = &n.corpora {
        next.corpora = c.clone();
    }
    if let Some(a) = &n.actions {
        next.actions = a.clone();
    }
    if let Some(v) = n.spend_cap {
        next.spend_cap = v;
    }
    if let Some(v) = n.rate_cap {
        next.rate_cap = v;
    }
    if let Some(v) = n.not_before {
        next.not_before = v;
    }
    if let Some(v) = n.expiry {
        next.expiry = v;
    }
    check_narrower(cur, &next).map_err(|_| Deny::Widened)?;
    next.validate().map_err(|_| Deny::Malformed)?;
    Ok(next)
}

fn pk_ok(s: &str) -> bool {
    key_id_of(s).is_some()
}

fn prev_of(sig: &str) -> String {
    hex::encode(blake3::hash(sig.as_bytes()).as_bytes())
}

fn root_message(claims: &Json, key_id: &str, next_pubkey: &str) -> Json {
    Json::Object(vec![
        ("alg".into(), Json::Str(ALG.into())),
        ("claims".into(), claims.clone()),
        ("key_id".into(), Json::Str(key_id.into())),
        ("next_pubkey".into(), Json::Str(next_pubkey.into())),
        ("v".into(), Json::Num(1)),
    ])
}

fn block_message(narrow: &Json, next_pubkey: &str, prev: &str) -> Json {
    Json::Object(vec![
        ("narrow".into(), narrow.clone()),
        ("next_pubkey".into(), Json::Str(next_pubkey.into())),
        ("prev".into(), Json::Str(prev.into())),
    ])
}

fn top(key_id: &str, root_claims: &Json, next_pubkey: &str, sig: &str, blocks: Vec<Json>) -> Json {
    Json::Object(vec![
        ("alg".into(), Json::Str(ALG.into())),
        ("blocks".into(), Json::Array(blocks)),
        ("key_id".into(), Json::Str(key_id.into())),
        (
            "root".into(),
            Json::Object(vec![
                ("claims".into(), root_claims.clone()),
                ("next_pubkey".into(), Json::Str(next_pubkey.into())),
                ("sig".into(), Json::Str(sig.into())),
            ]),
        ),
        ("v".into(), Json::Num(1)),
    ])
}

/// Sign a root token. The holder receives the secret for the committed ephemeral key.
pub fn issue_c(issuer: &Probe, claims: &Claims) -> Result<Wallet, IssueError> {
    claims.validate().map_err(IssueError::InvalidClaims)?;
    let kid = key_id_of(&issuer.pubkey_hex()).ok_or(IssueError::KeyMismatch)?;
    let eph = Probe::spawn();
    let next = eph.pubkey_hex();
    let cj = claims.to_json();
    let sig = issuer.sign_hex(&digest("c-root", &write(&root_message(&cj, &kid, &next))));
    let bytes = write(&top(&kid, &cj, &next, &sig, Vec::new()));
    if bytes.len() > MAX_C_BYTES {
        return Err(IssueError::TooLarge);
    }
    Ok(Wallet {
        token: bytes,
        key: eph,
    })
}

struct Block {
    narrow: Narrowing,
    narrow_json: Json,
    next_pubkey: String,
    prev: String,
    sig: String,
}

struct ParsedC {
    key_id: String,
    root_claims: Claims,
    root_json: Json,
    root_next: String,
    root_sig: String,
    blocks: Vec<Block>,
}

fn parse_c(bytes: &[u8]) -> Result<ParsedC, Deny> {
    if bytes.len() > MAX_C_BYTES {
        return Err(Deny::TooLarge);
    }
    let j = parse(bytes).map_err(canon_deny)?;
    if write(&j) != bytes {
        return Err(Deny::NotCanonical);
    }
    if !j.has_exactly(&["alg", "blocks", "key_id", "root", "v"]) {
        return Err(Deny::Malformed);
    }
    match j.get("alg").and_then(Json::as_str) {
        Some(a) if a == ALG => {}
        Some(_) => return Err(Deny::BadAlgorithm),
        None => return Err(Deny::Malformed),
    }
    if j.get("v").and_then(Json::as_u64) != Some(1) {
        return Err(Deny::Malformed);
    }
    let key_id = j
        .get("key_id")
        .and_then(Json::as_str)
        .filter(|k| is_hex(k, 16))
        .ok_or(Deny::Malformed)?
        .to_string();
    let root = j
        .get("root")
        .filter(|r| r.has_exactly(&["claims", "next_pubkey", "sig"]))
        .ok_or(Deny::Malformed)?;
    let root_json = root.get("claims").ok_or(Deny::Malformed)?.clone();
    let root_claims = Claims::from_json(&root_json)?;
    let root_next = root
        .get("next_pubkey")
        .and_then(Json::as_str)
        .filter(|s| pk_ok(s))
        .ok_or(Deny::Malformed)?
        .to_string();
    let root_sig = root
        .get("sig")
        .and_then(Json::as_str)
        .ok_or(Deny::Malformed)?
        .to_string();
    let Some(Json::Array(bl)) = j.get("blocks") else {
        return Err(Deny::Malformed);
    };
    if bl.len() > MAX_BLOCKS {
        return Err(Deny::TooManyBlocks);
    }
    let mut blocks = Vec::new();
    for b in bl {
        if !b.has_exactly(&["narrow", "next_pubkey", "prev", "sig"]) {
            return Err(Deny::Malformed);
        }
        let narrow_json = b.get("narrow").ok_or(Deny::Malformed)?.clone();
        blocks.push(Block {
            narrow: Narrowing::from_json(&narrow_json)?,
            narrow_json,
            next_pubkey: b
                .get("next_pubkey")
                .and_then(Json::as_str)
                .filter(|s| pk_ok(s))
                .ok_or(Deny::Malformed)?
                .to_string(),
            prev: b
                .get("prev")
                .and_then(Json::as_str)
                .filter(|s| is_hex(s, 64))
                .ok_or(Deny::Malformed)?
                .to_string(),
            sig: b
                .get("sig")
                .and_then(Json::as_str)
                .ok_or(Deny::Malformed)?
                .to_string(),
        });
    }
    Ok(ParsedC {
        key_id,
        root_claims,
        root_json,
        root_next,
        root_sig,
        blocks,
    })
}

/// Walk the chain: every signature under the key the previous block committed to, every block chained to the previous signature, every block
/// narrower than the effective claims so far. Returns the effective claims.
fn walk(t: &ParsedC, trust: &Trust) -> Result<Claims, Deny> {
    let pk = trust.get(&t.key_id).ok_or(Deny::UnknownKey)?;
    let rd = digest(
        "c-root",
        &write(&root_message(&t.root_json, &t.key_id, &t.root_next)),
    );
    if !sig_ok(pk, &rd, &t.root_sig) {
        return Err(Deny::BadSignature);
    }
    let mut eff = t.root_claims.clone();
    let mut signer_pk = t.root_next.clone();
    let mut prev_sig = t.root_sig.clone();
    for b in &t.blocks {
        let want_prev = prev_of(&prev_sig);
        if b.prev != want_prev {
            return Err(Deny::BadSignature);
        }
        let d = digest(
            "c-block",
            &write(&block_message(&b.narrow_json, &b.next_pubkey, &b.prev)),
        );
        if !sig_ok(&signer_pk, &d, &b.sig) {
            return Err(Deny::BadSignature);
        }
        eff = apply(&eff, &b.narrow)?;
        signer_pk = b.next_pubkey.clone();
        prev_sig = b.sig.clone();
    }
    Ok(eff)
}

/// Verify a design C token offline.
pub fn verify_c(
    bytes: &[u8],
    trust: &Trust,
    policy: &Policy,
    revocations: Option<&[u8]>,
) -> Result<Verified, Deny> {
    let t = parse_c(bytes)?;
    let eff = walk(&t, trust)?;
    check_policy(&eff, policy)?;
    let mut ids: Vec<&str> = vec![t.root_claims.token_id.as_str()];
    if let Some(p) = &t.root_claims.parent {
        ids.push(p.as_str());
    }
    check_revocation(&ids, revocations, trust, policy)?;
    Ok(Verified {
        token_id: t.root_claims.token_id.clone(),
        chain_len: 1 + t.blocks.len(),
        claims: eff,
    })
}

/// Append a block signed by `signer`. `check_narrow` refuses a widening block; `check_key` requires `signer` to be the committed key.
pub(crate) fn append_impl(
    w: &Wallet,
    n: &Narrowing,
    signer: &Probe,
    check_narrow: bool,
    check_key: bool,
    check_limit: bool,
    commit: Option<&str>,
) -> Result<Wallet, IssueError> {
    let t = parse_c(&w.token).map_err(|_| IssueError::Parse)?;
    if check_limit && t.blocks.len() >= MAX_BLOCKS {
        return Err(IssueError::TooManyBlocks);
    }
    let committed = t
        .blocks
        .last()
        .map_or(&t.root_next, |b| &b.next_pubkey)
        .clone();
    if check_key && signer.pubkey_hex() != committed {
        return Err(IssueError::KeyMismatch);
    }
    if check_narrow {
        let mut eff = t.root_claims.clone();
        for b in &t.blocks {
            eff = apply(&eff, &b.narrow).map_err(|_| IssueError::Parse)?;
        }
        apply(&eff, n).map_err(|_| IssueError::Widened("a field"))?;
    }
    let prev_sig = t.blocks.last().map_or(&t.root_sig, |b| &b.sig).clone();
    let prev = prev_of(&prev_sig);
    let eph = Probe::spawn();
    let next = commit.map_or_else(|| eph.pubkey_hex(), String::from);
    let nj = n.to_json();
    let sig = signer.sign_hex(&digest(
        "c-block",
        &write(&block_message(&nj, &next, &prev)),
    ));
    let mut blocks: Vec<Json> = t
        .blocks
        .iter()
        .map(|b| {
            Json::Object(vec![
                ("narrow".into(), b.narrow_json.clone()),
                ("next_pubkey".into(), Json::Str(b.next_pubkey.clone())),
                ("prev".into(), Json::Str(b.prev.clone())),
                ("sig".into(), Json::Str(b.sig.clone())),
            ])
        })
        .collect();
    blocks.push(Json::Object(vec![
        ("narrow".into(), nj),
        ("next_pubkey".into(), Json::Str(next)),
        ("prev".into(), Json::Str(prev)),
        ("sig".into(), Json::Str(sig)),
    ]));
    let bytes = write(&top(
        &t.key_id,
        &t.root_json,
        &t.root_next,
        &t.root_sig,
        blocks,
    ));
    if bytes.len() > MAX_C_BYTES {
        return Err(IssueError::TooLarge);
    }
    Ok(Wallet {
        token: bytes,
        key: eph,
    })
}

/// Append a narrowing block with the holder's key. A widening block is refused.
pub fn append_c(w: &Wallet, n: &Narrowing) -> Result<Wallet, IssueError> {
    append_impl(w, n, &w.key, true, true, true, None)
}
