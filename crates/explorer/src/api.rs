//! The routes. Every function here is pure over the verified bundle and answers canonical JSON.

use crate::canon::canonical;
use crate::query::{self, BadQuery, MAX_CURSOR};
use crate::Limits;
use entropa_ledger::{Handle, Tenant};
use serde_json::{json, Map, Value};

/// Kinds that appear in a bundle (the ledger's own three plus the approval and policy records).
const KINDS: [&str; 8] = [
    "agent.invocation",
    "tx.screened",
    "directory.actor",
    "policy.decision",
    "approval.request",
    "approval.approve",
    "approval.deny",
    "approval.consume",
];
const DEFAULT_PAGE: usize = 20;

/// How long a client may keep an answer.
#[derive(Clone, Copy)]
pub(crate) enum Cache {
    /// Addressed by index or size: never changes.
    Immutable,
    /// Changes when the log grows.
    Short,
}

/// A routed answer: status, body, cache class (errors are never cached).
pub(crate) struct Answer {
    pub status: u16,
    pub body: String,
    pub cache: Option<Cache>,
}

pub(crate) fn error(status: u16, code: &str) -> Answer {
    Answer {
        status,
        body: canonical(&json!({ "error": code })),
        cache: None,
    }
}

fn bad() -> Answer {
    error(400, "bad_request")
}

fn not_found() -> Answer {
    error(404, "not_found")
}

fn ok(v: &Value, cache: Option<Cache>) -> Answer {
    Answer {
        status: 200,
        body: canonical(v),
        cache,
    }
}

/// The verified bundle, split into the parts the routes need.
pub(crate) struct Data {
    head: Value,
    log: Value,
    checkpoints: Vec<Value>,
    records: Vec<Value>,
    summaries: Vec<Value>,
    receipts: Vec<Value>,
    consistency: Vec<Value>,
    witnesses: Vec<Value>,
    actors: Vec<Value>,
}

fn array(v: &Value, key: &str) -> Result<Vec<Value>, String> {
    v.get(key)
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| format!("bundle has no array {key}"))
}

impl Data {
    pub(crate) fn from_value(v: &Value) -> Result<Data, String> {
        let records = array(v, "records")?;
        let mut summaries = Vec::with_capacity(records.len());
        for r in &records {
            let mut m = Map::new();
            for k in ["handle", "index", "kind", "summary", "tenant", "ts"] {
                m.insert(
                    k.to_string(),
                    r.get(k).cloned().ok_or("record field missing")?,
                );
            }
            summaries.push(Value::Object(m));
        }
        let mut witnesses = Vec::new();
        for w in array(v, "witnesses")? {
            let text = w.as_str().ok_or("witness is not a string")?;
            witnesses.push(serde_json::from_str(text).map_err(|_| "witness is not JSON")?);
        }
        Ok(Data {
            head: v.get("head").cloned().ok_or("no head")?,
            log: v.get("log").cloned().ok_or("no log")?,
            checkpoints: array(v, "checkpoints")?,
            summaries,
            receipts: array(v, "receipts")?,
            consistency: array(v, "consistency")?,
            actors: array(v, "actors")?,
            records,
            witnesses,
        })
    }
}

fn head_size(d: &Data) -> u64 {
    d.head.get("size").and_then(Value::as_u64).unwrap_or(0)
}

/// Route one validated path (segments after `/api/`).
pub(crate) fn route(d: &Data, limits: &Limits, segs: &[&str], q: &str) -> Answer {
    match segs {
        ["healthz"] => no_query(q).map_or_else(|e| e, |()| ok(&json!({ "status": "ok" }), None)),
        ["head"] => no_query(q).map_or_else(
            |e| e,
            |()| ok(&json!({ "checkpoint": d.head, "log": d.log, "size": head_size(d), "synthetic": true }), Some(Cache::Short)),
        ),
        ["checkpoints"] => checkpoints(d, limits, q),
        ["records"] => records(d, limits, q),
        ["records", i] => no_query(q).map_or_else(|e| e, |()| index(i, &d.records).map_or_else(not_found, |r| ok(r, Some(Cache::Immutable)))),
        ["receipts", i] => receipt(d, i, q),
        ["consistency"] => consistency(d, q),
        ["witnesses"] => witnesses(d, q),
        ["actors"] => no_query(q).map_or_else(|e| e, |()| ok(&json!({ "items": d.actors }), Some(Cache::Short))),
        ["actors", h] => no_query(q).map_or_else(|e| e, |()| actor(d, h)),
        ["feeds", t] => no_query(q).map_or_else(|e| e, |()| feed(d, t)),
        _ => not_found(),
    }
}

fn no_query(q: &str) -> Result<(), Answer> {
    if q.is_empty() {
        Ok(())
    } else {
        Err(bad())
    }
}

fn index<'a>(seg: &str, items: &'a [Value]) -> Option<&'a Value> {
    items.get(usize::try_from(query::decimal(seg)?).ok()?)
}

/// `limit` and `cursor` from an already parsed query.
fn paging(q: &[(&str, &str)], limits: &Limits) -> Result<(usize, Option<u64>), BadQuery> {
    let limit = match query::get(q, "limit") {
        None => DEFAULT_PAGE.min(limits.max_page),
        Some(s) => {
            let n = query::decimal(s).ok_or(BadQuery)?;
            let n = usize::try_from(n).map_err(|_| BadQuery)?;
            if n == 0 || n > limits.max_page {
                return Err(BadQuery);
            }
            n
        }
    };
    let cursor = match query::get(q, "cursor") {
        None => None,
        Some(s) => Some(
            query::decimal(s)
                .filter(|c| *c <= MAX_CURSOR)
                .ok_or(BadQuery)?,
        ),
    };
    Ok((limit, cursor))
}

/// Newest first over `(position, item)` pairs whose position is below the cursor.
/// The next cursor is the lowest position returned, when older items remain.
fn page(items: &[(u64, &Value)], limit: usize, cursor: Option<u64>) -> (Vec<Value>, Option<u64>) {
    let below: Vec<&(u64, &Value)> = items
        .iter()
        .rev()
        .filter(|(p, _)| cursor.is_none_or(|c| *p < c))
        .collect();
    let out: Vec<Value> = below
        .iter()
        .take(limit)
        .map(|(_, v)| (*v).clone())
        .collect();
    let next = if below.len() > limit {
        below.get(limit - 1).map(|(p, _)| *p)
    } else {
        None
    };
    (out, next)
}

fn checkpoints(d: &Data, limits: &Limits, q: &str) -> Answer {
    let Ok(parsed) = query::parse(q, &["limit", "cursor"]) else {
        return bad();
    };
    let Ok((limit, cursor)) = paging(&parsed, limits) else {
        return bad();
    };
    let items: Vec<(u64, &Value)> = d
        .checkpoints
        .iter()
        .enumerate()
        .map(|(i, v)| (i as u64, v))
        .collect();
    let (items, next) = page(&items, limit, cursor);
    ok(
        &json!({ "items": items, "next_cursor": next }),
        Some(Cache::Short),
    )
}

fn records(d: &Data, limits: &Limits, q: &str) -> Answer {
    let Ok(parsed) = query::parse(q, &["limit", "cursor", "tenant", "actor", "kind"]) else {
        return bad();
    };
    let Ok((limit, cursor)) = paging(&parsed, limits) else {
        return bad();
    };
    let tenant = query::get(&parsed, "tenant");
    let actor = query::get(&parsed, "actor");
    let kind = query::get(&parsed, "kind");
    if tenant.is_some_and(|t| Tenant::parse(t).is_none())
        || actor.is_some_and(|a| Handle::parse(a).is_none())
        || kind.is_some_and(|k| !KINDS.contains(&k))
    {
        return bad();
    }
    let matches = |v: &Value, key: &str, want: Option<&str>| {
        want.is_none_or(|w| v.get(key).and_then(Value::as_str) == Some(w))
    };
    let items: Vec<(u64, &Value)> = d
        .summaries
        .iter()
        .filter(|s| {
            matches(s, "tenant", tenant) && matches(s, "handle", actor) && matches(s, "kind", kind)
        })
        .filter_map(|s| Some((s.get("index")?.as_u64()?, s)))
        .collect();
    let (items, next) = page(&items, limit, cursor);
    ok(
        &json!({ "items": items, "next_cursor": next }),
        Some(Cache::Short),
    )
}

fn receipt(d: &Data, seg: &str, q: &str) -> Answer {
    let Ok(parsed) = query::parse(q, &["size"]) else {
        return bad();
    };
    let size = match query::get(&parsed, "size") {
        None => None,
        Some(s) => match query::decimal(s) {
            Some(n) => Some(n),
            None => return bad(),
        },
    };
    if size.is_some_and(|n| n != head_size(d)) {
        return not_found();
    }
    let (Some(rec), Some(rc)) = (index(seg, &d.records), index(seg, &d.receipts)) else {
        return not_found();
    };
    let body = json!({
        "checkpoint": d.head,
        "index": rc.get("index"),
        "proof": rc.get("proof"),
        "record_hex": rec.get("record_hex"),
    });
    ok(&body, Some(Cache::Immutable))
}

fn consistency(d: &Data, q: &str) -> Answer {
    let Ok(parsed) = query::parse(q, &["old", "new"]) else {
        return bad();
    };
    let (Some(old), Some(new)) = (
        query::get(&parsed, "old").and_then(query::decimal),
        query::get(&parsed, "new").and_then(query::decimal),
    ) else {
        return bad();
    };
    let found = d.consistency.iter().find(|c| {
        c.get("old_size").and_then(Value::as_u64) == Some(old)
            && c.get("new_size").and_then(Value::as_u64) == Some(new)
    });
    found.map_or_else(not_found, |c| ok(c, Some(Cache::Immutable)))
}

fn witnesses(d: &Data, q: &str) -> Answer {
    let Ok(parsed) = query::parse(q, &["size"]) else {
        return bad();
    };
    let size = match query::get(&parsed, "size") {
        None => None,
        Some(s) => match query::decimal(s) {
            Some(n) => Some(n),
            None => return bad(),
        },
    };
    let items: Vec<&Value> = d
        .witnesses
        .iter()
        .filter(|w| size.is_none_or(|n| w.get("size").and_then(Value::as_u64) == Some(n)))
        .collect();
    ok(&json!({ "items": items }), Some(Cache::Short))
}

fn actor(d: &Data, handle: &str) -> Answer {
    if Handle::parse(handle).is_none() {
        return not_found();
    }
    let Some(a) = d
        .actors
        .iter()
        .find(|a| a.get("handle").and_then(Value::as_str) == Some(handle))
    else {
        return not_found();
    };
    let mut kinds: std::collections::BTreeMap<&str, u64> = std::collections::BTreeMap::new();
    let mut n = 0u64;
    for s in d
        .summaries
        .iter()
        .filter(|s| s.get("handle").and_then(Value::as_str) == Some(handle))
    {
        n += 1;
        if let Some(k) = s.get("kind").and_then(Value::as_str) {
            *kinds.entry(k).or_insert(0) += 1;
        }
    }
    ok(
        &json!({ "actor": a, "kinds": kinds, "records": n }),
        Some(Cache::Short),
    )
}

fn feed(d: &Data, tenant: &str) -> Answer {
    if Tenant::parse(tenant).is_none() {
        return not_found();
    }
    let items: Vec<(u64, &Value)> = d
        .summaries
        .iter()
        .filter(|s| s.get("tenant").and_then(Value::as_str) == Some(tenant))
        .filter_map(|s| Some((s.get("index")?.as_u64()?, s)))
        .collect();
    let (items, _) = page(&items, DEFAULT_PAGE, None);
    ok(
        &json!({ "items": items, "tenant": tenant }),
        Some(Cache::Short),
    )
}
