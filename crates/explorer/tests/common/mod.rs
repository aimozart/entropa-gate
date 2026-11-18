//! Shared helpers. All data is synthetic. The fixture is the S7c bundle of seed 1 with 5 scenarios;
//! the test `f1` proves the ledger generator still reproduces it byte for byte.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub use entropa_explorer::*;
use serde_json::Value;
use std::cell::Cell;

pub const FIXTURE: &str = include_str!("../golden/bundle_seed1_n5.json");
pub const SCHEMA: &str = include_str!("../../../../policies/entropa.cedarschema");
pub const POLICIES: &str = include_str!("../../../../policies/entropa.cedar");
pub const NOW: u64 = 1_800_000_000;
pub const CLIENT: &str = "203.0.113.7";

pub struct FakeClock(pub Cell<u64>);
impl FakeClock {
    pub fn at(t: u64) -> FakeClock {
        FakeClock(Cell::new(t))
    }
    pub fn advance(&self, secs: u64) {
        self.0.set(self.0.get() + secs);
    }
}
impl Clock for FakeClock {
    fn now_secs(&self) -> u64 {
        self.0.get()
    }
}

pub fn explorer_with(limits: Limits) -> Explorer {
    match Explorer::from_bundle(FIXTURE, limits) {
        Ok(e) => e,
        Err(ExplorerError::NotImplemented) => panic!("{NOT_IMPLEMENTED}"),
        Err(e) => panic!("explorer did not load: {e:?}"),
    }
}

pub fn explorer() -> Explorer {
    explorer_with(Limits::default())
}

/// A request from "path?query".
pub fn get(target: &str) -> Request {
    from("GET", target, CLIENT)
}

pub fn from(method: &str, target: &str, client: &str) -> Request {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    Request {
        method: method.into(),
        path: path.into(),
        query: query.into(),
        client: client.into(),
        headers: vec![],
        body_len: 0,
    }
}

/// Ask with a fresh clock far from any limiter state; panics with the red marker while the stub answers.
pub fn ask(e: &Explorer, target: &str) -> Response {
    let r = e.handle(&get(target), &FakeClock::at(NOW));
    if r.status == 501 {
        panic!("{NOT_IMPLEMENTED}");
    }
    r
}

pub fn json(r: &Response) -> Value {
    serde_json::from_str(&r.body).unwrap_or_else(|_| panic!("the body is not JSON: {:?}", r.body))
}

pub fn fixture() -> Value {
    serde_json::from_str(FIXTURE).unwrap()
}

/// Canonical JSON: keys sorted at every level, no whitespace.
pub fn canonical(v: &Value) -> String {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", serde_json::to_string(k).unwrap(), canonical(&m[k])))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(a) => format!(
            "[{}]",
            a.iter().map(canonical).collect::<Vec<_>>().join(",")
        ),
        other => serde_json::to_string(other).unwrap(),
    }
}
