//! Canonical JSON: keys sorted at every level, no whitespace. The workspace enables serde_json's `preserve_order`,
//! so the order is imposed here and never assumed.

use serde_json::Value;

/// Serialize `v` with sorted keys and no whitespace.
pub(crate) fn canonical(v: &Value) -> String {
    let mut out = String::new();
    write(v, &mut out);
    out
}

fn write(v: &Value, out: &mut String) {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(k.clone()).to_string());
                out.push(':');
                if let Some(x) = m.get(k) {
                    write(x, out);
                }
            }
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(x, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

/// `BLAKE3(domain 0x00 || for each item in sorted byte order: u32be(len) || item)`, hex.
pub(crate) fn hash_sorted(domain: &[u8], items: &[String]) -> String {
    let mut sorted: Vec<&str> = items.iter().map(String::as_str).collect();
    sorted.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(&[0]);
    for s in sorted {
        h.update(&(s.len() as u32).to_be_bytes());
        h.update(s.as_bytes());
    }
    hex::encode(h.finalize().as_bytes())
}
