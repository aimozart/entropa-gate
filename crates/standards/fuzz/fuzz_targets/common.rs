// Shared by the standards fuzz targets: the hermetic corpus (the real ids of the committed hash-only manifest with synthetic text; no
// standards text, so nothing licensed can enter a corpus or a crash file).
#![allow(dead_code)]
use entropa_standards::corpus::{text_sha256, Clause, Tier};
use entropa_standards::retrieve::Retriever;
use std::sync::OnceLock;

const MANIFEST: &str = include_str!("../../../../docs/evidence/r1/manifest-c2026-11-13.json");
const WORDS: [&str; 24] = [
    "operator", "shall", "document", "review", "access", "audit", "record", "system", "policy", "control", "incident", "response",
    "backup", "restore", "encryption", "key", "network", "boundary", "monitor", "log", "retention", "training", "supplier", "risk",
];
pub fn clauses() -> Vec<Clause> {
    let v: serde_json::Value = serde_json::from_str(MANIFEST).unwrap();
    v["clauses"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let s = c["standard"].as_str().unwrap().to_string();
            let id = c["id"].as_str().unwrap().to_string();
            let t = format!(
                "{} {}. The {} shall {} the {} and {}.",
                WORDS[i % 24],
                WORDS[(i / 3) % 24],
                WORDS[(i * 7) % 24],
                WORDS[(i * 5 + 1) % 24],
                WORDS[(i * 11 + 2) % 24],
                WORDS[(i * 13 + 3) % 24]
            );
            Clause {
                tier: if s == "PCI-DSS" { Tier::Licensed } else { Tier::Open },
                standard: s,
                std_version: "1".into(),
                id,
                text_sha256: text_sha256(&t),
                text: t,
            }
        })
        .collect()
}
pub fn retriever() -> &'static Retriever {
    static R: OnceLock<Retriever> = OnceLock::new();
    R.get_or_init(|| Retriever::from_clauses("fz", &"0".repeat(64), clauses()))
}
