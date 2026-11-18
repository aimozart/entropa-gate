//! Golden vectors for the statement encoding, from an independent implementation.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_witness::*;
use serde_json::Value;

const VECTORS: &str = include_str!("vectors/witness_statement_v1.json");

#[test]
fn v1_canonical_bytes_and_digests_match_the_independent_generator() {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 5);
    for c in cases {
        let f = &c["fields"];
        let fields = StatementFields {
            log_id: f["log_id"].as_str().unwrap().into(),
            size: f["size"].as_u64().unwrap(),
            root: f["root"].as_str().unwrap().into(),
            log_timestamp: f["log_timestamp"].as_u64().unwrap(),
            witness_time: f["witness_time"].as_u64().unwrap(),
            previous_size: f["previous_size"].as_u64().unwrap(),
            previous_root: f["previous_root"].as_str().unwrap().into(),
            witness_pubkey: f["witness_pubkey"].as_str().unwrap().into(),
        };
        let canon = statement_canonical_bytes(&fields);
        if canon.is_empty() {
            panic!("{NOT_IMPLEMENTED}");
        }
        let name = c["name"].as_str().unwrap();
        assert_eq!(
            String::from_utf8(canon.clone()).unwrap(),
            c["canonical"].as_str().unwrap(),
            "{name}: canonical bytes"
        );
        assert_eq!(
            hex::encode(statement_digest(&canon)),
            c["digest_hex"].as_str().unwrap(),
            "{name}: digest"
        );
    }
}

#[test]
fn v2_the_no_previous_root_constant_matches_the_vector_file() {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(
        v["fixed"]["no_previous_root"].as_str().unwrap(),
        NO_PREVIOUS_ROOT
    );
    assert_eq!(v["fixed"]["type"].as_str().unwrap(), STATEMENT_TYPE);
}
