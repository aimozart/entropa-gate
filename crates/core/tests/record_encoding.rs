//! Definite-uniqueness tests for the record encoding (finding F4): two different
//! (payload, label) records must never share bytes, and therefore never share a leaf hash.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use entropa_core::merkle::leaf_hash;
use entropa_core::transparency_log::{decode_record, encode_record as try_encode, RecordError};

fn encode_record(p: &str, l: Option<&str>) -> Vec<u8> {
    try_encode(p, l).unwrap()
}
use proptest::prelude::*;

/// Strings drawn from an alphabet full of the bytes that confuse encodings: NUL, the
/// version bytes, flag-looking bytes, length-looking bytes, and ordinary text.
fn tricky_string() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop::sample::select(vec![
            '\0', '\u{1}', '\u{2}', '\u{3}', 'a', 'b', '\u{7f}', 'é',
        ]),
        0..12,
    )
    .prop_map(|v| v.into_iter().collect())
}

fn record() -> impl Strategy<Value = (String, Option<String>)> {
    (tricky_string(), prop::option::of(tricky_string()))
}

#[test]
fn the_f4_pair_encodes_differently() {
    assert_ne!(encode_record("a\0b", None), encode_record("a", Some("b\0")));
    assert_ne!(encode_record("a\0b", None), encode_record("a", Some("b")));
}

#[test]
fn every_payload_label_split_of_one_string_is_distinct() {
    let s = "ab\0cd";
    let mut seen = std::collections::HashSet::new();
    for i in 0..=s.len() {
        let (p, l) = s.split_at(i);
        assert!(
            seen.insert(encode_record(p, Some(l))),
            "split at {i} collided"
        );
    }
    assert!(
        seen.insert(encode_record(s, None)),
        "no-label form collided"
    );
}

#[test]
fn an_empty_payload_with_a_label_differs_from_a_payload_that_looks_like_it() {
    assert_ne!(encode_record("", Some("x")), encode_record("\0x", None));
    assert_ne!(encode_record("", Some("")), encode_record("", None));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]
    #[test]
    fn encoding_is_injective(a in record(), b in record()) {
        let ea = encode_record(&a.0, a.1.as_deref());
        let eb = encode_record(&b.0, b.1.as_deref());
        if ea == eb { prop_assert_eq!(&a, &b); }
        // distinct records must give distinct leaf hashes
        if a != b { prop_assert_ne!(leaf_hash(&ea), leaf_hash(&eb)); }
    }
}

/// Records built by re-splitting one string: the shape of every separator-ambiguity bug.
fn resplit_pair() -> impl Strategy<Value = ((String, Option<String>), (String, Option<String>))> {
    (
        tricky_string(),
        any::<prop::sample::Index>(),
        any::<prop::sample::Index>(),
        any::<bool>(),
    )
        .prop_map(|(s, i, j, none)| {
            let chars: Vec<char> = s.chars().collect();
            let split = |k: usize| {
                let (p, l) = chars.split_at(k);
                (
                    p.iter().collect::<String>(),
                    Some(l.iter().collect::<String>()),
                )
            };
            let a = split(i.index(chars.len() + 1));
            let b = if none {
                (s.clone(), None)
            } else {
                split(j.index(chars.len() + 1))
            };
            (a, b)
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3000))]
    #[test]
    fn encoding_is_injective_over_resplits_of_one_string((a, b) in resplit_pair()) {
        let ea = encode_record(&a.0, a.1.as_deref());
        let eb = encode_record(&b.0, b.1.as_deref());
        if a != b {
            prop_assert_ne!(&ea, &eb);
            prop_assert_ne!(leaf_hash(&ea), leaf_hash(&eb));
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3000))]

    #[test]
    fn decode_of_encode_is_the_identity(r in record()) {
        let bytes = encode_record(&r.0, r.1.as_deref());
        prop_assert_eq!(decode_record(&bytes), Ok(r));
    }

    /// Canonical form: any byte string the strict decoder accepts re-encodes to itself, so
    /// there is exactly one valid byte string per record. Arbitrary bytes rarely parse, so
    /// the second case mutates valid encodings by one byte.
    #[test]
    fn every_accepted_byte_string_is_canonical(bytes in prop::collection::vec(any::<u8>(), 0..40)) {
        if let Ok((p, l)) = decode_record(&bytes) {
            prop_assert_eq!(encode_record(&p, l.as_deref()), bytes);
        }
    }

    #[test]
    fn every_accepted_one_byte_mutation_of_a_valid_encoding_is_canonical(
        r in record(), pos in any::<prop::sample::Index>(), val in any::<u8>(),
    ) {
        let mut bytes = encode_record(&r.0, r.1.as_deref());
        let i = pos.index(bytes.len());
        bytes[i] = val;
        if let Ok((p, l)) = decode_record(&bytes) {
            prop_assert_eq!(encode_record(&p, l.as_deref()), bytes);
        }
    }

    #[test]
    fn truncations_and_extensions_of_a_valid_encoding_are_rejected(r in record(), extra in prop::collection::vec(any::<u8>(), 1..4)) {
        let bytes = encode_record(&r.0, r.1.as_deref());
        for cut in 0..bytes.len() {
            prop_assert!(decode_record(&bytes[..cut]).is_err());
        }
        let mut longer = bytes;
        longer.extend(extra);
        prop_assert!(decode_record(&longer).is_err());
    }
}

#[test]
fn a_payload_that_looks_like_an_encoded_record_does_not_collide_with_it() {
    let inner = encode_record("x", Some("y"));
    let inner_as_text = String::from_utf8_lossy(&inner).to_string();
    assert_ne!(encode_record(&inner_as_text, None), inner);
    assert_ne!(
        encode_record("", Some(&inner_as_text)),
        encode_record("x", Some("y"))
    );
}

#[test]
fn maximum_size_fields_are_accepted_and_one_more_byte_is_rejected() {
    use entropa_core::transparency_log::MAX_FIELD_BYTES;
    let max = "m".repeat(MAX_FIELD_BYTES);
    let bytes = try_encode(&max, Some(&max)).unwrap();
    assert_eq!(decode_record(&bytes).unwrap().0.len(), MAX_FIELD_BYTES);
    assert!(matches!(
        try_encode(&format!("{max}m"), None),
        Err(RecordError::FieldTooLarge { .. })
    ));
}

/// Golden vectors (public test data): exact bytes for fixed inputs.
/// See tests/vectors/README.md. These pin the wire format; changing them is a format break.
#[test]
fn golden_vectors_pin_the_exact_bytes_and_leaf_hashes() {
    const VECTORS: &str = include_str!("vectors/record_v2.json");
    let v: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    for case in v["cases"].as_array().unwrap() {
        let payload = case["payload"].as_str().unwrap();
        let label = case["label"].as_str();
        let want_hex = case["encoded_hex"].as_str().unwrap();
        let bytes = encode_record(payload, label);
        assert_eq!(
            hex::encode(&bytes),
            want_hex,
            "encoding of {payload:?}/{label:?}"
        );
        assert_eq!(
            hex::encode(leaf_hash(&bytes)),
            case["leaf_hash_hex"].as_str().unwrap(),
            "leaf hash of {payload:?}/{label:?}"
        );
        assert_eq!(decode_record(&bytes).unwrap().0, payload);
    }
}
