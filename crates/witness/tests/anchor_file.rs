//! INS2 slice 2a red tests: the anchor file format. Fixed test seeds; synthetic data only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::anchor::{sign_v2, Anchor, AnyCheckpoint};
use entropa_core::merkle;
use entropa_core::transparency_log::TransparencyLog;
use entropa_core::Probe;
use entropa_witness::anchor_file::{
    decode_anchor, decode_anchor_for, encode_anchor, AnchorFileError, MAX_ANCHOR_BYTES,
};
use entropa_witness::log_id_for;
use serde_json::{json, Value};

fn probe() -> Probe {
    Probe::from_signing_key_hex(&hex::encode([4u8; 32])).unwrap()
}
fn hash_only() -> Anchor {
    Anchor {
        size: 6,
        root: [0x22; 32],
        counter: Some(2),
        signed: None,
    }
}
fn v1_signed() -> (Anchor, String) {
    let p = probe();
    let mut log = TransparencyLog::new();
    for i in 0..4 {
        log.append(format!("r{i}").as_bytes());
    }
    let cp = log.checkpoint(&p, 1000);
    (
        Anchor {
            size: cp.size,
            root: cp.root,
            counter: None,
            signed: Some(AnyCheckpoint::V1(cp)),
        },
        log_id_for(&p.pubkey_hex()),
    )
}
fn v2_signed() -> (Anchor, String) {
    let p = probe();
    let leaves: Vec<_> = (0..4)
        .map(|i| merkle::leaf_hash(format!("r{i}").as_bytes()))
        .collect();
    let root = merkle::root(&leaves).unwrap();
    let cp = sign_v2(&p, 3, &[5u8; 32], &root, 4, 2000).unwrap();
    (
        Anchor {
            size: 4,
            root,
            counter: Some(3),
            signed: Some(AnyCheckpoint::V2(cp)),
        },
        log_id_for(&p.pubkey_hex()),
    )
}
const LOG: &str = "1111111111111111111111111111111111111111111111111111111111111111";

#[test]
fn a1_the_canonical_line_matches_an_independent_python_derivation() {
    let want = r#"{"checkpoint":null,"counter":2,"log_id":"1111111111111111111111111111111111111111111111111111111111111111","root":"2222222222222222222222222222222222222222222222222222222222222222","size":6,"type":"anchor","v":1}"#;
    assert_eq!(encode_anchor(&hash_only(), LOG), want);
}
#[test]
fn a2_every_kind_of_anchor_round_trips() {
    let (a1, l1) = v1_signed();
    let (a2, l2) = v2_signed();
    for (a, l) in [(hash_only(), LOG.to_string()), (a1, l1), (a2, l2)] {
        let text = encode_anchor(&a, &l);
        assert!(
            !text.contains('\n') && !text.contains(' '),
            "one canonical line: {text}"
        );
        let (back, log) = decode_anchor(&text).unwrap();
        assert_eq!((back, log), (a, l));
    }
}
#[test]
fn a3_a_text_with_a_trailing_newline_is_accepted_but_other_trailing_text_is_not() {
    let t = encode_anchor(&hash_only(), LOG);
    assert!(decode_anchor(&format!("{t}\n")).is_ok());
    assert!(decode_anchor(&format!("{t} x")).is_err());
    assert!(decode_anchor(&format!("{t}{t}")).is_err());
}

fn base() -> Value {
    serde_json::from_str(&encode_anchor(&hash_only(), LOG)).unwrap()
}
fn refused(v: &Value) -> AnchorFileError {
    decode_anchor(&v.to_string()).unwrap_err()
}
#[test]
fn b1_unknown_missing_and_wrong_typed_fields_are_refused() {
    let mut v = base();
    v["extra"] = json!(1);
    assert!(matches!(refused(&v), AnchorFileError::Invalid(_)));
    for k in [
        "v",
        "type",
        "log_id",
        "size",
        "root",
        "counter",
        "checkpoint",
    ] {
        let mut m = base();
        m.as_object_mut().unwrap().remove(k);
        assert!(
            matches!(refused(&m), AnchorFileError::Invalid(_)),
            "missing {k}"
        );
    }
    for (k, bad) in [
        ("v", json!(2)),
        ("type", json!("checkpoint")),
        ("size", json!("6")),
        ("size", json!(6.5)),
        ("size", json!(-1)),
        ("counter", json!(0)),
        ("counter", json!("2")),
        ("counter", json!(1.5)),
    ] {
        let mut m = base();
        m[k] = bad.clone();
        assert!(
            matches!(refused(&m), AnchorFileError::Invalid(_)),
            "{k}={bad}"
        );
    }
}
#[test]
fn b2_hex_fields_are_exact_lowercase_64_digit_strings() {
    for k in ["log_id", "root"] {
        for bad in [
            "",
            "ab",
            &"2".repeat(63),
            &"2".repeat(65),
            &"G".repeat(64),
            &"A".repeat(64),
        ] {
            let mut m = base();
            m[k] = json!(bad);
            assert!(
                matches!(refused(&m), AnchorFileError::Invalid(_)),
                "{k}={bad}"
            );
        }
    }
}
#[test]
fn b3_a_duplicated_key_is_refused() {
    let t = encode_anchor(&hash_only(), LOG).replacen("\"size\":6", "\"size\":6,\"size\":7", 1);
    assert!(matches!(
        decode_anchor(&t),
        Err(AnchorFileError::Invalid(_))
    ));
}
#[test]
fn b4_the_size_cap_is_exactly_32_kib_and_checked_before_parsing() {
    let t = encode_anchor(&hash_only(), LOG);
    let pad = |n: usize| format!("{t}{}", " ".repeat(n - t.len()));
    assert!(
        decode_anchor(&pad(MAX_ANCHOR_BYTES)).is_ok(),
        "exactly the cap parses"
    );
    assert!(matches!(
        decode_anchor(&pad(MAX_ANCHOR_BYTES + 1)),
        Err(AnchorFileError::Limit(_))
    ));
    assert!(
        matches!(
            decode_anchor(&"x".repeat(MAX_ANCHOR_BYTES + 1)),
            Err(AnchorFileError::Limit(_))
        ),
        "garbage over the cap is a limit, not a parse error"
    );
}
#[test]
fn b5_an_embedded_checkpoint_must_agree_with_the_top_level_fields() {
    let (a, l) = v2_signed();
    let good: Value = serde_json::from_str(&encode_anchor(&a, &l)).unwrap();
    for (k, bad) in [
        ("size", json!(5)),
        ("root", json!("ab".repeat(32))),
        ("counter", json!(9)),
    ] {
        let mut m = good.clone();
        m[k] = bad.clone();
        assert!(
            matches!(refused(&m), AnchorFileError::Invalid(_)),
            "top-level {k} differs from the embedded checkpoint"
        );
    }
    // a v1 checkpoint must not come with a counter, a v2 one must
    let (a1, l1) = v1_signed();
    let mut m: Value = serde_json::from_str(&encode_anchor(&a1, &l1)).unwrap();
    m["counter"] = json!(1);
    assert!(matches!(refused(&m), AnchorFileError::Invalid(_)));
    let mut m2 = good.clone();
    m2["counter"] = Value::Null;
    assert!(matches!(refused(&m2), AnchorFileError::Invalid(_)));
}
#[test]
fn b6_the_embedded_checkpoint_has_exact_keys_and_a_known_version() {
    let (a, l) = v2_signed();
    let good: Value = serde_json::from_str(&encode_anchor(&a, &l)).unwrap();
    let mut m = good.clone();
    m["checkpoint"]["extra"] = json!(1);
    assert!(matches!(refused(&m), AnchorFileError::Invalid(_)));
    let mut m = good.clone();
    m["checkpoint"].as_object_mut().unwrap().remove("prev");
    assert!(matches!(refused(&m), AnchorFileError::Invalid(_)));
    let mut m = good.clone();
    m["checkpoint"]["v"] = json!(3);
    assert!(matches!(refused(&m), AnchorFileError::Invalid(_)));
    let mut m = good;
    m["checkpoint"]["signature"] = json!("XYZ");
    assert!(matches!(refused(&m), AnchorFileError::Invalid(_)));
}
#[test]
fn b7_errors_never_echo_the_input() {
    let mut v = base();
    v["root"] = json!("SECRET-MARKER-VALUE");
    let e = format!("{:?}", refused(&v));
    assert!(!e.contains("SECRET-MARKER"), "{e}");
    let e2 = format!("{:?}", decode_anchor("SECRET-MARKER-NOT-JSON").unwrap_err());
    assert!(!e2.contains("SECRET-MARKER"), "{e2}");
}
#[test]
fn b8_nesting_depth_and_non_objects_are_refused() {
    for t in [
        "[]",
        "null",
        "1",
        "\"x\"",
        &format!("{}1{}", "[".repeat(200), "]".repeat(200)),
        "",
    ] {
        assert!(decode_anchor(t).is_err(), "{t:.20}");
    }
}

#[test]
fn c1_an_anchor_for_another_log_is_a_closed_refusal() {
    let (a, l) = v2_signed();
    let text = encode_anchor(&a, &l);
    assert_eq!(
        decode_anchor_for(&text, &probe().pubkey_hex()).unwrap(),
        a,
        "the right log"
    );
    let other = Probe::from_signing_key_hex(&hex::encode([9u8; 32])).unwrap();
    assert_eq!(
        decode_anchor_for(&text, &other.pubkey_hex()),
        Err(AnchorFileError::WrongLog)
    );
    // an unusable expected key never matches
    assert_eq!(
        decode_anchor_for(&text, "zz"),
        Err(AnchorFileError::WrongLog)
    );
    assert_eq!(decode_anchor_for(&text, ""), Err(AnchorFileError::WrongLog));
    // a malformed file is Invalid, not WrongLog, whatever the key
    assert!(matches!(
        decode_anchor_for("{}", &probe().pubkey_hex()),
        Err(AnchorFileError::Invalid(_))
    ));
}
#[test]
fn c2_a_second_line_or_trailing_bytes_are_refused_and_a_counter_with_a_v1_checkpoint_too() {
    let t = encode_anchor(&hash_only(), LOG);
    assert!(decode_anchor(&format!("{t}\n{t}")).is_err(), "second line");
    assert!(
        decode_anchor(&format!("{t}\n\n")).is_err(),
        "more than one trailing newline"
    );
    assert!(decode_anchor(&format!("{t}\0")).is_err(), "trailing NUL");
    let (a1, l1) = v1_signed();
    let mut m: Value = serde_json::from_str(&encode_anchor(&a1, &l1)).unwrap();
    m["counter"] = json!(3);
    assert!(
        decode_anchor(&m.to_string()).is_err(),
        "a v1 checkpoint carries no counter"
    );
    // a hash-only anchor MAY carry the counter (it is the hash form of a v2 checkpoint) or not
    let mut h = hash_only();
    assert!(decode_anchor(&encode_anchor(&h, LOG)).is_ok());
    h.counter = None;
    assert!(decode_anchor(&encode_anchor(&h, LOG)).is_ok());
}

#[test]
fn c3_a_signed_anchor_must_name_the_log_of_its_own_key() {
    let (a, _l) = v2_signed();
    let text = encode_anchor(&a, LOG); // the log id is not the id of the checkpoint's key
    assert!(matches!(
        decode_anchor(&text),
        Err(AnchorFileError::Invalid(_))
    ));
}

#[test]
fn c4_numbers_above_two_to_the_53_minus_1_are_refused_and_that_exact_value_is_accepted() {
    let t = encode_anchor(&hash_only(), LOG);
    let with = |n: u64| t.replace("\"size\":6", &format!("\"size\":{n}"));
    assert!(decode_anchor(&with((1u64 << 53) - 1)).is_ok());
    assert!(decode_anchor(&with(1u64 << 53)).is_err());
    assert!(decode_anchor(&with(u64::MAX)).is_err());
    let c = |n: u64| t.replace("\"counter\":2", &format!("\"counter\":{n}"));
    assert!(decode_anchor(&c((1u64 << 53) - 1)).is_ok());
    assert!(decode_anchor(&c(1u64 << 53)).is_err());
}

#[test]
#[ignore = "prints the worked examples of the threat model; run on purpose"]
fn z_print_examples() {
    let (v2, l2) = v2_signed();
    let t = encode_anchor(&v2, &l2);
    let v: Value = serde_json::from_str(&t).unwrap();
    let mut short = v.clone();
    for k in ["proposer_pubkey", "signature"] {
        let s = short["checkpoint"][k].as_str().unwrap().to_string();
        short["checkpoint"][k] = json!(format!("{}...({} hex digits)", &s[..16], s.len()));
    }
    println!("HASH_ONLY {}", encode_anchor(&hash_only(), LOG));
    println!("SIGNED_V2_SHORTENED {short}");
    println!("SIGNED_V2_LENGTH {} bytes", t.len());
}

#[test]
fn c5_the_key_and_signature_hex_of_an_embedded_checkpoint_have_exact_bounds() {
    use entropa_witness::log_id_for;
    let (a, _) = v2_signed();
    let base = |key: &str, sig: &str| {
        let mut cp = match &a.signed {
            Some(AnyCheckpoint::V2(c)) => c.clone(),
            _ => panic!(),
        };
        cp.proposer_pubkey = key.to_string();
        cp.signature = sig.to_string();
        let anchor = Anchor {
            signed: Some(AnyCheckpoint::V2(cp)),
            ..a.clone()
        };
        encode_anchor(&anchor, &log_id_for(key))
    };
    let ok_sig = "ab".repeat(100);
    // exactly 8192 hex digits is accepted (the bound is on the text, not on what a real key looks like)
    let max = "ab".repeat(4096);
    assert!(decode_anchor(&base(&max, &ok_sig)).is_ok(), "8192 digits");
    assert!(
        decode_anchor(&base(&"ab".repeat(100), &max)).is_ok(),
        "8192 digit signature"
    );
    let too_long = format!("{max}ab");
    assert!(
        decode_anchor(&base(&too_long, &ok_sig)).is_err(),
        "8194 digits key"
    );
    assert!(
        decode_anchor(&base(&"ab".repeat(100), &too_long)).is_err(),
        "8194 digits signature"
    );
    for bad in ["", "a", "abc", "AB", "zz"] {
        assert!(decode_anchor(&base(bad, &ok_sig)).is_err(), "key {bad:?}");
        assert!(
            decode_anchor(&base(&"ab".repeat(100), bad)).is_err(),
            "signature {bad:?}"
        );
    }
}
