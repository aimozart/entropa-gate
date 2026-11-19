//! The pre-registration: sign, verify, tamper classes, domain separation, and `--not-key-id`. Test keys are generated at run time in a scratch directory.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_check::prereg::{make, signed_bytes, verify, Hashes, TAG};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

fn scratch(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("prereg-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}
fn key(d: &std::path::Path, name: &str, byte: &str) -> (PathBuf, String) {
    let f = d.join(name);
    std::fs::write(&f, format!("{}\n", byte.repeat(32))).unwrap();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
    let probe = entropa_core::Probe::from_signing_key_hex(&byte.repeat(32)).unwrap();
    (f, probe.pubkey_hex())
}
fn h() -> Hashes {
    Hashes {
        set: "11".repeat(32),
        forecast: "22".repeat(32),
        runner: "33".repeat(32),
        target: "44".repeat(32),
    }
}

#[test]
fn p1_the_signed_bytes_start_with_the_tag_and_bind_every_field() {
    let a = signed_bytes("S1", &h(), "pk");
    assert!(a.starts_with(TAG), "the domain-separation tag comes first");
    assert_eq!(TAG, b"entropa-prereg-v1\0");
    let mut other = h();
    other.target = "55".repeat(32);
    assert_ne!(a, signed_bytes("S1", &other, "pk"));
    assert_ne!(a, signed_bytes("S2", &h(), "pk"));
    assert_ne!(a, signed_bytes("S1", &h(), "pk2"));
}

#[test]
fn p2_round_trip() {
    let d = scratch("p2");
    let (kf, pk) = key(&d, "k", "7a");
    let rec = make("S1", &h(), &kf, &[]).unwrap();
    let (stage, got) = verify(&rec, &pk).unwrap();
    assert_eq!(stage, "S1");
    assert_eq!(got, h());
    assert!(
        !rec.contains(&"7a".repeat(32)),
        "the seed is never in the record"
    );
}

#[test]
fn p3_every_tamper_is_refused() {
    let d = scratch("p3");
    let (kf, pk) = key(&d, "k", "7a");
    let (_, other_pk) = key(&d, "k2", "7b");
    let rec = make("S1", &h(), &kf, &[]).unwrap();
    let e = verify(&rec, &other_pk).unwrap_err();
    assert!(
        e.0.contains("public key"),
        "the wrong-key refusal says why: {e}"
    );
    for (from, to) in [
        ("11".repeat(32), "12".repeat(32)),
        ("22".repeat(32), "23".repeat(32)),
        ("33".repeat(32), "34".repeat(32)),
        ("44".repeat(32), "45".repeat(32)),
        ("\"S1\"".to_string(), "\"S9\"".to_string()),
    ] {
        assert!(rec.contains(&from), "fixture: {from}");
        assert!(
            verify(&rec.replacen(&from, &to, 1), &pk).is_err(),
            "changed {from}"
        );
    }
    let v: serde_json::Value = serde_json::from_str(&rec).unwrap();
    let sig = v["signature"].as_str().unwrap().to_string();
    let flipped = format!(
        "{}{}",
        &sig[..sig.len() - 1],
        if sig.ends_with('0') { "1" } else { "0" }
    );
    assert!(
        verify(&rec.replace(&sig, &flipped), &pk).is_err(),
        "flipped signature digit"
    );
    assert!(verify("{}", &pk).is_err() && verify("nope", &pk).is_err());
}

#[test]
fn p4_a_prereg_signature_is_not_a_release_manifest_signature_and_the_reverse() {
    // the same key and the same canonical text signed WITHOUT the tag (as another record type would be) must not verify as a prereg, and a prereg signature must not verify without the tag
    let d = scratch("p4");
    let (kf, pk) = key(&d, "k", "7a");
    let rec = make("S1", &h(), &kf, &[]).unwrap();
    let v: serde_json::Value = serde_json::from_str(&rec).unwrap();
    let sig = v["signature"].as_str().unwrap();
    let with_tag = signed_bytes("S1", &h(), &pk);
    let without_tag = with_tag[TAG.len()..].to_vec();
    assert!(
        entropa_core::verify_hex(&pk, &with_tag, sig),
        "the signature is over the tagged bytes"
    );
    assert!(
        !entropa_core::verify_hex(&pk, &without_tag, sig),
        "and NOT over the same text without the tag"
    );
    // a record signed over the untagged bytes (as if by another tool using the same key) is refused by verify
    let probe = entropa_core::Probe::from_signing_key_hex(&"7a".repeat(32)).unwrap();
    let foreign = probe.sign_hex(&without_tag);
    let mut forged = v.clone();
    forged["signature"] = serde_json::Value::String(foreign);
    assert!(
        verify(&forged.to_string(), &pk).is_err(),
        "an untagged signature is refused"
    );
}

#[test]
fn p5_not_key_id_refuses_a_key_equal_to_a_release_key() {
    let d = scratch("p5");
    let (kf, pk) = key(&d, "k", "7a");
    let id = entropa_release::cli::key_id(&pk);
    assert!(!id.is_empty());
    let e = make("S1", &h(), &kf, std::slice::from_ref(&id)).unwrap_err();
    assert!(e.0.contains("release key"), "{e}");
    assert!(
        make("S1", &h(), &kf, &["0000000000000000".to_string()]).is_ok(),
        "a different id is fine"
    );
}

#[test]
fn p6_a_key_file_readable_by_others_is_refused() {
    let d = scratch("p6");
    let (kf, _) = key(&d, "k", "7a");
    std::fs::set_permissions(&kf, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(make("S1", &h(), &kf, &[]).is_err());
}

#[test]
fn p7_a_hash_must_be_64_lowercase_hex_digits() {
    let d = scratch("p7");
    let (kf, pk) = key(&d, "k", "7a");
    for bad in [
        "1".repeat(63),
        "1".repeat(65),
        "A".repeat(64),
        "g".repeat(64),
        String::new(),
    ] {
        let mut hh = h();
        hh.set = bad.clone();
        assert!(make("S1", &hh, &kf, &[]).is_err(), "make accepted {bad:?}");
    }
    // a record whose hash was edited to a shorter string is refused at verify even before the signature is looked at
    let rec = make("S1", &h(), &kf, &[]).unwrap();
    let short = rec.replacen(&"11".repeat(32), &"1".repeat(63), 1);
    let e = verify(&short, &pk).unwrap_err();
    assert!(e.0.contains("malformed"), "{e}");
}
