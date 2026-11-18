//! EG1 task 2 (red first): the detectors D1 to D8 on single strings. Every canary is a published example, a reserved or never-issued value, or
//! a value generated here from a fixed seed; none is a real secret or real personal data.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_egress::detect::{scan, Det, DetectCfg, Term};

fn dets(text: &str) -> Vec<Det> {
    let mut v: Vec<Det> = scan(text, &DetectCfg::default())
        .iter()
        .map(|h| h.det)
        .collect();
    v.sort();
    v.dedup();
    v
}
fn has(text: &str, d: Det) -> bool {
    dets(text).contains(&d)
}
fn b64url(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

#[test]
fn d1_key_formats_match_and_near_misses_do_not() {
    for s in [
        "AKIAIOSFODNN7EXAMPLE",
        // EG1b TEST EDIT (reported to the reviewer): this string was listed as a near-miss under the base32 reading [A-Z2-7]. EG0 section 4 says
        // "16 upper-case alphanumerics", and the sealed run showed keys with 0, 1, 8, 9 leaking, so it is now a positive.
        "AKIA0123456789012345",
        "the id is ASIAIOSFODNN7EXAMPLE ok",
        "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB",
        "xoxb-0000000000-0000000000-canaryCANARYcanary00",
        "sk_live_canarycanarycanary00",
        "sk-canarycanarycanarycanarycanarycanary",
        "AIzaSyCanaryCanaryCanaryCanaryCanary012345",
        "npm_canarycanarycanarycanarycanarycanary",
    ] {
        assert!(has(s, Det::D1), "{s}");
    }
    for s in [
        "AKIA is a prefix",
        "AKIAIOSFODNN7EXAMPL",
        "ghp_short",
        "task-1234 risk-assessment",
        "skiing is fun, sk-1 too short",
    ] {
        assert!(!has(s, Det::D1), "{s}");
    }
}

#[test]
fn d1_github_style_checksum_is_reported_when_it_holds() {
    // 30 characters then a 6-character base62 CRC32 of them (computed by the reference below)
    fn crc32(data: &[u8]) -> u32 {
        let mut c = 0xFFFF_FFFFu32;
        for b in data {
            c ^= *b as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    (c >> 1) ^ 0xEDB8_8320
                } else {
                    c >> 1
                };
            }
        }
        !c
    }
    let body = "canaryCANARYcanary012345678901";
    assert_eq!(body.len(), 30);
    let mut n = crc32(body.as_bytes()) as u64;
    let al = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut out = Vec::new();
    for _ in 0..6 {
        out.push(al[(n % 62) as usize]);
        n /= 62;
    }
    out.reverse();
    let good = format!("ghp_{body}{}", String::from_utf8(out).unwrap());
    let h = scan(&good, &DetectCfg::default());
    assert!(h.iter().any(|x| x.det == Det::D1 && x.checksum_ok), "{h:?}");
    let bad = format!("ghp_{body}ZZZZZZ");
    let h = scan(&bad, &DetectCfg::default());
    assert!(
        h.iter().any(|x| x.det == Det::D1 && !x.checksum_ok),
        "{h:?}"
    );
}

#[test]
fn d1_published_example_strings_can_be_allowed_by_policy_and_nothing_else() {
    let cfg = DetectCfg {
        examples: vec!["AKIAIOSFODNN7EXAMPLE".into()],
        ..DetectCfg::default()
    };
    assert!(scan("AKIAIOSFODNN7EXAMPLE", &cfg).is_empty());
    assert!(!scan("AKIAIOSFODNN7EXAMPLF", &cfg).is_empty());
}

#[test]
fn d2_private_key_material_and_not_public_material() {
    assert!(has(
        "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----",
        Det::D2
    ));
    assert!(has("-----BEGIN RSA PRIVATE KEY-----", Det::D2));
    assert!(has("-----BEGIN OPENSSH PRIVATE KEY-----", Det::D2));
    assert!(has("PuTTY-User-Key-File-3: ssh-ed25519", Det::D2));
    assert!(has(
        r#"{"kty":"RSA","n":"abc","e":"AQAB","d":"canaryprivateexponent"}"#,
        Det::D2
    ));
    // a PKCS#8 DER body, base64, without any header
    let mut der = vec![
        0x30, 0x82, 0x04, 0xbd, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];
    der.extend((0..200u8).map(|i| i.wrapping_mul(7)));
    use base64::Engine;
    let b = base64::engine::general_purpose::STANDARD.encode(&der);
    assert!(has(&format!("key: {b}"), Det::D2), "headerless PKCS#8");
    for s in [
        "-----BEGIN PUBLIC KEY-----",
        "-----BEGIN CERTIFICATE-----",
        r#"{"kty":"RSA","n":"abc","e":"AQAB"}"#,
        "private keys are discussed here",
    ] {
        assert!(!has(s, Det::D2), "{s}");
    }
}

#[test]
fn d3_credential_structure() {
    let jwt = format!(
        "{}.{}.{}",
        b64url(br#"{"alg":"HS256","typ":"JWT"}"#),
        b64url(br#"{"sub":"canary"}"#),
        b64url(b"canarysignature")
    );
    assert!(has(&jwt, Det::D3));
    assert!(has("Authorization: Bearer canaryTOKEN0123456789", Det::D3));
    assert!(has("Authorization: Basic Y2FuYXJ5OnBhc3N3b3Jk", Det::D3));
    assert!(has(
        "postgres://svc:Zx9-canary-pw@db.example.test/app",
        Det::D3
    ));
    assert!(has(
        "Server=db.example.test;User Id=svc;Password=Zx9canaryPw;",
        Det::D3
    ));
    assert!(has(r#"{"api_key": "canaryvalue0123"}"#, Det::D3));
    assert!(has("password = hunter2canary", Det::D3));
    for s in [
        "password = changeme",
        "password = ${DB_PASSWORD}",
        "password: <password>",
        "password = xxxxxxxx",
        "password rules require length",
        "postgres://db.example.test/app",
        "eyJhbGciOiJub25lIn0 is not a three-part token",
        "token = short",
    ] {
        assert!(!has(s, Det::D3), "{s}");
    }
}

#[test]
fn d4_card_numbers_need_luhn_issuer_and_length() {
    for s in [
        "4111111111111111",
        "4111 1111 1111 1111",
        "4111-1111-1111-1111",
        "5555555555554444",
        "378282246310005",
        "6011111111111117",
        "3530111333300000",
        "pay with 4242424242424242 now",
    ] {
        assert!(has(s, Det::D4), "{s}");
    }
    for s in [
        "4111111111111112", /* bad Luhn */
        "1234567890123452", /* unknown issuer, Luhn ok */
        "411111111111",
        "41111111111111111111", /* 20 digits */
        "order 20261114123456 shipped",
        "x41111111111111111",
        "41111111111111111 7",
    ] {
        assert!(!has(s, Det::D4), "{s}");
    }
}

#[test]
fn d5_personal_data_shapes() {
    // national ids: shapes are caught even in never-issued ranges (the canaries live there)
    // the space-separated shape is built at run time from a reserved-invalid area and group (9xx-00-xxxx can never have been issued); the shape detector fires in every range
    let spaced = format!("SSN: {} {} {}", "912", "00", "3456");
    for s in [
        "ssn 000-12-3456",
        "987-65-4321",
        spaced.as_str(),
        "IBAN GB82WEST12345698765432",
        "DE89 3704 0044 0532 0130 00",
        "NHS 943 476 5919",
        "NI QQ123456C",
    ] {
        assert!(has(s, Det::D5Id), "{s}");
    }
    for s in [
        "IBAN GB82WEST12345698765433", /* bad mod 97 */
        "NHS 943 476 5918",            /* bad mod 11 */
        "123-45-678",
        "1234-56-7890x",
    ] {
        assert!(!has(s, Det::D5Id), "{s}");
    }
    for s in ["mail me at canary.user@example.com", "a+b@sub.example.test"] {
        assert!(has(s, Det::D5Email), "{s}");
    }
    for s in ["not an email@", "@example.com", "a@b"] {
        assert!(!has(s, Det::D5Email), "{s}");
    }
    for s in [
        "call +1 202 555 0100",
        "+44 20 7946 0958",
        "(202) 555-0100",
        "202-555-0100",
    ] {
        assert!(has(s, Det::D5Phone), "{s}");
    }
    for s in ["call 12345", "version 1.2.3.4", "2026-11-14"] {
        assert!(!has(s, Det::D5Phone), "{s}");
    }
    assert!(has("DOB: 1980-02-03", Det::D5Dob));
    assert!(has("date of birth 03/02/1980", Det::D5Dob));
    assert!(
        !has("released 1980-02-03", Det::D5Dob),
        "a date alone is not a date of birth"
    );
}

#[test]
fn d6_entropy_hint_is_record_only_class_and_needs_length() {
    assert!(has("zQ8vK2mXp9LrT4wYb7NcH1sJf6GdA3eU", Det::D6));
    assert!(
        !has("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Det::D6),
        "low entropy"
    );
    assert!(!has("short9Xk2", Det::D6));
    assert!(!has("the quick brown fox jumps over the lazy dog", Det::D6));
}

#[test]
fn d7_client_terms_whole_word_and_co_occurrence() {
    let cfg = DetectCfg {
        terms: vec![
            Term {
                words: vec!["Project Heron".into()],
                whole_word: true,
                all: true,
            },
            Term {
                words: vec!["orion".into()],
                whole_word: true,
                all: true,
            },
            Term {
                words: vec!["acme-ledger".into(), "rotation".into()],
                whole_word: false,
                all: true,
            },
        ],
        ..DetectCfg::default()
    };
    let hit = |s: &str| scan(s, &cfg).iter().any(|h| h.det == Det::D7);
    assert!(hit("about project heron timing"));
    assert!(hit("about PROJECT   HERON"), "case and spacing");
    assert!(hit("the Orion plan"));
    assert!(!hit("the orionids shower"), "whole word");
    assert!(hit("acme-ledger key rotation"));
    assert!(!hit("acme-ledger alone"), "co-occurrence needs both");
    assert!(!hit("rotation alone"));
}

#[test]
fn d8_banners_and_keyed_markers() {
    let key = b"canary-marker-key".to_vec();
    let first = "0a1b2c3d";
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(&key);
    h.update(first.as_bytes());
    let second = &hex::encode(h.finalize())[..8];
    let marker = format!("EGM-{first}-{second}");
    let cfg = DetectCfg {
        markers: vec!["internal only".into(), "do not distribute".into()],
        marker_key: key,
        ..DetectCfg::default()
    };
    let hit = |s: &str| scan(s, &cfg).iter().any(|h| h.det == Det::D8);
    assert!(hit("INTERNAL ONLY - draft"));
    assert!(hit("Do Not Distribute"));
    assert!(hit(&format!("text {marker} text")));
    assert!(
        !hit(&format!("text EGM-{first}-ffffffff text")),
        "a forged marker is not a marker"
    );
    assert!(!hit("internally the only way"));
}

#[test]
fn closed_detector_ids() {
    let all: Vec<&str> = Det::ALL.iter().map(|d| d.as_str()).collect();
    assert_eq!(
        all,
        ["D1", "D2", "D3", "D4", "D5.id", "D5.email", "D5.phone", "D5.dob", "D6", "D7", "D8"]
    );
    for d in Det::ALL {
        assert_eq!(Det::parse(d.as_str()), Some(*d));
    }
    assert_eq!(Det::parse("D9"), None);
}
