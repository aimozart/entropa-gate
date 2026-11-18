//! EG1b mutation triage, batch K: `detect::der_private`, the check that a long base64 token decodes to a PKCS#8-shaped private key: the first byte is 0x30, the
//! sequence `02 01 00 30` (version 0, then the algorithm sequence) lies within the first 12 bytes, and one of three algorithm identifiers (RSA, EC, Ed25519) follows within 40
//! bytes of it. The byte strings are built here by hand from those rules (and padded to 90 bytes so that the base64 token has more than 100 characters, the least the
//! pattern takes). Equivalent (a stage record (not published)): the `len < 40` test (a token of 100 characters decodes to at least 75 bytes, so it is never reached).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use base64::Engine;
use common::*;
use entropa_egress::detect::{scan, Det};

const RSA: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
];
const EC: [u8; 9] = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const ED: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];

/// 90 bytes: `lead` filler bytes, the sequence 02 01 00 30, then `gap` filler bytes, the identifier, then padding. The first byte is 0x30 unless `first` says otherwise.
fn der(first: u8, lead: usize, gap: usize, oid: &[u8]) -> Vec<u8> {
    let mut b = vec![first];
    b.extend(std::iter::repeat_n(0x11u8, lead));
    b.extend([0x02, 0x01, 0x00, 0x30]);
    b.extend(std::iter::repeat_n(0x22u8, gap));
    b.extend(oid);
    while b.len() < 90 {
        b.push(0x41);
    }
    b
}
fn is_key(bytes: &[u8]) -> bool {
    let tok = base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes);
    assert!(tok.len() >= 100, "{}", tok.len());
    let p = policy();
    scan(&format!("blob {tok} end"), p.detect_cfg())
        .iter()
        .any(|h| h.det == Det::D2)
}

#[test]
fn k1_each_algorithm_identifier_marks_a_private_key() {
    for (name, oid) in [("rsa", &RSA[..]), ("ec", &EC[..]), ("ed25519", &ED[..])] {
        assert!(is_key(&der(0x30, 3, 2, oid)), "{name}");
    }
}

#[test]
fn k2_the_first_byte_the_sequence_position_and_the_window_are_exact() {
    // the first byte must be 0x30
    assert!(!is_key(&der(0x31, 3, 2, &RSA)));
    assert!(!is_key(&der(0x00, 3, 2, &RSA)));
    // the sequence 02 01 00 30 must start within the first 12 bytes: at offset 8 (the last window of 4 inside 12) yes, at 9 no
    assert!(is_key(&der(0x30, 7, 2, &RSA)), "sequence at offset 8");
    assert!(!is_key(&der(0x30, 8, 2, &RSA)), "sequence at offset 9");
    assert!(is_key(&der(0x30, 0, 2, &RSA)), "sequence at offset 1");
    // the identifier must lie inside the 40 bytes from the sequence start: it may end exactly at the 40th byte, not one later
    let ends_at_40 = 40 - 4 - RSA.len();
    assert!(
        is_key(&der(0x30, 3, ends_at_40, &RSA)),
        "identifier ends at the last byte of the window"
    );
    assert!(
        !is_key(&der(0x30, 3, ends_at_40 + 1, &RSA)),
        "identifier ends one byte past the window"
    );
    // no identifier at all
    assert!(
        !is_key(&der(0x30, 3, 2, &[0x06, 0x03, 0x2b, 0x65, 0x71])),
        "a near-miss identifier"
    );
    assert!(!is_key(&der(0x30, 3, 2, &[])), "no identifier");
    // an identifier that is cut by the end of the window is not found
    assert!(!is_key(&der(0x30, 3, 36 - RSA.len() + 5, &RSA)));
}

/// Real PKCS#8 private keys made by `openssl genpkey ... -outform DER` AT RUN TIME into a temporary directory and dropped with it: no key is stored in the repository.
/// Method (recorded for review): ed25519, EC prime256v1 and RSA 2048 through `genpkey -outform DER` (OpenSSL 3.5 writes SEC1 `ECPrivateKey` `30 .. 02 01 01 04 20 ..` for EC and PKCS#1 `30 82 .. 02 01 00 02 82 ..` for RSA, and PKCS#8 for ed25519), base64 (standard alphabet, no padding), put in a sentence and scanned. If `openssl` is not on the
/// PATH the test says so and does not pass silently (it fails), because the claim "real keys are detected" would then be untested.
#[test]
fn k3_real_openssl_private_keys_are_detected() {
    let t = tempfile::tempdir().unwrap();
    let run = |args: &[&str], out: &str| {
        let o = std::process::Command::new("openssl")
            .args(args)
            .output()
            .expect("openssl must be on the PATH for this test");
        assert!(
            o.status.success(),
            "openssl {args:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        std::fs::write(t.path().join(out), &o.stdout).unwrap();
        o.stdout
    };
    for (name, args) in [
        (
            "ed25519",
            vec!["genpkey", "-algorithm", "ED25519", "-outform", "DER"],
        ),
        (
            "ec",
            vec![
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-outform",
                "DER",
            ],
        ),
        (
            "rsa",
            vec![
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-outform",
                "DER",
            ],
        ),
    ] {
        let der = run(&args, &format!("{name}.der"));
        assert_eq!(der[0], 0x30, "{name} is a DER sequence");
        // pad a short key (ed25519 is 48 bytes) so the token has the 100 characters the pattern needs, as a real key file with a comment or a wrapper would
        let mut bytes = der.clone();
        while bytes.len() < 90 {
            bytes.push(0x41);
        }
        assert!(
            is_key(&bytes),
            "{name}: a real private key was not detected"
        );
    }
}

#[test]
fn k4_the_traditional_layouts_are_recognised_by_their_own_shape_and_only_by_it() {
    let mut pkcs1 = vec![
        0x30, 0x82, 0x04, 0xa4, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00,
    ];
    pkcs1.resize(90, 0x5a);
    assert!(is_key(&pkcs1), "PKCS#1 with a two-byte length");
    let mut pkcs1_short = vec![0x30, 0x81, 0xc8, 0x02, 0x01, 0x00, 0x02, 0x81, 0x81, 0x00];
    pkcs1_short.resize(90, 0x5a);
    assert!(
        is_key(&pkcs1_short),
        "PKCS#1 with a one-byte long-form length"
    );
    let mut sec1 = vec![0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20];
    sec1.resize(90, 0x5a);
    assert!(is_key(&sec1), "SEC1 with a 32-byte scalar");
    for n in [16u8, 66] {
        let mut s = vec![0x30, 0x77, 0x02, 0x01, 0x01, 0x04, n];
        s.resize(90, 0x5a);
        assert!(is_key(&s), "SEC1 scalar length {n}");
    }
    for n in [15u8, 67, 0x80] {
        let mut s = vec![0x30, 0x77, 0x02, 0x01, 0x01, 0x04, n];
        s.resize(90, 0x5a);
        assert!(!is_key(&s), "SEC1 scalar length {n} is outside 16 to 66");
    }
    // near misses: wrong version, wrong element after the version, a short-form first length, a three-byte length form
    for bad in [
        vec![
            0x30, 0x82, 0x04, 0xa4, 0x02, 0x01, 0x01, 0x02, 0x82, 0x01, 0x01, 0x00,
        ], // PKCS#1 shape with version 1
        vec![
            0x30, 0x82, 0x04, 0xa4, 0x02, 0x01, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00,
        ], // not an INTEGER after the version
        vec![
            0x30, 0x82, 0x04, 0xa4, 0x02, 0x01, 0x00, 0x02, 0x05, 0x01, 0x01, 0x00,
        ], // a short-form modulus length
        vec![
            0x30, 0x83, 0x00, 0x04, 0xa4, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01,
        ], // a three-byte length form
        vec![
            0x31, 0x82, 0x04, 0xa4, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00,
        ], // first byte
        vec![0x30, 0x77, 0x02, 0x01, 0x00, 0x04, 0x20], // SEC1 with version 0
        vec![0x30, 0x77, 0x02, 0x01, 0x01, 0x05, 0x20], // not an OCTET STRING
    ] {
        let mut b = bad;
        b.resize(90, 0x5a);
        assert!(!is_key(&b), "{:02x?}", &b[..12]);
    }
}
