//! EG1 task 2 (red first): the views (fold, strip, bounded decoders).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_egress::views::{decoded, fold, strip};

#[test]
fn v1_fold_maps_every_look_alike_and_removes_invisible_characters() {
    let table: &[(char, char)] = &[
        ('\u{ff01}', '!'),
        ('\u{ff21}', 'A'),
        ('\u{ff41}', 'a'),
        ('\u{ff5e}', '~'),
        ('\u{430}', 'a'),
        ('\u{3b1}', 'a'),
        ('\u{435}', 'e'),
        ('\u{43e}', 'o'),
        ('\u{3bf}', 'o'),
        ('\u{440}', 'p'),
        ('\u{3c1}', 'p'),
        ('\u{441}', 'c'),
        ('\u{445}', 'x'),
        ('\u{443}', 'y'),
        ('\u{456}', 'i'),
        ('\u{3b9}', 'i'),
        ('\u{458}', 'j'),
        ('\u{455}', 's'),
        ('\u{501}', 'd'),
        ('\u{4bb}', 'h'),
        ('\u{3bd}', 'v'),
        ('\u{3ba}', 'k'),
        ('\u{3c5}', 'u'),
        ('\u{410}', 'A'),
        ('\u{391}', 'A'),
        ('\u{412}', 'B'),
        ('\u{392}', 'B'),
        ('\u{415}', 'E'),
        ('\u{395}', 'E'),
        ('\u{41a}', 'K'),
        ('\u{39a}', 'K'),
        ('\u{41c}', 'M'),
        ('\u{39c}', 'M'),
        ('\u{41d}', 'H'),
        ('\u{397}', 'H'),
        ('\u{41e}', 'O'),
        ('\u{39f}', 'O'),
        ('\u{420}', 'P'),
        ('\u{3a1}', 'P'),
        ('\u{421}', 'C'),
        ('\u{422}', 'T'),
        ('\u{3a4}', 'T'),
        ('\u{425}', 'X'),
        ('\u{3a7}', 'X'),
        ('\u{406}', 'I'),
        ('\u{399}', 'I'),
        ('\u{408}', 'J'),
        ('\u{405}', 'S'),
        ('\u{396}', 'Z'),
        ('\u{39d}', 'N'),
        ('\u{3a5}', 'Y'),
    ];
    for (c, a) in table {
        assert_eq!(
            fold(&c.to_string()).text,
            a.to_string(),
            "U+{:04X}",
            *c as u32
        );
    }
    assert_eq!(
        fold("a\u{200b}b\u{200d}c\u{ad}d\u{202e}e\u{feff}f\u{2060}g").text,
        "abcdefg"
    );
    assert_eq!(fold("A\u{7}B").text, "AB", "control characters are dropped");
    assert_eq!(
        fold("Plain Text 123").text,
        "Plain Text 123",
        "case is kept in the folded view"
    );
}

#[test]
fn v2_fold_keeps_a_map_back_to_the_raw_text() {
    let f = fold("x\u{200b}\u{430}y");
    assert_eq!(f.text, "xay");
    assert_eq!(f.spans.len(), 3);
    let raw = "x\u{200b}\u{430}y";
    assert_eq!(&raw[f.spans[1].0..f.spans[1].1], "\u{430}");
    assert_eq!(&raw[f.spans[2].0..f.spans[2].1], "y");
}

#[test]
fn v3_strip_removes_separators_and_keeps_a_map() {
    let s = strip("A K-I_A.1 2:3");
    assert_eq!(s.text, "akia123");
    assert_eq!(s.spans.len(), 7);
}

fn b64(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(s)
}

#[test]
fn v4_decoders_each_recover_their_encoding_with_the_source_range() {
    let secret = "AKIAIOSFODNN7EXAMPLE";
    let cases: Vec<(&str, String)> = vec![
        ("base64", b64(secret)),
        ("hex", hex::encode(secret)),
        (
            "percent",
            secret.bytes().map(|b| format!("%{b:02X}")).collect(),
        ),
        (
            "escape_u",
            secret
                .chars()
                .map(|c| format!("\\u{:04x}", c as u32))
                .collect(),
        ),
        (
            "escape_x",
            secret.bytes().map(|b| format!("\\x{b:02x}")).collect(),
        ),
        (
            "entity",
            secret.chars().map(|c| format!("&#{};", c as u32)).collect(),
        ),
        (
            "rot13",
            secret
                .chars()
                .map(|c| match c {
                    'A'..='Z' => (((c as u8 - b'A') + 13) % 26 + b'A') as char,
                    _ => c,
                })
                .collect(),
        ),
        ("reverse", secret.chars().rev().collect()),
        ("base32", {
            let al = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            let mut bits = 0u32;
            let mut n = 0;
            let mut o = String::new();
            for b in secret.bytes() {
                bits = (bits << 8) | b as u32;
                n += 8;
                while n >= 5 {
                    n -= 5;
                    o.push(al[((bits >> n) & 31) as usize] as char);
                }
            }
            if n > 0 {
                o.push(al[((bits << (5 - n)) & 31) as usize] as char);
            }
            o
        }),
    ];
    for (name, enc) in cases {
        let raw = format!("here: {enc} end");
        let d = decoded(&raw);
        assert!(
            d.iter()
                .any(|x| x.text.contains(secret) && x.chain.contains(&name)),
            "{name}: {d:?}"
        );
        let hit = d.iter().find(|x| x.text.contains(secret)).unwrap();
        assert!(
            raw[hit.src.0..hit.src.1].contains(&enc[..4.min(enc.len())]),
            "{name} source range"
        );
    }
}

#[test]
fn v5_chains_decode_to_depth_three_and_no_further() {
    let secret = "AKIAIOSFODNN7EXAMPLE";
    let d1 = b64(secret);
    let d2 = b64(&hex::encode(secret));
    let d3 = b64(&b64(&hex::encode(secret)));
    let d4 = b64(&d3);
    let any = |s: &str| decoded(s).iter().any(|x| x.text.contains(secret));
    assert!(any(&d1) && any(&d2) && any(&d3), "depths 1 to 3");
    assert!(!any(&d4), "depth 4 is a documented limit");
}

#[test]
fn v6_decoding_is_bounded_in_expansion_and_terminates() {
    let big = "A".repeat(200_000);
    let d = decoded(&big);
    let total: usize = d.iter().map(|x| x.text.len()).sum();
    assert!(total <= 4 * big.len() + 1024, "{total}");
    let nested = format!("{}{}", "%25".repeat(5000), "41");
    let _ = decoded(&nested);
}
