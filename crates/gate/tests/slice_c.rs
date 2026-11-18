//! S1 slice C (task 4): the offline licence file. Bars from a stage record (not published) (project rule to L6), fixed before the code: strict parse and canonical bytes,
//! fail closed on a bad signature, the wrong product, an expired or not-yet-valid window (clock tolerance 24 h, boundaries tested), no network and no
//! clock in the library, and a planted-attack battery of 300 cases in each of 14 classes with 0 accepted (95 percent bound stated), plus a control
//! that 300 fresh valid licences are all accepted. The test builds licences through its OWN path (canonical JSON signed here), not through the issuer
//! it checks. Keys are generated per run; nothing secret is stored. Synthetic data only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::Probe;
use entropa_gate::licence::{
    check, Claims, Deny, Policy, DEFAULT_TOLERANCE_SECS, MAX_LICENCE_BYTES, PRODUCT,
};
use entropa_tokens::canon::{parse, write, Json};
use entropa_tokens::{digest, key_id_of};

const NOW: u64 = 1_800_000_000;
/// One planted attack: the bytes and the time at which they are checked.
type Attack = (Vec<u8>, u64);

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn pick<'a, T>(&mut self, v: &'a [T]) -> &'a T {
        &v[(self.next() as usize) % v.len()]
    }
    fn word(&mut self, alphabet: &str, n: usize) -> String {
        let a: Vec<char> = alphabet.chars().collect();
        (0..n)
            .map(|_| a[(self.next() as usize) % a.len()])
            .collect()
    }
}

fn s(v: &str) -> Json {
    Json::Str(v.to_string())
}
/// The licence message (everything except the signature) as a JSON object.
fn message(kid: &str, c: &Claims) -> Json {
    Json::Object(vec![
        ("alg".into(), s("ML-DSA-65")),
        ("build_id".into(), s(&c.build_id)),
        ("customer_id".into(), s(&c.customer_id)),
        (
            "entitlements".into(),
            Json::Array(c.entitlements.iter().map(|e| s(e)).collect()),
        ),
        ("expiry".into(), Json::Num(c.expiry)),
        ("key_id".into(), s(kid)),
        ("mark".into(), s(&c.mark)),
        ("not_before".into(), Json::Num(c.not_before)),
        ("product".into(), s(&c.product)),
        ("v".into(), Json::Num(1)),
    ])
}
/// Sign `msg` with the given digest kind and return the full licence bytes (message plus signature, canonical).
fn seal(k: &Probe, kind: &str, msg: Json) -> Vec<u8> {
    let sig = k.sign_hex(&digest(kind, &write(&msg)));
    let Json::Object(mut o) = msg else {
        unreachable!()
    };
    o.push(("sig".into(), Json::Str(sig)));
    write(&Json::Object(o))
}
fn good_claims(g: &mut Lcg) -> Claims {
    let n = 1 + (g.next() % 4) as usize;
    let mut ents: Vec<String> = Vec::new();
    while ents.len() < n {
        let e = [
            "explorer",
            "guard",
            "tokens",
            "witness",
            "licence-check",
            "export",
        ][(g.next() % 6) as usize]
            .to_string();
        if !ents.contains(&e) {
            ents.push(e);
        }
    }
    Claims {
        product: PRODUCT.to_string(),
        customer_id: format!(
            "cust-{}",
            g.word("abcdefghijklmnopqrstuvwxyz0123456789", 12)
        ),
        entitlements: ents,
        not_before: NOW - 86_400 * (1 + g.next() % 30),
        expiry: NOW + 86_400 * (1 + g.next() % 365),
        build_id: format!("build-{}.{}", g.next() % 100, g.next() % 100),
        mark: g.word("abcdef0123456789", 32),
    }
}
fn licence(k: &Probe, c: &Claims) -> Vec<u8> {
    seal(
        k,
        "licence",
        message(&key_id_of(&k.pubkey_hex()).unwrap(), c),
    )
}
fn pol(now: u64) -> Policy {
    Policy {
        now,
        tolerance_secs: DEFAULT_TOLERANCE_SECS,
        require: None,
    }
}
fn get<'a>(j: &'a Json, k: &str) -> &'a Json {
    j.get(k).unwrap()
}
fn set(j: &Json, k: &str, v: Json) -> Json {
    let Json::Object(o) = j else { unreachable!() };
    Json::Object(
        o.iter()
            .map(|(a, b)| {
                if a == k {
                    (a.clone(), v.clone())
                } else {
                    (a.clone(), b.clone())
                }
            })
            .collect(),
    )
}
fn bound(n: u32) -> f64 {
    1.0 - 0.05f64.powf(1.0 / f64::from(n))
}

#[test]
fn c1_a_good_licence_is_accepted_and_its_claims_are_read_back() {
    let k = Probe::spawn();
    let c = good_claims(&mut Lcg(1));
    let got = check(&licence(&k, &c), &k.pubkey_hex(), &pol(NOW)).unwrap();
    assert_eq!(got, c);
    let mut p = pol(NOW);
    p.require = Some(c.entitlements[0].clone());
    assert!(check(&licence(&k, &c), &k.pubkey_hex(), &p).is_ok());
    p.require = Some("not-granted".into());
    assert_eq!(
        check(&licence(&k, &c), &k.pubkey_hex(), &p),
        Err(Deny::MissingEntitlement)
    );
}

#[test]
fn c2_each_refusal_has_its_own_closed_code() {
    let k = Probe::spawn();
    let k2 = Probe::spawn();
    let c = good_claims(&mut Lcg(2));
    let ok = licence(&k, &c);
    let pk = k.pubkey_hex();
    let kid = key_id_of(&pk).unwrap();
    // wrong product (signed correctly)
    let mut w = c.clone();
    w.product = "other-product".into();
    assert_eq!(
        check(&licence(&k, &w), &pk, &pol(NOW)),
        Err(Deny::WrongProduct)
    );
    // expired and not yet valid
    assert_eq!(
        check(&ok, &pk, &pol(c.expiry + DEFAULT_TOLERANCE_SECS + 1)),
        Err(Deny::Expired)
    );
    assert_eq!(
        check(&ok, &pk, &pol(c.not_before - DEFAULT_TOLERANCE_SECS - 1)),
        Err(Deny::NotYetValid)
    );
    // not the trusted key (a valid licence of another issuer)
    assert_eq!(
        check(&licence(&k2, &c), &pk, &pol(NOW)),
        Err(Deny::UnknownKey)
    );
    // claims the trusted key id but signed by another key
    let forged = seal(&k2, "licence", message(&kid, &c));
    assert_eq!(check(&forged, &pk, &pol(NOW)), Err(Deny::BadSignature));
    // a signature made for another kind of message
    assert_eq!(
        check(&seal(&k, "a-token", message(&kid, &c)), &pk, &pol(NOW)),
        Err(Deny::BadSignature)
    );
    // header fields
    let m = message(&kid, &c);
    assert_eq!(
        check(
            &seal(&k, "licence", set(&m, "v", Json::Num(2))),
            &pk,
            &pol(NOW)
        ),
        Err(Deny::BadHeader)
    );
    assert_eq!(
        check(
            &seal(&k, "licence", set(&m, "alg", s("ML-DSA-44"))),
            &pk,
            &pol(NOW)
        ),
        Err(Deny::BadHeader)
    );
    // size, truncation, trailing bytes, non-canonical spelling
    assert_eq!(
        check(&vec![b' '; MAX_LICENCE_BYTES + 1], &pk, &pol(NOW)),
        Err(Deny::TooLarge)
    );
    assert_eq!(
        check(&ok[..ok.len() - 1], &pk, &pol(NOW)),
        Err(Deny::Malformed)
    );
    let mut t = ok.clone();
    t.push(b'\n');
    assert!(check(&t, &pk, &pol(NOW)).is_err());
    let spaced = String::from_utf8(ok.clone())
        .unwrap()
        .replacen("\"alg\":", "\"alg\": ", 1);
    assert_eq!(
        check(spaced.as_bytes(), &pk, &pol(NOW)),
        Err(Deny::Malformed),
        "spaces are not part of the accepted subset"
    );
    // the same content with two keys swapped is valid JSON of the accepted subset but not the canonical bytes that were signed
    let jb = parse(&ok).unwrap();
    let Json::Object(mut o) = jb else {
        unreachable!()
    };
    o.swap(0, 1);
    assert_eq!(
        check(
            &entropa_tokens::canon::write(&Json::Object(o.clone())),
            &pk,
            &pol(NOW)
        ),
        Ok(c.clone()),
        "the canonical writer sorts keys, so this is canonical again"
    );
    let reordered = format!(
        "{{\"build_id\":{},\"alg\":\"ML-DSA-65\"{}",
        String::from_utf8(write(&Json::Str(c.build_id.clone()))).unwrap(),
        &String::from_utf8(ok.clone()).unwrap()[String::from_utf8(ok.clone())
            .unwrap()
            .find(",\"build_id\":")
            .unwrap()
            + ",\"build_id\":".len()
            + String::from_utf8(write(&Json::Str(c.build_id.clone())))
                .unwrap()
                .len()..]
    );
    assert_eq!(
        check(reordered.as_bytes(), &pk, &pol(NOW)),
        Err(Deny::NotCanonical)
    );
    // bad field forms
    let mut b = c.clone();
    b.customer_id = "UPPER-CASE-ID".into();
    assert_eq!(check(&licence(&k, &b), &pk, &pol(NOW)), Err(Deny::BadField));
    let mut b = c.clone();
    b.entitlements = vec![];
    assert_eq!(check(&licence(&k, &b), &pk, &pol(NOW)), Err(Deny::BadField));
    let mut b = c.clone();
    b.expiry = b.not_before;
    assert_eq!(check(&licence(&k, &b), &pk, &pol(NOW)), Err(Deny::BadField));
    let mut b = c.clone();
    b.expiry = b.not_before + 6 * 365 * 86_400; // a six-year window: over the five-year limit
    assert_eq!(check(&licence(&k, &b), &pk, &pol(NOW)), Err(Deny::BadField));
    let mut b = c.clone();
    b.entitlements = vec!["explorer".into(), "explorer".into()];
    assert_eq!(
        check(&licence(&k, &b), &pk, &pol(NOW)),
        Err(Deny::BadField),
        "a duplicated entitlement"
    );
    let mut b = c.clone();
    b.entitlements = (0..17).map(|i| format!("e{i}")).collect();
    assert_eq!(
        check(&licence(&k, &b), &pk, &pol(NOW)),
        Err(Deny::BadField),
        "17 entitlements"
    );
    // codes are a closed list of distinct words
    let codes: Vec<&str> = [
        Deny::Malformed,
        Deny::NotCanonical,
        Deny::TooLarge,
        Deny::BadHeader,
        Deny::UnknownKey,
        Deny::BadSignature,
        Deny::BadField,
        Deny::WrongProduct,
        Deny::Expired,
        Deny::NotYetValid,
        Deny::MissingEntitlement,
    ]
    .iter()
    .map(|d| d.as_str())
    .collect();
    let mut u = codes.clone();
    u.sort_unstable();
    u.dedup();
    assert_eq!(u.len(), codes.len());
}

#[test]
fn c3_the_clock_tolerance_is_24_hours_on_both_ends_with_exact_boundaries() {
    let k = Probe::spawn();
    let c = good_claims(&mut Lcg(3));
    let pk = k.pubkey_hex();
    let l = licence(&k, &c);
    assert!(check(&l, &pk, &pol(c.expiry)).is_ok());
    assert!(
        check(&l, &pk, &pol(c.expiry + DEFAULT_TOLERANCE_SECS)).is_ok(),
        "the last accepted second"
    );
    assert_eq!(
        check(&l, &pk, &pol(c.expiry + DEFAULT_TOLERANCE_SECS + 1)),
        Err(Deny::Expired)
    );
    assert!(
        check(&l, &pk, &pol(c.not_before - DEFAULT_TOLERANCE_SECS)).is_ok(),
        "the first accepted second"
    );
    assert_eq!(
        check(&l, &pk, &pol(c.not_before - DEFAULT_TOLERANCE_SECS - 1)),
        Err(Deny::NotYetValid)
    );
    // a smaller tolerance narrows both ends
    let tight = Policy {
        now: c.expiry + 1,
        tolerance_secs: 0,
        require: None,
    };
    assert_eq!(check(&l, &pk, &tight), Err(Deny::Expired));
    assert_eq!(DEFAULT_TOLERANCE_SECS, 86_400);
}

#[test]
fn c4_planted_attacks_300_per_class_in_15_classes_none_accepted() {
    let k = Probe::spawn();
    let k2 = Probe::spawn();
    let (pk, pk2) = (k.pubkey_hex(), k2.pubkey_hex());
    let kid = key_id_of(&pk).unwrap();
    let kid2 = key_id_of(&pk2).unwrap();
    let mut g = Lcg(20261215);
    let base_c = good_claims(&mut g);
    let base = licence(&k, &base_c);
    let base_j = parse(&base).unwrap();
    let other = licence(&k, &good_claims(&mut g));
    let other_sig = get(&parse(&other).unwrap(), "sig")
        .as_str()
        .unwrap()
        .to_string();
    let accepted = |bytes: &[u8], now: u64| check(bytes, &pk, &pol(now)).is_ok();
    let mut classes: Vec<(&str, Vec<Attack>)> = Vec::new();

    // 1 tampered field: a field changed, the old signature kept
    let mut v = Vec::new();
    for i in 0..300 {
        let (key, val): (&str, Json) = match i % 7 {
            0 => (
                "customer_id",
                s(&format!("cust-{}", g.word("abcdefghijklmnop", 12))),
            ),
            1 => (
                "expiry",
                Json::Num(base_c.expiry + 1 + g.next() % 10_000_000),
            ),
            2 => (
                "not_before",
                Json::Num(base_c.not_before - 1 - g.next() % 100_000),
            ),
            3 => (
                "build_id",
                s(&format!("build-{}", g.word("abcdef0123456789", 8))),
            ),
            4 => ("mark", s(&g.word("abcdef0123456789", 32))),
            5 => (
                "entitlements",
                Json::Array(vec![s("explorer"), s(&format!("x{}", g.word("abcdef", 6)))]),
            ),
            _ => ("key_id", s(&kid2)),
        };
        v.push((write(&set(&base_j, key, val)), NOW));
    }
    classes.push(("tampered_field", v));
    // 2 swapped signature: the signature of another licence of the same issuer
    classes.push((
        "swapped_signature",
        (0..300)
            .map(|i| {
                let mut c = base_c.clone();
                c.mark = format!("{:032x}", i + 1);
                let j = parse(&licence(&k, &c)).unwrap();
                (write(&set(&j, "sig", s(&other_sig))), NOW)
            })
            .collect(),
    ));
    // 3 wrong key: signed by another issuer, with its own key id or with the trusted key id
    classes.push((
        "wrong_key",
        (0..300)
            .map(|i| {
                let mut c = base_c.clone();
                c.mark = format!("{:032x}", i + 1);
                let id = if i % 2 == 0 { &kid2 } else { &kid };
                (seal(&k2, "licence", message(id, &c)), NOW)
            })
            .collect(),
    ));
    // 4 expired: past expiry plus tolerance
    classes.push((
        "expired",
        (0..300)
            .map(|_| {
                (
                    base.clone(),
                    base_c.expiry + DEFAULT_TOLERANCE_SECS + 1 + g.next() % 1_000_000,
                )
            })
            .collect(),
    ));
    // 5 not yet valid
    classes.push((
        "not_yet_valid",
        (0..300)
            .map(|_| {
                (
                    base.clone(),
                    base_c.not_before - DEFAULT_TOLERANCE_SECS - 1 - g.next() % 1_000_000,
                )
            })
            .collect(),
    ));
    // 6 duplicated keys: one key repeated, anywhere, spelled out as raw text
    let text = String::from_utf8(base.clone()).unwrap();
    let pairs: Vec<String> = {
        let Json::Object(o) = &base_j else {
            unreachable!()
        };
        o.iter()
            .filter(|(a, _)| a != "sig")
            .map(|(a, b)| format!("\"{a}\":{}", String::from_utf8(write(b)).unwrap()))
            .collect()
    };
    classes.push((
        "duplicate_keys",
        (0..300)
            .map(|i| {
                let p = &pairs[i % pairs.len()];
                let at = 1 + (g.next() as usize) % 40;
                let mut t = text.clone();
                t.insert_str(1.max(at.min(text.find(',').unwrap())), &format!("{p},"));
                (t.into_bytes(), NOW)
            })
            .collect(),
    ));
    // 7 oversize
    classes.push((
        "oversize",
        (0..300)
            .map(|i| {
                let mut c = base_c.clone();
                c.mark = "a".repeat(64);
                let mut b = licence(&k, &c);
                b.extend(std::iter::repeat_n(b' ', MAX_LICENCE_BYTES + 1 + i * 997));
                (b, NOW)
            })
            .collect(),
    ));
    // 8 truncated at 300 positions
    classes.push((
        "truncated",
        (0..300)
            .map(|i| {
                (
                    base[..(i * base.len() / 300).min(base.len() - 1)].to_vec(),
                    NOW,
                )
            })
            .collect(),
    ));
    // 9 trailing bytes
    classes.push((
        "trailing_bytes",
        (0..300)
            .map(|i| {
                let mut b = base.clone();
                let n = 1 + i % 17;
                for _ in 0..n {
                    b.push(*g.pick(&[b' ', b'\n', 0u8, b'}', b'{', b'"', b'x', 0xffu8]));
                }
                (b, NOW)
            })
            .collect(),
    ));
    // 10 wrong product (signed correctly)
    classes.push((
        "wrong_product",
        (0..300)
            .map(|i| {
                let mut c = base_c.clone();
                c.product = match i % 5 {
                    0 => "Entropa-Gate".into(),
                    1 => format!("{PRODUCT}-{i}"),
                    2 => "entropa".into(),
                    3 => format!("x{PRODUCT}"),
                    _ => g.word("abcdefghij-", 12),
                };
                (licence(&k, &c), NOW)
            })
            .collect(),
    ));
    // 11 unicode confusables in ids and product (signed correctly)
    classes.push((
        "unicode_confusables",
        (0..300)
            .map(|i| {
                let mut c = base_c.clone();
                let conf = [
                    "\u{435}", "\u{430}", "\u{ff41}", "\u{ff10}", "\u{200b}", "\u{212a}",
                    "\u{17f}", "\u{43e}",
                ];
                let ch = conf[i % conf.len()];
                match i % 3 {
                    0 => c.customer_id = format!("cust-{ch}{}", g.word("abcdef", 8)),
                    1 => c.product = format!("entrop{ch}-gate"),
                    _ => c.mark = format!("{}{ch}", g.word("abcdef0123456789", 20)),
                };
                (licence(&k, &c), NOW)
            })
            .collect(),
    ));
    // 12 cross-kind signature: a signature made under another message kind
    classes.push((
        "cross_kind_signature",
        (0..300)
            .map(|i| {
                let mut c = base_c.clone();
                c.mark = format!("{:032x}", i + 1);
                (
                    seal(
                        &k,
                        ["a-token", "c-token", "revocations", "checkpoint", ""][i % 5],
                        message(&kid, &c),
                    ),
                    NOW,
                )
            })
            .collect(),
    ));
    // 13 non-canonical spelling of a valid licence: spaces, newlines, reordered keys, escapes
    classes.push((
        "non_canonical",
        (0..300)
            .map(|i| {
                let t = text.clone();
                let cuts: Vec<usize> = t.match_indices([',', ':']).map(|(p, _)| p).collect();
                let p = cuts[i % cuts.len()];
                let ws = [" ", "\n", "\t", "  ", "\r\n"][i % 5];
                let mut o = t.clone();
                o.insert_str(p + 1, ws);
                if i % 4 == 3 {
                    o = o.replace("\"v\":1", "\"v\":01");
                }
                (o.into_bytes(), NOW)
            })
            .collect(),
    ));
    // 14 header fields: version, algorithm, key id wrong but correctly signed
    classes.push((
        "bad_header",
        (0..300)
            .map(|i| {
                let m = message(&kid, &base_c);
                let m = match i % 3 {
                    0 => set(&m, "v", Json::Num(2 + (i as u64) % 50)),
                    1 => set(
                        &m,
                        "alg",
                        s(&format!(
                            "ML-DSA-{}",
                            ["44", "87", "65x", "", "ed25519"][i % 5]
                        )),
                    ),
                    _ => set(&m, "key_id", s(&g.word("0123456789abcdef", 16))),
                };
                (seal(&k, "licence", m), NOW)
            })
            .collect(),
    ));

    // 13b reordered keys: valid JSON of the accepted subset with a valid signature, but not the canonical bytes (appended to class 13)
    for (name, cases) in classes.iter_mut() {
        if *name == "non_canonical" {
            let mut extra = Vec::new();
            for i in 0..300usize {
                let mut order: Vec<usize> = (0..pairs.len()).collect();
                let r = 1 + i % (pairs.len() - 1);
                order.rotate_left(r);
                let sigpair = format!("\"sig\":\"{}\"", get(&base_j, "sig").as_str().unwrap());
                let body: Vec<&str> = order.iter().map(|&x| pairs[x].as_str()).collect();
                let mut all = body.clone();
                all.insert(i % (all.len() + 1), &sigpair);
                extra.push((format!("{{{}}}", all.join(",")).into_bytes(), NOW));
            }
            cases.extend(extra);
        }
    }
    // 15 unknown signed field: an extra key inside the signed message
    classes.push((
        "unknown_field",
        (0..300)
            .map(|i| {
                let Json::Object(mut o) = message(&kid, &base_c) else {
                    unreachable!()
                };
                let name = ["extra", "admin", "role", "licence_type", "x", "seats"][i % 6];
                o.push((
                    format!("{name}{}", i / 6),
                    if i % 2 == 0 { Json::Num(1) } else { s("yes") },
                ));
                (seal(&k, "licence", Json::Object(o)), NOW)
            })
            .collect(),
    ));
    assert_eq!(classes.len(), 15);
    let mut report = String::new();
    for (name, cases) in &classes {
        assert!(cases.len() >= 300, "{name}: {} cases", cases.len());
        let acc = cases.iter().filter(|(b, now)| accepted(b, *now)).count();
        report.push_str(&format!("{name}: {acc} accepted of {}\n", cases.len()));
        assert_eq!(
            acc,
            0,
            "{name}: {acc} of {} attacks were accepted",
            cases.len()
        );
    }
    assert!(bound(300) < 0.01, "stated bound {:.4}", bound(300));
    eprintln!(
        "{report}95 percent upper bound per class (zero accepted of 300): {:.4}",
        bound(300)
    );

    // control: the same battery machinery with VALID inputs is accepted (the checker is not simply refusing everything)
    let valid: Vec<Vec<u8>> = (0..300)
        .map(|_| licence(&k, &good_claims(&mut g)))
        .collect();
    assert_eq!(
        valid.iter().filter(|b| accepted(b, NOW)).count(),
        300,
        "false rejects of valid licences"
    );
}

#[test]
fn c5_the_licence_path_holds_no_clock_no_network_and_no_issuer() {
    let src =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/licence.rs")).unwrap();
    for bad in [
        "SystemTime",
        "Instant",
        "std::net",
        "TcpStream",
        "std::env",
        "std::process",
        "std::fs",
        "sign_hex",
        "Probe",
    ] {
        assert!(!src.contains(bad), "{bad} in licence.rs");
    }
}

#[test]
fn c6_the_command_line_checks_a_licence_with_a_key_file_and_refuses_without_a_key() {
    let t = tempfile::tempdir().unwrap();
    let k = Probe::spawn();
    // the command line reads the real clock, so the window is built around it
    let real = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let c = Claims {
        not_before: real - 86_400,
        expiry: real + 365 * 86_400,
        ..good_claims(&mut Lcg(6))
    };
    let lf = t.path().join("licence.json");
    std::fs::write(&lf, licence(&k, &c)).unwrap();
    let kf = t.path().join("issuer.pub");
    std::fs::write(&kf, k.pubkey_hex()).unwrap();
    let run = |args: &[&str]| {
        let o = std::process::Command::new(env!("CARGO_BIN_EXE_entropa-gate"))
            .args(args)
            .output()
            .unwrap();
        (
            o.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&o.stdout).into_owned(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        )
    };
    let (code, out, err) = run(&[
        "licence",
        "check",
        "--file",
        lf.to_str().unwrap(),
        "--pubkey-file",
        kf.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("licence: OK")
            && out.contains(&c.customer_id)
            && out.contains("clock tolerance: 24 h"),
        "{out}"
    );
    assert!(
        out.contains("key source: file"),
        "the output must say the key did not come from the build: {out}"
    );
    // a changed byte
    let mut b = std::fs::read(&lf).unwrap();
    let i = b.len() / 2;
    b[i] = if b[i] == b'a' { b'b' } else { b'a' };
    let bad = t.path().join("bad.json");
    std::fs::write(&bad, b).unwrap();
    let (code, out, err) = run(&[
        "licence",
        "check",
        "--file",
        bad.to_str().unwrap(),
        "--pubkey-file",
        kf.to_str().unwrap(),
    ]);
    assert_eq!(code, 1);
    assert!(
        err.contains("licence: refused (") && !out.contains("OK"),
        "{err}"
    );
    // another issuer's key
    let other = t.path().join("other.pub");
    std::fs::write(&other, Probe::spawn().pubkey_hex()).unwrap();
    assert_eq!(
        run(&[
            "licence",
            "check",
            "--file",
            lf.to_str().unwrap(),
            "--pubkey-file",
            other.to_str().unwrap()
        ])
        .0,
        1
    );
    // no embedded key in this build and no key file: refuse, say why
    let (code, _, err) = run(&["licence", "check", "--file", lf.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(err.contains("no verification key"), "{err}");
}

#[test]
fn c7_the_issuer_and_the_checker_agree_and_the_issuer_is_a_feature() {
    let k = Probe::spawn();
    let c = good_claims(&mut Lcg(7));
    let bytes = entropa_gate::licence_issue::issue(&k, &c).unwrap();
    assert_eq!(
        bytes,
        licence(&k, &c),
        "the issuer writes the same bytes as the test's own path"
    );
    assert_eq!(check(&bytes, &k.pubkey_hex(), &pol(NOW)), Ok(c.clone()));
    let mut w = c;
    w.product = "other".into();
    assert!(entropa_gate::licence_issue::issue(&k, &w).is_none());
    let lib = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs")).unwrap();
    assert!(
        lib.contains("#[cfg(feature = \"issue\")]\npub mod licence_issue;"),
        "the issuer must be behind the feature"
    );
    let toml = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap();
    assert!(toml.contains("issue = []") && !toml.contains("default = [\"issue\"]"));
}
