//! AT1 (after the reviewer's review of the bite test): the three defences a mutant could remove without a single-context attack noticing are tested
//! by CROSS-CONTEXT constructions: a signature made over a different message than the verifier rebuilds (wrong domain tag, a field left out of
//! the signed message), a block spliced onto a different ancestor, and one kind of document presented as another. Every construction is first
//! built CORRECTLY (control: it verifies), then with one difference (attack: it must not).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::Probe;
use entropa_tokens::canon::{parse, write, Json};
use entropa_tokens::testing::append_c_committing;
use entropa_tokens::{
    append_c, digest, empty_revocations, issue_a, issue_c, key_id_of, verify_a, verify_c, Claims,
    Deny, Narrowing, Policy, Tier, Trust, ALG,
};

const NOW: u64 = 1_800_000_000;
fn claims() -> Claims {
    Claims {
        token_id: "f".repeat(32),
        subject: "agent-x".into(),
        tier: Tier::T2,
        corpora: (0..4)
            .map(|i| format!("{:02x}", i + 0x10).repeat(32))
            .collect(),
        actions: ["cite_check", "lookup_clause", "search", "write"]
            .iter()
            .map(ToString::to_string)
            .collect(),
        spend_cap: 5_000_000,
        rate_cap: 600,
        not_before: NOW - 100,
        expiry: NOW + 1000,
        audience: "node-1".into(),
        parent: None,
    }
}
fn policy() -> Policy {
    Policy {
        audience: "node-1".into(),
        now: NOW,
        ..Policy::default()
    }
}
fn world() -> (Probe, Trust, Vec<u8>) {
    let p = Probe::spawn();
    let mut t = Trust::default();
    t.add(&p.pubkey_hex());
    let rev = empty_revocations(&p, NOW);
    (p, t, rev)
}
fn s(x: &str) -> Json {
    Json::Str(x.into())
}
fn without(members: &[(&str, Json)], drop: Option<&str>) -> Json {
    Json::Object(
        members
            .iter()
            .filter(|(k, _)| Some(*k) != drop)
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect(),
    )
}

/// A design A token signed over the message that has `drop` left out and the digest tagged `tag` (the correct tag is `a-token`).
fn a_token(issuer: &Probe, c: &Claims, tag: &str, drop: Option<&str>) -> Vec<u8> {
    let kid = key_id_of(&issuer.pubkey_hex()).unwrap();
    let full = [
        ("alg", s(ALG)),
        ("claims", c.to_json()),
        ("key_id", s(&kid)),
        ("v", Json::Num(1)),
    ];
    let sig = issuer.sign_hex(&digest(tag, &write(&without(&full, drop))));
    let mut o: Vec<(String, Json)> = full
        .iter()
        .map(|(k, v)| ((*k).to_string(), v.clone()))
        .collect();
    o.push(("sig".into(), Json::Str(sig)));
    write(&Json::Object(o))
}
/// A design C root token (no blocks) signed over the message with `drop` left out under `tag` (correct: `c-root`).
fn c_root(issuer: &Probe, c: &Claims, tag: &str, drop: Option<&str>) -> Vec<u8> {
    let kid = key_id_of(&issuer.pubkey_hex()).unwrap();
    let eph = Probe::spawn().pubkey_hex();
    let msg = [
        ("alg", s(ALG)),
        ("claims", c.to_json()),
        ("key_id", s(&kid)),
        ("next_pubkey", s(&eph)),
        ("v", Json::Num(1)),
    ];
    let sig = issuer.sign_hex(&digest(tag, &write(&without(&msg, drop))));
    write(&Json::Object(vec![
        ("alg".into(), s(ALG)),
        ("blocks".into(), Json::Array(vec![])),
        ("key_id".into(), s(&kid)),
        (
            "root".into(),
            Json::Object(vec![
                ("claims".into(), c.to_json()),
                ("next_pubkey".into(), s(&eph)),
                ("sig".into(), Json::Str(sig)),
            ]),
        ),
        ("v".into(), Json::Num(1)),
    ]))
}

#[test]
fn x1_controls_the_hand_built_tokens_verify_when_built_exactly_as_the_library_builds_them() {
    let (p, t, rev) = world();
    let a = a_token(&p, &claims(), "a-token", None);
    assert!(verify_a(&a, &t, &policy(), Some(&rev), None).is_ok());
    assert_eq!(
        a,
        issue_a(&p, &claims()).unwrap(),
        "byte-identical to the library's token"
    );
    let c = c_root(&p, &claims(), "c-root", None);
    assert!(verify_c(&c, &t, &policy(), Some(&rev)).is_ok());
}

#[test]
fn x2_a_signature_made_under_another_domain_tag_never_verifies() {
    let (p, t, rev) = world();
    for tag in [
        "c-root",
        "c-block",
        "revocations",
        "",
        "a-token ",
        "A-TOKEN",
        "entropa-token-v1",
    ] {
        let a = a_token(&p, &claims(), tag, None);
        assert_eq!(
            verify_a(&a, &t, &policy(), Some(&rev), None).unwrap_err(),
            Deny::BadSignature,
            "A under tag {tag:?}"
        );
    }
    for tag in ["a-token", "c-block", "revocations", "", "c-root ", "C-ROOT"] {
        let c = c_root(&p, &claims(), tag, None);
        assert_eq!(
            verify_c(&c, &t, &policy(), Some(&rev)).unwrap_err(),
            Deny::BadSignature,
            "C root under tag {tag:?}"
        );
    }
}

#[test]
fn x3_a_signature_over_a_message_with_a_field_left_out_never_verifies() {
    let (p, t, rev) = world();
    for drop in ["key_id", "alg", "v", "claims"] {
        let a = a_token(&p, &claims(), "a-token", Some(drop));
        assert_eq!(
            verify_a(&a, &t, &policy(), Some(&rev), None).unwrap_err(),
            Deny::BadSignature,
            "A without {drop} in the signed message"
        );
    }
    for drop in ["key_id", "alg", "v", "claims", "next_pubkey"] {
        let c = c_root(&p, &claims(), "c-root", Some(drop));
        assert_eq!(
            verify_c(&c, &t, &policy(), Some(&rev)).unwrap_err(),
            Deny::BadSignature,
            "C root without {drop} in the signed message"
        );
    }
}

/// A block appended by the real holder, signed over a message with `drop` left out under `tag` (correct: `c-block`).
fn block_variant(w: &entropa_tokens::Wallet, tag: &str, drop: Option<&str>) -> Vec<u8> {
    let j = parse(&w.token).unwrap();
    let root_sig = match &j {
        Json::Object(o) => match o.iter().find(|(k, _)| k == "root").map(|(_, v)| v) {
            Some(r) => r.get("sig").and_then(Json::as_str).unwrap().to_string(),
            None => panic!(),
        },
        _ => panic!(),
    };
    let prev: String = blake3::hash(root_sig.as_bytes())
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let eph = Probe::spawn().pubkey_hex();
    let narrow = Json::Object(vec![("spend_cap".into(), Json::Num(100))]);
    let msg = [
        ("narrow", narrow.clone()),
        ("next_pubkey", s(&eph)),
        ("prev", s(&prev)),
    ];
    let sig = w.key.sign_hex(&digest(tag, &write(&without(&msg, drop))));
    let block = Json::Object(vec![
        ("narrow".into(), narrow),
        ("next_pubkey".into(), s(&eph)),
        ("prev".into(), s(&prev)),
        ("sig".into(), Json::Str(sig)),
    ]);
    let Json::Object(mut top) = j else { panic!() };
    for (k, v) in &mut top {
        if k == "blocks" {
            *v = Json::Array(vec![block.clone()]);
        }
    }
    write(&Json::Object(top))
}

#[test]
fn x4_blocks_signed_over_the_wrong_tag_or_a_missing_field_never_verify() {
    let (p, t, rev) = world();
    let w = issue_c(&p, &claims()).unwrap();
    assert!(
        verify_c(
            &block_variant(&w, "c-block", None),
            &t,
            &policy(),
            Some(&rev)
        )
        .is_ok(),
        "control: the hand-built block verifies"
    );
    for tag in ["c-root", "a-token", "revocations", ""] {
        assert_eq!(
            verify_c(&block_variant(&w, tag, None), &t, &policy(), Some(&rev)).unwrap_err(),
            Deny::BadSignature,
            "tag {tag:?}"
        );
    }
    for drop in ["prev", "next_pubkey", "narrow"] {
        assert_eq!(
            verify_c(
                &block_variant(&w, "c-block", Some(drop)),
                &t,
                &policy(),
                Some(&rev)
            )
            .unwrap_err(),
            Deny::BadSignature,
            "without {drop}"
        );
    }
}

#[test]
fn x5_a_delegates_later_block_cannot_be_moved_onto_a_different_ancestor_that_commits_the_same_key()
{
    let (p, t, rev) = world();
    let root = issue_c(&p, &claims()).unwrap(); // the delegator holds this wallet (key K0)
    let narrowed = append_c(
        &root,
        &Narrowing {
            corpora: Some(vec![claims().corpora[0].clone()]),
            ..Narrowing::default()
        },
    )
    .unwrap(); // given to a delegate (key K1)
    let delegate = append_c(
        &narrowed,
        &Narrowing {
            spend_cap: Some(100),
            ..Narrowing::default()
        },
    )
    .unwrap();
    let honest = verify_c(&delegate.token, &t, &policy(), Some(&rev)).unwrap();
    assert_eq!(honest.claims.corpora.len(), 1);
    // the delegator builds a WIDER first block that commits the SAME public key K1, and moves the delegate's block onto it
    let k1 = match parse(&narrowed.token).unwrap().get("blocks") {
        Some(Json::Array(b)) => b[0]
            .get("next_pubkey")
            .and_then(Json::as_str)
            .unwrap()
            .to_string(),
        _ => panic!(),
    };
    let wider = append_c(&root, &Narrowing::default()).unwrap(); // a harmless block, only to learn the shape
    let _ = wider;
    let alt = append_c_committing(
        &root,
        &Narrowing {
            corpora: Some(claims().corpora[..3].to_vec()),
            ..Narrowing::default()
        },
        &k1,
    );
    let (Json::Object(mut alt_top), Json::Object(del_top)) =
        (parse(&alt.token).unwrap(), parse(&delegate.token).unwrap())
    else {
        panic!()
    };
    let del_blocks = match del_top
        .iter()
        .find(|(k, _)| k == "blocks")
        .map(|(_, v)| v.clone())
    {
        Some(Json::Array(b)) => b,
        _ => panic!(),
    };
    for (k, v) in &mut alt_top {
        if k == "blocks" {
            let Json::Array(b) = v else { panic!() };
            b.push(del_blocks[1].clone());
        }
    }
    let spliced = write(&Json::Object(alt_top));
    assert_eq!(
        verify_c(&spliced, &t, &policy(), Some(&rev)).unwrap_err(),
        Deny::BadSignature,
        "the delegate's block must stay bound to the exact block it was appended to"
    );
}

#[test]
fn x6_one_kind_of_document_presented_as_another_is_refused() {
    let (p, t, rev) = world();
    let a = issue_a(&p, &claims()).unwrap();
    let c = issue_c(&p, &claims()).unwrap().token;
    assert_eq!(
        verify_c(&a, &t, &policy(), Some(&rev)).unwrap_err(),
        Deny::Malformed
    );
    assert_eq!(
        verify_a(&c, &t, &policy(), Some(&rev), None).unwrap_err(),
        Deny::Malformed
    );
    assert_eq!(
        verify_a(&rev, &t, &policy(), Some(&rev), None).unwrap_err(),
        Deny::Malformed
    );
    assert_eq!(
        verify_c(&rev, &t, &policy(), Some(&rev)).unwrap_err(),
        Deny::Malformed
    );
    // a token presented where a revocation list is expected
    assert_eq!(
        verify_a(&a, &t, &policy(), Some(&a), None).unwrap_err(),
        Deny::RevocationInvalid
    );
    assert_eq!(
        verify_c(&c, &t, &policy(), Some(&c)).unwrap_err(),
        Deny::RevocationInvalid
    );
}

#[test]
fn x7_the_digest_separates_kinds_and_lengths_and_the_four_signed_shapes_never_coincide() {
    let m = br#"{"a":1}"#;
    let kinds = ["a-token", "c-root", "c-block", "revocations"];
    for (i, k1) in kinds.iter().enumerate() {
        for k2 in &kinds[i + 1..] {
            assert_ne!(digest(k1, m), digest(k2, m), "{k1} vs {k2}");
        }
    }
    assert_ne!(digest("a-token", b"{}"), digest("a-token", b"{} "));
    // the premise of the argument that the tag is defence in depth: the four signed messages have pairwise different member sets
    let (p, _, rev) = world();
    let keys = |j: &Json, drop: &[&str]| -> Vec<String> {
        let Json::Object(o) = j else { panic!() };
        let mut k: Vec<String> = o
            .iter()
            .map(|(k, _)| k.clone())
            .filter(|k| !drop.contains(&k.as_str()))
            .collect();
        k.sort();
        k
    };
    let a = parse(&issue_a(&p, &claims()).unwrap()).unwrap();
    let c = issue_c(&p, &claims()).unwrap();
    let cj = parse(&c.token).unwrap();
    let root = cj.get("root").unwrap();
    let mut croot = keys(&cj, &["blocks", "root", "sig"]);
    croot.push("claims".into());
    croot.push("next_pubkey".into());
    croot.sort();
    let w1 = append_c(
        &c,
        &Narrowing {
            tier: Some(Tier::T1),
            ..Narrowing::default()
        },
    )
    .unwrap();
    let blk = match parse(&w1.token).unwrap().get("blocks") {
        Some(Json::Array(b)) => b[0].clone(),
        _ => panic!(),
    };
    let _ = root;
    let shapes = [
        ("a-token", keys(&a, &["sig"])),
        ("c-root", croot),
        ("c-block", keys(&blk, &["sig"])),
        ("revocations", keys(&parse(&rev).unwrap(), &["sig"])),
    ];
    for (i, (n1, s1)) in shapes.iter().enumerate() {
        for (n2, s2) in &shapes[i + 1..] {
            assert_ne!(s1, s2, "{n1} and {n2} would sign the same set of members");
        }
    }
}
