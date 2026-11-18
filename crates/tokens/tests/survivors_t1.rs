//! AT2 task 1 (closing the 48 open H1.2 survivors of the token crate): tests at the exact limits and on every clause of the validators. Expected values are written from the
//! documented limits (a stage record (not published) and the doc comments), not read from the code. Equivalent (argued in a stage record (not published)): the `kind` and `v` test in
//! `read_revocations` (the signature check re-derives the message with `v` 1 and `kind` revocations, so a list with other values can never verify), the size test in `issue_a`
//! (the closed claim limits keep a token under 16 KiB, far below the 64 KiB cap) and the `TooLarge` arm of `canon_deny` (the 64 KiB cap is checked before the 256 KiB one).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::Probe;
use entropa_tokens::canon::{parse, write, CanonError, Json, MAX_BYTES, MAX_DEPTH, MAX_NODES};
use entropa_tokens::{
    digest, issue_a, issue_revocations, key_id_of, narrow_a, verify_a, Claims, Deny, Policy,
    Reason, Tier, Trust, MAX_A_BYTES, MAX_LIST_BYTES,
};

const NOW: u64 = 1_800_000_000;

fn hex32(n: u64) -> String {
    format!("{n:032x}")
}
fn hex64(n: u64) -> String {
    format!("{n:064x}")
}
fn claims(id: u64) -> Claims {
    Claims {
        token_id: hex32(id),
        subject: "subject-1".into(),
        tier: Tier::T1,
        corpora: vec![hex64(1)],
        actions: vec!["call_model".into()],
        spend_cap: 1000,
        rate_cap: 10,
        not_before: NOW - 10,
        expiry: NOW + 600,
        audience: "node-1".into(),
        parent: None,
    }
}
fn policy() -> Policy {
    Policy {
        audience: "node-1".into(),
        now: NOW,
        skew: 30,
        max_ttl: 3600,
        rev_max_age: 300,
    }
}
fn trust_of(p: &Probe) -> Trust {
    let mut t = Trust::default();
    assert!(!t.add(&p.pubkey_hex()).is_empty());
    t
}

// ---- Claims::validate: every limit and clause ----
#[test]
fn t1_corpora_and_actions_limits_are_exact_and_every_clause_is_checked() {
    let mut c = claims(1);
    c.corpora = (1..=32).map(hex64).collect();
    assert!(c.validate().is_ok(), "32 corpora");
    c.corpora = (1..=33).map(hex64).collect();
    assert_eq!(c.validate(), Err("corpora"), "33 corpora");
    let mut c = claims(1);
    c.corpora = vec!["zz".repeat(32)];
    assert_eq!(c.validate(), Err("corpora"), "not hex");
    c.corpora = vec![hex64(0xabc).to_uppercase()];
    assert_eq!(c.validate(), Err("corpora"), "upper-case hex");
    c.corpora = vec![hex32(1)];
    assert_eq!(
        c.validate(),
        Err("corpora"),
        "32 hex characters are not a corpus hash"
    );
    c.corpora = vec![hex64(2), hex64(1)];
    assert_eq!(c.validate(), Err("corpora"), "descending");
    c.corpora = vec![hex64(1), hex64(1)];
    assert_eq!(c.validate(), Err("corpora"), "duplicate");

    let name = |i: usize| format!("act{i:03}");
    let mut c = claims(1);
    c.actions = (0..64).map(name).collect();
    assert!(c.validate().is_ok(), "64 actions");
    c.actions = (0..65).map(name).collect();
    assert_eq!(c.validate(), Err("actions"), "65 actions");
    let mut c = claims(1);
    c.actions = vec!["Bad Name".into()];
    assert_eq!(c.validate(), Err("actions"), "closed character set");
    c.actions = vec!["b".into(), "a".into()];
    assert_eq!(c.validate(), Err("actions"), "descending");
    c.actions = vec!["a".into(), "a".into()];
    assert_eq!(c.validate(), Err("actions"), "duplicate");
    c.actions = vec![String::new()];
    assert_eq!(c.validate(), Err("actions"), "empty name");
    c.actions = vec!["a".repeat(64)];
    assert!(c.validate().is_ok(), "a 64-character name");
    c.actions = vec!["a".repeat(65)];
    assert_eq!(c.validate(), Err("actions"), "a 65-character name");
    c.actions = vec!["a:b.c_d-e".into()];
    assert!(
        c.validate().is_ok(),
        "colon, dot, underscore, hyphen are allowed in an action name"
    );
}

#[test]
fn t2_names_and_ids_follow_their_closed_sets() {
    let mut c = claims(1);
    for ok in ["a", "a.b_c-d", &"a".repeat(64)] {
        c.subject = ok.to_string();
        assert!(c.validate().is_ok(), "{ok}");
    }
    for bad in ["", "A", "a b", "a:b", "é", &"a".repeat(65)] {
        c.subject = bad.to_string();
        assert_eq!(c.validate(), Err("subject"), "{bad:?}");
    }
    let mut c = claims(1);
    c.audience = "a".repeat(65);
    assert_eq!(c.validate(), Err("audience"));
    let mut c = claims(1);
    c.token_id = hex32(0xabc).to_uppercase();
    assert_eq!(c.validate(), Err("token_id"));
    c.token_id = "g".repeat(32);
    assert_eq!(c.validate(), Err("token_id"));
    c.token_id = hex64(1);
    assert_eq!(c.validate(), Err("token_id"), "32 characters exactly");
    let mut c = claims(1);
    c.parent = Some(hex32(1));
    assert_eq!(
        c.validate(),
        Err("parent"),
        "a token cannot be its own parent"
    );
    c.parent = Some(hex32(2));
    assert!(c.validate().is_ok());
    c.parent = Some("zz".repeat(16));
    assert_eq!(c.validate(), Err("parent"));
    let mut c = claims(1);
    c.expiry = c.not_before;
    assert_eq!(c.validate(), Err("validity window"));
}

// ---- key_id_of ----
#[test]
fn t3_a_key_id_exists_only_for_a_well_formed_public_key() {
    let k = Probe::spawn();
    let pk = k.pubkey_hex();
    let id = key_id_of(&pk).unwrap();
    assert_eq!(id.len(), 16);
    assert!(id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    assert!(key_id_of(&pk[..pk.len() - 2]).is_none(), "one byte short");
    assert!(key_id_of(&format!("{pk}00")).is_none(), "one byte long");
    assert!(key_id_of(&pk.to_uppercase()).is_none(), "upper-case");
    assert!(
        key_id_of(&format!("g{}", &pk[1..])).is_none(),
        "a non-hex character at the right length"
    );
    assert!(key_id_of("").is_none());
}

// ---- canonical JSON: limits and writing ----
#[test]
fn t4_the_reader_limits_are_exact() {
    let s = |n: usize| format!("\"{}\"", "a".repeat(n)).into_bytes();
    assert!(parse(&s(MAX_BYTES - 2)).is_ok(), "exactly 256 KiB");
    assert_eq!(
        parse(&s(MAX_BYTES - 1)),
        Err(CanonError::TooLarge),
        "one byte over"
    );
    let arr = |n: usize| format!("[{}]", vec!["1"; n].join(",")).into_bytes();
    assert!(
        parse(&arr(MAX_NODES - 1)).is_ok(),
        "the array and 4,095 elements are 4,096 values"
    );
    assert_eq!(parse(&arr(MAX_NODES)), Err(CanonError::TooMany));
    let nest = |k: usize| format!("{}1{}", "[".repeat(k), "]".repeat(k)).into_bytes();
    assert!(parse(&nest(MAX_DEPTH)).is_ok(), "8 nested containers");
    assert_eq!(parse(&nest(MAX_DEPTH + 1)), Err(CanonError::TooDeep));
    let nested_obj = |k: usize| format!("{}1{}", "{\"a\":".repeat(k), "}".repeat(k)).into_bytes();
    assert!(parse(&nested_obj(MAX_DEPTH)).is_ok());
    assert_eq!(parse(&nested_obj(MAX_DEPTH + 1)), Err(CanonError::TooDeep));
    // a wide and deep document of exactly the allowed shape: depth counts per branch, not per element
    assert!(parse(
        format!(
            "[{},{}]",
            String::from_utf8(nest(7)).unwrap(),
            String::from_utf8(nest(7)).unwrap()
        )
        .as_bytes()
    )
    .is_ok());
    // numbers
    for bad in ["-1", "+1", ".5", "01", "1.5", "1e3"] {
        let e = parse(bad.as_bytes());
        assert!(e.is_err(), "{bad}");
    }
    assert_eq!(parse(b"-1"), Err(CanonError::BadNumber));
    assert_eq!(parse(b"+1"), Err(CanonError::BadNumber));
    assert_eq!(parse(b".5"), Err(CanonError::BadNumber));
    assert_eq!(parse(b""), Err(CanonError::Empty));
    assert_eq!(parse(b"{\"a\":1,\"a\":2}"), Err(CanonError::DuplicateKey));
}

#[test]
fn t5_the_writer_escapes_control_characters_and_only_them() {
    assert_eq!(write(&Json::Str("\u{1}".into())), b"\"\\u0001\"");
    assert_eq!(write(&Json::Str("\u{1f}".into())), b"\"\\u001f\"");
    assert_eq!(
        write(&Json::Str(" ".into())),
        b"\" \"",
        "0x20 is not a control character"
    );
    assert_eq!(write(&Json::Str("\u{0}".into())), b"\"\\u0000\"");
    assert_eq!(
        write(&Json::Str("\t\n\r\u{8}\u{c}\"\\".into())),
        b"\"\\t\\n\\r\\b\\f\\\"\\\\\""
    );
    assert_eq!(write(&Json::Str("~".into())), b"\"~\"");
}

#[test]
fn t6_has_exactly_needs_the_same_keys_in_any_order() {
    let o = parse(br#"{"a":1,"b":2}"#).unwrap();
    assert!(o.has_exactly(&["a", "b"]));
    assert!(o.has_exactly(&["b", "a"]));
    assert!(!o.has_exactly(&["a"]), "one key short");
    assert!(!o.has_exactly(&["a", "b", "c"]), "one key more");
    assert!(!o.has_exactly(&["a", "c"]), "same count, one key missing");
    assert!(!o.has_exactly(&["c", "d"]));
    assert!(
        !parse(b"[1]").unwrap().has_exactly(&["a"]),
        "an array has no keys"
    );
}

// ---- revocation lists ----
fn revoked_list(issuer: &Probe, issued_at: u64, ids: &[(u64, Reason)]) -> Vec<u8> {
    let e: Vec<(String, u64, Reason)> = ids.iter().map(|(i, r)| (hex32(*i), 5, *r)).collect();
    issue_revocations(issuer, issued_at, &e)
}
fn token(issuer: &Probe, id: u64) -> Vec<u8> {
    issue_a(issuer, &claims(id)).unwrap()
}

#[test]
fn t7_every_reason_and_a_multi_entry_list_are_read() {
    let k = Probe::spawn();
    let trust = trust_of(&k);
    for reason in [Reason::Compromise, Reason::Requested, Reason::Superseded] {
        let list = revoked_list(
            &k,
            NOW,
            &[(1, reason), (7, Reason::Requested), (9, Reason::Compromise)],
        );
        assert_eq!(
            verify_a(&token(&k, 7), &trust, &policy(), Some(&list), None).map(|v| v.token_id),
            Err(Deny::Revoked),
            "{reason:?}: a token on a three-entry list"
        );
        assert_eq!(
            verify_a(&token(&k, 1), &trust, &policy(), Some(&list), None).map(|v| v.token_id),
            Err(Deny::Revoked)
        );
        assert!(
            verify_a(&token(&k, 5), &trust, &policy(), Some(&list), None).is_ok(),
            "a token that is not listed passes"
        );
    }
}

#[test]
fn t8_the_staleness_and_future_boundaries_use_the_clock_passed_in() {
    let k = Probe::spawn();
    let trust = trust_of(&k);
    let t = token(&k, 3);
    let at = |issued: u64| {
        verify_a(
            &t,
            &trust,
            &policy(),
            Some(&revoked_list(&k, issued, &[(8, Reason::Requested)])),
            None,
        )
        .map(|v| v.token_id)
    };
    assert!(
        at(NOW - 300).is_ok(),
        "a list exactly 300 s old is accepted"
    );
    assert_eq!(at(NOW - 301), Err(Deny::RevocationStale), "301 s is stale");
    assert!(at(NOW).is_ok());
    assert!(at(NOW + 30).is_ok(), "issued at now + skew is accepted");
    assert_eq!(
        at(NOW + 31),
        Err(Deny::RevocationInvalid),
        "issued after now + skew is dated in the future"
    );
    // the same list judged at another time: the clock is the policy's, nothing else
    let list = revoked_list(&k, NOW, &[(8, Reason::Requested)]);
    let mut later = policy();
    later.now = NOW + 300;
    later.max_ttl = 100_000;
    assert!(
        verify_a(&t, &trust, &later, Some(&list), None).is_ok(),
        "the token is valid until NOW + 600; the list is exactly 300 s old at NOW + 300: accepted"
    );
    later.now = NOW + 301;
    assert_eq!(
        verify_a(&t, &trust, &later, Some(&list), None).map(|v| v.token_id),
        Err(Deny::RevocationStale),
        "301 s later the same list is stale"
    );
    // a smaller maximum age narrows the window
    let mut tight = policy();
    tight.rev_max_age = 10;
    assert_eq!(
        verify_a(
            &t,
            &trust,
            &tight,
            Some(&revoked_list(&k, NOW - 11, &[])),
            None
        )
        .map(|v| v.token_id),
        Err(Deny::RevocationStale)
    );
    assert!(verify_a(
        &t,
        &trust,
        &tight,
        Some(&revoked_list(&k, NOW - 10, &[])),
        None
    )
    .is_ok());
    assert_eq!(
        verify_a(&t, &trust, &policy(), None, None).map(|v| v.token_id),
        Err(Deny::RevocationMissing)
    );
}

/// A list signed by `k` over a hand-built message, so that the ordering and format rules (not the issuer function) are what is tested.
fn handmade(k: &Probe, ids: &[&str]) -> Vec<u8> {
    let kid = key_id_of(&k.pubkey_hex()).unwrap();
    let entries = Json::Array(
        ids.iter()
            .map(|id| {
                Json::Object(vec![
                    ("reason".into(), Json::Str("requested".into())),
                    ("revoked_at".into(), Json::Num(5)),
                    ("token_id".into(), Json::Str((*id).to_string())),
                ])
            })
            .collect(),
    );
    let msg = Json::Object(vec![
        ("entries".into(), entries),
        ("issued_at".into(), Json::Num(NOW)),
        ("key_id".into(), Json::Str(kid)),
        ("kind".into(), Json::Str("revocations".into())),
        ("v".into(), Json::Num(1)),
    ]);
    let sig = k.sign_hex(&digest("revocations", &write(&msg)));
    let Json::Object(mut o) = msg else {
        unreachable!()
    };
    o.push(("sig".into(), Json::Str(sig)));
    write(&Json::Object(o))
}

#[test]
fn t9_a_correctly_signed_list_with_a_bad_entry_is_still_refused() {
    let k = Probe::spawn();
    let trust = trust_of(&k);
    let t = token(&k, 3);
    let v = |l: Vec<u8>| verify_a(&t, &trust, &policy(), Some(&l), None).map(|v| v.token_id);
    let (a, b, c) = (hex32(1), hex32(2), hex32(3));
    assert_eq!(
        v(handmade(&k, &[&a, &b, &c])),
        Err(Deny::Revoked),
        "token 3 is on this ascending list"
    );
    assert!(
        v(handmade(&k, &[&a, &b])).is_ok(),
        "an ascending list that does not name the token"
    );
    assert_eq!(
        v(handmade(&k, &[&b, &a])),
        Err(Deny::RevocationInvalid),
        "descending"
    );
    assert_eq!(
        v(handmade(&k, &[&a, &a])),
        Err(Deny::RevocationInvalid),
        "duplicate"
    );
    assert_eq!(
        v(handmade(&k, &["zz".repeat(16).as_str()])),
        Err(Deny::RevocationInvalid),
        "not hex"
    );
    assert_eq!(
        v(handmade(&k, &[hex32(0xabc).to_uppercase().as_str()])),
        Err(Deny::RevocationInvalid),
        "upper-case hex"
    );
    assert_eq!(
        v(handmade(&k, &[hex64(1).as_str()])),
        Err(Deny::RevocationInvalid),
        "64 characters"
    );
    assert_eq!(
        v(handmade(&k, &[&a[..30]])),
        Err(Deny::RevocationInvalid),
        "30 characters"
    );
}

#[test]
fn t10_a_list_of_exactly_the_maximum_size_is_read_and_one_byte_more_is_not() {
    let k = Probe::spawn();
    let trust = trust_of(&k);
    let t = token(&k, 3);
    // n entries of the same shape; revoked_at values of 1 to 20 digits adjust the length one byte at a time
    let build = |n: usize, extra: usize| {
        let mut left = extra;
        let e: Vec<(String, u64, Reason)> = (0..n)
            .map(|i| {
                let digits = 1 + left.min(18);
                left -= left.min(18);
                (
                    hex32(1000 + i as u64),
                    10u64.pow(digits as u32 - 1),
                    Reason::Requested,
                )
            })
            .collect();
        issue_revocations(&k, NOW, &e)
    };
    let mut n = 300;
    while build(n + 1, 0).len() <= MAX_LIST_BYTES {
        n += 1;
    }
    let base = build(n, 0).len();
    assert!(base <= MAX_LIST_BYTES);
    let list = build(n, MAX_LIST_BYTES - base);
    assert_eq!(
        list.len(),
        MAX_LIST_BYTES,
        "constructed to exactly the limit"
    );
    assert!(
        verify_a(&t, &trust, &policy(), Some(&list), None).is_ok(),
        "exactly 64 KiB is accepted"
    );
    let over = build(n, MAX_LIST_BYTES - base + 1);
    assert_eq!(over.len(), MAX_LIST_BYTES + 1);
    assert_eq!(
        verify_a(&t, &trust, &policy(), Some(&over), None).map(|v| v.token_id),
        Err(Deny::RevocationInvalid),
        "one byte over"
    );
}

// ---- design A parsing and parents ----
#[test]
fn t11_token_size_duplicate_keys_and_the_parent_checks() {
    let k = Probe::spawn();
    let k2 = Probe::spawn();
    let mut trust = trust_of(&k);
    assert!(!trust.add(&k2.pubkey_hex()).is_empty());
    let list = revoked_list(&k, NOW, &[]);
    // raw size: exactly the cap is not "too large" (it fails later), one more is
    let spaces = |n: usize| vec![b' '; n];
    assert_eq!(
        verify_a(
            &spaces(MAX_A_BYTES + 1),
            &trust,
            &policy(),
            Some(&list),
            None
        )
        .map(|v| v.token_id),
        Err(Deny::TooLarge)
    );
    assert_ne!(
        verify_a(&spaces(MAX_A_BYTES), &trust, &policy(), Some(&list), None).map(|v| v.token_id),
        Err(Deny::TooLarge),
        "exactly the cap passes the size test"
    );
    // a token with a repeated key is a duplicate-key refusal, not a generic one
    assert_eq!(
        verify_a(br#"{"a":1,"a":2}"#, &trust, &policy(), Some(&list), None).map(|v| v.token_id),
        Err(Deny::DuplicateKey)
    );

    // parent relations
    let parent = issue_a(&k, &claims(10)).unwrap();
    let mut child_claims = claims(11);
    child_claims.parent = Some(hex32(10));
    child_claims.actions = vec!["call_model".into()];
    let child = narrow_a(&k, &parent, &child_claims).unwrap();
    let ok = verify_a(&child, &trust, &policy(), Some(&list), Some(&parent));
    assert!(ok.is_ok(), "{ok:?}");
    // a different token of the same issuer presented as the parent: the id differs
    let other = issue_a(&k, &claims(12)).unwrap();
    assert_eq!(
        verify_a(&child, &trust, &policy(), Some(&list), Some(&other)).map(|v| v.token_id),
        Err(Deny::ParentMismatch),
        "wrong parent id, same key"
    );
    // the right id signed by another trusted issuer: the key differs
    let forged_parent = issue_a(&k2, &claims(10)).unwrap();
    assert_eq!(
        verify_a(&child, &trust, &policy(), Some(&list), Some(&forged_parent)).map(|v| v.token_id),
        Err(Deny::ParentMismatch),
        "right id, other issuer"
    );
    // a parent supplied for a token that names none
    let rootless = issue_a(&k, &claims(13)).unwrap();
    assert_eq!(
        verify_a(&rootless, &trust, &policy(), Some(&list), Some(&parent)).map(|v| v.token_id),
        Err(Deny::ParentMismatch),
        "a parent that was not named"
    );
    // a named parent that is not presented is simply not checked (the verifier checks what it is given)
    assert!(verify_a(&child, &trust, &policy(), Some(&list), None).is_ok());
}

// ---- the two survivors that were testable after the first kill-check ----
#[test]
fn t12_has_only_accepts_a_subset_of_keys_and_nothing_else() {
    let o = parse(br#"{"a":1,"b":2}"#).unwrap();
    assert!(o.has_only(&["a", "b"]));
    assert!(
        o.has_only(&["a", "b", "c"]),
        "a superset of the keys allowed is fine"
    );
    assert!(!o.has_only(&["a"]), "b is not among the allowed keys");
    assert!(!o.has_only(&[]));
    assert!(
        parse(b"{}").unwrap().has_only(&[]),
        "an empty object has only allowed keys"
    );
    assert!(
        !parse(b"[1]").unwrap().has_only(&["a"]),
        "an array is not an object"
    );
    assert!(!parse(b"1").unwrap().has_only(&["a"]));
}

#[test]
fn t13_the_denial_codes_written_to_the_trail_are_the_documented_closed_words() {
    let all = [
        (Deny::TooLarge, "too_large"),
        (Deny::Malformed, "malformed"),
        (Deny::DuplicateKey, "duplicate_key"),
        (Deny::NotCanonical, "not_canonical"),
        (Deny::BadAlgorithm, "bad_algorithm"),
        (Deny::UnknownKey, "unknown_key"),
        (Deny::BadSignature, "bad_signature"),
        (Deny::NotYetValid, "not_yet_valid"),
        (Deny::Expired, "expired"),
        (Deny::WrongAudience, "wrong_audience"),
        (Deny::TtlTooLong, "ttl_too_long"),
        (Deny::Revoked, "revoked"),
        (Deny::RevocationMissing, "revocation_missing"),
        (Deny::RevocationStale, "revocation_stale"),
        (Deny::RevocationInvalid, "revocation_invalid"),
        (Deny::Widened, "widened"),
        (Deny::ParentMismatch, "parent_mismatch"),
        (Deny::TooManyBlocks, "too_many_blocks"),
    ];
    for (d, s) in all {
        assert_eq!(d.as_str(), s);
    }
    let mut words: Vec<&str> = all.iter().map(|(_, s)| *s).collect();
    words.sort_unstable();
    words.dedup();
    assert_eq!(words.len(), 18, "eighteen distinct codes");
}
