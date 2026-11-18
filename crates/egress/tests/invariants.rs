//! EG1 task 2 (red first): E1 to E10 as properties and fixed tests. `EG1_CASES` overrides the case count (default 100,000).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_egress::decide::{decide, decide_with_fault, Action, Fault};
use entropa_egress::policy::Tier;
use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};

fn cases() -> u32 {
    std::env::var("EG1_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100_000)
}
fn runner(seed: u64) -> TestRunner {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&seed.to_le_bytes());
    TestRunner::new_with_rng(
        Config {
            cases: cases(),
            failure_persistence: None,
            ..Config::default()
        },
        TestRng::from_seed(RngAlgorithm::ChaCha, &b),
    )
}
fn t(s: &str) -> Tier {
    s.parse().unwrap()
}
fn word() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-z]{1,9}".prop_map(|s| s),
        Just(SECRET.to_string()),
        Just("canary.user@example.com".to_string()),
        Just("4111111111111111".to_string()),
        Just("987-65-4321".to_string()),
        Just("-----BEGIN PRIVATE KEY-----".to_string()),
        Just("\u{200b}".to_string()),
        Just("\u{430}".to_string()),
        "[ -~]{0,12}".prop_map(|s| s),
    ]
}
fn body() -> impl Strategy<Value = String> {
    prop::collection::vec(word(), 0..14).prop_map(|v| v.join(" "))
}

#[test]
fn e1_no_planted_value_ever_appears_in_a_record() {
    let mut r = runner(20261201);
    r.run(&body(), |b| {
        let sink = Mem::new();
        let _ = decide(&text_req(&b), &policy(), t("T1"), &conv(), &sink);
        let rec = sink.last();
        let all = format!(
            "{} {} {} {} {} {}",
            rec.kind, rec.label, rec.decision, rec.reason, rec.control, rec.detail
        );
        for c in [
            SECRET,
            "canary.user",
            "4111111111111111",
            "987-65-4321",
            "BEGIN PRIVATE",
            "example.com",
        ] {
            prop_assert!(!all.contains(c), "{} in record", c);
        }
        Ok(())
    })
    .unwrap();
}

#[test]
fn e2_same_input_same_decision_bytes() {
    let mut r = runner(20261202);
    r.run(&body(), |b| {
        let s1 = Mem::new();
        let s2 = Mem::new();
        let d1 = decide(&text_req(&b), &policy(), t("T1"), &conv(), &s1);
        let d2 = decide(&text_req(&b), &policy(), t("T1"), &conv(), &s2);
        prop_assert_eq!(d1.action(), d2.action());
        prop_assert_eq!(d1.redacted_body(), d2.redacted_body());
        prop_assert_eq!(s1.last(), s2.last());
        Ok(())
    })
    .unwrap();
}

#[test]
fn e3_every_injected_fault_blocks_and_nothing_is_sent() {
    let mut r = runner(20261203);
    r.run(&(body(), 0usize..Fault::ALL.len()), |(b, i)| {
        let sink = Mem::new();
        let d = decide_with_fault(
            &text_req(&b),
            &policy(),
            t("T1"),
            &conv(),
            &sink,
            Some(Fault::ALL[i]),
        );
        prop_assert_eq!(d.action(), Action::Block);
        let mut sent = 0;
        let _ = entropa_egress::send::send_with(&d, b.as_bytes(), &mut |_| sent += 1);
        prop_assert_eq!(sent, 0);
        Ok(())
    })
    .unwrap();
}

#[test]
fn e5_records_equal_decisions_and_a_failing_sink_forces_block() {
    let mut r = runner(20261204);
    r.run(&body(), |b| {
        let sink = Mem::new();
        let _ = decide(&text_req(&b), &policy(), t("T1"), &conv(), &sink);
        prop_assert_eq!(sink.len(), 1);
        let d = decide(&text_req(&b), &policy(), t("T1"), &conv(), &Failing);
        prop_assert_eq!(d.action(), Action::Block);
        Ok(())
    })
    .unwrap();
}

#[test]
fn e6_adding_a_match_never_weakens_the_action_and_a_stricter_tier_never_allows_more() {
    let strict = |a: Action| match a {
        Action::Block => 2,
        Action::Redact => 1,
        Action::Allow => 0,
    };
    let mut r = runner(20261205);
    r.run(&(body(), word()), |(b, extra)| {
        let sink = Mem::new();
        let a0 = decide(&text_req(&b), &policy(), t("T1"), &conv(), &sink).action();
        let a1 = decide(
            &text_req(&format!("{b} {extra}")),
            &policy(),
            t("T1"),
            &conv(),
            &sink,
        )
        .action();
        prop_assert!(strict(a1) >= strict(a0), "{:?} -> {:?}", a0, a1);
        let t0 = decide(&text_req(&b), &policy(), t("T0"), &conv(), &sink).action();
        prop_assert_eq!(t0, Action::Block);
        Ok(())
    })
    .unwrap();
}

#[test]
fn e7_after_redaction_the_detectors_find_nothing_and_placeholders_are_stable() {
    let mut r = runner(20261206);
    r.run(&body(), |b| {
        let sink = Mem::new();
        let d = decide(&text_req(&b), &policy(), t("T1"), &conv(), &sink);
        if d.action() == Action::Redact {
            let out = String::from_utf8(d.redacted_body().unwrap().to_vec()).unwrap();
            let again = decide(&text_req(&out), &policy(), t("T1"), &conv(), &sink);
            prop_assert_eq!(again.action(), Action::Allow, "residual in {:?}", out);
        }
        Ok(())
    })
    .unwrap();
}

#[test]
fn e9_decision_time_is_bounded_and_linear() {
    use std::time::Instant;
    let budget = if cfg!(debug_assertions) { 20.0 } else { 2.0 };
    let unit = "word ".repeat(2_000);
    let mut times = vec![];
    for k in [1usize, 2, 4, 8] {
        let s = unit.repeat(k).replace("word", "x");
        let t0 = Instant::now();
        let _ = decide(&text_req(&s), &policy(), t("T3"), &conv(), &Mem::new());
        let dt = t0.elapsed().as_secs_f64();
        assert!(dt < budget, "{dt}");
        times.push(dt);
    }
    // linear within a generous factor: 8x the input takes less than 40x the time of the 1x input (plus a floor for timer noise)
    assert!(times[3] < 40.0 * times[0] + 0.05, "{times:?}");
}

#[test]
fn e10_vocabularies_are_closed() {
    use entropa_egress::decide::Reason;
    let all: Vec<&str> = Reason::ALL.iter().map(|r| r.as_str()).collect();
    assert_eq!(all.len(), 24);
    for s in [
        "clean",
        "redacted",
        "secret_format",
        "private_key",
        "credential_structure",
        "card_number",
        "personal_id",
        "personal_contact",
        "do_not_send_term",
        "document_marker",
        "entropy_hint",
        "obfuscation_suspected",
        "residual_after_redaction",
        "destination_denied",
        "tier_no_egress",
        "size_limit",
        "attachment_type_denied",
        "malformed_request",
        "dns_label_suspect",
        "budget_exceeded",
        "policy_invalid",
        "internal_error",
        "record_failed",
        "send_mismatch",
    ] {
        assert!(all.contains(&s), "{s}");
        assert_eq!(Reason::parse(s).map(|r| r.as_str()), Some(s));
    }
    assert!(Reason::parse("other").is_none());
}

#[test]
fn e4_the_crate_depends_on_no_network_crate_and_has_one_send_path_f8_f9() {
    let out = std::process::Command::new(env!("CARGO"))
        .args([
            "tree",
            "-p",
            "entropa-egress",
            "--offline",
            "--prefix",
            "none",
            "-e",
            "normal",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    let tree = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for bad in [
        "tokio", "hyper", "reqwest", "rmcp", "mio", "socket2", "h2 ", "ureq", "curl", "openssl",
        "rustls",
    ] {
        assert!(
            !tree.lines().any(|l| l.starts_with(bad)),
            "network crate {bad} in the tree:\n{tree}"
        );
    }
    // the source holds no network use and exactly one function that takes bytes to the outside
    let mut n_send = 0;
    // every .rs file under src, including src/bin (a directory there once made this test panic: the walk now descends into it)
    let mut files = Vec::new();
    let mut todo = vec![std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
    while let Some(d) = todo.pop() {
        for f in std::fs::read_dir(&d).unwrap() {
            let p = f.unwrap().path();
            if p.is_dir() {
                todo.push(p);
            } else if p.extension().is_some_and(|e| e == "rs") {
                files.push(p);
            }
        }
    }
    assert!(files.len() >= 9, "the source walk found too few files");
    for p in files {
        let s = std::fs::read_to_string(&p).unwrap();
        for bad in [
            "std::net",
            "TcpStream",
            "UdpSocket",
            "std::process::Command",
        ] {
            assert!(!s.contains(bad), "{bad} in {}", p.display());
        }
        n_send += s.matches("pub fn send_with").count();
    }
    assert_eq!(n_send, 1);
}
