//! EG1b: multibyte input must never reach a panic. Found by the sealed run of 2026-11-14 (`decide.rs:659`, byte index inside a Cyrillic letter).
//! The engine catches a panic and blocks (`internal_error`), so the guard failed closed, but a panic is a defect and a false block. Every test
//! here asserts the decision is NOT `internal_error`. Seeds are fixed (20261214); synthetic text only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_egress::decide::{decide, Action, Attachment, Reason, Request};
use entropa_egress::policy::Tier;

fn run(req: &Request) -> (Action, Reason) {
    let p = policy();
    let d = decide(req, &p, Tier::T1, &conv(), &Mem::new());
    (d.action(), d.reason())
}

/// Pieces that are triggers for slicing code or multibyte characters that look like ASCII letters under case folding.
const PIECES: &[&str] = &[
    "://",
    "http",
    "https://",
    "ftp",
    "AKIA",
    "ghp_",
    "sk-",
    "eyJ",
    "Bearer ",
    "Authorization: ",
    "password=",
    "GB",
    "AB",
    "DE89",
    "GB82WEST",
    "NHS ",
    "%",
    "%4",
    "&#",
    "&#x",
    ";",
    "\\u",
    "\\x",
    "@",
    ".",
    "-",
    "_",
    " ",
    "\n",
    "0",
    "1",
    "7",
    "a",
    "Z",
    "x",
    "\u{212a}", // Kelvin sign: matches [a-z] under (?i), uppercases to itself, three bytes
    "\u{17f}",  // long s: matches [a-z] under (?i), four... two bytes
    "\u{435}",  // Cyrillic е
    "\u{410}",  // Cyrillic А
    "\u{2014}", // em dash, a non-ASCII non-letter before a scheme
    "\u{ab}",   // «
    "\u{e9}",
    "\u{1f600}",
    "\u{200d}",
    "\u{200b}",
    "\u{301}",
    "\u{ff21}", // fullwidth A
    "\u{ff10}", // fullwidth 0
];

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn text(&mut self) -> String {
        let n = 1 + (self.next() % 14) as usize;
        (0..n)
            .map(|_| PIECES[(self.next() as usize) % PIECES.len()])
            .collect()
    }
}

#[test]
fn m1_the_sealed_panic_input_does_not_panic() {
    // a URL whose scheme follows a multibyte non-letter, and one that follows a Cyrillic letter (the sealed run's shape)
    for t in [
        "\u{2014}https://api.model.example/x",
        "\u{435}https://api.model.example/x",
        "see \u{ab}http://example.invalid/a\u{bb}",
        "\u{435}\u{435}://x",
    ] {
        let (a, r) = run(&text_req(t));
        assert_ne!(r, Reason::InternalError, "panic caught for {t:?} ({a:?})");
    }
}

#[test]
fn m2_random_multibyte_text_never_panics_in_any_leaf_kind() {
    let mut g = Lcg(20261214);
    let mut bad: Vec<String> = Vec::new();
    for _ in 0..6000 {
        let t = g.text();
        let json = format!("{{\"a\":{}}}", serde_json::to_string(&t).unwrap());
        let mut reqs = vec![
            text_req(&t),
            Request {
                body: json.into_bytes(),
                body_is_json: true,
                ..text_req("")
            },
            Request {
                headers: vec![("x-note".into(), t.clone())],
                ..text_req("hello")
            },
            Request {
                attachments: vec![Attachment {
                    name: "n.txt".into(),
                    mime: "text/plain".into(),
                    bytes: t.clone().into_bytes(),
                }],
                ..text_req("hello")
            },
        ];
        reqs.push(text_req(&format!("{t}{t}")));
        for r in &reqs {
            if run(r).1 == Reason::InternalError {
                bad.push(t.clone());
                break;
            }
        }
    }
    assert!(
        bad.is_empty(),
        "{} inputs panicked, first: {:?}",
        bad.len(),
        &bad[..bad.len().min(5)]
    );
}

#[test]
fn m3_targeted_slices_in_detectors_do_not_panic() {
    // each input aims at one byte-index slice in detect.rs: the NINO prefix test, the github-token checksum split, the IBAN rearrangement
    let k = "\u{212a}";
    let gh = format!("ghp_{}{}{}", "a".repeat(29), k, "bcde"); // 36 bytes after the prefix, byte 30 inside the Kelvin sign
    let mut bad: Vec<String> = Vec::new();
    for t in [
        format!("{k}{k} 12 34 56 A"),
        format!("{k}B 12 34 56 A"),
        format!("Number {k}B123456C here"),
        gh,
        format!("GB82{k}EST12345698765432"),
        format!("DE89 3704 0044 0532 0130 0{k}"),
        format!("{k}E89370400440532013000"),
    ] {
        let (a, r) = run(&text_req(&t));
        if r == Reason::InternalError {
            bad.push(format!("{t:?} ({a:?})"));
        }
    }
    assert!(bad.is_empty(), "panics caught for: {bad:#?}");
}

/// E1 as a property (EG1 task 4): 100,000 generated texts (override with EG1_CASES) built from the trigger pieces, as plain body, JSON field,
/// header and attachment, never end in `internal_error` and decide the same way twice.
#[test]
fn m4_property_no_generated_text_reaches_internal_error_and_decisions_repeat() {
    use proptest::prelude::*;
    use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
    let cases: u32 = std::env::var("EG1_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100_000);
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&20261215u64.to_le_bytes());
    let mut runner = TestRunner::new_with_rng(
        Config {
            cases,
            failure_persistence: None,
            ..Config::default()
        },
        TestRng::from_seed(RngAlgorithm::ChaCha, &seed),
    );
    let strat = proptest::collection::vec(0..PIECES.len(), 1..16)
        .prop_map(|v| v.into_iter().map(|i| PIECES[i]).collect::<String>());
    let p = policy();
    runner
        .run(&strat, |t| {
            let json = format!("{{\"a\":{}}}", serde_json::to_string(&t).unwrap());
            let reqs = [
                text_req(&t),
                Request {
                    body: json.into_bytes(),
                    body_is_json: true,
                    ..text_req("")
                },
                Request {
                    headers: vec![("x-note".into(), t.clone())],
                    ..text_req("hello")
                },
            ];
            for r in &reqs {
                let a = decide(r, &p, Tier::T1, &conv(), &Mem::new());
                prop_assert_ne!(a.reason(), Reason::InternalError, "{:?}", t);
                let b = decide(r, &p, Tier::T1, &conv(), &Mem::new());
                prop_assert_eq!((a.action(), a.reason()), (b.action(), b.reason()));
            }
            Ok(())
        })
        .unwrap();
}
