//! H1.3 task 2: property tests of the standards crate against the invariants in a stage record (not published) (written before any run).
//! I1 no panic, no hang, no unbounded allocation; I2 nonexistent id abstains; I3 existing id answers exactly; I4 untrusted, flagged demoted,
//! licensed quote limit; I6 one hash-only record per call; I7 determinism; plus the store loader never opens a tampered store.
//! Hermetic corpus: the real ids of the committed manifest (no text) with synthetic generated text, PCI marked licensed.
//! Run in release mode with `--test-threads=1` (the memory reading is process-wide): see the plan.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_standards::corpus::{text_sha256, Clause, ClauseEntry, Manifest, SourceEntry, Tier};
use entropa_standards::flags;
use entropa_standards::records::{EvidenceRequest, RecordSink};
use entropa_standards::retrieve::{Config, Retriever, Verdict};
use entropa_standards::seal;
use entropa_standards::text;
use entropa_standards::tools::Server;
use proptest::prelude::*;
use proptest::test_runner::{Config as PConfig, RngSeed};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------------------------- memory and time budget (I1)
// The workspace forbids unsafe code, so no allocator hook: the peak resident set is read from /proc/self/status (VmHWM) after resetting
// it through /proc/self/clear_refs, per case. Granularity is a page and untouched allocations are not seen; fuzz targets add libFuzzer's own
// rss limit. A documented limit of this measurement.
static GATE: Mutex<()> = Mutex::new(());
/// Wall-clock budget per call: 2 s in release; a debug build is about ten times slower, so it gets 20 s (H1.2 finding: i1b took 2.0 s on 105 KB in debug).
const TIME_BUDGET: Duration = if cfg!(debug_assertions) {
    Duration::from_secs(20)
} else {
    Duration::from_secs(2)
};
const HEAP_BUDGET: usize = 64 * 1024 * 1024;

fn status_kb(key: &str) -> usize {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with(key))
                .and_then(|l| l.split_whitespace().nth(1)?.parse::<usize>().ok())
        })
        .unwrap_or(0)
}

/// The memory reading is process-wide, so it only means something when one test runs at a time (`--test-threads=1`, as the plan says). With
/// several threads another test's allocations land in the window and the heap budget is not asserted.
fn single_threaded() -> bool {
    static S: OnceLock<bool> = OnceLock::new();
    *S.get_or_init(|| {
        std::env::var("RUST_TEST_THREADS").is_ok_and(|v| v == "1") || {
            let a: Vec<String> = std::env::args().collect();
            a.iter().any(|x| x == "--test-threads=1")
                || a.windows(2)
                    .any(|w| w[0] == "--test-threads" && w[1] == "1")
        }
    })
}

/// Run `f`, returning its value, its wall time and the peak resident-set growth in bytes while it ran.
fn measured<T>(f: impl FnOnce() -> T) -> (T, Duration, usize) {
    let _g = GATE.lock().unwrap_or_else(|e| e.into_inner());
    let _ = std::fs::write("/proc/self/clear_refs", "5");
    let base = status_kb("VmRSS:");
    let t = Instant::now();
    let r = f();
    let dt = t.elapsed();
    let growth = status_kb("VmHWM:").saturating_sub(base) * 1024;
    (r, dt, if single_threaded() { growth } else { 0 })
}

fn cases() -> u32 {
    std::env::var("H13_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100_000)
}
fn cfg(seed: u64) -> PConfig {
    PConfig {
        cases: cases(),
        rng_seed: RngSeed::Fixed(seed),
        max_shrink_iters: 4096,
        max_global_rejects: 1_000_000,
        ..PConfig::default()
    }
}

// ---------------------------------------------------------------------------------------------- hermetic corpus
const WORDS: [&str; 64] = [
    "operator",
    "shall",
    "document",
    "review",
    "access",
    "audit",
    "record",
    "system",
    "policy",
    "control",
    "incident",
    "response",
    "backup",
    "restore",
    "encryption",
    "key",
    "network",
    "boundary",
    "monitor",
    "log",
    "retention",
    "training",
    "awareness",
    "supplier",
    "contract",
    "risk",
    "assessment",
    "vulnerability",
    "patch",
    "configuration",
    "baseline",
    "change",
    "approval",
    "identity",
    "password",
    "token",
    "session",
    "lock",
    "remote",
    "wireless",
    "media",
    "disposal",
    "physical",
    "visitor",
    "badge",
    "personnel",
    "screening",
    "contingency",
    "recovery",
    "testing",
    "resilience",
    "third",
    "party",
    "provider",
    "report",
    "notification",
    "governance",
    "oversight",
    "transparency",
    "human",
    "data",
    "quality",
    "accuracy",
    "robustness",
];
fn synth_text(standard: &str, id: &str) -> String {
    let h = Sha256::digest(format!("{standard}|{id}").as_bytes());
    let pick = |i: usize| WORDS[usize::from(h[i % 32]) % WORDS.len()];
    let title = format!("{} {}", pick(0), pick(1));
    let n = 14 + usize::from(h[2]) % 30;
    let body: Vec<&str> = (0..n).map(|i| pick(3 + i * 7)).collect();
    format!(
        "{title}. The {} shall {} the {} and {}.",
        pick(5),
        body.join(" "),
        pick(9),
        pick(11)
    )
}
fn manifest_ids() -> &'static Vec<(String, String)> {
    static IDS: OnceLock<Vec<(String, String)>> = OnceLock::new();
    IDS.get_or_init(|| {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/evidence/r1/manifest-c2026-11-13.json");
        let v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        v["clauses"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| {
                (
                    c["standard"].as_str().unwrap().into(),
                    c["id"].as_str().unwrap().into(),
                )
            })
            .collect()
    })
}
fn clauses() -> Vec<Clause> {
    manifest_ids()
        .iter()
        .map(|(s, id)| {
            let t = synth_text(s, id);
            Clause {
                standard: s.clone(),
                std_version: "1".into(),
                id: id.clone(),
                tier: if s == "PCI-DSS" {
                    Tier::Licensed
                } else {
                    Tier::Open
                },
                text_sha256: text_sha256(&t),
                text: t,
            }
        })
        .collect()
}
/// The corpus version searched: the hermetic one, or the real sealed store when H13_STORE and H13_VERSION are set (read-only; only ids and
/// counts are ever printed).
fn ver() -> &'static str {
    static V: OnceLock<String> = OnceLock::new();
    V.get_or_init(
        || match (std::env::var("H13_STORE"), std::env::var("H13_VERSION")) {
            (Ok(_), Ok(v)) => v,
            _ => "h13".to_string(),
        },
    )
}
fn build() -> Retriever {
    match (std::env::var("H13_STORE"), std::env::var("H13_VERSION")) {
        (Ok(store), Ok(v)) => {
            Retriever::from_sealed(vec![
                seal::open(std::path::Path::new(&store), &v).expect("the real store opens")
            ])
        }
        _ => Retriever::from_clauses("h13", &"0".repeat(64), clauses()),
    }
}
fn rt() -> &'static Retriever {
    static R: OnceLock<Retriever> = OnceLock::new();
    R.get_or_init(build)
}
/// id (lowercase) -> the standards that hold it
fn id_index() -> &'static BTreeMap<String, BTreeSet<String>> {
    static M: OnceLock<BTreeMap<String, BTreeSet<String>>> = OnceLock::new();
    M.get_or_init(|| {
        let mut m: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (s, id) in manifest_ids() {
            m.entry(id.to_lowercase()).or_default().insert(s.clone());
        }
        m
    })
}
/// The canonical lowercase id of a written id ("Article 43" is "art.43").
fn canon(id: &str) -> String {
    let l = id.to_lowercase();
    if let Some(n) = l.strip_prefix("article ") {
        return format!("art.{n}");
    }
    // a NIST enhancement may be written XX-n.e (accepted alias of XX-n(e))
    let dot = regex::Regex::new(r"^([a-z]{1,2}-\d+)\.(\d+)$").unwrap();
    match dot.captures(&l) {
        Some(c) => format!("{}({})", &c[1], &c[2]),
        None => l,
    }
}
fn exists(id: &str) -> bool {
    id_index().contains_key(&canon(id))
}

// ---------------------------------------------------------------------------------------------- generators
const PIECES: &[&str] = &[
    "AC-2",
    "AC-99",
    "AC-2(4)",
    "ZZ-3",
    "SC-7(6)",
    "164.312(a)",
    "164.320(b)(1)",
    "164.312",
    "8.3.6",
    "8.3.6.2",
    "13.1",
    "Art.12",
    "Article 150",
    "Annex III",
    "Annex XV",
    "PCI DSS",
    "NIST SP 800-53",
    "DORA RTS",
    "EU AI Act",
    "HIPAA",
    "45 CFR",
    "v4.0.1",
    "TLS 1.2",
    "A.5.1",
    "CC6.1",
    "\u{a7}",
    "what",
    "how",
    "does",
    "the",
    "audit",
    "log",
    "retention",
    "?",
    " ",
    "  ",
    "(",
    ")",
    "(a)",
    "-",
    ".",
    "800-53",
    "800-171",
    "Rev. 5",
    "SOC 2",
    "ISO/IEC 27001",
    "GDPR article",
    "\u{200b}",
    "\u{0}",
    "\u{430}udit",
    "\u{ff21}C-2",
    "\u{663}.\u{662}",
    "\u{202e}",
    "\u{feff}",
    "\u{ad}",
    "\u{301}",
    "\u{1f600}",
    "\n",
    "\t",
];
const HOSTILE_CHARS: &[char] = &[
    '\0',
    '\u{200b}',
    '\u{200c}',
    '\u{200d}',
    '\u{200e}',
    '\u{2060}',
    '\u{feff}',
    '\u{ad}',
    '\u{202e}',
    '\u{2066}',
    '\u{301}',
    '\u{430}',
    '\u{435}',
    '\u{43e}',
    '\u{3b1}',
    '\u{39f}',
    '\u{ff21}',
    '\u{ff10}',
    '\u{663}',
    '\u{968}',
    '\u{1d400}',
    '\u{1f600}',
    '\u{10ffff}',
    '-',
    '(',
    ')',
    '.',
    '\u{a7}',
    ' ',
    '\n',
    '\t',
    '?',
    '0',
    '1',
    '9',
    'A',
    'z',
    'I',
    'V',
    'X',
    '/',
    '[',
    ']',
    '<',
    '>',
    '!',
    '\'',
    '"',
    '\\',
];
fn hostile() -> impl Strategy<Value = String> {
    prop_oneof![
        8 => any::<String>(),
        6 => prop::collection::vec(prop::sample::select(HOSTILE_CHARS.to_vec()), 0..200).prop_map(|v| v.into_iter().collect::<String>()),
        6 => prop::collection::vec(prop::sample::select(PIECES.to_vec()), 0..40).prop_map(|v| v.join(" ")),
        3 => (prop::sample::select(PIECES.to_vec()), 1usize..600).prop_map(|(p, n)| p.repeat(n)),
        1 => (prop::sample::select(HOSTILE_CHARS.to_vec()), 20_000usize..200_000).prop_map(|(c, n)| std::iter::repeat_n(c, n).collect::<String>()),
        1 => (prop::sample::select(PIECES.to_vec()), 20_000usize..120_000).prop_map(|(p, n)| p.repeat(n / p.len().max(1) + 1)),
    ]
}
fn configs() -> impl Strategy<Value = Config> {
    (any::<bool>(), any::<bool>(), any::<bool>(), any::<bool>()).prop_map(|(a, b, c, d)| Config {
        unindexed_guard: a,
        structural_flags: b,
        entity_guard: c,
        foreign_guard: d,
        ..Config::default()
    })
}
const NOISE: &[&str] = &[
    "what",
    "does",
    "say",
    "about",
    "explain",
    "tell",
    "please",
    "summary",
    "regarding",
    "the",
    "requirement",
    "control",
    "clause",
    "quote",
    "describe",
    "means",
    "show",
    "give",
    "details",
    "briefly",
];
fn noise(n: std::ops::Range<usize>) -> impl Strategy<Value = String> {
    prop::collection::vec(prop::sample::select(NOISE.to_vec()), n).prop_map(|v| v.join(" "))
}

fn standard_alias(s: &str) -> &'static str {
    match s {
        "NIST-SP-800-53" => "NIST SP 800-53",
        "PCI-DSS" => "PCI DSS",
        "EU-AI-ACT" => "EU AI Act",
        "DORA-RTS" => "DORA RTS",
        _ => "HIPAA",
    }
}

// ---------------------------------------------------------------------------------------------- I1
proptest! {
    #![proptest_config(cfg(20261101))]
    /// I1a: any query, any configuration: no panic, within the time and heap budgets, k respected, every passage untrusted.
    #[test]
    fn i1a_search_never_panics_hangs_or_balloons(q in hostile(), k in 0usize..30, c in configs()) {
        let retriever = rt(); // built before the measured window: loading the corpus is not a query
        let (r, dt, heap) = measured(|| retriever.search(&q, Some(ver()), k, &c));
        prop_assert!(dt < TIME_BUDGET, "took {dt:?} for {} bytes", q.len());
        prop_assert!(heap < HEAP_BUDGET, "heap {heap} for {} bytes", q.len());
        prop_assert!(r.passages.len() <= 10);
        prop_assert!(r.passages.iter().all(|p| p.untrusted));
        prop_assert!(r.verdict == Verdict::Answered || r.passages.is_empty());
    }
}

proptest! {
    #![proptest_config(cfg(20261102))]
    /// I1b: the text helpers and the flag detectors on any string.
    #[test]
    fn i1b_text_and_flag_helpers_never_panic_hang_or_balloon(s in hostile(), t in hostile(), n in 0usize..80) {
        let (_, dt, heap) = measured(|| {
            let toks = text::tokens(&s);
            let _ = text::sanitise(&s);
            let _ = text::first_words(&s, n);
            let terms = text::tokens(&t);
            let _ = text::best_window(&s, &terms, n);
            let _ = text::stem(&s);
            let _ = text::is_stop_word(&s);
            let _ = text::is_content_token(&s);
            let df = flags::gram_df(std::iter::once(toks.as_slice()));
            let _ = flags::static_flags(&s, &toks, &df);
            let qtoks = text::tokens(&t);
            let _ = flags::query_flags(&qtoks, &toks, flags::is_question(&t));
            let _ = flags::longest_run(&qtoks, &toks);
            let _ = flags::shingles(&toks);
        });
        prop_assert!(dt < TIME_BUDGET, "took {dt:?} for {}+{} bytes", s.len(), t.len());
        prop_assert!(heap < HEAP_BUDGET, "heap {heap}");
    }
}

fn arb_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|n| json!(n)),
        any::<u64>().prop_map(|n| json!(n)),
        any::<f64>().prop_map(|n| json!(n)),
        hostile().prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 64, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..5).prop_map(Value::Array),
            prop::collection::btree_map(
                prop_oneof![
                    3 => prop::sample::select(vec!["query", "version", "k", "standard", "clause", "hash", "extra", "", "\u{0}"]).prop_map(String::from),
                    1 => hostile()
                ],
                inner,
                0..6
            )
            .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}
fn tool_name() -> impl Strategy<Value = String> {
    prop_oneof![
        4 => prop::sample::select(vec!["lookup_clause", "search", "list_versions", "cite_check"]).prop_map(String::from),
        1 => hostile()
    ]
}

#[derive(Clone, Default)]
struct Rec(Arc<Mutex<Vec<EvidenceRequest>>>);
impl RecordSink for Rec {
    fn emit(&self, r: &EvidenceRequest) -> Result<(), String> {
        self.0.lock().unwrap().push(r.clone());
        Ok(())
    }
}
fn server() -> (Server, Rec) {
    let rec = Rec::default();
    (Server::new(build(), Box::new(rec.clone()), "h13"), rec)
}

proptest! {
    #![proptest_config(cfg(20261103))]
    /// I1c + I6a: any tool name and any JSON arguments: no panic, within budgets, an outcome is returned, exactly ONE record is requested per
    /// call (refused and unknown calls included), and the record carries no query text.
    #[test]
    fn i1c_tool_calls_never_panic_and_make_exactly_one_hash_only_record(
        name in tool_name(), args in arb_json(), q in hostile()
    ) {
        thread_local! { static S: std::cell::RefCell<Option<(Server, Rec)>> = const { std::cell::RefCell::new(None) }; }
        S.with(|cell| {
            let mut slot = cell.borrow_mut();
            let (srv, rec) = slot.get_or_insert_with(server);
            let before = rec.0.lock().unwrap().len();
            // half the time the hostile string becomes the query of a valid-looking search call
            let args2 = if matches!(args, Value::Null | Value::Bool(_)) && !q.is_empty() { json!({"query": q.clone()}) } else { args.clone() };
            let (out, dt, heap) = measured(|| srv.call(&name, &args2));
            prop_assert!(dt < TIME_BUDGET, "took {dt:?}");
            prop_assert!(heap < HEAP_BUDGET, "heap {heap}");
            prop_assert!(out.body.is_object() || out.body.is_null(), "{:?}", out.body);
            let recs = rec.0.lock().unwrap();
            prop_assert_eq!(recs.len(), before + 1, "one record per call");
            let r = recs.last().unwrap();
            let all = format!("{}|{}|{}|{}|{}", r.kind, r.label, r.reason, r.control, r.detail);
            if let Some(qs) = args2.get("query").and_then(Value::as_str) {
                if qs.chars().count() >= 12 && qs.chars().any(char::is_alphanumeric) {
                    prop_assert!(!all.contains(qs), "the record holds the query text");
                }
            }
            Ok(())
        })?;
    }
}

proptest! {
    #![proptest_config(cfg(20261104))]
    /// I1d: the spec parser and the store loader never panic on arbitrary text or arbitrary file bytes.
    #[test]
    fn i1d_spec_parser_and_store_loader_never_panic(s in hostile(), bytes in prop::collection::vec(any::<u8>(), 0..400), ver in hostile()) {
        let (_, dt, heap) = measured(|| {
            let _ = seal::parse_spec(&s);
            let dir = scratch("i1d");
            let v = dir.join("v1");
            std::fs::create_dir_all(&v).unwrap();
            std::fs::write(v.join("manifest.json"), &bytes).unwrap();
            std::fs::write(v.join("clauses.jsonl"), s.as_bytes()).unwrap();
            let _ = seal::open(&dir, "v1");
            let _ = seal::open(&dir, &ver);
            let _ = seal::list_versions(&dir);
        });
        prop_assert!(dt < TIME_BUDGET, "took {dt:?}");
        prop_assert!(heap < HEAP_BUDGET, "heap {heap}");
    }
}
fn scratch(name: &str) -> std::path::PathBuf {
    static N: OnceLock<std::path::PathBuf> = OnceLock::new();
    let base = N.get_or_init(|| {
        let d = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("h13-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    });
    let d = base.join(name);
    std::fs::create_dir_all(&d).unwrap();
    d
}

// ---------------------------------------------------------------------------------------------- I2
/// A nonexistent id-shaped token of the documented grammar, with the way it may be written.
fn nonexistent_id() -> impl Strategy<Value = String> {
    let nist = (
        prop::sample::select(vec!['A', 'Z', 'S', 'C', 'X']),
        prop::sample::select(vec!['C', 'Z', 'Q', 'T', 'R', 'A']),
        1u32..120,
        prop::option::of(1u32..60),
        any::<bool>(),
    )
        .prop_map(|(a, b, n, e, dot)| match e {
            Some(e) if dot => format!("{a}{b}-{n}.{e}"),
            Some(e) => format!("{a}{b}-{n}({e})"),
            None => format!("{a}{b}-{n}"),
        });
    let pci = (
        1u32..100,
        0u32..40,
        prop::option::of(0u32..40),
        prop::option::of(0u32..40),
    )
        .prop_map(|(a, b, c, d)| match (c, d) {
            (Some(c), Some(d)) => format!("{a}.{b}.{c}.{d}"),
            (Some(c), None) => format!("{a}.{b}.{c}"),
            _ => format!("{a}.{b}"),
        });
    let eu = (100u32..2000, any::<bool>()).prop_map(|(n, long)| {
        if long {
            format!("Article {n}")
        } else {
            format!("Art.{n}")
        }
    });
    let annex = prop::sample::select(vec!["XIV", "XV", "XX", "XXI", "XL", "L", "C"])
        .prop_map(|r| format!("Annex {r}"));
    let annex_n = (1u32..60).prop_map(|n| format!("Annex {n}"));
    let dora = (43u32..999).prop_map(|n| format!("Article {n}"));
    let hipaa = (
        100u32..999,
        prop::collection::vec(
            prop::sample::select(vec!["a", "b", "f", "g", "1", "2", "ii", "iv", "A", "x"]),
            0..4,
        ),
    )
        .prop_map(|(n, g)| {
            format!(
                "164.{n}{}",
                g.iter().map(|x| format!("({x})")).collect::<String>()
            )
        });
    let hipaa_nested = prop::sample::select(vec![
        "164.312(a)(1)",
        "164.312(a)(2)(iv)",
        "164.312(f)",
        "164.312(e)(2)(ii)",
        "164.312(a)(1)(i)",
    ])
    .prop_map(String::from);
    let other = (
        prop::sample::select(vec!["A", "CC", "AB", "C", "SOC"]),
        1u32..30,
        1u32..30,
        prop::option::of(1u32..30),
        any::<bool>(),
    )
        .prop_map(|(l, a, b, c, dot)| {
            let sep = if dot { "." } else { "" };
            match c {
                Some(c) => format!("{l}{sep}{a}.{b}.{c}"),
                None => format!("{l}{sep}{a}.{b}"),
            }
        });
    prop_oneof![
        nist,
        pci,
        eu,
        annex,
        annex_n,
        dora,
        hipaa,
        hipaa_nested,
        other
    ]
}
/// The documented exemptions of I2 (plan): versions n.0 and n.0.m, and a bare held HIPAA section.
fn exempt(id: &str) -> bool {
    let v = regex::Regex::new(r"^\d{1,2}\.0(\.\d{1,2})?$").unwrap();
    v.is_match(id) || id.eq_ignore_ascii_case("164.312")
}

proptest! {
    #![proptest_config(cfg(20261105))]
    /// I2: a nonexistent id-shaped token, with noise words around it and any case or spacing the grammar allows, never returns a passage.
    #[test]
    fn i2_a_nonexistent_id_never_returns_a_passage(
        id in nonexistent_id(), pre in noise(0..4), post in noise(0..4),
        upper in 0u8..3, std_name in prop::option::of(0usize..5), qmark in any::<bool>()
    ) {
        prop_assume!(!exists(&id) && !exempt(&id));
        let id_s = match upper { 0 => id.clone(), 1 => id.to_lowercase(), _ => id.to_uppercase() };
        let names = ["NIST-SP-800-53", "PCI-DSS", "EU-AI-ACT", "DORA-RTS", "HIPAA-SECURITY-RULE"];
        let sn = std_name.map(|i| standard_alias(names[i])).unwrap_or("");
        let q = format!("{pre} {sn} {id_s} {post}{}", if qmark { "?" } else { "" });
        let r = rt().search(&q, Some(ver()), 5, &Config::default());
        prop_assert!(r.passages.is_empty(), "{q:?} returned {:?}", r.passages.iter().map(|p| (&p.standard, &p.clause_id)).collect::<Vec<_>>());
        prop_assert_eq!(r.verdict, Verdict::NotInCorpus);
    }
}

proptest! {
    #![proptest_config(cfg(20261106))]
    /// I2b: an existing id next to a nonexistent one: the whole query abstains.
    #[test]
    fn i2b_an_existing_id_next_to_a_nonexistent_one_abstains(i in 0usize..1502, bad in nonexistent_id(), pre in noise(0..3)) {
        prop_assume!(!exists(&bad) && !exempt(&bad));
        let (s, id) = &manifest_ids()[i % manifest_ids().len()];
        let _ = s;
        let q = format!("{pre} {id} and {bad}");
        let r = rt().search(&q, Some(ver()), 5, &Config::default());
        prop_assert!(r.passages.is_empty(), "{q:?}");
    }
}

// ---------------------------------------------------------------------------------------------- I3
/// The ways each standard's ids are promised to be accepted.
fn written(std: &str, id: &str, variant: u8, upper: u8) -> String {
    let cased = |s: &str| match upper {
        0 => s.to_string(),
        1 => s.to_lowercase(),
        _ => s.to_uppercase(),
    };
    match std {
        "NIST-SP-800-53" => match (variant % 4, id.find('(')) {
            (1, Some(i)) => cased(&format!("{} {}", &id[..i], &id[i..])),
            (2, Some(i)) => cased(&format!("{}( {} )", &id[..i], &id[i + 1..id.len() - 1])),
            (3, _) => cased(&format!("control {id}")),
            _ => cased(id),
        },
        "PCI-DSS" => match variant % 4 {
            1 => format!("requirement {id}"),
            2 => format!("PCI DSS v4.0.1 requirement {id}"),
            3 => format!("PCI DSS 4.0 {id}"),
            _ => id.to_string(),
        },
        "EU-AI-ACT" | "DORA-RTS" => {
            if let Some(n) = id.strip_prefix("Art.") {
                match variant % 4 {
                    1 => format!("Article {n}"),
                    2 => cased(&format!("art. {n}")),
                    3 => cased(&format!("ARTICLE {n}")),
                    _ => format!("Art.{n}"),
                }
            } else {
                // "Annex III"
                match variant % 3 {
                    1 => cased(id),
                    2 => format!("the {id} list"),
                    _ => id.to_string(),
                }
            }
        }
        _ => match variant % 5 {
            1 => id.replace('(', " ("),
            2 => format!("\u{a7}{id}"),
            3 => format!("45 CFR \u{a7}{id}"),
            4 => cased(id),
            _ => id.to_string(),
        },
    }
}
proptest! {
    #![proptest_config(cfg(20261107))]
    /// I3: every existing id, in every written form the parser promises and with noise words around it, answers with exactly that clause
    /// (the standard's name in the query when two standards hold the same id).
    #[test]
    fn i3_an_existing_id_answers_exactly_that_clause(
        i in 0usize..1502, variant in 0u8..5, upper in 0u8..3, pre in noise(0..4), post in noise(0..4), name_it in any::<bool>()
    ) {
        let (std, id) = &manifest_ids()[i % manifest_ids().len()];
        let holders = &id_index()[&id.to_lowercase()];
        let shared = holders.len() > 1;
        let w = written(std, id, variant, upper);
        let name = if name_it || shared { standard_alias(std) } else { "" };
        let q = format!("{pre} {name} {w} {post}");
        let r = rt().search(&q, Some(ver()), 10, &Config::default());
        prop_assert_eq!(r.verdict, Verdict::Answered, "{} -> {}", q, r.reason);
        prop_assert!(r.passages[0].exact_id, "{q:?}");
        let got: Vec<(String, String)> = r.passages.iter().map(|p| (p.standard.clone(), p.clause_id.clone())).collect();
        prop_assert!(got.iter().any(|(s, c)| s == std && c.eq_ignore_ascii_case(id)), "{q:?} -> {got:?}");
        if name_it || shared || name.is_empty() {
            // exactly one clause: the named standard's, or the only holder of the id
            let expect_n = if !name.is_empty() { 1 } else { holders.len() };
            prop_assert_eq!(got.len(), expect_n, "{:?} -> {:?}", q, got);
        }
    }
}

// ---------------------------------------------------------------------------------------------- I4
fn vocab_query() -> impl Strategy<Value = String> {
    prop_oneof![
        4 => prop::collection::vec(prop::sample::select(WORDS.to_vec()), 1..9).prop_map(|v| v.join(" ")),
        2 => (prop::collection::vec(prop::sample::select(WORDS.to_vec()), 1..9), prop::sample::select(vec!["How", "What", "Which", "Who"]))
            .prop_map(|(v, w)| format!("{w} does the {} say?", v.join(" "))),
        1 => hostile(),
    ]
}
proptest! {
    #![proptest_config(cfg(20261108))]
    /// I4a: every passage is untrusted; a licensed passage has a quote of at most 25 words and no text; an open passage has text and no quote.
    #[test]
    fn i4a_passages_are_untrusted_and_licensed_text_is_one_short_quote(q in vocab_query(), k in 1usize..11) {
        let r = rt().search(&q, Some(ver()), k, &Config::default());
        for p in &r.passages {
            prop_assert!(p.untrusted);
            match p.tier {
                Tier::Licensed => {
                    prop_assert!(p.text.is_none(), "licensed text returned");
                    let quote = p.quote.as_ref().expect("a licensed passage carries its quote");
                    prop_assert!(quote.split_whitespace().count() <= 25, "{} words", quote.split_whitespace().count());
                }
                Tier::Open => prop_assert!(p.quote.is_none() && p.text.is_some()),
            }
        }
    }
}
proptest! {
    #![proptest_config(cfg(20261109))]
    /// I4b: with the flags on, a flagged text-search passage scores `flag_factor` times its score with the flags off (or is gone for an
    /// excluding flag) and an unflagged passage scores the same: a flagged clause cannot overtake an unflagged one of equal off-score.
    #[test]
    fn i4b_flags_demote_exactly_and_never_promote(q in vocab_query()) {
        let on = Config::default();
        let off = Config { structural_flags: false, ..Config::default() };
        let a = rt().search(&q, Some(ver()), 10, &on);
        let b = rt().search(&q, Some(ver()), 10, &off);
        if a.reason == "bm25" && b.reason == "bm25" {
            for p in &a.passages {
                if let Some(o) = b.passages.iter().find(|x| x.standard == p.standard && x.clause_id == p.clause_id) {
                    let query_flagged = (p.score - o.score).abs() > 1e-9 * o.score.abs().max(1.0);
                    if p.flags.is_empty() && !query_flagged {
                        prop_assert!((p.score - o.score).abs() <= 1e-9 * o.score.abs().max(1.0));
                    }
                    prop_assert!(p.score <= o.score * (1.0 + 1e-9), "promoted: {} > {}", p.score, o.score);
                    if !p.flags.is_empty() {
                        prop_assert!((p.score - o.score * on.flag_factor).abs() <= 1e-6 * o.score.abs().max(1.0) || p.score == 0.0, "{:?} {} vs {}", p.flags, p.score, o.score);
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------- I7
proptest! {
    #![proptest_config(cfg(20261110))]
    /// I7: two separately built retrievers (different hash seeds) and two calls give byte-identical output for any query.
    #[test]
    fn i7_retrieval_is_deterministic(q in prop_oneof![vocab_query(), hostile()], c in configs()) {
        static OTHER: OnceLock<Retriever> = OnceLock::new();
        let other = OTHER.get_or_init(build);
        let a = serde_json::to_string(&rt().search(&q, Some(ver()), 10, &c)).unwrap();
        let b = serde_json::to_string(&other.search(&q, Some(ver()), 10, &c)).unwrap();
        let a2 = serde_json::to_string(&rt().search(&q, Some(ver()), 10, &c)).unwrap();
        prop_assert_eq!(&a, &b);
        prop_assert_eq!(&a, &a2);
    }
}

// ---------------------------------------------------------------------------------------------- store loader tamper
fn good_store() -> (
    std::path::PathBuf,
    Vec<u8>,
    Vec<u8>,
    entropa_standards::corpus::Manifest,
    Vec<Clause>,
) {
    let cl: Vec<Clause> = clauses()
        .into_iter()
        .filter(|c| c.standard != "NIST-SP-800-53" || c.id.len() < 5)
        .take(40)
        .collect();
    let entries: Vec<ClauseEntry> = cl
        .iter()
        .map(|c| ClauseEntry {
            standard: c.standard.clone(),
            id: c.id.clone(),
            text_sha256: c.text_sha256.clone(),
        })
        .collect();
    let sources = vec![SourceEntry {
        standard: "S".into(),
        std_version: "1".into(),
        tier: Tier::Open,
        format: "text".into(),
        file: "s.txt".into(),
        source_sha256: "0".repeat(64),
        clauses: entries.len(),
    }];
    let m = Manifest {
        corpus_version: "v1".into(),
        corpus_hash: Manifest::compute_hash("v1", &sources, &entries),
        sources,
        clauses: entries,
    };
    let manifest = serde_json::to_vec_pretty(&m).unwrap();
    let mut jl = Vec::new();
    for c in &cl {
        jl.extend(serde_json::to_vec(c).unwrap());
        jl.push(b'\n');
    }
    (scratch("store"), manifest, jl, m, cl)
}
#[derive(Debug, Clone)]
enum Op {
    Flip(usize, u8),
    Delete(usize),
    Insert(usize, u8),
    Truncate(usize),
    DupLine(usize),
    DelLine(usize),
    SwapLines(usize, usize),
}
fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (any::<usize>(), 1u8..=255).prop_map(|(p, x)| Op::Flip(p, x)),
        any::<usize>().prop_map(Op::Delete),
        (any::<usize>(), any::<u8>()).prop_map(|(p, b)| Op::Insert(p, b)),
        any::<usize>().prop_map(Op::Truncate),
        any::<usize>().prop_map(Op::DupLine),
        any::<usize>().prop_map(Op::DelLine),
        (any::<usize>(), any::<usize>()).prop_map(|(a, b)| Op::SwapLines(a, b)),
    ]
}
fn apply(mut b: Vec<u8>, op: &Op) -> Vec<u8> {
    if b.is_empty() {
        return b;
    }
    let n = b.len();
    match op {
        Op::Flip(p, x) => b[p % n] ^= x,
        Op::Delete(p) => {
            b.remove(p % n);
        }
        Op::Insert(p, x) => b.insert(p % (n + 1), *x),
        Op::Truncate(p) => b.truncate(p % n),
        Op::DupLine(p) | Op::DelLine(p) | Op::SwapLines(p, _) => {
            let mut lines: Vec<Vec<u8>> = b.split(|c| *c == b'\n').map(<[u8]>::to_vec).collect();
            let m = lines.len();
            match op {
                Op::DupLine(p) => lines.insert(p % m, lines[p % m].clone()),
                Op::DelLine(p) => {
                    lines.remove(p % m);
                }
                Op::SwapLines(p, q) => lines.swap(p % m, q % m),
                _ => {}
            }
            let _ = p;
            b = lines.join(&b'\n');
        }
    }
    b
}
proptest! {
    #![proptest_config(cfg(20261111))]
    /// I5c: a tampered or truncated store never opens as verified unless it decodes to exactly the original manifest and clauses.
    #[test]
    fn i5c_a_tampered_store_never_opens(file in 0u8..2, o in op(), o2 in prop::option::of(op())) {
        let (dir, manifest, clauses_jl, m, cl) = good_store();
        let v = dir.join("v1");
        std::fs::create_dir_all(&v).unwrap();
        let (mut mb, mut cb) = (manifest.clone(), clauses_jl.clone());
        let target = if file == 0 { &mut mb } else { &mut cb };
        *target = apply(target.clone(), &o);
        if let Some(o2) = &o2 { *target = apply(target.clone(), o2); }
        std::fs::write(v.join("manifest.json"), &mb).unwrap();
        std::fs::write(v.join("clauses.jsonl"), &cb).unwrap();
        if let Ok(s) = seal::open(&dir, "v1") {
            prop_assert!(s.manifest == m && s.clauses == cl, "a changed store opened as verified");
        }
    }
}
