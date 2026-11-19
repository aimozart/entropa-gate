//! DASH1 red tests (a stage record (not published)). Expected counts are derived here from the request generator, not from the crate under test. Synthetic data only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::Probe;
use entropa_mockview::{generate, utc_day, Config, LABEL};
use serde_json::Value;
use std::path::PathBuf;

fn probe() -> Probe {
    Probe::from_signing_key_hex(&"05".repeat(32)).unwrap()
}
fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("dash1-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}
fn req_step(i: u32, step: u64) -> String {
    let (kind, label, control) = if i.is_multiple_of(3) {
        ("evidence.change", "code_change", "hitrust_10_sdlc")
    } else {
        (
            "evidence.policy",
            "policy_verdict",
            "hitrust_01_access_control",
        )
    };
    let (dec, reason) = if i.is_multiple_of(2) {
        ("allow", "within_limits")
    } else {
        ("deny", "policy_deny")
    };
    // one record per 20,000 s: the day changes every 4.32 records, so the day counts are not all equal
    format!(
        r#"{{"kind":"{kind}","label":"{label}","decision":"{dec}","reason":"{reason}","control":"{control}","total":{},"passed":{},"flagged":{},"detail":"synthetic detail {i}","run_id":"{i:064x}","ts":{}}}"#,
        i + 1,
        i % 2,
        i % 5,
        1_800_000_000u64 + u64::from(i) * step
    )
}
fn mock(tag: &str, n: u32) -> (PathBuf, String) {
    mock_step(tag, n, 20_000)
}
fn mock_step(tag: &str, n: u32, step: u64) -> (PathBuf, String) {
    let d = scratch(tag);
    std::fs::create_dir_all(d.join("evidence-ledger")).unwrap();
    let p = probe();
    let pk = p.pubkey_hex();
    for i in 0..n {
        let f = entropa_nodecore::evidence_event(&req_step(i, step), &pk).unwrap();
        entropa_nodecore::append(&d, "evidence-ledger", &p, &f).unwrap();
    }
    std::fs::write(
        d.join("MOCK-DATA.txt"),
        format!("{LABEL}\nsynthetic traffic; throwaway key; not production\n"),
    )
    .unwrap();
    (d, pk)
}
fn json(p: &std::path::Path) -> Value {
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

#[test]
fn d1_the_dashboard_files_exist_with_the_label_and_the_counts_match_the_generator() {
    let n = 45u32;
    let (d, pk) = mock("d1", n);
    let out = scratch("d1-out");
    generate(&d, &pk, &out, &Config::default()).unwrap();
    for f in ["dashboard.html", "dashboard.js", "data/summary.json"] {
        let t = std::fs::read_to_string(out.join(f)).unwrap_or_else(|_| panic!("missing {f}"));
        if f != "dashboard.js" {
            assert!(t.contains(LABEL), "{f} lacks the label");
        }
    }
    let s = json(&out.join("data/summary.json"));
    assert_eq!(s["records"], n);
    let even = (0..n).filter(|i| i % 2 == 0).count() as u64;
    assert_eq!(s["by_decision"]["allow"], even);
    assert_eq!(s["by_decision"]["deny"], u64::from(n) - even);
    let third = (0..n).filter(|i| i % 3 == 0).count() as u64;
    assert_eq!(s["by_kind"]["evidence.change"], third);
    assert_eq!(s["by_kind"]["evidence.policy"], u64::from(n) - third);
    assert_eq!(s["by_reason"]["within_limits"], even);
    assert_eq!(s["by_control"]["hitrust_10_sdlc"], third);
    // days: derived by hand from the timestamps with a separate formula
    let mut days = std::collections::BTreeMap::new();
    for i in 0..n {
        let ts = 1_800_000_000u64 + u64::from(i) * 20_000;
        *days.entry(ts / 86_400).or_insert(0u64) += 1;
    }
    let by_day = s["by_day"].as_object().unwrap();
    assert_eq!(by_day.len(), days.len());
    assert_eq!(
        by_day.values().map(|v| v.as_u64().unwrap()).sum::<u64>(),
        u64::from(n)
    );
    assert_eq!(
        by_day
            .values()
            .map(|v| v.as_u64().unwrap())
            .collect::<Vec<_>>(),
        days.values().copied().collect::<Vec<_>>(),
        "oldest day first, counts equal"
    );
    let newest = s["newest"].as_array().unwrap();
    assert_eq!(newest.len(), 10);
    assert_eq!(newest[0]["index"], n - 1, "newest first");
    assert_eq!(s["head"]["size"].as_u64().unwrap() as u32, n);
}

#[test]
fn d2_no_unsafe_sinks_csp_one_external_script_and_no_banned_or_process_words() {
    let (d, pk) = mock("d2", 12);
    let out = scratch("d2-out");
    generate(&d, &pk, &out, &Config::default()).unwrap();
    let js = std::fs::read_to_string(out.join("dashboard.js")).unwrap();
    for bad in [
        "innerHTML",
        "outerHTML",
        "eval(",
        "new Function",
        "document.write",
        "insertAdjacentHTML",
        "setAttribute(\"on",
        "setAttribute('on",
        ".style",
    ] {
        assert!(!js.contains(bad), "dashboard.js uses {bad}");
    }
    assert!(js.contains("textContent"));
    let html = std::fs::read_to_string(out.join("dashboard.html")).unwrap();
    assert!(html.contains("Content-Security-Policy"));
    assert!(html.contains("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'none'; base-uri 'none'; form-action 'none'"));
    assert_eq!(html.matches("<script").count(), 1);
    assert!(html.contains("<script src=\"dashboard.js\">"));
    assert!(!html.contains(" style=") && !html.contains(" onclick=") && !html.contains(" onload="));
    for f in ["dashboard.html", "dashboard.js", "data/summary.json"] {
        let low = std::fs::read_to_string(out.join(f))
            .unwrap()
            .replace("HITRUST secure development and maintenance", "")
            .to_lowercase();
        // the internal names are stored reversed so that this file does not carry them
        let reversed = ["yttocs", "kcops", "niatpac", "edualc"];
        let names: Vec<String> = reversed.iter().map(|n| n.chars().rev().collect()).collect();
        for w in [
            "secure",
            "compliant",
            "certified",
            "builder",
            "reviewer",
            "council",
        ]
        .iter()
        .map(|w| w.to_string())
        .chain(names)
        {
            assert!(!low.contains(&w), "{f} contains a banned word");
        }
    }
}

const HARNESS: &str = r#"
const fs = require('fs'); const path = process.argv[2]; const tamper = process.argv[3] || '';
function el(tag){ return {tag, children:[], textContent:'', attrs:{}, setAttribute(k,v){this.attrs[k]=v;}, removeAttribute(k){delete this.attrs[k];}, appendChild(c){this.children.push(c); return c;}, addEventListener(){}, set className(v){this.attrs.class=v;}, get className(){return this.attrs.class||'';}}; }
const doc = { createElement: el, getElementById: (id)=> (doc._ids[id] ||= el('div')), _ids:{} };
global.document = doc;
global.fetch = (u) => { let t = fs.readFileSync(path + '/' + u, 'utf8'); if (tamper && u === 'data/summary.json') { const j = JSON.parse(t); if (tamper === 'earlier') j.earlier_days.records += 1; else j.by_decision.allow += 1; t = JSON.stringify(j); } return Promise.resolve({ ok:true, json: () => Promise.resolve(JSON.parse(t)) }); };
const app = require(path + '/dashboard.js');
app.start(doc, fetch).then((r) => {
  const all = []; (function walk(n){ all.push(n); (n.children||[]).forEach(walk); })({children: Object.values(doc._ids)});
  console.log(JSON.stringify({ mismatch: doc._ids['mismatch'] ? doc._ids['mismatch'].textContent : null, label: doc._ids['label'] ? doc._ids['label'].textContent : null, meters: all.filter(n => n.tag === 'meter').length, rows: all.filter(n => n.attrs && n.attrs.class === 'newest-row').length, result: r }));
}).catch(e => { console.log('ERR ' + e.message); process.exit(1); });
"#;
/// The node program (ENTROPA_NODE overrides it, so that "node is missing" can be tried).
fn node_cmd() -> String {
    std::env::var("ENTROPA_NODE").unwrap_or_else(|_| "node".to_string())
}
/// The page tests run the page's JavaScript with node. The CI container image has no node: then the test SKIPS with a loud line, unless ENTROPA_REQUIRE_NODE=1 says node is required (then it fails).
fn node_or_skip(test: &str) -> bool {
    let present = std::process::Command::new(node_cmd())
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if present {
        return true;
    }
    assert!(
        std::env::var("ENTROPA_REQUIRE_NODE").as_deref() != Ok("1")
            && std::env::var("ENTROPA_REQUIRE_TOOLS").as_deref() != Ok("1"),
        "{test}: node is required (ENTROPA_REQUIRE_NODE=1) but was not found"
    );
    eprintln!("SKIPPED {test}: node is not installed here, so the page's JavaScript was not run");
    false
}
fn run_node(out: &std::path::Path, tamper: &str) -> Value {
    std::fs::write(out.join("harness.js"), HARNESS).unwrap();
    let o = std::process::Command::new(node_cmd())
        .arg(out.join("harness.js"))
        .arg(out)
        .arg(tamper)
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&o.stdout).to_string();
    assert!(
        o.status.success(),
        "node failed: {s} {}",
        String::from_utf8_lossy(&o.stderr)
    );
    serde_json::from_str(s.trim()).unwrap()
}

#[test]
fn d3_the_page_recomputes_the_numbers_and_shows_a_banner_only_when_they_differ() {
    if !node_or_skip("d3") {
        return;
    }
    let (d, pk) = mock("d3", 30);
    let out = scratch("d3-out");
    generate(
        &d,
        &pk,
        &out,
        &Config {
            page_size: 7,
            include_ledger: false,
        },
    )
    .unwrap();
    let good = run_node(&out, "");
    assert_eq!(good["mismatch"], "", "no banner for matching numbers");
    assert_eq!(good["label"], LABEL);
    assert!(good["meters"].as_u64().unwrap() >= 5, "bars are drawn");
    assert_eq!(good["rows"], 10);
    // a deliberately wrong number in summary.json (allow + 1)
    let bad = run_node(&out, "tamper");
    assert!(
        bad["mismatch"].as_str().unwrap().contains("do not match"),
        "banner for a wrong number: {bad}"
    );
}

#[test]
fn d4_regeneration_is_byte_identical() {
    let (d, pk) = mock("d4", 25);
    let (a, b) = (scratch("d4-a"), scratch("d4-b"));
    generate(&d, &pk, &a, &Config::default()).unwrap();
    generate(&d, &pk, &b, &Config::default()).unwrap();
    for f in ["dashboard.html", "dashboard.js", "data/summary.json"] {
        assert_eq!(
            std::fs::read(a.join(f)).unwrap(),
            std::fs::read(b.join(f)).unwrap(),
            "{f}"
        );
    }
}

#[test]
fn d5_a_refusal_writes_no_dashboard_file() {
    let (d, pk) = mock("d5", 10);
    let out = scratch("d5-out");
    let wrong = hex_flip(&pk);
    assert!(generate(&d, &wrong, &out, &Config::default()).is_err());
    for f in ["dashboard.html", "dashboard.js", "data/summary.json"] {
        assert!(!out.join(f).exists(), "{f} written on refusal");
    }
}
fn hex_flip(h: &str) -> String {
    let mut b = h.as_bytes().to_vec();
    b[0] = if b[0] == b'0' { b'1' } else { b'0' };
    String::from_utf8(b).unwrap()
}

#[test]
fn d6_utc_days_change_exactly_at_midnight_and_handle_leap_days() {
    assert_eq!(utc_day(0), "1970-01-01");
    assert_eq!(utc_day(86_399), "1970-01-01");
    assert_eq!(utc_day(86_400), "1970-01-02");
    assert_eq!(utc_day(951_782_400), "2000-02-29");
    assert_eq!(utc_day(1_800_000_000), "2027-01-15");
}

#[test]
#[ignore = "10,000 records: slow; writes the bundle into DASH1_OUT for the real-browser pass"]
fn d7_a_ten_thousand_record_bundle_for_the_browser_pass() {
    let Some(out) = std::env::var_os("DASH1_OUT") else {
        return;
    };
    let out = PathBuf::from(out);
    let (d, pk) = mock("d7", 10_000);
    let r = generate(&d, &pk, &out, &Config::default()).unwrap();
    let size = |f: &str| std::fs::metadata(out.join(f)).unwrap().len();
    println!(
        "D7 records={} pages={} total_bytes={} dashboard.html={} dashboard.js={} summary.json={}",
        r.records,
        r.pages,
        r.bytes,
        size("dashboard.html"),
        size("dashboard.js"),
        size("data/summary.json")
    );
}

#[test]
fn d8_a_feed_over_60_days_shows_the_latest_60_and_keeps_the_rest_as_a_total() {
    if !node_or_skip("d8") {
        return;
    }
    // 80 records, one every 100,000 s (1.157 days): 93 distinct days
    let n = 80u32;
    let step = 100_000u64;
    let (d, pk) = mock_step("d8", n, step);
    let out = scratch("d8-out");
    generate(
        &d,
        &pk,
        &out,
        &Config {
            page_size: 25,
            include_ledger: false,
        },
    )
    .unwrap();
    let s = json(&out.join("data/summary.json"));
    let mut days = std::collections::BTreeMap::new();
    for i in 0..n {
        *days
            .entry((1_800_000_000u64 + u64::from(i) * step) / 86_400)
            .or_insert(0u64) += 1;
    }
    assert!(days.len() > 60, "the fixture spans {} days", days.len());
    let by_day = s["by_day"].as_object().unwrap();
    assert_eq!(by_day.len(), 60, "only the latest 60 days are listed");
    let latest: Vec<u64> = days.values().rev().take(60).rev().copied().collect();
    assert_eq!(
        by_day
            .values()
            .map(|v| v.as_u64().unwrap())
            .collect::<Vec<_>>(),
        latest
    );
    let earlier_records: u64 = days.values().rev().skip(60).sum();
    assert_eq!(
        s["earlier_days"]["days"].as_u64().unwrap(),
        (days.len() - 60) as u64
    );
    assert_eq!(
        s["earlier_days"]["records"].as_u64().unwrap(),
        earlier_records
    );
    assert_eq!(
        earlier_records + latest.iter().sum::<u64>(),
        u64::from(n),
        "nothing is lost"
    );
    // the page recomputes the same split and agrees; a wrong earlier total shows the banner
    let good = run_node(&out, "");
    assert_eq!(good["mismatch"], "", "{good}");
    let bad = run_node(&out, "earlier");
    assert!(
        bad["mismatch"].as_str().unwrap().contains("do not match"),
        "{bad}"
    );
}

#[test]
fn d9_a_feed_of_60_days_or_fewer_has_no_earlier_total() {
    let (d, pk) = mock("d9", 20);
    let out = scratch("d9-out");
    generate(&d, &pk, &out, &Config::default()).unwrap();
    let s = json(&out.join("data/summary.json"));
    assert_eq!(s["earlier_days"]["days"], 0);
    assert_eq!(s["earlier_days"]["records"], 0);
}
