//! LS2 red tests (a stage record (not published)). The ledger under test is built here from synthetic requests with a fixed synthetic key; the expected record fields come from the INDEPENDENT platinum export
//! (`entropa_platinum::export_evidence`), not from the crate under test. Synthetic data only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::Probe;
use entropa_ledger::Kind;
use entropa_mockview::{generate, Config, ViewError, LABEL};
use std::path::{Path, PathBuf};

const SEED_BYTE: u8 = 5;
fn probe() -> Probe {
    Probe::from_signing_key_hex(&format!("{SEED_BYTE:02x}").repeat(32)).unwrap()
}
fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ls2-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}
fn req(i: u32) -> String {
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
    format!(
        r#"{{"kind":"{kind}","label":"{label}","decision":"{dec}","reason":"{reason}","control":"{control}","total":{},"passed":{},"flagged":{},"detail":"synthetic detail {i}","run_id":"{i:064x}","ts":{}}}"#,
        i + 1,
        i % 2,
        i % 5,
        1_800_000_000 + i
    )
}
/// A mock ledger directory with `n` records, the marker file and the throwaway key's public half.
fn mock(tag: &str, n: u32) -> (PathBuf, String) {
    let d = scratch(tag);
    std::fs::create_dir_all(d.join("evidence-ledger")).unwrap();
    let p = probe();
    let pk = p.pubkey_hex();
    for i in 0..n {
        let f = entropa_nodecore::evidence_event(&req(i), &pk).unwrap();
        entropa_nodecore::append(&d, "evidence-ledger", &p, &f).unwrap();
    }
    std::fs::write(
        d.join("MOCK-DATA.txt"),
        format!(
            "{LABEL}\nsynthetic traffic from a seeded generator; throwaway key; not production\n"
        ),
    )
    .unwrap();
    (d, pk)
}
fn files(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = vec![];
    fn walk(base: &Path, d: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        let mut es: Vec<_> = std::fs::read_dir(d)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        es.sort();
        for p in es {
            if p.is_dir() {
                walk(base, &p, out);
            } else {
                out.push((
                    p.strip_prefix(base).unwrap().to_string_lossy().into_owned(),
                    std::fs::read(&p).unwrap(),
                ));
            }
        }
    }
    if dir.exists() {
        walk(dir, dir, &mut out);
    }
    out
}
fn text(b: &[u8]) -> String {
    String::from_utf8(b.to_vec()).unwrap()
}

#[test]
fn l1_a_verified_mock_ledger_becomes_a_paged_bundle_with_the_label_everywhere() {
    let (d, pk) = mock("l1", 450);
    let out = scratch("l1-out");
    let r = generate(&d, &pk, &out, &Config::default()).unwrap();
    assert_eq!((r.records, r.pages), (450, 3));
    let fs = files(&out);
    let names: Vec<&str> = fs.iter().map(|f| f.0.as_str()).collect();
    for want in [
        "index.html",
        "style.css",
        "app.js",
        "data/meta.json",
        "data/page-0001.json",
        "data/page-0002.json",
        "data/page-0003.json",
    ] {
        assert!(names.contains(&want), "missing {want}: {names:?}");
    }
    assert!(!names.contains(&"data/page-0004.json"));
    for (n, b) in &fs {
        if n.ends_with(".html") || n.ends_with(".json") {
            assert!(text(b).contains(LABEL), "{n} lacks the label");
        }
    }
    let p3: serde_json::Value =
        serde_json::from_slice(&fs.iter().find(|f| f.0 == "data/page-0003.json").unwrap().1)
            .unwrap();
    assert_eq!(p3["records"].as_array().unwrap().len(), 50);
    assert_eq!(p3["records"][0]["index"], 400);
    assert_eq!(r.bytes, fs.iter().map(|f| f.1.len() as u64).sum::<u64>());
}

#[test]
fn l2_every_refusal_writes_nothing() {
    let (d, pk) = mock("l2", 20);
    let cfg = Config::default();
    let try_out = |dir: &Path, key: &str, tag: &str| {
        let out = scratch(tag);
        let e = generate(dir, key, &out, &cfg).unwrap_err();
        assert!(
            files(&out).is_empty(),
            "{tag}: files were written on refusal"
        );
        e
    };
    // wrong key
    let other = Probe::from_signing_key_hex(&format!("{:02x}", 6u8).repeat(32))
        .unwrap()
        .pubkey_hex();
    assert!(matches!(
        try_out(&d, &other, "l2-key"),
        ViewError::NotVerified(_)
    ));
    // a flipped byte in a record and in a checkpoint
    for (f, tag) in [("records.log", "l2-rec"), ("checkpoints.log", "l2-cp")] {
        let c = scratch(&format!("{tag}-src"));
        std::fs::create_dir_all(c.join("evidence-ledger")).unwrap();
        for g in ["records.log", "checkpoints.log"] {
            std::fs::copy(
                d.join("evidence-ledger").join(g),
                c.join("evidence-ledger").join(g),
            )
            .unwrap();
        }
        std::fs::copy(d.join("MOCK-DATA.txt"), c.join("MOCK-DATA.txt")).unwrap();
        let p = c.join("evidence-ledger").join(f);
        let mut b = std::fs::read(&p).unwrap();
        b[60] = if b[60] == b'0' { b'1' } else { b'0' };
        std::fs::write(&p, b).unwrap();
        assert!(
            matches!(try_out(&c, &pk, tag), ViewError::NotVerified(_)),
            "{tag}"
        );
    }
    // marker: missing, wrong first line, oversize
    let m = d.join("MOCK-DATA.txt");
    let good = std::fs::read(&m).unwrap();
    let moved = d.join("MOCK-DATA.moved");
    std::fs::rename(&m, &moved).unwrap(); // moved aside, not deleted
    assert!(matches!(
        try_out(&d, &pk, "l2-nomarker"),
        ViewError::NoMockMarker(_)
    ));
    std::fs::write(&m, "real data\n").unwrap(); // a new file with the wrong first line
    assert!(matches!(
        try_out(&d, &pk, "l2-wrong"),
        ViewError::NoMockMarker(_)
    ));
    std::fs::write(&m, format!("{LABEL}\n{}", "x".repeat(4097))).unwrap();
    assert!(matches!(
        try_out(&d, &pk, "l2-big"),
        ViewError::NoMockMarker(_)
    ));
    std::fs::write(&m, &good).unwrap();
    // an empty ledger
    let e = scratch("l2-empty");
    std::fs::create_dir_all(e.join("evidence-ledger")).unwrap();
    std::fs::write(e.join("MOCK-DATA.txt"), format!("{LABEL}\n")).unwrap();
    assert_eq!(try_out(&e, &pk, "l2-empty-out"), ViewError::Empty);
    // sanity: the untouched ledger does generate
    assert!(generate(&d, &pk, &scratch("l2-ok"), &cfg).is_ok());
    let _ = Kind::PlatinumDecision;
}

#[test]
fn l3_hostile_marker_text_never_reaches_the_pages_as_markup() {
    let (d, pk) = mock("l3", 5);
    let hostile = "<script>alert(1)</script> \u{202e}\u{1F600} & \"quote\" </script><img src=x onerror=alert(2)>";
    std::fs::write(d.join("MOCK-DATA.txt"), format!("{LABEL}\n{hostile}\n")).unwrap();
    let out = scratch("l3-out");
    generate(&d, &pk, &out, &Config::default()).unwrap();
    for (n, b) in files(&out) {
        let t = text(&b);
        if n.ends_with(".json") {
            assert!(
                !t.contains('<') && !t.contains('>') && !t.contains('&'),
                "{n}: raw markup character in JSON"
            );
        }
        if n.ends_with(".html") {
            let scripts: Vec<&str> = t
                .match_indices("<script")
                .map(|(i, _)| &t[i..i + 40.min(t.len() - i)])
                .collect();
            assert!(
                scripts
                    .iter()
                    .all(|s| s.starts_with("<script src=\"app.js\"")),
                "{n}: inline or foreign script: {scripts:?}"
            );
            assert!(!t.contains("onerror") && !t.contains("alert("), "{n}");
            assert!(t.contains("Content-Security-Policy"), "{n}: no CSP");
            for part in [
                "default-src 'none'",
                "script-src 'self'",
                "style-src 'self'",
                "connect-src 'self'",
                "img-src 'none'",
                "base-uri 'none'",
                "form-action 'none'",
            ] {
                assert!(t.contains(part), "{n}: CSP lacks {part}");
            }
        }
    }
    // the hostile text IS preserved (as data, JSON-escaped) so the test proves the escaping rather than a dropped field
    let meta = files(&out)
        .into_iter()
        .find(|f| f.0 == "data/meta.json")
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&meta.1).unwrap();
    assert!(
        v.to_string().contains("alert(1)"),
        "the note was dropped: the test would prove nothing"
    );
}

#[test]
fn l4_no_private_string_no_email_no_banned_word_and_the_allowed_fields_only() {
    let (d, pk) = mock("l4", 30);
    let out = scratch("l4-out");
    generate(&d, &pk, &out, &Config::default()).unwrap();
    let seed = format!("{SEED_BYTE:02x}").repeat(32);
    for (n, b) in files(&out) {
        let t = text(&b);
        // the one allowed occurrence: the NAME of a HITRUST control category inside a plain-English sentence (a proper name, not a claim about this system)
        let low = t
            .replace("HITRUST secure development and maintenance", "")
            .to_lowercase();
        for bad in [
            "akia",
            "begin private",
            "begin certificate",
            "platinum.key",
            &seed,
            "synthetic detail",
        ] {
            assert!(!low.contains(bad), "{n} contains {bad:?}");
        }
        // email-shaped: an @ directly after a letter or digit (a CSS at-rule such as @media starts after a line break and is fine)
        let b = t.as_bytes();
        assert!(
            !(1..b.len()).any(|i| b[i] == b'@' && b[i - 1].is_ascii_alphanumeric()),
            "{n}: an email-shaped text"
        );
        for w in ["secure", "compliant", "certified"] {
            assert!(!low.contains(w), "{n} contains the word {w}");
        }
    }
    let p1: serde_json::Value = serde_json::from_slice(
        &files(&out)
            .into_iter()
            .find(|f| f.0 == "data/page-0001.json")
            .unwrap()
            .1,
    )
    .unwrap();
    let allowed = [
        "index",
        "ts",
        "plain",
        "kind",
        "label",
        "decision",
        "reason",
        "control",
        "total",
        "passed",
        "flagged",
        "subject_hash",
        "leaf_hash",
        "key_id",
        "checkpoint_size",
        "checkpoint_root",
    ];
    for r in p1["records"].as_array().unwrap() {
        let mut keys: Vec<&str> = r.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        let mut want = allowed.to_vec();
        want.sort_unstable();
        assert_eq!(keys, want);
    }
}

#[test]
fn l5_records_equal_the_independent_platinum_export() {
    let (d, pk) = mock("l5", 12);
    // the platinum export reads the node key file: write the SAME synthetic test key (generated here from a repeated byte) into this scratch directory only
    let kf = d.join("platinum.key");
    std::fs::write(&kf, format!("{}\n", format!("{SEED_BYTE:02x}").repeat(32))).unwrap();
    std::os::unix::fs::PermissionsExt::set_mode(
        &mut std::fs::metadata(&kf).unwrap().permissions(),
        0o600,
    );
    std::fs::set_permissions(&kf, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    let out = scratch("l5-out");
    generate(
        &d,
        &pk,
        &out,
        &Config {
            page_size: 5,
            ..Config::default()
        },
    )
    .unwrap();
    let want = entropa_platinum::export_evidence(&d).unwrap();
    let want = want["records"].as_array().unwrap();
    assert_eq!(want.len(), 12);
    let mut got = vec![];
    for k in 1..=3 {
        let b = std::fs::read(out.join(format!("data/page-{k:04}.json"))).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        got.extend(v["records"].as_array().unwrap().clone());
    }
    assert_eq!(got.len(), 12);
    for (g, w) in got.iter().zip(want) {
        for k in [
            "index",
            "ts",
            "plain",
            "kind",
            "label",
            "decision",
            "reason",
            "control",
            "total",
            "passed",
            "flagged",
            "subject_hash",
            "leaf_hash",
            "key_id",
        ] {
            assert_eq!(g[k], w[k], "record {} field {k}", w["index"]);
        }
    }
    // the checkpoint of record i covers i+1 records
    for (i, g) in got.iter().enumerate() {
        assert_eq!(g["checkpoint_size"], i + 1);
    }
}

#[test]
fn l6_output_is_deterministic_and_the_verify_block_is_exact() {
    let (d, pk) = mock("l6", 40);
    let (a, b) = (scratch("l6-a"), scratch("l6-b"));
    generate(&d, &pk, &a, &Config::default()).unwrap();
    generate(&d, &pk, &b, &Config::default()).unwrap();
    assert_eq!(files(&a), files(&b));
    let meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(a.join("data/meta.json")).unwrap()).unwrap();
    assert_eq!(meta["label"], LABEL);
    assert_eq!(
        meta["verify_command"],
        "entropa-mockview verify <DIR> <PUBLIC_KEY_HEX>"
    );
    assert_eq!(meta["key_id"].as_str().unwrap().len(), 16);
    assert_eq!(meta["pubkey"], pk);
    assert_eq!(meta["records"], 40);
    assert_eq!(meta["checkpoint_head"]["size"], 40);
    assert!(meta["not_claimed"]
        .as_str()
        .unwrap()
        .contains("does not verify anything in your browser"));
    assert!(meta["what_is_mock"]
        .as_array()
        .is_some_and(|a| !a.is_empty()));
    assert!(meta["what_is_real"]
        .as_array()
        .is_some_and(|a| !a.is_empty()));
}

#[test]
fn l7_app_js_is_free_of_unsafe_sinks_and_renders_under_a_fake_dom() {
    let (d, pk) = mock("l7", 8);
    let out = scratch("l7-out");
    generate(&d, &pk, &out, &Config::default()).unwrap();
    let js = std::fs::read_to_string(out.join("app.js")).unwrap();
    for bad in [
        "innerHTML",
        "outerHTML",
        "eval(",
        "new Function",
        "document.write",
        "insertAdjacentHTML",
        "setAttribute(\"on",
    ] {
        assert!(!js.contains(bad), "app.js uses {bad}");
    }
    assert!(js.contains("textContent"));
    // run it headless with a minimal fake DOM (node is installed on this machine)
    let harness = r#"
const fs = require('fs'); const path = process.argv[2];
function el(tag){ return {tag, children:[], textContent:'', attrs:{}, setAttribute(k,v){this.attrs[k]=v;}, appendChild(c){this.children.push(c); return c;}, addEventListener(){}, set className(v){this.attrs.class=v;}, get className(){return this.attrs.class||'';}}; }
const doc = { createElement: el, getElementById: (id)=> (doc._ids[id] ||= el('div')), _ids:{} };
global.document = doc;
global.window = { location: { search: '' } };
global.fetch = (u) => Promise.resolve({ ok:true, json: () => Promise.resolve(JSON.parse(fs.readFileSync(path + '/' + u, 'utf8'))) });
const app = require(path + '/app.js');
app.start(doc, fetch, '').then(() => {
  const rows = []; (function walk(n){ if(n.attrs && n.attrs.class==='row') rows.push(n); (n.children||[]).forEach(walk); })(doc._ids['records'] || {children:[]});
  console.log(JSON.stringify({rows: rows.length, label: doc._ids['label'] ? doc._ids['label'].textContent : null}));
}).catch(e => { console.log('ERR ' + e.message); process.exit(1); });
"#;
    std::fs::write(out.join("harness.js"), harness).unwrap();
    let o = std::process::Command::new("node")
        .arg(out.join("harness.js"))
        .arg(&out)
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&o.stdout);
    assert!(
        o.status.success(),
        "node failed: {s} {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let v: serde_json::Value = serde_json::from_str(s.trim()).unwrap();
    assert_eq!(v["rows"], 8);
    assert_eq!(v["label"], LABEL);
}

// ---- mutation triage (first run: 32 mutants, 11 missed) ----
#[test]
fn q1_the_marker_limit_is_exactly_4096_bytes_and_errors_print_their_variant() {
    let (d, pk) = mock("q1", 3);
    let m = d.join("MOCK-DATA.txt");
    let head = format!("{LABEL}\n");
    std::fs::write(&m, format!("{head}{}", "x".repeat(4096 - head.len()))).unwrap();
    assert_eq!(std::fs::metadata(&m).unwrap().len(), 4096);
    assert!(
        generate(&d, &pk, &scratch("q1-ok"), &Config::default()).is_ok(),
        "exactly 4096 bytes is accepted"
    );
    std::fs::write(&m, format!("{head}{}", "x".repeat(4097 - head.len()))).unwrap();
    let e = generate(&d, &pk, &scratch("q1-big"), &Config::default()).unwrap_err();
    assert!(matches!(e, ViewError::NoMockMarker(_)));
    assert!(e.to_string().contains("NoMockMarker"));
}

#[test]
fn q2_the_command_line_tool_prints_ok_refuses_with_exit_1_and_checks_its_arguments() {
    let (d, pk) = mock("q2", 25);
    let bin = env!("CARGO_BIN_EXE_entropa-mockview");
    let run = |args: &[&str]| std::process::Command::new(bin).args(args).output().unwrap();
    let out = scratch("q2-out");
    let o = run(&[d.to_str().unwrap(), &pk, out.to_str().unwrap(), "10"]);
    assert!(o.status.success());
    let t = String::from_utf8_lossy(&o.stdout);
    assert!(t.starts_with("OK records=25 pages=3 "), "{t}");
    assert!(
        out.join("data/page-0003.json").exists(),
        "the page size argument was ignored"
    );
    // no arguments, too few, too many: usage and exit 2
    for args in [vec![], vec!["a", "b"], vec!["a", "b", "c", "10", "extra"]] {
        let o = run(&args);
        assert_eq!(o.status.code(), Some(2), "{args:?}");
        assert!(String::from_utf8_lossy(&o.stderr).contains("usage"));
    }
    // exactly three arguments is valid (the default page size)
    let o = run(&[
        d.to_str().unwrap(),
        &pk,
        scratch("q2-three").to_str().unwrap(),
    ]);
    assert!(o.status.success());
    assert!(String::from_utf8_lossy(&o.stdout).contains("pages=1 "));
    // a refusal exits 1 and writes nothing
    let bad = scratch("q2-bad");
    let o = run(&[
        d.to_str().unwrap(),
        &"0".repeat(pk.len()),
        bad.to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stderr).contains("refused"));
    assert!(files(&bad).is_empty());
}
