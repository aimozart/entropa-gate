//! S1 slice B (task 3): the static per-client explorer. Bars from a stage record (not published) (E1 to E5), fixed before the code: no external request of any
//! kind in any generated file; 300 hostile strings (config values) never create a tag or attribute that the generator itself did not write; a tampered
//! copy shows a visible FAIL taken from the verify result at generation time; no claim of browser-side verification; 20 runs give byte-identical output.
//! The checks parse the output with a strict tokenizer (allowed tags, allowed attributes, double-quoted values, relative URLs only), so an escaping
//! bug shows up as a structural violation and not only as a missing string. Synthetic data only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_gate::config::Config;
use entropa_gate::explorer::generate;
use entropa_gate::{keys, node};
use std::path::{Path, PathBuf};

const REQ: &str = r#"{"label":"nl_query","decision":"allow","reason":"guard_passed","input":"How many claims were denied by payer?","output":"SELECT 1","run_id":"run-s1-b","provider":"vertex","model_id":"gemini-3.8-flash","input_tokens":1,"output_tokens":1,"cost_micro_usd":1,"ts":1700000000}"#;

fn cfg(org: &str) -> Config {
    Config::parse(&format!(
        "org_name = {}\nwitnesses = [\"https://witness.example.invalid/w\"]\n",
        toml_str(org)
    ))
    .unwrap()
}
fn toml_str(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}
fn ledger(t: &tempfile::TempDir, n: usize) -> PathBuf {
    let d = t.path().join("node");
    keys::init(&d).unwrap();
    for _ in 0..n {
        node::record(&d, REQ).unwrap();
    }
    d
}
fn files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(files(&p));
        } else {
            out.push(p);
        }
    }
    out.sort();
    out
}
fn read(p: &Path) -> String {
    String::from_utf8_lossy(&std::fs::read(p).unwrap()).into_owned()
}

const TAGS: &[&str] = &[
    "html", "head", "meta", "title", "link", "body", "header", "main", "footer", "section", "h1",
    "h2", "h3", "table", "thead", "tbody", "tr", "th", "td", "span", "div", "p", "img", "script",
    "nav", "ul", "li", "code", "strong", "em", "input", "label",
];
const ATTRS: &[&str] = &[
    "lang",
    "charset",
    "name",
    "content",
    "http-equiv",
    "rel",
    "href",
    "src",
    "alt",
    "title",
    "class",
    "id",
    "type",
    "colspan",
    "scope",
    "placeholder",
    "aria-label",
    "width",
    "height",
    "for",
    "data-label",
    "data-decision",
];

/// Strict structural check of one generated HTML file; returns the list of violations (empty = clean) and the number of script tags.
fn check_html(h: &str) -> (Vec<String>, usize) {
    let mut bad = Vec::new();
    let mut scripts = 0;
    let b = h.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'<' {
            i += 1;
            continue;
        }
        if h[i..].starts_with("<!doctype html>") {
            i += "<!doctype html>".len();
            continue;
        }
        if h[i..].starts_with("<!--") || h[i..].starts_with("<!") || h[i..].starts_with("<?") {
            bad.push(format!("comment or declaration at {i}"));
            i += 1;
            continue;
        }
        let mut j = i + 1;
        let closing = b.get(j) == Some(&b'/');
        if closing {
            j += 1;
        }
        let s = j;
        while j < b.len() && (b[j].is_ascii_alphanumeric()) {
            j += 1;
        }
        let name = h[s..j].to_ascii_lowercase();
        if name.is_empty() || !TAGS.contains(&name.as_str()) {
            bad.push(format!(
                "tag not allowed: {:?}",
                &h[i..(i + 24).min(h.len())]
            ));
            i += 1;
            continue;
        }
        if name == "script" && !closing {
            scripts += 1;
        }
        // attributes
        loop {
            while j < b.len() && (b[j] == b' ' || b[j] == b'\n') {
                j += 1;
            }
            if j >= b.len() {
                bad.push("unterminated tag".into());
                break;
            }
            if b[j] == b'>' {
                j += 1;
                break;
            }
            if b[j] == b'/' && b.get(j + 1) == Some(&b'>') {
                j += 2;
                break;
            }
            let s = j;
            while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'-') {
                j += 1;
            }
            let an = h[s..j].to_ascii_lowercase();
            if an.is_empty() || !ATTRS.contains(&an.as_str()) {
                bad.push(format!(
                    "attribute not allowed: {:?} on <{name}>",
                    &h[s..(s + 20).min(h.len())]
                ));
                j = (s + 1).min(b.len());
                continue;
            }
            if b.get(j) == Some(&b'=') {
                j += 1;
                if b.get(j) != Some(&b'"') {
                    bad.push(format!("attribute value of {an} is not double-quoted"));
                    continue;
                }
                j += 1;
                let vs = j;
                while j < b.len() && b[j] != b'"' {
                    if b[j] == b'<' || b[j] == b'>' {
                        bad.push(format!("raw < or > inside the value of {an}"));
                    }
                    j += 1;
                }
                let v = &h[vs..j.min(h.len())];
                j += 1;
                if (an == "href" || an == "src")
                    && (v.contains(':') || v.starts_with("//") || v.starts_with('\\'))
                {
                    bad.push(format!("{an} is not a relative URL: {v:?}"));
                }
                if an == "http-equiv" && v != "Content-Security-Policy" {
                    bad.push(format!("http-equiv {v:?}"));
                }
            }
        }
        i = j;
    }
    (bad, scripts)
}

#[test]
fn b1_the_site_makes_no_external_request_and_holds_one_script_and_one_stylesheet() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(&t, 3);
    let out = t.path().join("site");
    let g = generate(&d, &cfg("Example Clinic"), &out).unwrap();
    assert!(g.verified);
    let names: Vec<String> = files(&out)
        .iter()
        .map(|p| p.strip_prefix(&out).unwrap().to_string_lossy().into_owned())
        .collect();
    for want in ["app.js", "index.html", "style.css"] {
        assert!(
            names.iter().any(|n| n == want),
            "{want} missing from {names:?}"
        );
    }
    let (bad, scripts) = check_html(&read(&out.join("index.html")));
    assert!(bad.is_empty(), "{bad:#?}");
    assert_eq!(scripts, 1, "exactly the generator's own script tag");
    let html = read(&out.join("index.html"));
    assert!(html.contains("Content-Security-Policy"), "no CSP");
    assert!(html.contains("default-src 'none'"), "CSP must start closed");
    // the CSS and the JS must not reach out either
    let css = read(&out.join("style.css"));
    for bad in [
        "@import",
        "url(http",
        "url(//",
        "url(\"http",
        "url('http",
        "expression(",
    ] {
        assert!(!css.contains(bad), "{bad} in style.css");
    }
    let js = read(&out.join("app.js"));
    for bad in [
        "fetch(",
        "XMLHttpRequest",
        "WebSocket",
        "EventSource",
        "sendBeacon",
        "import(",
        "new Image",
        "eval(",
        "Function(",
        "document.write",
        "innerHTML",
        "http://",
        "https://",
        "localStorage",
        "indexedDB",
    ] {
        assert!(!js.contains(bad), "{bad} in app.js");
    }
    // the witness URL from the config is shown as text, never as a link or a resource
    assert!(html.contains("witness.example.invalid"));
}

#[test]
fn b2_300_hostile_config_values_create_no_tag_or_attribute_of_their_own() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(&t, 2);
    let frags = [
        "<script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "'><svg onload=alert(1)>",
        "</title><script>x</script>",
        "javascript:alert(1)",
        "<iframe src=//evil.invalid>",
        "&lt;b&gt;",
        "&#x3c;script&#x3e;",
        "\" onmouseover=\"alert(1)",
        "<!--",
        "-->",
        "<style>*{}</style>",
        "{{7*7}}",
        "${7*7}",
        "%3Cscript%3E",
        "\u{202e}rtl",
        "\u{0}",
        "\\u003cscript\\u003e",
        "<a href=javascript:1>x</a>",
        "<meta http-equiv=refresh content=0;url=http://evil.invalid>",
        "<base href=//evil.invalid/>",
        "</div></body></html><body>",
        "`;alert(1);//",
        "</script><script>1</script>",
        "<link rel=stylesheet href=//evil.invalid/x.css>",
        "<form action=//evil.invalid><input name=a>",
        "<math><mi xlink:href=javascript:1>",
        "<object data=x>",
        "<embed src=x>",
        "<![CDATA[x]]>",
        "\u{ff1c}script\u{ff1e}",
    ];
    let logo = t.path().join("logo.png");
    std::fs::write(&logo, [0x89, b'P', b'N', b'G', 13, 10, 26, 10]).unwrap();
    let mut n = 0;
    let mut seen_escape_bug = Vec::new();
    for a in 0..frags.len() {
        for b in 0..frags.len() {
            if n >= 300 {
                break;
            }
            let s = format!("{}{}", frags[a], frags[b]);
            // org_name allows 80 characters and no control characters; the witness URL allows no whitespace or control characters
            let org: String = s.chars().filter(|c| !c.is_control()).take(80).collect();
            if org.is_empty() {
                continue;
            }
            let url: String = format!(
                "https://w.example.invalid/{}",
                s.chars()
                    .filter(|c| !c.is_control() && !c.is_whitespace())
                    .take(60)
                    .collect::<String>()
            );
            // a logo makes the organisation name appear in an attribute (alt) as well as in text and the title
            let text = format!(
                "org_name = {}\nwitnesses = [{}]\nlogo_file = {}\n",
                toml_str(&org),
                toml_str(&url),
                toml_str(logo.to_str().unwrap())
            );
            let Ok(c) = Config::parse(&text) else {
                continue;
            };
            n += 1;
            let out = t.path().join(format!("s{n}"));
            generate(&d, &c, &out).unwrap();
            for f in files(&out) {
                if f.extension().and_then(|e| e.to_str()) == Some("html") {
                    let (bad, scripts) = check_html(&read(&f));
                    if !bad.is_empty() || scripts != 1 {
                        seen_escape_bug.push(format!("{org:?}: {bad:?} scripts={scripts}"));
                    }
                }
                let body = read(&f);
                // a value with a markup character must never appear raw (it appears escaped or not at all)
                if f.extension().and_then(|e| e.to_str()) == Some("html")
                    && org.contains(['&', '<', '>', '"', '\'', '`'])
                {
                    assert!(
                        !body.contains(&org),
                        "the raw organisation name {org:?} is in the page"
                    );
                }
                assert!(
                    !body.contains("evil.invalid") || !body.contains("<iframe"),
                    "payload became markup in {}",
                    f.display()
                );
            }
        }
    }
    assert!(
        n >= 300,
        "only {n} hostile configs were accepted by the config parser"
    );
    assert!(
        seen_escape_bug.is_empty(),
        "{} of {n} outputs have markup the generator did not write; first: {:?}",
        seen_escape_bug.len(),
        seen_escape_bug.first()
    );
}

#[test]
fn b3_a_tampered_copy_shows_a_visible_fail_and_an_intact_one_shows_ok() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(&t, 3);
    let ok_out = t.path().join("ok");
    assert!(
        generate(&d, &cfg("Example Clinic"), &ok_out)
            .unwrap()
            .verified
    );
    let html = read(&ok_out.join("index.html"));
    assert!(
        html.contains("status-ok") && html.contains("OK records=3 checkpoints=3"),
        "{html}"
    );
    assert!(!html.contains("status-fail"));
    // tamper one byte in a copy
    let c = t.path().join("copy");
    std::fs::create_dir_all(c.join("ledger")).unwrap();
    std::fs::copy(d.join("platinum.key"), c.join("platinum.key")).unwrap();
    for f in ["records.log", "checkpoints.log"] {
        std::fs::copy(d.join("ledger").join(f), c.join("ledger").join(f)).unwrap();
    }
    let p = c.join("ledger/records.log");
    let mut b = std::fs::read(&p).unwrap();
    let i = b.len() / 2;
    b[i] = if b[i] == b'a' { b'b' } else { b'a' };
    std::fs::write(&p, b).unwrap();
    let bad_out = t.path().join("bad");
    let g = generate(&c, &cfg("Example Clinic"), &bad_out).unwrap();
    assert!(!g.verified);
    assert_eq!(
        g.shown, 0,
        "records of a failed ledger are not shown as if they were trusted"
    );
    let html = read(&bad_out.join("index.html"));
    assert!(
        html.contains("status-fail") && html.contains("FAIL"),
        "no visible FAIL: {html}"
    );
    assert!(!html.contains("status-ok"));
    assert!(check_html(&html).0.is_empty());
}

#[test]
fn b4_the_page_never_claims_browser_side_verification_or_safety() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(&t, 2);
    let out = t.path().join("site");
    generate(&d, &cfg("Example Clinic"), &out).unwrap();
    let mut all = String::new();
    for f in files(&out) {
        all.push_str(&read(&f).to_lowercase());
    }
    for bad in [
        "verified in your browser",
        "browser-side verification",
        "verify in the browser",
        "tamper-proof",
        "tamper proof",
        "secure",
        "compliant",
        "certified",
        "unhackable",
        "guarantee",
    ] {
        assert!(!all.contains(bad), "the output says {bad:?}");
    }
    assert!(
        all.contains("this page does not verify anything in your browser"),
        "the honest sentence is missing"
    );
    assert!(all.contains("checked by the offline verifier when this page was generated"));
}

#[test]
fn b5_twenty_runs_give_byte_identical_output() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(&t, 4);
    let c = cfg("Example Clinic");
    let mut first: Option<Vec<(String, Vec<u8>)>> = None;
    for n in 0..20 {
        let out = t.path().join(format!("r{n}"));
        generate(&d, &c, &out).unwrap();
        let got: Vec<(String, Vec<u8>)> = files(&out)
            .iter()
            .map(|p| {
                (
                    p.strip_prefix(&out).unwrap().to_string_lossy().into_owned(),
                    std::fs::read(p).unwrap(),
                )
            })
            .collect();
        match &first {
            None => first = Some(got),
            Some(f) => assert_eq!(&got, f, "run {n} differs"),
        }
    }
}

#[test]
fn b6_the_output_directory_and_the_logo_are_handled_safely() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(&t, 1);
    // a non-empty directory that is not a previous output is refused and left untouched
    let mine = t.path().join("mine");
    std::fs::create_dir_all(&mine).unwrap();
    std::fs::write(mine.join("notes.txt"), "keep me").unwrap();
    assert!(generate(&d, &cfg("X"), &mine).is_err());
    assert_eq!(
        std::fs::read_to_string(mine.join("notes.txt")).unwrap(),
        "keep me"
    );
    assert!(!mine.join("index.html").exists());
    // an output of this command may be regenerated
    let out = t.path().join("site");
    generate(&d, &cfg("X"), &out).unwrap();
    generate(&d, &cfg("X"), &out).unwrap();
    // config extras: accent colour must be #rrggbb, tiers closed length, logo file type and size
    assert!(Config::parse("org_name = \"X\"\naccent_color = \"#1a73e8\"\n").is_ok());
    for bad in [
        "accent_color = \"red\"",
        "accent_color = \"#12345\"",
        "accent_color = \"#1a73e8;}body{display:none\"",
        "accent_color = \"url(x)\"",
    ] {
        assert!(
            Config::parse(&format!("org_name = \"X\"\n{bad}\n")).is_err(),
            "accepted {bad}"
        );
    }
    assert!(Config::parse("org_name = \"X\"\ntiers = [\"T0\", \"T1 staff\"]\n").is_ok());
    assert!(
        Config::parse("org_name = \"X\"\ntiers = [\"<b>\"]\n").is_err(),
        "tier names are plain words"
    );
    let tiers_many = format!(
        "org_name = \"X\"\ntiers = [{}]\n",
        (0..9)
            .map(|i| format!("\"t{i}\""))
            .collect::<Vec<_>>()
            .join(",")
    );
    assert!(Config::parse(&tiers_many).is_err(), "at most 8 tiers");
    // logo
    let logo = t.path().join("logo.png");
    std::fs::write(&logo, [0x89, b'P', b'N', b'G', 13, 10, 26, 10]).unwrap();
    let lg = format!(
        "org_name = \"X\"\nlogo_file = {}\n",
        toml_str(logo.to_str().unwrap())
    );
    let site = t.path().join("with-logo");
    generate(&d, &Config::parse(&lg).unwrap(), &site).unwrap();
    assert_eq!(
        std::fs::read(site.join("logo.png")).unwrap(),
        std::fs::read(&logo).unwrap()
    );
    let html = read(&site.join("index.html"));
    assert!(check_html(&html).0.is_empty());
    assert!(html.contains("src=\"logo.png\""));
    let big = t.path().join("big.png");
    std::fs::write(&big, vec![0u8; 200 * 1024]).unwrap();
    let txt = t.path().join("logo.txt");
    std::fs::write(&txt, "x").unwrap();
    for p in [&big, &txt, &t.path().join("missing.png")] {
        let lg = format!(
            "org_name = \"X\"\nlogo_file = {}\n",
            toml_str(p.to_str().unwrap())
        );
        assert!(
            generate(&d, &Config::parse(&lg).unwrap(), &t.path().join("never")).is_err(),
            "accepted logo {}",
            p.display()
        );
    }
}

#[test]
fn b7_the_command_line_writes_the_site_and_needs_a_config() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(&t, 2);
    let cfgp = t.path().join("c.toml");
    std::fs::write(
        &cfgp,
        "org_name = \"Example Clinic\"\ntiers = [\"T0\", \"T1\"]\n",
    )
    .unwrap();
    let out = t.path().join("site");
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
    let (code, stdout, err) = run(&[
        "explorer",
        "--dir",
        d.to_str().unwrap(),
        "--config",
        cfgp.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(
        stdout.contains("verified: true") && stdout.contains("index.html"),
        "{stdout}"
    );
    assert!(out.join("index.html").exists());
    let (code, _, err) = run(&[
        "explorer",
        "--dir",
        d.to_str().unwrap(),
        "--out",
        t.path().join("x").to_str().unwrap(),
    ]);
    assert_ne!(code, 0, "an explorer without a config");
    assert!(err.contains("--config"), "{err}");
}
