//! R1 task 1: clause-level chunking of the corpus sources, sealing into versions that are never overwritten, tiers, and the corpus_version
//! receipt. Fixtures are SYNTHETIC invented text: no real standard's text is in this repository.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_standards::chunk::{self, Format};
use entropa_standards::corpus::Tier;
use entropa_standards::records::{EvidenceRequest, RecordSink};
use entropa_standards::seal::{self, SealError, SealOutcome};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .unwrap()
}
fn sha(s: &[u8]) -> String {
    hex::encode(Sha256::digest(s))
}
fn ids(v: &[chunk::RawClause]) -> Vec<&str> {
    v.iter().map(|c| c.id.as_str()).collect()
}
fn text<'a>(v: &'a [chunk::RawClause], id: &str) -> &'a str {
    &v.iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("no clause {id}"))
        .text
}

// ---- chunkers ----
#[test]
fn i1_oscal_controls_and_enhancements_are_separate_clauses_with_nist_style_ids() {
    let c = chunk::chunk(Format::Oscal, &fixture("oscal_mini.json")).unwrap();
    assert_eq!(ids(&c), ["ZZ-1", "ZZ-1(2)", "ZZ-3"]); // the withdrawn control has no text and is skipped
    let z1 = text(&c, "ZZ-1");
    assert!(
        z1.contains("Policy and Procedures")
            && z1.contains("Develop and document")
            && z1.contains("Synthetic guidance")
    );
    assert!(!z1.contains("automated mechanisms")); // the enhancement is its own clause
    assert!(!z1.contains("{{") && z1.contains("[organization-defined parameter]"));
    assert!(text(&c, "ZZ-1(2)").contains("Employ automated mechanisms"));
}

#[test]
fn i2_eu_articles_are_clauses_noise_and_chapter_lines_are_dropped_and_duplicates_keep_the_longest()
{
    let c = chunk::chunk(Format::EuText, &fixture("eu_mini.txt")).unwrap();
    assert_eq!(ids(&c), ["Art.1", "Art.2", "Art.3", "Annex I"]);
    let a1 = text(&c, "Art.1");
    assert!(
        a1.starts_with("Subject matter")
            && a1.contains("rules about widgets")
            && a1.contains("also covers gadgets")
    );
    assert!(!a1.contains("1/9") && !a1.contains("OJ L") && !a1.contains("CHAPTER"));
    let a2 = text(&c, "Art.2");
    assert!(
        a2.contains("widget makers and to gadget makers")
            && !a2.contains("ELI:")
            && !a2.contains("REQUIREMENTS")
    );
    assert!(text(&c, "Art.3").contains("traceability")); // the longer of the two Article 3 blocks
    assert!(
        text(&c, "Annex I").contains("kind A and kind B")
            || text(&c, "Annex I").contains("Kind A and kind B")
    );
}

#[test]
fn i3_pci_style_requirements_merge_statement_and_testing_lines_and_ignore_noise() {
    let c = chunk::chunk(Format::PciText, &fixture("pci_mini.txt")).unwrap();
    assert_eq!(ids(&c), ["10.2.1.1", "10.3.4", "12.3.3"]);
    let r = text(&c, "10.3.4");
    assert!(
        r.contains("cannot be changed without alerts")
            && r.contains("Examine settings and results")
    );
    assert!(!r.contains("Guidance text"));
    assert!(text(&c, "12.3.3").contains("reviewed at least once every 12 months"));
    assert!(!ids(&c).contains(&"99.1.1") && !ids(&c).contains(&"2023")); // outside the 1..=12 requirement range
}

#[test]
fn i4_html_sections_are_clauses_with_tags_scripts_and_entities_removed() {
    let c = chunk::chunk(Format::Html, &fixture("html_mini.html")).unwrap();
    assert_eq!(ids(&c), ["9.9(a)", "9.9(b)", "9.9(c)"]);
    let a = text(&c, "9.9(a)");
    assert!(
        a.contains("Access control")
            && a.contains("Assign a unique name")
            && !a.contains("<p>")
            && !a.contains("var a=1")
    );
    assert!(text(&c, "9.9(b)").contains("activity & usage"));
    assert!(
        !text(&c, "9.9(c)").contains("Footer noise") && !text(&c, "9.9(c)").contains("Navigation")
    );
}

#[test]
fn i5_chunking_is_deterministic_and_an_empty_or_idless_source_is_refused() {
    for (f, n) in [
        (Format::Oscal, "oscal_mini.json"),
        (Format::EuText, "eu_mini.txt"),
        (Format::PciText, "pci_mini.txt"),
        (Format::Html, "html_mini.html"),
    ] {
        assert_eq!(
            chunk::chunk(f, &fixture(n)).unwrap(),
            chunk::chunk(f, &fixture(n)).unwrap()
        );
        assert!(chunk::chunk(f, "").is_err(), "{n}");
        assert!(
            chunk::chunk(f, "no clause markers anywhere in this text").is_err(),
            "{n}"
        );
    }
    assert!(chunk::chunk(Format::Oscal, "{not json").is_err());
}

// ---- sealing ----
struct Fake(RefCell<Vec<EvidenceRequest>>);
impl RecordSink for Fake {
    fn emit(&self, r: &EvidenceRequest) -> Result<(), String> {
        self.0.borrow_mut().push(r.clone());
        Ok(())
    }
}

struct Env {
    _t: tempfile::TempDir,
    src: PathBuf,
    store: PathBuf,
}
fn env() -> Env {
    let t = tempfile::tempdir().unwrap();
    let src = t.path().join("src");
    std::fs::create_dir(&src).unwrap();
    for n in [
        "oscal_mini.json",
        "eu_mini.txt",
        "pci_mini.txt",
        "html_mini.html",
    ] {
        std::fs::write(src.join(n), fixture(n)).unwrap();
    }
    let store = t.path().join("store");
    Env { _t: t, src, store }
}
fn spec(e: &Env, version: &str) -> String {
    let s = |n: &str| sha(&std::fs::read(e.src.join(n)).unwrap());
    format!(
        r#"{{"corpus_version":"{version}","sources":[
 {{"standard":"SYN-OSCAL","std_version":"0.0.1","tier":"OPEN","format":"oscal","file":"oscal_mini.json","sha256":"{}"}},
 {{"standard":"SYN-EU","std_version":"2000","tier":"OPEN","format":"eu_text","file":"eu_mini.txt","sha256":"{}"}},
 {{"standard":"SYN-PAY","std_version":"4.0.1","tier":"LICENSED","format":"pci_text","file":"pci_mini.txt","sha256":"{}"}},
 {{"standard":"SYN-HTML","std_version":"1","tier":"OPEN","format":"html","file":"html_mini.html","sha256":"{}"}}]}}"#,
        s("oscal_mini.json"),
        s("eu_mini.txt"),
        s("pci_mini.txt"),
        s("html_mini.html")
    )
}
fn no_pdf(_: &Path) -> Result<String, String> {
    Err("no pdf here".into())
}
fn seal_it(
    e: &Env,
    version: &str,
    sink: Option<&dyn RecordSink>,
) -> Result<SealOutcome, SealError> {
    seal::seal(
        &seal::parse_spec(&spec(e, version)).unwrap(),
        &e.src,
        &e.store,
        &no_pdf,
        sink,
    )
}

#[test]
fn i6_a_seal_writes_a_manifest_with_hashes_and_no_text_and_the_clauses_with_text() {
    let e = env();
    let out = seal_it(&e, "c-test-1", None).unwrap();
    let SealOutcome::Created {
        corpus_hash,
        clauses,
        sources,
    } = out
    else {
        panic!("expected Created")
    };
    assert_eq!((clauses, sources), (3 + 4 + 3 + 3, 4));
    let man = std::fs::read_to_string(e.store.join("c-test-1/manifest.json")).unwrap();
    assert!(
        man.contains(&corpus_hash)
            && man.contains("\"tier\": \"LICENSED\"")
            && man.contains("pci_mini.txt")
    );
    assert!(
        !man.contains("cannot be changed without alerts"),
        "the manifest must hold hashes, never clause text"
    );
    let s = seal::open(&e.store, "c-test-1").unwrap();
    assert_eq!(s.manifest.corpus_hash, corpus_hash);
    assert_eq!(s.clauses.len(), 13);
    let c = s
        .clauses
        .iter()
        .find(|c| c.standard == "SYN-PAY" && c.id == "10.3.4")
        .unwrap();
    assert_eq!((c.tier, c.std_version.as_str()), (Tier::Licensed, "4.0.1"));
    assert_eq!(c.text_sha256, sha(c.text.as_bytes()));
    assert!(c.text.contains("cannot be changed without alerts"));
}

#[test]
fn i7_the_corpus_hash_is_deterministic_and_the_same_content_again_is_a_no_op() {
    let e = env();
    let SealOutcome::Created {
        corpus_hash: h1, ..
    } = seal_it(&e, "c-test-1", None).unwrap()
    else {
        panic!()
    };
    let before = std::fs::read(e.store.join("c-test-1/manifest.json")).unwrap();
    let out = seal_it(&e, "c-test-1", None).unwrap();
    let SealOutcome::AlreadySealed { corpus_hash: h2 } = out else {
        panic!("expected AlreadySealed")
    };
    assert_eq!(h1, h2);
    assert_eq!(
        std::fs::read(e.store.join("c-test-1/manifest.json")).unwrap(),
        before
    );
    let e2 = env();
    let SealOutcome::Created {
        corpus_hash: h3, ..
    } = seal_it(&e2, "c-test-1", None).unwrap()
    else {
        panic!()
    };
    assert_eq!(
        h1, h3,
        "the same sources give the same corpus hash anywhere"
    );
}

#[test]
fn i8_a_changed_source_under_the_same_version_name_is_refused_and_nothing_is_overwritten() {
    let e = env();
    seal_it(&e, "c-test-1", None).unwrap();
    let before = std::fs::read(e.store.join("c-test-1/clauses.jsonl")).unwrap();
    let old_spec = spec(&e, "c-test-1");
    std::fs::write(
        e.src.join("eu_mini.txt"),
        format!(
            "{}\nArticle 9\nNew\nA new article.\n",
            fixture("eu_mini.txt")
        ),
    )
    .unwrap();
    // (a) the file changed but the spec still pins the old hash
    let err = seal::seal(
        &seal::parse_spec(&old_spec).unwrap(),
        &e.src,
        &e.store,
        &no_pdf,
        None,
    )
    .unwrap_err();
    assert!(matches!(err, SealError::Refused(_)), "{err:?}");
    // (b) the spec is updated to the new hash but the version name is reused
    let err = seal_it(&e, "c-test-1", None).unwrap_err();
    assert!(matches!(err, SealError::Refused(_)), "{err:?}");
    assert_eq!(
        std::fs::read(e.store.join("c-test-1/clauses.jsonl")).unwrap(),
        before
    );
    // (c) a NEW version name seals fine and the old version is untouched
    let out = seal_it(&e, "c-test-2", None).unwrap();
    assert!(matches!(out, SealOutcome::Created { .. }));
    assert_eq!(
        std::fs::read(e.store.join("c-test-1/clauses.jsonl")).unwrap(),
        before
    );
    assert_eq!(seal::list_versions(&e.store), ["c-test-1", "c-test-2"]);
}

#[test]
fn i9_opening_a_sealed_version_detects_a_tampered_clause_or_manifest() {
    let e = env();
    seal_it(&e, "c-test-1", None).unwrap();
    let f = e.store.join("c-test-1/clauses.jsonl");
    let orig = std::fs::read_to_string(&f).unwrap();
    std::fs::write(&f, orig.replacen("Subject matter", "Subject matteR", 1)).unwrap();
    assert!(matches!(
        seal::open(&e.store, "c-test-1").unwrap_err(),
        SealError::Tampered(_)
    ));
    std::fs::write(&f, &orig).unwrap();
    assert!(seal::open(&e.store, "c-test-1").is_ok());
    let m = e.store.join("c-test-1/manifest.json");
    let mo = std::fs::read_to_string(&m).unwrap();
    std::fs::write(&m, mo.replacen("SYN-EU", "SYN-EX", 1)).unwrap();
    assert!(matches!(
        seal::open(&e.store, "c-test-1").unwrap_err(),
        SealError::Tampered(_)
    ));
    assert!(matches!(
        seal::open(&e.store, "nope").unwrap_err(),
        SealError::Missing(_)
    ));
}

#[test]
fn i10_a_seal_emits_one_corpus_version_receipt_request_and_a_refusal_emits_a_denial() {
    let e = env();
    let sink = Fake(RefCell::new(vec![]));
    seal_it(&e, "c-test-1", Some(&sink)).unwrap();
    let r = sink.0.borrow()[0].clone();
    assert_eq!(
        (
            r.kind.as_str(),
            r.label.as_str(),
            r.decision.as_str(),
            r.reason.as_str()
        ),
        ("evidence.change", "corpus_version", "allow", "check_passed")
    );
    assert_eq!((r.total, r.passed, r.flagged), (13, 4, 0));
    assert!(
        r.detail.contains("corpus_hash=")
            && r.detail.contains("c-test-1")
            && r.run_id.starts_with("corpus-c-test-1")
    );
    assert!(
        !r.detail.contains("Subject matter"),
        "a receipt holds hashes and counts, never clause text"
    );
    // the same content again emits nothing new
    seal_it(&e, "c-test-1", Some(&sink)).unwrap();
    assert_eq!(sink.0.borrow().len(), 1);
    // a refusal is recorded as a denial
    std::fs::write(
        e.src.join("html_mini.html"),
        format!(
            "{}<p>(d) Standard: New . Added.</p>",
            fixture("html_mini.html")
        ),
    )
    .unwrap();
    assert!(seal_it(&e, "c-test-1", Some(&sink)).is_err());
    let d = sink.0.borrow()[1].clone();
    assert_eq!(
        (d.decision.as_str(), d.reason.as_str(), d.label.as_str()),
        ("deny", "check_failed", "corpus_version")
    );
    assert!(d.flagged >= 1 && d.flagged <= d.total);
}

#[test]
fn i11_a_failing_sink_does_not_unseal_the_corpus_but_is_reported() {
    struct Broken;
    impl RecordSink for Broken {
        fn emit(&self, _: &EvidenceRequest) -> Result<(), String> {
            Err("node unavailable".into())
        }
    }
    let e = env();
    let err = seal_it(&e, "c-test-1", Some(&Broken)).unwrap_err();
    assert!(matches!(err, SealError::Receipt(_)), "{err:?}");
    assert!(
        seal::open(&e.store, "c-test-1").is_ok(),
        "the sealed corpus stays; the missing receipt is reported"
    );
}

#[test]
fn i12_pdf_sources_go_through_the_extractor_and_a_missing_extractor_is_an_error_not_a_panic() {
    let e = env();
    std::fs::write(e.src.join("eu.pdf"), b"%PDF-fake").unwrap();
    let s = |n: &str| sha(&std::fs::read(e.src.join(n)).unwrap());
    let spec = format!(
        r#"{{"corpus_version":"c-pdf","sources":[{{"standard":"SYN-EU","std_version":"2000","tier":"OPEN","format":"eu_text","file":"eu.pdf","sha256":"{}"}}]}}"#,
        s("eu.pdf")
    );
    let ok = |_: &Path| Ok(fixture("eu_mini.txt"));
    let out = seal::seal(
        &seal::parse_spec(&spec).unwrap(),
        &e.src,
        &e.store,
        &ok,
        None,
    )
    .unwrap();
    assert!(matches!(out, SealOutcome::Created { clauses: 4, .. }));
    let e2 = env();
    std::fs::write(e2.src.join("eu.pdf"), b"%PDF-fake").unwrap();
    assert!(matches!(
        seal::seal(
            &seal::parse_spec(&spec).unwrap(),
            &e2.src,
            &e2.store,
            &no_pdf,
            None
        )
        .unwrap_err(),
        SealError::Source(_)
    ));
}

#[test]
fn i13_a_bad_spec_is_refused_before_anything_is_read_or_written() {
    let good = r#"{"corpus_version":"v1","sources":[{"standard":"A","std_version":"1","tier":"OPEN","format":"oscal","file":"a.json","sha256":"00"}]}"#;
    assert!(
        seal::parse_spec(good).is_err(),
        "a sha256 must be 64 hex characters"
    );
    let h = "a".repeat(64);
    let mk = |v: &str, std: &str, tier: &str, fmt: &str, file: &str| {
        format!(
            r#"{{"corpus_version":"{v}","sources":[{{"standard":"{std}","std_version":"1","tier":"{tier}","format":"{fmt}","file":"{file}","sha256":"{h}"}}]}}"#
        )
    };
    assert!(seal::parse_spec(&mk("v1", "A", "OPEN", "oscal", "a.json")).is_ok());
    for bad in [
        mk("../v1", "A", "OPEN", "oscal", "a.json"),
        mk("", "A", "OPEN", "oscal", "a.json"),
        mk("v 1", "A", "OPEN", "oscal", "a.json"),
        mk("v1", "A", "SECRET", "oscal", "a.json"),
        mk("v1", "A", "OPEN", "docx", "a.json"),
        mk("v1", "A", "OPEN", "oscal", "../a.json"),
        mk("v1", "A", "OPEN", "oscal", "/etc/passwd"),
        mk("v1", "A/B", "OPEN", "oscal", "a.json"),
        mk("v1", "", "OPEN", "oscal", "a.json"),
        r#"{"corpus_version":"v1","sources":[]}"#.to_string(),
        "not json".to_string(),
        r#"{"corpus_version":"v1"}"#.to_string(),
    ] {
        assert!(seal::parse_spec(&bad).is_err(), "{bad}");
    }
    let dup = format!(
        r#"{{"corpus_version":"v1","sources":[{{"standard":"A","std_version":"1","tier":"OPEN","format":"oscal","file":"a.json","sha256":"{h}"}},{{"standard":"A","std_version":"1","tier":"OPEN","format":"oscal","file":"b.json","sha256":"{h}"}}]}}"#
    );
    assert!(
        seal::parse_spec(&dup).is_err(),
        "the same standard and version twice"
    );
}
