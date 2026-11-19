//! INS2 slice 2b red tests, through the real command line: `entropa-gate check` and `entropa-gate anchor export` on planted on-disk ledgers (docs/THREAT-MODEL-OPERATOR.md, section 4 and the precedence list).
//! Keys are fixed synthetic test seeds (a repeated byte). Synthetic data only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::anchor::{sign_v2, CheckpointV2};
use entropa_core::merkle;
use entropa_core::Probe;
use entropa_gate::{cli, node};
use entropa_witness::anchor_file::decode_anchor;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn req(tag: &str, n: u32) -> String {
    format!(
        r#"{{"label":"nl_query","decision":"allow","reason":"guard_passed","input":"synthetic question {tag} {n}","output":"SELECT {tag} {n}","run_id":"run-{tag}-{n}","provider":"vertex","model_id":"gemini-3.8-flash","input_tokens":{n},"output_tokens":4,"cost_micro_usd":9,"ts":{}}}"#,
        1_700_000_000 + n
    )
}
fn fresh(root: &Path, name: &str, seed_byte: u8) -> PathBuf {
    let d = root.join(name);
    std::fs::create_dir_all(d.join("ledger")).unwrap();
    let k = d.join("platinum.key");
    std::fs::write(&k, format!("{}\n", format!("{seed_byte:02x}").repeat(32))).unwrap();
    std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}
fn ledger(root: &Path, name: &str, seed_byte: u8, tag: &str, n: u32) -> PathBuf {
    let d = fresh(root, name, seed_byte);
    for i in 1..=n {
        node::record(&d, &req(tag, i)).unwrap();
    }
    d
}
fn run(args: &[&str]) -> (i32, String, String) {
    let a: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = cli::run(&a, &mut std::io::empty(), &mut out, &mut err);
    (
        code,
        String::from_utf8_lossy(&out).into(),
        String::from_utf8_lossy(&err).into(),
    )
}
fn check(d: &Path, extra: &[&str]) -> (i32, String, String) {
    let mut a = vec!["check", "--dir", d.to_str().unwrap()];
    a.extend_from_slice(extra);
    run(&a)
}
fn verdict(r: &(i32, String, String)) -> String {
    r.1.lines().next().unwrap_or("").to_string()
}
fn export(d: &Path, out: &Path, signed: bool) -> (i32, String, String) {
    let mut a = vec![
        "anchor",
        "export",
        "--dir",
        d.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ];
    if signed {
        a.push("--signed");
    }
    run(&a)
}
fn lines(p: &Path) -> Vec<String> {
    std::fs::read_to_string(p)
        .unwrap()
        .lines()
        .map(String::from)
        .collect()
}
fn write_lines(p: &Path, l: &[String]) {
    std::fs::write(p, l.iter().map(|x| format!("{x}\n")).collect::<String>()).unwrap();
}
fn copy_ledger(from: &Path, to: &Path) {
    std::fs::create_dir_all(to.join("ledger")).unwrap();
    std::fs::copy(from.join("platinum.key"), to.join("platinum.key")).unwrap();
    std::fs::set_permissions(
        to.join("platinum.key"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    std::fs::set_permissions(to, std::fs::Permissions::from_mode(0o700)).unwrap();
    for f in ["records.log", "checkpoints.log"] {
        std::fs::copy(from.join("ledger").join(f), to.join("ledger").join(f)).unwrap();
    }
}
fn flip(h: &str, at: usize) -> String {
    let mut b = h.as_bytes().to_vec();
    b[at] = if b[at] == b'0' { b'1' } else { b'0' };
    String::from_utf8(b).unwrap()
}

#[test]
fn k1_an_honest_ledger_is_ok_unanchored_with_the_warning_and_prints_no_record_content() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(t.path(), "a", 7, "orig", 5);
    let r = check(&d, &[]);
    assert_eq!(r.0, 0, "{r:?}");
    assert_eq!(verdict(&r), "verdict: ok_unanchored");
    assert!(r.2.contains("warning: no anchor was given"), "{}", r.2);
    for bad in ["SELECT", "synthetic question", "orig", "run-"] {
        assert!(
            !r.1.contains(bad) && !r.2.contains(bad),
            "record content printed: {bad}"
        );
    }
    // the old command is untouched
    let v = run(&["verify", "--dir", d.to_str().unwrap()]);
    assert_eq!(
        (v.0, v.1.trim().to_string()),
        (0, "OK records=5 checkpoints=5".to_string())
    );
}
#[test]
fn k2_require_anchor_without_one_is_anchor_missing_and_exit_1() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(t.path(), "a", 7, "orig", 3);
    let r = check(&d, &["--require-anchor"]);
    assert_eq!(
        (r.0, verdict(&r)),
        (1, "verdict: anchor_missing".to_string()),
        "{r:?}"
    );
}
#[test]
fn k3_an_exported_anchor_gives_ok_anchored_with_its_size_hash_only_or_signed() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(t.path(), "a", 7, "orig", 3);
    for (signed, name) in [(false, "h.anchor"), (true, "s.anchor")] {
        let f = t.path().join(name);
        let e = export(&d, &f, signed);
        assert_eq!(e.0, 0, "{e:?}");
        let (a, _log) = decode_anchor(&std::fs::read_to_string(&f).unwrap()).unwrap();
        assert_eq!((a.size, a.signed.is_some()), (3, signed));
    }
    // two more records, then compare with the old anchors
    for i in 4..=5 {
        node::record(&d, &req("orig", i)).unwrap();
    }
    for name in ["h.anchor", "s.anchor"] {
        let r = check(&d, &["--anchor", t.path().join(name).to_str().unwrap()]);
        assert_eq!(
            (r.0, verdict(&r)),
            (0, "verdict: ok_anchored 3".to_string()),
            "{r:?}"
        );
        assert!(
            !r.2.contains("warning"),
            "no warning when an anchor was compared: {}",
            r.2
        );
    }
    let both = check(
        &d,
        &[
            "--anchor",
            t.path().join("h.anchor").to_str().unwrap(),
            "--anchor",
            t.path().join("s.anchor").to_str().unwrap(),
            "--require-anchor",
        ],
    );
    assert_eq!(verdict(&both), "verdict: ok_anchored 3");
}
#[test]
fn k4_export_refuses_to_overwrite_and_refuses_a_ledger_that_does_not_verify() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(t.path(), "a", 7, "orig", 3);
    let f = t.path().join("x.anchor");
    assert_eq!(export(&d, &f, false).0, 0);
    let before = std::fs::read(&f).unwrap();
    let again = export(&d, &f, true);
    assert_eq!(again.0, 1, "{again:?}");
    assert_eq!(
        std::fs::read(&f).unwrap(),
        before,
        "the existing file is untouched"
    );
    let bad = copy_of(&d, t.path(), "bad");
    let mut r = lines(&bad.join("ledger/records.log"));
    r[1] = flip(&r[1], 20);
    write_lines(&bad.join("ledger/records.log"), &r);
    let g = t.path().join("bad.anchor");
    let e = export(&bad, &g, false);
    assert_eq!(e.0, 1, "{e:?}");
    assert!(
        !g.exists(),
        "nothing is written for a ledger that does not verify"
    );
}
fn copy_of(d: &Path, root: &Path, name: &str) -> PathBuf {
    let to = root.join(name);
    copy_ledger(d, &to);
    to
}
#[test]
fn k5_a1_rewrite_and_resign_hash_only_signed_and_no_anchor() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(t.path(), "a", 7, "orig", 5);
    let (h, s) = (t.path().join("h.anchor"), t.path().join("s.anchor"));
    export(&d, &h, false);
    export(&d, &s, true);
    let alt = ledger(t.path(), "alt", 7, "alt", 5); // same key, other history
    assert_eq!(
        verdict(&check(&alt, &[])),
        "verdict: ok_unanchored",
        "the known undetectable case"
    );
    assert_eq!(
        verdict(&check(&alt, &["--anchor", h.to_str().unwrap()])),
        "verdict: rewritten_since_anchor"
    );
    let r = check(&alt, &["--anchor", s.to_str().unwrap()]);
    assert_eq!(
        (r.0, verdict(&r)),
        (1, "verdict: fork_detected".to_string())
    );
}
#[test]
fn k6_a2_a3_an_older_or_shorter_ledger_is_rolled_back_with_an_anchor() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(t.path(), "a", 7, "orig", 5);
    let a = t.path().join("a.anchor");
    export(&d, &a, false);
    let old = copy_of(&d, t.path(), "old");
    for f in ["records.log", "checkpoints.log"] {
        let l = lines(&old.join("ledger").join(f));
        write_lines(&old.join("ledger").join(f), &l[..3]);
    }
    assert_eq!(verdict(&check(&old, &[])), "verdict: ok_unanchored");
    let r = check(&old, &["--anchor", a.to_str().unwrap()]);
    assert_eq!((r.0, verdict(&r)), (1, "verdict: rolled_back".to_string()));
}
#[test]
fn k7_records_cut_but_the_newest_checkpoint_kept_and_a_flipped_record_are_checkpoint_mismatch() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(t.path(), "a", 7, "orig", 5);
    let cut = copy_of(&d, t.path(), "cut");
    let l = lines(&cut.join("ledger/records.log"));
    write_lines(&cut.join("ledger/records.log"), &l[..4]);
    assert_eq!(verdict(&check(&cut, &[])), "verdict: checkpoint_mismatch");
    let fl = copy_of(&d, t.path(), "flip");
    let mut l = lines(&fl.join("ledger/records.log"));
    l[2] = flip(&l[2], 30);
    write_lines(&fl.join("ledger/records.log"), &l);
    assert_eq!(verdict(&check(&fl, &[])), "verdict: checkpoint_mismatch");
}
#[test]
fn k8_hostile_ledger_files_are_format_error_and_never_a_crash() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(t.path(), "a", 7, "orig", 3);
    let cases: Vec<(&str, &str, Vec<u8>)> = vec![
        ("partial last line", "records.log", {
            let mut b = std::fs::read(d.join("ledger/records.log")).unwrap();
            b.pop();
            b
        }),
        ("not hex", "records.log", b"zz\n".to_vec()),
        ("odd hex", "records.log", b"abc\n".to_vec()),
        ("empty record line", "records.log", b"\n".to_vec()),
        ("NUL byte", "records.log", b"ab\0cd\n".to_vec()),
        (
            "invalid UTF-8 in a record line",
            "records.log",
            b"\xff\xfe\n".to_vec(),
        ),
        (
            "invalid UTF-8 in a checkpoint",
            "checkpoints.log",
            b"\xff\xfe\n".to_vec(),
        ),
        (
            "checkpoint is not JSON",
            "checkpoints.log",
            b"not json\n".to_vec(),
        ),
        (
            "checkpoint of the wrong shape",
            "checkpoints.log",
            b"{\"a\":1}\n".to_vec(),
        ),
        ("a 1 MiB line", "records.log", {
            let mut b = vec![b'a'; 1024 * 1024];
            b.push(b'\n');
            b
        }),
        ("a 1 MiB checkpoint line", "checkpoints.log", {
            let mut b = vec![b'{'; 1024 * 1024];
            b.push(b'\n');
            b
        }),
    ];
    for (what, file, bytes) in cases {
        let c = copy_of(&d, t.path(), "h");
        std::fs::write(c.join("ledger").join(file), &bytes).unwrap();
        let r = check(&c, &[]);
        assert_eq!(
            (r.0, verdict(&r)),
            (1, "verdict: format_error".to_string()),
            "{what}: {r:?}"
        );
        std::fs::remove_dir_all(&c).ok();
    }
}
#[test]
fn k9_an_anchor_for_another_log_or_an_unreadable_one_is_refused_with_exit_3() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(t.path(), "a", 7, "orig", 3);
    let other = ledger(t.path(), "b", 9, "orig", 3);
    let f = t.path().join("other.anchor");
    export(&other, &f, false);
    let r = check(&d, &["--anchor", f.to_str().unwrap()]);
    assert_eq!(r.0, 3, "{r:?}");
    assert!(r.2.contains("another log"), "{}", r.2);
    assert!(!r.1.contains("verdict"), "a refusal is not a verdict");
    let missing = check(&d, &["--anchor", t.path().join("nope").to_str().unwrap()]);
    assert_eq!(missing.0, 3, "{missing:?}");
    let junk = t.path().join("junk");
    std::fs::write(&junk, "{}").unwrap();
    assert_eq!(check(&d, &["--anchor", junk.to_str().unwrap()]).0, 3);
}
#[test]
fn k10_precedence_through_the_command_line() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(t.path(), "a", 7, "orig", 5);
    // format_error beats signature_invalid: a flipped checkpoint signature AND a partial last record line
    let c = copy_of(&d, t.path(), "c1");
    let mut cps = lines(&c.join("ledger/checkpoints.log"));
    let at = cps[1].find("\"signature\":\"").unwrap() + 20;
    cps[1] = flip(&cps[1], at);
    write_lines(&c.join("ledger/checkpoints.log"), &cps);
    assert_eq!(verdict(&check(&c, &[])), "verdict: signature_invalid");
    let mut b = std::fs::read(c.join("ledger/records.log")).unwrap();
    b.pop();
    std::fs::write(c.join("ledger/records.log"), b).unwrap();
    assert_eq!(verdict(&check(&c, &[])), "verdict: format_error");
    // signature_invalid beats checkpoint_mismatch: the same bad signature AND cut records
    let c2 = copy_of(&d, t.path(), "c2");
    write_lines(&c2.join("ledger/checkpoints.log"), &cps);
    let l = lines(&c2.join("ledger/records.log"));
    write_lines(&c2.join("ledger/records.log"), &l[..3]);
    assert_eq!(verdict(&check(&c2, &[])), "verdict: signature_invalid");
}
#[test]
fn k11_a_ledger_signed_by_another_key_is_key_changed_unlogged() {
    let t = tempfile::tempdir().unwrap();
    let theirs = ledger(t.path(), "theirs", 9, "orig", 3);
    let mine = fresh(t.path(), "mine", 7);
    for f in ["records.log", "checkpoints.log"] {
        std::fs::copy(theirs.join("ledger").join(f), mine.join("ledger").join(f)).unwrap();
    }
    assert_eq!(verdict(&check(&mine, &[])), "verdict: key_changed_unlogged");
}
/// v2 checkpoints written next to the records of a real ledger, with the given times.
fn with_v2(d: &Path, seed_byte: u8, sizes: &[usize], times: &[u64]) {
    let p = Probe::from_signing_key_hex(&format!("{seed_byte:02x}").repeat(32)).unwrap();
    let leaves: Vec<_> = lines(&d.join("ledger/records.log"))
        .iter()
        .map(|l| merkle::leaf_hash(&hex::decode(l).unwrap()))
        .collect();
    let mut prev = [0u8; 32];
    let mut out = vec![];
    for (i, (s, t)) in sizes.iter().zip(times).enumerate() {
        let cp: CheckpointV2 = sign_v2(
            &p,
            i as u64 + 1,
            &prev,
            &merkle::root(&leaves[..*s]).unwrap(),
            *s,
            *t,
        )
        .unwrap();
        prev = cp.chain_digest();
        out.push(serde_json::to_string(&cp).unwrap());
    }
    write_lines(&d.join("ledger/checkpoints.log"), &out);
}
#[test]
fn k12_v2_checkpoints_on_disk_clock_regression_and_the_counter_in_a_hash_only_anchor() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(t.path(), "a", 7, "orig", 5);
    with_v2(&d, 7, &[2, 4, 5], &[100, 200, 300]);
    assert_eq!(
        verdict(&check(&d, &[])),
        "verdict: ok_unanchored",
        "a v2 ledger verifies"
    );
    let a = t.path().join("v2.anchor");
    let e = export(&d, &a, false);
    assert_eq!(e.0, 0, "{e:?}");
    let (anchor, _) = decode_anchor(&std::fs::read_to_string(&a).unwrap()).unwrap();
    assert_eq!((anchor.size, anchor.counter), (5, Some(3)));
    // the same records with a shorter chain: counter 2 at size 5 is older than the anchor's counter 3
    let older = copy_of(&d, t.path(), "older");
    with_v2(&older, 7, &[2, 5], &[100, 300]);
    let r = check(&older, &["--anchor", a.to_str().unwrap()]);
    assert_eq!(verdict(&r), "verdict: rolled_back");
    // times that run backwards
    let back = copy_of(&d, t.path(), "back");
    with_v2(&back, 7, &[2, 4, 5], &[100, 300, 200]);
    let r = check(&back, &[]);
    assert_eq!(
        (r.0, verdict(&r)),
        (1, "verdict: clock_regression".to_string())
    );
}
#[test]
fn k13_usage_errors_exit_2() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(t.path(), "a", 7, "orig", 1);
    let dir = d.to_str().unwrap();
    for args in [
        vec!["check"],
        vec!["check", "--dir"],
        vec!["anchor"],
        vec!["anchor", "export", "--dir", dir],
        vec!["anchor", "frobnicate", "--dir", dir, "--out", "x"],
        vec!["check", "--dir", dir, "--anchor"],
    ] {
        assert_eq!(run(&args).0, 2, "{args:?}");
    }
}

#[test]
fn k14_a_record_signed_by_another_key_under_our_checkpoints_is_signature_invalid() {
    use entropa_core::transparency_log::TransparencyLog;
    let t = tempfile::tempdir().unwrap();
    let theirs = ledger(t.path(), "theirs", 9, "orig", 3);
    let mine = fresh(t.path(), "mine", 7);
    std::fs::copy(
        theirs.join("ledger/records.log"),
        mine.join("ledger/records.log"),
    )
    .unwrap();
    // our key signs checkpoints over THEIR records: checkpoints and records agree, but each record's own signature is by the other key
    let p = Probe::from_signing_key_hex(&"07".repeat(32)).unwrap();
    let mut log = TransparencyLog::new();
    let mut cps = vec![];
    for l in lines(&mine.join("ledger/records.log")) {
        log.append(&hex::decode(l).unwrap());
        cps.push(serde_json::to_string(&log.checkpoint(&p, 1_700_000_000)).unwrap());
    }
    write_lines(&mine.join("ledger/checkpoints.log"), &cps);
    let r = check(&mine, &[]);
    assert_eq!(
        (r.0, verdict(&r)),
        (1, "verdict: signature_invalid".to_string()),
        "{r:?}"
    );
}

#[test]
fn k15_an_unterminated_extra_line_and_the_exact_record_size_limit() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(t.path(), "a", 7, "orig", 3);
    // a crash left a partial line after the last record ("abc" is odd; dropping its last digit would make it look valid)
    let c = copy_of(&d, t.path(), "p");
    let mut b = std::fs::read(c.join("ledger/records.log")).unwrap();
    b.extend_from_slice(b"abc");
    std::fs::write(c.join("ledger/records.log"), b).unwrap();
    assert_eq!(verdict(&check(&c, &[])), "verdict: format_error");
    // a record of exactly 64 KiB is read (the ledger then disagrees with its checkpoints); one byte more is a format error
    for (n, want) in [
        (64 * 1024, "verdict: checkpoint_mismatch"),
        (64 * 1024 + 1, "verdict: format_error"),
    ] {
        let e = copy_of(&d, t.path(), "e");
        std::fs::write(
            e.join("ledger/records.log"),
            format!("{}\n", "ab".repeat(n)),
        )
        .unwrap();
        assert_eq!(verdict(&check(&e, &[])), want, "{n} bytes");
        std::fs::remove_dir_all(&e).ok();
    }
}

// ---- slice 3: the writer issues v2 checkpoints
fn is_v2_line(l: &str) -> bool {
    l.contains("\"counter\"")
}
#[test]
fn m1_record_writes_v2_checkpoints_and_check_reports_the_format() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(t.path(), "a", 7, "orig", 4);
    let cps = lines(&d.join("ledger/checkpoints.log"));
    assert!(
        cps.iter().all(|l| is_v2_line(l)),
        "every checkpoint is v2: {cps:?}"
    );
    let r = check(&d, &[]);
    assert_eq!(
        (r.0, verdict(&r)),
        (0, "verdict: ok_unanchored".to_string()),
        "{r:?}"
    );
    assert_eq!(
        r.1.lines().nth(1).unwrap(),
        "records=4 checkpoints=4 anchors=0 format=v2"
    );
    let v = run(&["verify", "--dir", d.to_str().unwrap()]);
    assert_eq!(
        (v.0, v.1.trim().to_string()),
        (0, "OK records=4 checkpoints=4".to_string()),
        "the old verify reads v2 ledgers"
    );
    let st = run(&["status", "--dir", d.to_str().unwrap()]);
    assert!(
        st.1.contains("records: 4") && st.1.contains("checkpoints: 4"),
        "{st:?}"
    );
}
#[test]
fn m2_a_ledger_that_starts_v1_and_continues_v2_is_ok_and_says_v1_plus_v2_and_a_v1_after_v2_is_refused(
) {
    let t = tempfile::tempdir().unwrap();
    let d = fresh(t.path(), "a", 7);
    // two records written by the older (v1) writer, then the gate continues
    let p = Probe::from_signing_key_hex(&"07".repeat(32)).unwrap();
    for i in 1..=2 {
        let f = entropa_nodecore::decision_fields(&req("orig", i), &p.pubkey_hex()).unwrap();
        entropa_nodecore::append(&d, "ledger", &p, &f).unwrap();
    }
    for i in 3..=4 {
        node::record(&d, &req("orig", i)).unwrap();
    }
    let r = check(&d, &[]);
    assert_eq!(
        (r.0, verdict(&r)),
        (0, "verdict: ok_unanchored".to_string()),
        "{r:?}"
    );
    assert_eq!(
        r.1.lines().nth(1).unwrap(),
        "records=4 checkpoints=4 anchors=0 format=v1+v2"
    );
    // the downgrade, planted by hand: a v1 checkpoint line after the v2 lines
    let c = copy_of(&d, t.path(), "down");
    let mut cps = lines(&c.join("ledger/checkpoints.log"));
    let v1_line = cps[1].clone();
    cps.push(v1_line);
    write_lines(&c.join("ledger/checkpoints.log"), &cps);
    let r = check(&c, &[]);
    assert_eq!(
        (r.0, verdict(&r)),
        (1, "verdict: checkpoint_mismatch".to_string()),
        "{r:?}"
    );
}
#[test]
fn m3_a_v2_ledger_exports_a_signed_anchor_with_its_counter_and_rollback_by_counter_is_caught() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(t.path(), "a", 7, "orig", 5);
    let (h, s) = (t.path().join("h.anchor"), t.path().join("s.anchor"));
    assert_eq!(
        export(&d, &h, false).1.trim(),
        "anchor written: size=5 counter=5"
    );
    assert_eq!(export(&d, &s, true).0, 0);
    let (a, _) = decode_anchor(&std::fs::read_to_string(&s).unwrap()).unwrap();
    assert!(matches!(
        a.signed,
        Some(entropa_core::anchor::AnyCheckpoint::V2(_))
    ));
    node::record(&d, &req("orig", 6)).unwrap();
    for f in [&h, &s] {
        let r = check(&d, &["--anchor", f.to_str().unwrap()]);
        assert_eq!(
            (r.0, verdict(&r)),
            (0, "verdict: ok_anchored 5".to_string()),
            "{r:?}"
        );
    }
    // a rewrite with the same key is a fork against the signed v2 anchor and a rewrite against the hash-only one
    let alt = ledger(t.path(), "alt", 7, "alt", 5);
    assert_eq!(
        verdict(&check(&alt, &["--anchor", s.to_str().unwrap()])),
        "verdict: fork_detected"
    );
    assert_eq!(
        verdict(&check(&alt, &["--anchor", h.to_str().unwrap()])),
        "verdict: rewritten_since_anchor"
    );
}
#[test]
fn m4_the_gate_writer_never_emits_a_checkpoint_time_that_goes_backwards() {
    let t = tempfile::tempdir().unwrap();
    let d = fresh(t.path(), "a", 7);
    for (i, ts) in [
        (1u32, 1_700_000_900u64),
        (2, 1_700_000_100),
        (3, 1_700_000_500),
    ] {
        let r = req("orig", i).replace(
            &format!("\"ts\":{}", 1_700_000_000 + i),
            &format!("\"ts\":{ts}"),
        );
        node::record(&d, &r).unwrap();
    }
    let r = check(&d, &[]);
    assert_eq!(
        (r.0, verdict(&r)),
        (0, "verdict: ok_unanchored".to_string()),
        "an honest writer cannot trip clock_regression: {r:?}"
    );
}

// ---- added after the first mutation run (survivors in check.rs)
#[test]
fn n1_an_option_value_that_looks_like_the_option_is_taken_as_its_value() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(t.path(), "a", 7, "orig", 2);
    // `--anchor --anchor`: the second word is the FILE NAME of the first (it does not exist): refused with exit 3, not a usage error
    let r = check(&d, &["--anchor", "--anchor"]);
    assert_eq!(r.0, 3, "{r:?}");
}
#[test]
fn n2_an_anchor_file_of_exactly_32_kib_is_read_and_one_byte_more_is_refused_as_too_large() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(t.path(), "a", 7, "orig", 3);
    let f = t.path().join("a.anchor");
    export(&d, &f, false);
    let line = std::fs::read_to_string(&f).unwrap();
    let line = line.trim_end();
    let pad = |n: usize| format!("{line}{}", " ".repeat(n - line.len()));
    let exact = t.path().join("exact.anchor");
    std::fs::write(&exact, pad(32 * 1024)).unwrap();
    let r = check(&d, &["--anchor", exact.to_str().unwrap()]);
    assert_eq!(
        (r.0, verdict(&r)),
        (0, "verdict: ok_anchored 3".to_string()),
        "{r:?}"
    );
    let over = t.path().join("over.anchor");
    std::fs::write(&over, pad(32 * 1024 + 1)).unwrap();
    let r = check(&d, &["--anchor", over.to_str().unwrap()]);
    assert_eq!(r.0, 3, "{r:?}");
    assert!(r.2.contains("larger than 32 KiB"), "{}", r.2);
}
#[test]
fn n3_a_record_of_another_kind_in_the_ledger_is_signature_invalid() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(t.path(), "a", 7, "orig", 2);
    // an evidence record, correctly signed by our key and covered by our checkpoints, is not a decision record of this ledger
    let p = Probe::from_signing_key_hex(&"07".repeat(32)).unwrap();
    let ev = r#"{"kind":"evidence.change","label":"code_change","decision":"allow","reason":"within_limits","control":"hitrust_10_sdlc","total":1,"passed":1,"flagged":0,"detail":"synthetic","run_id":"0000000000000000000000000000000000000000000000000000000000000001","ts":1700000009}"#;
    let f = entropa_nodecore::evidence_event(ev, &p.pubkey_hex()).unwrap();
    entropa_nodecore::append_v2(&d, "ledger", &p, &f).unwrap();
    let r = check(&d, &[]);
    assert_eq!(
        (r.0, verdict(&r)),
        (1, "verdict: signature_invalid".to_string()),
        "{r:?}"
    );
}
#[test]
fn n4_the_no_anchor_warning_belongs_to_ok_unanchored_only() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(t.path(), "a", 7, "orig", 3);
    let missing = check(&d, &["--require-anchor"]);
    assert_eq!(verdict(&missing), "verdict: anchor_missing");
    assert!(
        !missing.2.contains("warning"),
        "no warning on an alarm: {}",
        missing.2
    );
    let cut = copy_of(&d, t.path(), "cut");
    let l = lines(&cut.join("ledger/records.log"));
    write_lines(&cut.join("ledger/records.log"), &l[..2]);
    let r = check(&cut, &[]);
    assert_eq!(verdict(&r), "verdict: checkpoint_mismatch");
    assert!(!r.2.contains("warning"), "{}", r.2);
}

#[test]
fn k16_upper_case_hex_in_the_ledger_files_is_a_format_error_for_check_and_a_refusal_for_verify() {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(t.path(), "a", 7, "orig", 3);
    let r = copy_of(&d, t.path(), "upper-records");
    let up = std::fs::read_to_string(r.join("ledger/records.log"))
        .unwrap()
        .to_uppercase();
    std::fs::write(r.join("ledger/records.log"), up).unwrap();
    let c = check(&r, &[]);
    assert_eq!(
        (c.0, verdict(&c)),
        (1, "verdict: format_error".to_string()),
        "{c:?}"
    );
    assert_eq!(
        run(&["verify", "--dir", r.to_str().unwrap()]).0,
        1,
        "the older command agrees"
    );
    let k = copy_of(&d, t.path(), "upper-cp");
    let cps: Vec<String> = lines(&k.join("ledger/checkpoints.log"))
        .iter()
        .map(|l| {
            let i = l.find("\"root\":\"").unwrap() + 8;
            format!("{}{}{}", &l[..i], l[i..i + 64].to_uppercase(), &l[i + 64..])
        })
        .collect();
    write_lines(&k.join("ledger/checkpoints.log"), &cps);
    assert_eq!(verdict(&check(&k, &[])), "verdict: format_error");
}

#[test]
fn k17_a_duplicated_or_unknown_key_in_a_checkpoint_line_is_a_format_error_for_check_and_a_refusal_for_verify(
) {
    let t = tempfile::tempdir().unwrap();
    let d = ledger(t.path(), "a", 7, "orig", 3);
    for (what, edit) in [
        (
            "duplicate size, same value",
            (|l: &str| format!("{},\"size\":3}}", &l[..l.len() - 1])) as fn(&str) -> String,
        ),
        ("duplicate counter, other value", |l: &str| {
            format!("{},\"counter\":99}}", &l[..l.len() - 1])
        }),
        ("unknown extra key", |l: &str| {
            format!("{},\"extra\":1}}", &l[..l.len() - 1])
        }),
        ("unknown extra text key", |l: &str| {
            format!("{},\"note\":\"x\"}}", &l[..l.len() - 1])
        }),
    ] {
        let c = copy_of(&d, t.path(), "edited");
        let mut cps = lines(&c.join("ledger/checkpoints.log"));
        let last = cps.len() - 1;
        cps[last] = edit(&cps[last]);
        write_lines(&c.join("ledger/checkpoints.log"), &cps);
        let r = check(&c, &[]);
        assert_eq!(
            (r.0, verdict(&r)),
            (1, "verdict: format_error".to_string()),
            "{what}: {r:?}"
        );
        assert_eq!(
            run(&["verify", "--dir", c.to_str().unwrap()]).0,
            1,
            "{what}: verify refuses too"
        );
        std::fs::remove_dir_all(&c).ok();
    }
}
