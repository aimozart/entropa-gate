//! S1 slice A (task 2): `entropa-gate init`, `record`, `verify`, `status` and the strict config. Bars from a stage record (not published) (I1 to I6), fixed before
//! the code: the key is 0600 in a 0700 directory and never printed; unknown config keys are refused; a record is hash-only; 300 planted canaries never
//! reach a file, a receipt or stdout; ONE changed byte in a copy fails verification at 5 of 5 positions and the original is untouched; the dependency tree
//! and the sources hold no network code. Synthetic data only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_gate::config::Config;
use entropa_gate::{keys, node};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const REQ: &str = r#"{"label":"nl_query","decision":"allow","reason":"guard_passed","input":"How many claims were denied by payer?","output":"SELECT payer, COUNT(*) FROM t GROUP BY payer LIMIT 100","run_id":"run-s1-a","provider":"vertex","model_id":"gemini-3.8-flash","input_tokens":120,"output_tokens":40,"cost_micro_usd":90}"#;

fn bin(args: &[&str], stdin: Option<&str>) -> (i32, String, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_entropa-gate"));
    c.args(args)
        .env_remove("ENTROPA_GCP_KMS_KEY")
        .env_remove("PLATINUM_KEY_FILE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut ch = c.spawn().unwrap();
    if let Some(s) = stdin {
        // a command may refuse and exit before it reads all of a large input: a broken pipe is not a test failure
        let _ = ch.stdin.take().unwrap().write_all(s.as_bytes());
    } else {
        drop(ch.stdin.take());
    }
    let o = ch.wait_with_output().unwrap();
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}
fn node_dir(t: &tempfile::TempDir) -> PathBuf {
    t.path().join("node")
}
fn key_hex(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("platinum.key"))
        .unwrap()
        .trim()
        .to_string()
}
fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let (p, q) = (e.path(), to.join(e.file_name()));
        if p.is_dir() {
            copy_dir(&p, &q);
        } else {
            std::fs::copy(&p, &q).unwrap();
        }
    }
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
    out
}

#[test]
fn a1_init_makes_a_private_key_in_a_private_directory_and_never_prints_it() {
    let t = tempfile::tempdir().unwrap();
    let d = node_dir(&t);
    let (code, out, err) = bin(&["init", "--dir", d.to_str().unwrap()], None);
    assert_eq!(code, 0, "{err}");
    let key = key_hex(&d);
    assert_eq!(key.len(), 64, "a 32-byte seed in hex");
    assert!(
        !out.contains(&key) && !err.contains(&key),
        "the key was printed"
    );
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&d.join("platinum.key")), 0o600);
    assert_eq!(mode(&d), 0o700, "the data directory is private");
    // a second init must not replace the key
    let (code2, _, err2) = bin(&["init", "--dir", d.to_str().unwrap()], None);
    assert_ne!(code2, 0);
    assert!(err2.contains("already initialised"), "{err2}");
    assert_eq!(key_hex(&d), key);
}

#[test]
fn a2_the_config_has_closed_keys() {
    let ok = Config::parse(
        "org_name = \"Example Clinic\"\nwitnesses = [\"https://witness.example.invalid\"]\n",
    )
    .unwrap();
    assert_eq!(ok.org_name, "Example Clinic");
    assert_eq!(
        ok.witnesses,
        vec!["https://witness.example.invalid".to_string()]
    );
    assert!(Config::parse("org_name = \"X\"\n")
        .unwrap()
        .witnesses
        .is_empty());
    for bad in [
        "org_name = \"X\"\ncolour = \"red\"\n",          // unknown key
        "witnesses = []\n",                              // org_name is required
        "org_name = 5\n",                                // wrong type
        "org_name = \"\"\n",                             // empty
        "org_name = \"X\"\nwitnesses = [\"ftp://a\"]\n", // only https
        "org_name = \"X\"\nwitnesses = [\"http://a.example.invalid\"]\n",
        "org_name = \"X\"\n[sub]\nk = 1\n",     // a table
        "org_name = \"X\"\norg_name = \"Y\"\n", // duplicate key
        "not toml at all [",
    ] {
        assert!(Config::parse(bad).is_err(), "accepted: {bad}");
    }
    let long = format!("org_name = \"{}\"\n", "x".repeat(81));
    assert!(Config::parse(&long).is_err(), "81 characters");
}

#[test]
fn a3_init_record_verify_status_round_trip_on_the_command_line() {
    let t = tempfile::tempdir().unwrap();
    let ds = node_dir(&t);
    let ds = ds.to_str().unwrap();
    assert_eq!(bin(&["init", "--dir", ds], None).0, 0);
    for i in 1..=3 {
        let (code, out, err) = bin(&["record", "--dir", ds], Some(REQ));
        assert_eq!(code, 0, "{err}");
        assert!(out.contains("subject_hash"), "{out}");
        assert!(
            out.contains(&format!("\"index\":{}", i - 1))
                || out.contains(&format!("\"index\": {}", i - 1)),
            "{out}"
        );
    }
    let (code, out, err) = bin(&["verify", "--dir", ds], None);
    assert_eq!(code, 0, "{err}");
    assert!(out.starts_with("OK records=3 checkpoints=3"), "{out}");
    let (code, out, _) = bin(&["status", "--dir", ds], None);
    assert_eq!(code, 0);
    assert!(out.contains("records: 3"), "{out}");
    assert!(
        !out.contains(&key_hex(Path::new(ds))),
        "status printed the key"
    );
}

#[test]
fn a4_record_refuses_bad_requests_and_changes_nothing() {
    let t = tempfile::tempdir().unwrap();
    let d = node_dir(&t);
    let ds = d.to_str().unwrap();
    bin(&["init", "--dir", ds], None);
    let ssn = format!("ssn {}-{}-{}", "123", "45", "6789");
    let big = format!(
        "{},\"pad\":\"{}\"}}",
        &REQ[..REQ.len() - 1],
        "x".repeat(4096)
    );
    let bad = [
        "not json".to_string(),
        r#"{"label":"nl_query"}"#.to_string(),
        REQ.replace("nl_query", "fraud_screen"),
        REQ.replace('}', r#","extra":"x"}"#),
        REQ.replace("How many claims", &ssn),
        REQ.replace("run-s1-a", "bad run id with spaces"),
        REQ.replace(
            "How many claims were denied by payer?",
            &"q".repeat(3 * 1024 * 1024),
        ),
        big,
    ];
    for b in &bad {
        let (code, _, err) = bin(&["record", "--dir", ds], Some(b));
        assert_ne!(code, 0, "accepted: {}", &b[..b.len().min(80)]);
        assert!(!err.contains("qqqq"), "the input was echoed");
    }
    assert!(
        bin(&["verify", "--dir", ds], None)
            .1
            .starts_with("OK records=0"),
        "a refused request must not write"
    );
}

#[test]
fn a5_300_planted_canaries_never_reach_a_file_a_receipt_or_stdout() {
    let t = tempfile::tempdir().unwrap();
    let d = node_dir(&t);
    keys::init(&d).unwrap();
    let mut canaries = Vec::new();
    let mut receipts = String::new();
    for i in 0..300u32 {
        // synthetic canary: a fixed prefix and 16 hex digits derived from the counter, never a real value
        let c = format!(
            "ENTROPA-CANARY-{:016x}",
            0x5eed_0000_0000_0000u64 + u64::from(i) * 7919
        );
        let req = REQ
            .replace(
                "How many claims were denied by payer?",
                &format!("question {c}"),
            )
            .replace("SELECT payer", &format!("SELECT {c}"));
        let r = node::record(&d, &req).unwrap();
        receipts.push_str(&format!("{r:?}"));
        canaries.push(c);
    }
    // the scan itself must be able to find a canary (control): plant one in a copy of a file
    let probe = t.path().join("planted.txt");
    std::fs::write(&probe, format!("x {} y", canaries[0])).unwrap();
    let hay = |p: &Path| String::from_utf8_lossy(&std::fs::read(p).unwrap()).into_owned();
    assert!(
        hay(&probe).contains(&canaries[0]),
        "the scan cannot see a planted canary"
    );
    let mut all = receipts;
    for f in files(&d) {
        all.push_str(&hay(&f));
    }
    let (_, out, err) = bin(&["verify", "--dir", d.to_str().unwrap()], None);
    all.push_str(&out);
    all.push_str(&err);
    let hits = canaries.iter().filter(|c| all.contains(c.as_str())).count();
    assert_eq!(hits, 0, "{hits} of 300 canaries leaked");
}

#[test]
fn a6_one_changed_byte_in_a_copy_fails_verification_at_five_of_five_positions() {
    let t = tempfile::tempdir().unwrap();
    let d = node_dir(&t);
    keys::init(&d).unwrap();
    for _ in 0..5 {
        node::record(&d, REQ).unwrap();
    }
    assert!(node::verify(&d).unwrap().starts_with("OK records=5"));
    let before: Vec<(PathBuf, Vec<u8>)> = files(&d)
        .into_iter()
        .map(|p| {
            let b = std::fs::read(&p).unwrap();
            (p, b)
        })
        .collect();
    let rec = "ledger/records.log";
    let len = std::fs::metadata(d.join(rec)).unwrap().len() as usize;
    let mut detected = 0;
    for (n, how) in ["first", "middle", "last", "append", "truncate"]
        .iter()
        .enumerate()
    {
        let c = t.path().join(format!("copy{n}"));
        copy_dir(&d, &c);
        let p = c.join(rec);
        let mut b = std::fs::read(&p).unwrap();
        match *how {
            "first" => b[0] = if b[0] == b'0' { b'1' } else { b'0' },
            "middle" => {
                let i = len / 2;
                b[i] = if b[i] == b'a' { b'b' } else { b'a' };
            }
            "last" => {
                let i = len - 2;
                b[i] = if b[i] == b'a' { b'b' } else { b'a' };
            }
            "append" => b.extend_from_slice(b"00\n"),
            _ => b.truncate(len - 40),
        }
        std::fs::write(&p, &b).unwrap();
        let r = node::verify(&c);
        let (code, _, _) = bin(&["verify", "--dir", c.to_str().unwrap()], None);
        if r.is_err() && code != 0 {
            detected += 1;
        } else {
            eprintln!("not detected: {how}");
        }
    }
    assert_eq!(detected, 5, "tamper detected at {detected} of 5 positions");
    for (p, b) in before {
        assert_eq!(
            std::fs::read(&p).unwrap(),
            b,
            "the original changed: {}",
            p.display()
        );
    }
}

#[test]
fn a7_a_key_file_that_others_can_read_is_refused() {
    let t = tempfile::tempdir().unwrap();
    let d = node_dir(&t);
    keys::init(&d).unwrap();
    node::record(&d, REQ).unwrap();
    std::fs::set_permissions(
        d.join("platinum.key"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(node::record(&d, REQ).is_err(), "record with a 0644 key");
    assert!(node::verify(&d).is_err(), "verify with a 0644 key");
    assert!(node::status(&d).is_err(), "status with a 0644 key");
}

#[test]
fn a8_the_library_holds_no_network_code_and_never_reads_the_cloud_key_variables() {
    let out = Command::new(env!("CARGO"))
        .args([
            "tree",
            "-p",
            "entropa-gate",
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
        "tokio",
        "hyper",
        "reqwest",
        "axum",
        "mio",
        "socket2",
        "h2 ",
        "ureq",
        "curl",
        "openssl",
        "rustls",
        "entropa-platinum",
        "entropa-kms",
    ] {
        assert!(
            !tree.lines().any(|l| l.starts_with(bad)),
            "{bad} is in the tree:\n{tree}"
        );
    }
    let mut n = 0;
    for p in files(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src")) {
        let s = std::fs::read_to_string(&p).unwrap();
        n += 1;
        for bad in [
            "std::net",
            "TcpStream",
            "UdpSocket",
            "std::process::Command",
            "ENTROPA_GCP_KMS_KEY",
            "PLATINUM_KEY_FILE",
        ] {
            assert!(!s.contains(bad), "{bad} in {}", p.display());
        }
    }
    assert!(n >= 6, "the source walk found {n} files");
}

#[test]
fn a9_only_keys_rs_names_the_key_file_and_no_public_function_returns_key_bytes() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for p in files(&src) {
        let s = std::fs::read_to_string(&p).unwrap();
        let name = p.file_name().unwrap().to_str().unwrap().to_string();
        if name != "keys.rs" {
            assert!(
                !s.contains("platinum.key"),
                "the key file is named in {name}"
            );
        }
    }
    let keys = std::fs::read_to_string(src.join("keys.rs")).unwrap();
    for l in keys.lines().filter(|l| l.contains("pub fn")) {
        assert!(
            !l.contains("-> String")
                && !l.contains("Vec<u8>")
                && !l.contains("&[u8]")
                && !l.contains("Seed"),
            "a public key function returns bytes: {l}"
        );
    }
}

#[test]
fn a10_a_gate_ledger_verifies_with_the_platinum_verifier_and_the_other_way_round() {
    let t = tempfile::tempdir().unwrap();
    let d = node_dir(&t);
    keys::init(&d).unwrap();
    node::record(&d, REQ).unwrap();
    node::record(&d, REQ).unwrap();
    let st = node::status(&d).unwrap();
    assert_eq!(st.records, 2);
    assert!(entropa_platinum::verify_with(&d, &st.pubkey)
        .unwrap()
        .starts_with("OK records=2"));
    // a platinum-made ledger verifies with the gate (same format)
    let p = t.path().join("plat");
    entropa_platinum::init(&p).unwrap();
    entropa_platinum::log_with(&p, &*entropa_platinum::node_signer(&p).unwrap(), REQ).unwrap();
    assert!(node::verify(&p).unwrap().starts_with("OK records=1"));
}

#[test]
fn a4b_the_library_refuses_a_request_over_the_size_limit_even_when_it_is_valid() {
    let t = tempfile::tempdir().unwrap();
    let d = node_dir(&t);
    keys::init(&d).unwrap();
    let ok = REQ.replace("How many claims were denied by payer?", &"q".repeat(1000));
    assert!(node::record(&d, &ok).is_ok(), "a 1 KB question is fine");
    let big = REQ.replace(
        "How many claims were denied by payer?",
        &"q".repeat(node::MAX_REQUEST_BYTES + 1000),
    );
    let e = node::record(&d, &big).unwrap_err().to_string();
    assert!(e.contains("too large"), "refused for another reason: {e}");
    assert_eq!(node::verify(&d).unwrap(), "OK records=1 checkpoints=1");
}
