//! S2e red tests (a stage record (not published)): the program, run as a real process. Expected values: the library's own verifier is NOT used to judge the CLI; the files and exit codes are.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_entropa-release"))
}
fn run(args: &[&str]) -> (i32, String, String) {
    let o = bin().args(args).output().unwrap();
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}
fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("s2e-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}
fn lock() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.lock")
}
fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}
/// A release directory with two synthetic artifacts, a key, an SBOM; returns (root, release dir, key, pubkey).
fn setup(tag: &str) -> (PathBuf, PathBuf, PathBuf, String, PathBuf) {
    let root = scratch(tag);
    let rel = root.join("release");
    std::fs::create_dir_all(&rel).unwrap();
    std::fs::write(rel.join("tool-linux-x86_64"), b"synthetic binary").unwrap();
    std::fs::write(rel.join("tool.sha256sums"), b"synthetic sums").unwrap();
    let key = root.join("signing.key");
    let (code, out, _) = run(&["keygen", "--out", s(&key)]);
    assert_eq!(code, 0, "keygen failed");
    let pubkey = out
        .lines()
        .find_map(|l| l.strip_prefix("public key: "))
        .expect("no public key line")
        .trim()
        .to_string();
    let sbom = root.join("sbom.json");
    assert_eq!(
        run(&[
            "sbom",
            "--lock",
            s(&lock()),
            "--product",
            "tool",
            "--version",
            "1.0.0",
            "--out",
            s(&sbom)
        ])
        .0,
        0
    );
    (root, rel, key, pubkey, sbom)
}
fn sign(rel: &Path, key: &Path, sbom: &Path, out: &Path) -> (i32, String, String) {
    run(&[
        "sign",
        "--dir",
        s(rel),
        "--product",
        "tool",
        "--version",
        "1.0.0",
        "--sbom",
        s(sbom),
        "--key",
        s(key),
        "--out",
        s(out),
    ])
}

#[test]
fn c1_keygen_writes_a_private_file_prints_only_the_public_key_and_never_overwrites() {
    let root = scratch("c1");
    let key = root.join("k.key");
    let (code, out, err) = run(&["keygen", "--out", s(&key)]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let seed = std::fs::read_to_string(&key).unwrap().trim().to_string();
    assert_eq!(seed.len(), 64, "a 32-byte seed in hex");
    assert!(
        !out.contains(&seed) && !err.contains(&seed),
        "the seed was printed"
    );
    let pk = out
        .lines()
        .find_map(|l| l.strip_prefix("public key: "))
        .unwrap()
        .trim();
    assert_eq!(pk.len(), 3904, "an ML-DSA-65 public key in hex");
    assert!(out
        .lines()
        .any(|l| l.starts_with("key id: ") && l.trim().len() == "key id: ".len() + 16));
    let before = std::fs::read(&key).unwrap();
    let (code, _, err) = run(&["keygen", "--out", s(&key)]);
    assert_eq!(code, 1, "overwrote an existing key");
    assert!(err.contains("exists"));
    assert_eq!(before, std::fs::read(&key).unwrap());
}

#[test]
fn c2_the_full_flow_sign_then_verify_exits_zero() {
    let (root, rel, key, pubkey, sbom) = setup("c2");
    let m = root.join("manifest.json");
    let (code, _, err) = sign(&rel, &key, &sbom, &m);
    assert_eq!(code, 0, "{err}");
    let seed = std::fs::read_to_string(&key).unwrap().trim().to_string();
    for f in [&m, &sbom] {
        assert!(
            !std::fs::read_to_string(f).unwrap().contains(&seed),
            "the seed is in {f:?}"
        );
    }
    let (code, out, err) = run(&[
        "verify",
        "--dir",
        s(&rel),
        "--manifest",
        s(&m),
        "--pubkey",
        &pubkey,
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.starts_with("OK tool 1.0.0 artifacts=2 key_id="),
        "{out}"
    );
}

#[test]
fn c3_verify_exits_one_for_every_tamper_class() {
    let (root, rel, key, pubkey, sbom) = setup("c3");
    let m = root.join("manifest.json");
    assert_eq!(sign(&rel, &key, &sbom, &m).0, 0);
    let v = |pk: &str, man: &Path| {
        run(&[
            "verify",
            "--dir",
            s(&rel),
            "--manifest",
            s(man),
            "--pubkey",
            pk,
        ])
    };
    // wrong public key
    let other = root.join("other.key");
    let (_, o, _) = run(&["keygen", "--out", s(&other)]);
    let other_pk = o
        .lines()
        .find_map(|l| l.strip_prefix("public key: "))
        .unwrap()
        .trim()
        .to_string();
    assert_eq!(v(&other_pk, &m).0, 1, "wrong key");
    // a changed manifest (one character of the signed text)
    let text = std::fs::read_to_string(&m).unwrap();
    let bad = root.join("bad.json");
    std::fs::write(&bad, text.replacen("tool-linux", "tool-evil", 1)).unwrap();
    assert_eq!(v(&pubkey, &bad).0, 1, "changed manifest");
    // a changed byte, an extra file, a removed file
    let f = rel.join("tool-linux-x86_64");
    std::fs::write(&f, b"synthetic binarz").unwrap();
    assert_eq!(v(&pubkey, &m).0, 1, "changed byte");
    std::fs::write(&f, b"synthetic binary").unwrap();
    assert_eq!(
        v(&pubkey, &m).0,
        0,
        "restored file verifies again (the test is not vacuous)"
    );
    std::fs::write(rel.join("extra.txt"), b"x").unwrap();
    assert_eq!(v(&pubkey, &m).0, 1, "extra file");
    std::fs::rename(rel.join("extra.txt"), root.join("extra.moved")).unwrap();
    std::fs::rename(rel.join("tool.sha256sums"), root.join("sums.moved")).unwrap();
    assert_eq!(v(&pubkey, &m).0, 1, "removed file");
}

#[test]
fn c4_sign_refuses_a_bad_key_an_existing_output_a_subdirectory_and_an_empty_directory() {
    let (root, rel, key, _pk, sbom) = setup("c4");
    let seed = std::fs::read_to_string(&key).unwrap().trim().to_string();
    let out = root.join("m.json");
    // key readable by others
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    let (code, o, e) = sign(&rel, &key, &sbom, &out);
    assert_eq!(code, 1);
    assert!(e.contains("permission") || e.contains("0600"), "{e}");
    assert!(!out.exists(), "an output was written for a bad key");
    assert!(!o.contains(&seed) && !e.contains(&seed));
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    // missing key, a key file that is not a key
    assert_eq!(sign(&rel, &root.join("nokey"), &sbom, &out).0, 1);
    let junk = root.join("junk.key");
    std::fs::write(&junk, "not a key\n").unwrap();
    std::fs::set_permissions(&junk, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(sign(&rel, &junk, &sbom, &out).0, 1);
    // existing output is not overwritten
    std::fs::write(&out, "keep me").unwrap();
    assert_eq!(sign(&rel, &key, &sbom, &out).0, 1);
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "keep me");
    // a subdirectory, an empty directory
    let out2 = root.join("m2.json");
    std::fs::create_dir_all(rel.join("sub")).unwrap();
    assert_eq!(sign(&rel, &key, &sbom, &out2).0, 1, "subdirectory");
    let empty = root.join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    assert_eq!(sign(&empty, &key, &sbom, &out2).0, 1, "empty directory");
    assert!(!out2.exists());
}

#[test]
fn c5_usage_errors_exit_two() {
    for args in [
        vec![],
        vec!["nope"],
        vec!["keygen"],
        vec!["sbom", "--lock", "x"],
        vec!["sign"],
        vec!["verify", "--dir", "x"],
    ] {
        let (code, _, err) = run(&args);
        assert_eq!(code, 2, "{args:?}: {err}");
        assert!(err.contains("usage"), "{args:?}");
    }
}

#[test]
fn c6_a_manifest_stored_inside_the_release_directory_is_not_one_of_its_artifacts() {
    let (_root, rel, key, pubkey, sbom) = setup("c6");
    let m = rel.join("manifest.json");
    let (code, _, err) = sign(&rel, &key, &sbom, &m);
    assert_eq!(code, 0, "{err}");
    let (code, out, err) = run(&[
        "verify",
        "--dir",
        s(&rel),
        "--manifest",
        s(&m),
        "--pubkey",
        &pubkey,
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("artifacts=2"), "{out}");
}

// ---- mutation triage (first run: 45 mutants, 4 missed: the read cap) ----
#[test]
fn c7_the_manifest_read_cap_is_exactly_one_mebibyte() {
    let (root, rel, key, pubkey, sbom) = setup("c7");
    let m = root.join("manifest.json");
    assert_eq!(sign(&rel, &key, &sbom, &m).0, 0);
    let text = std::fs::read_to_string(&m).unwrap();
    let cap = 1usize << 20;
    let at = root.join("at.json");
    std::fs::write(&at, format!("{text}{}", " ".repeat(cap - text.len()))).unwrap();
    assert_eq!(std::fs::metadata(&at).unwrap().len() as usize, cap);
    let (code, _, err) = run(&[
        "verify",
        "--dir",
        s(&rel),
        "--manifest",
        s(&at),
        "--pubkey",
        &pubkey,
    ]);
    assert_eq!(code, 0, "exactly the cap must verify: {err}");
    let over = root.join("over.json");
    std::fs::write(&over, format!("{text}{}", " ".repeat(cap + 1 - text.len()))).unwrap();
    let (code, _, err) = run(&[
        "verify",
        "--dir",
        s(&rel),
        "--manifest",
        s(&over),
        "--pubkey",
        &pubkey,
    ]);
    assert_eq!(code, 1, "one byte over the cap must be refused");
    assert!(err.contains("too large"), "{err}");
}
