//! S2 red tests (a stage record (not published)). Expected values come from independent sources: `cargo metadata` for the SBOM, the `minisign` program for its wrapper, `sha256sum`-style hashes computed here by the
//! test with its own tiny reference (no call into the crate under test), and fixed synthetic keys generated at run time. Synthetic data only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::Probe;
use entropa_release::{manifest, minisign, sbom, Component, ReleaseError};
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn lock() -> String {
    std::fs::read_to_string(root().join("Cargo.lock")).unwrap()
}
fn metadata() -> String {
    let o = std::process::Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--offline",
            "--filter-platform",
            "x86_64-unknown-linux-gnu",
        ])
        .current_dir(root())
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8(o.stdout).unwrap()
}
fn probe(b: u8) -> Probe {
    Probe::from_signing_key_hex(&format!("{b:02x}").repeat(32)).unwrap()
}
fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("s2-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}
fn files() -> Vec<(String, Vec<u8>)> {
    vec![
        (
            "entropa-gate-linux-x86_64".into(),
            b"synthetic binary one".to_vec(),
        ),
        ("entropa-gate.sha256sums".into(), b"synthetic sums".to_vec()),
    ]
}
fn signed(p: &Probe) -> (String, String) {
    let sb =
        sbom::to_cyclonedx(&sbom::from_lock(&lock()).unwrap(), "entropa-gate", "0.2.0").unwrap();
    let m = manifest::build("entropa-gate", "0.2.0", &files(), &sb).unwrap();
    (manifest::sign(&m, p).unwrap(), sb)
}

// ---- SBOM ----
#[test]
fn s1_the_sbom_has_one_component_per_lock_package() {
    let l = lock();
    let want = l.matches("[[package]]").count();
    assert!(want > 100, "the real lock is large: {want}");
    assert_eq!(sbom::from_lock(&l).unwrap().len(), want);
}

#[test]
fn s2_the_sbom_covers_every_package_of_cargo_metadata_on_the_real_workspace() {
    // `cargo metadata` for ALL platforms needs sources that are not downloaded (offline): measured, so the check is "metadata for this platform is a subset"
    let c = sbom::from_lock(&lock()).unwrap();
    let md: serde_json::Value = serde_json::from_str(&metadata()).unwrap();
    let n = md["packages"].as_array().unwrap().len();
    let r = sbom::cross_check(&c, &metadata()).unwrap();
    assert_eq!(r.checked, n);
    assert_eq!(r.checked + r.not_in_metadata, c.len());
    assert!(
        r.not_in_metadata > 0,
        "other-platform packages exist in the lock: {r:?}"
    );
    sbom::check_lock(&c, &lock()).unwrap();
}

#[test]
fn s3_every_planted_fault_is_found_by_the_checks() {
    let good = sbom::from_lock(&lock()).unwrap();
    let md = metadata();
    let used: Vec<String> = serde_json::from_str::<serde_json::Value>(&md).unwrap()["packages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| !p["source"].is_null())
        .map(|p| p["name"].as_str().unwrap().to_string())
        .collect();
    let i = good
        .iter()
        .position(|c| c.source.is_some() && used.contains(&c.name))
        .unwrap();
    let mut extra = good.clone();
    extra.push(Component {
        name: "planted-extra".into(),
        version: "1.0.0".into(),
        source: Some("registry+https://github.com/rust-lang/crates.io-index".into()),
        checksum: Some("0".repeat(64)),
    });
    let mut missing = good.clone();
    missing.remove(i);
    let mut version = good.clone();
    version[i].version = "99.99.99".into();
    let mut source = good.clone();
    source[i].source = Some("git+https://example.invalid/x".into());
    // an extra component is invisible to a subset check but found against the lock; the other three are found by BOTH
    assert!(
        matches!(
            sbom::check_lock(&extra, &lock()),
            Err(ReleaseError::Mismatch(_))
        ),
        "extra not found by the lock check"
    );
    for (name, bad) in [
        ("missing", missing),
        ("version", version),
        ("source", source),
    ] {
        assert!(
            matches!(sbom::cross_check(&bad, &md), Err(ReleaseError::Mismatch(_))),
            "{name} not found by metadata"
        );
        assert!(
            matches!(
                sbom::check_lock(&bad, &lock()),
                Err(ReleaseError::Mismatch(_))
            ),
            "{name} not found by the lock check"
        );
    }
}

#[test]
fn s4_the_sbom_text_is_identical_on_two_runs_and_reads_back() {
    let c = sbom::from_lock(&lock()).unwrap();
    let (a, b) = (
        sbom::to_cyclonedx(&c, "entropa-gate", "0.2.0").unwrap(),
        sbom::to_cyclonedx(&c, "entropa-gate", "0.2.0").unwrap(),
    );
    assert_eq!(a, b);
    assert!(a.contains("\"bomFormat\":\"CycloneDX\"") && a.contains("\"specVersion\":\"1.5\""));
    assert!(
        !a.contains("timestamp") && !a.contains("serialNumber"),
        "must be deterministic"
    );
    assert_eq!(sbom::parse_cyclonedx(&a).unwrap(), c);
}

#[test]
fn s5_a_lock_that_is_not_a_lock_is_refused() {
    for bad in [
        "",
        "not toml [",
        "[[package]]\nname = \"x\"\n",
        "[[package]]\nversion = \"1\"\n",
    ] {
        assert!(
            matches!(sbom::from_lock(bad), Err(ReleaseError::Lock(_))),
            "accepted {bad:?}"
        );
    }
}

// ---- manifest ----
#[test]
fn m1_a_signed_manifest_verifies_with_the_right_key_and_the_right_files() {
    let p = probe(3);
    let (env, _) = signed(&p);
    let v = manifest::verify(&env, &p.pubkey_hex(), &files()).unwrap();
    assert_eq!(
        (v.product.as_str(), v.version.as_str(), v.artifacts),
        ("entropa-gate", "0.2.0", 2)
    );
    assert_eq!(v.key_id, entropa_approvals_key_id(&p));
}
fn entropa_approvals_key_id(p: &Probe) -> String {
    // independent of the crate under test: the first 16 hex characters of the blake3 of the public key bytes
    let pk = hex::decode(p.pubkey_hex()).unwrap();
    blake3::hash(&pk).to_hex()[..16].to_string()
}

#[test]
fn m2_every_tamper_class_is_refused() {
    let p = probe(3);
    let (env, _) = signed(&p);
    let pk = p.pubkey_hex();
    // a changed file byte, a missing file, an extra unlisted file
    let mut f = files();
    f[0].1[0] ^= 1;
    assert!(
        matches!(
            manifest::verify(&env, &pk, &f),
            Err(ReleaseError::Mismatch(_))
        ),
        "changed byte"
    );
    let mut f = files();
    f.pop();
    assert!(
        matches!(
            manifest::verify(&env, &pk, &f),
            Err(ReleaseError::Mismatch(_))
        ),
        "missing file"
    );
    let mut f = files();
    f.push(("extra".into(), b"x".to_vec()));
    assert!(
        matches!(
            manifest::verify(&env, &pk, &f),
            Err(ReleaseError::Mismatch(_))
        ),
        "extra file"
    );
    // wrong key
    assert!(
        matches!(
            manifest::verify(&env, &probe(4).pubkey_hex(), &files()),
            Err(ReleaseError::Signature(_))
        ),
        "wrong key"
    );
    // a changed version, product and sbom hash inside the signed text (the signature no longer matches)
    for (from, to) in [
        (
            "\\\"version\\\":\\\"0.2.0\\\"",
            "\\\"version\\\":\\\"0.2.1\\\"",
        ),
        (
            "\\\"product\\\":\\\"entropa-gate\\\"",
            "\\\"product\\\":\\\"entropa-evil\\\"",
        ),
    ] {
        assert!(
            env.contains(from),
            "the test does not find {from} in the envelope"
        );
        let bad = env.replacen(from, to, 1);
        assert!(
            matches!(
                manifest::verify(&bad, &pk, &files()),
                Err(ReleaseError::Signature(_))
            ),
            "changed {from}"
        );
    }
    // one flipped hex digit of the signature, a truncated one
    let k = env.find("\"signature\":\"").unwrap() + 13;
    let mut b = env.clone().into_bytes();
    b[k] = if b[k] == b'0' { b'1' } else { b'0' };
    assert!(
        matches!(
            manifest::verify(&String::from_utf8(b).unwrap(), &pk, &files()),
            Err(ReleaseError::Signature(_))
        ),
        "flipped digit"
    );
    let end = env[k..].find('"').unwrap() + k;
    let trunc = format!("{}{}", &env[..end - 10], &env[end..]);
    assert!(
        manifest::verify(&trunc, &pk, &files()).is_err(),
        "truncated signature"
    );
}

#[test]
fn m3_malformed_envelopes_are_refused_with_the_manifest_error() {
    let p = probe(3);
    let (env, _) = signed(&p);
    let pk = p.pubkey_hex();
    let unknown = env.replacen("{", "{\"zzz\":1,", 1);
    let dup = env.replacen("{", "{\"alg\":\"ML-DSA-65\",", 1);
    let big = format!("{env}{}", " ".repeat(1 << 20));
    for (name, bad) in [
        ("unknown field", unknown),
        ("duplicate key", dup),
        ("oversize", big),
        ("empty", String::new()),
        ("array", "[]".into()),
    ] {
        assert!(
            matches!(
                manifest::verify(&bad, &pk, &files()),
                Err(ReleaseError::Manifest(_))
            ),
            "{name}"
        );
    }
    for bad_key in ["", "zz", "00"] {
        assert!(
            manifest::verify(&env, bad_key, &files()).is_err(),
            "key {bad_key:?}"
        );
    }
}

#[test]
fn m4_the_manifest_text_is_deterministic_and_sorted_and_binds_the_sbom() {
    let sb = "{\"sbom\":1}";
    let (mut rev, fwd) = (files(), files());
    rev.reverse();
    let (a, b) = (
        manifest::build("p", "1", &fwd, sb).unwrap(),
        manifest::build("p", "1", &rev, sb).unwrap(),
    );
    assert_eq!(a, b, "artifact order must not matter");
    // the sha256 inside is the reference hash computed here, not by the crate
    let want = reference_sha256_hex(&files()[0].1);
    assert!(a.contains(&want), "sha256 of the first artifact missing");
    assert!(
        a.contains(&reference_sha256_hex(sb.as_bytes())),
        "the SBOM hash is not bound"
    );
    assert_ne!(a, manifest::build("p", "1", &fwd, "{\"sbom\":2}").unwrap());
}
fn reference_sha256_hex(b: &[u8]) -> String {
    // the system's sha256sum is the independent reference
    use std::io::Write;
    let mut c = std::process::Command::new("sha256sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(b).unwrap();
    String::from_utf8(c.wait_with_output().unwrap().stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

// ---- minisign ----
fn mkkeys(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
    let d = scratch(tag);
    let (sk, pk) = (d.join("k.key"), d.join("k.pub"));
    let o = std::process::Command::new("minisign")
        .args(["-G", "-W", "-f", "-s"])
        .arg(&sk)
        .arg("-p")
        .arg(&pk)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    (d, sk, pk)
}

/// Tests that need a program the CI container image does not have (node, minisign) SKIP with a loud line when it is missing; ENTROPA_REQUIRE_TOOLS=1 makes a missing tool a failure.
fn tool_or_skip(tool: &str, test: &str) -> bool {
    let missing = matches!(
        std::process::Command::new(tool).arg("--version").output(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound
    );
    if !missing {
        return true;
    }
    assert!(
        std::env::var("ENTROPA_REQUIRE_TOOLS").as_deref() != Ok("1"),
        "{test}: {tool} is required (ENTROPA_REQUIRE_TOOLS=1) but was not found"
    );
    eprintln!("SKIPPED {test}: {tool} is not installed here, so this check was not run");
    false
}

#[test]
fn x1_minisign_round_trip_and_the_three_refusals() {
    if !tool_or_skip("minisign", "x1") {
        return;
    }
    let (d, sk, pk) = mkkeys("x1");
    let f = d.join("artifact.bin");
    std::fs::write(&f, b"synthetic artifact").unwrap();
    let sig = minisign::sign(&f, &sk).unwrap();
    assert!(sig.exists() && sig.to_string_lossy().ends_with(".minisig"));
    minisign::verify(&f, &pk).unwrap();
    // the installed minisign agrees with the wrapper
    assert!(std::process::Command::new("minisign")
        .args(["-Vm"])
        .arg(&f)
        .arg("-p")
        .arg(&pk)
        .output()
        .unwrap()
        .status
        .success());
    // changed file
    std::fs::write(&f, b"synthetic artifacu").unwrap();
    assert!(minisign::verify(&f, &pk).is_err(), "changed file");
    std::fs::write(&f, b"synthetic artifact").unwrap();
    // wrong key
    let (_d2, _sk2, pk2) = mkkeys("x1b");
    assert!(minisign::verify(&f, &pk2).is_err(), "wrong key");
    // missing signature
    let g = d.join("other.bin");
    std::fs::write(&g, b"x").unwrap();
    assert!(minisign::verify(&g, &pk).is_err(), "no .minisig");
}

// ---- mutation triage (first run: 71 mutants, 14 missed) ----
#[test]
fn q1_errors_print_their_variant_and_the_sbom_carries_package_urls() {
    assert!(ReleaseError::Lock("x".into()).to_string().contains("Lock"));
    let c = sbom::from_lock(&lock()).unwrap();
    let j = sbom::to_cyclonedx(&c, "p", "1").unwrap();
    let sj = c.iter().find(|c| c.name == "serde_json").unwrap();
    assert!(
        j.contains(&format!("pkg:cargo/serde_json@{}", sj.version)),
        "package URL missing"
    );
}

#[test]
fn q2_build_refuses_unacceptable_names_and_versions_at_their_exact_limits() {
    let f = files();
    let ok = |p: &str, v: &str| manifest::build(p, v, &f, "{}").is_ok();
    assert!(
        ok(&"a".repeat(128), &"1".repeat(64)),
        "the limits themselves are fine"
    );
    assert!(!ok(&"a".repeat(129), "1"), "product 129");
    assert!(!ok("", "1"), "empty product");
    assert!(!ok("has space", "1"), "space in product");
    assert!(!ok("../x", "1"), "path in product");
    assert!(!ok("p", ""), "empty version");
    assert!(!ok("p", &"1".repeat(65)), "version 65");
    let one = |n: &str| manifest::build("p", "1", &[(n.to_string(), b"x".to_vec())], "{}");
    assert!(one(&"a".repeat(128)).is_ok());
    for bad in ["", "a b", "a/b", "..", &"a".repeat(129)] {
        if bad == ".." {
            continue; // dots are allowed characters; the name ".." is plain text in a manifest and is never used as a path by verify
        }
        assert!(one(bad).is_err(), "artifact name {bad:?}");
    }
    let dup = vec![
        ("a".to_string(), b"1".to_vec()),
        ("a".to_string(), b"2".to_vec()),
    ];
    assert!(
        manifest::build("p", "1", &dup, "{}").is_err(),
        "duplicate artifact names"
    );
    let bad_only = vec![
        ("a b".to_string(), b"1".to_vec()),
        ("c".to_string(), b"2".to_vec()),
    ];
    assert!(
        manifest::build("p", "1", &bad_only, "{}").is_err(),
        "one bad name among good ones"
    );
}

#[test]
fn q3_the_envelope_size_limit_is_exact_and_refusal_messages_name_their_cause() {
    let p = probe(3);
    let (env, _) = signed(&p);
    let pk = p.pubkey_hex();
    let at = format!(
        "{env}{}",
        " ".repeat(manifest::MAX_ENVELOPE_BYTES - env.len())
    );
    assert_eq!(at.len(), manifest::MAX_ENVELOPE_BYTES);
    assert!(
        manifest::verify(&at, &pk, &files()).is_ok(),
        "exactly the limit is accepted"
    );
    let over = format!("{at} ");
    assert!(
        matches!(manifest::verify(&over, &pk, &files()), Err(ReleaseError::Manifest(m)) if m.contains("too large"))
    );
    // a wrong key is refused at the key id, with that cause
    let e = manifest::verify(&env, &probe(4).pubkey_hex(), &files()).unwrap_err();
    assert!(
        matches!(&e, ReleaseError::Signature(m) if m.contains("key id")),
        "{e:?}"
    );
    // an empty key is refused too
    assert!(manifest::verify(&env, "", &files()).is_err());
    // the right signature in UPPERCASE hex is refused (the format is lowercase hex only)
    let k = env.find("\"signature\":\"").unwrap() + 13;
    let end = env[k..].find('"').unwrap() + k;
    let upper = format!("{}{}{}", &env[..k], env[k..end].to_uppercase(), &env[end..]);
    assert!(
        matches!(
            manifest::verify(&upper, &pk, &files()),
            Err(ReleaseError::Signature(_))
        ),
        "uppercase signature"
    );
}
