//! LS2 follow-up (the reviewer's decision 2026-11-16): an OPTIONAL `ledger.tar` in the bundle so a reader can run the verify command on the ledger the page describes. The tar holds the mock marker, the
//! records and the checkpoints and NOTHING else (never a key file). Expected values: the system `tar` lists and extracts it; `entropa_nodecore::verify_ledger` verifies the extracted copy.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::Probe;
use entropa_ledger::Kind;
use entropa_mockview::{generate, Config, LABEL};
use std::path::{Path, PathBuf};

const SEED_BYTE: u8 = 9;
fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ls2tar-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}
fn mock(tag: &str, n: u32) -> (PathBuf, String) {
    let d = scratch(tag);
    std::fs::create_dir_all(d.join("evidence-ledger")).unwrap();
    let p = Probe::from_signing_key_hex(&format!("{SEED_BYTE:02x}").repeat(32)).unwrap();
    let pk = p.pubkey_hex();
    for i in 0..n {
        let req = format!(
            r#"{{"kind":"evidence.policy","label":"policy_verdict","decision":"allow","reason":"within_limits","control":"hitrust_01_access_control","total":1,"passed":1,"flagged":0,"detail":"d{i}","run_id":"{i:064x}","ts":{}}}"#,
            1_800_000_000 + i
        );
        let f = entropa_nodecore::evidence_event(&req, &pk).unwrap();
        entropa_nodecore::append(&d, "evidence-ledger", &p, &f).unwrap();
    }
    std::fs::write(
        d.join("MOCK-DATA.txt"),
        format!("{LABEL}\nsynthetic traffic; throwaway key; not production\n"),
    )
    .unwrap();
    (d, pk)
}
fn with_tar() -> Config {
    Config {
        include_ledger: true,
        ..Config::default()
    }
}
fn tar_list(tar: &Path) -> Vec<String> {
    let o = std::process::Command::new("tar")
        .arg("-tf")
        .arg(tar)
        .output()
        .unwrap();
    assert!(
        o.status.success(),
        "tar -tf failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let mut v: Vec<String> = String::from_utf8(o.stdout)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    v.sort();
    v
}

#[test]
fn t1_the_tar_holds_exactly_the_marker_records_and_checkpoints_and_the_copy_verifies() {
    let (d, pk) = mock("t1", 30);
    let out = scratch("t1-out");
    generate(&d, &pk, &out, &with_tar()).unwrap();
    let tar = out.join("ledger.tar");
    assert!(tar.exists(), "no ledger.tar");
    assert_eq!(
        tar_list(&tar),
        [
            "MOCK-DATA.txt",
            "evidence-ledger/checkpoints.log",
            "evidence-ledger/records.log"
        ]
    );
    let x = scratch("t1-x");
    let o = std::process::Command::new("tar")
        .arg("-xf")
        .arg(&tar)
        .arg("-C")
        .arg(&x)
        .output()
        .unwrap();
    assert!(o.status.success());
    for f in [
        "MOCK-DATA.txt",
        "evidence-ledger/records.log",
        "evidence-ledger/checkpoints.log",
    ] {
        assert_eq!(
            std::fs::read(x.join(f)).unwrap(),
            std::fs::read(d.join(f)).unwrap(),
            "{f} differs"
        );
    }
    assert_eq!(
        entropa_nodecore::verify_ledger(&x, "evidence-ledger", Kind::is_evidence, &pk).unwrap(),
        "OK records=30 checkpoints=30"
    );
}

#[test]
fn t2_a_key_file_and_any_other_file_in_the_ledger_directory_never_enter_the_tar() {
    let (d, pk) = mock("t2", 5);
    let seed = format!("{SEED_BYTE:02x}").repeat(32);
    std::fs::write(d.join("platinum.key"), format!("{seed}\n")).unwrap();
    std::fs::write(d.join("run.json"), "{}").unwrap();
    std::fs::write(d.join("notes-secret.txt"), "decoy").unwrap();
    std::fs::write(d.join("evidence-ledger").join("stray.bin"), "decoy2").unwrap();
    let out = scratch("t2-out");
    generate(&d, &pk, &out, &with_tar()).unwrap();
    assert_eq!(
        tar_list(&out.join("ledger.tar")),
        [
            "MOCK-DATA.txt",
            "evidence-ledger/checkpoints.log",
            "evidence-ledger/records.log"
        ]
    );
    let bytes = std::fs::read(out.join("ledger.tar")).unwrap();
    let text = String::from_utf8_lossy(&bytes).to_string();
    for bad in [seed.as_str(), "platinum.key", "decoy"] {
        assert!(!text.contains(bad), "the tar contains {bad}");
    }
}

#[test]
fn t3_meta_describes_the_tar_and_without_the_option_there_is_none() {
    let (d, pk) = mock("t3", 12);
    let (a, b) = (scratch("t3-a"), scratch("t3-b"));
    generate(&d, &pk, &a, &with_tar()).unwrap();
    generate(&d, &pk, &b, &Config::default()).unwrap();
    assert!(!b.join("ledger.tar").exists());
    let mb: serde_json::Value =
        serde_json::from_slice(&std::fs::read(b.join("data/meta.json")).unwrap()).unwrap();
    assert!(
        mb.get("ledger_tar").is_none(),
        "meta mentions a tar that is not there"
    );
    let ma: serde_json::Value =
        serde_json::from_slice(&std::fs::read(a.join("data/meta.json")).unwrap()).unwrap();
    let bytes = std::fs::read(a.join("ledger.tar")).unwrap();
    assert_eq!(ma["ledger_tar"]["file"], "ledger.tar");
    assert_eq!(ma["ledger_tar"]["bytes"], bytes.len());
    assert_eq!(
        ma["ledger_tar"]["blake3"],
        blake3::hash(&bytes).to_hex().to_string()
    );
    assert!(ma["ledger_tar"]["how_to"]
        .as_str()
        .unwrap()
        .contains("entropa-mockview verify"));
}

#[test]
fn t4_the_tar_is_deterministic_and_a_refusal_writes_no_tar() {
    let (d, pk) = mock("t4", 8);
    let (a, b) = (scratch("t4-a"), scratch("t4-b"));
    generate(&d, &pk, &a, &with_tar()).unwrap();
    generate(&d, &pk, &b, &with_tar()).unwrap();
    assert_eq!(
        std::fs::read(a.join("ledger.tar")).unwrap(),
        std::fs::read(b.join("ledger.tar")).unwrap()
    );
    let r = scratch("t4-refused");
    let other = Probe::from_signing_key_hex(&format!("{:02x}", 1u8).repeat(32))
        .unwrap()
        .pubkey_hex();
    assert!(generate(&d, &other, &r, &with_tar()).is_err());
    assert!(
        !r.join("ledger.tar").exists() && std::fs::read_dir(&r).unwrap().next().is_none(),
        "files written on refusal"
    );
}

#[test]
fn t5_the_page_links_the_tar_with_textcontent_only_and_the_csp_still_holds() {
    let (d, pk) = mock("t5", 6);
    let out = scratch("t5-out");
    generate(&d, &pk, &out, &with_tar()).unwrap();
    let js = std::fs::read_to_string(out.join("app.js")).unwrap();
    assert!(
        js.contains("ledger_tar"),
        "app.js does not show the download"
    );
    for bad in ["innerHTML", "eval(", "document.write"] {
        assert!(!js.contains(bad));
    }
    let h = r#"
const fs = require('fs'); const path = process.argv[2];
function el(tag){ return {tag, children:[], textContent:'', attrs:{}, setAttribute(k,v){this.attrs[k]=v;}, appendChild(c){this.children.push(c); return c;}, addEventListener(){}, set className(v){this.attrs.class=v;}, get className(){return this.attrs.class||'';}}; }
const doc = { createElement: el, getElementById: (id)=> (doc._ids[id] ||= el('div')), _ids:{} };
global.document = doc; global.window = { location: { search: '' } };
global.fetch = (u) => Promise.resolve({ ok:true, json: () => Promise.resolve(JSON.parse(fs.readFileSync(path + '/' + u, 'utf8'))) });
require(path + '/app.js').start(doc, fetch, '').then(() => {
  const links = []; (function walk(n){ if(n.tag==='a' && n.attrs.href) links.push(n.attrs.href); (n.children||[]).forEach(walk); })(doc._ids['verify'] || {children:[]});
  console.log(JSON.stringify(links));
});
"#;
    std::fs::write(out.join("h.js"), h).unwrap();
    let o = std::process::Command::new("node")
        .arg(out.join("h.js"))
        .arg(&out)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let links: Vec<String> =
        serde_json::from_str(String::from_utf8_lossy(&o.stdout).trim()).unwrap();
    assert_eq!(
        links,
        ["ledger.tar"],
        "the verify block must link exactly the tar"
    );
}

#[test]
fn t6_the_command_line_flag_writes_the_tar_and_nothing_else_changes() {
    let (d, pk) = mock("t6", 7);
    let bin = env!("CARGO_BIN_EXE_entropa-mockview");
    let (a, b) = (scratch("t6-a"), scratch("t6-b"));
    let o = std::process::Command::new(bin)
        .arg(&d)
        .arg(&pk)
        .arg(&a)
        .arg("--with-ledger")
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(a.join("ledger.tar").exists());
    let o = std::process::Command::new(bin)
        .arg(&d)
        .arg(&pk)
        .arg(&b)
        .output()
        .unwrap();
    assert!(o.status.success());
    assert!(!b.join("ledger.tar").exists(), "the tar must be opt-in");
}

// ---- FINDING (found by running the real 10k tar): `entropa-platinum verify-evidence DIR` needs the node's PRIVATE key file to learn the public key, so a reader holding only the tar could not run the command the page showed. The reader-side command is now `entropa-mockview verify DIR PUBLIC_KEY_HEX`.
#[test]
fn v1_the_reader_command_verifies_the_extracted_tar_with_only_the_public_key() {
    let (d, pk) = mock("v1", 14);
    let out = scratch("v1-out");
    generate(&d, &pk, &out, &with_tar()).unwrap();
    let x = scratch("v1-x");
    assert!(std::process::Command::new("tar")
        .arg("-xf")
        .arg(out.join("ledger.tar"))
        .arg("-C")
        .arg(&x)
        .status()
        .unwrap()
        .success());
    assert!(
        !x.join("platinum.key").exists(),
        "the extracted directory has no key file: the command must not need one"
    );
    let bin = env!("CARGO_BIN_EXE_entropa-mockview");
    let o = std::process::Command::new(bin)
        .args(["verify"])
        .arg(&x)
        .arg(&pk)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(
        String::from_utf8_lossy(&o.stdout).trim(),
        "OK records=14 checkpoints=14"
    );
}

#[test]
fn v2_the_reader_command_refuses_a_wrong_key_a_changed_byte_and_bad_usage() {
    let (d, pk) = mock("v2", 6);
    let bin = env!("CARGO_BIN_EXE_entropa-mockview");
    let run = |a: &[&str]| std::process::Command::new(bin).args(a).output().unwrap();
    let other = Probe::from_signing_key_hex(&format!("{:02x}", 2u8).repeat(32))
        .unwrap()
        .pubkey_hex();
    let o = run(&["verify", d.to_str().unwrap(), &other]);
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stderr).contains("refused"));
    let c = scratch("v2-copy");
    std::fs::create_dir_all(c.join("evidence-ledger")).unwrap();
    for f in ["records.log", "checkpoints.log"] {
        std::fs::copy(
            d.join("evidence-ledger").join(f),
            c.join("evidence-ledger").join(f),
        )
        .unwrap();
    }
    let p = c.join("evidence-ledger/records.log");
    let mut b = std::fs::read(&p).unwrap();
    b[50] = if b[50] == b'0' { b'1' } else { b'0' };
    std::fs::write(&p, b).unwrap();
    assert_eq!(
        run(&["verify", c.to_str().unwrap(), &pk]).status.code(),
        Some(1)
    );
    assert_eq!(run(&["verify", d.to_str().unwrap()]).status.code(), Some(2));
    assert_eq!(run(&["verify"]).status.code(), Some(2));
    assert_eq!(
        run(&["verify", d.to_str().unwrap(), &pk, "extra"])
            .status
            .code(),
        Some(2)
    );
    // the right key on the untouched ledger still passes (the refusals are not vacuous)
    assert_eq!(
        run(&["verify", d.to_str().unwrap(), &pk]).status.code(),
        Some(0)
    );
}

#[test]
fn v3_the_reader_command_works_on_read_only_media_and_refuses_a_path_with_no_ledger() {
    // found by running the command in a container with read-only mounts: verification must not need to write (a lock file) and must not say OK for a path that holds no ledger
    let (d, pk) = mock("v3", 9);
    let out = scratch("v3-out");
    generate(&d, &pk, &out, &with_tar()).unwrap();
    let x = scratch("v3-x");
    assert!(std::process::Command::new("tar")
        .arg("-xf")
        .arg(out.join("ledger.tar"))
        .arg("-C")
        .arg(&x)
        .status()
        .unwrap()
        .success());
    for e in [
        "evidence-ledger/records.log",
        "evidence-ledger/checkpoints.log",
        "MOCK-DATA.txt",
    ] {
        std::fs::set_permissions(
            x.join(e),
            std::os::unix::fs::PermissionsExt::from_mode(0o444),
        )
        .unwrap();
    }
    for e in ["evidence-ledger", ""] {
        std::fs::set_permissions(
            x.join(e),
            std::os::unix::fs::PermissionsExt::from_mode(0o555),
        )
        .unwrap();
    }
    let bin = env!("CARGO_BIN_EXE_entropa-mockview");
    let o = std::process::Command::new(bin)
        .arg("verify")
        .arg(&x)
        .arg(&pk)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(
        String::from_utf8_lossy(&o.stdout).trim(),
        "OK records=9 checkpoints=9"
    );
    assert!(!x.join("evidence-ledger/.lock").exists());
    // a path with no ledger in it: refused, not "OK records=0"
    let empty = scratch("v3-empty");
    let o = std::process::Command::new(bin)
        .arg("verify")
        .arg(&empty)
        .arg(&pk)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("no ledger"),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(
        !empty.join("evidence-ledger").exists(),
        "verify created a directory"
    );
}
