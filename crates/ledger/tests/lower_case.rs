//! INS slice 4 red tests (round-1 finding 2): the documented layout is lower-case hex. The raw reader and the store refuse upper-case hex in records.log and in the hex fields of checkpoints.log
//! (the anchor decoder already does). No writer emits upper case. Synthetic data only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::transparency_log::TransparencyLog;
use entropa_core::Probe;
use entropa_ledger::{read_raw, FileStore, LedgerError, LedgerStore};
use std::path::{Path, PathBuf};

fn made(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("lower-case-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    let p = Probe::from_signing_key_hex(&hex::encode([8u8; 32])).unwrap();
    {
        let mut s = FileStore::open(&d).unwrap();
        let mut log = TransparencyLog::new();
        for i in 0..3u8 {
            let rec = vec![0xAB, 0xCD, 0xEF, i, 0x0A, 0xFF];
            s.append(&rec).unwrap();
            log.append(&rec);
            s.put_checkpoint(&log.checkpoint(&p, 10 + u64::from(i)))
                .unwrap();
        }
    }
    d
}
fn upper_records(d: &Path) {
    let t = std::fs::read_to_string(d.join("records.log")).unwrap();
    assert!(t.contains("abcdef"), "the honest file is lower case: {t}");
    std::fs::write(d.join("records.log"), t.to_uppercase()).unwrap();
}
fn upper_in_checkpoints(d: &Path, field: &str) {
    let t = std::fs::read_to_string(d.join("checkpoints.log")).unwrap();
    let out: Vec<String> = t
        .lines()
        .map(|l| {
            let key = format!("\"{field}\":\"");
            let i = l.find(&key).unwrap() + key.len();
            let j = l[i..].find('"').unwrap() + i;
            format!("{}{}{}", &l[..i], l[i..j].to_uppercase(), &l[j..])
        })
        .collect();
    std::fs::write(d.join("checkpoints.log"), out.join("\n") + "\n").unwrap();
}

#[test]
fn u1_the_honest_files_are_read_and_upper_case_records_are_refused_by_the_raw_reader() {
    let d = made("u1");
    assert_eq!(read_raw(&d).unwrap().leaves.len(), 3);
    upper_records(&d);
    match read_raw(&d) {
        Err(LedgerError::Corrupt(m)) => assert!(m.contains("lower-case"), "{m}"),
        other => panic!("{other:?}"),
    }
}
#[test]
fn u2_upper_case_in_any_hex_field_of_a_checkpoint_is_refused_by_the_raw_reader() {
    for field in ["root", "signature", "proposer_pubkey"] {
        let d = made(&format!("u2-{field}"));
        upper_in_checkpoints(&d, field);
        match read_raw(&d) {
            Err(LedgerError::Corrupt(m)) => assert!(m.contains("lower-case"), "{field}: {m}"),
            other => panic!("{field}: {other:?}"),
        }
    }
}
#[test]
fn u3_the_store_refuses_upper_case_too_so_verify_and_check_agree() {
    let d = made("u3");
    assert!(FileStore::open_read_only(&d).is_ok());
    upper_records(&d);
    assert!(
        FileStore::open_read_only(&d).is_err(),
        "records.log in upper case"
    );
    let d2 = made("u3b");
    upper_in_checkpoints(&d2, "root");
    assert!(
        FileStore::open_read_only(&d2).is_err(),
        "checkpoints.log root in upper case"
    );
}
