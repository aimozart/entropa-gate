//! LEDGER-STORE-VERIFY pins (a stage record (not published)): the exact observable results of `put_checkpoint` and of `FileStore::open` on every kind of damage, as a transcript whose sha256
//! was produced by the code BEFORE the change and is pinned here; the same transcript must come out after. Checkpoints are built from `entropa_core::merkle` (independent of the store).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::merkle::{leaf_hash, root};
use entropa_core::transparency_log::Checkpoint;
use entropa_ledger::{FileStore, LedgerStore};
use std::fmt::Write as _;

fn recs(n: usize) -> Vec<Vec<u8>> {
    (0..n).map(|i| format!("rec-{i}").into_bytes()).collect()
}
/// A checkpoint of `size` records with the independent root (the signature is not checked by the store's `check_checkpoint`).
fn cp(r: &[Vec<u8>], size: usize, corrupt: bool) -> Checkpoint {
    let leaves: Vec<_> = r[..size.min(r.len())]
        .iter()
        .map(|x| leaf_hash(x))
        .collect();
    let mut root_bytes = if size == 0 {
        leaf_hash(&[])
    } else {
        root(&leaves).unwrap_or([0; 32])
    };
    if corrupt {
        root_bytes[0] ^= 1;
    }
    Checkpoint {
        root: root_bytes,
        size,
        timestamp: 1_800_000_000 + size as u64,
        proposer_pubkey: "00".into(),
        signature: "00".into(),
    }
}

fn transcript() -> String {
    let mut t = String::new();
    for n in [
        1usize, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 31, 32, 33, 64, 65,
    ] {
        let r = recs(n);
        // every size alone, valid and corrupted, in a fresh store
        for size in 0..=n + 2 {
            for corrupt in [false, true] {
                let mut s = entropa_ledger::MemoryStore::default();
                for x in &r {
                    s.append(x).unwrap();
                }
                let res = s.put_checkpoint(&cp(&r, size, corrupt));
                writeln!(t, "n={n} size={size} corrupt={corrupt} -> {res:?}").unwrap();
            }
        }
        // sequences: ascending, then older, then same size with a wrong root
        let mut s = entropa_ledger::MemoryStore::default();
        for x in &r {
            s.append(x).unwrap();
        }
        for (size, corrupt) in [
            (n / 2, false),
            (n, false),
            (n / 2, false),
            (n, true),
            (n, false),
            (n + 1, false),
        ] {
            let res = s.put_checkpoint(&cp(&r, size, corrupt));
            writeln!(t, "n={n} seq size={size} corrupt={corrupt} -> {res:?}").unwrap();
        }
        writeln!(t, "n={n} stored checkpoints = {}", s.checkpoints().len()).unwrap();
    }
    t
}

fn file_case(tag: &str, damage: &dyn Fn(&std::path::Path)) -> String {
    let d = std::env::temp_dir().join(format!("pins-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let r = recs(9);
    {
        let mut s = FileStore::open(&d).unwrap();
        for (i, x) in r.iter().enumerate() {
            s.append(x).unwrap();
            if i % 3 == 2 {
                s.put_checkpoint(&cp(&r, i + 1, false)).unwrap();
            }
        }
    }
    damage(&d);
    match FileStore::open(&d) {
        Ok(s) => format!(
            "{tag}: opened records={} checkpoints={}",
            s.len(),
            s.checkpoints().len()
        ),
        Err(e) => format!("{tag}: {e:?}"),
    }
}

fn file_transcript() -> String {
    let rd = |d: &std::path::Path, f: &str| std::fs::read_to_string(d.join(f)).unwrap();
    let mut t = String::new();
    t += &file_case("clean", &|_| {});
    t += "\n";
    t += &file_case("record-flipped", &|d| {
        let mut lines: Vec<String> = rd(d, "records.log").lines().map(String::from).collect();
        let c = lines[1].pop().unwrap();
        lines[1].push(if c == '0' { '1' } else { '0' });
        std::fs::write(d.join("records.log"), lines.join("\n") + "\n").unwrap();
    });
    t += "\n";
    t += &file_case("checkpoint-root-flipped", &|d| {
        let mut lines: Vec<String> = rd(d, "checkpoints.log").lines().map(String::from).collect();
        let v = lines[0].replacen("\"root\":\"", "\"root\":\"ff", 1);
        lines[0] = v;
        std::fs::write(d.join("checkpoints.log"), lines.join("\n") + "\n").unwrap();
    });
    t += "\n";
    t += &file_case("checkpoint-root-digit-flipped", &|d| {
        let mut lines: Vec<String> = rd(d, "checkpoints.log").lines().map(String::from).collect();
        let i = lines[1].find("\"root\":\"").unwrap() + 8;
        let c = lines[1].as_bytes()[i];
        let n = if c == b'0' { '1' } else { '0' };
        lines[1].replace_range(i..i + 1, &n.to_string());
        std::fs::write(d.join("checkpoints.log"), lines.join("\n") + "\n").unwrap();
    });
    t += "\n";
    t += &file_case("checkpoint-size-too-large", &|d| {
        let mut lines: Vec<String> = rd(d, "checkpoints.log").lines().map(String::from).collect();
        lines[2] = lines[2].replace("\"size\":9", "\"size\":99");
        std::fs::write(d.join("checkpoints.log"), lines.join("\n") + "\n").unwrap();
    });
    t += "\n";
    t += &file_case("checkpoints-out-of-order", &|d| {
        let mut lines: Vec<String> = rd(d, "checkpoints.log").lines().map(String::from).collect();
        lines.swap(0, 2);
        std::fs::write(d.join("checkpoints.log"), lines.join("\n") + "\n").unwrap();
    });
    t += "\n";
    t += &file_case("partial-last-line", &|d| {
        let mut s = rd(d, "records.log");
        s.push_str("abcd");
        std::fs::write(d.join("records.log"), s).unwrap();
    });
    t += "\n";
    t += &file_case("record-not-hex", &|d| {
        let mut lines: Vec<String> = rd(d, "records.log").lines().map(String::from).collect();
        lines[0] = "zz".into();
        std::fs::write(d.join("records.log"), lines.join("\n") + "\n").unwrap();
    });
    t + "\n"
}

#[test]
fn p1_put_checkpoint_transcript_is_pinned() {
    let t = transcript();
    let sha = blake3::hash(t.as_bytes()).to_hex().to_string();
    eprintln!("PIN_PUT {sha} ({} lines)", t.lines().count());
    assert_eq!(sha, PIN_PUT, "put_checkpoint changed observable behaviour");
}

#[test]
fn p2_file_store_open_transcript_is_pinned() {
    let t = file_transcript();
    let sha = blake3::hash(t.as_bytes()).to_hex().to_string();
    eprintln!("PIN_OPEN {sha}\n{t}");
    assert_eq!(
        sha, PIN_OPEN,
        "FileStore::open changed observable behaviour"
    );
}

const PIN_PUT: &str = "c7e6c28924b31ec3cb800487c56869dacbd150c4d8af6d38b44cea78b05f654a";
const PIN_OPEN: &str = "7bd57114c190febdb774a3a421e30b7d389c60f6aac244dfe98b3d5550585d01";
