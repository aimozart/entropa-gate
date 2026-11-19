//! INS2 slice 2b: `entropa-gate check --dir D [--anchor FILE]... [--require-anchor]` and `entropa-gate anchor export --dir D --out FILE [--signed]`.
//! `check` prints `verdict: <closed code>[ N]` and a counts line; it never prints record content. Exit codes: 0 ok_*, 1 any alarm, 2 usage, 3 an input file was refused (not a verdict).
use crate::keys;
use crate::opts::{self, Spec};
use entropa_core::anchor::{assess, Anchor, AnyCheckpoint, Verdict};
use entropa_core::transparency_log::decode_record;
use entropa_ledger::{read_raw_with, verify_event, Kind, LedgerError};
use entropa_witness::anchor_file::{
    decode_anchor_for, encode_anchor, AnchorFileError, MAX_ANCHOR_BYTES,
};
use entropa_witness::log_id_for;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const USAGE_CHECK: &str =
    "usage: entropa-gate check --dir DIR [--anchor FILE]... [--require-anchor]";
const USAGE_ANCHOR: &str = "usage: entropa-gate anchor export --dir DIR --out FILE [--signed]";

enum Loaded {
    /// Anchors that decoded and name this log.
    Anchors(Vec<Anchor>),
    /// The first refusal, as a fixed sentence.
    Refused(&'static str),
}

fn load_anchors(files: &[String], pubkey: &str) -> Loaded {
    let mut anchors = Vec::new();
    for f in files {
        let mut text = String::new();
        let read = std::fs::File::open(f).and_then(|h| {
            h.take(MAX_ANCHOR_BYTES as u64 + 1)
                .read_to_string(&mut text)
        });
        if read.is_err() {
            return Loaded::Refused("refused: an anchor file cannot be read");
        }
        match decode_anchor_for(&text, pubkey) {
            Ok(a) => anchors.push(a),
            Err(AnchorFileError::Limit(_)) => {
                return Loaded::Refused("refused: an anchor file is larger than 32 KiB")
            }
            Err(AnchorFileError::WrongLog) => {
                return Loaded::Refused("refused: an anchor file is for another log")
            }
            Err(AnchorFileError::Invalid(_)) => {
                return Loaded::Refused("refused: an anchor file is not a valid anchor")
            }
        }
    }
    Loaded::Anchors(anchors)
}

/// The result of reading and judging one ledger.
struct Judged {
    verdict: Verdict,
    records: usize,
    checkpoints: Vec<AnyCheckpoint>,
}

/// Read the ledger of `dir` raw, judge it against `anchors`, and (only when the checkpoints and records agree) check each record's own signature and kind.
fn judge(
    dir: &Path,
    pubkey: &str,
    anchors: &[Anchor],
    require_anchor: bool,
) -> Result<Judged, String> {
    let mut records_ok = true;
    let raw = match read_raw_with(&dir.join("ledger"), &mut |bytes| {
        let ok = decode_record(bytes)
            .ok()
            .and_then(|(payload, label)| verify_event(&payload, pubkey).ok().map(|ev| (ev, label)))
            .is_some_and(|(ev, label)| {
                ev.fields.kind == Kind::PlatinumDecision
                    && label.as_deref() == Some(ev.fields.kind.as_str())
            });
        records_ok &= ok;
    }) {
        Ok(r) => r,
        Err(LedgerError::Corrupt(_) | LedgerError::Limit(_)) => {
            return Ok(Judged {
                verdict: Verdict::FormatError,
                records: 0,
                checkpoints: Vec::new(),
            });
        }
        Err(_) => return Err("the ledger files cannot be read".to_string()),
    };
    let mut verdict = assess(
        &raw.leaves,
        &raw.checkpoints,
        anchors,
        pubkey,
        require_anchor,
    );
    if matches!(verdict, Verdict::OkAnchored(_) | Verdict::OkUnanchored) && !records_ok {
        verdict = Verdict::SignatureInvalid;
    }
    Ok(Judged {
        verdict,
        records: raw.leaves.len(),
        checkpoints: raw.checkpoints,
    })
}

/// `v1`, `v2` or `v1+v2` (v1 first, then v2); `none` when the ledger has no checkpoint.
fn format_name(cps: &[AnyCheckpoint]) -> &'static str {
    let v1 = cps.iter().any(|c| matches!(c, AnyCheckpoint::V1(_)));
    let v2 = cps.iter().any(|c| matches!(c, AnyCheckpoint::V2(_)));
    match (v1, v2) {
        (true, true) => "v1+v2",
        (true, false) => "v1",
        (false, true) => "v2",
        (false, false) => "none",
    }
}

fn verdict_line(v: &Verdict) -> String {
    match v {
        Verdict::OkAnchored(n) => format!("verdict: {} {n}", v.code()),
        other => format!("verdict: {}", other.code()),
    }
}

fn is_ok(v: &Verdict) -> bool {
    matches!(v, Verdict::OkAnchored(_) | Verdict::OkUnanchored)
}

fn pubkey_of(dir: &Path) -> Result<String, String> {
    keys::load(dir)
        .map(|p| p.pubkey_hex())
        .map_err(|e| e.to_string())
}

fn run_check(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let usage = |err: &mut dyn Write| {
        let _ = writeln!(err, "{USAGE_CHECK}");
        2
    };
    let spec = Spec {
        once: &["--dir"],
        many: &["--anchor"],
        flags: &["--require-anchor"],
    };
    let Some(o) = opts::parse(&args[1..], &spec) else {
        return usage(err);
    };
    let Some(dir) = o.one("--dir") else {
        return usage(err);
    };
    let files: Vec<String> = o.all("--anchor").into_iter().map(String::from).collect();
    let dir = PathBuf::from(dir);
    let require = o.flag("--require-anchor");
    let pubkey = match pubkey_of(&dir) {
        Ok(k) => k,
        Err(e) => {
            let _ = writeln!(err, "{e}");
            return 1;
        }
    };
    let anchors = match load_anchors(&files, &pubkey) {
        Loaded::Anchors(a) => a,
        Loaded::Refused(why) => {
            let _ = writeln!(err, "{why}");
            return 3;
        }
    };
    let j = match judge(&dir, &pubkey, &anchors, require) {
        Ok(j) => j,
        Err(e) => {
            let _ = writeln!(err, "{e}");
            return 1;
        }
    };
    let _ = writeln!(out, "{}", verdict_line(&j.verdict));
    let _ = writeln!(
        out,
        "records={} checkpoints={} anchors={} format={}",
        j.records,
        j.checkpoints.len(),
        anchors.len(),
        format_name(&j.checkpoints)
    );
    if anchors.is_empty() && j.verdict == Verdict::OkUnanchored {
        let _ = writeln!(err, "warning: no anchor was given; nothing outside this machine was compared, so a ledger rewritten and signed again by the key holder would look the same (ok_unanchored)");
    }
    i32::from(!is_ok(&j.verdict))
}

fn run_export(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let usage = |err: &mut dyn Write| {
        let _ = writeln!(err, "{USAGE_ANCHOR}");
        2
    };
    let spec = Spec {
        once: &["--dir", "--out"],
        many: &[],
        flags: &["--signed"],
    };
    let Some(o) = opts::parse(&args[2..], &spec) else {
        return usage(err);
    };
    let (Some(dir), Some(file)) = (o.one("--dir"), o.one("--out")) else {
        return usage(err);
    };
    let signed = o.flag("--signed");
    let dir = PathBuf::from(dir);
    let pubkey = match pubkey_of(&dir) {
        Ok(k) => k,
        Err(e) => {
            let _ = writeln!(err, "{e}");
            return 1;
        }
    };
    let j = match judge(&dir, &pubkey, &[], false) {
        Ok(j) => j,
        Err(e) => {
            let _ = writeln!(err, "{e}");
            return 1;
        }
    };
    if !is_ok(&j.verdict) {
        let _ = writeln!(
            err,
            "refused: the ledger does not verify ({}); nothing was written",
            j.verdict.code()
        );
        return 1;
    }
    let Some(cp) = j.checkpoints.last() else {
        let _ = writeln!(err, "refused: the ledger has no checkpoint to export");
        return 1;
    };
    let (size, root, counter) = match cp {
        AnyCheckpoint::V1(c) => (c.size, c.root, None),
        AnyCheckpoint::V2(c) => (c.size, c.root, Some(c.counter)),
    };
    let anchor = Anchor {
        size,
        root,
        counter,
        signed: signed.then(|| cp.clone()),
    };
    let text = encode_anchor(&anchor, &log_id_for(&pubkey));
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(file)
        .and_then(|mut f| {
            f.write_all(format!("{text}\n").as_bytes())
                .and_then(|()| f.sync_all())
        });
    if written.is_err() {
        let _ = writeln!(
            err,
            "refused: the anchor file was not written (it may already exist)"
        );
        return 1;
    }
    let _ = writeln!(
        out,
        "anchor written: size={size}{}",
        counter.map(|c| format!(" counter={c}")).unwrap_or_default()
    );
    0
}

/// Run `check` or `anchor`; returns the exit code.
pub fn run(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    match (
        args.first().map(String::as_str),
        args.get(1).map(String::as_str),
    ) {
        (Some("check"), _) => run_check(args, out, err),
        (Some("anchor"), Some("export")) => run_export(args, out, err),
        _ => {
            let _ = writeln!(err, "{USAGE_ANCHOR}");
            2
        }
    }
}
