//! `entropa-standards`: seal and inspect a standards corpus. Retrieval and the MCP server are separate modules and binaries.
//!
//!   entropa-standards seal --spec SPEC.json --sources DIR --store DIR [--node DIR --platinum BIN]
//!   entropa-standards versions --store DIR
//!   entropa-standards inspect --store DIR --version V
//!   entropa-standards cites-check --citations FILE (--manifest FILE | --store DIR --version V) --repo DIR
//!   entropa-standards eval --store DIR --version V --eval-dir DIR --out DIR
//!
//! Exit codes: 0 ok, 2 bad usage or spec, 3 refused (a source or a sealed version would change), 4 a source could not be read or extracted,
//! 5 sealed but the receipt was not written.

use entropa_standards::citations;
use entropa_standards::eval;
use entropa_standards::r2eval;
use entropa_standards::r3eval;
use entropa_standards::records::{ProcessSink, RecordSink};
use entropa_standards::retrieve::Retriever;
use entropa_standards::rs1eval;
use entropa_standards::seal::{self, SealError, SealOutcome};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn pdftotext(path: &Path) -> Result<String, String> {
    let out = Command::new("pdftotext")
        .arg(path)
        .arg("-")
        .output()
        .map_err(|_| "pdftotext is not available".to_string())?;
    if !out.status.success() {
        return Err("pdftotext failed".into());
    }
    String::from_utf8(out.stdout).map_err(|_| "pdftotext output is not UTF-8".into())
}

fn usage(msg: &str) -> ExitCode {
    eprintln!("entropa-standards: {msg}\nusage: entropa-standards seal --spec SPEC --sources DIR --store DIR [--node DIR --platinum BIN] | versions --store DIR | inspect --store DIR --version V");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("seal") => {
            let (Some(spec), Some(sources), Some(store)) = (
                flag(&args, "--spec"),
                flag(&args, "--sources"),
                flag(&args, "--store"),
            ) else {
                return usage("seal needs --spec, --sources and --store");
            };
            let Ok(text) = std::fs::read_to_string(&spec) else {
                return usage("cannot read the spec file");
            };
            let spec = match seal::parse_spec(&text) {
                Ok(s) => s,
                Err(SealError::Spec(m)) => return usage(&m),
                Err(_) => return usage("bad spec"),
            };
            let sink = match (flag(&args, "--node"), flag(&args, "--platinum")) {
                (Some(n), Some(b)) => Some(ProcessSink {
                    platinum_bin: PathBuf::from(b),
                    node_dir: PathBuf::from(n),
                }),
                (None, None) => None,
                _ => return usage("--node and --platinum go together"),
            };
            let sink_ref: Option<&dyn RecordSink> = sink.as_ref().map(|s| s as &dyn RecordSink);
            match seal::seal(
                &spec,
                Path::new(&sources),
                Path::new(&store),
                &pdftotext,
                sink_ref,
            ) {
                Ok(SealOutcome::Created {
                    corpus_hash,
                    clauses,
                    sources,
                }) => {
                    println!("sealed {} with {clauses} clauses from {sources} sources; corpus_hash {corpus_hash}", spec.corpus_version);
                    ExitCode::SUCCESS
                }
                Ok(SealOutcome::AlreadySealed { corpus_hash }) => {
                    println!(
                        "{} is already sealed with the same content; corpus_hash {corpus_hash}",
                        spec.corpus_version
                    );
                    ExitCode::SUCCESS
                }
                Err(SealError::Refused(m)) => {
                    eprintln!("refused: {m}");
                    ExitCode::from(3)
                }
                Err(SealError::Source(m)) => {
                    eprintln!("source error: {m}");
                    ExitCode::from(4)
                }
                Err(SealError::Receipt(m)) => {
                    eprintln!("{m}");
                    ExitCode::from(5)
                }
                Err(e) => {
                    eprintln!("error: {e:?}");
                    ExitCode::from(4)
                }
            }
        }
        Some("versions") => {
            let Some(store) = flag(&args, "--store") else {
                return usage("versions needs --store");
            };
            for v in seal::list_versions(Path::new(&store)) {
                println!("{v}");
            }
            ExitCode::SUCCESS
        }
        Some("inspect") => {
            let (Some(store), Some(version)) = (flag(&args, "--store"), flag(&args, "--version"))
            else {
                return usage("inspect needs --store and --version");
            };
            match seal::open(Path::new(&store), &version) {
                Ok(s) => {
                    println!(
                        "version {} corpus_hash {}",
                        s.manifest.corpus_version, s.manifest.corpus_hash
                    );
                    for src in &s.manifest.sources {
                        println!(
                            "{} {} {} {} clauses={} source_sha256={}",
                            src.standard,
                            src.std_version,
                            src.tier.as_str(),
                            src.format,
                            src.clauses,
                            src.source_sha256
                        );
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e:?}");
                    ExitCode::from(4)
                }
            }
        }
        Some("cites-check") => {
            let (Some(cf), Some(repo)) = (flag(&args, "--citations"), flag(&args, "--repo")) else {
                return usage("cites-check needs --citations, --repo and --manifest or --store with --version");
            };
            let manifest_json = match (
                flag(&args, "--manifest"),
                flag(&args, "--store"),
                flag(&args, "--version"),
            ) {
                (Some(m), None, None) => match std::fs::read_to_string(&m) {
                    Ok(t) => t,
                    Err(_) => return usage("cannot read the manifest"),
                },
                (None, Some(st), Some(v)) => match seal::open(Path::new(&st), &v) {
                    Ok(s) => serde_json::to_string(&s.manifest).unwrap_or_default(),
                    Err(e) => {
                        eprintln!("error: {e:?}");
                        return ExitCode::from(4);
                    }
                },
                _ => return usage("give --manifest, or --store with --version"),
            };
            let Ok(text) = std::fs::read_to_string(&cf) else {
                return usage("cannot read the citations file");
            };
            let c = match citations::parse(&text) {
                Ok(c) => c,
                Err(e) => return usage(&e),
            };
            let lookup = match citations::manifest_lookup(&manifest_json) {
                Ok(l) => l,
                Err(e) => return usage(&e),
            };
            let mut findings = citations::check(&c, &*lookup);
            findings.extend(citations::check_subjects(&c, Path::new(&repo)));
            if findings.is_empty() {
                println!("no drift: {} register rows and {} guardrails cite {} clauses of corpus {}; every text hash matches", c.register_rows.len(), c.guardrails.len(), c.all_refs().len(), c.corpus_version);
                return ExitCode::SUCCESS;
            }
            for f in findings {
                match f {
                    citations::Finding::Drift { subject, standard, clause, cited, current } => eprintln!("drift: {subject} cites {standard} {clause} with hash {cited} but the clause now hashes to {current}"),
                    citations::Finding::Unknown { subject, standard, clause } => eprintln!("unknown: {subject} cites {standard} {clause}, which is not in the corpus version"),
                    citations::Finding::MissingSubject { subject, file } => eprintln!("missing: guardrail {subject}: file {file} does not exist"),
                    citations::Finding::MarkerMissing { subject, file } => eprintln!("marker missing: guardrail {subject}: {file} no longer holds its marker line"),
                }
            }
            ExitCode::from(3)
        }
        Some("dev-eval") => {
            let (Some(store), Some(version), Some(dir)) = (
                flag(&args, "--store"),
                flag(&args, "--version"),
                flag(&args, "--dev-dir"),
            ) else {
                return usage("dev-eval needs --store, --version and --dev-dir");
            };
            let sealed = match seal::open(Path::new(&store), &version) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: {e:?}");
                    return ExitCode::from(4);
                }
            };
            let dev = match r2eval::load_dev(Path::new(&dir)) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("refused: {e}");
                    return ExitCode::from(3);
                }
            };
            let retriever = Retriever::from_sealed(vec![sealed]);
            let (mut off, mut on) = r2eval::configs();
            if let Some(spec) = flag(&args, "--set") {
                if let Err(e) = r2eval::apply_overrides(&mut off, &spec)
                    .and_then(|()| r2eval::apply_overrides(&mut on, &spec))
                {
                    return usage(&e);
                }
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&r2eval::run_dev_with(
                    &retriever, &version, &dev, &off, &on
                ))
                .unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        Some("flag-census") => {
            let (Some(store), Some(version)) = (flag(&args, "--store"), flag(&args, "--version"))
            else {
                return usage("flag-census needs --store and --version");
            };
            let sealed = match seal::open(Path::new(&store), &version) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: {e:?}");
                    return ExitCode::from(4);
                }
            };
            let n = sealed.clauses.len();
            let retriever = Retriever::from_sealed(vec![sealed]);
            let rows: Vec<serde_json::Value> = retriever
                .flag_census(Some(&version))
                .into_iter()
                .map(|(s, i, f)| serde_json::json!({"standard": s, "id": i, "flags": f}))
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({"clauses": n, "flagged": rows.len(), "rows": rows})
                )
                .unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        Some("dev3-explain") => {
            let (Some(dir), Some(case)) = (flag(&args, "--dev-dir"), flag(&args, "--case")) else {
                return usage("dev3-explain needs --dev-dir and --case");
            };
            let Ok(d3) = r3eval::load_dev3(Path::new(&dir)) else {
                eprintln!("refused: the DEV3 files do not verify");
                return ExitCode::from(3);
            };
            let (mut off, _) = r2eval::configs();
            if let Some(spec) = flag(&args, "--set") {
                if let Err(e) = r2eval::apply_overrides(&mut off, &spec) {
                    return usage(&e);
                }
            }
            for line in r3eval::explain_case(&d3, &case, &off).unwrap_or_default() {
                println!("{line}");
            }
            ExitCode::SUCCESS
        }
        Some("dev3-eval") => {
            let (Some(store), Some(version), Some(dir)) = (
                flag(&args, "--store"),
                flag(&args, "--version"),
                flag(&args, "--dev-dir"),
            ) else {
                return usage("dev3-eval needs --store, --version and --dev-dir");
            };
            let sealed = match seal::open(Path::new(&store), &version) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: {e:?}");
                    return ExitCode::from(4);
                }
            };
            let (d3, d2) = match (
                r3eval::load_dev3(Path::new(&dir)),
                r2eval::load_dev(Path::new(&dir)),
            ) {
                (Ok(a), Ok(b)) => (a, b),
                (Err(e), _) | (_, Err(e)) => {
                    eprintln!("refused: {e}");
                    return ExitCode::from(3);
                }
            };
            let retriever = Retriever::from_sealed(vec![sealed]);
            let (mut off, mut on) = r2eval::configs();
            if let Some(spec) = flag(&args, "--set") {
                if let Err(e) = r2eval::apply_overrides(&mut off, &spec)
                    .and_then(|()| r2eval::apply_overrides(&mut on, &spec))
                {
                    return usage(&e);
                }
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&r3eval::run_dev3(
                    &retriever, &version, &d3, &d2.desc, &off, &on
                ))
                .unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        Some("rs1-signals") => {
            let (Some(store), Some(version), Some(dir)) = (
                flag(&args, "--store"),
                flag(&args, "--version"),
                flag(&args, "--dev-dir"),
            ) else {
                return usage("rs1-signals needs --store, --version and --dev-dir");
            };
            let Ok(sealed) = seal::open(Path::new(&store), &version) else {
                return ExitCode::from(4);
            };
            let Ok(d) = rs1eval::load_dev_rs1(Path::new(&dir)) else {
                return ExitCode::from(3);
            };
            let retriever = Retriever::from_sealed(vec![sealed]);
            let (off, _) = r2eval::configs();
            println!(
                "{}",
                serde_json::to_string_pretty(&rs1eval::run_signals(&retriever, &version, &d, &off))
                    .unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        Some("rs1-census") => {
            let (Some(store), Some(version)) = (flag(&args, "--store"), flag(&args, "--version"))
            else {
                return usage("rs1-census needs --store and --version");
            };
            let words = flag(&args, "--words")
                .and_then(|w| w.parse().ok())
                .unwrap_or(12usize);
            let Ok(sealed) = seal::open(Path::new(&store), &version) else {
                return ExitCode::from(4);
            };
            let (mut off, _) = r2eval::configs();
            if let Some(spec) = flag(&args, "--set") {
                if let Err(e) = r2eval::apply_overrides(&mut off, &spec) {
                    return usage(&e);
                }
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&rs1eval::run_census(&sealed, &version, words, &off))
                    .unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        Some("rs1-ask") => {
            let (Some(store), Some(version), Some(q)) = (
                flag(&args, "--store"),
                flag(&args, "--version"),
                flag(&args, "--q"),
            ) else {
                return usage("rs1-ask needs --store, --version and --q");
            };
            let Ok(sealed) = seal::open(Path::new(&store), &version) else {
                return ExitCode::from(4);
            };
            let (mut off, _) = r2eval::configs();
            if let Some(spec) = flag(&args, "--set") {
                if let Err(e) = r2eval::apply_overrides(&mut off, &spec) {
                    return usage(&e);
                }
            }
            let r = Retriever::from_sealed(vec![sealed]);
            let res = r.search(&q, Some(&version), 3, &off);
            println!("verdict={:?} reason={}", res.verdict, res.reason);
            for p in &res.passages {
                println!(
                    "{}:{} score={:.2} flags={:?}",
                    p.standard, p.clause_id, p.score, p.flags
                );
            }
            for l in r.explain(&q, Some(&version), &off).iter().take(3) {
                println!("  {l}");
            }
            ExitCode::SUCCESS
        }
        Some("rs1-explain") => {
            let (Some(dir), Some(case)) = (flag(&args, "--dev-dir"), flag(&args, "--case")) else {
                return usage("rs1-explain needs --dev-dir and --case");
            };
            let Ok(d) = rs1eval::load_dev_rs1(Path::new(&dir)) else {
                eprintln!("refused: the RS1 DEV sets do not match their frozen hashes");
                return ExitCode::from(3);
            };
            let (mut off, _) = r2eval::configs();
            if let Some(spec) = flag(&args, "--set") {
                if let Err(e) = r2eval::apply_overrides(&mut off, &spec) {
                    return usage(&e);
                }
            }
            for line in rs1eval::explain_case_rs1(&d, &case, &off).unwrap_or_default() {
                println!("{line}");
            }
            ExitCode::SUCCESS
        }
        Some("rs1-dev-eval") => {
            let (Some(store), Some(version), Some(dir)) = (
                flag(&args, "--store"),
                flag(&args, "--version"),
                flag(&args, "--dev-dir"),
            ) else {
                return usage("rs1-dev-eval needs --store, --version and --dev-dir");
            };
            let sealed = match seal::open(Path::new(&store), &version) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: {e:?}");
                    return ExitCode::from(4);
                }
            };
            let d = match rs1eval::load_dev_rs1(Path::new(&dir)) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("refused: {e}");
                    return ExitCode::from(3);
                }
            };
            let retriever = Retriever::from_sealed(vec![sealed]);
            let (mut off, mut on) = r2eval::configs();
            if let Some(spec) = flag(&args, "--set") {
                if let Err(e) = r2eval::apply_overrides(&mut off, &spec)
                    .and_then(|()| r2eval::apply_overrides(&mut on, &spec))
                {
                    return usage(&e);
                }
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&rs1eval::run_dev_rs1(
                    &retriever, &version, &d, &off, &on
                ))
                .unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        Some("heldout-rs1") => {
            // ONE scored run: the sha256 is an ARGUMENT, checked before the file is parsed; an existing report blocks a second run.
            let (Some(store), Some(version), Some(file), Some(sha), Some(out)) = (
                flag(&args, "--store"),
                flag(&args, "--version"),
                flag(&args, "--file"),
                flag(&args, "--sha"),
                flag(&args, "--out"),
            ) else {
                return usage("heldout-rs1 needs --store, --version, --file, --sha and --out");
            };
            if Path::new(&out).exists() {
                eprintln!("refused: a held-out report already exists; the run happens once");
                return ExitCode::from(3);
            }
            let (held, kinds, attacks) = match rs1eval::load_heldout_rs1(Path::new(&file), &sha) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("refused: {e}");
                    return ExitCode::from(3);
                }
            };
            let sealed = match seal::open(Path::new(&store), &version) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: {e:?}");
                    return ExitCode::from(4);
                }
            };
            let retriever = Retriever::from_sealed(vec![sealed]);
            let switches = flag(&args, "--set").unwrap_or_default();
            let rep = match rs1eval::run_heldout_rs1(
                &retriever, &version, &held, &kinds, &attacks, &switches,
            ) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("refused: {e}");
                    return ExitCode::from(3);
                }
            };
            let text = serde_json::to_string_pretty(&rep).unwrap_or_default();
            if std::fs::write(&out, &text).is_err() {
                eprintln!("error: cannot write the report");
                return ExitCode::from(5);
            }
            println!("{text}");
            ExitCode::SUCCESS
        }
        Some("heldout-r3") => {
            // ONE scored run: the sha256 in the R3 order is checked before parsing, and an existing report file blocks a second run.
            let (Some(store), Some(version), Some(file), Some(out)) = (
                flag(&args, "--store"),
                flag(&args, "--version"),
                flag(&args, "--file"),
                flag(&args, "--out"),
            ) else {
                return usage("heldout-r3 needs --store, --version, --file and --out");
            };
            if Path::new(&out).exists() {
                eprintln!("refused: a held-out report already exists; the run happens once");
                return ExitCode::from(3);
            }
            let held = match r3eval::load_heldout_r3(Path::new(&file)) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("refused: {e}");
                    return ExitCode::from(3);
                }
            };
            let sealed = match seal::open(Path::new(&store), &version) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: {e:?}");
                    return ExitCode::from(4);
                }
            };
            let retriever = Retriever::from_sealed(vec![sealed]);
            let rep = r3eval::run_heldout_r3(&retriever, &version, &held);
            let text = serde_json::to_string_pretty(&rep).unwrap_or_default();
            if std::fs::write(&out, &text).is_err() {
                eprintln!("error: cannot write the report");
                return ExitCode::from(5);
            }
            println!("{text}");
            ExitCode::SUCCESS
        }
        Some("heldout") => {
            // ONE scored run: the sha256 is checked before parsing, and an existing report file blocks a second run.
            let (Some(store), Some(version), Some(file), Some(out)) = (
                flag(&args, "--store"),
                flag(&args, "--version"),
                flag(&args, "--file"),
                flag(&args, "--out"),
            ) else {
                return usage("heldout needs --store, --version, --file and --out");
            };
            if Path::new(&out).exists() {
                eprintln!("refused: a held-out report already exists; the run happens once");
                return ExitCode::from(3);
            }
            let held = match r2eval::load_heldout(Path::new(&file), r2eval::HELDOUT_SHA256) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("refused: {e}");
                    return ExitCode::from(3);
                }
            };
            let sealed = match seal::open(Path::new(&store), &version) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: {e:?}");
                    return ExitCode::from(4);
                }
            };
            let retriever = Retriever::from_sealed(vec![sealed]);
            let rep = r2eval::run_heldout(&retriever, &version, &held);
            let text = serde_json::to_string_pretty(&rep).unwrap_or_default();
            if std::fs::write(&out, &text).is_err() {
                eprintln!("error: cannot write the report");
                return ExitCode::from(5);
            }
            println!("{text}");
            ExitCode::SUCCESS
        }
        Some("eval") => {
            let (Some(store), Some(version), Some(ed), Some(out)) = (
                flag(&args, "--store"),
                flag(&args, "--version"),
                flag(&args, "--eval-dir"),
                flag(&args, "--out"),
            ) else {
                return usage("eval needs --store, --version, --eval-dir and --out");
            };
            if let Err(e) = eval::verify_frozen(Path::new(&ed)) {
                eprintln!("refused: the frozen sets do not verify: {e}");
                return ExitCode::from(3);
            }
            let sealed = match seal::open(Path::new(&store), &version) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: {e:?}");
                    return ExitCode::from(4);
                }
            };
            let hash = sealed.manifest.corpus_hash.clone();
            let retriever = Retriever::from_sealed(vec![sealed]);
            let report = match eval::run_real(&retriever, Path::new(&ed), &version, &hash) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("refused: {e}");
                    return ExitCode::from(3);
                }
            };
            let stem = format!("r1-eval-{version}-{}", &hash[..8]);
            let (report_path, preds_path) = (
                Path::new(&out).join(format!("{stem}.json")),
                Path::new(&out).join(format!("{stem}.predictions.jsonl")),
            );
            if report_path.exists() || preds_path.exists() {
                eprintln!("refused: results for this corpus version already exist and are never overwritten");
                return ExitCode::from(3);
            }
            let preds: Vec<String> = report
                .predictions
                .iter()
                .filter_map(|p| serde_json::to_string(p).ok())
                .collect();
            let write = || -> std::io::Result<()> {
                std::fs::create_dir_all(&out)?;
                std::fs::write(
                    &report_path,
                    serde_json::to_string_pretty(&report).unwrap_or_default() + "\n",
                )?;
                std::fs::write(&preds_path, preds.join("\n") + "\n")
            };
            if let Err(e) = write() {
                eprintln!("cannot write the results: {e}");
                return ExitCode::from(4);
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&eval::summary(&report)).unwrap_or_default()
            );
            println!(
                "wrote {} and {}",
                report_path.display(),
                preds_path.display()
            );
            ExitCode::SUCCESS
        }
        _ => usage("unknown or missing command"),
    }
}
