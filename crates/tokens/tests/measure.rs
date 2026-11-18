//! AT1 task 4: size per hop, issue and verify time (p50 and p95), memory and lines of code, for design A and design C. Run with
//! `cargo test --release -p entropa-tokens --test measure -- --ignored --nocapture` (AT1_MEASURE=path writes the JSON). Release build, one machine,
//! one run: the numbers are a record of this machine, not a benchmark.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_core::Probe;
use entropa_tokens::{
    append_c, empty_revocations, issue_a, issue_c, narrow_a, verify_a, verify_c, Claims, Narrowing,
    Policy, Tier, Trust,
};
use std::time::Instant;

const NOW: u64 = 1_800_000_000;
const RUNS: usize = 200;

fn claims() -> Claims {
    Claims {
        token_id: "a".repeat(32),
        subject: "agent-1".into(),
        tier: Tier::T2,
        corpora: (0..4)
            .map(|i| format!("{:02x}", i + 0x10).repeat(32))
            .collect(),
        actions: ["cite_check", "lookup_clause", "search", "write"]
            .iter()
            .map(ToString::to_string)
            .collect(),
        spend_cap: 5_000_000,
        rate_cap: 600,
        not_before: NOW - 100,
        expiry: NOW + 1000,
        audience: "node-1".into(),
        parent: None,
    }
}
fn pct(mut v: Vec<f64>, p: f64) -> f64 {
    v.sort_by(|a, b| a.total_cmp(b));
    v[((v.len() as f64 - 1.0) * p).round() as usize]
}
fn time_us<T>(mut f: impl FnMut() -> T) -> (f64, f64) {
    let v: Vec<f64> = (0..RUNS)
        .map(|_| {
            let t = Instant::now();
            let _ = std::hint::black_box(f());
            t.elapsed().as_secs_f64() * 1e6
        })
        .collect();
    (pct(v.clone(), 0.5), pct(v, 0.95))
}
fn status_kb(key: &str) -> usize {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with(key))
                .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
        })
        .unwrap_or(0)
}
fn lines(file: &str) -> usize {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(file);
    std::fs::read_to_string(p)
        .map(|s| {
            s.lines()
                .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with("//"))
                .count()
        })
        .unwrap_or(0)
}

#[test]
#[ignore = "measurement, run on demand"]
fn measure_designs_a_and_c() {
    let issuer = Probe::spawn();
    let mut trust = Trust::default();
    trust.add(&issuer.pubkey_hex());
    let policy = Policy {
        audience: "node-1".into(),
        now: NOW,
        ..Policy::default()
    };
    let rev = empty_revocations(&issuer, NOW);
    let mut out = String::from("{\n");

    // sizes
    let a_root = issue_a(&issuer, &claims()).unwrap();
    let a_child = narrow_a(
        &issuer,
        &a_root,
        &Claims {
            token_id: "b".repeat(32),
            spend_cap: 1000,
            ..claims()
        },
    )
    .unwrap();
    let mut w = issue_c(&issuer, &claims()).unwrap();
    let mut c_sizes = vec![w.token.len()];
    let mut chains = vec![w.token.clone()];
    for i in 0..7 {
        w = append_c(
            &w,
            &Narrowing {
                spend_cap: Some(4_000_000 - i),
                ..Narrowing::default()
            },
        )
        .unwrap();
        c_sizes.push(w.token.len());
        chains.push(w.token.clone());
    }
    out += &format!(" \"size_bytes\": {{\"A_token\": {}, \"A_narrowed_child\": {}, \"C_root\": {}, \"C_with_blocks_1_to_7\": {:?}, \"C_growth_per_block_bytes\": {}}},\n",
        a_root.len(), a_child.len(), c_sizes[0], &c_sizes[1..], (c_sizes[7] - c_sizes[0]) / 7);

    // time
    let (ai50, ai95) = time_us(|| issue_a(&issuer, &claims()).unwrap());
    let (an50, an95) = time_us(|| {
        narrow_a(
            &issuer,
            &a_root,
            &Claims {
                token_id: "b".repeat(32),
                spend_cap: 1000,
                ..claims()
            },
        )
        .unwrap()
    });
    let (av50, av95) = time_us(|| verify_a(&a_root, &trust, &policy, Some(&rev), None).unwrap());
    let (avp50, avp95) =
        time_us(|| verify_a(&a_child, &trust, &policy, Some(&rev), Some(&a_root)).unwrap());
    let (ci50, ci95) = time_us(|| issue_c(&issuer, &claims()).unwrap());
    let w0 = issue_c(&issuer, &claims()).unwrap();
    let (cap50, cap95) = time_us(|| {
        append_c(
            &w0,
            &Narrowing {
                spend_cap: Some(10),
                ..Narrowing::default()
            },
        )
        .unwrap()
    });
    out += &format!(" \"time_us\": {{\"A_issue\": [{ai50:.0}, {ai95:.0}], \"A_narrow_by_issuer\": [{an50:.0}, {an95:.0}], \"A_verify\": [{av50:.0}, {av95:.0}], \"A_verify_with_parent\": [{avp50:.0}, {avp95:.0}], \"C_issue_root\": [{ci50:.0}, {ci95:.0}], \"C_append_block\": [{cap50:.0}, {cap95:.0}], \"C_verify_by_blocks\": {{");
    for (i, n) in [(0usize, "0"), (1, "1"), (3, "3"), (7, "7")] {
        let (p50, p95) = time_us(|| verify_c(&chains[i], &trust, &policy, Some(&rev)).unwrap());
        out += &format!(
            "{}\"{n}\": [{p50:.0}, {p95:.0}]",
            if i == 0 { "" } else { ", " }
        );
    }
    out += "}},\n";

    // memory: peak resident-set growth over 200 verifications of the longest chain, and of A
    let _ = std::fs::write("/proc/self/clear_refs", "5");
    let base = status_kb("VmRSS:");
    for _ in 0..RUNS {
        let _ = verify_c(&chains[7], &trust, &policy, Some(&rev)).unwrap();
    }
    let growth_c = status_kb("VmHWM:").saturating_sub(base);
    let _ = std::fs::write("/proc/self/clear_refs", "5");
    let base = status_kb("VmRSS:");
    for _ in 0..RUNS {
        let _ = verify_a(&a_root, &trust, &policy, Some(&rev), None).unwrap();
    }
    let growth_a = status_kb("VmHWM:").saturating_sub(base);
    out += &format!(" \"peak_rss_growth_kb_over_{RUNS}_verifies\": {{\"A\": {growth_a}, \"C_8_blocks\": {growth_c}}},\n");

    // lines of code (non-empty, non-comment)
    let shared = [
        "src/canon.rs",
        "src/claims.rs",
        "src/verify.rs",
        "src/revoke.rs",
        "src/lib.rs",
    ]
    .iter()
    .map(|f| lines(f))
    .sum::<usize>();
    out += &format!(" \"lines_of_code\": {{\"shared\": {shared}, \"design_A\": {}, \"design_C\": {}, \"tests\": {}}}\n}}\n", lines("src/design_a.rs"), lines("src/design_c.rs") + lines("src/testing.rs"),
        ["tests/api_a.rs", "tests/api_c.rs", "tests/canon.rs", "tests/props.rs", "tests/battery.rs"].iter().map(|f| lines(f)).sum::<usize>());
    println!("{out}");
    if let Ok(p) = std::env::var("AT1_MEASURE") {
        std::fs::write(p, &out).unwrap();
    }
}
