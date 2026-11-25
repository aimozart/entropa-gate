//! Tests added after the first mutation run on the whole crate (a stage record (not published)): exact size boundaries, secret limits, the 1 MiB output boundary, the secret match boundary, no leftover child
//! processes, the ETXTBSY retry, the bound on the wait for the pipes, and two wrapper details. Synthetic data only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_check::sealed::{run, Options};
use entropa_check::set::{parse, Case};
use entropa_check::target::{run_case, Reason, Verdict};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

fn case(expect: &str) -> Case {
    Case {
        id: "c".into(),
        class: "k".into(),
        input: b"x".to_vec(),
        expect: expect.into(),
        attack: false,
        secrets: vec![],
        timeout_ms: 5000,
    }
}
const SET: &str = r#"{"schema":"entropa-sealed-v1","cases":[{"id":"a","class":"k","input":{"text":"x"},"expect":"allow"}]}"#;

#[test]
fn t1_the_set_file_limit_is_exactly_32_mib() {
    let limit = 32 * 1024 * 1024;
    let pad = |n: usize| format!("{SET}{}", " ".repeat(n - SET.len()));
    assert!(
        parse(pad(limit).as_bytes()).is_ok(),
        "exactly 32 MiB parses"
    );
    assert!(parse(pad(limit + 1).as_bytes())
        .unwrap_err()
        .0
        .contains("32 MiB"));
}

#[test]
fn t2_the_sealed_file_size_gate_is_exactly_32_mib_and_runs_before_the_sha() {
    let d = scratch("t2");
    let target = script(&d, "g", GUARD);
    for (n, want_size_refusal) in [(32 * 1024 * 1024u64, false), (32 * 1024 * 1024 + 1, true)] {
        let f = d.join(format!("big-{n}.json"));
        std::fs::File::create(&f).unwrap().set_len(n).unwrap();
        let o = Options {
            file: f,
            sha: "0".repeat(64),
            out: d.join(format!("r-{n}.json")),
            target: target.clone(),
            args: vec![],
            forecast: None,
            prereg: None,
            no_prereg: true,
            runner: None,
            anchor_ledger: None,
        };
        let e = run(&o).unwrap_err();
        assert_eq!(e.0.contains("32 MiB"), want_size_refusal, "{n}: {e}");
    }
}

#[test]
fn t3_secret_limits_are_exact() {
    let with = |secrets: String| {
        format!(
            r#"{{"schema":"entropa-sealed-v1","cases":[{{"id":"a","class":"k","input":{{"text":"x"}},"expect":"allow","secrets":{secrets}}}]}}"#
        )
    };
    let n = |k: usize| {
        format!(
            "[{}]",
            (0..k)
                .map(|i| format!("\"s{i}\""))
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    assert!(
        parse(with(n(100)).as_bytes()).is_ok(),
        "100 secrets are accepted"
    );
    assert!(parse(with(n(101)).as_bytes()).is_err(), "101 are refused");
    assert!(
        parse(with(format!("[\"{}\"]", "a".repeat(4096))).as_bytes()).is_ok(),
        "a 4096-byte secret is accepted"
    );
    assert!(
        parse(with(format!("[\"{}\"]", "a".repeat(4097))).as_bytes()).is_err(),
        "4097 bytes are refused"
    );
    assert!(
        parse(with("[\"\"]".into()).as_bytes()).is_err(),
        "an empty secret is refused"
    );
}

#[test]
fn t4_output_of_exactly_one_mib_is_accepted_and_one_byte_more_is_too_large() {
    let d = scratch("t4");
    let cap = 1024 * 1024;
    // "allow\n" is 6 bytes; the padding makes the total exactly the cap, then one more byte
    let exact = script(
        &d,
        "exact",
        &format!(
            "cat >/dev/null; printf 'allow\\n'; head -c {} /dev/zero | tr '\\0' 'a'",
            cap - 6
        ),
    );
    let over = script(
        &d,
        "over",
        &format!(
            "cat >/dev/null; printf 'allow\\n'; head -c {} /dev/zero | tr '\\0' 'a'",
            cap - 5
        ),
    );
    let o = run_case(&exact, &[], &case("allow"));
    assert_eq!(
        (o.verdict, o.failed),
        (Verdict::Allow, None),
        "exactly 1 MiB passes"
    );
    assert_eq!(
        run_case(&over, &[], &case("allow")).failed,
        Some(Reason::OutputTooLarge),
        "one byte more is too large"
    );
}

#[test]
fn t5_a_secret_is_found_anywhere_and_absent_from_a_longer_clean_output() {
    let d = scratch("t5");
    let mut c = case("allow");
    c.secrets = vec!["HUNTER2".into()];
    let clean = script(
        &d,
        "clean",
        "cat >/dev/null; echo allow; echo 'a perfectly ordinary and much longer line of output'",
    );
    assert_eq!(
        run_case(&clean, &[], &c).failed,
        None,
        "a longer clean output holds no secret"
    );
    let at_end = script(
        &d,
        "end",
        "cat >/dev/null; echo allow; printf 'tail HUNTER2'",
    );
    assert_eq!(
        run_case(&at_end, &[], &c).failed,
        Some(Reason::EchoedSecret)
    );
    let exact = script(
        &d,
        "exact",
        "cat >/dev/null; echo allow >&2; printf 'HUNTER2'",
    );
    // stdout is exactly the secret and the verdict word went to stderr: the secret check takes precedence over a bad verdict (the documented reason order)
    assert_eq!(run_case(&exact, &[], &c).failed, Some(Reason::EchoedSecret));
}

#[test]
fn t6_a_process_the_target_leaves_running_is_stopped() {
    let d = scratch("t6");
    let pidfile = d.join("child.pid");
    let t = script(
        &d,
        "leaver",
        &format!(
            "cat >/dev/null; sleep 60 & echo $! > {}; echo allow",
            pidfile.display()
        ),
    );
    let o = run_case(&t, &[], &case("allow"));
    assert_eq!((o.verdict, o.failed), (Verdict::Allow, None));
    let pid: u32 = std::fs::read_to_string(&pidfile)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let alive = std::path::Path::new(&format!("/proc/{pid}")).exists()
        && std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .map(|s| !s.contains(") Z "))
            .unwrap_or(false);
    assert!(!alive, "the child the target left running was stopped");
}

#[test]
fn t7_a_file_still_open_for_writing_is_retried_until_it_can_run() {
    let d = scratch("t7");
    let p = d.join("late.sh");
    let mut f = std::fs::File::create(&p).unwrap();
    f.write_all(b"#!/bin/sh\ncat >/dev/null; echo allow\n")
        .unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    // the writer handle stays open for 80 ms: exec fails with ETXTBSY meanwhile
    let h = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(80));
        drop(f);
    });
    let o = run_case(&p, &[], &case("allow"));
    h.join().unwrap();
    assert_eq!(
        (o.verdict, o.failed),
        (Verdict::Allow, None),
        "the spawn was retried"
    );
}

#[test]
fn t8_a_fast_target_is_not_made_to_wait_for_the_pipes() {
    let d = scratch("t8");
    let t = script(&d, "fast", GUARD);
    let mut worst = Duration::ZERO;
    for _ in 0..5 {
        let s = Instant::now();
        assert_eq!(run_case(&t, &[], &case("allow")).failed, None);
        worst = worst.max(s.elapsed());
    }
    assert!(
        worst < Duration::from_millis(700),
        "a fast target finishes in {worst:?}: the collection of the pipes ends when both are read"
    );
}

#[test]
fn t9_a_spawn_error_that_is_not_a_busy_file_is_not_retried() {
    // a missing program is a plain error: it must end the case at once as a crash, not after the sleeps meant for a busy file (5 x 30 ms)
    let d = scratch("t9");
    let missing = d.join("does-not-exist");
    let mut worst = Duration::ZERO;
    for _ in 0..3 {
        let s = Instant::now();
        let o = run_case(&missing, &[], &case("allow"));
        worst = worst.max(s.elapsed());
        assert_eq!((o.verdict, o.failed), (Verdict::Error, Some(Reason::Crash)));
    }
    assert!(
        worst < Duration::from_millis(100),
        "a missing program ends the case in {worst:?}: only ETXTBSY is retried"
    );
}
