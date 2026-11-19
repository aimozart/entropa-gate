//! The target runner: verdicts and every closed failure reason. Synthetic data only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use entropa_check::set::Case;
use entropa_check::target::{run_case, Reason, Verdict};

fn case(input: &str, expect: &str) -> Case {
    Case {
        id: "c".into(),
        class: "k".into(),
        input: input.as_bytes().to_vec(),
        expect: expect.into(),
        attack: false,
        secrets: vec![],
        timeout_ms: 3000,
    }
}

#[test]
fn r1_allow_and_block_are_read_from_the_first_stdout_line_and_stdin_is_delivered() {
    let d = scratch("r1");
    let t = script(&d, "g", GUARD);
    let o = run_case(&t, &[], &case("hello", "allow"));
    assert_eq!((o.verdict, o.failed), (Verdict::Allow, None));
    let o = run_case(&t, &[], &case("this is BAD", "block"));
    assert_eq!((o.verdict, o.failed), (Verdict::Block, None));
    // only the first line counts
    let t2 = script(&d, "g2", "cat >/dev/null; echo block; echo allow");
    assert_eq!(
        run_case(&t2, &[], &case("x", "block")).verdict,
        Verdict::Block
    );
}

#[test]
fn r2_wrong_verdict() {
    let d = scratch("r2");
    let t = script(&d, "g", GUARD);
    let o = run_case(&t, &[], &case("this is BAD", "allow"));
    assert_eq!(
        (o.verdict, o.failed),
        (Verdict::Block, Some(Reason::WrongVerdict))
    );
}

#[test]
fn r3_every_other_reason() {
    let d = scratch("r3");
    let mut c = case("x", "allow");
    let t = script(&d, "slow", "sleep 5; echo allow");
    c.timeout_ms = 200;
    let started = std::time::Instant::now();
    let o = run_case(&t, &[], &c);
    assert_eq!(
        (o.verdict, o.failed),
        (Verdict::Error, Some(Reason::Timeout))
    );
    assert!(
        started.elapsed().as_secs() < 3,
        "the target was stopped at the limit, not waited for"
    );
    let c = case("x", "allow");
    assert_eq!(
        run_case(
            &script(&d, "crash", "cat >/dev/null; echo allow; exit 3"),
            &[],
            &c
        )
        .failed,
        Some(Reason::Crash)
    );
    assert_eq!(
        run_case(&script(&d, "sig", "kill -9 $$"), &[], &c).failed,
        Some(Reason::Crash)
    );
    assert_eq!(
        run_case(&script(&d, "bad", "cat >/dev/null; echo maybe"), &[], &c).failed,
        Some(Reason::BadVerdict)
    );
    assert_eq!(
        run_case(&script(&d, "none", "cat >/dev/null"), &[], &c).failed,
        Some(Reason::BadVerdict)
    );
    assert_eq!(
        run_case(
            &script(
                &d,
                "big",
                "cat >/dev/null; echo allow; head -c 2000000 /dev/zero"
            ),
            &[],
            &c
        )
        .failed,
        Some(Reason::OutputTooLarge)
    );
    assert_eq!(
        run_case(&d.join("missing"), &[], &c).failed,
        Some(Reason::Crash),
        "a target that cannot start is a crash"
    );
}

#[test]
fn r4_a_secret_in_stdout_or_stderr_is_an_echo_even_when_the_verdict_is_right() {
    let d = scratch("r4");
    let mut c = case("the key is HUNTER2", "allow");
    c.secrets = vec!["HUNTER2".into()];
    let echo_out = script(&d, "eo", "in=$(cat); echo allow; echo \"$in\"");
    assert_eq!(
        run_case(&echo_out, &[], &c).failed,
        Some(Reason::EchoedSecret)
    );
    let echo_err = script(&d, "ee", "in=$(cat); echo \"$in\" >&2; echo allow");
    assert_eq!(
        run_case(&echo_err, &[], &c).failed,
        Some(Reason::EchoedSecret)
    );
    let clean = script(&d, "ok", "cat >/dev/null; echo allow");
    assert_eq!(run_case(&clean, &[], &c).failed, None);
}

#[test]
fn r5_arguments_are_passed_without_a_shell() {
    let d = scratch("r5");
    let t = script(&d, "args", "cat >/dev/null; if [ \"$1\" = \"--mode\" ] && [ \"$2\" = \"a b; echo block\" ]; then echo allow; else echo block; fi");
    let o = run_case(
        &t,
        &["--mode".into(), "a b; echo block".into()],
        &case("x", "allow"),
    );
    assert_eq!(o.failed, None, "{o:?}");
}
