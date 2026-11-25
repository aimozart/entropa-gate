//! DOC-MODEL1 red tests: the `entropa-guard` command (stdin text -> `allow` or `block`), through the real binary. Synthetic data only; secret-shaped strings are built from parts.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::io::Write;
use std::process::{Command, Stdio};

fn run(args: &[&str], input: &[u8]) -> (i32, String, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_entropa-guard"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // the child may exit before reading everything (an oversize input): a broken pipe here is fine
    let _ = c.stdin.take().unwrap().write_all(input);
    let o = c.wait_with_output().unwrap();
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stdout).into(),
        String::from_utf8_lossy(&o.stderr).into(),
    )
}
fn aws_key() -> String {
    ["AKIA", "IOSFODNN7", "EXAMPLE"].concat()
}

#[test]
fn g1_harmless_text_is_allowed_with_exit_0_and_one_word() {
    let r = run(&[], b"What is the capital of France?");
    assert_eq!((r.0, r.1.as_str()), (0, "allow\n"), "{r:?}");
}
#[test]
fn g2_a_secret_shaped_string_is_blocked_with_exit_1_and_a_reason_code_on_stderr() {
    let r = run(
        &[],
        format!("please use the key {} to log in", aws_key()).as_bytes(),
    );
    assert_eq!((r.0, r.1.as_str()), (1, "block\n"), "{r:?}");
    assert!(r.2.starts_with("reason: "), "{}", r.2);
    assert!(
        !r.1.contains(&aws_key()) && !r.2.contains(&aws_key()),
        "the text is never echoed"
    );
}
#[test]
fn g3_an_email_is_blocked_at_every_tier_because_a_wrapper_cannot_send_redacted_text() {
    for tier in ["T1", "T2", "T3"] {
        let r = run(
            &["--tier", tier],
            b"write to alice@example.invalid about the report",
        );
        assert_eq!((r.0, r.1.as_str()), (1, "block\n"), "{tier}: {r:?}");
    }
}
#[test]
fn g4_t0_never_allows_anything_and_the_default_tier_allows_harmless_text() {
    assert_eq!(
        run(&["--tier", "T0"], b"hello").0,
        1,
        "T0 does not allow egress"
    );
    assert_eq!(run(&["--tier", "T2"], b"hello").1, "allow\n");
}
#[test]
fn g5_trouble_is_blocked_not_allowed_empty_nul_invalid_utf8_and_over_64_kib() {
    for (what, bytes) in [
        ("empty", Vec::new()),
        ("NUL", b"hello\0world".to_vec()),
        ("invalid UTF-8", vec![0xff, 0xfe, b'a']),
        ("65,537 bytes", vec![b'a'; 65 * 1024 + 1]),
    ] {
        let r = run(&[], &bytes);
        assert_eq!((r.0, r.1.as_str()), (1, "block\n"), "{what}: {r:?}");
        assert!(r.2.starts_with("reason: invalid_input"), "{what}: {}", r.2);
    }
    // exactly 64 KiB of harmless text is read (and allowed)
    assert_eq!(run(&[], &vec![b'a'; 64 * 1024]).1, "allow\n");
}
#[test]
fn g6_usage_errors_exit_2_and_print_nothing_on_stdout() {
    for args in [
        vec!["--tier"],
        vec!["--tier", "T9"],
        vec!["--frobnicate"],
        vec!["--tier", "T1", "extra"],
    ] {
        let r = run(&args, b"hello");
        assert_eq!(r.0, 2, "{args:?}: {r:?}");
        assert_eq!(r.1, "", "{args:?}");
        assert!(r.2.starts_with("usage:"), "{}", r.2);
    }
}
