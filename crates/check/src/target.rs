//! Running the user's target on one case (the target contract of a stage record (not published)).
use crate::set::Case;
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

/// What the target said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The first stdout line was `allow`.
    Allow,
    /// The first stdout line was `block`.
    Block,
    /// Anything else: another word, no output, a crash, a timeout.
    Error,
}

/// The closed failure reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Reason {
    /// The verdict differs from the expected one.
    WrongVerdict,
    /// A secret of the case appeared in stdout or stderr.
    EchoedSecret,
    /// The case time limit was exceeded.
    Timeout,
    /// The target exited non-zero or was killed by a signal.
    Crash,
    /// Exit 0 but the first stdout line is not `allow` or `block`.
    BadVerdict,
    /// stdout or stderr exceeded 1 MiB.
    OutputTooLarge,
}

impl Reason {
    /// The closed word used in reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::WrongVerdict => "wrong_verdict",
            Reason::EchoedSecret => "echoed_secret",
            Reason::Timeout => "timeout",
            Reason::Crash => "crash",
            Reason::BadVerdict => "bad_verdict",
            Reason::OutputTooLarge => "output_too_large",
        }
    }
}

/// The result of one case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    /// What the target said.
    pub verdict: Verdict,
    /// Why the case failed, `None` when it passed.
    pub failed: Option<Reason>,
}

const CAP: usize = 1024 * 1024;

fn read_capped(mut r: impl Read, large: Arc<AtomicBool>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        match r.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if out.len() + n > CAP {
                    out.extend_from_slice(&buf[..CAP.saturating_sub(out.len())]);
                    large.store(true, Ordering::SeqCst);
                    break;
                }
                out.extend_from_slice(&buf[..n]);
            }
        }
    }
    out
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

fn kill_group(pid: u32) {
    // the target may have started children that hold the pipes: stop the whole process group (best effort; no shell)
    let _ = Command::new("kill")
        .arg("-KILL")
        .arg("--")
        .arg(format!("-{pid}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Run the target once on `case` (a file, no shell; stdin gets the input; stdout and stderr are capped at 1 MiB; the time limit is the case's).
pub fn run_case(target: &Path, args: &[String], case: &Case) -> Outcome {
    let crash = Outcome {
        verdict: Verdict::Error,
        failed: Some(Reason::Crash),
    };
    let mut spawned = None;
    for attempt in 0..6 {
        match Command::new(target)
            .args(args)
            .process_group(0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => {
                spawned = Some(c);
                break;
            }
            // ETXTBSY (26): the file was written a moment ago and another thread's fork still holds it open for writing; it clears in milliseconds
            Err(e) if e.raw_os_error() == Some(26) && attempt < 5 => {
                std::thread::sleep(Duration::from_millis(30))
            }
            Err(_) => break,
        }
    }
    let Some(mut child) = spawned else {
        return crash;
    };
    let pid = child.id();
    let large = Arc::new(AtomicBool::new(false));
    let stdin = child.stdin.take();
    let input = case.input.clone();
    std::thread::spawn(move || {
        if let Some(mut s) = stdin {
            let _ = s.write_all(&input);
        }
    });
    let (tx, rx) = mpsc::channel::<(bool, Vec<u8>)>();
    let pipes: [(bool, Option<Box<dyn Read + Send>>); 2] = [
        (
            true,
            child
                .stdout
                .take()
                .map(|p| Box::new(p) as Box<dyn Read + Send>),
        ),
        (
            false,
            child
                .stderr
                .take()
                .map(|p| Box::new(p) as Box<dyn Read + Send>),
        ),
    ];
    for (is_out, pipe) in pipes {
        let (tx, large) = (tx.clone(), large.clone());
        std::thread::spawn(move || {
            let data = pipe.map(|p| read_capped(p, large)).unwrap_or_default();
            let _ = tx.send((is_out, data));
        });
    }
    drop(tx);
    let deadline = Instant::now() + Duration::from_millis(case.timeout_ms);
    let (mut status, mut timed_out) = (None, false);
    while status.is_none() {
        match child.try_wait() {
            Ok(Some(s)) => status = Some(s),
            Ok(None) => {
                if large.load(Ordering::SeqCst) {
                    break;
                }
                if Instant::now() >= deadline {
                    timed_out = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(_) => return crash,
        }
    }
    if status.is_none() {
        kill_group(pid);
        let _ = child.kill();
        let _ = child.wait();
    }
    if status.is_some() {
        kill_group(pid); // leftovers of a finished target hold the pipes open: stop them BEFORE reading, or the verdict it printed would be lost
    }
    // collect the two pipes (a grandchild that keeps a pipe open cannot hang us: the wait is bounded)
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut got = 0;
    let wait_until = Instant::now() + Duration::from_millis(if timed_out { 200 } else { 1000 });
    while got < 2 {
        match rx.recv_timeout(wait_until.saturating_duration_since(Instant::now())) {
            Ok((true, d)) => {
                out = d;
                got += 1;
            }
            Ok((false, d)) => {
                err = d;
                got += 1;
            }
            Err(_) => break,
        }
    }
    if timed_out {
        return Outcome {
            verdict: Verdict::Error,
            failed: Some(Reason::Timeout),
        };
    }
    if large.load(Ordering::SeqCst) {
        return Outcome {
            verdict: Verdict::Error,
            failed: Some(Reason::OutputTooLarge),
        };
    }
    if !status.is_some_and(|s| s.success()) {
        return crash;
    }
    let first = out.split(|b| *b == b'\n').next().unwrap_or(&[]);
    let first = first.strip_suffix(b"\r").unwrap_or(first);
    let verdict = match first {
        b"allow" => Verdict::Allow,
        b"block" => Verdict::Block,
        _ => Verdict::Error,
    };
    let failed = if case
        .secrets
        .iter()
        .any(|s| contains(&out, s.as_bytes()) || contains(&err, s.as_bytes()))
    {
        Some(Reason::EchoedSecret)
    } else if verdict == Verdict::Error {
        Some(Reason::BadVerdict)
    } else if (verdict == Verdict::Allow) != (case.expect == "allow") {
        Some(Reason::WrongVerdict)
    } else {
        None
    };
    Outcome { verdict, failed }
}
