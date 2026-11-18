//! The HTTP layer with a fake mailer. Synthetic data only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_contact::*;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Default)]
struct Fake {
    sent: Mutex<Vec<Message>>,
    fail: bool,
}
impl Mailer for Fake {
    fn send(&self, m: &Message) -> Result<(), String> {
        if self.fail {
            return Err("boom: secret-detail".into());
        }
        self.sent.lock().unwrap().push(m.clone());
        Ok(())
    }
}

fn start(mailer: Arc<Fake>, limits: Limits) -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.set_nonblocking(true).unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let l = tokio::net::TcpListener::from_std(l).unwrap();
            axum::serve(
                l,
                app(mailer, limits).into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
    });
    port
}

fn http(port: u16, method: &str, path: &str, ip: &str, body: &str) -> (u16, String) {
    let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let req = format!("{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nX-Forwarded-For: {ip}\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{body}", body.len());
    c.write_all(req.as_bytes()).unwrap();
    let mut out = String::new();
    let _ = c.read_to_string(&mut out);
    let code = out
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    (code, out.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
}

const GOOD: &str = r#"{"name":"Jane Recruiter","email":"jane@example.com","reason":"Hiring inquiry","message":"Hello there","website":""}"#;
fn limits() -> Limits {
    Limits {
        per_ip_per_hour: 3,
        daily_cap: 100,
    }
}

#[test]
fn h1_a_good_submission_is_sent_once_and_does_not_echo_the_input() {
    let f = Arc::new(Fake::default());
    let p = start(f.clone(), limits());
    let (c, b) = http(p, "POST", "/api/contact", "1.1.1.1", GOOD);
    assert_eq!(c, 200, "{b}");
    assert!(!b.contains("jane") && !b.contains("Recruiter"));
    assert_eq!(f.sent.lock().unwrap().len(), 1);
    assert_eq!(http(p, "POST", "/v1/contact", "1.1.1.2", GOOD).0, 200);
}

#[test]
fn h2_invalid_input_is_400_and_sends_nothing() {
    let f = Arc::new(Fake::default());
    let p = start(f.clone(), limits());
    assert_eq!(
        http(p, "POST", "/api/contact", "2.2.2.2", "not json").0,
        400
    );
    assert_eq!(
        http(p, "POST", "/api/contact", "2.2.2.2", r#"{"name":"x"}"#).0,
        400
    );
    assert!(f.sent.lock().unwrap().is_empty());
}

#[test]
fn h3_a_bot_gets_a_normal_looking_200_and_nothing_is_sent() {
    let f = Arc::new(Fake::default());
    let p = start(f.clone(), limits());
    let bot = GOOD.replace(r#""website":"""#, r#""website":"http://spam""#);
    assert_eq!(http(p, "POST", "/api/contact", "3.3.3.3", &bot).0, 200);
    assert!(f.sent.lock().unwrap().is_empty());
}

#[test]
fn h4_each_address_is_rate_limited() {
    let f = Arc::new(Fake::default());
    let p = start(f.clone(), limits());
    for _ in 0..3 {
        assert_eq!(http(p, "POST", "/api/contact", "4.4.4.4", GOOD).0, 200);
    }
    assert_eq!(http(p, "POST", "/api/contact", "4.4.4.4", GOOD).0, 429);
    assert_eq!(http(p, "POST", "/api/contact", "4.4.4.5", GOOD).0, 200);
    assert_eq!(f.sent.lock().unwrap().len(), 4);
}

#[test]
fn h5_a_daily_cap_stops_everything() {
    let f = Arc::new(Fake::default());
    let p = start(
        f.clone(),
        Limits {
            per_ip_per_hour: 50,
            daily_cap: 2,
        },
    );
    assert_eq!(http(p, "POST", "/api/contact", "5.0.0.1", GOOD).0, 200);
    assert_eq!(http(p, "POST", "/api/contact", "5.0.0.2", GOOD).0, 200);
    assert_eq!(http(p, "POST", "/api/contact", "5.0.0.3", GOOD).0, 429);
}

#[test]
fn h6_a_mailer_failure_is_a_generic_502() {
    let f = Arc::new(Fake {
        fail: true,
        ..Fake::default()
    });
    let p = start(f, limits());
    let (c, b) = http(p, "POST", "/api/contact", "6.6.6.6", GOOD);
    assert_eq!(c, 502);
    assert!(!b.contains("secret-detail") && !b.contains("boom"));
}

#[test]
fn h7_oversize_bodies_wrong_methods_and_unknown_paths() {
    let f = Arc::new(Fake::default());
    let p = start(f, limits());
    let big = format!(r#"{{"message":"{}"}}"#, "x".repeat(40_000));
    assert_eq!(http(p, "POST", "/api/contact", "7.7.7.7", &big).0, 413);
    assert_eq!(http(p, "GET", "/api/contact", "7.7.7.7", "").0, 405);
    assert_eq!(http(p, "GET", "/nope", "7.7.7.7", "").0, 404);
    assert_eq!(http(p, "GET", "/healthz", "7.7.7.7", "").0, 200);
}
