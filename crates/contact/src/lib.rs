//! Contact-form service: validates a submission and forwards it to one private inbox. The inbox
//! address lives only in the service's environment; no page ever shows it. Spam controls: a hidden
//! field, a per-client hourly limit and a daily cap. Replies never echo the input.

mod gmail;
pub use gmail::GmailMailer;

use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use serde_json::Value;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_BODY: usize = 16 * 1024;
const REASON_DEFAULT: &str = "General";

/// A validated submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Clean {
    /// Visitor name.
    pub name: String,
    /// Visitor email (used only as Reply-To in the private inbox).
    pub email: String,
    /// Topic.
    pub reason: String,
    /// Message text.
    pub message: String,
}

/// Why a submission was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// The hidden field was filled: a bot. Answered with a normal-looking success, nothing sent.
    Spam,
    /// Malformed input.
    Invalid,
}

fn plain_line(s: &str, max: usize) -> bool {
    !s.is_empty() && s.chars().count() <= max && !s.chars().any(char::is_control)
}

fn email_shape(s: &str) -> bool {
    if s.len() > 254 || s.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return false;
    }
    let mut parts = s.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains("..")
}

fn text<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

/// Validate a JSON submission.
pub fn validate(v: &Value) -> Result<Clean, Reject> {
    if !v.is_object() {
        return Err(Reject::Invalid);
    }
    if !text(v, "website").is_empty() {
        return Err(Reject::Spam);
    }
    let name = text(v, "name").trim();
    let email = text(v, "email").trim();
    let message = text(v, "message").trim();
    if !plain_line(name, 100) || !email_shape(email) {
        return Err(Reject::Invalid);
    }
    if message.is_empty() || message.chars().count() > 5000 {
        return Err(Reject::Invalid);
    }
    let reason = text(v, "reason").trim();
    let reason = if plain_line(reason, 60) {
        reason
    } else {
        REASON_DEFAULT
    };
    Ok(Clean {
        name: name.to_string(),
        email: email.to_string(),
        reason: reason.to_string(),
        message: message.to_string(),
    })
}

/// What is sent to the private inbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Subject line (ASCII).
    pub subject: String,
    /// Plain-text body.
    pub body: String,
    /// The visitor's address, for the Reply-To header only.
    pub reply_to: String,
}

fn ascii(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii() && !c.is_control())
        .collect()
}

/// Build the message for a validated submission.
pub fn build_message(c: &Clean) -> Message {
    Message {
        subject: format!("Entropa contact: {}", ascii(&c.reason)),
        body: format!(
            "From: {} <{}>\nTopic: {}\n\n{}\n",
            c.name, c.email, c.reason, c.message
        ),
        reply_to: c.email.clone(),
    }
}

/// Sends a message to the private inbox.
pub trait Mailer: Send + Sync {
    /// Send one message.
    fn send(&self, m: &Message) -> Result<(), String>;
}

/// Request limits.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Submissions accepted per client address per hour.
    pub per_ip_per_hour: usize,
    /// Submissions accepted per day in total (a kill switch against floods).
    pub daily_cap: usize,
}

struct State_ {
    mailer: Arc<dyn Mailer>,
    limits: Limits,
    seen: Mutex<HashMap<String, Vec<Instant>>>,
    day: Mutex<Vec<Instant>>,
}

fn allow(st: &State_, ip: &str) -> bool {
    let now = Instant::now();
    let (Ok(mut seen), Ok(mut day)) = (st.seen.lock(), st.day.lock()) else {
        return false;
    };
    day.retain(|t| now.duration_since(*t) < Duration::from_secs(86_400));
    let hits = seen.entry(ip.to_string()).or_default();
    hits.retain(|t| now.duration_since(*t) < Duration::from_secs(3600));
    if hits.len() >= st.limits.per_ip_per_hour || day.len() >= st.limits.daily_cap {
        return false;
    }
    hits.push(now);
    day.push(now);
    true
}

fn client_ip(h: &HeaderMap, peer: SocketAddr) -> String {
    h.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().chars().take(64).collect::<String>())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| peer.ip().to_string())
}

async fn submit(
    State(st): State<Arc<State_>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: String,
) -> (StatusCode, &'static str) {
    let Ok(v) = serde_json::from_str::<Value>(&body) else {
        return (StatusCode::BAD_REQUEST, r#"{"error":"invalid"}"#);
    };
    let clean = match validate(&v) {
        Ok(c) => c,
        Err(Reject::Spam) => return (StatusCode::OK, r#"{"ok":true}"#),
        Err(Reject::Invalid) => return (StatusCode::BAD_REQUEST, r#"{"error":"invalid"}"#),
    };
    if !allow(&st, &client_ip(&headers, peer)) {
        return (StatusCode::TOO_MANY_REQUESTS, r#"{"error":"slow down"}"#);
    }
    let msg = build_message(&clean);
    let mailer = st.mailer.clone();
    match tokio::task::spawn_blocking(move || mailer.send(&msg)).await {
        Ok(Ok(())) => (StatusCode::OK, r#"{"ok":true}"#),
        Ok(Err(reason)) => {
            // Short reason codes only (never the submission), so an operator can see why delivery failed.
            eprintln!("contact: delivery failed: {reason}");
            (StatusCode::BAD_GATEWAY, r#"{"error":"not sent"}"#)
        }
        Err(_) => (StatusCode::BAD_GATEWAY, r#"{"error":"not sent"}"#),
    }
}

/// The HTTP application. Serve it with `into_make_service_with_connect_info::<SocketAddr>()`.
pub fn app(mailer: Arc<dyn Mailer>, limits: Limits) -> Router {
    let st = Arc::new(State_ {
        mailer,
        limits,
        seen: Mutex::new(HashMap::new()),
        day: Mutex::new(Vec::new()),
    });
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/api/contact", post(submit))
        .route("/v1/contact", post(submit))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(st)
}
