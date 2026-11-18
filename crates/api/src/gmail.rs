//! Sends email as `aimozart@entropa.space` via Gmail API domain-wide delegation --
//! the service account (`entropa-gmail-ops`) never has its own mailbox, it's
//! authorized to act *as* that real Workspace user. Used for customer login codes
//! and dashboard-originated support contact.
//!
//! Private-only -- not mirrored to `entropa-public`.

use base64::Engine;
use serde_json::{json, Value};

const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

fn build_jwt_claims(
    sa_email: &str,
    impersonate: &str,
    scope: &str,
    now_secs: u64,
    ttl_secs: u64,
) -> Value {
    json!({
        "iss": sa_email,
        "sub": impersonate,
        "scope": scope,
        "aud": TOKEN_URL,
        "iat": now_secs,
        "exp": now_secs + ttl_secs,
    })
}

/// Builds a minimal RFC 2822 message and base64url-encodes it (no padding) --
/// the exact shape Gmail API's `users.messages.send` expects in its `raw` field.
/// Email headers (RFC 5322) must be ASCII -- a literal UTF-8 em-dash or any
/// other non-ASCII byte in a raw `Subject:` line gets misread as Latin-1 by
/// the receiving client (the classic "Ã¢Â€Â"" mojibake for U+2014). RFC 2047
/// encoded-words (`=?UTF-8?B?<base64>?=`) are the correct fix -- only applied
/// when actually needed, so a plain ASCII subject stays untouched/readable.
fn encode_header_value(s: &str) -> String {
    if s.is_ascii() {
        s.to_string()
    } else {
        format!(
            "=?UTF-8?B?{}?=",
            base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
        )
    }
}

fn build_raw_email(from: &str, to: &str, subject: &str, body: &str) -> String {
    let subject = encode_header_value(subject);
    let message = format!(
        "From: {from}\r\nTo: {to}\r\nSubject: {subject}\r\nContent-Type: text/plain; charset=\"UTF-8\"\r\n\r\n{body}"
    );
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(message.as_bytes())
}

const SENDER: &str = "aimozart@entropa.space";
const SEND_SCOPE: &str = "https://www.googleapis.com/auth/gmail.send";
const TOKEN_TTL_SECS: u64 = 3600;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(serde::Deserialize)]
struct ServiceAccountKey {
    client_email: String,
    private_key: String,
}

#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
}

/// Exchanges a service-account JWT assertion for a short-lived OAuth token
/// impersonating `impersonate`, via domain-wide delegation. `sa_key_json` is the
/// full service-account JSON key (as issued by GCP), not just the private key.
async fn delegated_access_token(
    sa_key_json: &str,
    impersonate: &str,
    scope: &str,
) -> Option<String> {
    let key: ServiceAccountKey = serde_json::from_str(sa_key_json).ok()?;
    let claims = build_jwt_claims(
        &key.client_email,
        impersonate,
        scope,
        now_secs(),
        TOKEN_TTL_SECS,
    );
    let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(key.private_key.as_bytes()).ok()?;
    let assertion = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
        &claims,
        &encoding_key,
    )
    .ok()?;

    let client = reqwest::Client::new();
    let resp = client
        .post(TOKEN_URL)
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", &assertion),
        ])
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<TokenResponse>()
        .await
        .ok()
        .map(|t| t.access_token)
}

/// Sends an email as `aimozart@entropa.space` via Gmail API domain-wide delegation.
/// Fails soft (returns `false`) if `ENTROPA_GMAIL_SA_KEY` is unset or any step
/// fails -- callers treat email delivery as best-effort, never blocking the
/// underlying action (a login-code request, a support message) on it.
pub async fn send_email(to: &str, subject: &str, body: &str) -> bool {
    let Ok(sa_key_json) = std::env::var("ENTROPA_GMAIL_SA_KEY") else {
        eprintln!("gmail: ENTROPA_GMAIL_SA_KEY is unset, cannot send");
        return false;
    };
    let Some(token) = delegated_access_token(&sa_key_json, SENDER, SEND_SCOPE).await else {
        eprintln!("gmail: failed to obtain a delegated access token");
        return false;
    };
    let raw = build_raw_email(SENDER, to, subject, body);
    let client = reqwest::Client::new();
    let resp = client
        .post("https://gmail.googleapis.com/gmail/v1/users/me/messages/send")
        .bearer_auth(token)
        .json(&json!({ "raw": raw }))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await;
    match resp {
        Ok(r) if r.status().is_success() => true,
        Ok(r) => {
            let status = r.status();
            let body = r.text().await.unwrap_or_default();
            eprintln!("gmail: send rejected ({status}): {body}");
            false
        }
        Err(e) => {
            eprintln!("gmail: send request failed: {e}");
            false
        }
    }
}

const READ_SCOPE: &str = "https://www.googleapis.com/auth/gmail.readonly";

/// One search result: enough to confirm a message exists and skim what it says,
/// without pulling the full MIME body.
pub struct MessageSummary {
    pub id: String,
    pub subject: String,
    pub snippet: String,
    pub from: String,
    pub date: String,
}

/// Pulls message IDs out of a `users.messages.list` response. Returns an empty
/// vec for a query with zero matches (a real, valid outcome) or a malformed
/// response (nothing to walk).
fn parse_message_list(list_json: &Value) -> Vec<String> {
    list_json
        .get("messages")
        .and_then(|m| m.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| m.get("id").and_then(|v| v.as_str()).map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Extracts the fields worth showing from a `users.messages.get` (metadata format)
/// response. `None` for a response missing its own `id` (nothing meaningful to show).
fn parse_message_summary(msg_json: &Value) -> Option<MessageSummary> {
    let id = msg_json.get("id")?.as_str()?.to_string();
    let snippet = msg_json
        .get("snippet")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let header = |name: &str| -> String {
        msg_json
            .get("payload")
            .and_then(|p| p.get("headers"))
            .and_then(|h| h.as_array())
            .and_then(|headers| {
                headers.iter().find(|h| {
                    h.get("name")
                        .and_then(|n| n.as_str())
                        .map(|n| n.eq_ignore_ascii_case(name))
                        .unwrap_or(false)
                })
            })
            .and_then(|h| h.get("value"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    Some(MessageSummary {
        id,
        subject: header("Subject"),
        from: header("From"),
        date: header("Date"),
        snippet,
    })
}

/// Searches `aimozart@entropa.space`'s inbox via domain-wide delegation
/// (`gmail.readonly` scope) and returns up to `max_results` matching message
/// summaries, most recent first (Gmail's own default ordering). Fails soft
/// (empty vec) if `ENTROPA_GMAIL_SA_KEY` is unset, the readonly scope hasn't
/// been granted yet, or any network step fails -- same posture as `send_email`.
pub async fn search_recent(query: &str, max_results: u32) -> Vec<MessageSummary> {
    let Ok(sa_key_json) = std::env::var("ENTROPA_GMAIL_SA_KEY") else {
        eprintln!("gmail: ENTROPA_GMAIL_SA_KEY is unset, cannot search");
        return Vec::new();
    };
    let Some(token) = delegated_access_token(&sa_key_json, SENDER, READ_SCOPE).await else {
        eprintln!("gmail: failed to obtain a delegated read access token");
        return Vec::new();
    };
    let client = reqwest::Client::new();
    let list_resp = client
        .get("https://gmail.googleapis.com/gmail/v1/users/me/messages")
        .bearer_auth(&token)
        .query(&[("q", query), ("maxResults", &max_results.to_string())])
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await;
    let Ok(list_resp) = list_resp else {
        eprintln!("gmail: message-list request failed");
        return Vec::new();
    };
    if !list_resp.status().is_success() {
        let status = list_resp.status();
        let body = list_resp.text().await.unwrap_or_default();
        eprintln!("gmail: message-list rejected ({status}): {body}");
        return Vec::new();
    }
    let Ok(list_json) = list_resp.json::<Value>().await else {
        return Vec::new();
    };
    let ids = parse_message_list(&list_json);

    let mut summaries = Vec::new();
    for id in ids {
        let get_resp = client
            .get(format!(
                "https://gmail.googleapis.com/gmail/v1/users/me/messages/{id}"
            ))
            .bearer_auth(&token)
            .query(&[
                ("format", "metadata"),
                ("metadataHeaders", "Subject"),
                ("metadataHeaders", "From"),
                ("metadataHeaders", "Date"),
            ])
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await;
        let Ok(get_resp) = get_resp else { continue };
        if !get_resp.status().is_success() {
            continue;
        }
        let Ok(msg_json) = get_resp.json::<Value>().await else {
            continue;
        };
        if let Some(summary) = parse_message_summary(&msg_json) {
            summaries.push(summary);
        }
    }
    summaries
}

#[cfg(test)]
mod parse_message_list_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extracts_ids_from_a_real_list_response() {
        let resp = json!({
            "messages": [{"id": "abc123", "threadId": "t1"}, {"id": "def456", "threadId": "t2"}],
            "resultSizeEstimate": 2
        });
        assert_eq!(parse_message_list(&resp), vec!["abc123", "def456"]);
    }

    #[test]
    fn a_zero_match_response_yields_an_empty_vec() {
        let resp = json!({"resultSizeEstimate": 0});
        assert!(parse_message_list(&resp).is_empty());
    }

    #[test]
    fn a_malformed_response_yields_an_empty_vec_not_a_panic() {
        let resp = json!({"unexpected": "shape"});
        assert!(parse_message_list(&resp).is_empty());
    }
}

#[cfg(test)]
mod parse_message_summary_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extracts_headers_and_snippet_from_a_real_metadata_response() {
        let resp = json!({
            "id": "abc123",
            "snippet": "Your login code is 482913...",
            "payload": {
                "headers": [
                    {"name": "Subject", "value": "Your Entropa login code"},
                    {"name": "From", "value": "Entropa <aimozart@entropa.space>"},
                    {"name": "Date", "value": "Wed, 26 Aug 2026 06:40:00 +0000"},
                ]
            }
        });
        let summary = parse_message_summary(&resp).expect("should parse");
        assert_eq!(summary.id, "abc123");
        assert_eq!(summary.subject, "Your Entropa login code");
        assert_eq!(summary.from, "Entropa <aimozart@entropa.space>");
        assert_eq!(summary.date, "Wed, 26 Aug 2026 06:40:00 +0000");
        assert_eq!(summary.snippet, "Your login code is 482913...");
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let resp = json!({
            "id": "abc123",
            "payload": {"headers": [{"name": "subject", "value": "lowercase header name"}]}
        });
        let summary = parse_message_summary(&resp).expect("should parse");
        assert_eq!(summary.subject, "lowercase header name");
    }

    #[test]
    fn missing_id_yields_none() {
        let resp = json!({"snippet": "no id here"});
        assert!(parse_message_summary(&resp).is_none());
    }

    #[test]
    fn missing_headers_yield_empty_strings_not_a_panic() {
        let resp = json!({"id": "abc123"});
        let summary = parse_message_summary(&resp).expect("should parse");
        assert_eq!(summary.subject, "");
        assert_eq!(summary.from, "");
    }
}

#[cfg(test)]
mod build_jwt_claims_tests {
    use super::*;

    #[test]
    fn carries_the_expected_fields() {
        let claims = build_jwt_claims(
            "entropa-gmail-ops@entropa-testnet.iam.gserviceaccount.com",
            "aimozart@entropa.space",
            "https://www.googleapis.com/auth/gmail.send",
            1_700_000_000,
            3600,
        );
        assert_eq!(
            claims["iss"],
            "entropa-gmail-ops@entropa-testnet.iam.gserviceaccount.com"
        );
        assert_eq!(claims["sub"], "aimozart@entropa.space");
        assert_eq!(
            claims["scope"],
            "https://www.googleapis.com/auth/gmail.send"
        );
        assert_eq!(claims["aud"], "https://oauth2.googleapis.com/token");
        assert_eq!(claims["iat"], 1_700_000_000);
        assert_eq!(claims["exp"], 1_700_003_600);
    }
}

#[cfg(test)]
mod build_raw_email_tests {
    use super::*;
    use base64::Engine;

    fn decode(raw: &str) -> String {
        String::from_utf8(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(raw)
                .expect("valid base64url"),
        )
        .expect("valid utf8")
    }

    #[test]
    fn produces_a_valid_rfc2822_message_base64url_encoded() {
        let raw = build_raw_email(
            "aimozart@entropa.space",
            "customer@example.com",
            "Your Entropa login code",
            "Your code is 123456.",
        );
        let decoded = decode(&raw);
        assert!(decoded.contains("From: aimozart@entropa.space"));
        assert!(decoded.contains("To: customer@example.com"));
        assert!(decoded.contains("Subject: Your Entropa login code"));
        assert!(decoded.contains("Your code is 123456."));
    }

    #[test]
    fn a_non_ascii_subject_is_rfc2047_encoded_not_left_as_raw_utf8() {
        // Real bug, 2026-08-26: a literal em-dash in the Subject header showed up as
        // mojibake ("Ã¢Â€Â"") in a real received email -- RFC 5322 headers must be
        // ASCII, and the raw UTF-8 bytes were being misread as Latin-1.
        let raw = build_raw_email(
            "aimozart@entropa.space",
            "customer@example.com",
            "Entropa Dashboard — pinnacle-financial",
            "body",
        );
        let decoded = decode(&raw);
        assert!(
            !decoded.contains("Subject: Entropa Dashboard —"),
            "the raw em-dash must never appear literally in a header line"
        );
        assert!(
            decoded.contains("Subject: =?UTF-8?B?"),
            "a non-ASCII subject must be wrapped as an RFC 2047 encoded-word"
        );
    }

    #[test]
    fn encoding_has_no_padding_or_url_unsafe_characters() {
        let raw = build_raw_email(
            "aimozart@entropa.space",
            "customer@example.com",
            "Subject with / and + risk??",
            "body",
        );
        assert!(!raw.contains('='));
        assert!(!raw.contains('+'));
        assert!(!raw.contains('/'));
    }
}
