//! Firestore persistence for in-flight login codes -- `login_codes/{sha256(email)}`,
//! same one-time-reveal shape as a freshly issued key.

use serde_json::{json, Value};

const COLLECTION: &str = "login_codes";

fn doc_id(email: &str) -> String {
    hex::encode(blake3::hash(email.trim().to_lowercase().as_bytes()).as_bytes())
}

fn login_code_fields(code_hash: &str, slug: &str, created_at_secs: u64, attempts: u32) -> Value {
    json!({
        "fields": {
            "code_hash": {"stringValue": code_hash},
            "slug": {"stringValue": slug},
            "created_at": {"integerValue": created_at_secs.to_string()},
            "attempts": {"integerValue": attempts.to_string()},
        }
    })
}

struct LoginCodeDoc {
    code_hash: String,
    slug: String,
    created_at_secs: u64,
    attempts: u32,
}

fn parse_login_code_fields(doc: &Value) -> Option<LoginCodeDoc> {
    let f = doc.get("fields")?;
    let code_hash = f
        .get("code_hash")?
        .get("stringValue")?
        .as_str()?
        .to_string();
    let slug = f.get("slug")?.get("stringValue")?.as_str()?.to_string();
    let created_at_secs = f
        .get("created_at")?
        .get("integerValue")?
        .as_str()?
        .parse()
        .ok()?;
    let attempts = f
        .get("attempts")
        .and_then(|v| v.get("integerValue"))
        .and_then(|v| v.as_str())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    Some(LoginCodeDoc {
        code_hash,
        slug,
        created_at_secs,
        attempts,
    })
}

/// The maximum number of wrong-code attempts before a code is invalidated
/// outright, regardless of TTL -- bounds brute-forcing the 6-digit space
/// within the 10-minute window.
const MAX_ATTEMPTS: u32 = 5;

pub(crate) async fn save_login_code(
    email: &str,
    code_hash: &str,
    slug: &str,
    created_at_secs: u64,
) -> bool {
    let Some(proj) = crate::persistence::project() else {
        return false;
    };
    let client = reqwest::Client::new();
    let Some(token) = crate::persistence::access_token(&client).await else {
        return false;
    };
    let url = format!(
        "{}/{COLLECTION}/{}",
        crate::persistence::base_url(&proj),
        doc_id(email)
    );
    client
        .patch(&url)
        .bearer_auth(token)
        .header("Content-Type", "application/json")
        .json(&login_code_fields(code_hash, slug, created_at_secs, 0))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

/// Checks `code` against the stored code for `email`. On a correct code,
/// deletes the doc (one-time use) and returns the slug. On a wrong code,
/// increments the attempt counter (deleting the doc outright once
/// `MAX_ATTEMPTS` is reached) and returns `None`.
pub(crate) async fn verify_and_consume_login_code(
    email: &str,
    code: &str,
    now_secs: u64,
) -> Option<String> {
    let proj = crate::persistence::project()?;
    let client = reqwest::Client::new();
    let token = crate::persistence::access_token(&client).await?;
    let url = format!(
        "{}/{COLLECTION}/{}",
        crate::persistence::base_url(&proj),
        doc_id(email)
    );
    let resp = client.get(&url).bearer_auth(&token).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let doc: Value = resp.json().await.ok()?;
    let parsed = parse_login_code_fields(&doc)?;

    if !super::auth::is_code_within_ttl(parsed.created_at_secs, now_secs) {
        let _ = client.delete(&url).bearer_auth(&token).send().await;
        return None;
    }

    let code_hash = crate::admin::crypto::hash_key(code);
    if code_hash == parsed.code_hash {
        let _ = client.delete(&url).bearer_auth(&token).send().await;
        return Some(parsed.slug);
    }

    if parsed.attempts + 1 >= MAX_ATTEMPTS {
        let _ = client.delete(&url).bearer_auth(&token).send().await;
    } else {
        let _ = client
            .patch(&url)
            .bearer_auth(&token)
            .header("Content-Type", "application/json")
            .json(&login_code_fields(
                &parsed.code_hash,
                &parsed.slug,
                parsed.created_at_secs,
                parsed.attempts + 1,
            ))
            .send()
            .await;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_its_firestore_field_shape() {
        let fields = login_code_fields("hash123", "acme", 1_700_000_000, 2);
        let parsed = parse_login_code_fields(&fields).expect("should parse");
        assert_eq!(parsed.code_hash, "hash123");
        assert_eq!(parsed.slug, "acme");
        assert_eq!(parsed.created_at_secs, 1_700_000_000);
        assert_eq!(parsed.attempts, 2);
    }

    #[test]
    fn missing_attempts_field_defaults_to_zero() {
        let mut fields = login_code_fields("hash123", "acme", 1_700_000_000, 0);
        fields["fields"].as_object_mut().unwrap().remove("attempts");
        let parsed = parse_login_code_fields(&fields).expect("should parse");
        assert_eq!(parsed.attempts, 0);
    }

    #[test]
    fn rejects_a_document_missing_required_fields() {
        assert!(parse_login_code_fields(&serde_json::json!({"fields": {}})).is_none());
    }

    #[test]
    fn doc_id_is_deterministic_and_case_insensitive() {
        assert_eq!(doc_id("Person@Example.com"), doc_id("person@example.com"));
    }

    #[test]
    fn doc_id_differs_per_email() {
        assert_ne!(doc_id("alice@example.com"), doc_id("bob@example.com"));
    }
}
