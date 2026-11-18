//! Sends through the Gmail API with domain-wide delegation: the service account acts as one
//! Workspace user and mails the private inbox. The key and the addresses come from the environment.

use crate::{Mailer, Message};
use base64::Engine;
use serde_json::json;

const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const SEND_SCOPE: &str = "https://www.googleapis.com/auth/gmail.send";

/// Keep only the part of Google's error text that is safe to log: it can echo the signed assertion
/// (which carries addresses), so everything from the first `token:` or `eyJ` onward is dropped.
pub fn sanitize_description(d: &str) -> String {
    let cut = ["token:", "eyJ"]
        .iter()
        .filter_map(|m| d.find(m))
        .min()
        .unwrap_or(d.len());
    d[..cut]
        .chars()
        .filter(|c| !c.is_control())
        .take(80)
        .collect::<String>()
        .trim()
        .to_string()
}

/// Mailer using a service-account key (`GMAIL_SA_KEY`, full JSON), the user to act as
/// (`GMAIL_SENDER`) and the private inbox (`CONTACT_TO`).
pub struct GmailMailer {
    sa_key_json: Option<String>,
    sender: String,
    to: String,
}

#[derive(serde::Deserialize)]
struct Key {
    client_email: String,
    private_key: String,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl GmailMailer {
    /// Read the configuration from the environment; `None` if anything is missing.
    pub fn from_env() -> Option<GmailMailer> {
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        Some(GmailMailer {
            sa_key_json: get("GMAIL_SA_KEY"),
            sender: get("GMAIL_SENDER")?,
            to: get("CONTACT_TO")?,
        })
    }

    /// Sign the delegation assertion: with a key file when one is configured, otherwise keyless, using
    /// the service's own identity through the IAM Credentials API (needs Token Creator on itself).
    fn assertion(&self) -> Result<String, String> {
        if let Some(sa_key_json) = &self.sa_key_json {
            let key: Key = serde_json::from_str(sa_key_json).map_err(|_| "bad key".to_string())?;
            let claims = json!({"iss": key.client_email, "sub": self.sender, "scope": SEND_SCOPE, "aud": TOKEN_URL, "iat": now(), "exp": now() + 3600});
            let enc = jsonwebtoken::EncodingKey::from_rsa_pem(key.private_key.as_bytes())
                .map_err(|_| "bad key".to_string())?;
            return jsonwebtoken::encode(
                &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
                &claims,
                &enc,
            )
            .map_err(|_| "sign failed".to_string());
        }
        let meta = |path: &str| -> Result<String, String> {
            let r = reqwest::blocking::Client::new()
                .get(format!("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/{path}"))
                .header("Metadata-Flavor", "Google")
                .timeout(std::time::Duration::from_secs(5))
                .send()
                .map_err(|_| "metadata unreachable".to_string())?;
            r.text().map_err(|_| "metadata reply".to_string())
        };
        let email = meta("email")?.trim().to_string();
        let tok: serde_json::Value =
            serde_json::from_str(&meta("token")?).map_err(|_| "metadata token".to_string())?;
        let access = tok["access_token"]
            .as_str()
            .ok_or("no metadata token")?
            .to_string();
        let claims = json!({"iss": email, "sub": self.sender, "scope": SEND_SCOPE, "aud": TOKEN_URL, "iat": now(), "exp": now() + 3600});
        let resp = reqwest::blocking::Client::new()
            .post(format!("https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{email}:signJwt"))
            .bearer_auth(access)
            .json(&json!({ "payload": claims.to_string() }))
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .map_err(|_| "signJwt request failed".to_string())?;
        if !resp.status().is_success() {
            return Err(format!("signJwt status {}", resp.status().as_u16()));
        }
        let v: serde_json::Value = resp.json().map_err(|_| "signJwt reply".to_string())?;
        v["signedJwt"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| "no signedJwt".to_string())
    }

    fn token(&self) -> Result<String, String> {
        let jwt = self.assertion()?;
        let resp = reqwest::blocking::Client::new()
            .post(TOKEN_URL)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", jwt.as_str()),
            ])
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .map_err(|_| "token request failed".to_string())?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            // Google's error code is safe to log; the description is cut before anything that could echo the assertion.
            let v: serde_json::Value = resp.json().unwrap_or_default();
            let code: String = v["error"].as_str().unwrap_or("").chars().take(60).collect();
            let desc = sanitize_description(v["error_description"].as_str().unwrap_or(""));
            return Err(format!("token status {status}: {code} {desc}"));
        }
        let v: serde_json::Value = resp.json().map_err(|_| "token reply".to_string())?;
        v["access_token"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| "no token".to_string())
    }
}

impl Mailer for GmailMailer {
    fn send(&self, m: &Message) -> Result<(), String> {
        let raw = format!(
            "From: {}\r\nTo: {}\r\nReply-To: {}\r\nSubject: {}\r\nContent-Type: text/plain; charset=\"UTF-8\"\r\n\r\n{}",
            self.sender, self.to, m.reply_to, m.subject, m.body
        );
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw.as_bytes());
        let resp = reqwest::blocking::Client::new()
            .post("https://gmail.googleapis.com/gmail/v1/users/me/messages/send")
            .bearer_auth(self.token()?)
            .json(&json!({ "raw": raw }))
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .map_err(|_| "send request failed".to_string())?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("send status {}", resp.status().as_u16()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::sanitize_description;

    #[test]
    fn the_error_text_never_carries_the_assertion() {
        let d =
            "java.security.SignatureException: Invalid signature for token: eyJ0eXAiOiJKV1Qi.abc";
        let out = sanitize_description(d);
        assert!(out.contains("Invalid signature for"));
        assert!(!out.contains("eyJ"));
        assert!(!sanitize_description("x eyJabc").contains("eyJ"));
    }
}
