//! Passwordless customer login: a 6-digit emailed code exchanged for a signed,
//! stateless bearer session token -- no cookies (this dashboard is a static,
//! cross-origin page), no passwords, no server-side session store to manage.

use hmac::{Hmac, Mac};
use sha2::Sha256;

pub const LOGIN_CODE_TTL_SECS: u64 = 600;
const SESSION_TTL_SECS: u64 = 86_400;

pub fn generate_login_code() -> String {
    use rand::Rng;
    format!("{:06}", rand::thread_rng().gen_range(0..1_000_000))
}

pub fn is_code_within_ttl(created_at_secs: u64, now_secs: u64) -> bool {
    now_secs.saturating_sub(created_at_secs) <= LOGIN_CODE_TTL_SECS
}

fn hmac_hex(secret: &str, message: &str) -> Option<String> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(message.as_bytes());
    Some(hex::encode(mac.finalize().into_bytes()))
}

/// Signs a stateless session token for `slug`, expiring at `expires_at_secs`.
/// Format is deliberately plain (`slug.expires_at.hmac`), not base64 -- a slug
/// is already a public identifier (it's in the API's own URLs), so there's
/// nothing to hide, only tampering to detect.
pub fn sign_session(slug: &str, expires_at_secs: u64, secret: &str) -> String {
    let signed_part = format!("{slug}.{expires_at_secs}");
    let mac = hmac_hex(secret, &signed_part).unwrap_or_default();
    format!("{signed_part}.{mac}")
}

/// Verifies a session token, returning the slug it was issued for if the
/// signature is genuine and it hasn't expired. Rejects (never panics on) a
/// malformed token, a tampered slug/expiry, or the wrong secret.
pub fn verify_session(token: &str, secret: &str, now_secs: u64) -> Option<String> {
    let parts: Vec<&str> = token.split('.').collect();
    let [slug, expires_at_str, received_mac] = parts[..] else {
        return None;
    };
    let expires_at: u64 = expires_at_str.parse().ok()?;
    if now_secs > expires_at {
        return None;
    }
    let expected_mac = hmac_hex(secret, &format!("{slug}.{expires_at_str}"))?;
    if expected_mac != received_mac {
        return None;
    }
    Some(slug.to_string())
}

/// Convenience for callers that just want "give me a fresh valid session
/// token for this slug right now" without threading expiry math through.
pub fn new_session_for(slug: &str, now_secs: u64, secret: &str) -> String {
    sign_session(slug, now_secs + SESSION_TTL_SECS, secret)
}

#[cfg(test)]
mod generate_login_code_tests {
    use super::*;

    #[test]
    fn produces_a_six_digit_numeric_code() {
        let code = generate_login_code();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn is_random_each_time() {
        assert_ne!(generate_login_code(), generate_login_code());
    }
}

#[cfg(test)]
mod is_code_within_ttl_tests {
    use super::*;

    #[test]
    fn a_fresh_code_is_within_the_window() {
        assert!(is_code_within_ttl(1_700_000_000, 1_700_000_010));
    }

    #[test]
    fn exactly_at_the_ttl_boundary_is_still_valid() {
        assert!(is_code_within_ttl(
            1_700_000_000,
            1_700_000_000 + LOGIN_CODE_TTL_SECS
        ));
    }

    #[test]
    fn past_the_ttl_is_rejected() {
        assert!(!is_code_within_ttl(
            1_700_000_000,
            1_700_000_000 + LOGIN_CODE_TTL_SECS + 1
        ));
    }
}

#[cfg(test)]
mod session_tests {
    use super::*;

    #[test]
    fn a_genuine_session_verifies_and_returns_the_slug() {
        let token = sign_session("acme", 1_700_003_600, "secret");
        assert_eq!(
            verify_session(&token, "secret", 1_700_000_000),
            Some("acme".to_string())
        );
    }

    #[test]
    fn an_expired_session_is_rejected() {
        let token = sign_session("acme", 1_700_000_000, "secret");
        assert_eq!(verify_session(&token, "secret", 1_700_000_001), None);
    }

    #[test]
    fn a_tampered_slug_is_rejected() {
        let token = sign_session("acme", 1_700_003_600, "secret");
        let tampered = token.replacen("acme", "evilco", 1);
        assert_eq!(verify_session(&tampered, "secret", 1_700_000_000), None);
    }

    #[test]
    fn a_tampered_expiry_is_rejected() {
        let token = sign_session("acme", 1_700_003_600, "secret");
        let tampered = token.replacen("1700003600", "9999999999", 1);
        assert_eq!(verify_session(&tampered, "secret", 1_700_000_000), None);
    }

    #[test]
    fn the_wrong_secret_is_rejected() {
        let token = sign_session("acme", 1_700_003_600, "right-secret");
        assert_eq!(verify_session(&token, "wrong-secret", 1_700_000_000), None);
    }

    #[test]
    fn a_malformed_token_never_panics() {
        assert_eq!(verify_session("not-a-real-token", "secret", 0), None);
        assert_eq!(verify_session("", "secret", 0), None);
    }
}
