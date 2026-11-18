//! Shared GCP plumbing (auth, HTTP client reuse) used by every module that talks
//! to Firestore directly — `transparency_persistence`, `admin::store`,
//! `dashboard::store`, `pubsub`, `pull_subscriber`.
//!
//! Deliberately minimal: no cloud SDK, just the Firestore REST API authenticated
//! via the Cloud Run metadata server's Application Default Credentials. Entirely
//! optional: if `GCP_PROJECT` isn't set (e.g. local `cargo run`), or the metadata
//! server isn't reachable (anywhere off Cloud Run/GCE), every call fails soft.

pub(crate) fn project() -> Option<String> {
    std::env::var("GCP_PROJECT").ok()
}

pub(crate) fn base_url(project: &str) -> String {
    format!("https://firestore.googleapis.com/v1/projects/{project}/databases/(default)/documents")
}

/// Whether a cached token is still safe to reuse. `margin_secs` gives up a token
/// slightly before its real expiry so a token doesn't expire mid-request.
pub(crate) fn token_is_still_fresh(
    expires_at_epoch_secs: u64,
    now_epoch_secs: u64,
    margin_secs: u64,
) -> bool {
    now_epoch_secs + margin_secs < expires_at_epoch_secs
}

struct CachedToken {
    value: String,
    expires_at_epoch_secs: u64,
}

static TOKEN_CACHE: std::sync::OnceLock<std::sync::Mutex<Option<CachedToken>>> =
    std::sync::OnceLock::new();
static SHARED_CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();

/// A shared, reused HTTP client -- every one of this project's GCP REST calls used
/// to construct a brand-new `reqwest::Client` per call, discarding connection
/// keep-alive every single time. Under real concurrent load (the 2026-08-25
/// elastic-ingest-tier load test) this measurably hurt throughput; reusing one
/// client is free and has no downside.
pub(crate) fn http_client() -> &'static reqwest::Client {
    SHARED_CLIENT.get_or_init(reqwest::Client::new)
}

fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

const METADATA_TOKEN_URL: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";

/// Same real problem as `http_client`: this used to fetch a fresh token from the
/// metadata server on *every single call*, which is a real network round trip
/// (found to measurably contribute to latency/503s under the 2026-08-25 load
/// test, alongside the fresh-client issue above). ADC tokens are valid for a full
/// hour; caching with a safety margin removes almost all of that cost for free.
pub(crate) async fn access_token(client: &reqwest::Client) -> Option<String> {
    let cache = TOKEN_CACHE.get_or_init(|| std::sync::Mutex::new(None));
    {
        let guard = cache.lock().unwrap();
        if let Some(cached) = guard.as_ref() {
            if token_is_still_fresh(cached.expires_at_epoch_secs, now_epoch_secs(), 60) {
                return Some(cached.value.clone());
            }
        }
    }

    #[derive(serde::Deserialize)]
    struct TokenResponse {
        access_token: String,
        expires_in: u64,
    }
    let resp = client
        .get(METADATA_TOKEN_URL)
        .header("Metadata-Flavor", "Google")
        .timeout(std::time::Duration::from_secs(2))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let parsed: TokenResponse = resp.json().await.ok()?;
    let mut guard = cache.lock().unwrap();
    *guard = Some(CachedToken {
        value: parsed.access_token.clone(),
        expires_at_epoch_secs: now_epoch_secs() + parsed.expires_in,
    });
    Some(parsed.access_token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_well_before_expiry_is_still_fresh() {
        assert!(token_is_still_fresh(1_000, 500, 60));
    }

    #[test]
    fn a_token_past_its_expiry_is_not_fresh() {
        assert!(!token_is_still_fresh(1_000, 1_001, 60));
    }

    #[test]
    fn a_token_inside_the_safety_margin_is_not_fresh() {
        // Expires at 1000, now is 950, margin is 60 -- only 50s of real life left,
        // less than the 60s margin, so treat it as already expired.
        assert!(!token_is_still_fresh(1_000, 950, 60));
    }

    #[test]
    fn a_token_exactly_at_the_margin_boundary_is_not_fresh() {
        assert!(!token_is_still_fresh(1_000, 940, 60));
    }
}
