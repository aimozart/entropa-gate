//! The elastic ingest tier's handler — authenticates a customer, validates and hands
//! off a submission to a [`Publisher`], returning `202 Accepted` + a tracking ID
//! immediately. Holds no shared mutable state itself beyond a rate-limit map, which is
//! what actually lets Cloud Run scale this tier elastically. See
//! `a stage record (not published)`.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::admin::model::PartnerRecord;
use crate::partner_directory::PartnerDirectory;
use crate::pubsub::Publisher;

pub(crate) struct RateBucket {
    tokens: f64,
    last_refill: std::time::Instant,
}

pub(crate) const PER_KEY_RATE: f64 = 20.0;
pub(crate) const PER_KEY_BURST: f64 = 20.0;

/// `true` if the request is allowed (and consumes a token); `false` if this partner is
/// over their own rate limit right now. Independent per partner — one partner maxing out
/// their budget has zero effect on any other partner's.
pub(crate) fn check_per_key_rate_limit(
    buckets: &Mutex<HashMap<String, RateBucket>>,
    key: &str,
) -> bool {
    let mut map = buckets.lock().unwrap();
    let now = std::time::Instant::now();
    let bucket = map.entry(key.to_string()).or_insert_with(|| RateBucket {
        tokens: PER_KEY_BURST,
        last_refill: now,
    });
    let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
    bucket.tokens = (bucket.tokens + elapsed * PER_KEY_RATE).min(PER_KEY_BURST);
    bucket.last_refill = now;
    if bucket.tokens >= 1.0 {
        bucket.tokens -= 1.0;
        true
    } else {
        false
    }
}

pub struct IngestState<P: Publisher, D: PartnerDirectory> {
    pub publisher: Arc<P>,
    pub directory: Arc<D>,
    pub(crate) rate_buckets: Arc<Mutex<HashMap<String, RateBucket>>>,
}

impl<P: Publisher, D: PartnerDirectory> IngestState<P, D> {
    pub fn new(publisher: P, directory: D) -> Self {
        Self {
            publisher: Arc::new(publisher),
            directory: Arc::new(directory),
            rate_buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

// Manual `Clone` -- everything here is already `Arc`-wrapped and cheap to clone
// regardless of whether `P`/`D` themselves implement `Clone`.
impl<P: Publisher, D: PartnerDirectory> Clone for IngestState<P, D> {
    fn clone(&self) -> Self {
        Self {
            publisher: self.publisher.clone(),
            directory: self.directory.clone(),
            rate_buckets: self.rate_buckets.clone(),
        }
    }
}

#[derive(Deserialize)]
struct SubmitRequest {
    payload: String,
    /// Optional, customer-disclosed metadata (e.g. "loan-underwriting:approved")
    /// -- never the customer's actual sensitive decision content, which stays
    /// as an opaque hash in `payload`. Meant to be generated automatically by
    /// the customer's own AI agent as part of the same submission call, not a
    /// manual annotation step. Folded into the same Merkle leaf as the
    /// payload (see `entropa_core::transparency_log::encode_record`), so it's
    /// just as tamper-evident as the hash itself.
    #[serde(default)]
    label: Option<String>,
}

#[derive(Serialize)]
struct SubmitAccepted {
    tracking_id: String,
    status: &'static str,
}

/// A pure, deterministic tracking ID — not a receipt (the record hasn't
/// been sequenced into the log yet), just a correlation handle. Derived
/// from the payload and submission time so two calls never collide.
fn make_tracking_id(payload: &str, submitted_at_nanos: u128) -> String {
    let mut input = Vec::new();
    input.extend_from_slice(payload.as_bytes());
    input.extend_from_slice(&submitted_at_nanos.to_be_bytes());
    let hash = blake3::hash(&input);
    hex::encode(&hash.as_bytes()[..16])
}

/// Extracts the raw bearer token from an `Authorization: Bearer <key>` header.
/// Pure and independently testable.
fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

async fn authenticate<D: PartnerDirectory>(
    directory: &D,
    headers: &HeaderMap,
) -> Result<PartnerRecord, StatusCode> {
    let token = extract_bearer_token(headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let partner = directory
        .authenticate(token)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)?;
    Ok(partner)
}

async fn submit<P: Publisher + 'static, D: PartnerDirectory + 'static>(
    State(state): State<IngestState<P, D>>,
    headers: HeaderMap,
    body: Result<Json<SubmitRequest>, axum::extract::rejection::JsonRejection>,
) -> axum::response::Response {
    let partner = match authenticate(&*state.directory, &headers).await {
        Ok(p) => p,
        Err(status) => return status.into_response(),
    };

    if !check_per_key_rate_limit(&state.rate_buckets, &partner.slug) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    let Json(req) = match body {
        Ok(json) => json,
        Err(rejection) => return (StatusCode::BAD_REQUEST, rejection.body_text()).into_response(),
    };
    let submitted_at_nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tracking_id = make_tracking_id(&req.payload, submitted_at_nanos);

    let message = serde_json::json!({
        "tracking_id": tracking_id,
        "payload": req.payload,
        "label": req.label,
        "submitted_at_nanos": submitted_at_nanos,
        "partner": partner.slug,
    });
    let data = match serde_json::to_vec(&message) {
        Ok(bytes) => bytes,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
    };

    match state.publisher.publish(&data, &partner.slug).await {
        Ok(_message_id) => (
            StatusCode::ACCEPTED,
            Json(SubmitAccepted {
                tracking_id,
                status: "queued",
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("could not queue submission: {e}"),
        )
            .into_response(),
    }
}

pub fn router<P: Publisher + 'static, D: PartnerDirectory + 'static>(
    state: IngestState<P, D>,
) -> Router {
    Router::new()
        .route("/api/tx", post(submit::<P, D>))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::partner_directory::FakePartnerDirectory;
    use crate::pubsub::FakePublisher;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    /// Regression test for per-key rate limiting: one partner exhausting their own
    /// budget must have zero effect on any other partner's budget -- the whole
    /// point of moving off a single shared global bucket.
    #[test]
    fn per_key_rate_limit_is_independent_per_partner() {
        let buckets: Mutex<HashMap<String, RateBucket>> = Mutex::new(HashMap::new());

        for _ in 0..(PER_KEY_BURST as usize) {
            assert!(check_per_key_rate_limit(&buckets, "acme"));
        }
        assert!(
            !check_per_key_rate_limit(&buckets, "acme"),
            "acme should be out of budget after exhausting its burst capacity"
        );
        assert!(
            check_per_key_rate_limit(&buckets, "other-partner"),
            "a different partner must be unaffected by acme's exhausted budget"
        );
    }

    fn test_partner() -> PartnerRecord {
        PartnerRecord {
            slug: "acme".to_string(),
            display_name: "Acme".to_string(),
            email: String::new(),
            api_key_hash: crate::admin::crypto::hash_key("test-key-123"),
            notes: String::new(),
        }
    }

    fn state_with(
        publisher: FakePublisher,
        partners: Vec<PartnerRecord>,
    ) -> IngestState<FakePublisher, FakePartnerDirectory> {
        IngestState {
            publisher: Arc::new(publisher),
            directory: Arc::new(FakePartnerDirectory { partners }),
            rate_buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn authed_request(body: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/api/tx")
            .header("content-type", "application/json")
            .header("authorization", "Bearer test-key-123")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    #[test]
    fn extract_bearer_token_reads_a_well_formed_header() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer abc123".parse().unwrap());
        assert_eq!(extract_bearer_token(&headers), Some("abc123"));
    }

    #[test]
    fn extract_bearer_token_returns_none_when_header_is_missing() {
        let headers = HeaderMap::new();
        assert_eq!(extract_bearer_token(&headers), None);
    }

    #[test]
    fn extract_bearer_token_returns_none_for_a_non_bearer_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Basic abc123".parse().unwrap());
        assert_eq!(extract_bearer_token(&headers), None);
    }

    #[tokio::test]
    async fn a_request_with_no_authorization_header_is_rejected() {
        let state = state_with(FakePublisher::default(), vec![test_partner()]);
        let resp = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/tx")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"payload":"x"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    fn second_partner() -> PartnerRecord {
        PartnerRecord {
            slug: "lapsed".to_string(),
            display_name: "Lapsed Co".to_string(),
            email: String::new(),
            api_key_hash: crate::admin::crypto::hash_key("lapsed-key"),
            notes: String::new(),
        }
    }

    /// the owner's decision (S0c2): Entropa has no billing, so ingest has no 402 path.
    /// This replaces `a_canceled_partners_key_is_rejected_with_payment_required`.
    #[tokio::test]
    async fn every_authenticated_partner_is_accepted_there_is_no_402_path() {
        let state = state_with(FakePublisher::default(), vec![second_partner()]);
        let resp = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/tx")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer lapsed-key")
                    .body(Body::from(r#"{"payload":"lands-now"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn a_request_with_an_unknown_key_is_rejected() {
        let state = state_with(FakePublisher::default(), vec![test_partner()]);
        let resp = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/tx")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer totally-wrong-key")
                    .body(Body::from(r#"{"payload":"x"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Stripe removal (S0c1): the log tier serves `/api/tx` only; the retired signup and
    /// Stripe routes must be gone, not merely unused.
    #[tokio::test]
    async fn the_ingest_router_serves_no_signup_or_stripe_routes() {
        for (method, uri) in [
            ("POST", "/api/signup"),
            ("POST", "/api/stripe/webhook"),
            ("GET", "/api/signup/status"),
        ] {
            let resp = router(state_with(FakePublisher::default(), vec![test_partner()]))
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{method} {uri}");
        }
    }

    #[tokio::test]
    async fn a_valid_submission_is_accepted_and_published() {
        let publisher = FakePublisher::default();
        let resp = router(state_with(publisher, vec![test_partner()]))
            .oneshot(authed_request(r#"{"payload":"real-payload"}"#))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["status"], "queued");
        assert!(!value["tracking_id"].as_str().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_valid_submission_actually_publishes_the_payload() {
        let publisher = FakePublisher::default();
        let state = state_with(publisher, vec![test_partner()]);
        let publisher_ref = state.publisher.clone();
        router(state)
            .oneshot(authed_request(r#"{"payload":"trace-me"}"#))
            .await
            .unwrap();
        let published = publisher_ref.published.lock().unwrap();
        assert_eq!(published.len(), 1);
        let msg: serde_json::Value = serde_json::from_slice(&published[0]).unwrap();
        assert_eq!(msg["payload"], "trace-me");
        assert_eq!(msg["partner"], "acme");
    }

    /// The real reason ordering keys exist: this is what lets multiple
    /// `entropa-transparency` instances run concurrently without ever racing
    /// on the same customer's in-memory tree -- Pub/Sub itself guarantees
    /// only one instance processes a given key's messages at a time.
    #[tokio::test]
    async fn a_submission_is_published_with_the_partners_slug_as_the_ordering_key() {
        let publisher = FakePublisher::default();
        let state = state_with(publisher, vec![test_partner()]);
        let publisher_ref = state.publisher.clone();
        router(state)
            .oneshot(authed_request(r#"{"payload":"trace-me"}"#))
            .await
            .unwrap();
        assert_eq!(*publisher_ref.ordering_keys.lock().unwrap(), vec!["acme"]);
    }

    #[tokio::test]
    async fn malformed_json_is_a_client_error_not_a_crash() {
        let state = state_with(FakePublisher::default(), vec![test_partner()]);
        let resp = router(state)
            .oneshot(authed_request("not json"))
            .await
            .unwrap();
        assert!(resp.status().is_client_error());
    }

    #[tokio::test]
    async fn a_publisher_failure_is_reported_as_service_unavailable() {
        let publisher = FakePublisher {
            always_fail: true,
            ..Default::default()
        };
        let state = state_with(publisher, vec![test_partner()]);
        let resp = router(state)
            .oneshot(authed_request(r#"{"payload":"doomed"}"#))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn exceeding_the_per_partner_rate_limit_returns_429() {
        let state = state_with(FakePublisher::default(), vec![test_partner()]);
        // PER_KEY_BURST is 20 -- the 21st rapid request from the same partner
        // must be rejected while everyone else's budget is untouched.
        let mut last_status = StatusCode::OK;
        for _ in 0..21 {
            let resp = router(state.clone())
                .oneshot(authed_request(r#"{"payload":"spam"}"#))
                .await
                .unwrap();
            last_status = resp.status();
        }
        assert_eq!(last_status, StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn a_rate_limited_request_never_reaches_the_publisher() {
        let publisher = FakePublisher::default();
        let state = state_with(publisher, vec![test_partner()]);
        let publisher_ref = state.publisher.clone();
        for _ in 0..21 {
            router(state.clone())
                .oneshot(authed_request(r#"{"payload":"spam"}"#))
                .await
                .unwrap();
        }
        // 20 allowed through, the 21st rejected before ever publishing.
        assert_eq!(publisher_ref.published.lock().unwrap().len(), 20);
    }
}
