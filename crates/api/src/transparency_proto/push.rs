//! Pub/Sub push delivery for the sequencer — the mechanism that actually
//! lets `entropa-transparency` scale horizontally on Cloud Run. The prior
//! design ran an internal `tokio::spawn`'d pull loop inside one long-running
//! process; Cloud Run's autoscaler has no visibility into that loop, so
//! raising `max-instances` alone would never actually add capacity under
//! load. Push delivery makes each message a real incoming HTTP request,
//! which is the signal Cloud Run's autoscaler responds to.
//!
//! Safety under concurrency comes from Pub/Sub's per-key ordering guarantee
//! (see `pubsub::Publisher::publish`'s doc comment), not from anything in
//! this file — Pub/Sub itself never delivers two messages for the same
//! ordering key (a customer's slug) to more than one outstanding request at
//! a time, so two `entropa-transparency` instances can never race on the
//! same customer's in-memory tree.
//!
//! Authentication is a shared-secret query-string token rather than full
//! Pub/Sub OIDC-JWT verification (Google's own documented alternative for a
//! push endpoint that isn't otherwise IAM-protected) — this service stays
//! `--allow-unauthenticated` overall since it also serves public reads
//! (`/api/receipt`, `/api/chain`), so gating the whole service behind IAM
//! isn't an option; the token is known only to this service's own env and
//! the Pub/Sub push subscription's configured endpoint URL.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use serde::Deserialize;

use entropa_core::transparency_log::encode_record;

use super::state::ProtoState;

#[derive(Deserialize)]
pub(super) struct PushAuth {
    token: String,
}

#[derive(Deserialize)]
struct PushEnvelope {
    message: PushMessage,
}

#[derive(Deserialize)]
struct PushMessage {
    data: String,
}

#[derive(Deserialize)]
struct QueuedMessage {
    partner: String,
    payload: String,
    #[serde(default)]
    label: Option<String>,
}

/// Pure: does the request's token match the configured push secret? `None`
/// (push not configured at all) always rejects -- there is no "open" default
/// the way `/api/tx`'s bearer auth has for local/dev convenience, since a
/// misconfigured push endpoint would let anyone forge submissions into a
/// customer's tree.
pub(super) fn push_token_is_valid(provided: &str, expected: Option<&str>) -> bool {
    expected.is_some_and(|e| !e.is_empty() && provided == e)
}

/// Pure: decode a Pub/Sub push envelope into `(partner, record_bytes)`,
/// ready for `ProtoState::ingest`. Separated from the handler so the actual
/// parsing logic is directly unit-testable without a real HTTP round trip.
fn decode_push_body(body: &[u8]) -> Result<(String, Vec<u8>), String> {
    let envelope: PushEnvelope = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&envelope.message.data)
        .map_err(|e| e.to_string())?;
    let queued: QueuedMessage = serde_json::from_slice(&decoded).map_err(|e| e.to_string())?;
    let record =
        encode_record(&queued.payload, queued.label.as_deref()).map_err(|e| e.to_string())?;
    Ok((queued.partner, record))
}

/// `POST /internal/pubsub-push?token=...` -- Pub/Sub calls this directly.
/// Any non-2xx response tells Pub/Sub to redeliver, so a failure at any
/// step here (bad token, malformed body, ingest failure) simply returns an
/// error status rather than needing an explicit un-ack call the way the old
/// pull-based `sequencer::drain_and_process` did.
pub(super) async fn pubsub_push(
    State(state): State<ProtoState>,
    Query(auth): Query<PushAuth>,
    body: axum::body::Bytes,
) -> StatusCode {
    let expected = std::env::var("ENTROPA_PUBSUB_PUSH_TOKEN").ok();
    if !push_token_is_valid(&auth.token, expected.as_deref()) {
        return StatusCode::UNAUTHORIZED;
    }
    let Ok((partner, record)) = decode_push_body(&body) else {
        return StatusCode::BAD_REQUEST;
    };
    match state.ingest(&partner, &record).await {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_matching_token_is_valid() {
        assert!(push_token_is_valid("real-secret", Some("real-secret")));
    }

    #[test]
    fn a_wrong_token_is_rejected() {
        assert!(!push_token_is_valid("guessed", Some("real-secret")));
    }

    #[test]
    fn push_is_rejected_when_no_secret_is_configured_at_all() {
        assert!(!push_token_is_valid("anything", None));
    }

    #[test]
    fn an_empty_configured_secret_never_validates_anything() {
        // Guards against a misconfigured empty env var silently becoming an
        // "auth always passes" hole.
        assert!(!push_token_is_valid("", Some("")));
        assert!(!push_token_is_valid("x", Some("")));
    }

    fn real_pubsub_envelope(partner: &str, payload: &str) -> Vec<u8> {
        use base64::Engine;
        let inner = serde_json::json!({ "partner": partner, "payload": payload });
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(inner.to_string().as_bytes());
        serde_json::json!({
            "message": { "data": encoded, "messageId": "123", "orderingKey": partner },
            "subscription": "projects/p/subscriptions/s",
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn decodes_a_real_pubsub_push_envelope_shape() {
        let body = real_pubsub_envelope("acme-corp", "deadbeef");
        let (partner, record) = decode_push_body(&body).unwrap();
        assert_eq!(partner, "acme-corp");
        let (payload, label) = entropa_core::transparency_log::decode_record(&record).unwrap();
        assert_eq!(payload, "deadbeef");
        assert_eq!(label, None);
    }

    #[test]
    fn rejects_a_body_that_isnt_a_pubsub_envelope_at_all() {
        assert!(decode_push_body(b"not json").is_err());
    }

    #[test]
    fn rejects_a_message_data_field_that_isnt_valid_base64() {
        let body = serde_json::json!({
            "message": { "data": "not-base64!!!" },
        })
        .to_string();
        assert!(decode_push_body(body.as_bytes()).is_err());
    }
}
