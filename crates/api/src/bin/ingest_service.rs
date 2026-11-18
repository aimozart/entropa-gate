//! The elastic ingest tier — stateless, scales fully on Cloud Run. Validates a
//! submission, publishes it to Pub/Sub, returns `202` + a tracking ID immediately.
//! See `a stage record (not published)`.

use entropa_api::ingest::{router, IngestState};
use entropa_api::partner_directory::CachedPartnerDirectory;
use entropa_api::pubsub::PubSubPublisher;

#[tokio::main]
async fn main() {
    let topic =
        std::env::var("ENTROPA_PUBSUB_TOPIC").unwrap_or_else(|_| "entropa-submissions".to_string());
    println!("📤 ingest tier live, publishing to topic={topic}");

    let state = IngestState::new(PubSubPublisher { topic }, CachedPartnerDirectory::default());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080")
        .await
        .expect("bind :8080");
    println!("📥 Ingest tier live at http://localhost:8080 — stateless, elastic, auth required");
    axum::serve(listener, router(state)).await.expect("serve");
}
