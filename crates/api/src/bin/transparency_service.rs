//! The real transparency-log service — single writer, event-driven checkpointing, no
//! quorum/peer networking. See `a stage record (not published)`. Deployed
//! alongside the existing N=3 quorum validators, not replacing them yet — this stands
//! up independently so it can be verified live before anything old is decommissioned.
//!
//! Identity survives redeploys the same way the validators' does: `ENTROPA_PROBE_KEY`
//! loads a persisted key; unset falls back to a fresh one (fine for a first boot, but
//! a real deployment should set this so a customer's checkpoint-signer pubkey doesn't
//! change out from under them on every redeploy).

use entropa_api::transparency_proto::{router, ProtoState};
use entropa_core::pqc::Probe;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Single fixed epoch — this design deliberately has no epoch-rotation complexity
/// (that existed in the old chain to isolate a corrupted history's tail from a fresh
/// restart; the incremental frontier here doesn't carry the same rollback-recovery
/// concern, since a genuinely bad append would fail Merkle verification, not silently
/// corrupt unrelated history).
const EPOCH: &str = "epoch-1";

#[tokio::main]
async fn main() {
    let probe = match std::env::var("ENTROPA_PROBE_KEY") {
        Ok(key) if !key.trim().is_empty() => Probe::from_signing_key_hex(key.trim())
            .unwrap_or_else(|| {
                eprintln!(
                    "⚠️  ENTROPA_PROBE_KEY is set but not a valid key — falling back to a \
                     fresh identity"
                );
                Probe::spawn()
            }),
        _ => {
            eprintln!(
                "⚠️  ENTROPA_PROBE_KEY not set — using a fresh identity that will NOT survive \
                 a redeploy. Set it for any deployment customers actually rely on."
            );
            Probe::spawn()
        }
    };
    println!("🔑 transparency service identity: {}", probe.id());

    let state = ProtoState::resume(EPOCH, probe).await;

    // Deliberately alongside the existing HTTP /api/tx, not replacing it yet -- see
    // a stage record (not published)'s sequencing. Absent
    // ENTROPA_PUBSUB_SUBSCRIPTION (local/dev, or before the queue-fronted ingest tier
    // is cut over), the sequencer simply doesn't run a pull loop.
    if let Ok(subscription) = std::env::var("ENTROPA_PUBSUB_SUBSCRIPTION") {
        println!("📥 sequencer pull loop starting, subscription={subscription}");
        let sequencer_state = state.clone();
        let subscriber = entropa_api::pull_subscriber::PubSubSubscriber { subscription };
        tokio::spawn(async move {
            const HEARTBEAT_INTERVAL_SECS: u64 = 30;
            let mut last_heartbeat = now_secs();
            loop {
                match entropa_api::sequencer::drain_and_process(&sequencer_state, &subscriber, 20)
                    .await
                {
                    Ok(0) => tokio::time::sleep(std::time::Duration::from_secs(2)).await,
                    Ok(n) => println!("sequencer: processed {n} queued message(s)"),
                    Err(e) => {
                        eprintln!("sequencer: pull/process error: {e}");
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    }
                }
                let now = now_secs();
                if entropa_api::heartbeat::should_emit(last_heartbeat, now, HEARTBEAT_INTERVAL_SECS)
                {
                    println!(
                        "💓 sequencer alive — total_height={} customers={}",
                        sequencer_state.total_len(),
                        sequencer_state.partner_count()
                    );
                    last_heartbeat = now;
                }
            }
        });
    } else {
        println!(
            "ℹ️  ENTROPA_PUBSUB_SUBSCRIPTION not set — sequencer pull loop disabled, HTTP \
             /api/tx only"
        );
    }

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080")
        .await
        .expect("bind :8080");
    println!("🌳 Transparency log service live at http://localhost:8080 — Merkle log, no quorum");
    axum::serve(listener, router(state)).await.expect("serve");
}
