//! The sequencer's pull-and-process step: drains a batch from a
//! [`Subscriber`], ingests each message into a [`ProtoState`], and acks
//! only the ones that were actually durably accepted. A message that fails
//! to parse or ingest is left un-acked, so Pub/Sub redelivers it later
//! rather than the record silently vanishing. See
//! `a stage record (not published)`.

use serde::Deserialize;

use entropa_core::transparency_log::encode_record;

use crate::pull_subscriber::Subscriber;
use crate::transparency_proto::ProtoState;

#[derive(Deserialize)]
struct QueuedMessage {
    partner: String,
    payload: String,
    #[serde(default)]
    label: Option<String>,
}

/// Process one pulled batch: parse each message, ingest its payload, ack
/// only the ones that succeeded. Returns how many were successfully
/// ingested, for the caller's own logging/metrics.
pub async fn drain_and_process<S: Subscriber>(
    state: &ProtoState,
    subscriber: &S,
    max_messages: usize,
) -> Result<usize, String> {
    let messages = subscriber.pull(max_messages).await?;
    let mut succeeded_ack_ids = Vec::new();
    let mut succeeded_count = 0;

    for message in messages {
        let Ok(parsed) = serde_json::from_slice::<QueuedMessage>(&message.data) else {
            // Malformed message: leave it un-acked so it isn't silently
            // dropped -- Pub/Sub will redeliver it, and a human/alert can
            // investigate a message that keeps failing to parse.
            continue;
        };
        let Ok(record) = encode_record(&parsed.payload, parsed.label.as_deref()) else {
            // Oversized field: same treatment as a malformed message (left un-acked).
            continue;
        };
        if state.ingest(&parsed.partner, &record).await.is_ok() {
            succeeded_ack_ids.push(message.ack_id);
            succeeded_count += 1;
        }
        // An ingest failure (e.g. Firestore unreachable) also leaves the
        // message un-acked for the same reason -- never ack a message
        // whose record wasn't actually durably written.
    }

    subscriber.ack(&succeeded_ack_ids).await?;
    Ok(succeeded_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pull_subscriber::FakeSubscriber;

    #[tokio::test]
    async fn drains_and_ingests_every_valid_message_in_order() {
        let state = ProtoState::new();
        let sub = FakeSubscriber::default();
        sub.push("ack-1", br#"{"partner":"acme","payload":"alpha"}"#);
        sub.push("ack-2", br#"{"partner":"acme","payload":"beta"}"#);

        let processed = drain_and_process(&state, &sub, 10).await.unwrap();

        assert_eq!(processed, 2);
        assert_eq!(state.len("acme"), 2);
    }

    #[tokio::test]
    async fn acks_only_the_messages_it_actually_ingested() {
        let state = ProtoState::new();
        let sub = FakeSubscriber::default();
        sub.push("ack-good", br#"{"partner":"acme","payload":"real"}"#);
        sub.push("ack-bad", b"not valid json at all");

        let processed = drain_and_process(&state, &sub, 10).await.unwrap();

        assert_eq!(processed, 1);
        assert_eq!(*sub.acked.lock().unwrap(), vec!["ack-good".to_string()]);
    }

    #[tokio::test]
    async fn a_malformed_message_does_not_block_processing_the_rest_of_the_batch() {
        let state = ProtoState::new();
        let sub = FakeSubscriber::default();
        sub.push("ack-1", b"garbage");
        sub.push(
            "ack-2",
            br#"{"partner":"acme","payload":"still-processed"}"#,
        );

        let processed = drain_and_process(&state, &sub, 10).await.unwrap();

        assert_eq!(processed, 1);
        assert_eq!(state.len("acme"), 1);
    }

    #[tokio::test]
    async fn an_empty_queue_processes_nothing_without_error() {
        let state = ProtoState::new();
        let sub = FakeSubscriber::default();
        let processed = drain_and_process(&state, &sub, 10).await.unwrap();
        assert_eq!(processed, 0);
    }
}
