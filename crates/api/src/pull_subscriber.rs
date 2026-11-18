//! A pull seam for the sequencer, paired with `pubsub::Publisher` on the
//! ingest side — real Pub/Sub pull+ack over REST, plus a fake for tests.
//! See `a stage record (not published)`.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PulledMessage {
    pub ack_id: String,
    pub data: Vec<u8>,
}

pub trait Subscriber: Send + Sync {
    fn pull(
        &self,
        max_messages: usize,
    ) -> impl std::future::Future<Output = Result<Vec<PulledMessage>, String>> + Send;

    fn ack(
        &self,
        ack_ids: &[String],
    ) -> impl std::future::Future<Output = Result<(), String>> + Send;
}

/// Real Pub/Sub subscriber, REST-based — same auth pattern as
/// `pubsub::PubSubPublisher`. Not independently unit-tested (real network
/// I/O), same posture as `persistence.rs`'s async functions.
pub struct PubSubSubscriber {
    pub subscription: String,
}

impl Subscriber for PubSubSubscriber {
    async fn pull(&self, max_messages: usize) -> Result<Vec<PulledMessage>, String> {
        let project = crate::persistence::project().ok_or("GCP_PROJECT not set")?;
        let client = crate::persistence::http_client();
        let token = crate::persistence::access_token(client)
            .await
            .ok_or("could not obtain an access token")?;
        let url = format!(
            "https://pubsub.googleapis.com/v1/projects/{project}/subscriptions/{}:pull",
            self.subscription
        );
        let body = serde_json::json!({ "maxMessages": max_messages });
        let resp = client
            .post(&url)
            .bearer_auth(token)
            .json(&body)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("pull failed: HTTP {}", resp.status()));
        }
        #[derive(serde::Deserialize)]
        struct PulledEnvelope {
            #[serde(rename = "ackId")]
            ack_id: String,
            message: PubSubMessage,
        }
        #[derive(serde::Deserialize)]
        struct PubSubMessage {
            data: String,
        }
        #[derive(serde::Deserialize)]
        struct PullResponse {
            #[serde(rename = "receivedMessages", default)]
            received_messages: Vec<PulledEnvelope>,
        }
        let parsed: PullResponse = resp.json().await.map_err(|e| e.to_string())?;
        parsed
            .received_messages
            .into_iter()
            .map(|env| {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(&env.message.data)
                    .map(|data| PulledMessage {
                        ack_id: env.ack_id,
                        data,
                    })
                    .map_err(|e| e.to_string())
            })
            .collect()
    }

    async fn ack(&self, ack_ids: &[String]) -> Result<(), String> {
        if ack_ids.is_empty() {
            return Ok(());
        }
        let project = crate::persistence::project().ok_or("GCP_PROJECT not set")?;
        let client = crate::persistence::http_client();
        let token = crate::persistence::access_token(client)
            .await
            .ok_or("could not obtain an access token")?;
        let url = format!(
            "https://pubsub.googleapis.com/v1/projects/{project}/subscriptions/{}:acknowledge",
            self.subscription
        );
        let body = serde_json::json!({ "ackIds": ack_ids });
        let resp = client
            .post(&url)
            .bearer_auth(token)
            .json(&body)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("ack failed: HTTP {}", resp.status()));
        }
        Ok(())
    }
}

/// An in-memory fake, for testing the sequencer's drain loop without any
/// real GCP calls -- mirrors `pubsub::FakePublisher`.
#[derive(Default)]
pub struct FakeSubscriber {
    pub queue: std::sync::Mutex<Vec<PulledMessage>>,
    pub acked: std::sync::Mutex<Vec<String>>,
}

impl FakeSubscriber {
    pub fn push(&self, ack_id: &str, data: &[u8]) {
        self.queue.lock().unwrap().push(PulledMessage {
            ack_id: ack_id.to_string(),
            data: data.to_vec(),
        });
    }
}

impl Subscriber for FakeSubscriber {
    async fn pull(&self, max_messages: usize) -> Result<Vec<PulledMessage>, String> {
        let mut queue = self.queue.lock().unwrap();
        let take = max_messages.min(queue.len());
        Ok(queue.drain(..take).collect())
    }

    async fn ack(&self, ack_ids: &[String]) -> Result<(), String> {
        self.acked.lock().unwrap().extend_from_slice(ack_ids);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fake_subscriber_pulls_up_to_max_messages() {
        let s = FakeSubscriber::default();
        s.push("a", b"one");
        s.push("b", b"two");
        s.push("c", b"three");
        let pulled = s.pull(2).await.unwrap();
        assert_eq!(pulled.len(), 2);
        assert_eq!(pulled[0].data, b"one");
        assert_eq!(pulled[1].data, b"two");
        // Draining leaves the rest for the next pull.
        let rest = s.pull(10).await.unwrap();
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].data, b"three");
    }

    #[tokio::test]
    async fn fake_subscriber_pull_on_empty_queue_returns_empty() {
        let s = FakeSubscriber::default();
        assert!(s.pull(5).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn fake_subscriber_records_acked_ids() {
        let s = FakeSubscriber::default();
        s.ack(&["x".to_string(), "y".to_string()]).await.unwrap();
        assert_eq!(
            *s.acked.lock().unwrap(),
            vec!["x".to_string(), "y".to_string()]
        );
    }
}
