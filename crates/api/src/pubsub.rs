//! A publish seam for the elastic ingest tier — real Pub/Sub over REST, plus
//! a fake for tests, same pattern as `leader.rs`'s `LeaseStore`/`Clock`
//! trait seam. See `a stage record (not published)`.

use base64::Engine;

pub trait Publisher: Send + Sync {
    /// `ordering_key` is what makes horizontal scaling of the sequencer safe: Pub/Sub
    /// guarantees messages sharing a key are delivered in order and never to more than
    /// one outstanding request at a time, so using each customer's slug as the key
    /// means multiple `entropa-transparency` instances can run concurrently without
    /// ever racing on the same customer's in-memory Merkle tree.
    fn publish(
        &self,
        data: &[u8],
        ordering_key: &str,
    ) -> impl std::future::Future<Output = Result<String, String>> + Send;
}

/// Real Pub/Sub publisher, REST-based — same auth pattern as
/// `persistence::access_token`/`persistence::project` (metadata-server ADC,
/// no key file to manage). Not independently unit-tested (real network I/O),
/// same posture as `persistence.rs`'s async functions.
pub struct PubSubPublisher {
    pub topic: String,
}

impl Publisher for PubSubPublisher {
    async fn publish(&self, data: &[u8], ordering_key: &str) -> Result<String, String> {
        let project = crate::persistence::project().ok_or("GCP_PROJECT not set")?;
        let client = crate::persistence::http_client();
        let token = crate::persistence::access_token(client)
            .await
            .ok_or("could not obtain an access token")?;
        let url = format!(
            "https://pubsub.googleapis.com/v1/projects/{project}/topics/{}:publish",
            self.topic
        );
        let encoded = base64::engine::general_purpose::STANDARD.encode(data);
        let body =
            serde_json::json!({ "messages": [{ "data": encoded, "orderingKey": ordering_key }] });
        let resp = client
            .post(&url)
            .bearer_auth(token)
            .json(&body)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("publish failed: HTTP {}", resp.status()));
        }
        #[derive(serde::Deserialize)]
        struct PublishResponse {
            #[serde(rename = "messageIds")]
            message_ids: Vec<String>,
        }
        let parsed: PublishResponse = resp.json().await.map_err(|e| e.to_string())?;
        parsed
            .message_ids
            .into_iter()
            .next()
            .ok_or_else(|| "Pub/Sub returned no message ID".to_string())
    }
}

/// An in-memory fake, for testing the ingest handler without any real GCP
/// calls -- mirrors the role `FakeLeaseStore` plays for `leader.rs`.
#[derive(Default)]
pub struct FakePublisher {
    pub published: std::sync::Mutex<Vec<Vec<u8>>>,
    pub ordering_keys: std::sync::Mutex<Vec<String>>,
    pub always_fail: bool,
}

impl Publisher for FakePublisher {
    async fn publish(&self, data: &[u8], ordering_key: &str) -> Result<String, String> {
        if self.always_fail {
            return Err("fake publisher configured to fail".to_string());
        }
        let mut published = self.published.lock().unwrap();
        published.push(data.to_vec());
        self.ordering_keys
            .lock()
            .unwrap()
            .push(ordering_key.to_string());
        Ok(format!("fake-message-{}", published.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fake_publisher_records_every_published_message() {
        let p = FakePublisher::default();
        p.publish(b"first", "partner-a").await.unwrap();
        p.publish(b"second", "partner-a").await.unwrap();
        let published = p.published.lock().unwrap();
        assert_eq!(*published, vec![b"first".to_vec(), b"second".to_vec()]);
    }

    /// The whole point of ordering keys: Pub/Sub guarantees only one instance
    /// ever processes a given key's messages at a time, which is what lets
    /// `entropa-transparency` scale horizontally without two instances ever
    /// racing on the same customer's tree. Real production incident this
    /// prevents: two Cloud Run instances each holding an independent
    /// in-memory copy of the same customer's Merkle tree, silently forking it.
    #[tokio::test]
    async fn fake_publisher_records_the_ordering_key_per_message() {
        let p = FakePublisher::default();
        p.publish(b"one", "acme-corp").await.unwrap();
        p.publish(b"two", "globex-inc").await.unwrap();
        let keys = p.ordering_keys.lock().unwrap();
        assert_eq!(
            *keys,
            vec!["acme-corp".to_string(), "globex-inc".to_string()]
        );
    }

    #[tokio::test]
    async fn fake_publisher_returns_distinct_message_ids_in_order() {
        let p = FakePublisher::default();
        let id1 = p.publish(b"a", "partner-a").await.unwrap();
        let id2 = p.publish(b"b", "partner-a").await.unwrap();
        assert_ne!(id1, id2);
    }

    #[tokio::test]
    async fn fake_publisher_configured_to_fail_never_records_anything() {
        let p = FakePublisher {
            always_fail: true,
            ..Default::default()
        };
        assert!(p.publish(b"never-stored", "partner-a").await.is_err());
        assert!(p.published.lock().unwrap().is_empty());
    }
}
