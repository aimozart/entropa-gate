//! Customer authentication for the ingest tier — looks up a bearer API key
//! against the existing Admin CRM's `partners/{slug}` registry
//! (`admin::store`), so a customer's identity comes from one real source of truth. Cached in memory
//! with a short TTL (same pattern as `persistence::token_is_still_fresh`)
//! rather than a live Firestore call on every submission.

use std::sync::Mutex;

use crate::admin::crypto::hash_key;
use crate::admin::model::PartnerRecord;
use crate::admin::store::list_partners;

/// Whether a cached partner list is still safe to serve without refreshing.
pub(crate) fn cache_is_fresh(last_refreshed_secs: u64, now_secs: u64, ttl_secs: u64) -> bool {
    now_secs < last_refreshed_secs + ttl_secs
}

/// Find the partner whose stored key hash matches the given raw API key.
/// Pure and independently testable -- the actual Firestore fetch/cache-TTL
/// logic lives in `PartnerDirectory` below.
pub(crate) fn find_by_raw_key<'a>(
    partners: &'a [PartnerRecord],
    raw_key: &str,
) -> Option<&'a PartnerRecord> {
    let target_hash = hash_key(raw_key);
    partners.iter().find(|p| p.api_key_hash == target_hash)
}

pub trait PartnerDirectory: Send + Sync {
    fn authenticate(
        &self,
        raw_key: &str,
    ) -> impl std::future::Future<Output = Option<PartnerRecord>> + Send;
}

struct Cached {
    partners: Vec<PartnerRecord>,
    refreshed_at_secs: u64,
}

const CACHE_TTL_SECS: u64 = 30;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The real directory: Firestore-backed via the existing Admin CRM partner
/// registry, cached for `CACHE_TTL_SECS` so a burst of customer traffic
/// doesn't turn into a burst of Firestore reads.
pub struct CachedPartnerDirectory {
    cache: Mutex<Option<Cached>>,
}

impl Default for CachedPartnerDirectory {
    fn default() -> Self {
        Self {
            cache: Mutex::new(None),
        }
    }
}

impl PartnerDirectory for CachedPartnerDirectory {
    async fn authenticate(&self, raw_key: &str) -> Option<PartnerRecord> {
        let needs_refresh = {
            let guard = self.cache.lock().unwrap();
            match guard.as_ref() {
                Some(cached) => {
                    !cache_is_fresh(cached.refreshed_at_secs, now_secs(), CACHE_TTL_SECS)
                }
                None => true,
            }
        };
        if needs_refresh {
            let partners = list_partners().await;
            let mut guard = self.cache.lock().unwrap();
            *guard = Some(Cached {
                partners,
                refreshed_at_secs: now_secs(),
            });
        }
        let guard = self.cache.lock().unwrap();
        let partners = &guard.as_ref()?.partners;
        find_by_raw_key(partners, raw_key).cloned()
    }
}

/// An in-memory fake, for testing the ingest handler's auth without any
/// real Firestore calls -- mirrors `pubsub::FakePublisher`.
#[derive(Default)]
pub struct FakePartnerDirectory {
    pub partners: Vec<PartnerRecord>,
}

impl PartnerDirectory for FakePartnerDirectory {
    async fn authenticate(&self, raw_key: &str) -> Option<PartnerRecord> {
        find_by_raw_key(&self.partners, raw_key).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn partner(slug: &str, raw_key: &str) -> PartnerRecord {
        PartnerRecord {
            slug: slug.to_string(),
            display_name: slug.to_string(),
            email: String::new(),
            api_key_hash: hash_key(raw_key),
            notes: String::new(),
        }
    }

    #[test]
    fn cache_within_ttl_is_still_fresh() {
        assert!(cache_is_fresh(1_000, 1_010, 30));
    }

    #[test]
    fn cache_past_ttl_is_not_fresh() {
        assert!(!cache_is_fresh(1_000, 1_031, 30));
    }

    #[test]
    fn find_by_raw_key_matches_the_correct_partner() {
        let partners = vec![partner("alpha", "key-a"), partner("beta", "key-b")];
        let found = find_by_raw_key(&partners, "key-b").unwrap();
        assert_eq!(found.slug, "beta");
    }

    #[test]
    fn find_by_raw_key_returns_none_for_an_unknown_key() {
        let partners = vec![partner("alpha", "key-a")];
        assert!(find_by_raw_key(&partners, "not-a-real-key").is_none());
    }

    #[tokio::test]
    async fn fake_directory_authenticates_a_known_key() {
        let dir = FakePartnerDirectory {
            partners: vec![partner("alpha", "real-key")],
        };
        let result = dir.authenticate("real-key").await;
        assert_eq!(result.unwrap().slug, "alpha");
    }

    #[tokio::test]
    async fn fake_directory_rejects_an_unknown_key() {
        let dir = FakePartnerDirectory {
            partners: vec![partner("alpha", "real-key")],
        };
        assert!(dir.authenticate("wrong-key").await.is_none());
    }
}
