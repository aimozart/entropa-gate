//! Firestore-backed durability for the transparency-log service — see
//! `a stage record (not published)`. Mirrors the existing `persistence.rs`
//! patterns (`access_token`/`base_url`/`project`) rather than duplicating them.
//!
//! **Known, honest limitation, documented rather than hidden**: resume replays every
//! persisted record through `TransparencyLog::append()` on boot — O(n) in record count.
//! Starting from a genuinely clean slate (the owner's explicit call, 2026-08-25 — no
//! existing customers, no history to carry forward), this is fine today. It is exactly
//! the same class of limitation the old chain's full-history resume had before
//! `persistence::load_recent_blocks` fixed it (found the hard way at real production
//! scale, 2026-08-23) — flagged here in advance so it gets fixed *before* it becomes an
//! incident this time, not after. Real fix when it matters: persist `frontier`/`size`
//! directly (a handful of hashes) instead of replaying full history.

use serde_json::Value;

use crate::persistence::{access_token, base_url, project};

/// Each customer gets their own private Merkle tree -- one customer's usage is never
/// intermingled with another's, in storage or in the tree math itself. The owner's
/// explicit call, 2026-08-26: "cant intermingle... ea customer get st he perosnal
/// tree." `partner` (the partner's slug) scopes every record under its own
/// subcollection, so deleting one partner's tree entirely (the account-cancellation
/// wipe) never touches any other partner's data or proofs.
fn partner_records_path(project: &str, epoch: &str, partner: &str) -> String {
    format!(
        "{}/transparency_log/{epoch}/partners/{partner}/records",
        base_url(project)
    )
}

/// Persist one record, with a few retries on transient failure — the write IS the
/// product here, so unlike a fire-and-forget call, callers should
/// `.await` this and only report success to a customer once it actually lands.
/// `submitted_at` is the real moment this record was submitted (unix seconds) —
/// this is not metadata on the side, it's the entire point of the product
/// ("timestamped proof of activity"), so it's captured and persisted alongside
/// the record itself rather than approximated later from a shared checkpoint time.
pub async fn save_record(
    epoch: &str,
    partner: &str,
    index: usize,
    record: &[u8],
    submitted_at: u64,
) -> bool {
    let Some(project) = project() else {
        return false;
    };
    let client = reqwest::Client::new();

    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        let Some(token) = access_token(&client).await else {
            continue;
        };
        let url = format!("{}/{index}", partner_records_path(&project, epoch, partner));
        let body = serde_json::json!({
            "fields": {
                "index": { "integerValue": index.to_string() },
                "record_hex": { "stringValue": hex::encode(record) },
                "submitted_at": { "integerValue": submitted_at.to_string() },
            }
        });
        match client
            .patch(&url)
            .bearer_auth(token)
            .header("Content-Type", "application/json")
            .json(&body)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => return true,
            Ok(resp) => {
                if attempt == MAX_ATTEMPTS {
                    eprintln!(
                        "transparency_persistence: save failed for record {index}: HTTP {} \
                         after {MAX_ATTEMPTS} attempts",
                        resp.status()
                    );
                }
            }
            Err(e) => {
                if attempt == MAX_ATTEMPTS {
                    eprintln!(
                        "transparency_persistence: save failed for record {index}: {e} after \
                         {MAX_ATTEMPTS} attempts"
                    );
                }
            }
        }
    }
    false
}

/// A visible marker for a position whose real content was permanently lost
/// (persistence failed and the process restarted before it could be retried --
/// see the 2026-08-27 incident in the project history). Decodes via
/// `entropa_core::transparency_log::decode_record` as payload `""`, label
/// `"ENTROPA_LOST_RECORD_NOT_PERSISTED"` -- deliberately visible in the
/// dashboard/explorer rather than silently missing or, worse, silently
/// occupied by a *different* real record's content.
fn tombstone_record() -> Vec<u8> {
    // The constant fields are far below MAX_FIELD_BYTES, so encoding cannot fail.
    entropa_core::transparency_log::encode_record("", Some("ENTROPA_LOST_RECORD_NOT_PERSISTED"))
        .unwrap_or_default()
}

/// **The regression fix for the 2026-08-27 index-compaction incident.** Given
/// records loaded from storage tagged with their own real index (not assumed
/// contiguous), reconstructs the exact sequence to replay via
/// `TransparencyLog::append` -- padding any gap with `tombstone_record()`
/// instead of silently compacting. This is what makes position N after resume
/// always mean the *same* logical index N it always did, even when some
/// record in the middle was never successfully persisted. `records` need not
/// be pre-sorted; this sorts by index itself. A duplicate index (should never
/// happen, but real-world data is real-world data) keeps the first occurrence
/// and drops the rest, rather than silently double-counting a position.
fn pad_gaps_with_tombstones(mut records: Vec<(usize, Vec<u8>, u64)>) -> Vec<(Vec<u8>, u64)> {
    records.sort_by_key(|(index, _, _)| *index);
    let mut result = Vec::with_capacity(records.len());
    let mut next_expected = 0usize;
    for (index, bytes, ts) in records {
        if index < next_expected {
            continue; // duplicate index already covered -- keep the first, drop this one
        }
        while next_expected < index {
            result.push((tombstone_record(), 0));
            next_expected += 1;
        }
        result.push((bytes, ts));
        next_expected = index + 1;
    }
    result
}

/// Load every persisted record for one partner's private tree under `epoch`, in
/// index order, for resume-by-replay -- each paired with its own real submission
/// timestamp, not a shared/approximated one. Any gap in the stored index
/// sequence (a record that failed to persist and was never retried) is padded
/// with a visible tombstone rather than silently shifting every later record's
/// position -- see `pad_gaps_with_tombstones`. See this module's own doc
/// comment for the honest O(n) limitation.
pub async fn load_all_records(epoch: &str, partner: &str) -> Vec<(Vec<u8>, u64)> {
    let Some(project) = project() else {
        return Vec::new();
    };
    let client = reqwest::Client::new();
    let Some(token) = access_token(&client).await else {
        return Vec::new();
    };

    let mut records = Vec::new();
    let mut page_token: Option<String> = None;
    loop {
        // Real bug found live (2026-08-25): `orderBy=%2F__name__` is invalid syntax
        // for Firestore's REST `documents.list` endpoint (confirmed via direct
        // reproduction — HTTP 400 "Invalid order by clause"), and the old code
        // swallowed that error silently, resuming with zero records despite real
        // persisted data existing. Ordering by an explicit `index` field (same
        // pattern `persistence/blocks.rs` already uses) is what Firestore actually
        // supports.
        let mut url = format!(
            "{}?pageSize=300&orderBy=index",
            partner_records_path(&project, epoch, partner)
        );
        if let Some(pt) = &page_token {
            url.push_str(&format!("&pageToken={pt}"));
        }
        let resp = match client
            .get(&url)
            .bearer_auth(&token)
            .timeout(std::time::Duration::from_secs(15))
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                eprintln!("transparency_persistence: load_all_records request failed: {e}");
                break;
            }
        };
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            eprintln!(
                "transparency_persistence: load_all_records got HTTP {status}: {body} -- \
                 resuming with whatever was successfully loaded before this page, not silently \
                 as a clean empty log"
            );
            break;
        }
        let value = match resp.json::<Value>().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("transparency_persistence: load_all_records bad JSON: {e}");
                break;
            }
        };
        if let Some(docs) = value.get("documents").and_then(|d| d.as_array()) {
            for doc in docs {
                if let Some(triple) = record_from_fields(doc) {
                    records.push(triple);
                }
            }
        }
        page_token = value
            .get("nextPageToken")
            .and_then(|t| t.as_str())
            .map(String::from);
        if page_token.is_none() {
            break;
        }
    }
    pad_gaps_with_tombstones(records)
}

/// Deletes every persisted record in one partner's private tree -- the real,
/// account-cancellation "wipe" (the owner's explicit call, 2026-08-26: "we wipe it all
/// after cancel"). Safe by construction: since each partner has their own private
/// tree/subcollection (never shared), this can never touch another partner's data
/// or invalidate another partner's already-issued receipts -- the exact problem
/// that made deleting from the old single shared log impossible. Returns `false`
/// if any single document failed to delete (caller should not report the wipe as
/// complete in that case); does not stop early on one failure, so a partial
/// network blip doesn't leave most of the tree deleted and a few strays behind.
pub async fn delete_all_records(epoch: &str, partner: &str) -> bool {
    let Some(project) = project() else {
        return false;
    };
    let client = reqwest::Client::new();
    let mut all_ok = true;
    let mut page_token: Option<String> = None;
    loop {
        let Some(token) = access_token(&client).await else {
            return false;
        };
        let mut url = format!(
            "{}?pageSize=300&orderBy=index",
            partner_records_path(&project, epoch, partner)
        );
        if let Some(pt) = &page_token {
            url.push_str(&format!("&pageToken={pt}"));
        }
        let Ok(resp) = client
            .get(&url)
            .bearer_auth(&token)
            .timeout(std::time::Duration::from_secs(15))
            .send()
            .await
        else {
            return false;
        };
        if !resp.status().is_success() {
            return false;
        }
        let Ok(value) = resp.json::<Value>().await else {
            return false;
        };
        if let Some(docs) = value.get("documents").and_then(|d| d.as_array()) {
            for doc in docs {
                let Some(name) = doc.get("name").and_then(|n| n.as_str()) else {
                    continue;
                };
                let delete_url = format!("https://firestore.googleapis.com/v1/{name}");
                let deleted = client
                    .delete(&delete_url)
                    .bearer_auth(&token)
                    .timeout(std::time::Duration::from_secs(10))
                    .send()
                    .await
                    .map(|r| r.status().is_success())
                    .unwrap_or(false);
                if !deleted {
                    all_ok = false;
                }
            }
        }
        page_token = value
            .get("nextPageToken")
            .and_then(|t| t.as_str())
            .map(String::from);
        if page_token.is_none() {
            break;
        }
    }
    all_ok
}

/// Pure: decode one Firestore document into a record's raw bytes plus its real
/// submission timestamp. Separated from the I/O above so the parsing logic
/// itself is directly unit-testable.
///
/// **Real incident, 2026-08-27**: an earlier version of this function rejected
/// any document missing `submitted_at` entirely -- which every record persisted
/// before this timestamp feature existed. On resume, `load_all_records` silently
/// dropped 100% of one real customer's history (2,336 records), the in-memory
/// tree came back empty, and new submissions during that window re-used and
/// overwrote the first 6 real Firestore documents before the bug was caught.
/// That data is gone -- Firestore has no document history by default. The fix:
/// a record missing its timestamp is **not** rejected -- it's accepted with
/// `submitted_at = 0` (`unix epoch, meaning "predates timestamp tracking"`),
/// so old records stay visible and safe rather than being silently dropped
/// again by some future stricter check. See the project history for the full
/// incident writeup.
fn record_from_fields(doc: &Value) -> Option<(usize, Vec<u8>, u64)> {
    let fields = doc.get("fields")?;
    let index = fields
        .get("index")?
        .get("integerValue")?
        .as_str()?
        .parse::<usize>()
        .ok()?;
    let hex_str = fields.get("record_hex")?.get("stringValue")?.as_str()?;
    let bytes = hex::decode(hex_str).ok()?;
    let submitted_at = fields
        .get("submitted_at")
        .and_then(|v| v.get("integerValue"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    Some((index, bytes, submitted_at))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The regression test for the 2026-08-27 index-compaction incident:
    /// `ProtoState::resume` used to replay whatever records were found, in
    /// order, via a fresh sequential `TransparencyLog::append` per record --
    /// silently shifting every record after a gap down into the wrong
    /// position. `pad_gaps_with_tombstones` must instead preserve each
    /// record's own original index by padding any gap with a visible
    /// tombstone, so position N after reconstruction always means the same
    /// logical index N a previously-issued receipt already claims it does.
    #[test]
    fn pad_gaps_with_tombstones_preserves_original_index_positions_across_a_gap() {
        let records = vec![
            (0, b"first".to_vec(), 100),
            (1, b"second".to_vec(), 200),
            // indices 2, 3 missing -- never successfully persisted
            (4, b"fifth".to_vec(), 500),
        ];
        let result = pad_gaps_with_tombstones(records);
        assert_eq!(
            result.len(),
            5,
            "must be dense 0..=4, gap padded not compacted"
        );
        assert_eq!(result[0].0, b"first".to_vec());
        assert_eq!(result[1].0, b"second".to_vec());
        // The two padded positions must be visibly marked as lost, not the
        // silently-wrong-content bug this replaces, and not simply absent.
        let (payload, label) = entropa_core::transparency_log::decode_record(&result[2].0).unwrap();
        assert_eq!(payload, "");
        assert_eq!(label.as_deref(), Some("ENTROPA_LOST_RECORD_NOT_PERSISTED"));
        let (payload, label) = entropa_core::transparency_log::decode_record(&result[3].0).unwrap();
        assert_eq!(payload, "");
        assert_eq!(label.as_deref(), Some("ENTROPA_LOST_RECORD_NOT_PERSISTED"));
        // Position 4 (the real, correct index) must be the real record --
        // this is the exact position that was silently wrong before the fix
        // (it would have landed at position 2 instead).
        assert_eq!(result[4].0, b"fifth".to_vec());
        assert_eq!(result[4].1, 500);
    }

    #[test]
    fn pad_gaps_with_tombstones_is_a_noop_when_there_is_no_gap() {
        let records = vec![
            (0, b"a".to_vec(), 1),
            (1, b"b".to_vec(), 2),
            (2, b"c".to_vec(), 3),
        ];
        let result = pad_gaps_with_tombstones(records);
        assert_eq!(
            result,
            vec![(b"a".to_vec(), 1), (b"b".to_vec(), 2), (b"c".to_vec(), 3),]
        );
    }

    #[test]
    fn pad_gaps_with_tombstones_pads_before_the_first_record_if_index_zero_is_missing() {
        let records = vec![(2, b"third".to_vec(), 300)];
        let result = pad_gaps_with_tombstones(records);
        assert_eq!(result.len(), 3);
        assert_eq!(result[2].0, b"third".to_vec());
    }

    #[test]
    fn pad_gaps_with_tombstones_keeps_the_first_occurrence_of_a_duplicate_index() {
        let records = vec![
            (0, b"real".to_vec(), 100),
            (0, b"duplicate-should-be-dropped".to_vec(), 999),
            (1, b"second".to_vec(), 200),
        ];
        let result = pad_gaps_with_tombstones(records);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].0, b"real".to_vec());
    }

    #[test]
    fn pad_gaps_with_tombstones_on_empty_input_returns_empty() {
        assert_eq!(
            pad_gaps_with_tombstones(vec![]),
            Vec::<(Vec<u8>, u64)>::new()
        );
    }

    #[test]
    fn record_from_fields_decodes_a_real_document_shape_with_its_real_submission_timestamp() {
        let doc = serde_json::json!({
            "name": "projects/p/databases/(default)/documents/transparency_log/e/records/0",
            "fields": {
                "index": { "integerValue": "0" },
                "record_hex": { "stringValue": "68656c6c6f" },
                "submitted_at": { "integerValue": "1700000000" },
            }
        });
        assert_eq!(
            record_from_fields(&doc),
            Some((0, b"hello".to_vec(), 1_700_000_000))
        );
    }

    /// The regression test for the 2026-08-27 incident: a document missing its
    /// timestamp (any record persisted before this feature existed) must still
    /// load -- rejecting it is what silently dropped a real customer's entire
    /// history and led to their earliest records being overwritten.
    #[test]
    fn record_from_fields_accepts_a_pre_existing_document_with_no_submission_timestamp() {
        let doc = serde_json::json!({
            "fields": {
                "index": { "integerValue": "5" },
                "record_hex": { "stringValue": "68656c6c6f" },
            }
        });
        assert_eq!(record_from_fields(&doc), Some((5, b"hello".to_vec(), 0)));
    }

    /// The other regression test from the same incident: `record_from_fields`
    /// must also return each document's own real index, not assume position
    /// equals index -- that assumption is exactly what silently compacted a
    /// customer's log around a gap (see `pad_gaps_with_tombstones`).
    #[test]
    fn record_from_fields_rejects_a_document_missing_its_index() {
        let doc = serde_json::json!({
            "fields": {
                "record_hex": { "stringValue": "68656c6c6f" },
                "submitted_at": { "integerValue": "1700000000" },
            }
        });
        assert_eq!(record_from_fields(&doc), None);
    }

    #[test]
    fn record_from_fields_rejects_missing_fields_wrapper() {
        let doc = serde_json::json!({ "name": "..." });
        assert_eq!(record_from_fields(&doc), None);
    }

    #[test]
    fn record_from_fields_rejects_non_hex_content() {
        let doc = serde_json::json!({
            "fields": {
                "index": { "integerValue": "0" },
                "record_hex": { "stringValue": "not-hex!" },
                "submitted_at": { "integerValue": "1700000000" },
            }
        });
        assert_eq!(record_from_fields(&doc), None);
    }
}
