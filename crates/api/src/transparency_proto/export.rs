//! The customer's full-history export endpoint — extracted from `handlers.rs`
//! per the project rules. Every record in a partner's own private tree, no cap -- unlike
//! `get_chain`'s bounded page (a live-browsing convenience), this is the real,
//! complete archive a customer downloads before canceling. The owner's explicit
//! call, 2026-08-26: "you cancel you have to dlaod al your attestions" -- so
//! this has to actually be everything, not a truncated preview.

use axum::{extract::State, Json};
use serde::Deserialize;

use entropa_core::transparency_log::{decode_record_or_marker, Receipt};

use super::state::ProtoState;

#[derive(Deserialize)]
pub(super) struct ExportQuery {
    /// Real unix-second bounds on each record's own submission timestamp, both
    /// inclusive. `None` means unbounded on that side -- omitting both keeps the
    /// existing "download everything" behavior exactly as it was.
    from: Option<u64>,
    to: Option<u64>,
}

/// Pure: does a record submitted at `submitted_at` fall within `[from, to]`
/// (either bound optional/unbounded)? Separated so the filter logic is directly
/// unit-testable without needing a real partner/checkpoint/HTTP round trip.
fn in_range(submitted_at: u64, from: Option<u64>, to: Option<u64>) -> bool {
    from.is_none_or(|f| submitted_at >= f) && to.is_none_or(|t| submitted_at <= t)
}

/// A single exported record's own JSON -- deliberately excludes every checkpoint
/// field (root/signature/size). The checkpoint is identical for every record in
/// one export (they're all proven against the same one), so it belongs exactly
/// once at the top level of the response, not duplicated per record. See
/// `export_record_tests` for the real incident this fixes: the ~6.6KB hex ML-DSA
/// signature, duplicated across ~6,366 records, is what actually tripped Cloud
/// Run's response-size limit once the O(n^2) receipt-lookup bug was fixed and the
/// request became fast enough to reach serialization at all.
pub(super) fn export_record_json(receipt: &Receipt, submitted_at: u64) -> serde_json::Value {
    let (payload, label) = decode_record_or_marker(&receipt.record);
    serde_json::json!({
        "index": receipt.index,
        "hash": hex::encode(entropa_core::merkle::leaf_hash(&receipt.record)),
        "payload": payload,
        "label": label,
        "timestamp": submitted_at,
    })
}

pub(super) async fn full_export(
    State(state): State<ProtoState>,
    axum::extract::Query(range): axum::extract::Query<ExportQuery>,
    axum::extract::Extension(crate::dashboard::CustomerSlug(partner)): axum::extract::Extension<
        crate::dashboard::CustomerSlug,
    >,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    let partners = state.partners.lock().unwrap();
    let Some(entry) = partners.get(&partner) else {
        return Json(serde_json::json!({ "partner": partner, "records": [] })).into_response();
    };
    let Some(checkpoint) = entry.latest_checkpoint.clone() else {
        return Json(serde_json::json!({ "partner": partner, "records": [] })).into_response();
    };
    // Same batched fix as `get_chain` -- this is the exact endpoint whose
    // per-index `receipt()` loop caused the real 2026-08-27 incident (17+ second,
    // then-failing 500s on the dashboard's "download my full history" button at
    // Pinnacle Financial's live record count).
    let in_range_indices: Vec<usize> = (0..checkpoint.size)
        .filter(|&i| {
            entry
                .submitted_at
                .get(i)
                .copied()
                .is_some_and(|t| in_range(t, range.from, range.to))
        })
        .collect();
    let records: Vec<serde_json::Value> = entry
        .log
        .receipts_for(&in_range_indices, &checkpoint)
        .into_iter()
        .zip(&in_range_indices)
        .filter_map(|(receipt, &i)| {
            let receipt = receipt?;
            let submitted_at = entry.submitted_at.get(i).copied()?;
            Some(export_record_json(&receipt, submitted_at))
        })
        .collect();
    // Checkpoint fields (including the ~6.6KB hex ML-DSA signature) live once
    // here, not duplicated inside every record -- see `export_record_json`'s
    // doc comment for the real incident this fixes.
    Json(serde_json::json!({
        "partner": partner,
        "signer_pubkey": state.signer_pubkey_hex(),
        "checkpoint_root": hex::encode(checkpoint.root),
        "checkpoint_signature": checkpoint.signature,
        "checkpoint_size": checkpoint.size,
        "record_count": records.len(),
        "records": records,
    }))
    .into_response()
}

#[cfg(test)]
mod export_range_tests {
    use super::in_range;

    #[test]
    fn unbounded_range_accepts_everything() {
        assert!(in_range(1_000, None, None));
    }

    #[test]
    fn lower_bound_excludes_earlier_records() {
        assert!(!in_range(999, Some(1_000), None));
        assert!(in_range(1_000, Some(1_000), None));
    }

    #[test]
    fn upper_bound_excludes_later_records() {
        assert!(in_range(2_000, None, Some(2_000)));
        assert!(!in_range(2_001, None, Some(2_000)));
    }

    #[test]
    fn both_bounds_together_form_a_closed_interval() {
        assert!(!in_range(999, Some(1_000), Some(2_000)));
        assert!(in_range(1_500, Some(1_000), Some(2_000)));
        assert!(!in_range(2_001, Some(1_000), Some(2_000)));
    }
}

#[cfg(test)]
mod export_record_tests {
    use super::export_record_json;
    use entropa_core::pqc::Probe;
    use entropa_core::transparency_log::TransparencyLog;

    /// Real production bug (2026-08-27, found immediately after the O(n^2) fix
    /// was deployed): `full_export` embedded the *entire checkpoint* -- including
    /// its ~6.6KB hex-encoded ML-DSA signature -- inside every single record's
    /// JSON object. The signature is identical for every record in one export
    /// (they're all proven against the same checkpoint), so duplicating it per
    /// record inflated a real ~6,366-record export to tens of megabytes, tripping
    /// Cloud Run's response-size limit with a genuine 500 -- confirmed live via
    /// `gcloud logging read` (`Response size was too large`) right after the
    /// O(n^2) fix made the request fast enough to actually reach serialization.
    /// A per-record JSON object must never carry the checkpoint's own fields.
    #[test]
    fn a_records_own_json_never_embeds_the_checkpoint_signature() {
        let mut log = TransparencyLog::new();
        log.append(b"payload-one");
        let p = Probe::spawn();
        let checkpoint = log.checkpoint(&p, 1_000);
        let receipt = log.receipt(0, &checkpoint).unwrap();
        let json = export_record_json(&receipt, 1_700_000_000);
        assert!(
            json.get("checkpoint_signature").is_none(),
            "checkpoint_signature must live once at the top level of the export \
             response, never duplicated inside every record"
        );
        assert!(json.get("checkpoint_root").is_none());
        assert!(json.get("checkpoint_size").is_none());
        assert_eq!(json["index"], 0);
        assert_eq!(json["timestamp"], 1_700_000_000);
    }
}
