//! `ProtoState` — one independent Merkle tree per customer, behind one map.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use entropa_core::pqc::Probe;
use entropa_core::transparency_log::{Checkpoint, TransparencyLog};

use super::rate_tier::{self, RateTier};
use crate::transparency_persistence;

pub(super) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One customer's private tree: their own log, their own latest checkpoint. Never
/// exposed to, or provable against, any other customer's data.
pub(super) struct PartnerLog {
    pub(super) log: TransparencyLog,
    pub(super) latest_checkpoint: Option<Checkpoint>,
    /// The real moment each record was submitted (unix seconds), index-aligned
    /// with `log`'s own records -- this is the actual point of the product
    /// ("timestamped proof of activity"), persisted alongside each record, never
    /// approximated from a shared checkpoint timestamp.
    pub(super) submitted_at: Vec<u64>,
    /// Submission timestamps within the trailing hour -- purely an operational
    /// throughput signal (see `rate_tier`), never persisted, never part of the
    /// audit trail itself. Resets on redeploy, which is fine for what it's for.
    rate_window: std::collections::VecDeque<u64>,
    /// The highest rate tier already alerted on, so a sustained high rate emails
    /// once per crossing rather than on every single submission. Re-arms if the
    /// rate drops back down and later crosses again.
    alerted_tier: RateTier,
}

impl PartnerLog {
    fn new() -> Self {
        Self {
            log: TransparencyLog::new(),
            latest_checkpoint: None,
            submitted_at: Vec::new(),
            rate_window: std::collections::VecDeque::new(),
            alerted_tier: RateTier::default(),
        }
    }
}

/// Shared state for the router — a single in-process writer (matching the design
/// this whole prototype exists to prove out: no peer networking, no quorum), holding
/// one independent tree per customer behind one map. A single lock across all
/// partners is a deliberate simplicity choice at this traffic scale, not a
/// performance-tuned design -- correct first, matching this project's own standing
/// practice of proving correctness before optimizing for concurrency nobody's hit yet.
#[derive(Clone)]
pub struct ProtoState {
    pub(super) partners: Arc<Mutex<HashMap<String, PartnerLog>>>,
    pub(super) signer: Arc<Probe>,
    pub(super) epoch: Arc<str>,
}

impl ProtoState {
    /// In-memory only, no persistence — used by tests and local/offline runs. Real
    /// deployments use [`ProtoState::resume`] instead.
    pub fn new() -> Self {
        Self {
            partners: Arc::new(Mutex::new(HashMap::new())),
            signer: Arc::new(Probe::spawn()),
            epoch: Arc::from("local"),
        }
    }

    /// Resume from Firestore: for every partner in the existing Admin CRM registry
    /// (`admin::store::list_partners` -- reusing infrastructure that already exists
    /// and is proven, rather than a new Firestore listing query), load and replay
    /// their private tree's persisted records. A partner with no records yet simply
    /// gets no entry -- their tree is created lazily on first submission. See
    /// `transparency_persistence`'s own doc comment for the honest O(n)-per-partner
    /// replay limitation this accepts for now.
    pub async fn resume(epoch: &str, signer: Probe) -> Self {
        let signer = Arc::new(signer);
        let known_partners = crate::admin::store::list_partners().await;
        let mut partners = HashMap::new();
        let mut total_records = 0usize;
        for partner in &known_partners {
            let records = transparency_persistence::load_all_records(epoch, &partner.slug).await;
            if records.is_empty() {
                continue;
            }
            let mut log = TransparencyLog::new();
            let mut submitted_at = Vec::with_capacity(records.len());
            for (record, ts) in &records {
                log.append(record);
                submitted_at.push(*ts);
            }
            total_records += records.len();
            let latest_checkpoint = Some(log.checkpoint(&signer, now()));
            partners.insert(
                partner.slug.clone(),
                PartnerLog {
                    log,
                    latest_checkpoint,
                    submitted_at,
                    rate_window: std::collections::VecDeque::new(),
                    alerted_tier: RateTier::default(),
                },
            );
        }
        println!(
            "📦 transparency log resumed — epoch {epoch}, {} partner tree(s), {total_records} record(s) total",
            partners.len()
        );
        Self {
            partners: Arc::new(Mutex::new(partners)),
            signer,
            epoch: Arc::from(epoch),
        }
    }

    pub fn signer_pubkey_hex(&self) -> String {
        self.signer.pubkey_hex()
    }

    /// Record count for one partner's private tree. `0` for a partner with no tree
    /// yet -- not an error, just nothing submitted so far.
    pub fn len(&self, partner: &str) -> usize {
        self.partners
            .lock()
            .unwrap()
            .get(partner)
            .map(|p| p.log.len())
            .unwrap_or(0)
    }

    pub fn is_empty(&self, partner: &str) -> bool {
        self.len(partner) == 0
    }

    /// Total records across every customer's tree combined -- an aggregate service
    /// health signal only. Never used to answer a customer's own query (those are
    /// always scoped to their own tree via `len`/`ingest`/receipt lookups).
    pub fn total_len(&self) -> usize {
        self.partners
            .lock()
            .unwrap()
            .values()
            .map(|p| p.log.len())
            .sum()
    }

    pub fn partner_count(&self) -> usize {
        self.partners.lock().unwrap().len()
    }

    /// Append `payload` to `partner`'s own private tree (creating it on first use),
    /// persist it durably under that partner's own storage path, and checkpoint —
    /// the same core logic both the HTTP `submit_tx` handler and the queue-fed
    /// sequencer loop share, per `a stage record (not published)`. `Err` means
    /// the submission was *not* durably accepted and must not be reported as such by
    /// either caller.
    pub async fn ingest(&self, partner: &str, payload: &[u8]) -> Result<usize, String> {
        // One real moment, captured once and reused everywhere below -- this is
        // the actual submission timestamp the product's whole "timestamped proof
        // of activity" claim rests on, not an approximation from a later
        // checkpoint or rate-tracking call.
        let submitted_at = now();

        let index = {
            let mut partners = self.partners.lock().unwrap();
            let entry = partners
                .entry(partner.to_string())
                .or_insert_with(PartnerLog::new);
            let index = entry.log.append(payload);
            entry.submitted_at.push(submitted_at);
            index
        };

        if crate::persistence::project().is_some() {
            let persisted = transparency_persistence::save_record(
                &self.epoch,
                partner,
                index,
                payload,
                submitted_at,
            )
            .await;
            if !persisted {
                return Err("could not durably persist this submission".to_string());
            }
        }

        let crossing = {
            let mut partners = self.partners.lock().unwrap();
            let entry = partners
                .get_mut(partner)
                .expect("just inserted or already present above");
            let checkpoint = entry.log.checkpoint(&self.signer, now());
            entry.latest_checkpoint = Some(checkpoint);

            let rate = rate_tier::record_and_count(&mut entry.rate_window, submitted_at);
            let tier = rate_tier::classify_rate(rate);
            let previous = entry.alerted_tier;
            entry.alerted_tier = tier;
            (tier > previous).then_some((tier, rate))
        };

        // Fired outside the lock -- never hold a std::sync::Mutex across an
        // await. Best-effort: a failed/unset-credentials email must never fail
        // the underlying submission it's reporting on.
        if let Some((tier, rate)) = crossing {
            let subject = format!("Entropa — {partner} crossed {tier:?} rate");
            let body = format!(
                "Partner '{partner}' just crossed the {tier:?} attestation-rate tier: \
                 {rate} attestations in the trailing hour."
            );
            crate::gmail::send_email("aimozart@entropa.space", &subject, &body).await;
        }

        Ok(index)
    }

    /// Deletes a partner's entire private tree, in memory and durably in Firestore --
    /// the real account-cancellation wipe (the owner's explicit call, 2026-08-26: "we
    /// wipe it all after cancel"). Safe by construction: since each partner's tree
    /// was never shared with any other partner's, this can never invalidate anyone
    /// else's already-issued receipts. Returns `false` if the durable delete didn't
    /// fully succeed -- caller should not report the wipe as complete in that case.
    pub async fn delete_partner_tree(&self, partner: &str) -> bool {
        let persisted_ok = if crate::persistence::project().is_some() {
            transparency_persistence::delete_all_records(&self.epoch, partner).await
        } else {
            true
        };
        self.partners.lock().unwrap().remove(partner);
        persisted_ok
    }
}

impl Default for ProtoState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use entropa_core::transparency_log::verify_receipt;

    #[tokio::test]
    async fn ingest_appends_and_returns_the_assigned_index() {
        let state = ProtoState::new();
        let idx0 = state
            .ingest("acme", b"first")
            .await
            .expect("first ingest ok");
        let idx1 = state
            .ingest("acme", b"second")
            .await
            .expect("second ingest ok");
        assert_eq!(idx0, 0);
        assert_eq!(idx1, 1);
    }

    #[tokio::test]
    async fn ingest_result_is_immediately_fetchable_as_a_verified_receipt() {
        let state = ProtoState::new();
        let index = state.ingest("acme", b"real-record").await.unwrap();
        let partners = state.partners.lock().unwrap();
        let entry = partners.get("acme").unwrap();
        let checkpoint = entry.latest_checkpoint.clone().unwrap();
        let receipt = entry.log.receipt(index, &checkpoint).unwrap();
        drop(partners);
        assert!(verify_receipt(&receipt, &state.signer_pubkey_hex()));
    }

    #[tokio::test]
    async fn two_partners_never_share_a_tree() {
        let state = ProtoState::new();
        state.ingest("acme", b"acme-record-1").await.unwrap();
        state.ingest("acme", b"acme-record-2").await.unwrap();
        state.ingest("globex", b"globex-record-1").await.unwrap();

        assert_eq!(state.len("acme"), 2);
        assert_eq!(state.len("globex"), 1);
        assert_eq!(state.total_len(), 3);
        assert_eq!(state.partner_count(), 2);
    }

    #[tokio::test]
    async fn a_partner_with_no_submissions_yet_has_an_empty_tree() {
        let state = ProtoState::new();
        state.ingest("acme", b"something").await.unwrap();
        assert_eq!(state.len("never-submitted"), 0);
        assert!(state.is_empty("never-submitted"));
    }

    #[tokio::test]
    async fn ingest_tracks_rate_and_starts_at_the_base_tier() {
        let state = ProtoState::new();
        state.ingest("acme", b"one").await.unwrap();
        let partners = state.partners.lock().unwrap();
        let entry = partners.get("acme").unwrap();
        assert_eq!(entry.alerted_tier, RateTier::Base);
        assert_eq!(entry.rate_window.len(), 1);
    }

    #[tokio::test]
    async fn ingest_advances_the_alerted_tier_once_the_rate_crosses_elevated() {
        let state = ProtoState::new();
        for _ in 0..rate_tier::ELEVATED_THRESHOLD_PER_HOUR {
            state.ingest("acme", b"x").await.unwrap();
        }
        let partners = state.partners.lock().unwrap();
        assert_eq!(
            partners.get("acme").unwrap().alerted_tier,
            RateTier::Elevated
        );
    }

    #[tokio::test]
    async fn deleting_one_partners_tree_never_touches_another_partners_data() {
        let state = ProtoState::new();
        state.ingest("acme", b"acme-record").await.unwrap();
        state.ingest("globex", b"globex-record").await.unwrap();

        let deleted = state.delete_partner_tree("acme").await;

        assert!(deleted);
        assert_eq!(state.len("acme"), 0);
        assert_eq!(
            state.len("globex"),
            1,
            "globex's tree must be completely untouched"
        );
    }
}
