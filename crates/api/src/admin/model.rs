//! The partner data model — `partners/{slug}` in Firestore.
//!
//! Entropa has no billing: older stored documents may still carry `stripe_*` and
//! `billing_status` fields, which are ignored when read (see `store::fields_to_partner`).

#[derive(Debug, Clone)]
pub struct PartnerRecord {
    pub slug: String,
    pub display_name: String,
    pub email: String,
    pub api_key_hash: String,
    pub notes: String,
}
