//! Firestore persistence for `partners/{slug}` documents.

use serde_json::{json, Value};

use crate::persistence::{access_token, base_url, project};

use super::model::PartnerRecord;

const COLLECTION: &str = "partners";

fn partner_to_fields(p: &PartnerRecord) -> Value {
    json!({
        "fields": {
            "display_name": {"stringValue": p.display_name},
            "email": {"stringValue": p.email},
            "api_key_hash": {"stringValue": p.api_key_hash},
            "notes": {"stringValue": p.notes},
        }
    })
}

fn fields_to_partner(slug: &str, doc: &Value) -> Option<PartnerRecord> {
    let f = doc.get("fields")?;
    let get_str = |k: &str| -> String {
        f.get(k)
            .and_then(|v| v.get("stringValue"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    Some(PartnerRecord {
        slug: slug.to_string(),
        display_name: get_str("display_name"),
        email: get_str("email"),
        api_key_hash: get_str("api_key_hash"),
        notes: get_str("notes"),
    })
}

pub(crate) async fn list_partners() -> Vec<PartnerRecord> {
    let Some(proj) = project() else {
        return Vec::new();
    };
    let client = reqwest::Client::new();
    let Some(token) = access_token(&client).await else {
        return Vec::new();
    };
    let url = format!("{}/{COLLECTION}", base_url(&proj));
    let Ok(resp) = client.get(&url).bearer_auth(&token).send().await else {
        return Vec::new();
    };
    let Ok(value) = resp.json::<Value>().await else {
        return Vec::new();
    };
    value
        .get("documents")
        .and_then(|d| d.as_array())
        .map(|docs| {
            docs.iter()
                .filter_map(|doc| {
                    let name = doc.get("name")?.as_str()?;
                    let slug = name.rsplit('/').next()?;
                    fields_to_partner(slug, doc)
                })
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) async fn get_partner(slug: &str) -> Option<PartnerRecord> {
    let proj = project()?;
    let client = reqwest::Client::new();
    let token = access_token(&client).await?;
    let url = format!("{}/{COLLECTION}/{slug}", base_url(&proj));
    let resp = client.get(&url).bearer_auth(&token).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let doc: Value = resp.json().await.ok()?;
    fields_to_partner(slug, &doc)
}

/// A simple linear scan over `list_partners()` -- fine at current scale,
/// same posture as `partner_directory`'s existing full-list-then-filter
/// approach. Case-insensitive since email addresses are.
pub(crate) async fn find_partner_by_email(email: &str) -> Option<PartnerRecord> {
    let needle = email.trim().to_lowercase();
    list_partners()
        .await
        .into_iter()
        .find(|p| p.email.trim().to_lowercase() == needle)
}

/// Issues a fresh key for `slug`, overwriting the old key's hash so it
/// stops authenticating immediately. Shared by the admin panel's own
/// regenerate endpoint and the customer dashboard's, so both go through
/// one implementation.
pub(crate) async fn regenerate_key_for(slug: &str) -> Option<(PartnerRecord, String)> {
    let mut p = get_partner(slug).await?;
    let raw_key = super::crypto::generate_key();
    p.api_key_hash = super::crypto::hash_key(&raw_key);
    if !save_partner(&p).await {
        return None;
    }
    Some((p, raw_key))
}

/// Deletes a partner's account record entirely -- real, permanent removal of their
/// PII (email, display name, API key hash, notes). Used by the
/// account-cancellation wipe (the owner's explicit call, 2026-08-26). Distinct from
/// the partner's attestation *tree* (`transparency_persistence::delete_all_records`
/// / `ProtoState::delete_partner_tree`) -- this only removes the account record.
pub(crate) async fn delete_partner(slug: &str) -> bool {
    let Some(proj) = project() else { return false };
    let client = reqwest::Client::new();
    let Some(token) = access_token(&client).await else {
        return false;
    };
    let url = format!("{}/{COLLECTION}/{slug}", base_url(&proj));
    client
        .delete(&url)
        .bearer_auth(token)
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

pub(crate) async fn save_partner(p: &PartnerRecord) -> bool {
    let Some(proj) = project() else { return false };
    let client = reqwest::Client::new();
    let Some(token) = access_token(&client).await else {
        return false;
    };
    let url = format!("{}/{COLLECTION}/{}", base_url(&proj), p.slug);
    client
        .patch(&url)
        .bearer_auth(token)
        .header("Content-Type", "application/json")
        .json(&partner_to_fields(p))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

pub(crate) fn partner_json(p: &PartnerRecord) -> Value {
    json!({
        "slug": p.slug,
        "display_name": p.display_name,
        "email": p.email,
        "notes": p.notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> PartnerRecord {
        PartnerRecord {
            slug: "acme".into(),
            display_name: "Acme".into(),
            email: "a@example.com".into(),
            api_key_hash: "hash".into(),
            notes: "n".into(),
        }
    }

    #[test]
    fn stored_partner_fields_carry_no_stripe_or_billing_keys() {
        let doc = partner_to_fields(&sample()).to_string();
        for banned in ["stripe", "billing"] {
            assert!(
                !doc.contains(banned),
                "stored document still has {banned}: {doc}"
            );
        }
    }

    #[test]
    fn the_admin_json_carries_no_stripe_or_billing_keys() {
        let doc = partner_json(&sample()).to_string();
        for banned in ["stripe", "billing"] {
            assert!(
                !doc.contains(banned),
                "admin json still has {banned}: {doc}"
            );
        }
    }

    /// Existing Firestore documents still contain the old fields: reading must ignore them.
    #[test]
    fn an_old_stored_document_with_stripe_fields_still_reads() {
        let old = json!({"fields": {
            "display_name": {"stringValue": "Acme"},
            "email": {"stringValue": "a@example.com"},
            "api_key_hash": {"stringValue": "hash"},
            "stripe_customer_id": {"stringValue": "cus_old"},
            "stripe_subscription_id": {"stringValue": "sub_old"},
            "billing_status": {"stringValue": "past_due"},
            "notes": {"stringValue": "n"},
        }});
        let p = fields_to_partner("acme", &old).expect("old document must still parse");
        assert_eq!(p.slug, "acme");
        assert_eq!(p.display_name, "Acme");
        assert_eq!(p.api_key_hash, "hash");
        assert_eq!(p.notes, "n");
    }
}
