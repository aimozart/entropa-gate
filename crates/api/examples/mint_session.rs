//! Diagnostic tool: mints a real, valid customer-dashboard session token for a
//! given partner slug, given the live `ENTROPA_CUSTOMER_SESSION_SECRET` value
//! (fetch via `gcloud secrets versions access latest --secret=... > file`, then
//! pass that file's path -- read as raw bytes, not trimmed, since the secret's
//! stored value includes a trailing newline that must match exactly). Used to
//! verify authenticated endpoints directly via curl without a live email-code
//! login round trip.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use entropa_api::dashboard::auth::new_session_for;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let slug = std::env::args().nth(1).expect("slug arg");
    let secret_path = std::env::args().nth(2).expect("secret file path");
    let secret = std::fs::read_to_string(secret_path).expect("read secret file");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    println!("{}", new_session_for(&slug, now, &secret));
}
