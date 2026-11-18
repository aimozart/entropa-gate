//! TEST ONLY: writes a throwaway issuer public key and a licence signed with a fresh key into a directory, for the install-to-first-record test.
//! The private key is generated in memory and dropped; nothing is stored. Not part of the client binary (feature `issue`, example target).
use entropa_core::Probe;
use entropa_gate::licence::{Claims, PRODUCT};
use entropa_gate::licence_issue::issue;

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| ".".to_string());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let k = Probe::spawn();
    let c = Claims {
        product: PRODUCT.to_string(),
        customer_id: "test-customer-0001".to_string(),
        entitlements: vec!["explorer".to_string(), "guard".to_string()],
        not_before: now.saturating_sub(86_400),
        expiry: now + 365 * 86_400,
        build_id: "s1-install-test".to_string(),
        mark: "0123456789abcdef0123456789abcdef".to_string(),
    };
    let Some(bytes) = issue(&k, &c) else {
        eprintln!("could not issue");
        std::process::exit(1);
    };
    let write = |name: &str, data: &[u8]| {
        if std::fs::write(format!("{dir}/{name}"), data).is_err() {
            eprintln!("cannot write {name}");
            std::process::exit(1);
        }
    };
    write("licence.json", &bytes);
    write("issuer.pub", k.pubkey_hex().as_bytes());
    write("README-TEST-ONLY.txt", b"These files are a throwaway test key and licence made for one install test. They are not a real issuer key and carry no entitlement.\n");
}
