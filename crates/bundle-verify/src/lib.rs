//! The browser verifier (BV1). `verify_bytes` is the whole decision: the bytes of a static bundle in, a closed reason code and the counts out. `abi` exports it to WebAssembly through a plain C interface.
//! Verification only: no signing, no randomness, no clock, no network.

mod abi;

/// The closed reason codes. The page shows one plain sentence per code; nothing from the input is echoed.
pub const OK: i32 = 0;
/// The bundle is malformed (not JSON, a duplicated key, a wrong field, a bad value).
pub const INVALID: i32 = 1;
/// The bundle parses but a signature, proof or hash does not verify (it was changed, or it is not what it says).
pub const VERIFY: i32 = 2;
/// The bundle is larger than the 5 MiB limit.
pub const LIMIT: i32 = 3;
/// Any other failure of the verifier (never expected for a bundle).
pub const OTHER: i32 = 4;

/// The verdict of one bundle: the code and a JSON text (`{"code":..,"reason":"..",counts}`) for the page. Nothing from the input is echoed.
pub fn verify_bytes(bytes: &[u8]) -> (i32, String) {
    use entropa_ledger::{verify_bundle, LedgerError, MAX_BUNDLE_BYTES};
    let (code, reason) = if bytes.len() > MAX_BUNDLE_BYTES {
        (LIMIT, "limit")
    } else {
        match std::str::from_utf8(bytes) {
            Err(_) => (INVALID, "invalid"),
            Ok(text) => match verify_bundle(text) {
                Ok(r) => {
                    return (
                        OK,
                        format!(
                            "{{\"code\":0,\"reason\":\"ok\",\"records\":{},\"checkpoints\":{},\"receipts\":{},\"consistency\":{},\"witnesses\":{},\"signatures\":{}}}",
                            r.records, r.checkpoints, r.receipts, r.consistency, r.witnesses, r.signatures
                        ),
                    )
                }
                Err(LedgerError::Invalid(_)) => (INVALID, "invalid"),
                Err(LedgerError::Verify(_)) => (VERIFY, "verify"),
                Err(LedgerError::Limit(_)) => (LIMIT, "limit"),
                Err(_) => (OTHER, "other"),
            },
        }
    };
    (code, format!("{{\"code\":{code},\"reason\":\"{reason}\"}}"))
}
