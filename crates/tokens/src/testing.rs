//! Helpers for the planted-attack battery: they build tokens that a correct library would never build, so the verifier can be shown to refuse
//! them. Not part of the supported API.
#![doc(hidden)]

use crate::design_c::{append_impl, Narrowing, Wallet};
use entropa_core::Probe;

/// A holder with the REAL committed key signs a block without the narrowing check (a widening block, correctly signed).
pub fn append_c_unchecked(w: &Wallet, n: &Narrowing) -> Wallet {
    append_impl(w, n, &w.key, false, true, true, None).unwrap_or_else(|_| Wallet {
        token: w.token.clone(),
        key: Probe::spawn(),
    })
}

/// A block signed by an arbitrary key (not the committed one), without any check.
pub fn append_c_with_key(w: &Wallet, n: &Narrowing, key: &Probe) -> Wallet {
    append_impl(w, n, key, false, false, true, None).unwrap_or_else(|_| Wallet {
        token: w.token.clone(),
        key: Probe::spawn(),
    })
}

/// A holder appends a narrowing block even past the limit of seven (the verifier must still refuse the token).
pub fn append_c_unlimited(w: &Wallet, n: &Narrowing) -> Wallet {
    append_impl(w, n, &w.key, true, true, false, None).unwrap_or_else(|_| Wallet {
        token: w.token.clone(),
        key: Probe::spawn(),
    })
}

/// A holder appends a block that commits to a GIVEN next public key (not a fresh one): used to splice a delegate's later block onto a different
/// ancestor that commits the same key. The returned wallet's key does not match the committed one.
pub fn append_c_committing(w: &Wallet, n: &Narrowing, next_pubkey_hex: &str) -> Wallet {
    append_impl(w, n, &w.key, true, true, true, Some(next_pubkey_hex)).unwrap_or_else(|_| Wallet {
        token: w.token.clone(),
        key: Probe::spawn(),
    })
}
