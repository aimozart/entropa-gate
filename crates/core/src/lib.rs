//! # Entropa core
//!
//! Post-quantum primitives for Entropa's signed Merkle transparency log.
//!
//! - [`pqc`] — Probe identities and ML-DSA (FIPS-204) post-quantum signatures.
//! - [`merkle`] — domain-separated leaf/node hashing and inclusion proofs
//!   (Certificate-Transparency-style, RFC 6962).
//! - [`transparency_log`] — the append-only log itself: append, checkpoint,
//!   receipt, and independent verification.
//!
//! This crate is pure Rust with no network calls of its own.

pub mod anchor;
pub mod merkle;
pub mod pqc;
pub mod signer;
pub mod transparency_log;

pub use pqc::{probe_id, verify_hex, Probe};
pub use signer::{CheckpointSigner, SignError};

/// Compiles and runs the README quickstart as a doc test.
#[cfg(all(doctest, feature = "signing"))]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
