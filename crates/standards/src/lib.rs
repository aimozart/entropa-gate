//! # entropa-standards (R1)
//!
//! Deterministic retrieval over a sealed, versioned standards corpus, for AI agents. This crate holds the pure core: clause-level
//! chunking, sealing into versions that are never overwritten, and (later modules) BM25 retrieval with an abstention gate and a citation
//! check. It never generates text, never calls a model and never opens a network connection. Licensed text exists only in the local
//! sealed store, never in a repository.

pub mod chunk;
pub mod citations;
pub mod corpus;
pub mod eval;
pub mod flags;
pub mod r2eval;
pub mod r3eval;
pub mod records;
pub mod retrieve;
pub mod rs1eval;
pub mod seal;
pub mod text;
pub mod tools;
