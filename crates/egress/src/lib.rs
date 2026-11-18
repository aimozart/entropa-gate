//! Egress Guard engine (EG1): a deterministic, offline check of every outbound model or tool request. It holds no network client, reads no
//! clock to decide, and contains no learned component. Design: `a stage record (not published)`; plan and bars: `a stage record (not published)`. Results are "tested
//! against these sets": nothing here claims that all secrets or all personal data are found.
#![deny(missing_docs)]

pub mod contain;
pub mod context;
pub mod decide;
pub mod detect;
pub mod eval;
pub mod policy;
pub mod record;
pub mod sealed;
pub mod send;
pub mod v2;
pub mod views;
