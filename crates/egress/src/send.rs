//! The only way bytes leave: a send bound to a decision (F7, F8). The guard itself never touches the network; the caller supplies the closure
//! that does, and it is called only when the decision allows exactly these bytes.
use crate::decide::{Action, Decision};

/// Why a send was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    /// The decision is a block.
    Blocked,
    /// The bytes are not the bytes that were decided (their hash differs).
    Mismatch,
}

/// Hand `bytes` to `send` only if the decision allows them: not a block, and the SHA-256 of `bytes` equals the decided hash (the original body
/// for an allow, the redacted body for a redact).
pub fn send_with(
    decision: &Decision,
    bytes: &[u8],
    send: &mut dyn FnMut(&[u8]),
) -> Result<(), SendError> {
    let expected = match decision.action() {
        Action::Block => return Err(SendError::Blocked),
        Action::Allow => decision.request_sha256(),
        Action::Redact => decision.redacted_sha256().ok_or(SendError::Blocked)?,
    };
    if crate::decide::sha256_hex(bytes) != expected {
        return Err(SendError::Mismatch);
    }
    send(bytes);
    Ok(())
}
