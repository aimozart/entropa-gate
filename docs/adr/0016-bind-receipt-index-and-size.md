# ADR 0016: bind a receipt's index and tree size to its inclusion proof
Date: 2026-10-20. Status: accepted (stage S0g, decision by the reviewer for the owner). Closes design finding D6 of docs/ARCHITECTURE-MCP.md.

## Context
`verify_receipt` checked the checkpoint signature and that the hashes of the proof combine to the root, but ignored `receipt.index` and `checkpoint.size`. A receipt could therefore claim any index for a record that is in the log at another position (threat T10 in the MCP design).

## Decision
Add `merkle::verify_inclusion_at(leaf, index, tree_size, proof, root)`, implementing RFC 6962 / RFC 9162 inclusion verification: it rejects `index >= tree_size`, derives from `index` and `tree_size` which side every sibling must be on and the exact number of steps, and requires the path to end at the root. `verify_receipt` now calls it with `receipt.index` and `receipt.checkpoint.size`. `verify_inclusion` stays (documented as not position-binding).

## Consequences
- A proof verifies only at the index it was built for (unit tests for sizes 1 to 33 and a property test) and only if the path shape fits the claimed size.
- **Limit that cannot be removed by path shape:** two tree sizes can give the same audit-path shape for an index (for example index 1 in sizes 3 and 4). The path alone cannot distinguish them; what binds the size to the root is the signature over (root, size, timestamp). A signer that signed a false size for a real root is outside this check (the witness, S5, compares checkpoints).
- Semver: `verify_receipt` is stricter and a function is added. entropa-core 0.2.0 is unpublished, so this is a CHANGELOG entry inside 0.2.0, not a new version. Receipts produced by `TransparencyLog::receipt` and `receipts_for` all still verify (tested for every index of every size up to 33).
