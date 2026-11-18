# Glossary

- **Append-only log**: a list of records that can only grow; changing an earlier record breaks the later checkpoints.
- **Checkpoint**: the size of the log and the Merkle root at that size, signed by the log's key.
- **Closed vocabulary**: a fixed list of allowed words for kinds, labels, decisions and reasons; anything else is refused.
- **Consistency proof**: evidence that a later checkpoint extends an earlier one without changing it.
- **Held-out set**: test cases written by someone other than the person who built the code and kept sealed until one run.
- **Set spent**: a held-out set that has been run once and is never run again, so it cannot be tuned against.
- **Set flaw**: a mistake in a test set (not in the code under test), listed with the results and not counted against the code.
- **Merkle tree**: a tree of hashes whose root commits to every record under it.
- **ML-DSA-65**: a post-quantum digital signature scheme (a NIST standard); used for checkpoints, tokens and release manifests.
- **Mock data, real signed records**: the label on the explorer pages; the traffic is generated, the code that decided, signed and stored it is the real code.
- **Mutation testing**: changing the code on purpose (for example flipping a comparison) to see whether the tests notice.
- **Receipt**: an inclusion proof that one record is in the log at a given checkpoint.
- **SBOM**: a software bill of materials, the list of packages a build is made from.
- **Tier (T0 to T3)**: how much a caller may send to a model and what it may do; higher tiers need stronger tokens.
- **Token**: a signed statement of what a caller may do (tier, actions, corpus, limits, expiry).
- **Witness**: an independent party that signs the checkpoints it has seen, so a log cannot show two different histories.
