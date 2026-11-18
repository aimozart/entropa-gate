# ADR 0015: keep the working history; publish from a clean squashed branch
Date: 2026-10-20. Status: accepted (decision by the reviewer for the owner, stage S0c3).

## Context
The stage branches are on the private Gitea remote. Commit 97f34f9 accidentally tracked the generated fuzz corpus (5,203 files); 6a2125e untracked it, but it stays in history. Rewriting local history would need a force push, which is forbidden here, and the red/green commit sequence is itself the evidence Paxel reads.

## Decision
Do not rewrite the working history. When the project goes to GitHub, create a new publication branch with one clean commit per stage (no fuzz corpus), built from the stage heads listed in docs/EVIDENCE-INDEX.md. The Gitea history remains the full record.

## Consequences
The Gitea repository is larger than a clean one by the corpus blobs. The published history will not show every red/green commit, so docs/EVIDENCE-INDEX.md and docs/evidence/ must travel with it (they do, they are files in the tree). Nothing goes to GitHub until the owner says so.
