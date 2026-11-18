#!/usr/bin/env bash
# The standard gate: fmt, clippy -D warnings, test --locked, doc, deny, audit, plus the public-readiness preflight (S0j). Needs docker only.
set -euo pipefail
source "$(dirname "$0")/lib-docker.sh"
[ -d "$ROOT/admin-ui/dist" ] || "$ROOT/scripts/build-admin-ui.sh"
scripts/check-site-links.sh
scripts/tests/container-limits.sh
scripts/tests/mutants-speed.sh
scripts/tests/build-admin-ui-retry.sh
scripts/tests/gitignore-baseline.sh
scripts/tests/governance-checks.sh
scripts/public-preflight.sh
scripts/tests/public-preflight-shim.sh
in_dev bash -ec '
set -x
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo deny check
cargo audit
'
