#!/usr/bin/env bash
# This repo's CI. entropa-chain is Gitea-hosted (<private-lan-address>), private, and
# deliberately never touches GitHub Actions or any third-party CI runner - the
# private transparency-log/ingest source must never leave local disk / Cloud
# Build (see SECURITY.md and ARCHITECTURE.md § Repo split). This script IS the
# CI for this repo: run it before every push, same checks entropa-public's
# GitHub Actions run.
set -euo pipefail

echo "== cargo fmt --check =="
cargo fmt --all -- --check

echo "== cargo clippy -D warnings =="
cargo clippy --workspace --all-targets -- -D warnings

echo "== cargo test --workspace =="
cargo test --workspace

echo "== file size ceiling =="
./scripts/check-file-sizes.sh

echo "== document links (project rule harness) =="
./scripts/check-doc-links.sh

echo "== test coverage gate (project rule backstop) =="
python3 ./scripts/check-test-coverage-gate.py

echo "== gitleaks (secret scan) =="
./scripts/security/secret-scan.sh

echo "== cargo audit (dependency scan) =="
./scripts/security/dependency-audit.sh

echo ""
echo "ALL CHECKS PASSED — this repo's CI is green."
