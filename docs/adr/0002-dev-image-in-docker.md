# ADR 0002: Run all tooling in a pinned Docker dev image
Date: 2026-10-20. Status: accepted (stage S0b).

## Context
Rust and Node are not installed on the build PC; results must be reproducible.

## Decision
tools/Dockerfile.dev builds entropa-dev:1 from rust:1.99.1-bookworm with clippy, rustfmt, llvm-tools, a nightly toolchain and the cargo tools below. scripts/*.sh run inside it via scripts/lib-docker.sh. rust-toolchain.toml pins the same stable version.

## Consequences
First build compiles several tools (slow, cached after). Tool versions are not pinned individually (cargo install --locked uses each tool's own lockfile); revisit if drift hurts.
