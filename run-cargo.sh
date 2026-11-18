#!/usr/bin/env bash
# Runs cargo in a container (Rust is not installed on this PC).
# Usage: ./run-cargo.sh test | clippy --workspace --all-targets -- -D warnings | fmt --all [-- --check]
# Uses the local image clinic-rust:1 (rust:1-bookworm plus clippy and rustfmt, see ../clinic-ops/tools/Dockerfile.rust),
# built automatically on first use. To rebuild it: docker build -t clinic-rust:1 -f ../clinic-ops/tools/Dockerfile.rust ../clinic-ops/tools
set -euo pipefail
cd "$(dirname "$0")"
IMAGE="${CLINIC_RUST_IMAGE:-clinic-rust:1}"
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "run-cargo.sh: building $IMAGE (first use)..." >&2
  docker build -q -t "$IMAGE" -f ../clinic-ops/tools/Dockerfile.rust ../clinic-ops/tools >&2
fi
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/work/target \
  -v "$HOME/.cache/clinic-cargo":/cargo -v "$PWD":/work -w /work "$IMAGE" cargo "$@"
