#!/usr/bin/env bash
# CycloneDX SBOMs (JSON) for each crate, written next to the crate's Cargo.toml as *.cdx.json (gitignored).
set -euo pipefail
source "$(dirname "$0")/lib-docker.sh"
in_dev cargo cyclonedx --format json
find "$ROOT/crates" -name '*.cdx.json' -print
