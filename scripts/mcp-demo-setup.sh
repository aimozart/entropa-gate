#!/usr/bin/env bash
# Builds entropa-mcp (release) and writes the synthetic demo fixtures for docs/REAL-CLIENT-TEST.md.
# Prints the two lines the owner pastes before starting Claude Code. Needs Docker only.
set -euo pipefail
source "$(dirname "$0")/lib-docker.sh"
in_dev cargo build --release -p entropa-mcp --locked
in_dev cargo run --release -p entropa-mcp --locked --example make_fixture -- /work/target/mcp-demo
echo
echo "Paste these three lines in the terminal, then start Claude Code from $ROOT:"
echo "  export ENTROPA_MCP_BIN=$ROOT/target/release/entropa-mcp"
echo "  export ENTROPA_DEMO_DIR=$ROOT/target/mcp-demo"
echo "  export ENTROPA_DEMO_PUBKEY=\$(cat $ROOT/target/mcp-demo/trusted_pubkey.txt)"
