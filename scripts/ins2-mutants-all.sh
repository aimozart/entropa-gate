#!/usr/bin/env bash
# INS2 full mutation run: runs both scripts (anchor, anchor file, raw reader, check; store v2 parts and the v2 writer). Usage: scripts/ins2-mutants-all.sh OUT_DIR
set -u
cd "$(dirname "$0")/.."
scripts/ins2-mutants.sh "$1/a"
scripts/ins2-mutants-2.sh "$1/b"
