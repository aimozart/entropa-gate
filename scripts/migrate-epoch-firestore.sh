#!/usr/bin/env bash
# Reports before/after block counts around an epoch rotation and refuses to
# proceed if the target epoch already has data -- a safety check alongside the
# real rotation logic, which lives in Rust (persistence.rs's epoch chaining,
# see the project history 2026-08-18). Firestore isn't gcloud-CLI-driven in this
# project (direct REST calls, same as leader.rs), so the count operation is a
# swappable command (COUNT_CMD) rather than a gcloud invocation.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/gcloud-runner.sh"

require_env PROJECT_ID
require_env SOURCE_EPOCH
require_env TARGET_EPOCH

count_blocks() {
    local epoch="$1"
    "${COUNT_CMD:?COUNT_CMD must be set to a real Firestore-count command in production}" "$epoch"
}

before_count="$(count_blocks "$SOURCE_EPOCH")"
target_count="$(count_blocks "$TARGET_EPOCH")"

if [ "$target_count" != "0" ]; then
    echo "error: target epoch $TARGET_EPOCH already exists with $target_count block(s) -- refusing to overwrite" >&2
    exit 1
fi

if [ "${DRY_RUN:-0}" = "1" ]; then
    echo "Would migrate from $SOURCE_EPOCH to $TARGET_EPOCH (project $PROJECT_ID)"
    echo "before: $SOURCE_EPOCH has $before_count block(s), $TARGET_EPOCH has $target_count block(s)"
    exit 0
fi

echo "before: $SOURCE_EPOCH has $before_count block(s), $TARGET_EPOCH has $target_count block(s)"
echo "note: the actual rotation is performed by the running Rust service (persistence.rs) on its next resume, not by this script -- this script is the pre-flight safety check and count report around that event."
