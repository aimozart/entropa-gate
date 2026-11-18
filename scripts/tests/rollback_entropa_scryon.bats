#!/usr/bin/env bats
# Tests for scripts/rollback-entropa-scryon.sh against a fake gcloud binary.

setup() {
    REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
    export GCLOUD_CALL_LOG="$BATS_TEST_TMPDIR/gcloud-calls.log"
    export GCLOUD_BIN="$REPO_ROOT/scripts/tests/fakes/gcloud"
    export SMOKE_CMD="true"
    export PROJECT_ID="entropa-testnet"
    export REGION="us-central1"
    export SERVICE="entropa-scryon"
    ROLLBACK_SCRIPT="$REPO_ROOT/scripts/rollback-entropa-scryon.sh"
}

@test "fails without a target revision" {
    run "$ROLLBACK_SCRIPT"
    [ "$status" -ne 0 ]
    [[ "$output" == *"REVISION"* ]]
}

@test "refuses an ambiguous revision (comma-separated list)" {
    export REVISION="entropa-scryon-00026-6sj,entropa-scryon-00025-abc"
    run "$ROLLBACK_SCRIPT"
    [ "$status" -ne 0 ]
    [[ "$output" == *"ambiguous"* ]]
}

@test "dry run prints the selected revision without executing the traffic update" {
    export REVISION="entropa-scryon-00026-6sj"
    export DRY_RUN=1
    run "$ROLLBACK_SCRIPT"
    [ "$status" -eq 0 ]
    [[ "$output" == *"entropa-scryon-00026-6sj"* ]]
    # The revision-existence check is a safe read and still runs even in dry-run --
    # only the actual traffic-shifting call is skipped.
    ! grep -q "update-traffic" "$GCLOUD_CALL_LOG"
}

@test "rollback uses the entropa-scryon service name" {
    export REVISION="entropa-scryon-00026-6sj"
    run "$ROLLBACK_SCRIPT"
    [ "$status" -eq 0 ]
    grep -q "entropa-scryon" "$GCLOUD_CALL_LOG"
}

@test "rollback uses the us-central1 region" {
    export REVISION="entropa-scryon-00026-6sj"
    run "$ROLLBACK_SCRIPT"
    [ "$status" -eq 0 ]
    grep -q "us-central1" "$GCLOUD_CALL_LOG"
}

@test "rollback runs the post-rollback health smoke check" {
    export REVISION="entropa-scryon-00026-6sj"
    export SMOKE_CMD="$BATS_TEST_TMPDIR/mark-smoke-ran.sh"
    printf '#!/usr/bin/env bash\ntouch "%s/smoke-ran"\n' "$BATS_TEST_TMPDIR" > "$SMOKE_CMD"
    chmod +x "$SMOKE_CMD"
    run "$ROLLBACK_SCRIPT"
    [ "$status" -eq 0 ]
    [ -f "$BATS_TEST_TMPDIR/smoke-ran" ]
}

@test "rollback fails closed if the smoke check fails after rollback" {
    export REVISION="entropa-scryon-00026-6sj"
    export SMOKE_CMD="false"
    run "$ROLLBACK_SCRIPT"
    [ "$status" -ne 0 ]
}

@test "refuses to roll back to a revision that doesn't exist" {
    export REVISION="entropa-scryon-99999-nope"
    run "$ROLLBACK_SCRIPT"
    [ "$status" -ne 0 ]
    [[ "$output" == *"does not exist"* ]]
    [ ! -f "$GCLOUD_CALL_LOG" ] || ! grep -q "update-traffic" "$GCLOUD_CALL_LOG"
}

@test "proceeds when the target revision is confirmed to exist" {
    export REVISION="entropa-scryon-00025-abc"
    run "$ROLLBACK_SCRIPT"
    [ "$status" -eq 0 ]
    grep -q "update-traffic" "$GCLOUD_CALL_LOG"
}
