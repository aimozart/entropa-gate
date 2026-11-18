#!/usr/bin/env bats
# Tests for scripts/deploy-entropa-scryon.sh against a fake gcloud binary — no real
# GCP calls, no network. See scripts/tests/fakes/gcloud for the fake's behavior.

setup() {
    REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
    export GCLOUD_CALL_LOG="$BATS_TEST_TMPDIR/gcloud-calls.log"
    export GCLOUD_BIN="$REPO_ROOT/scripts/tests/fakes/gcloud"
    export SMOKE_CMD="true" # a no-op that always succeeds, unless a test overrides it
    export PROJECT_ID="entropa-testnet"
    export REGION="us-central1"
    export SERVICE="entropa-scryon"
    DEPLOY_SCRIPT="$REPO_ROOT/scripts/deploy-entropa-scryon.sh"
}

@test "fails when PROJECT_ID is missing" {
    unset PROJECT_ID
    run "$DEPLOY_SCRIPT"
    [ "$status" -ne 0 ]
    [[ "$output" == *"PROJECT_ID"* ]]
}

@test "fails when REGION is missing" {
    unset REGION
    run "$DEPLOY_SCRIPT"
    [ "$status" -ne 0 ]
    [[ "$output" == *"REGION"* ]]
}

@test "fails when SERVICE is missing" {
    unset SERVICE
    run "$DEPLOY_SCRIPT"
    [ "$status" -ne 0 ]
    [[ "$output" == *"SERVICE"* ]]
}

@test "dry run prints the gcloud run deploy command without executing it" {
    export DRY_RUN=1
    run "$DEPLOY_SCRIPT"
    [ "$status" -eq 0 ]
    [[ "$output" == *"gcloud run deploy"* ]]
    # The service-existence check is a safe read and still runs even in dry-run --
    # only the actual deploy call is skipped.
    ! grep -q "^run deploy" "$GCLOUD_CALL_LOG"
}

@test "deploy uses the entropa-scryon service name" {
    run "$DEPLOY_SCRIPT"
    [ "$status" -eq 0 ]
    grep -q "entropa-scryon" "$GCLOUD_CALL_LOG"
}

@test "deploy uses the us-central1 region" {
    run "$DEPLOY_SCRIPT"
    [ "$status" -eq 0 ]
    grep -q "us-central1" "$GCLOUD_CALL_LOG"
}

@test "deploy runs the post-deploy health smoke check" {
    export SMOKE_CMD="$BATS_TEST_TMPDIR/mark-smoke-ran.sh"
    printf '#!/usr/bin/env bash\ntouch "%s/smoke-ran"\n' "$BATS_TEST_TMPDIR" > "$SMOKE_CMD"
    chmod +x "$SMOKE_CMD"
    run "$DEPLOY_SCRIPT"
    [ "$status" -eq 0 ]
    [ -f "$BATS_TEST_TMPDIR/smoke-ran" ]
}

@test "deploy fails if the health smoke check fails" {
    export SMOKE_CMD="false"
    run "$DEPLOY_SCRIPT"
    [ "$status" -ne 0 ]
}

@test "dry run does not run the smoke check" {
    export DRY_RUN=1
    export SMOKE_CMD="false" # would fail the whole script if it ran
    run "$DEPLOY_SCRIPT"
    [ "$status" -eq 0 ]
}

@test "warns but still proceeds when deploying a brand-new service not yet in the project" {
    # A genuinely new service is a real, valid case (e.g. onboarding validator-4) --
    # this must warn, not fail closed, unlike rollback's stricter existence check.
    export SERVICE="entropa-validator-4"
    run "$DEPLOY_SCRIPT"
    [ "$status" -eq 0 ]
    [[ "$output" == *"not yet a known service"* ]]
}

@test "does not warn when deploying an existing known service" {
    run "$DEPLOY_SCRIPT"
    [ "$status" -eq 0 ]
    [[ "$output" != *"not yet a known service"* ]]
}
