#!/usr/bin/env bats
# Tests for scripts/migrate-epoch-firestore.sh. Firestore isn't gcloud-CLI-driven
# in this project (persistence.rs talks to it via direct REST calls) -- so instead
# of faking gcloud, this fakes the count command the script shells out to.

setup() {
    REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
    export PROJECT_ID="entropa-testnet"
    export SOURCE_EPOCH="epoch-old"
    export TARGET_EPOCH="epoch-new"
    MIGRATE_SCRIPT="$REPO_ROOT/scripts/migrate-epoch-firestore.sh"
}

fake_count_cmd() {
    # $1: epoch name to "count" -- echoes a fixed number based on which epoch is asked about
    local script="$BATS_TEST_TMPDIR/fake-count.sh"
    cat > "$script" <<EOF
#!/usr/bin/env bash
case "\$1" in
    epoch-old) echo "$1" ;;
    epoch-new) echo "$2" ;;
    *) echo "0" ;;
esac
EOF
    chmod +x "$script"
    echo "$script"
}

@test "fails without a source epoch" {
    unset SOURCE_EPOCH
    run "$MIGRATE_SCRIPT"
    [ "$status" -ne 0 ]
    [[ "$output" == *"SOURCE_EPOCH"* ]]
}

@test "fails without a target epoch" {
    unset TARGET_EPOCH
    run "$MIGRATE_SCRIPT"
    [ "$status" -ne 0 ]
    [[ "$output" == *"TARGET_EPOCH"* ]]
}

@test "refuses to proceed when the target epoch already has blocks" {
    export COUNT_CMD
    COUNT_CMD="$(fake_count_cmd 974 5)" # target epoch already has 5 blocks
    run "$MIGRATE_SCRIPT"
    [ "$status" -ne 0 ]
    [[ "$output" == *"already exists"* ]]
}

@test "dry run prints the plan without proceeding" {
    export COUNT_CMD
    COUNT_CMD="$(fake_count_cmd 974 0)"
    export DRY_RUN=1
    run "$MIGRATE_SCRIPT"
    [ "$status" -eq 0 ]
    [[ "$output" == *"epoch-old"* ]]
    [[ "$output" == *"epoch-new"* ]]
}

@test "emits before and after block counts" {
    export COUNT_CMD
    COUNT_CMD="$(fake_count_cmd 974 0)"
    run "$MIGRATE_SCRIPT"
    [ "$status" -eq 0 ]
    [[ "$output" == *"before"* ]]
    [[ "$output" == *"974"* ]]
}
