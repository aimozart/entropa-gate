#!/usr/bin/env bash
# Shared helpers for entropa-chain's deploy/rollback/migration scripts — the only
# place that directly invokes gcloud, so it's the one place a test can swap in a
# fake binary (GCLOUD_BIN) and assert on exactly what was called (GCLOUD_CALL_LOG,
# written by the fake itself — see scripts/tests/fakes/gcloud).

require_env() {
    local var_name="$1"
    if [ -z "${!var_name:-}" ]; then
        echo "error: required environment variable $var_name is not set" >&2
        exit 1
    fi
}

# Runs gcloud (or its fake, via GCLOUD_BIN) with the given args — unless DRY_RUN=1,
# in which case it prints the command it would have run and does nothing else.
run_gcloud() {
    local bin="${GCLOUD_BIN:-gcloud}"
    if [ "${DRY_RUN:-0}" = "1" ]; then
        echo "$bin $*"
        return 0
    fi
    "$bin" "$@"
}
