#!/bin/bash
# Captures entropa-scryon's real application stdout/stderr during a live production
# test/action and appends it, in real time, to docs/LIVE_TEST_LOG.md.
#
# Why this exists, and why it filters on stdout/stderr specifically (not the more
# obvious-looking HTTP-access-log filter, which returns blank payloads for this
# service): see docs/operations.md § Live-testing evidence practice (the project rules).
#
# Usage:
#   scripts/observability/live_log_capture.sh start "<label>"
#   scripts/observability/live_log_capture.sh stop
set -uo pipefail

ACTION="${1:-}"
LABEL="${2:-}"
PROJECT="entropa-testnet"
SERVICE="entropa-scryon"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOGFILE="$REPO_ROOT/docs/LIVE_TEST_LOG.md"
PIDFILE="/tmp/entropa_live_capture.pid"
SEENFILE="/tmp/entropa_live_capture_seen.txt"

usage() {
    echo "Usage: $0 start \"<label>\"   |   $0 stop"
    exit 1
}

case "$ACTION" in
  start)
    [ -n "$LABEL" ] || usage
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        echo "A capture is already running (pid $(cat "$PIDFILE")). Run 'stop' first." >&2
        exit 1
    fi
    : > "$SEENFILE"
    {
        echo ""
        echo "## $(date -u +%Y-%m-%dT%H:%M:%SZ) UTC — $LABEL (capture started)"
        echo '```'
    } >> "$LOGFILE"
    (
        while true; do
            gcloud logging read "resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"$SERVICE\" AND (logName=\"projects/$PROJECT/logs/run.googleapis.com%2Fstdout\" OR logName=\"projects/$PROJECT/logs/run.googleapis.com%2Fstderr\")" \
                --project="$PROJECT" --format="csv[no-heading](insertId,timestamp,textPayload)" \
                --order=asc --freshness=10m 2>/dev/null |
            while IFS=, read -r id ts msg; do
                [ -z "$id" ] && continue
                if ! grep -qF "$id" "$SEENFILE" 2>/dev/null; then
                    echo "$id" >> "$SEENFILE"
                    echo "$ts  $msg" >> "$LOGFILE"
                fi
            done
            sleep 4
        done
    ) &
    disown
    echo $! > "$PIDFILE"
    echo "Capture started (pid $(cat "$PIDFILE")) -> $LOGFILE"
    ;;
  stop)
    if [ -f "$PIDFILE" ]; then
        kill "$(cat "$PIDFILE")" 2>/dev/null
        rm -f "$PIDFILE"
        echo '```' >> "$LOGFILE"
        echo "Capture stopped. See $LOGFILE"
    else
        echo "No capture running."
    fi
    ;;
  *)
    usage
    ;;
esac
