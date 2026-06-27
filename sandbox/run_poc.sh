#!/bin/bash
set -euo pipefail

POC_SCRIPT="${POC_SCRIPT:-/poc/run.sh}"
TIMEOUT="${TIMEOUT:-300}"
OUTPUT_DIR="/workspace/results"
mkdir -p "$OUTPUT_DIR"

case "$TIMEOUT" in
  ''|*[!0-9]*) echo "ERROR: TIMEOUT must be numeric" >&2; exit 2 ;;
esac

write_state() {
  local name="$1"
  {
    echo "--- $name ---"
    date -u +%Y-%m-%dT%H:%M:%SZ
    id
    ps aux 2>/dev/null || true
    ss -tlnp 2>/dev/null || true
  } > "$OUTPUT_DIR/${name}.txt"
}

if [ ! -f "$POC_SCRIPT" ]; then
  echo "ERROR: PoC script not found: $POC_SCRIPT" > "$OUTPUT_DIR/stderr.txt"
  echo 1 > "$OUTPUT_DIR/exit_code.txt"
  exit 1
fi

write_state pre_state
/opt/monitor.sh "$OUTPUT_DIR/monitor.log" &
MONITOR_PID=$!

EXIT_CODE=0
timeout --preserve-status "$TIMEOUT" bash "$POC_SCRIPT" > "$OUTPUT_DIR/stdout.txt" 2> "$OUTPUT_DIR/stderr.txt" || EXIT_CODE=$?

kill "$MONITOR_PID" 2>/dev/null || true
wait "$MONITOR_PID" 2>/dev/null || true
write_state post_state

echo "$EXIT_CODE" > "$OUTPUT_DIR/exit_code.txt"
exit "$EXIT_CODE"
