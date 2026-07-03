#!/bin/bash
set -euo pipefail

POC_SCRIPT="${POC_SCRIPT:-/poc/run.sh}"
TIMEOUT="${TIMEOUT:-300}"
OUTPUT_DIR="${OUTPUT_DIR:-/workspace/results}"
MONITOR_INTERVAL="${MONITOR_INTERVAL:-1}"
mkdir -p "$OUTPUT_DIR"

case "$TIMEOUT" in
  ''|*[!0-9]*) echo "ERROR: TIMEOUT must be numeric" >&2; exit 2 ;;
esac
case "$MONITOR_INTERVAL" in
  ''|*[!0-9]*) echo "ERROR: MONITOR_INTERVAL must be numeric" >&2; exit 2 ;;
esac

write_state() {
  local name="$1"
  {
    echo "--- $name ---"
    date -u +%Y-%m-%dT%H:%M:%SZ
    id
    pwd
    ps aux 2>/dev/null || true
    ss -tlnp 2>/dev/null || true
    find /workspace -maxdepth 2 -mindepth 1 -printf '%M %u %g %p\n' 2>/dev/null || true
  } > "$OUTPUT_DIR/${name}.txt"
}

write_result() {
  local exit_code="$1"
  local timed_out="$2"
  local status="$3"
  echo "$exit_code" > "$OUTPUT_DIR/exit_code.txt"
  echo "$timed_out" > "$OUTPUT_DIR/timeout.txt"
  echo "$status" > "$OUTPUT_DIR/status.txt"
}

stop_process() {
  local pid="$1"
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    sleep 1
  fi
  if kill -0 "$pid" 2>/dev/null; then
    kill -9 "$pid" 2>/dev/null || true
  fi
}

if [ ! -f "$POC_SCRIPT" ]; then
  echo "ERROR: PoC script not found: $POC_SCRIPT" > "$OUTPUT_DIR/stderr.txt"
  : > "$OUTPUT_DIR/stdout.txt"
  write_state pre_state
  write_state post_state
  write_result 1 false poc_error
  exit 1
fi

if [ ! -r "$POC_SCRIPT" ]; then
  echo "ERROR: PoC script is not readable: $POC_SCRIPT" > "$OUTPUT_DIR/stderr.txt"
  : > "$OUTPUT_DIR/stdout.txt"
  write_state pre_state
  write_state post_state
  write_result 1 false poc_error
  exit 1
fi

write_state pre_state

bash "$POC_SCRIPT" > "$OUTPUT_DIR/stdout.txt" 2> "$OUTPUT_DIR/stderr.txt" &
POC_PID=$!

MONITOR_PID=""
MONITOR_OUT="$OUTPUT_DIR/monitor.log"
MONITOR_INTERVAL="$MONITOR_INTERVAL" /opt/monitor.sh --pid "$POC_PID" --out "$MONITOR_OUT" &
MONITOR_PID=$!

TIMEOUT_EXIT=0
timeout "$TIMEOUT" sh -c 'while kill -0 "$1" 2>/dev/null; do sleep 1; done' sh "$POC_PID" || TIMEOUT_EXIT=$?

TIMED_OUT=false
EXIT_CODE=0
STATUS=failed

if [ "$TIMEOUT_EXIT" -eq 124 ]; then
  TIMED_OUT=true
  STATUS=timeout
  stop_process "$POC_PID"
  wait "$POC_PID" 2>/dev/null || true
  EXIT_CODE=124
else
  wait "$POC_PID" || EXIT_CODE=$?
  if [ "$EXIT_CODE" -eq 0 ]; then
    STATUS=completed
  elif [ "$EXIT_CODE" -gt 128 ]; then
    STATUS=crash
  else
    STATUS=failed
  fi
fi

if [ -n "$MONITOR_PID" ]; then
  kill "$MONITOR_PID" 2>/dev/null || true
  wait "$MONITOR_PID" 2>/dev/null || true
fi

write_state post_state
write_result "$EXIT_CODE" "$TIMED_OUT" "$STATUS"

exit "$EXIT_CODE"
