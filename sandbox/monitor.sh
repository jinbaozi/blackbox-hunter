#!/bin/sh
set -eu

PID="${1:-}"
INTERVAL="${MONITOR_INTERVAL:-1}"
OUT="${MONITOR_OUT:-/tmp/poc-monitor.log}"

if [ -z "$PID" ]; then
  echo "usage: monitor.sh <pid>" >&2
  exit 2
fi

while kill -0 "$PID" 2>/dev/null; do
  if [ -r "/proc/$PID/status" ]; then
    awk '/^(VmRSS|Threads|voluntary_ctxt_switches|nonvoluntary_ctxt_switches):/ {print strftime("%Y-%m-%dT%H:%M:%SZ"), $0}' "/proc/$PID/status" >> "$OUT"
  fi
  sleep "$INTERVAL"
done
