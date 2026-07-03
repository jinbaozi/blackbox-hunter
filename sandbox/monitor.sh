#!/bin/sh
set -eu

PID=""
INTERVAL="${MONITOR_INTERVAL:-1}"
OUT="${MONITOR_OUT:-/tmp/poc-monitor.log}"

usage() {
  echo "usage: monitor.sh --pid <pid> [--out <path>]" >&2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --pid)
      [ "$#" -ge 2 ] || { usage; exit 2; }
      PID="$2"
      shift 2
      ;;
    --out)
      [ "$#" -ge 2 ] || { usage; exit 2; }
      OUT="$2"
      shift 2
      ;;
    *)
      # Backward-compatible positional form: monitor.sh <pid> [out]
      if [ -z "$PID" ]; then
        PID="$1"
      else
        OUT="$1"
      fi
      shift
      ;;
  esac
done

if [ -z "$PID" ]; then
  usage
  exit 2
fi

case "$PID" in
  ''|*[!0-9]*) echo "ERROR: PID must be numeric" >&2; exit 2 ;;
esac
case "$INTERVAL" in
  ''|*[!0-9]*) echo "ERROR: MONITOR_INTERVAL must be numeric" >&2; exit 2 ;;
esac

mkdir -p "$(dirname "$OUT")"
while kill -0 "$PID" 2>/dev/null; do
  if [ -r "/proc/$PID/status" ]; then
    awk '/^(VmPeak|VmRSS|Threads|voluntary_ctxt_switches|nonvoluntary_ctxt_switches):/ {print strftime("%Y-%m-%dT%H:%M:%SZ"), $0}' "/proc/$PID/status" >> "$OUT"
  else
    printf '%s pid=%s status=unreadable\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$PID" >> "$OUT"
  fi
  sleep "$INTERVAL"
done
