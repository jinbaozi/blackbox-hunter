#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMPDIR="${TMPDIR:-/tmp}/bbh-rpm-real-$$"
trap 'rm -rf "$TMPDIR"' EXIT
mkdir -p "$TMPDIR/workspace"

if [ "${BBH_RUN_RPM_INTEGRATION:-0}" != "1" ]; then
  echo "SKIP: set BBH_RUN_RPM_INTEGRATION=1 to run real RPM extraction integration"
  exit 0
fi

RPM_PATH="$(bash "$ROOT/tests/integration/build_minimal_rpm.sh" "$TMPDIR" || true)"
if [ -z "$RPM_PATH" ] || [ ! -f "$RPM_PATH" ]; then
  echo "SKIP: unable to build real RPM fixture"
  exit 0
fi
if ! command -v rpm2cpio >/dev/null 2>&1 || ! command -v cpio >/dev/null 2>&1; then
  echo "SKIP: rpm2cpio and cpio are required for real RPM extraction integration"
  exit 0
fi

SCAN_ID="BBH-20260704-rpmint"
python3 "$ROOT/tools/bbh_scan.py" --package "$RPM_PATH" --workspace "$TMPDIR/workspace" --scan-id "$SCAN_ID" --mode quick >/dev/null

python3 - "$TMPDIR/workspace/$SCAN_ID/target_profile.json" "$TMPDIR/workspace/$SCAN_ID/scan_state.json" <<'PY'
import json, sys
profile = json.load(open(sys.argv[1], encoding="utf-8"))
state = json.load(open(sys.argv[2], encoding="utf-8"))
assert state["current_phase"] == "completed", state
assert profile["package"]["type"] == "rpm", profile
method = profile["extraction"]["method"]
assert method != "synthetic-rpm-fixture", method
assert method == "rpm2cpio+cpio", method
assert profile["binaries"], profile
PY

echo "real RPM extraction integration OK"
