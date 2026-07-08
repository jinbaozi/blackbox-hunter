#!/bin/bash
# A2 e2e regression: Track A default-on for standard/deep/full modes.
#
# Verifies the mode-aware default policy in ``tools.bbh_scan`` end-to-end:
#   1. mode=standard without --run-track-a-tools ATTEMPTS Track A
#      (scan_state.json shows track_a.status: running, not skipped).
#   2. --skip-track-a overrides the standard-mode default
#      (track_a.status: skipped, metadata.skipped_reason=explicit_skip_track_a_flag).
#   3. mode=quick without flags remains skipped (back-compat)
#      (metadata.skipped_reason=mode_quick_default_skip).
#   4. mode=quick + --run-track-a-tools still attempts Track A (back-compat).
#   5. mode=deep, mode=full also default to running Track A.
#
# NOTE: A2 only changes WHEN Track A is invoked. The pre-existing adapter bugs
# (cwe_checker FileNotFoundError, cve-bin-tool None-keys) may cause the
# invocation to fail. This test asserts the INTENT of A2 (Track A was
# attempted) via scan_state.json, not via track_a_findings.json (which may be
# missing if the run crashes).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMPDIR="${TMPDIR:-/tmp}/bbh-a2-default-$$"
WS="$TMPDIR/workspace"
REG="$ROOT/tools/tool_registry.json"
trap 'rm -rf "$TMPDIR"' EXIT
mkdir -p "$WS"

cat > "$TMPDIR/bbh-fixture.rpm" <<'EOF'
RPM_FIXTURE_PLACEHOLDER_FOR_CONTEXT_BUILD_ONLY
EOF

run_scan() {
  local sid=$1; shift
  python3 "$ROOT/tools/bbh_scan.py" \
    --package "$TMPDIR/bbh-fixture.rpm" \
    --workspace "$WS" \
    --registry "$REG" \
    --scan-id "$sid" \
    --allow-synthetic-rpm-fixture \
    "$@" >/dev/null 2>&1 || true
}

# 1. mode=standard, no flag -> track_a attempted
run_scan "BBH-20260708-a2def1" --mode standard
echo "[1] mode=standard (no flag) -> state:"
python3 - "$WS/BBH-20260708-a2def1/scan_state.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1], encoding="utf-8"))
print(f"    track_a.status={s['phase_status']['track_a']['status']}")
assert s["phase_status"]["track_a"]["status"] != "skipped", s
print("    PASS: standard mode did NOT skip Track A")
PY

# 2. mode=standard + --skip-track-a -> findings show "skipped" with explicit reason
run_scan "BBH-20260708-a2def2" --mode standard --skip-track-a
echo "[2] mode=standard + --skip-track-a -> state + findings:"
python3 - "$WS/BBH-20260708-a2def2/scan_state.json" "$WS/BBH-20260708-a2def2/track_a_findings.json" <<'PY'
import json, sys, os
s = json.load(open(sys.argv[1], encoding="utf-8"))
ta_path = sys.argv[2]
ta = json.load(open(ta_path, encoding="utf-8")) if os.path.exists(ta_path) else {}
print(f"    phase_status={s['phase_status']['track_a']['status']}  findings.status={ta.get('status')}  reason={ta.get('metadata', {}).get('skipped_reason')}")
# The phase runs successfully (status=done) but the inner findings record shows
# the skip with the explicit reason. That is the correct A2 contract.
assert s["phase_status"]["track_a"]["status"] in ("done", "skipped"), s
assert ta.get("status") == "skipped", ta
assert ta.get("metadata", {}).get("skipped_reason") == "explicit_skip_track_a_flag", ta
print("    PASS: --skip-track-a override works")
PY

# 3. mode=quick, no flag -> skipped, mode_quick_default_skip
run_scan "BBH-20260708-a2def3" --mode quick
echo "[3] mode=quick (no flag) -> back-compat:"
python3 - "$WS/BBH-20260708-a2def3/track_a_findings.json" <<'PY'
import json, sys
ta = json.load(open(sys.argv[1], encoding="utf-8"))
print(f"    status={ta['status']}  reason={ta['metadata'].get('skipped_reason')}")
assert ta["status"] == "skipped"
assert ta["metadata"]["skipped_reason"] == "mode_quick_default_skip"
print("    PASS: quick mode back-compat preserved")
PY

# 4. mode=quick + --run-track-a-tools -> Track A attempted
run_scan "BBH-20260708-a2def4" --mode quick --run-track-a-tools
echo "[4] mode=quick + --run-track-a-tools -> state:"
python3 - "$WS/BBH-20260708-a2def4/scan_state.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1], encoding="utf-8"))
print(f"    track_a.status={s['phase_status']['track_a']['status']}")
assert s["phase_status"]["track_a"]["status"] != "skipped", s
print("    PASS: --run-track-a-tools back-compat honored")
PY

# 5. mode=deep, no flag -> Track A attempted
run_scan "BBH-20260708-a2def5" --mode deep
echo "[5] mode=deep (no flag) -> state:"
python3 - "$WS/BBH-20260708-a2def5/scan_state.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1], encoding="utf-8"))
print(f"    track_a.status={s['phase_status']['track_a']['status']}")
assert s["phase_status"]["track_a"]["status"] != "skipped", s
print("    PASS: deep mode auto-attempts Track A")
PY

# 6. mode=full, no flag -> Track A attempted
run_scan "BBH-20260708-a2def6" --mode full
echo "[6] mode=full (no flag) -> state:"
python3 - "$WS/BBH-20260708-a2def6/scan_state.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1], encoding="utf-8"))
print(f"    track_a.status={s['phase_status']['track_a']['status']}")
assert s["phase_status"]["track_a"]["status"] != "skipped", s
print("    PASS: full mode auto-attempts Track A")
PY

echo "full workflow track-a-default e2e OK"
