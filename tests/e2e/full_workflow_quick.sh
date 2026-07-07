#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMPDIR="${TMPDIR:-/tmp}/bbh-full-workflow-$$"
trap 'rm -rf "$TMPDIR"' EXIT
mkdir -p "$TMPDIR/workspace" "$TMPDIR/pkg/DEBIAN" "$TMPDIR/pkg/usr/bin"

cat > "$TMPDIR/registry-workflow.json" <<'EOF'
{
  "registry_version": 1,
  "package_manager_priority": {
    "rpm": ["dnf", "microdnf", "yum", "zypper", "rpm-ostree", "apt", "brew"],
    "deb": ["apt", "dnf", "microdnf", "yum", "zypper", "rpm-ostree", "brew"]
  },
  "tools": [
    {
      "name": "docker",
      "binary_name": "docker",
      "execution_model": "host_binary",
      "install_priority": ["manual"],
      "install_cmds": {"manual": "manual docker"},
      "priority": "required_verify",
      "fallbacks": [],
      "platform": ["linux", "darwin"]
    },
    {
      "name": "yara",
      "binary_name": "yara",
      "execution_model": "host_binary",
      "install_priority": ["manual"],
      "install_cmds": {"manual": "manual yara"},
      "priority": "high",
      "fallbacks": [],
      "platform": ["linux", "darwin"]
    }
  ]
}
EOF

cat > "$TMPDIR/pkg/DEBIAN/control" <<'EOF'
Package: bbh-full
Version: 1.0
Section: utils
Priority: optional
Architecture: all
Maintainer: BlackBox Hunter <noreply@example.invalid>
Description: full workflow fixture
EOF

cat > "$TMPDIR/pkg/usr/bin/bbh-full" <<'EOF'
#!/bin/sh
printf '%s
' full-workflow
EOF
chmod +x "$TMPDIR/pkg/usr/bin/bbh-full"

if command -v dpkg-deb >/dev/null 2>&1; then
  dpkg-deb --build "$TMPDIR/pkg" "$TMPDIR/bbh-full.deb" >/dev/null
else
  echo "dpkg-deb unavailable; skipping full deb workflow fixture"
  exit 0
fi

DEB_SCAN_ID="BBH-20260703-fwf001"
python3 "$ROOT/tools/bbh_scan.py" \
  --package "$TMPDIR/bbh-full.deb" \
  --workspace "$TMPDIR/workspace" \
  --registry "$TMPDIR/registry-workflow.json" \
  --scan-id "$DEB_SCAN_ID" \
  --mode quick >/dev/null

test -s "$TMPDIR/workspace/$DEB_SCAN_ID/env_check.json"
test -s "$TMPDIR/workspace/$DEB_SCAN_ID/target_profile.json"
test -s "$TMPDIR/workspace/$DEB_SCAN_ID/track_a_findings.json"
test -s "$TMPDIR/workspace/$DEB_SCAN_ID/track_b_findings.json"
test -s "$TMPDIR/workspace/$DEB_SCAN_ID/merged_findings.json"
test -s "$TMPDIR/workspace/$DEB_SCAN_ID/verified_findings.json"
test -s "$TMPDIR/workspace/$DEB_SCAN_ID/report/blackbox-security-report.md"
grep -q "预检环境摘要" "$TMPDIR/workspace/$DEB_SCAN_ID/report/blackbox-security-report.md"
grep -q "Track A 汇总" "$TMPDIR/workspace/$DEB_SCAN_ID/report/blackbox-security-report.md"
grep -q "覆盖缺口" "$TMPDIR/workspace/$DEB_SCAN_ID/report/blackbox-security-report.md"

python3 - "$TMPDIR/workspace/$DEB_SCAN_ID/scan_state.json" "$TMPDIR/workspace/$DEB_SCAN_ID/track_a_findings.json" "$TMPDIR/workspace/$DEB_SCAN_ID/merged_findings.json" <<'PY'
import json, sys
state = json.load(open(sys.argv[1], encoding="utf-8"))
track_a = json.load(open(sys.argv[2], encoding="utf-8"))
merged = json.load(open(sys.argv[3], encoding="utf-8"))
assert state["current_phase"] == "completed", state
for phase in ["preflight", "phase_0", "track_a", "track_b", "phase_2", "phase_4"]:
    assert state["phase_status"][phase]["status"] == "done", (phase, state["phase_status"][phase])
assert state["phase_status"]["phase_3"]["status"] in {"done", "skipped"}
assert track_a["status"] == "skipped"
assert track_a["warnings"], track_a
assert merged["dedup_stats"]["input_findings"] == 0
assert "track_a_status" in merged["coverage_summary"]
PY

test -d "$TMPDIR/workspace/$DEB_SCAN_ID/poc_results"
python3 - "$TMPDIR/workspace/$DEB_SCAN_ID/verified_findings.json" "$TMPDIR/workspace/$DEB_SCAN_ID/scan_state.json" <<'PY'
import json, sys
verified = json.load(open(sys.argv[1], encoding="utf-8"))
state = json.load(open(sys.argv[2], encoding="utf-8"))
if state["phase_status"]["phase_3"]["status"] == "skipped":
    assert verified["verification_stats"].get("skipped", 0) >= 0
    assert any(item.get("phase") == "phase_3" for item in state.get("error_log", [])), state
PY

DEFAULT_SCAN_ID="BBH-20260703-fwf003"
(
  cd "$TMPDIR"
  python3 "$ROOT/tools/bbh_scan.py" \
    --package "$TMPDIR/bbh-full.deb" \
    --registry "$TMPDIR/registry-workflow.json" \
    --scan-id "$DEFAULT_SCAN_ID" \
    --mode quick >/dev/null
)

test -s "$TMPDIR/black-audit-output/$DEFAULT_SCAN_ID/env_check.json"
test -s "$TMPDIR/black-audit-output/$DEFAULT_SCAN_ID/report/findings.json"

cat > "$TMPDIR/bbh-full.rpm" <<'EOF'
RPM_FIXTURE_PLACEHOLDER_FOR_CONTEXT_BUILD_ONLY
EOF

RPM_SCAN_ID="BBH-20260703-fwf002"
python3 "$ROOT/tools/bbh_scan.py" \
  --package "$TMPDIR/bbh-full.rpm" \
  --workspace "$TMPDIR/workspace" \
  --registry "$TMPDIR/registry-workflow.json" \
  --scan-id "$RPM_SCAN_ID" \
  --mode quick \
  --allow-synthetic-rpm-fixture >/dev/null

test -s "$TMPDIR/workspace/$RPM_SCAN_ID/report/blackbox-security-report.md"
grep -q "目标画像摘要" "$TMPDIR/workspace/$RPM_SCAN_ID/report/blackbox-security-report.md"
python3 - "$TMPDIR/workspace/$RPM_SCAN_ID/scan_state.json" "$TMPDIR/workspace/$RPM_SCAN_ID/target_profile.json" <<'PY'
import json, sys
state = json.load(open(sys.argv[1], encoding="utf-8"))
profile = json.load(open(sys.argv[2], encoding="utf-8"))
assert state["current_phase"] == "completed", state
assert profile["package"]["type"] == "rpm"
assert profile["extraction"]["method"] == "synthetic-rpm-fixture"
PY

echo "full workflow quick e2e OK"
