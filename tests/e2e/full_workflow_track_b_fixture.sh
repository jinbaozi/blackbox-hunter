#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMPDIR="${TMPDIR:-/tmp}/bbh-trackb-workflow-$$"
trap 'rm -rf "$TMPDIR"' EXIT
mkdir -p "$TMPDIR/workspace" "$TMPDIR/pkg/DEBIAN" "$TMPDIR/pkg/usr/bin"

cat > "$TMPDIR/registry-workflow.json" <<'EOF'
{
  "registry_version": 1,
  "package_manager_priority": {
    "deb": ["apt", "dnf"],
    "rpm": ["dnf", "apt"]
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
    }
  ]
}
EOF

cat > "$TMPDIR/pkg/DEBIAN/control" <<'EOF'
Package: bbh-trackb
Version: 1.0
Section: utils
Priority: optional
Architecture: all
Maintainer: BlackBox Hunter <noreply@example.invalid>
Description: Track B fixture package
EOF

cat > "$TMPDIR/pkg/usr/bin/bbh-trackb" <<'EOF'
#!/bin/sh
printf '%s
' track-b-fixture
EOF
chmod +x "$TMPDIR/pkg/usr/bin/bbh-trackb"

if command -v dpkg-deb >/dev/null 2>&1; then
  dpkg-deb --build "$TMPDIR/pkg" "$TMPDIR/bbh-trackb.deb" >/dev/null
else
  echo "dpkg-deb unavailable; skipping Track B workflow fixture"
  exit 0
fi

cat > "$TMPDIR/track_b_positive.json" <<'EOF'
{
  "finding_present": true,
  "finding_status": "confirmed_static",
  "title": "Unchecked copy into fixed stack buffer",
  "cwe_id": "CWE-120",
  "severity": "high",
  "confidence": 0.78,
  "location": {
    "binary": "/usr/bin/bbh-trackb",
    "function": "parse_request",
    "address_offset": "0x4012ab"
  },
  "evidence": {
    "description": "The function copies attacker-controlled input into a fixed buffer without a visible length guard.",
    "supporting_files": ["context/track_b_evidence.json"],
    "source_to_sink": "argv -> parse_request -> strcpy",
    "guard_analysis": "No bounds check is visible before the copy."
  },
  "attack_surface": {
    "type": "cli",
    "entry_point": "/usr/bin/bbh-trackb"
  },
  "verification": {
    "poc_status": "untested"
  },
  "remediation": {
    "suggestion": "Use bounded parsing and reject oversized fields before copying into the fixed buffer.",
    "effort": "medium"
  },
  "references": ["https://cwe.mitre.org/data/definitions/120.html"]
}
EOF

SCAN_ID="BBH-20260704-tbf001"
python3 "$ROOT/tools/bbh_scan.py" \
  --package "$TMPDIR/bbh-trackb.deb" \
  --workspace "$TMPDIR/workspace" \
  --registry "$TMPDIR/registry-workflow.json" \
  --scan-id "$SCAN_ID" \
  --mode quick \
  --track-b-output "$TMPDIR/track_b_positive.json" \
  --track-b-dimension dangerous_functions \
  --track-b-finding-id TB-777 >/dev/null

SCAN_ROOT="$TMPDIR/workspace/$SCAN_ID"
test -s "$SCAN_ROOT/track_b_findings.json"
test -s "$SCAN_ROOT/merged_findings.json"
test -s "$SCAN_ROOT/report/findings.json"
test -s "$SCAN_ROOT/report/blackbox-security-report.md"
grep -q "发现项生命周期汇总" "$SCAN_ROOT/report/blackbox-security-report.md"
grep -q "静态确认" "$SCAN_ROOT/report/blackbox-security-report.md"

python3 - "$SCAN_ROOT/track_b_findings.json" "$SCAN_ROOT/merged_findings.json" "$SCAN_ROOT/report/findings.json" "$SCAN_ROOT/scan_state.json" "$SCAN_ID" <<'PY'
import json, sys
track_b = json.load(open(sys.argv[1], encoding="utf-8"))
merged = json.load(open(sys.argv[2], encoding="utf-8"))
report_findings = json.load(open(sys.argv[3], encoding="utf-8"))
state = json.load(open(sys.argv[4], encoding="utf-8"))
scan_id = sys.argv[5]
assert state["current_phase"] == "completed", state
assert track_b["status"] == "success", track_b
assert track_b["findings_count"] == 1, track_b
assert track_b["findings"][0]["finding_id"] == "TB-777"
assert merged["dedup_stats"]["input_findings"] == 1, merged
assert merged["dedup_stats"]["merged_findings"] == 1, merged
assert merged["merged_findings"][0]["finding"]["finding_id"] == "TB-777"
assert report_findings["schema_version"] == 1, report_findings
assert report_findings["scan_id"] == scan_id, report_findings
assert "generated_at" in report_findings, report_findings
assert report_findings["summary"]["total"] == 1, report_findings
assert len(report_findings["findings"]) == 1, report_findings
assert report_findings["findings"][0]["finding_id"] == "TB-777"
PY

echo "full workflow Track B fixture e2e OK: $SCAN_ID"
