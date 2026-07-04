#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMPDIR="${TMPDIR:-/tmp}/bbh-tracka-workflow-$$"
trap 'rm -rf "$TMPDIR"' EXIT
mkdir -p "$TMPDIR/workspace" "$TMPDIR/pkg/DEBIAN" "$TMPDIR/pkg/usr/bin" "$TMPDIR/pkg/usr/lib"

cat > "$TMPDIR/registry-workflow.json" <<'EOF'
{
  "registry_version": 1,
  "package_manager_priority": {
    "deb": ["apt", "dnf"],
    "rpm": ["dnf", "apt"]
  },
  "tools": [
    {
      "name": "dependency-parser",
      "binary_name": "python3",
      "execution_model": "host_binary",
      "install_priority": ["manual"],
      "install_cmds": {"manual": "python3 is required for dependency-parser"},
      "detect_cmd": "python3 --version",
      "priority": "high",
      "fallbacks": [],
      "platform": ["linux", "darwin"]
    },
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
Package: bbh-tracka
Version: 1.0
Section: utils
Priority: optional
Architecture: all
Maintainer: BlackBox Hunter <noreply@example.invalid>
Description: Track A workflow fixture
EOF

cat > "$TMPDIR/pkg/usr/bin/bbh-tracka" <<'EOF'
#!/bin/sh
printf '%s
' track-a-fixture
EOF
chmod +x "$TMPDIR/pkg/usr/bin/bbh-tracka"

cat > "$TMPDIR/pkg/usr/lib/libssl.so" <<'EOF'
not a real shared object; fixture only
EOF

if command -v dpkg-deb >/dev/null 2>&1; then
  dpkg-deb --build "$TMPDIR/pkg" "$TMPDIR/bbh-tracka.deb" >/dev/null
else
  echo "dpkg-deb unavailable; skipping Track A workflow fixture"
  exit 0
fi

SCAN_ID="BBH-20260704-taf001"
python3 "$ROOT/tools/bbh_scan.py" \
  --package "$TMPDIR/bbh-tracka.deb" \
  --workspace "$TMPDIR/workspace" \
  --registry "$TMPDIR/registry-workflow.json" \
  --scan-id "$SCAN_ID" \
  --mode quick \
  --run-track-a-tools >/dev/null

SCAN_ROOT="$TMPDIR/workspace/$SCAN_ID"
test -s "$SCAN_ROOT/track_a_findings.json"
test -s "$SCAN_ROOT/raw/track_a/dependencies.json"
test -s "$SCAN_ROOT/raw/track_a/normalized/dependency-parser-1.json"
test -s "$SCAN_ROOT/merged_findings.json"
test -s "$SCAN_ROOT/report/blackbox-security-report.md"
grep -q "Track A Summary" "$SCAN_ROOT/report/blackbox-security-report.md"
grep -q "signals_count: 1" "$SCAN_ROOT/report/blackbox-security-report.md"

python3 - "$SCAN_ROOT/track_a_findings.json" "$SCAN_ROOT/raw/track_a/dependencies.json" "$SCAN_ROOT/merged_findings.json" "$SCAN_ROOT/scan_state.json" <<'PY'
import json, sys
track_a = json.load(open(sys.argv[1], encoding="utf-8"))
raw = json.load(open(sys.argv[2], encoding="utf-8"))
merged = json.load(open(sys.argv[3], encoding="utf-8"))
state = json.load(open(sys.argv[4], encoding="utf-8"))
assert state["current_phase"] == "completed", state
assert track_a["status"] == "success", track_a
assert track_a["metadata"]["tools_executed"] == ["dependency-parser"], track_a
assert track_a["metadata"]["signals_count"] == 1, track_a
assert track_a["metadata"]["signals"][0]["signal_type"] == "crypto_dependency"
assert any("libssl.so" in item for item in raw["imports"]), raw
assert merged["dedup_stats"]["signals_considered"] == 1, merged
assert merged["coverage_summary"]["track_a_status"] == "success", merged
PY

echo "full workflow Track A fixture e2e OK: $SCAN_ID"
