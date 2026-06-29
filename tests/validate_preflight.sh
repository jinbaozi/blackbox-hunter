#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMPDIR="${TMPDIR:-/tmp}/bbh-preflight-$$"
trap 'rm -rf "$TMPDIR"' EXIT

mkdir -p "$TMPDIR/fakebin" "$TMPDIR/home/.local/bin" "$TMPDIR/scan"

cat > "$TMPDIR/fakebin/lowtool" <<'EOF'
#!/bin/sh
echo lowtool 1.0
EOF
chmod +x "$TMPDIR/fakebin/lowtool"

cat > "$TMPDIR/home/.local/bin/fallback-ok" <<'EOF'
#!/bin/sh
echo fallback-ok 3.0
EOF
chmod +x "$TMPDIR/home/.local/bin/fallback-ok"

cat > "$TMPDIR/registry-ok.json" <<'EOF'
{
  "registry_version": 1,
  "tools": [
    {
      "name": "primary-required",
      "binary_name": "primary-required",
      "install_priority": ["manual"],
      "install_cmds": { "manual": "install primary-required manually" },
      "detect_cmd": "primary-required --version",
      "priority": "required",
      "fallbacks": ["fallback-ok"],
      "platform": ["linux", "darwin"]
    },
    {
      "name": "lowtool",
      "binary_name": "lowtool",
      "install_priority": ["manual"],
      "version_min": "2.0",
      "install_cmds": { "manual": "install lowtool manually" },
      "detect_cmd": "lowtool --version",
      "priority": "high",
      "fallbacks": [],
      "platform": ["linux", "darwin"]
    },
    {
      "name": "rpm-only",
      "binary_name": "rpm-only",
      "install_priority": ["manual"],
      "detect_cmd": "rpm-only --version",
      "priority": "high",
      "fallbacks": [],
      "platform": ["linux", "darwin"],
      "applies_to": "rpm"
    },
    {
      "name": "docker",
      "binary_name": "docker",
      "install_priority": ["manual"],
      "detect_cmd": "docker --version",
      "priority": "required_verify",
      "fallbacks": [],
      "platform": ["linux", "darwin"]
    }
  ]
}
EOF

HOME="$TMPDIR/home" PATH="$TMPDIR/fakebin:/usr/bin:/bin" \
  bash "$ROOT/tools/install.sh" \
    --check-only \
    --offline \
    --auto-fix \
    --package-type deb \
    --registry "$TMPDIR/registry-ok.json" \
    --scan-root "$TMPDIR/scan"

python3 - "$TMPDIR/scan/env_check.json" <<'PY'
import json
import sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text())
tools = {tool["name"]: tool for tool in data["tools"]}
assert data["output_path"].endswith("/scan/env_check.json")
assert data["path_patched"] is True
assert tools["primary-required"]["status"] == "fallback_active"
assert tools["primary-required"]["fallback_used"] == "fallback-ok"
assert tools["lowtool"]["status"] == "version_low"
assert tools["rpm-only"]["status"] == "skipped_not_applicable"
assert data["block_decision"]["blocked"] is False
assert data["block_decision"]["phase_blocks"][0]["phase"] == "phase_3"
assert data["confidence_ceiling"] < 0.95
PY

cat > "$TMPDIR/registry-block.json" <<'EOF'
{
  "registry_version": 1,
  "tools": [
    {
      "name": "must-have",
      "binary_name": "must-have",
      "install_priority": ["manual"],
      "install_cmds": { "manual": "install must-have manually" },
      "detect_cmd": "must-have --version",
      "priority": "required",
      "fallbacks": [],
      "platform": ["linux", "darwin"]
    }
  ]
}
EOF

set +e
HOME="$TMPDIR/home" PATH="$TMPDIR/fakebin:/usr/bin:/bin" \
  bash "$ROOT/tools/install.sh" \
    --check-only \
    --offline \
    --package-type deb \
    --registry "$TMPDIR/registry-block.json" \
    --output "$TMPDIR/blocked-env-check.json"
rc=$?
set -e

[ "$rc" -eq 1 ] || { echo "FAIL: expected hard-block exit 1, got $rc"; exit 1; }

python3 - "$TMPDIR/blocked-env-check.json" <<'PY'
import json
import sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text())
assert data["block_decision"]["blocked"] is True
assert data["block_decision"]["blocked_tools"] == ["must-have"]
assert data["block_decision"]["install_hints"]
PY

echo "preflight validation passed"
