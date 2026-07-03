#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMPDIR="${TMPDIR:-/tmp}/bbh-preflight-contracts-$$"
trap 'rm -rf "$TMPDIR"' EXIT
mkdir -p "$TMPDIR/fakebin" "$TMPDIR/home" "$TMPDIR/scan"

cat > "$TMPDIR/fakebin/badtool" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$TMPDIR/fakebin/badtool"

cat > "$TMPDIR/fakebin/dnf" <<'EOF'
#!/bin/sh
echo dnf fixture
EOF
chmod +x "$TMPDIR/fakebin/dnf"

cat > "$TMPDIR/registry.json" <<'EOF'
{
  "registry_version": 1,
  "package_manager_priority": {
    "rpm": ["dnf", "apt"],
    "deb": ["apt", "dnf"]
  },
  "tools": [
    {
      "name": "badtool",
      "binary_name": "badtool",
      "execution_model": "host_binary",
      "install_priority": ["dnf", "manual"],
      "system_packages": {"dnf": ["badtool-pkg"]},
      "install_cmds": {"manual": "manual badtool"},
      "detect_cmd": "badtool --definitely-invalid",
      "priority": "required",
      "fallbacks": [],
      "platform": ["linux", "darwin"]
    },
    {
      "name": "deb-only",
      "binary_name": "deb-only",
      "execution_model": "host_binary",
      "install_priority": ["manual"],
      "install_cmds": {"manual": "manual deb-only"},
      "priority": "high",
      "fallbacks": [],
      "platform": ["linux", "darwin"],
      "applies_to": "deb"
    }
  ]
}
EOF

touch "$TMPDIR/sample.rpm"
set +e
HOME="$TMPDIR/home" PATH="$TMPDIR/fakebin:/usr/bin:/bin" \
  python3 "$ROOT/tools/preflight.py" \
    --check-only \
    --offline \
    --auto-fix \
    --package-path "$TMPDIR/sample.rpm" \
    --registry "$TMPDIR/registry.json" \
    --scan-root "$TMPDIR/scan"
rc=$?
set -e
[ "$rc" -eq 1 ] || { echo "FAIL: expected hard block for failing detect_cmd, got $rc"; exit 1; }

python3 - "$TMPDIR/scan/env_check.json" <<'PY'
import json, sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text())
tools = {tool["name"]: tool for tool in data["tools"]}
assert data["package_type"] == "rpm"
assert data["package_manager"] == "dnf"
assert tools["badtool"]["status"] == "missing", tools["badtool"]
assert data["block_decision"]["blocked"] is True
hint = data["block_decision"]["install_hints"][0]
assert hint.startswith("badtool: "), hint
assert hint.endswith("dnf install -y badtool-pkg"), hint
assert tools["deb-only"]["status"] == "skipped_not_applicable"
PY

echo "preflight contract validation passed"
