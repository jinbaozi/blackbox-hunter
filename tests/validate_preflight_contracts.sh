#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMPDIR="${TMPDIR:-/tmp}/bbh-preflight-contracts-$$"
trap 'rm -rf "$TMPDIR"' EXIT
mkdir -p "$TMPDIR/fakebin" "$TMPDIR/home" "$TMPDIR/scan"

cat > "$TMPDIR/fakebin/badtool" <<'EOF'
#!/bin/sh
case "$1" in
  --version) echo badtool 1.0; exit 0 ;;
  *) echo bad detect >&2; exit 7 ;;
esac
EOF
chmod +x "$TMPDIR/fakebin/badtool"

cat > "$TMPDIR/fakebin/nonzero-ok" <<'EOF'
#!/bin/sh
echo nonzero-ok 2.1
exit 9
EOF
chmod +x "$TMPDIR/fakebin/nonzero-ok"

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
      "name": "nonzero-ok",
      "binary_name": "nonzero-ok",
      "execution_model": "host_binary",
      "install_priority": ["manual"],
      "install_cmds": {"manual": "manual nonzero-ok"},
      "detect_cmd": "nonzero-ok --probe",
      "detect_nonzero_ok": true,
      "priority": "high",
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
assert tools["nonzero-ok"]["status"] == "available", tools["nonzero-ok"]
assert tools["nonzero-ok"]["detected_version"] == "2.1", tools["nonzero-ok"]
assert data["block_decision"]["blocked"] is True
hint = data["block_decision"]["install_hints"][0]
assert hint.startswith("badtool: "), hint
assert hint.endswith("dnf install -y badtool-pkg"), hint
assert tools["deb-only"]["status"] == "skipped_not_applicable"
PY

echo "preflight contract validation passed"
