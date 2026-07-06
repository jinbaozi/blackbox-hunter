#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMPDIR="${TMPDIR:-/tmp}/bbh-preflight-$$"
trap 'rm -rf "$TMPDIR"' EXIT

mkdir -p "$TMPDIR/fakebin" "$TMPDIR/home/.local/bin" "$TMPDIR/scan" "$TMPDIR/rpm-scan"

cat > "$TMPDIR/fakebin/lowtool" <<'EOF'
#!/bin/sh
echo lowtool 1.0
EOF
chmod +x "$TMPDIR/fakebin/lowtool"

cat > "$TMPDIR/fakebin/dnf" <<'EOF'
#!/bin/sh
echo dnf 5.0
EOF
chmod +x "$TMPDIR/fakebin/dnf"

cat > "$TMPDIR/home/.local/bin/fallback-ok" <<'EOF'
#!/bin/sh
echo fallback-ok 3.0
EOF
chmod +x "$TMPDIR/home/.local/bin/fallback-ok"

cat > "$TMPDIR/home/.local/bin/rpm-fallback" <<'EOF'
#!/bin/sh
echo rpm-fallback 3.0
EOF
chmod +x "$TMPDIR/home/.local/bin/rpm-fallback"

cat > "$TMPDIR/registry-ok.json" <<'EOF'
{
  "registry_version": 1,
  "tools": [
    {
      "name": "primary-required",
      "binary_name": "primary-required",
      "install_priority": ["manual"],
      "install_cmds": { "manual": "manual primary-required" },
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
      "install_cmds": { "manual": "manual lowtool" },
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
import shutil
import sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text())
tools = {tool["name"]: tool for tool in data["tools"]}
assert data["output_path"].endswith("/scan/env_check.json")
assert data["path_patched"] is True
assert data["package_type"] == "deb"
assert data["package_manager"] in {"apt", "dnf", "microdnf", "yum", "zypper", "rpm-ostree", "brew", "unknown"}
if shutil.which("apt-get"):
    assert data["package_manager"] == "apt", data["package_manager"]
assert tools["primary-required"]["status"] == "fallback_active"
assert tools["primary-required"]["fallback_used"] == "fallback-ok"
assert tools["lowtool"]["status"] == "version_low"
assert tools["rpm-only"]["status"] == "skipped_not_applicable"
assert data["block_decision"]["blocked"] is False

docker_status = tools["docker"]["status"]
phase_blocks = data["block_decision"].get("phase_blocks") or []
if docker_status == "available":
    assert not any(block.get("phase") == "phase_3" and block.get("tool") == "docker" for block in phase_blocks)
else:
    assert any(block.get("phase") == "phase_3" and block.get("tool") == "docker" for block in phase_blocks)

assert data["confidence_ceiling"] < 0.95
PY

cat > "$TMPDIR/registry-rpm.json" <<'EOF'
{
  "registry_version": 1,
  "tools": [
    {
      "name": "rpm-primary",
      "binary_name": "rpm-primary",
      "install_priority": ["apt", "pip", "dnf", "manual"],
      "install_cmds": {
        "apt": "apt rpm-primary",
        "dnf": "dnf rpm-primary",
        "manual": "manual rpm-primary"
      },
      "detect_cmd": "rpm-primary --version",
      "priority": "required",
      "fallbacks": ["rpm-fallback"],
      "platform": ["linux"]
    },
    {
      "name": "deb-only",
      "binary_name": "deb-only",
      "install_priority": ["apt"],
      "install_cmds": { "apt": "apt deb-only" },
      "priority": "high",
      "fallbacks": [],
      "platform": ["linux"],
      "applies_to": "deb"
    }
  ]
}
EOF

HOME="$TMPDIR/home" PATH="$TMPDIR/fakebin:/usr/bin:/bin" \
  bash "$ROOT/tools/install.sh" \
    --check-only \
    --offline \
    --auto-fix \
    --package-type rpm \
    --registry "$TMPDIR/registry-rpm.json" \
    --scan-root "$TMPDIR/rpm-scan"

python3 - "$TMPDIR/rpm-scan/env_check.json" <<'PY'
import json
import sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text())
tools = {tool["name"]: tool for tool in data["tools"]}
assert data["package_type"] == "rpm"
assert data["package_manager"] == "dnf", data["package_manager"]
assert tools["rpm-primary"]["status"] == "fallback_active"
assert tools["rpm-primary"]["fallback_used"] == "rpm-fallback"
assert tools["deb-only"]["status"] == "skipped_not_applicable"
assert data["block_decision"]["blocked"] is False
assert data["confidence_ceiling"] == 0.8
PY

cat > "$TMPDIR/registry-block.json" <<'EOF'
{
  "registry_version": 1,
  "tools": [
    {
      "name": "must-have",
      "binary_name": "must-have",
      "install_priority": ["manual"],
      "install_cmds": { "manual": "manual must-have" },
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

cat > "$TMPDIR/registry-block-rpm.json" <<'EOF'
{
  "registry_version": 1,
  "tools": [
    {
      "name": "must-have-rpm",
      "binary_name": "must-have-rpm",
      "install_priority": ["apt", "pip", "dnf", "manual"],
      "install_cmds": {
        "apt": "apt must-have-rpm",
        "dnf": "dnf must-have-rpm",
        "manual": "manual must-have-rpm"
      },
      "detect_cmd": "must-have-rpm --version",
      "priority": "required",
      "fallbacks": [],
      "platform": ["linux"]
    }
  ]
}
EOF

set +e
HOME="$TMPDIR/home" PATH="$TMPDIR/fakebin:/usr/bin:/bin" \
  bash "$ROOT/tools/install.sh" \
    --check-only \
    --offline \
    --package-type rpm \
    --registry "$TMPDIR/registry-block-rpm.json" \
    --output "$TMPDIR/blocked-rpm-env-check.json"
rc=$?
set -e

[ "$rc" -eq 1 ] || { echo "FAIL: expected rpm hard-block exit 1, got $rc"; exit 1; }

python3 - "$TMPDIR/blocked-rpm-env-check.json" <<'PY'
import json
import sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text())
assert data["package_manager"] == "dnf"
assert data["block_decision"]["blocked"] is True
assert data["block_decision"]["blocked_tools"] == ["must-have-rpm"]
hints = data["block_decision"]["install_hints"]
assert hints[0] == "must-have-rpm: dnf must-have-rpm", hints
PY

echo "preflight validation passed"
