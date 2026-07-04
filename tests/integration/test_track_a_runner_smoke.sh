#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMPDIR="${TMPDIR:-/tmp}/bbh-track-a-real-$$"
trap 'rm -rf "$TMPDIR"' EXIT
mkdir -p "$TMPDIR/scan/extracted/usr/bin" "$TMPDIR/scan/raw/track_a" "$TMPDIR/fakebin"

if ! command -v yara >/dev/null 2>&1; then
  echo "SKIP: yara not installed; real Track A smoke disabled"
  exit 0
fi

cat > "$TMPDIR/scan/extracted/usr/bin/unsafe.sh" <<'EOF'
#!/bin/sh
# strings intentionally used to trigger YARA rule context
printf '%s\n' system strcpy sprintf
EOF
chmod +x "$TMPDIR/scan/extracted/usr/bin/unsafe.sh"

cat > "$TMPDIR/scan/env_check.json" <<EOF
{
  "tools": [
    {"name": "yara", "status": "available", "priority": "high", "binary_name": "yara", "execution_model": "host_binary", "applicable": true}
  ],
  "block_decision": {"blocked": false, "warnings": [], "blocked_tools": [], "install_hints": [], "phase_blocks": []}
}
EOF

cat > "$TMPDIR/scan/target_profile.json" <<EOF
{
  "binaries": [
    {"path": "$TMPDIR/scan/extracted/usr/bin/unsafe.sh", "elf": false, "architecture": "script", "priority": 10}
  ],
  "extraction": {"root": "$TMPDIR/scan/extracted"}
}
EOF

python3 "$ROOT/tools/track_a_runner.py" --scan-root "$TMPDIR/scan" --tools yara >/dev/null

test -s "$TMPDIR/scan/track_a_findings.json"
python3 - "$TMPDIR/scan/track_a_findings.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)
assert "yara" in data["metadata"]["tools_executed"], data
assert data["metadata"]["signals_count"] > 0, data
PY

echo "Track A real tool smoke OK"
