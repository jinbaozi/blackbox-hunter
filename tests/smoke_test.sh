#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMPDIR="${TMPDIR:-/tmp}/bbh-smoke-$$"
WORKSPACE="$TMPDIR/workspace"
mkdir -p "$WORKSPACE" "$TMPDIR/pkg/DEBIAN" "$TMPDIR/pkg/usr/bin"
trap 'rm -rf "$TMPDIR"' EXIT

cat > "$TMPDIR/pkg/DEBIAN/control" <<'EOF'
Package: bbh-smoke
Version: 1.0
Section: utils
Priority: optional
Architecture: all
Maintainer: BlackBox Hunter <noreply@example.invalid>
Description: smoke fixture package
EOF

cat > "$TMPDIR/pkg/usr/bin/bbh-smoke" <<'EOF'
#!/bin/sh
echo smoke
EOF
chmod +x "$TMPDIR/pkg/usr/bin/bbh-smoke"

if command -v dpkg-deb >/dev/null 2>&1; then
  dpkg-deb --build "$TMPDIR/pkg" "$TMPDIR/bbh-smoke.deb" >/dev/null
else
  echo "dpkg-deb unavailable; smoke fixture build skipped"
  exit 0
fi

SCAN_ID="BBH-$(date -u +%Y%m%d)-a1b2c3"
SCAN_ROOT="$WORKSPACE/$SCAN_ID"
mkdir -p "$SCAN_ROOT/extracted" "$SCAN_ROOT/raw"
dpkg-deb -x "$TMPDIR/bbh-smoke.deb" "$SCAN_ROOT/extracted"

cat > "$SCAN_ROOT/scan_strategy.json" <<EOF
{"scan_id":"$SCAN_ID","mode":"quick","track_a_tools":[],"track_b_focus":["hardcoded_config"],"disassembly_engine":"strings_only"}
EOF

test -d "$SCAN_ROOT/extracted/usr/bin"
grep -q "$SCAN_ID" "$SCAN_ROOT/scan_strategy.json"

# Preflight phase checks
test -f "$ROOT/phases/phase-preflight.md" || { echo "FAIL: phases/phase-preflight.md not found"; exit 1; }
grep -q "env_check.json" "$ROOT/SKILL.md" || { echo "FAIL: SKILL.md does not reference env_check.json"; exit 1; }

echo "smoke OK: $SCAN_ID"
