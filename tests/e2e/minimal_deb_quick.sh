#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMPDIR="${TMPDIR:-/tmp}/bbh-e2e-minimal-$$"
SCAN_ID="BBH-$(date -u +%Y%m%d)-e2e001"
SCAN_ROOT="$TMPDIR/workspace/$SCAN_ID"

mkdir -p "$TMPDIR/pkg/DEBIAN" "$TMPDIR/pkg/usr/bin" "$SCAN_ROOT/context" "$SCAN_ROOT/raw"
trap 'rm -rf "$TMPDIR"' EXIT

cat > "$TMPDIR/pkg/DEBIAN/control" <<'EOF'
Package: bbh-e2e
Version: 1.0
Section: utils
Priority: optional
Architecture: all
Maintainer: BlackBox Hunter <noreply@example.invalid>
Description: minimal e2e fixture package
EOF

cat > "$TMPDIR/pkg/usr/bin/bbh-e2e" <<'EOF'
#!/bin/sh
API_KEY="fixture-not-secret"
echo "$API_KEY" >/dev/null
EOF
chmod +x "$TMPDIR/pkg/usr/bin/bbh-e2e"

if command -v dpkg-deb >/dev/null 2>&1; then
  dpkg-deb --build "$TMPDIR/pkg" "$TMPDIR/bbh-e2e.deb" >/dev/null
  mkdir -p "$SCAN_ROOT/extracted"
  dpkg-deb -x "$TMPDIR/bbh-e2e.deb" "$SCAN_ROOT/extracted"
else
  echo "dpkg-deb unavailable; package build skipped, continuing with prompt-build e2e"
  mkdir -p "$SCAN_ROOT/extracted/usr/bin"
  cp "$TMPDIR/pkg/usr/bin/bbh-e2e" "$SCAN_ROOT/extracted/usr/bin/bbh-e2e"
fi

cat > "$SCAN_ROOT/evidence_slice.json" <<EOF
{
  "binary": "$SCAN_ROOT/extracted/usr/bin/bbh-e2e",
  "dimension": "hardcoded_config",
  "function": "main",
  "address": null,
  "architecture": "script",
  "attack_surface": {"type": "cli", "entry_point": "/usr/bin/bbh-e2e"},
  "imports": [],
  "xrefs_summary": [],
  "body_excerpt": "Shell script contains a bounded fixture API_KEY assignment for prompt-build regression only.",
  "supporting_files": ["$SCAN_ROOT/raw/strings.txt"],
  "omitted": {"$SCAN_ROOT/raw/strings.txt": "full raw artifact kept on disk"},
  "truncated": false,
  "suspicious": false,
  "injection_findings": []
}
EOF

cat > "$SCAN_ROOT/raw/strings.txt" <<'EOF'
RAW_ARTIFACT_CONTENT_MUST_NOT_BE_READ_BY_PROMPT_BUILDER
EOF

python3 "$ROOT/tools/context/prompt_builder.py" \
  --root "$ROOT" \
  --dimension hardcoded_config \
  --mode quick \
  --evidence "$SCAN_ROOT/evidence_slice.json" \
  --scan-id "$SCAN_ID" \
  --target "$SCAN_ROOT/extracted/usr/bin/bbh-e2e" \
  --function main \
  --context-manifest "$SCAN_ROOT/context/track_b_hardcoded_config.json" \
  --output "$SCAN_ROOT/context/prompt.txt" \
  --metadata-output "$SCAN_ROOT/context/prompt_metadata.json"

test -s "$SCAN_ROOT/context/prompt.txt"
test -s "$SCAN_ROOT/context/prompt_metadata.json"
test -s "$SCAN_ROOT/context/track_b_hardcoded_config.json"
grep -q "UNTRUSTED_EVIDENCE" "$SCAN_ROOT/context/prompt.txt"
grep -q "hardcoded_config" "$SCAN_ROOT/context/prompt_metadata.json"
if grep -q "RAW_ARTIFACT_CONTENT_MUST_NOT_BE_READ_BY_PROMPT_BUILDER" "$SCAN_ROOT/context/prompt.txt"; then
  echo "FAIL: prompt builder leaked full raw artifact content"
  exit 1
fi

python3 - "$SCAN_ROOT/context/track_b_hardcoded_config.json" <<'PY'
import json, sys
manifest = json.load(open(sys.argv[1], encoding="utf-8"))
assert manifest["phase"] == "track_b"
assert manifest["dimension"] == "hardcoded_config"
assert "README.md" in manifest["excluded_files"]
assert manifest["token_budget"]["estimated"] <= manifest["token_budget"]["max"]
PY

echo "minimal deb quick e2e OK: $SCAN_ID"
