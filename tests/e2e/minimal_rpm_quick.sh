#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMPDIR="${TMPDIR:-/tmp}/bbh-e2e-minimal-rpm-$$"
SCAN_ID="BBH-$(date -u +%Y%m%d)-e2e003"
SCAN_ROOT="$TMPDIR/workspace/$SCAN_ID"

mkdir -p "$SCAN_ROOT/context" "$SCAN_ROOT/raw" "$SCAN_ROOT/extracted/usr/bin"
trap 'rm -rf "$TMPDIR"' EXIT

cat > "$TMPDIR/bbh-e2e.rpm" <<'EOF'
RPM_FIXTURE_PLACEHOLDER_FOR_CONTEXT_BUILD_ONLY
EOF

cat > "$SCAN_ROOT/extracted/usr/bin/bbh-rpm-e2e" <<'EOF'
#!/bin/sh
printf '%s\n' "rpm e2e fixture"
EOF
chmod +x "$SCAN_ROOT/extracted/usr/bin/bbh-rpm-e2e"

cat > "$SCAN_ROOT/target_profile.json" <<EOF
{
  "scan_id": "$SCAN_ID",
  "package": {
    "path": "$TMPDIR/bbh-e2e.rpm",
    "type": "rpm",
    "name": "bbh-rpm-e2e",
    "version": "1.0",
    "architecture": "noarch",
    "size_bytes": 44
  },
  "extraction": {
    "status": "success",
    "root": "$SCAN_ROOT/extracted",
    "method": "simulated-rpm-fixture",
    "warnings": []
  },
  "binaries": [
    {
      "path": "$SCAN_ROOT/extracted/usr/bin/bbh-rpm-e2e",
      "elf": false,
      "architecture": "script",
      "priority": 20
    }
  ],
  "attack_surface": [
    {
      "type": "cli",
      "entry_point": "/usr/bin/bbh-rpm-e2e",
      "evidence": "RPM fixture command-line entry point"
    }
  ],
  "architectures": ["script"],
  "metadata": {
    "fixture": true,
    "package_manager_preference": "rpm"
  }
}
EOF

cat > "$SCAN_ROOT/evidence_slice.json" <<EOF
{
  "binary": "$SCAN_ROOT/extracted/usr/bin/bbh-rpm-e2e",
  "dimension": "hardcoded_config",
  "function": "main",
  "address": null,
  "architecture": "script",
  "attack_surface": {"type": "cli", "entry_point": "/usr/bin/bbh-rpm-e2e"},
  "imports": [],
  "xrefs_summary": [],
  "body_excerpt": "Shell script fixture used to verify RPM package-type workflow wiring.",
  "supporting_files": ["$SCAN_ROOT/raw/rpm_strings.txt"],
  "omitted": {"$SCAN_ROOT/raw/rpm_strings.txt": "full raw artifact kept on disk"},
  "truncated": false,
  "suspicious": false,
  "injection_findings": []
}
EOF

cat > "$SCAN_ROOT/raw/rpm_strings.txt" <<'EOF'
RPM_RAW_ARTIFACT_CONTENT_MUST_NOT_BE_READ_BY_PROMPT_BUILDER
EOF

python3 "$ROOT/tools/context/prompt_builder.py" \
  --root "$ROOT" \
  --dimension hardcoded_config \
  --mode quick \
  --evidence "$SCAN_ROOT/evidence_slice.json" \
  --scan-id "$SCAN_ID" \
  --target "$SCAN_ROOT/extracted/usr/bin/bbh-rpm-e2e" \
  --function main \
  --context-manifest "$SCAN_ROOT/context/track_b_hardcoded_config.json" \
  --output "$SCAN_ROOT/context/prompt.txt" \
  --metadata-output "$SCAN_ROOT/context/prompt_metadata.json"

test -s "$SCAN_ROOT/context/prompt.txt"
test -s "$SCAN_ROOT/context/prompt_metadata.json"
test -s "$SCAN_ROOT/context/track_b_hardcoded_config.json"
grep -q "UNTRUSTED_EVIDENCE" "$SCAN_ROOT/context/prompt.txt"
grep -q "hardcoded_config" "$SCAN_ROOT/context/prompt_metadata.json"
if grep -q "RPM_RAW_ARTIFACT_CONTENT_MUST_NOT_BE_READ_BY_PROMPT_BUILDER" "$SCAN_ROOT/context/prompt.txt"; then
  echo "FAIL: prompt builder leaked full RPM raw artifact content"
  exit 1
fi

python3 - "$SCAN_ROOT/target_profile.json" "$SCAN_ROOT/context/track_b_hardcoded_config.json" <<'PY'
import json, sys
profile = json.load(open(sys.argv[1], encoding="utf-8"))
manifest = json.load(open(sys.argv[2], encoding="utf-8"))
assert profile["package"]["type"] == "rpm"
assert profile["metadata"]["package_manager_preference"] == "rpm"
assert manifest["phase"] == "track_b"
assert manifest["dimension"] == "hardcoded_config"
assert "README.md" in manifest["excluded_files"]
assert manifest["token_budget"]["estimated"] <= manifest["token_budget"]["max"]
PY

echo "minimal rpm quick e2e OK: $SCAN_ID"
