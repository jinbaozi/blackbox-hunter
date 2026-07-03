#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMPDIR="${TMPDIR:-/tmp}/bbh-trackb-prompt-$$"
mkdir -p "$TMPDIR/context" "$TMPDIR/raw"
trap 'rm -rf "$TMPDIR"' EXIT

cat > "$TMPDIR/evidence_slice.json" <<EOF
{
  "binary": "/usr/bin/prompt-fixture",
  "dimension": "dangerous_functions",
  "function": "parse_request",
  "address": "0x4012ab",
  "architecture": "x86_64",
  "attack_surface": {"type": "network", "entry_point": "tcp/8080"},
  "imports": ["strcpy", "recv"],
  "xrefs_summary": ["handle_client -> parse_request"],
  "body_excerpt": "recv(fd, buf, sizeof(buf), 0); strcpy(local_80, buf);",
  "supporting_files": ["$TMPDIR/raw/ghidra.json"],
  "omitted": {"$TMPDIR/raw/ghidra.json": "full raw artifact kept on disk"},
  "truncated": false,
  "suspicious": false,
  "injection_findings": []
}
EOF

cat > "$TMPDIR/raw/ghidra.json" <<'EOF'
THIS_FULL_RAW_GHIDRA_CONTENT_MUST_NOT_APPEAR_IN_PROMPT
EOF

python3 "$ROOT/tools/context/prompt_builder.py" \
  --root "$ROOT" \
  --dimension dangerous_functions \
  --mode quick \
  --evidence "$TMPDIR/evidence_slice.json" \
  --scan-id "BBH-20260703-e2e002" \
  --target "/usr/bin/prompt-fixture" \
  --function parse_request \
  --context-manifest "$TMPDIR/context/manifest.json" \
  --output "$TMPDIR/context/prompt.txt" \
  --metadata-output "$TMPDIR/context/metadata.json"

grep -q "Track B Base Contract" "$TMPDIR/context/prompt.txt"
grep -q "Dimension: dangerous_functions" "$TMPDIR/context/prompt.txt"
grep -q "UNTRUSTED_EVIDENCE" "$TMPDIR/context/prompt.txt"
if grep -q "Dimension: memory_management" "$TMPDIR/context/prompt.txt"; then
  echo "FAIL: unrelated dimension card leaked into prompt"
  exit 1
fi
if grep -q "THIS_FULL_RAW_GHIDRA_CONTENT_MUST_NOT_APPEAR_IN_PROMPT" "$TMPDIR/context/prompt.txt"; then
  echo "FAIL: full raw artifact leaked into prompt"
  exit 1
fi

python3 - "$TMPDIR/context/metadata.json" <<'PY'
import json, sys
metadata = json.load(open(sys.argv[1], encoding="utf-8"))
assert metadata["context_profile"].endswith("dangerous_functions")
assert "prompts/track_b/dimensions/dangerous_functions.md" in metadata["loaded_files"]
assert all("memory_management" not in item for item in metadata["loaded_files"])
assert metadata["estimated_tokens"] <= metadata["max_prompt_tokens"]
PY

echo "Track B prompt build e2e OK"
