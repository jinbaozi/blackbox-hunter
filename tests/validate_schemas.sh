#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCHEMAS_DIR="$SCRIPT_DIR/../templates"
FIXTURES_DIR="$SCRIPT_DIR/fixtures"
ERRORS=0

validate_json() {
  local file="$1"
  python3 - "$file" <<'PYIN'
import json, sys
with open(sys.argv[1], encoding="utf-8") as fh:
    json.load(fh)
PYIN
}

validate_schema_shape() {
  local schema_file="$1"
  python3 - "$schema_file" <<'PYIN'
import json, sys
with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)
assert data.get("$schema") == "https://json-schema.org/draft/2020-12/schema", "wrong or missing $schema"
assert data.get("$id", "").startswith("https://blackbox-hunter/schemas/"), "invalid $id prefix"
assert data.get("type") in ("object", "array"), "schema must declare type"
PYIN
}

validate_fixture_with_schema() {
  local fixture="$1"
  local schema="$2"
  if python3 - <<'PYIN' >/dev/null 2>&1
import importlib.util, sys
sys.exit(0 if importlib.util.find_spec("jsonschema") else 1)
PYIN
  then
    python3 - "$fixture" "$schema" <<'PYIN'
import json, sys
from pathlib import Path
from jsonschema import Draft202012Validator, RefResolver

fixture_path = Path(sys.argv[1]).resolve()
schema_path = Path(sys.argv[2]).resolve()
with fixture_path.open(encoding="utf-8") as fh:
    fixture = json.load(fh)
with schema_path.open(encoding="utf-8") as fh:
    schema = json.load(fh)
resolver = RefResolver(base_uri=schema_path.as_uri(), referrer=schema)
Draft202012Validator(schema, resolver=resolver).validate(fixture)
PYIN
  else
    validate_json "$fixture"
  fi
}

schema_for_fixture() {
  case "$(basename "$1")" in
    sample_profile.json) echo "$SCHEMAS_DIR/target_profile.json" ;;
    sample_finding.json) echo "$SCHEMAS_DIR/finding.json" ;;
    sample_scan_strategy.json) echo "$SCHEMAS_DIR/scan_strategy.json" ;;
    sample_scan_state.json) echo "$SCHEMAS_DIR/scan_state.json" ;;
    sample_sandbox_status.json) echo "$SCHEMAS_DIR/sandbox_status.json" ;;
    sample_track_findings.json) echo "$SCHEMAS_DIR/track_findings.json" ;;
    sample_merged_findings.json) echo "$SCHEMAS_DIR/merged_findings.json" ;;
    sample_coverage_report.json) echo "$SCHEMAS_DIR/coverage_report.json" ;;
    sample_verified_findings.json) echo "$SCHEMAS_DIR/verified_findings.json" ;;
    *) echo "" ;;
  esac
}

for schema in "$SCHEMAS_DIR"/*.json; do
  name="$(basename "$schema")"
  printf '  schema %-32s ' "$name"
  if validate_schema_shape "$schema"; then echo OK; else echo FAIL; ERRORS=$((ERRORS + 1)); fi
done

for fixture in "$FIXTURES_DIR"/*.json; do
  name="$(basename "$fixture")"
  schema="$(schema_for_fixture "$fixture")"
  printf '  fixture %-31s ' "$name"
  if [ -n "$schema" ] && [ -f "$schema" ]; then
    if validate_fixture_with_schema "$fixture" "$schema"; then echo OK; else echo FAIL; ERRORS=$((ERRORS + 1)); fi
  else
    if validate_json "$fixture"; then echo "OK (json only)"; else echo FAIL; ERRORS=$((ERRORS + 1)); fi
  fi
done

if [ "$ERRORS" -ne 0 ]; then
  echo "$ERRORS validation(s) failed."
  exit 1
fi

echo "All schema validations passed."
