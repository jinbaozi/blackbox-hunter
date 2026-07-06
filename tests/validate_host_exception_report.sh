#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMPDIR="${TMPDIR:-/tmp}/bbh-host-exception-$$"
ROOTFS="$ROOT/assets/rootfs/v11-2503-rootfs.tar"
RECORD="$ROOT/tools/.imported_rootfs.json"
RECORD_BACKUP="$TMPDIR/imported_rootfs.json.bak"
STABLE_REF="bbh-base:local-imported"

mkdir -p "$TMPDIR/workspace"

ENGINE=""
for candidate in docker podman; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" info >/dev/null 2>&1; then
        ENGINE="$candidate"
        break
    fi
done
if [ -z "$ENGINE" ]; then
    echo "host exception report validation skipped: no reachable docker or podman engine"
    rm -rf "$TMPDIR"
    exit 0
fi

sha_actual="$(sha256sum "$ROOTFS" | awk '{print $1}')"
CONTENT_REF="bbh-base:local-${sha_actual:0:12}"
HAD_RECORD=0
HAD_STABLE_REF=0
HAD_CONTENT_REF=0
STABLE_IMAGE_ID=""

if [ -f "$RECORD" ]; then
    cp "$RECORD" "$RECORD_BACKUP"
    HAD_RECORD=1
fi
if "$ENGINE" image inspect "$STABLE_REF" >/dev/null 2>&1; then
    HAD_STABLE_REF=1
    STABLE_IMAGE_ID="$("$ENGINE" image inspect --format '{{.Id}}' "$STABLE_REF")"
fi
if "$ENGINE" image inspect "$CONTENT_REF" >/dev/null 2>&1; then
    HAD_CONTENT_REF=1
fi

restore() {
    if [ "$HAD_RECORD" -eq 1 ]; then
        cp "$RECORD_BACKUP" "$RECORD"
    else
        rm -f "$RECORD"
    fi

    if [ "$HAD_STABLE_REF" -eq 1 ] && [ -n "$STABLE_IMAGE_ID" ]; then
        "$ENGINE" tag "$STABLE_IMAGE_ID" "$STABLE_REF" >/dev/null 2>&1 || true
    else
        "$ENGINE" rmi -f "$STABLE_REF" >/dev/null 2>&1 || true
    fi
    if [ "$HAD_CONTENT_REF" -eq 0 ]; then
        "$ENGINE" rmi -f "$CONTENT_REF" >/dev/null 2>&1 || true
    fi

    rm -rf "$TMPDIR"
}
trap restore EXIT

python3 "$ROOT/tools/import_rootfs.py" \
    --tarball "$ROOTFS" \
    --tag-prefix bbh-base \
    --record-path "$RECORD" >/dev/null

cat >"$TMPDIR/registry.json" <<'JSON'
{
  "registry_version": 1,
  "package_manager_priority": {
    "rpm": ["dnf", "microdnf", "yum", "zypper", "rpm-ostree", "apt", "brew"],
    "deb": ["apt", "dnf", "microdnf", "yum", "zypper", "rpm-ostree", "brew"]
  },
  "tools": [
    {
      "name": "docker",
      "binary_name": "docker",
      "execution_model": "host_binary",
      "install_priority": ["manual"],
      "install_cmds": {"manual": "manual docker"},
      "priority": "required_verify",
      "fallbacks": [],
      "platform": ["linux", "darwin"]
    }
  ]
}
JSON

cat >"$TMPDIR/approved-action-gate.json" <<'JSON'
{
  "request": {
    "action_type": "run_poc",
    "phase": "phase_3",
    "runs_target_code": false,
    "in_sandbox": false,
    "user_approved": true
  },
  "decision": {
    "allowed": true,
    "blocked_rules": []
  },
  "host_exception": {
    "id": "host-kernel-probe",
    "category": "kernel_access",
    "reason": "read host kernel counters while PoC stays sandboxed",
    "target_is_target_package": false
  }
}
JSON

cat >"$TMPDIR/denied-action-gate.json" <<'JSON'
{
  "request": {
    "action_type": "run_poc",
    "phase": "phase_3",
    "runs_target_code": false,
    "in_sandbox": false,
    "user_approved": true
  },
  "decision": {
    "allowed": false,
    "blocked_rules": ["manual_denial"]
  },
  "host_exception": {
    "id": "host-kernel-probe",
    "category": "kernel_access",
    "reason": "operator denied host probe",
    "target_is_target_package": false
  }
}
JSON

cat >"$TMPDIR/c7-action-gate.json" <<'JSON'
{
  "request": {
    "action_type": "run_poc",
    "phase": "phase_3",
    "runs_target_code": false,
    "in_sandbox": false,
    "user_approved": true
  },
  "decision": {
    "allowed": true,
    "blocked_rules": []
  },
  "host_exception": {
    "id": "host-kernel-probe",
    "category": "kernel_access",
    "reason": "attempt to run target package on host",
    "target_is_target_package": true
  }
}
JSON

PACKAGE="$TMPDIR/bbh-host-exception.rpm"
printf '%s\n' RPM_FIXTURE_PLACEHOLDER_FOR_CONTEXT_BUILD_ONLY >"$PACKAGE"

run_scan() {
    local scan_id="$1"
    local gate="$2"
    python3 "$ROOT/tools/bbh_scan.py" \
        --package "$PACKAGE" \
        --workspace "$TMPDIR/workspace" \
        --registry "$TMPDIR/registry.json" \
        --scan-id "$scan_id" \
        --mode quick \
        --allow-synthetic-rpm-fixture \
        --action-gate "$gate" >/dev/null
}

run_scan "BBH-20260706-he0001" "$TMPDIR/approved-action-gate.json"
run_scan "BBH-20260706-he0002" "$TMPDIR/denied-action-gate.json"
run_scan "BBH-20260706-he0003" "$TMPDIR/c7-action-gate.json"

python3 - "$TMPDIR/workspace" <<'PY'
import json
import sys
from pathlib import Path

workspace = Path(sys.argv[1])

approved = workspace / "BBH-20260706-he0001"
state = json.loads((approved / "scan_state.json").read_text(encoding="utf-8"))
report = (approved / "report" / "blackbox-security-report.md").read_text(encoding="utf-8")
phase_3 = state["phase_status"]["phase_3"]
assert phase_3["status"] == "done", phase_3
assert phase_3["execution_mode"] == "host_exception", phase_3
assert phase_3["host_exception_ref"] == "host-kernel-probe", phase_3
assert any(item.get("code") == "host_exception_invoked" for item in state["error_log"]), state["error_log"]
assert "## 主机例外调用摘要" in report, report
assert "例外 ID: host-kernel-probe" in report, report
assert "read host kernel counters while PoC stays sandboxed" in report, report

for scan_id in ["BBH-20260706-he0002", "BBH-20260706-he0003"]:
    scan = workspace / scan_id
    state = json.loads((scan / "scan_state.json").read_text(encoding="utf-8"))
    report = (scan / "report" / "blackbox-security-report.md").read_text(encoding="utf-8")
    phase_3 = state["phase_status"]["phase_3"]
    assert phase_3["status"] == "skipped", (scan_id, phase_3)
    assert phase_3["execution_mode"] == "sandbox", (scan_id, phase_3)
    assert any(item.get("code") == "host_exception_denied" for item in state["error_log"]), state["error_log"]
    assert "## 主机例外调用摘要" in report, report
    assert "无主机例外调用。" in report, report

c7_errors = json.loads((workspace / "BBH-20260706-he0003" / "scan_state.json").read_text(encoding="utf-8"))["error_log"]
assert any("C7 violation" in item.get("reason", "") for item in c7_errors), c7_errors
PY

echo "host exception report validation passed"
