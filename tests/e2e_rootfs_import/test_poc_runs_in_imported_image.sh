#!/bin/bash
# E2E T3: quick scan uses the imported rootfs image as the sandbox base.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMPDIR="${TMPDIR:-/tmp}/bbh-t3-$$"
SCAN_ID="BBH-20260706-t3$(printf '%04d' $(( $$ % 10000 )))"
SCAN_ROOT="$TMPDIR/workspace/$SCAN_ID"
ROOTFS="$ROOT/assets/rootfs/v11-2503-rootfs.tar"
RECORD="$ROOT/tools/.imported_rootfs.json"
RECORD_BACKUP="$TMPDIR/imported_rootfs.json.bak"
STABLE_REF="bbh-base:local-imported"

mkdir -p "$TMPDIR"

ENGINE=""
for candidate in docker podman; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" info >/dev/null 2>&1; then
        ENGINE="$candidate"
        break
    fi
done
[ -n "$ENGINE" ] || { echo "no reachable docker or podman engine"; exit 1; }

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

command -v dpkg-deb >/dev/null 2>&1 || { echo "BLOCKED: dpkg-deb missing"; exit 77; }

PKGROOT="$TMPDIR/pkgroot"
mkdir -p "$PKGROOT/DEBIAN" "$PKGROOT/usr/bin"
cat >"$PKGROOT/DEBIAN/control" <<'CONTROL'
Package: bbh-t3-fixture
Version: 1.0
Section: misc
Priority: optional
Architecture: all
Maintainer: BlackBox Hunter Test <noreply@example.invalid>
Description: Minimal fixture for imported image quick scan
CONTROL
cat >"$PKGROOT/usr/bin/bbh-t3-fixture" <<'SCRIPT'
#!/bin/sh
exit 0
SCRIPT
chmod 0755 "$PKGROOT/usr/bin/bbh-t3-fixture"

PACKAGE="$TMPDIR/bbh-t3-fixture.deb"
dpkg-deb --build "$PKGROOT" "$PACKAGE" >/dev/null

python3 "$ROOT/tools/import_rootfs.py" \
    --tarball "$ROOTFS" \
    --tag-prefix bbh-base \
    --record-path "$RECORD"

python3 "$ROOT/tools/bbh_scan.py" \
    --package "$PACKAGE" \
    --workspace "$TMPDIR/workspace" \
    --scan-id "$SCAN_ID" \
    --mode quick

test -f "$SCAN_ROOT/env_check.json"
test -f "$SCAN_ROOT/sandbox_status.json"
test -f "$SCAN_ROOT/scan_state.json"

python3 - "$SCAN_ROOT" <<'PY'
import json
import sys
from pathlib import Path

scan_root = Path(sys.argv[1])
env_check = json.loads((scan_root / "env_check.json").read_text(encoding="utf-8"))
sandbox_status = json.loads((scan_root / "sandbox_status.json").read_text(encoding="utf-8"))
scan_state = json.loads((scan_root / "scan_state.json").read_text(encoding="utf-8"))

assert sandbox_status["base_image_ref"] == "bbh-base:local-imported", sandbox_status
assert sandbox_status["base_image_source"] == "imported_rootfs_tarball", sandbox_status
assert env_check["rootfs_status"] == "imported", env_check
assert scan_state["current_phase"] == "completed", scan_state
PY

echo "T3 passed"
