#!/bin/bash
# Wrapper: runs the three e2e tests for the tarball-rootfs feature.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
E2E_DIR="$ROOT/tests/e2e_rootfs_import"

for t in \
    "$E2E_DIR/test_import_rootfs.sh" \
    "$E2E_DIR/test_lfs_pointer_block.sh" \
    "$E2E_DIR/test_poc_runs_in_imported_image.sh"
do
    echo "  -> $(basename "$t")"
    bash "$t"
done

echo "E2E rootfs validation passed."
