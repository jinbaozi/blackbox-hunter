#!/bin/bash
# Wrapper around tools/import_rootfs.py.
# Forwards all arguments; resolves its own location to find the .py file.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/import_rootfs.py" "$@"
