#!/bin/bash
# BlackBox Hunter - Tool Environment Preflight and Installer
# Usage: ./install.sh [--check-only] [--force] [--offline] [--auto-fix]
#                    [--package-type deb|rpm] [--output file|--scan-root dir]
#                    [--registry file]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/preflight.py" "$@"
