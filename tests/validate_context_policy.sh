#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 "$PROJECT_DIR/tools/context/validate_context_policy.py"
python3 "$PROJECT_DIR/tests/context/test_context_policy.py"
