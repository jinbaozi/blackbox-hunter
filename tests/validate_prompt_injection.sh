#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 "$PROJECT_DIR/tests/prompt_injection/test_injection_filter.py"
python3 "$PROJECT_DIR/tests/prompt_injection/test_context_integration.py"
