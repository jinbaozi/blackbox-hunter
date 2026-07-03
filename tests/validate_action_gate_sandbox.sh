#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 "$PROJECT_DIR/tests/context/test_action_gate.py"
python3 "$PROJECT_DIR/tests/sandbox/test_result_interpreter.py"
bash "$PROJECT_DIR/tests/sandbox/run_poc_matrix.sh"
