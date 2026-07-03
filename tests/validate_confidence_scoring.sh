#!/bin/bash
set -euo pipefail

python3 tests/merge/test_confidence_scoring.py
python3 -m py_compile tools/merge/confidence_scoring.py

echo "Confidence scoring validation passed."
