#!/bin/bash
set -euo pipefail

python3 tests/security/test_no_runtime_context_pollution.py

echo "Security regression validation passed."
