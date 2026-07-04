#!/bin/bash
set -euo pipefail

bash tests/integration/test_rpm_extract_real.sh

echo "RPM integration validation completed."
