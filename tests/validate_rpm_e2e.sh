#!/bin/bash
set -euo pipefail

bash tests/e2e/minimal_rpm_quick.sh

echo "RPM E2E validation passed."
