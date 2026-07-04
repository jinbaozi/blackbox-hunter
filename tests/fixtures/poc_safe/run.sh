#!/bin/sh
set -eu
printf '%s\n' SAFE_POC_STARTED
if touch /pkg/should-not-write 2>/workspace/results/pkg_write_error.txt; then
  printf '%s\n' UNEXPECTED_PKG_WRITE
else
  printf '%s\n' PKG_WRITE_BLOCKED
fi
printf '%s\n' result-ok > /workspace/results/poc_output.txt
