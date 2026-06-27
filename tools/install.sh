#!/bin/bash
# BlackBox Hunter - Tool Auto-Installation Script
# Usage: ./install.sh [--check-only] [--force]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGISTRY="$SCRIPT_DIR/tool_registry.json"
CHECK_ONLY=false
FORCE=false
INSTALLED=()
FAILED=()
SKIPPED=()

for arg in "$@"; do
  case "$arg" in
    --check-only) CHECK_ONLY=true ;;
    --force) FORCE=true ;;
  esac
done

detect_os() {
  if command -v apt-get &>/dev/null; then echo "apt"
  elif command -v dnf &>/dev/null; then echo "dnf"
  elif command -v brew &>/dev/null; then echo "brew"
  else echo "unknown"
  fi
}

OS=$(detect_os)
echo "=== BlackBox Hunter Tool Installer ==="
echo "Detected OS package manager: $OS"
echo ""

TOOL_COUNT=$(python3 -c "import json; print(len(json.load(open('$REGISTRY'))['tools']))")

for i in $(seq 0 $((TOOL_COUNT - 1))); do
  TOOL_JSON=$(python3 -c "
import json
tools = json.load(open('$REGISTRY'))['tools']
t = tools[$i]
print(json.dumps(t))
")

  NAME=$(echo "$TOOL_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['name'])")
  DETECT=$(echo "$TOOL_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['detect_cmd'])")
  PRIORITY=$(echo "$TOOL_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['priority'])")

  echo -n "[$((i+1))/$TOOL_COUNT] $NAME ($PRIORITY) ... "

  # Check if already installed
  if eval "$DETECT" &>/dev/null; then
    echo "already installed"
    INSTALLED+=("$NAME")
    continue
  fi

  if $CHECK_ONLY; then
    echo "MISSING"
    SKIPPED+=("$NAME")
    continue
  fi

  # Try to install
  INSTALL_CMD=$(echo "$TOOL_JSON" | python3 -c "
import json, sys
t = json.load(sys.stdin)
cmds = t.get('install_cmds', {})
os = '$OS'
if os in cmds:
    print(cmds[os])
elif 'fallback' in cmds:
    print(cmds['fallback'])
else:
    print('')
")

  if [ -z "$INSTALL_CMD" ]; then
    echo "no install command for $OS"
    FAILED+=("$NAME")
    continue
  fi

  echo "installing..."
  if eval "$INSTALL_CMD" &>/dev/null; then
    if eval "$DETECT" &>/dev/null; then
      echo "  OK"
      INSTALLED+=("$NAME")
    else
      echo "  install seemed to succeed but detection failed"
      FAILED+=("$NAME")
    fi
  else
    # Try fallbacks
    echo "  primary install failed, trying fallbacks..."
    FALLBACK_OK=false
    FALLBACKS=$(echo "$TOOL_JSON" | python3 -c "import json,sys; print(' '.join(json.load(sys.stdin).get('fallbacks',[])))")
    for fb in $FALLBACKS; do
      if command -v "$fb" &>/dev/null; then
        echo "  fallback '$fb' available"
        INSTALLED+=("$NAME(via $fb)")
        FALLBACK_OK=true
        break
      fi
    done
    if ! $FALLBACK_OK; then
      echo "  FAILED (no fallbacks available)"
      FAILED+=("$NAME")
    fi
  fi
done

echo ""
echo "=== Installation Summary ==="
echo "Installed: ${#INSTALLED[@]} (${INSTALLED[*]:-none})"
echo "Failed:    ${#FAILED[@]} (${FAILED[*]:-none})"
echo "Skipped:   ${#SKIPPED[@]} (${SKIPPED[*]:-none})"

if [ ${#FAILED[@]} -gt 0 ]; then
  echo ""
  echo "WARNING: Some tools failed to install. Scanning will continue with available tools."
  exit 0  # Don't fail the whole pipeline
fi
