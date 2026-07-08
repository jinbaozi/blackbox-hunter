#!/bin/bash
# BlackBox Hunter fuzz runner (B7).
#
# Invoked inside the bbh-fuzz:local-imported container. Selects an
# engine, builds the harness, runs it for the requested duration, and
# writes a machine-readable summary to /results/fuzz_summary.json.
#
# Exit codes:
#   0  - clean run (engine produced output, may or may not have found bugs)
#   2  - engine not on PATH (af++, clang, honggfuzz)
#   3  - harness compile failed
#   4  - user-supplied duration <= 0 (B7 default off)
set -euo pipefail

ENGINE="libfuzzer"
HARNESS=""
HARNESS_BIN="/harness/fuzz_target"
CORPUS="/corpus"
RESULTS="/results"
DURATION_SEC=60
EXTRA_ASAN_FLAGS="abort_on_error=1:detect_leaks=1:exitcode=42"
TARGET_BINARY=""
TARGET_ARGS=""

usage() {
    cat <<USAGE
usage: fuzz_runner.sh [--engine {afl,libfuzzer,honggfuzz}]
                      --harness /harness/<file.c>
                      [--duration-sec N]
                      [--target-binary /path/to/binary]
                      [--target-arg arg1 --target-arg arg2]
USAGE
    exit 64
}

while [ $# -gt 0 ]; do
    case "$1" in
        --engine) ENGINE="$2"; shift 2 ;;
        --harness) HARNESS="$2"; shift 2 ;;
        --duration-sec) DURATION_SEC="$2"; shift 2 ;;
        --target-binary) TARGET_BINARY="$2"; shift 2 ;;
        --target-arg) TARGET_ARGS="$TARGET_ARGS $2"; shift 2 ;;
        --help|-h) usage ;;
        *) echo "unknown arg: $1" >&2; usage ;;
    esac
done

mkdir -p "$RESULTS"

# B7 default: duration_sec=0 means "off" (matches the contract in
# target_profile.fuzz_config.duration_sec).
if [ "${DURATION_SEC:-0}" -le 0 ]; then
    echo "duration_sec <= 0; B7 fuzz disabled" >&2
    exit 4
fi

if [ -z "$HARNESS" ]; then
    echo "ERROR: --harness is required" >&2
    usage
fi

# Resolve engine.
case "$ENGINE" in
    afl)
        ENGINE_BIN="$(command -v afl-fuzz || command -v afl++-fuzz || true)"
        ;;
    libfuzzer)
        ENGINE_BIN="$(command -v clang)"
        ;;
    honggfuzz)
        ENGINE_BIN="$(command -v honggfuzz)"
        ;;
    *)
        echo "ERROR: unknown engine: $ENGINE" >&2
        exit 2
        ;;
esac

if [ -z "$ENGINE_BIN" ]; then
    echo "ERROR: engine '$ENGINE' not on PATH" >&2
    exit 2
fi

# Build the harness (clang -fsanitize=fuzzer,address).
if [ "$ENGINE" = "libfuzzer" ] || [ "$ENGINE" = "afl" ]; then
    echo "==> compiling harness with $ENGINE_BIN"
    if ! $ENGINE_BIN -fsanitize=fuzzer,address -g -O1 "$HARNESS" \
            -o "$HARNESS_BIN" 2>"$RESULTS/compile.log"; then
        echo "harness compile failed; see $RESULTS/compile.log" >&2
        exit 3
    fi
fi

# Run the engine.
export ASAN_OPTIONS="$EXTRA_ASAN_FLAGS"
START_EPOCH="$(date -u +%s)"
case "$ENGINE" in
    libfuzzer)
        timeout "$DURATION_SEC" "$HARNESS_BIN" "$CORPUS" \
            -max_total_time="$DURATION_SEC" \
            -artifact_prefix="$RESULTS/" \
            > "$RESULTS/fuzz.log" 2>&1 || true
        ;;
    afl)
        mkdir -p "$RESULTS/afl-out"
        AFL_DRIVER_DSO_DEFER=1 timeout "$DURATION_SEC" \
            "$ENGINE_BIN" -i "$CORPUS" -o "$RESULTS/afl-out" \
                -V "$DURATION_SEC" -- "$HARNESS_BIN" \
            > "$RESULTS/fuzz.log" 2>&1 || true
        ;;
    honggfuzz)
        timeout "$DURATION_SEC" "$ENGINE_BIN" \
            --input="$CORPUS" --max_time="$DURATION_SEC" \
            --output "$RESULTS" -- "$HARNESS_BIN" \
            > "$RESULTS/fuzz.log" 2>&1 || true
        ;;
esac
END_EPOCH="$(date -u +%s)"

# Emit a machine-readable summary that maps to
# `coverage_report.fuzz_coverage_pct` and `track_a.metadata.crashes`.
CRASHES="$(find "$RESULTS" -name 'crash-*' -type f 2>/dev/null | wc -l)"
DURATION_ACTUAL=$((END_EPOCH - START_EPOCH))
cat > "$RESULTS/fuzz_summary.json" <<JSON
{
  "engine": "$ENGINE",
  "duration_sec_actual": $DURATION_ACTUAL,
  "crashes": $CRASHES,
  "harness": "$HARNESS",
  "corpus": "$CORPUS"
}
JSON

echo "fuzz run finished: $CRASHES crash(es); duration=${DURATION_ACTUAL}s"
exit 0