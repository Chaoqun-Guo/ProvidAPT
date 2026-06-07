#!/bin/bash
# ── ProvidAPT API Load Test ──────────────────────────────────
# Runs HTTP load tests against a running ProvidAPT instance.
#
# Prerequisites:
#   Install hey: go install github.com/rakyll/hey@latest
#
# Usage:
#   ./test/load/run.sh                          # default: localhost:8080
#   TARGET=http://10.0.1.100:8080 ./test/load/run.sh
#   ./test/load/run.sh --bench                   # Go benchmark mode
#   ./test/load/run.sh --help

set -euo pipefail

TARGET="${TARGET:-http://localhost:8080}"
BENCH_DURATION="${BENCH_DURATION:-10s}"
RESULTS_DIR="${RESULTS_DIR:-test/load/results}"
API_KEY="${API_KEY:-}"
AUTH_HEADER=""

if [ -n "$API_KEY" ]; then
    AUTH_HEADER="-H X-API-Key:${API_KEY}"
fi

mkdir -p "$RESULTS_DIR"

bench_go() {
    echo "=== Running Go benchmark load tests ==="
    cd "$(dirname "$0")/../.."
    go test -bench=BenchmarkAPI -benchtime=5x -count=1 ./test/load/ 2>&1 \
        | tee "$RESULTS_DIR/go-bench.txt"
    echo "Go benchmark results: $RESULTS_DIR/go-bench.txt"
}

bench_hey() {
    local label="$1" endpoint="$2" qps="$3" concurrency="$4"

    echo "--- $label ---"
    hey -n "$(( qps * 10 ))" \
        -q "$qps" \
        -c "$concurrency" \
        -z "$BENCH_DURATION" \
        -o csv \
        $AUTH_HEADER \
        "${TARGET}${endpoint}" \
        > "$RESULTS_DIR/${label}.csv" 2>/dev/null

    # Summary
    echo "  Requests:   $(tail -1 "$RESULTS_DIR/${label}.csv" | cut -d, -f1)"
    echo "  Results:    $RESULTS_DIR/${label}.csv"
}

run_load_tests() {
    echo "=== ProvidAPT Load Test ==="
    echo "Target:     $TARGET"
    echo "Duration:   $BENCH_DURATION"
    echo "Results:    $RESULTS_DIR"
    echo ""

    # Health check first
    if ! curl -sf "${TARGET}/health" > /dev/null 2>&1; then
        echo "ERROR: Target $TARGET is not responding"
        exit 1
    fi
    echo "✓ Target is healthy"
    echo ""

    # Status endpoint - low QPS
    bench_hey "status-low" "/api/v1/status" 50 5

    # Status endpoint - medium QPS
    bench_hey "status-med" "/api/v1/status" 200 10

    # Health endpoint
    bench_hey "health" "/health" 200 10

    # Graph export (small)
    bench_hey "graph-export" "/api/v1/graph/export" 50 5

    # Graph export with PID filter
    bench_hey "graph-filter" "/api/v1/graph/export?pid=1" 100 10

    echo ""
    echo "=== All load tests completed ==="
}

case "${1:-}" in
    --bench)
        bench_go
        ;;
    --help)
        echo "Usage: TARGET=http://host:8080 $0 [--bench]"
        echo ""
        echo "Options:"
        echo "  --bench       Run Go benchmark tests (no server required)"
        echo "  --help        Show this help"
        echo ""
        echo "Environment:"
        echo "  TARGET        ProvidAPT API URL (default: http://localhost:8080)"
        echo "  BENCH_DURATION  Duration per test (default: 10s)"
        echo "  API_KEY       API key for authenticated endpoints"
        echo "  RESULTS_DIR   Output directory (default: test/load/results)"
        exit 0
        ;;
    *)
        run_load_tests
        ;;
esac
