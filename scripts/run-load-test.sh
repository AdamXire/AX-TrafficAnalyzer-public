#!/bin/bash
# AX-TrafficAnalyzer Load Test Runner
# Copyright © 2025 MMeTech (Macau) Ltd.
#
# Usage:
#   ./scripts/run-load-test.sh              # Interactive mode (web UI)
#   ./scripts/run-load-test.sh --headless   # Headless mode (CI/CD)
#   ./scripts/run-load-test.sh --quick      # Quick 1-minute test

set -euo pipefail

echo "=============================================="
echo "  AX-TrafficAnalyzer Load Test"
echo "=============================================="

# Configuration
HOST="${HOST:-http://localhost:8443}"
USERS="${USERS:-50}"
SPAWN_RATE="${SPAWN_RATE:-10}"
RUN_TIME="${RUN_TIME:-5m}"
LOCUSTFILE="tests/load/locustfile.py"

# Check if locust is installed
if ! command -v locust &> /dev/null; then
    echo "[LOAD] ❌ Locust not installed"
    echo "[LOAD] Install with: pip install locust"
    exit 1
fi

echo "[LOAD] Host: $HOST"
echo "[LOAD] Users: $USERS"
echo "[LOAD] Spawn rate: $SPAWN_RATE"
echo "[LOAD] Run time: $RUN_TIME"
echo ""

# Parse arguments
HEADLESS=""
QUICK=""
for arg in "$@"; do
    case $arg in
        --headless)
            HEADLESS="--headless"
            ;;
        --quick)
            QUICK="true"
            RUN_TIME="1m"
            USERS="10"
            ;;
    esac
done

# Run locust
if [ -n "$HEADLESS" ]; then
    echo "[LOAD] Running in headless mode..."
    locust -f "$LOCUSTFILE" \
        --host="$HOST" \
        --users "$USERS" \
        --spawn-rate "$SPAWN_RATE" \
        --run-time "$RUN_TIME" \
        --headless \
        --csv=load-test-results \
        --html=load-test-report.html
    
    echo ""
    echo "[LOAD] Results saved to:"
    echo "  - load-test-results_stats.csv"
    echo "  - load-test-report.html"
else
    echo "[LOAD] Starting Locust web UI..."
    echo "[LOAD] Open http://localhost:8089 in your browser"
    echo ""
    locust -f "$LOCUSTFILE" --host="$HOST"
fi

echo ""
echo "[LOAD] ✅ Load test complete"

