#!/bin/bash
# AX-TrafficAnalyzer Docker Entrypoint
# Copyright © 2025 MMeTech (Macau) Ltd.
#
# FAIL-FAST: Exit immediately on any error
set -euo pipefail

echo "=============================================="
echo "  AX-TrafficAnalyzer Container Startup"
echo "=============================================="

# -----------------------------------------------------------------------------
# FAIL-FAST: Validate critical dependencies
# -----------------------------------------------------------------------------
echo "[ENTRYPOINT] Validating system dependencies..."

check_command() {
    local cmd=$1
    local pkg=$2
    if ! command -v "$cmd" &> /dev/null; then
        echo "[ENTRYPOINT] ❌ FATAL: $cmd not found"
        echo "[ENTRYPOINT] Install with: apt-get install $pkg"
        exit 1
    fi
    echo "[ENTRYPOINT] ✓ $cmd found"
}

check_command hostapd hostapd
check_command dnsmasq dnsmasq
check_command iptables iptables
check_command tcpdump tcpdump
check_command tshark tshark

echo "[ENTRYPOINT] ✅ All system dependencies validated"

# -----------------------------------------------------------------------------
# FAIL-FAST: Validate Python environment
# -----------------------------------------------------------------------------
echo "[ENTRYPOINT] Validating Python environment..."

if ! python3 --version &> /dev/null; then
    echo "[ENTRYPOINT] ❌ FATAL: Python3 not found"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "[ENTRYPOINT] ✓ Python $PYTHON_VERSION found"

# Validate critical Python imports
python3 -c "from src.community.core import get_platform_info" || {
    echo "[ENTRYPOINT] ❌ FATAL: Cannot import core modules"
    exit 1
}
echo "[ENTRYPOINT] ✅ Python environment validated"

# -----------------------------------------------------------------------------
# FAIL-FAST: Validate network capabilities
# -----------------------------------------------------------------------------
echo "[ENTRYPOINT] Validating network capabilities..."

# Check if running with required capabilities
if ! capsh --print 2>/dev/null | grep -q "cap_net_admin"; then
    echo "[ENTRYPOINT] ⚠ Warning: NET_ADMIN capability may not be available"
    echo "[ENTRYPOINT] Run container with: --cap-add=NET_ADMIN"
fi

# Check if running in privileged mode (required for iptables)
if [ ! -w /proc/sys/net/ipv4/ip_forward ]; then
    echo "[ENTRYPOINT] ⚠ Warning: Cannot modify network settings"
    echo "[ENTRYPOINT] Run container with: --privileged"
fi

echo "[ENTRYPOINT] ✅ Network capabilities checked"

# -----------------------------------------------------------------------------
# Initialize directories
# -----------------------------------------------------------------------------
echo "[ENTRYPOINT] Initializing directories..."

mkdir -p /app/data /app/logs /app/captures /app/certs
chmod 755 /app/data /app/logs /app/captures /app/certs

echo "[ENTRYPOINT] ✅ Directories initialized"

# -----------------------------------------------------------------------------
# Run database migrations
# -----------------------------------------------------------------------------
echo "[ENTRYPOINT] Running database migrations..."

cd /app
if [ -f "alembic.ini" ]; then
    alembic upgrade head || {
        echo "[ENTRYPOINT] ⚠ Migration failed, continuing anyway..."
    }
    echo "[ENTRYPOINT] ✅ Database migrations complete"
else
    echo "[ENTRYPOINT] ⚠ No alembic.ini found, skipping migrations"
fi

# -----------------------------------------------------------------------------
# Start application
# -----------------------------------------------------------------------------
echo "[ENTRYPOINT] Starting AX-TrafficAnalyzer..."
echo "=============================================="

exec "$@"

