# AX-TrafficAnalyzer Docker Image
# Copyright © 2025 MMeTech (Macau) Ltd.
# Author: AdamChe 谢毅翔, 字:吉祥
#
# Multi-stage build with fail-fast validation
# REQUIRES: privileged mode and NET_ADMIN capability

# =============================================================================
# Stage 1: Builder - Install all dependencies
# =============================================================================
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.11 \
    python3.11-venv \
    python3-pip \
    build-essential \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python3.11 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# =============================================================================
# Stage 2: Runtime - Minimal production image
# =============================================================================
FROM ubuntu:22.04 AS runtime

LABEL maintainer="AdamChe <AdamXire@gmail.com>"
LABEL org.opencontainers.image.title="AX-TrafficAnalyzer"
LABEL org.opencontainers.image.description="Mobile Application Traffic Analysis Platform"
LABEL org.opencontainers.image.vendor="MMeTech (Macau) Ltd."
LABEL org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/opt/venv/bin:$PATH"
ENV AX_ENV=production

# Install runtime system dependencies
# FAIL-FAST: All these are REQUIRED for core functionality
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.11 \
    # Network tools (REQUIRED)
    hostapd \
    dnsmasq \
    iptables \
    tcpdump \
    tshark \
    iproute2 \
    net-tools \
    wireless-tools \
    # Optional tools
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && echo "[DOCKER] System dependencies installed"

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Create app directories
RUN mkdir -p /app/src /app/config /app/data /app/logs /app/captures /app/certs \
    && echo "[DOCKER] Directories created"

WORKDIR /app

# Copy application code
COPY src/ /app/src/
COPY config/ /app/config/
COPY alembic/ /app/alembic/
COPY alembic.ini /app/

# Copy entrypoint script
COPY docker/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# FAIL-FAST: Validate dependencies at build time
RUN echo "[DOCKER] Validating Python imports..." && \
    python3 -c "from src.community.core import DependencyValidator; print('[DOCKER] Core imports OK')" && \
    python3 -c "from src.community.storage import DatabaseManager; print('[DOCKER] Storage imports OK')" && \
    python3 -c "from src.community.api import health_router; print('[DOCKER] API imports OK')" && \
    echo "[DOCKER] ✅ All Python imports validated"

# Expose ports
# 8443 - HTTPS API + Web UI
# 9090 - Prometheus metrics (optional)
EXPOSE 8443 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8443/api/v1/health || exit 1

# Run as root (REQUIRED for network operations)
USER root

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["python3", "-m", "src.community.main"]

