<!-- COMMUNITY-START -->
# AX-TrafficAnalyzer Installation Guide

**Copyright © 2025 MMeTech (Macau) Ltd.**

## Prerequisites

### System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| OS | Ubuntu 20.04+ / Debian 11+ | Ubuntu 22.04 |
| Kernel | 5.4+ | 5.15+ |
| CPU | 2 cores | 4+ cores |
| RAM | 2 GB | 4+ GB |
| Disk | 10 GB | 50+ GB |
| WiFi | AP mode support | Dedicated adapter |

### Required System Tools

```bash
# FAIL-FAST: All these are required
sudo apt-get update
sudo apt-get install -y \
    hostapd \
    dnsmasq \
    iptables \
    tcpdump \
    tshark \
    python3.11 \
    python3.11-venv \
    python3-pip
```

## Installation Methods

### Method 1: Docker (Recommended)

```bash
# Clone repository
git clone https://github.com/AdamXire/AX-TrafficAnalyzer.git
cd AX-TrafficAnalyzer

# Build and run
cd docker
docker-compose up -d

# Check status
docker-compose ps
docker-compose logs -f ax-traffic

# Access UI
open http://localhost:8443
```

### Method 2: Manual Installation

```bash
# 1. Clone repository
git clone https://github.com/AdamXire/AX-TrafficAnalyzer.git
cd AX-TrafficAnalyzer

# 2. Create virtual environment
python3.11 -m venv venv
source venv/bin/activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Run database migrations
alembic upgrade head

# 5. Start application
sudo python -m src.community.main
```

### Method 3: Kubernetes

```bash
# Build Docker image
docker build -f docker/Dockerfile -t ax-traffic-analyzer:latest .

# Deploy to Kubernetes
kubectl apply -k k8s/

# Check status
kubectl get pods -n ax-traffic
kubectl logs -n ax-traffic deployment/ax-traffic-analyzer
```

## Post-Installation

### 1. Verify Installation

```bash
# Check health endpoint
curl http://localhost:8443/api/v1/health

# Expected response:
# {"status": "healthy", "components": {...}}
```

### 2. Access Web UI

Open `http://localhost:8443` in your browser.

Default credentials:
- Username: `admin`
- Password: `admin` (change immediately!)

### 3. Connect Mobile Devices

1. Connect device to WiFi: `AX-Traffic-Analyzer`
2. Install CA certificate (shown as QR code)
3. Browse normally - traffic is captured

## Troubleshooting

See [troubleshooting.md](troubleshooting.md) for common issues.

## Next Steps

- [User Guide](user-guide.md)
- [API Reference](api.md)
- [Plugin Development](PLUGIN_DEVELOPMENT.md)
<!-- COMMUNITY-END -->

