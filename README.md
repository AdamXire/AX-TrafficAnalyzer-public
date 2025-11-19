# AX-TrafficAnalyzer

**Copyright © 2025 MMeTech (Macau) Ltd.**  
**Author**: AdamChe 谢毅翔, 字:吉祥  
**Classification**: Enterprise Security Auditor and Education

**World-Class Mobile Application Traffic Analysis Platform**

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20WSL2-lightgrey.svg)](DESIGN_PLAN.md#platform-support-strategy)

## Overview

AX-TrafficAnalyzer is a professional-grade, open-source network traffic analysis platform designed specifically for mobile application security testing and debugging. It provides **transparent HTTPS interception** through an integrated WiFi hotspot with **zero client-side configuration required**.

### Key Features

✅ **Zero Configuration** - Mobile devices connect to a normal WiFi hotspot, no proxy settings needed  
✅ **Transparent HTTPS MITM** - Automatic SSL/TLS interception with dynamic certificate generation  
✅ **Integrated Workflow** - Single platform combining hotspot, capture, analysis, and visualization  
✅ **Wireshark Integration** - Native PCAP export for deep protocol analysis  
✅ **Extensible Architecture** - Plugin system for custom analysis and scanning  
✅ **Production Ready** - Fail-fast design, comprehensive monitoring, automatic recovery  
✅ **Advanced Analysis** - Protocol analyzers, vulnerability scanner, HTTP fuzzer  
✅ **Real-time Dashboard** - Web UI with live traffic monitoring  
✅ **API-First Design** - RESTful API + WebSocket for automation  

## Quick Start

```bash
# Clone repository
git clone https://github.com/yourusername/AX-TrafficAnalyzer.git
cd AX-TrafficAnalyzer

# Install (automated script)
sudo ./scripts/install.sh

# Start the analyzer
sudo ax-traffic start

# Open web UI
open https://localhost:8443
```

## Architecture

```
Mobile Device → WiFi Hotspot → HTTPS MITM → Analysis → PCAP Export → Wireshark
                    ↓              ↓           ↓           ↓
                  hostapd      mitmproxy   Scanners   Web Dashboard
```

See [DESIGN_PLAN.md](DESIGN_PLAN.md) for complete architectural details.

## Platform Support

| Platform | Status | Features |
|----------|--------|----------|
| Native Linux (Ubuntu, Debian, Fedora, Arch) | ✅ Tier 1 | Full feature set |
| WSL2 (Windows 10/11) | ✅ Tier 1 | Full feature set |
| Native Windows | ❌ Not supported | Use WSL2 instead |
| Android (rooted) | 🔄 Future | Limited features |

## Use Cases

- 📱 **Mobile App Security Testing** - Intercept and analyze mobile app communications
- 🐛 **API Debugging** - Debug REST APIs and GraphQL queries
- 🔍 **Network Analysis** - Deep packet inspection with Wireshark
- 🛡️ **Vulnerability Scanning** - Detect security issues in mobile apps
- 🧪 **Penetration Testing** - Fuzzing, request replay, active scanning
- 📊 **Traffic Monitoring** - Monitor and log all network activity

## Documentation

- [📖 Design Plan](DESIGN_PLAN.md) - Complete system design and architecture
- [🚀 Installation Guide](docs/installation.md) - Detailed installation instructions
- [📚 User Guide](docs/user-guide.md) - How to use AX-TrafficAnalyzer
- [🔌 Plugin Development](docs/plugins.md) - Creating custom plugins
- [🔧 API Reference](docs/api.md) - REST API and WebSocket documentation
- [❓ Troubleshooting](docs/troubleshooting.md) - Common issues and solutions
- [📝 Marker Guide](docs/MARKER_GUIDE.md) - Documentation marker system for dual licensing

## Documentation Generation

This project uses a hybrid repository strategy with explicit markers to separate Community Edition and Enterprise Edition content. The `generate-community-docs.py` script automatically generates Community Edition documentation from marked source files.

### Usage

```bash
# Generate all Community Edition documentation files
python3 scripts/generate-community-docs.py --all

# Generate a single file
python3 scripts/generate-community-docs.py README.md build/community/README.md

# Validate markers without generating files
python3 scripts/generate-community-docs.py --validate-only --all

# Dry run (show what would be generated)
python3 scripts/generate-community-docs.py --dry-run --all

# Verbose output
python3 scripts/generate-community-docs.py --all --verbose

# Force mode (bypass git status check)
python3 scripts/generate-community-docs.py --all --force

# Rollback file to latest backup
python3 scripts/generate-community-docs.py --rollback build/community/README.md

# Verify checksums
python3 scripts/generate-community-docs.py --verify-checksums

# Disable backups
python3 scripts/generate-community-docs.py --all --no-backup
```

### Configuration

The generator uses `scripts/community-doc-config.json` for configuration. See the file for available options.

### File Operations

The generator includes production-grade file operation safety features:
- **Backup System**: Automatic backups before file modifications
- **Atomic Writes**: All-or-nothing file writes
- **Rollback Mechanism**: Automatic recovery on failure
- **Checksum Verification**: File integrity validation

See [docs/FILE_OPERATIONS.md](docs/FILE_OPERATIONS.md) for complete documentation.

### Public Repository Setup

**Automated Setup** (Recommended):
```bash
# Create and configure public repository automatically
python3 scripts/setup-public-repo.py --repo-name AX-TrafficAnalyzer-public

# Dry-run (validate only)
python3 scripts/setup-public-repo.py --repo-name my-repo --dry-run
```

**Prerequisites**:
- GitHub CLI (`gh`) >= 2.0.0 installed
- Authenticated: `gh auth login`

See [docs/PUBLIC_REPO_SETUP.md](docs/PUBLIC_REPO_SETUP.md) for complete setup guide.

### Syncing to Public Repository

Sync generated Community Edition documentation to a public repository:

```bash
# Sync to public repository
./scripts/sync-to-public.sh https://github.com/user/repo.git

# Detect leaks in public repo
./scripts/detect-leaks.sh ../AX-TrafficAnalyzer-public

# Emergency rollback (if needed)
./scripts/emergency-rollback.sh ../AX-TrafficAnalyzer-public
```

See [docs/SYNC_GUIDE.md](docs/SYNC_GUIDE.md) for complete sync documentation.

### Marker System

Documentation files use explicit HTML comment markers to separate content:
- `<!-- COMMUNITY-START -->` / `<!-- COMMUNITY-END -->` - Community Edition content
- `<!-- ENTERPRISE-START -->` / `<!-- ENTERPRISE-END -->` - Enterprise Edition content (excluded from public)
- `<!-- SHARED-START -->` / `<!-- SHARED-END -->` - Content for both editions

See [docs/MARKER_GUIDE.md](docs/MARKER_GUIDE.md) for complete marker syntax and usage.

### Troubleshooting

If generation fails, see [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for common issues and solutions.

## Project Status

**Current Phase**: Design & Planning  
**Version**: 1.0 (in development)  
**Target Release**: Q2 2026

### Implementation Progress

- [x] Comprehensive design plan
- [ ] Phase 1: Foundation (Weeks 1-2)
- [ ] Phase 2: Traffic Capture (Weeks 3-4)
- [ ] Phase 3: Storage & API (Weeks 5-6)
- [ ] Phase 4: Web UI (Weeks 7-8)
- [ ] Phase 5: Analysis Features (Weeks 9-10)
- [ ] Phase 6: Advanced Features (Weeks 11-12)
- [ ] Phase 7: Nice-to-Have (Weeks 13-14)
- [ ] Phase 8: Production Ready (Weeks 15-16)

## Requirements

### System Requirements

- **OS**: Linux (Ubuntu 20.04+, Debian 11+, Fedora 35+, Arch) or WSL2
- **Kernel**: 5.4+
- **CPU**: 2+ cores (4+ recommended)
- **RAM**: 2GB minimum (4GB+ recommended)
- **Disk**: 10GB+ free space
- **WiFi**: WiFi adapter with AP mode support

### Software Dependencies

**System Tools**:
- hostapd (>= 2.9)
- dnsmasq (>= 2.80)
- iptables (>= 1.8)
- tcpdump (>= 4.9)
- tshark (>= 3.0)
- systemd

**Python** (>= 3.11):
- mitmproxy
- fastapi
- scapy
- sqlalchemy
- structlog
- See [requirements.txt](requirements.txt) for complete list

## Installation

### Automated Installation

```bash
# One-command installation (recommended)
curl -sSL https://raw.githubusercontent.com/yourusername/AX-TrafficAnalyzer/main/scripts/install.sh | sudo bash
```

### Manual Installation

```bash
# 1. Install system dependencies
sudo apt-get update
sudo apt-get install -y hostapd dnsmasq iptables tcpdump tshark python3.11 python3-pip

# 2. Clone repository
git clone https://github.com/yourusername/AX-TrafficAnalyzer.git
cd AX-TrafficAnalyzer

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Run setup
sudo python -m src.setup

# 5. Start service
sudo systemctl start ax-traffic
```

### Docker Installation

```bash
# Using Docker Compose
docker-compose up -d

# Access web UI
open https://localhost:8443
```

## Usage

### Starting the Hotspot

```bash
# Start AX-TrafficAnalyzer
sudo ax-traffic start

# Check status
sudo ax-traffic status

# View logs
sudo ax-traffic logs

# Stop
sudo ax-traffic stop
```

### Connecting Devices

1. Connect your mobile device to the WiFi network (default SSID: `AX-Traffic-Analyzer`)
2. Install the CA certificate (displayed as QR code on first connection)
3. Browse normally - all traffic is captured automatically
4. View captured traffic in the web dashboard at `https://localhost:8443`

### Using the Web UI

1. **Dashboard** - Real-time metrics and activity
2. **Traffic** - Browse all captured HTTP/HTTPS requests
3. **Sessions** - View sessions by device
4. **PCAP Files** - Download captures for Wireshark
5. **Findings** - Security vulnerabilities detected
6. **Plugins** - Manage installed plugins

### Exporting to Wireshark

```bash
# Export session to PCAP
ax-traffic export --session <session-id> --output capture.pcap

# Open in Wireshark
wireshark capture.pcap
```

## API Usage

### REST API

```bash
# Get all sessions
curl -H "Authorization: Bearer <token>" https://localhost:8443/api/v1/sessions

# Get traffic for a session
curl -H "Authorization: Bearer <token>" https://localhost:8443/api/v1/sessions/<id>/flows

# Download PCAP
curl -H "Authorization: Bearer <token>" https://localhost:8443/api/v1/pcaps/<id>/download -o capture.pcap
```

### WebSocket

```javascript
const ws = new WebSocket('wss://localhost:8443/api/v1/ws');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.event === 'http_flow') {
    console.log('New request:', data.data);
  }
};
```

## Plugin Development

Create custom plugins to extend AX-TrafficAnalyzer:

```python
from ax_traffic.plugins import Plugin

class MyPlugin(Plugin):
    name = "my_plugin"
    version = "1.0.0"
    
    def on_request(self, flow):
        # Analyze HTTP request
        if 'password' in flow.request.text:
            self.alert("Password in cleartext detected!")
    
    def on_response(self, flow):
        # Analyze HTTP response
        pass
```

See [Plugin Development Guide](docs/plugins.md) for details.

## Security Considerations

⚠️ **Important**: This tool captures and decrypts HTTPS traffic. Use responsibly and legally:

- ✅ Only use on networks you own or have explicit permission to monitor
- ✅ Inform users that their traffic is being captured
- ✅ Comply with local privacy laws (GDPR, CCPA, etc.)
- ✅ Secure captured data appropriately
- ✅ Delete captured data when no longer needed

See [Security Documentation](docs/security.md) for best practices.

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone repository
git clone https://github.com/yourusername/AX-TrafficAnalyzer.git
cd AX-TrafficAnalyzer

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Run linter
ruff check src/

# Format code
black src/
```

## Comparison with Other Tools

| Feature | AX-Traffic | mitmproxy | Burp Suite | Wireshark |
|---------|-----------|-----------|------------|-----------|
| Integrated Hotspot | ✅ | ❌ | ❌ | ❌ |
| Zero Client Config | ✅ | ❌ | ❌ | ✅ |
| HTTPS MITM | ✅ | ✅ | ✅ | ❌ |
| PCAP Export | ✅ | ❌ | ❌ | ✅ |
| Vulnerability Scanner | ✅ | ❌ | ✅ | ❌ |
| Web Dashboard | ✅ | ✅ | ✅ | ❌ |
| Plugin System | ✅ | ✅ | ✅ | ✅ |
| Request Replay | ✅ | ✅ | ✅ | ❌ |
| Fuzzer | ✅ | ❌ | ✅ | ❌ |
| Open Source | ✅ | ✅ | ❌ | ✅ |

## Roadmap

### Version 1.0 (Current)
- Core traffic capture
- HTTPS MITM
- PCAP export
- Web UI
- Basic analysis
- Plugin system

### Version 1.1 (Q1 2026)
- Mobile app
- Enhanced ML models
- Advanced fuzzing
- Improved collaboration

### Version 2.0 (Q3 2026)
- Multi-platform support
- Enterprise features
- Advanced reporting
- Performance improvements

See [DESIGN_PLAN.md](DESIGN_PLAN.md#future-roadmap) for complete roadmap.

## CI/CD

This project uses GitHub Actions for automated validation and testing:

- **Marker Validation**: Automatically validates documentation markers on every push/PR
- **Test Suite**: Runs full test suite with coverage reporting
- **Leak Detection**: Checks for Enterprise content leaks in generated files

**Status:**
[![Validate Markers](https://github.com/yourusername/AX-TrafficAnalyzer/actions/workflows/validate-markers.yml/badge.svg)](https://github.com/yourusername/AX-TrafficAnalyzer/actions/workflows/validate-markers.yml)
[![Tests](https://github.com/yourusername/AX-TrafficAnalyzer/actions/workflows/test.yml/badge.svg)](https://github.com/yourusername/AX-TrafficAnalyzer/actions/workflows/test.yml)

See [docs/CI_CD.md](docs/CI_CD.md) for complete CI/CD documentation.

## Support

- 📧 Email: support@ax-traffic-analyzer.com
- 💬 Discord: https://discord.gg/ax-traffic
- 🐛 Issues: https://github.com/yourusername/AX-TrafficAnalyzer/issues
- 📖 Documentation: https://docs.ax-traffic-analyzer.com

## License

**Copyright © 2025 MMeTech (Macau) Ltd.**  
**Author**: AdamChe 谢毅翔, 字:吉祥  
**Classification**: Enterprise Security Auditor and Education

### Dual Licensing Model

AX-TrafficAnalyzer is available under two licenses:

<!-- COMMUNITY-START -->
#### Community Edition (MIT License)
- ✅ **Free and open source**
- ✅ Perfect for education, research, personal projects
- ✅ Includes core traffic capture and analysis features
- ✅ See [LICENSE-COMMUNITY](LICENSE-COMMUNITY) for details
<!-- COMMUNITY-END -->

<!-- ENTERPRISE-START -->
#### Enterprise Edition (Proprietary)
- 🔒 **Commercial license required**
- 🔒 Advanced features (ML, active scanning, fuzzing, compliance)
- 🔒 SLA-backed support with 99.9% uptime
- 🔒 Contact: sales@mmetech.com
- 🔒 See [LICENSE-ENTERPRISE](LICENSE-ENTERPRISE) for details
<!-- ENTERPRISE-END -->

See [LICENSING_GUIDE.md](LICENSING_GUIDE.md) for complete comparison.

### License Compliance Notice

This software contains:
- **MIT-licensed dependencies**: mitmproxy, FastAPI, React (see [NOTICES.md](NOTICES.md))
- **AdamChe proprietary innovations**: Copyright (c) 2025 MMeTech (Macau) Ltd.

**Community Edition**: MIT License allows free use, modification, and distribution  
<!-- ENTERPRISE-START -->
**Enterprise Edition**: Proprietary features require commercial license
<!-- ENTERPRISE-END -->

## Acknowledgments

- **mitmproxy** - HTTPS interception engine
- **Wireshark** - Inspiration for packet analysis
- **hostapd** - WiFi AP functionality
- **FastAPI** - Modern Python web framework

## Citation

If you use AX-TrafficAnalyzer in your research, please cite:

```bibtex
@software{ax_traffic_analyzer,
  title = {AX-TrafficAnalyzer: Mobile Application Traffic Analysis Platform},
  author = {AdamChe 谢毅翔, 字:吉祥},
  publisher = {MMeTech (Macau) Ltd.},
  year = {2025},
  classification = {Enterprise Security Auditor and Education},
  url = {https://github.com/yourusername/AX-TrafficAnalyzer}
}
```

---

**Copyright © 2025 MMeTech (Macau) Ltd.**  
**Author**: AdamChe 谢毅翔, 字:吉祥  
**Classification**: Enterprise Security Auditor and Education

Made with ❤️ for enterprise security and education

