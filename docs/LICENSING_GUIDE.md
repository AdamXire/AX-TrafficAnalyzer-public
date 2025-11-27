# AX-TrafficAnalyzer Licensing Guide

**Copyright © 2025 MMeTech (Macau) Ltd.**
**Author**: AdamChe 谢毅翔, 字:吉祥
**Classification**: Enterprise Security Auditor and Education

---

## Table of Contents

1. [Overview](#overview)
2. [Community Edition (MIT License)](#community-edition-mit-license)
4. [Feature Comparison](#feature-comparison)
5. [Phased Rollout Plan](#phased-rollout-plan)
6. [Pricing](#pricing)
7. [How to Choose](#how-to-choose)
8. [FAQ](#faq)
9. [Contact](#contact)

---

## Overview

AX-TrafficAnalyzer uses a **dual licensing model** to serve both educational and enterprise markets:

- **Community Edition**: MIT License (free, open source)

This model allows:
- ✅ Free use for education and research
- ✅ Community contributions and adoption
- ✅ Commercial viability for enterprises
- ✅ Sustainable development and support

---


## Community Edition (MIT License)

### What's Included

**Core Infrastructure:**
✅ WiFi hotspot creation and management
✅ Transparent HTTPS MITM interception
✅ Automatic certificate generation and rotation
✅ Traffic capture and logging
✅ IPv6 dual-stack support
✅ Network partition resilience
✅ Time synchronization (NTP)
✅ Atomic startup with rollback

**Traffic Analysis:**
✅ Basic protocol analysis (HTTP, TLS, DNS)
✅ Session and device tracking
✅ Basic vulnerability scanning (passive only)
✅ PCAP export for Wireshark
✅ Streaming PCAP with backpressure
✅ Traffic statistics and metrics

**User Interface:**
✅ Web dashboard (basic features)
✅ Real-time traffic viewing
✅ Session browser
✅ Device list
✅ PCAP file manager

**API & Integration:**
✅ REST API (core endpoints)
✅ WebSocket server (real-time updates)
✅ Authentication (JWT)
✅ Basic RBAC
✅ Wireshark integration
✅ Plugin system (core framework)

**Security & Compliance:**
✅ Certificate management
✅ Plugin sandboxing (seccomp)
✅ GDPR compliance tools
✅ Basic audit logging
✅ Data retention management

### License Terms

- **Type**: MIT License
- **Cost**: **FREE** (永久免費)
- **Source Code**: Available on GitHub
- **Redistribution**: Allowed
- **Commercial Use**: Allowed
- **Modification**: Allowed
- **Attribution Required**: Yes

### Use Cases

✅ **Education**: Teaching network security, traffic analysis
✅ **Research**: Academic research, security studies
✅ **Personal Projects**: Learning, testing, experimentation
✅ **Startups**: Early-stage companies, MVPs
✅ **Open Source**: Contributing to the community

### Support

- **Documentation**: Complete user guides and API docs
- **Community Forum**: GitHub Discussions
- **Issue Tracking**: GitHub Issues
- **Updates**: Regular releases on GitHub
- **Response Time**: Best effort (no SLA)

### How to Get Started

```bash
# Clone repository
git clone https://github.com/yourusername/AX-TrafficAnalyzer.git
cd AX-TrafficAnalyzer

# Install Community Edition
sudo ./scripts/install.sh --edition=community

# Start the analyzer
sudo ax-traffic start

# Open web UI
open https://localhost:8443

# Check edition
ax-traffic --version
```


---


---

## Feature Comparison


| Feature Category | Community | Enterprise |
|------------------|-----------|------------|
| **Core Capture** | | |
| WiFi Hotspot | ✅ | ✅ |
| HTTPS MITM | ✅ | ✅ |
| Traffic Logging | ✅ | ✅ |
| PCAP Export | ✅ | ✅ |
| IPv6 Support | ✅ | ✅ |
| **Analysis** | | |
| Protocol Analysis | ✅ Basic | ✅ Advanced |
| Vulnerability Scanning | ✅ Passive | ✅ Active + Passive |
| ML Anomaly Detection | ❌ | ✅ |
| AI Zero-Day Detection | ❌ | ✅ |
| HTTP Fuzzing | ❌ | ✅ |
| Request Replay | ✅ Basic | ✅ Advanced |
| **UI & Dashboard** | | |
| Web Dashboard | ✅ Basic | ✅ Advanced |
| Desktop GUI | ✅ | ✅ |
| Mobile App | ✅ Basic | ✅ Advanced |
| Real-time Collaboration | ❌ | ✅ |
| **Enterprise Features** | | |
| Multi-tenant | ❌ | ✅ |
| SSO/LDAP | ❌ | ✅ |
| Compliance Reporting | ❌ | ✅ |
| Distributed Capture | ❌ | ✅ |
| Hardware Acceleration | ❌ | ✅ |
| Blockchain Audit Trail | ❌ | ✅ |
| **Support & SLA** | | |
| Community Support | ✅ | ✅ |
| Email Support | ❌ | ✅ |
| Phone Support | ❌ | ✅ 24/7 |
| Response Time SLA | ❌ | ✅ 4h |
| Uptime SLA | ❌ | ✅ 99.9% |
| Professional Services | ❌ | ✅ |
| **Deployment** | | |
| Max Deployments | Unlimited | Per License |
| Source Code | ✅ GitHub | ❌ Binary |
| Updates | ✅ | ✅ Priority |
| **Cost** | | |
| Price | **FREE** | **Commercial pricing** (see pricing section) |


---

## Phased Rollout Plan

### Phase 0-6: Community Edition Only (Weeks 1-12)
**Status**: 100% MIT License

**Released Features:**
- ✅ Phase 0: Critical Infrastructure
- ✅ Phase 1: Foundation (Platform, Hotspot)
- ✅ Phase 2: Traffic Capture (mitmproxy, PCAP)
- ✅ Phase 3: Storage & API
- ✅ Phase 4: Web UI
- ✅ Phase 5: Basic Analysis
- ✅ Phase 6: Basic Advanced Features

**All features**: Open source on GitHub under MIT License

---

### Phase 7: First Enterprise Features (Weeks 13-14)
**Status**: Core MIT + Enterprise Add-ons

**Community (MIT):**
- ✅ Desktop GUI (Electron)
- ✅ Basic mobile app
- ✅ 802.11 monitor mode
- ✅ GPS tracking


---

### Phase 8: Production Ready + Enterprise Expansion (Weeks 15-18)
**Status**: Dual licensing fully operational

**Community (MIT):**
- ✅ Performance optimization
- ✅ Security hardening
- ✅ Complete documentation
- ✅ Docker/Kubernetes


---

### Post-Release: Ongoing Enterprise Development

**Community Edition** (Quarterly updates):
- Bug fixes and security patches
- Minor feature improvements
- Community contributions
- Documentation updates


---

## Pricing


### Community Edition
**Price**: **FREE** (永久免費)
**License**: MIT License
**Support**: Community forums
**Updates**: GitHub releases



---

## How to Choose

### Choose Community Edition if:
✅ You're using it for education or research
✅ You're a student or individual developer
✅ You're a startup with limited budget
✅ You only need basic traffic capture and analysis
✅ You can rely on community support
✅ You want to contribute to open source



---

## FAQ

### General Questions

**Q: What's the difference between Community and Enterprise?**

**Q: Can I use Community Edition commercially?**
A: Yes! MIT License allows commercial use. However, Enterprise features require a commercial license.

**Q: Is the source code available?**

**Q: Can I contribute to Community Edition?**
A: Yes! We welcome contributions under MIT License (CLA may be required).

### Licensing Questions

**Q: What happens when my Enterprise license expires?**
A: Enterprise features stop working, but you can continue using Community Edition under MIT License.

**Q: Can I switch from Enterprise back to Community?**
A: Yes, at any time. Just don't renew your Enterprise license.

**Q: Do I need a license for each server?**
A: Production License: Yes, per deployment. Enterprise Subscription: No, unlimited deployments.

**Q: Can I move my license between servers?**
A: Yes, deactivate on one server, activate on another. License is per deployment, not per hardware.

**Q: What if I exceed my deployment limit?**
A: You'll need to purchase additional licenses or upgrade to Enterprise Subscription.

### Feature Questions

**Q: Can I add custom plugins to Community Edition?**

**Q: Can Community Edition users export to PCAP?**
A: Yes, PCAP export is in Community Edition.

**Q: Do I need Enterprise for vulnerability scanning?**
A: Community has passive scanning. Enterprise has active scanning with fuzzing.

**Q: Can Community Edition handle 50+ clients?**
A: Yes, performance is the same. Enterprise adds features, not limits.

### Pricing Questions

**Q: Is there a free trial for Enterprise?**
A: Yes, 30-day free trial with all Enterprise features.

**Q: Do you offer non-profit discounts?**
A: Yes, up to 50% discount for qualified organizations. Contact sales@mmetech.com.

**Q: Are there volume discounts?**
A: Yes, 10-40% discounts for multiple deployments.

**Q: What payment methods do you accept?**
A: Credit card, wire transfer, purchase order. Annual or multi-year prepayment.

**Q: Can I get a perpetual license instead of subscription?**
A: Yes, perpetual licenses available at 5x annual price. Contact sales for details.

### Support Questions

**Q: What's included in Enterprise support?**
A: 24/7 phone + email support, 4-hour SLA for critical issues, priority patches, dedicated account manager.

**Q: Can Community users get paid support?**
A: Yes, we offer support contracts separately. Contact support@mmetech.com.

**Q: Do you offer training?**
A: Yes, on-site or remote training available. Included with Enterprise Subscription or available separately.

**Q: Can you help with implementation?**
A: Yes, professional services available. 40 hours included with Enterprise Subscription.

---

## Code Organization

### Directory Structure

```
AX-TrafficAnalyzer/
├── LICENSE # Dual license notice
├── LICENSE-COMMUNITY # MIT License
├── LICENSING_GUIDE.md # This file
├── NOTICES.md # Third-party attributions
├── src/
│ ├── community/ # MIT licensed (open source)
│ │ ├── core/ # Platform, validation
│ │ ├── hotspot/ # WiFi AP management
│ │ ├── capture/ # Traffic capture (mitmproxy, tcpdump)
│ │ ├── analysis/ # Basic protocol analyzers
│ │ ├── storage/ # Database, PCAP storage
│ │ ├── api/ # Core REST API
│ │ ├── ui/ # Basic web UI
│ │ ├── plugins/ # Plugin framework
│ │ └── integrations/ # Wireshark integration
```

### File Header Examples

**Community Edition file** (`src/community/core/platform.py`):
```python
"""
@fileoverview Platform detection and validation
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education
@version 1.0.0
@edition Community

This file is part of AX-TrafficAnalyzer Community Edition.
Licensed under MIT License. See LICENSE-COMMUNITY for details.
"""
```


---

## Contact

### Sales & Licensing
- **Email**: sales@mmetech.com
- **Phone**: [To be added]
- **Website**: [To be added]

### Technical Support
- **Community**: GitHub Issues (https://github.com/yourusername/AX-TrafficAnalyzer/issues)
- **Enterprise**: support@mmetech.com (login required)
- **Phone**: 24/7 for Enterprise customers

### General Inquiries
- **Email**: info@mmetech.com
- **Documentation**: https://docs.ax-traffic-analyzer.com

---

## Legal

**Copyright © 2025 MMeTech (Macau) Ltd.**
**Author**: AdamChe 谢毅翔, 字:吉祥
**Classification**: Enterprise Security Auditor and Education

**Community Edition**: Licensed under MIT License

For complete license terms, see:
- [LICENSE](LICENSE) - Dual licensing overview
- [LICENSE-COMMUNITY](LICENSE-COMMUNITY) - MIT License terms

---

**Last Updated**: November 18, 2025
**Version**: 1.0

