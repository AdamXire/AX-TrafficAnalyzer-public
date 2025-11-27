# AX-TrafficAnalyzer: Comprehensive Design Plan

**Copyright © 2025 MMeTech (Macau) Ltd.**
**Author**: AdamChe 谢毅翔, 字:吉祥
**Classification**: Enterprise Security Auditor and Education

**Version:** 1.0
**Date:** November 18, 2025
**Status:** Design Phase
**Target:** World-Class Mobile Application Traffic Analysis System

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Project Vision & Goals](#project-vision--goals)
3. [System Architecture](#system-architecture)
4. [Platform Support Strategy](#platform-support-strategy)
5. [Core Components](#core-components)
6. [Module Specifications](#module-specifications)
7. [Code Organization & Licensing](#code-organization--licensing)
8. [Implementation Phases](#implementation-phases)
9. [Technical Stack](#technical-stack)
10. [Security Architecture](#security-architecture)
11. [Performance Requirements](#performance-requirements)
12. [Testing Strategy](#testing-strategy)
13. [Deployment Strategy](#deployment-strategy)
14. [Monitoring & Observability](#monitoring--observability)
15. [Plugin System](#plugin-system)
16. [API Specification](#api-specification)
17. [User Interface Design](#user-interface-design)
18. [Data Flow](#data-flow)
19. [Error Handling & Recovery](#error-handling--recovery)
20. [Compliance & Legal](#compliance--legal)
21. [Future Roadmap](#future-roadmap)

---

## Executive Summary

### Overview
AX-TrafficAnalyzer is a professional-grade, open-source network traffic analysis platform designed specifically for mobile application security testing and debugging. It provides transparent HTTPS interception through an integrated WiFi hotspot with zero client-side configuration required.

### Key Differentiators
- **Zero Configuration**: Mobile devices connect to a normal WiFi hotspot - no proxy settings, no manual certificate installation
- **Transparent HTTPS MITM**: Automatic SSL/TLS interception with dynamic certificate generation
- **Integrated Workflow**: Single platform combining hotspot, capture, analysis, and visualization
- **Wireshark Integration**: Native PCAP export for deep protocol analysis
- **Extensible Architecture**: Plugin system for custom analysis and scanning
- **Production Ready**: Fail-fast design, comprehensive monitoring, automatic recovery

### Target Users
- Mobile application security researchers
- QA engineers testing mobile apps
- Network security professionals
- Penetration testers
- Mobile app developers debugging network issues

---

## Project Vision & Goals

### Primary Goals
1. **Best-in-class mobile traffic analysis** - Superior to existing solutions for mobile app testing
2. **Zero friction deployment** - One command installation, automatic configuration
3. **Professional reliability** - Production-grade error handling and monitoring
4. **Complete visibility** - Capture and decrypt all mobile app communications
5. **Extensible platform** - Plugin ecosystem for custom analysis needs

### Success Criteria
- ✅ Capture 100% of HTTP/HTTPS traffic from connected devices
- ✅ Decrypt HTTPS traffic without client configuration in >95% of cases
- ✅ Export valid PCAP files readable by Wireshark
- ✅ Support 50+ concurrent client connections
- ✅ Process 1000+ requests/second without packet loss
- ✅ Auto-recovery from failures within 5 seconds
- ✅ Comprehensive API with >99% uptime
- ✅ Plugin system supporting hot-reload

---

## System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│ AX-TrafficAnalyzer Platform │
├─────────────────────────────────────────────────────────────────────────┤
│ │
│ ┌────────────────────────────────────────────────────────────────┐ │
│ │ Network Layer │ │
│ │ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ │ │
│ │ │ WiFi │ │ Monitor │ │ GPS │ │ │
│ │ │ Hotspot │ │ 802.11 │ │ Tracker │ │ │
│ │ │ (hostapd) │ │ (airmon) │ │ (gpsd) │ │ │
│ │ └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ │ │
│ └─────────┼──────────────────┼──────────────────┼─────────────────┘ │
│ │ │ │ │
│ ┌─────────┴──────────────────┴──────────────────┴─────────────────┐ │
│ │ Capture Layer │ │
│ │ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ │ │
│ │ │ mitmproxy │ │ tcpdump │ │ tshark │ │ │
│ │ │ (HTTP/S) │ │ (raw UDP) │ │ (dissector) │ │ │
│ │ │ │ │ │ │ │ │ │
│ │ │ • Addons │ │ • Filtering │ │ • Custom │ │ │
│ │ │ • Certs │ │ • Rotation │ │ Protocols │ │ │
│ │ └──────┬──────┘ └──────┬──────┘ └──────┬──────┘ │ │
│ └─────────┼─────────────────┼─────────────────┼─────────────────────┘ │
│ │ │ │ │
│ ┌─────────┴─────────────────┴─────────────────┴─────────────────────┐ │
│ │ Processing Pipeline │ │
│ │ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │ │
│ │ │ Protocol │ │ Fuzzer │ │ Scanner │ │ Plugin │ │ │
│ │ │ Analyzer │ │ Engine │ │ Engine │ │ System │ │ │
│ │ │ │ │ │ │ │ │ │ │ │
│ │ │ • HTTP │ │ • Paylds │ │ • Passive│ │ • Custom │ │ │
│ │ │ • TLS │ │ • Mutate │ │ • Active │ │ • Addons │ │ │
│ │ │ • DNS │ │ • Replay │ │ • Rules │ │ • Hot-RL │ │ │
│ │ └──────┬───┘ └──────┬───┘ └──────┬───┘ └──────┬───┘ │ │
│ └─────────┼──────────────┼──────────────┼──────────────┼───────────────┘ │
│ │ │ │ │ │
│ ┌─────────┴──────────────┴──────────────┴──────────────┴───────────┐ │
│ │ Storage & Persistence Layer │ │
│ │ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │ │
│ │ │ PCAP │ │ SQLite │ │ JSON │ │ Time │ │ │
│ │ │ Storage │ │ DB │ │ Logs │ │ Series │ │ │
│ │ │ │ │ │ │ │ │ │ │ │
│ │ │ • Stream │ │ • Schema │ │ • Struct │ │ • Metrics│ │ │
│ │ │ • Valid │ │ • Index │ │ • Rotate │ │ • Events │ │ │
│ │ │ • Rotate │ │ • Migrate│ │ • Compress│ │ • Stats │ │ │
│ │ └──────┬───┘ └──────┬───┘ └──────┬───┘ └──────┬───┘ │ │
│ └─────────┼──────────────┼──────────────┼──────────────┼───────────────┘ │
│ │ │ │ │ │
│ ┌─────────┴──────────────┴──────────────┴──────────────┴───────────┐ │
│ │ API Layer │ │
│ │ ┌──────────────────┐ ┌──────────────────┐ │ │
│ │ │ REST API │ │ WebSocket │ │ │
│ │ │ (FastAPI) │ │ (Real-time) │ │ │
│ │ │ │ │ │ │ │
│ │ │ • OpenAPI Docs │ │ • Traffic Stream │ │ │
│ │ │ • Authentication │ │ • Events │ │ │
│ │ │ • Rate Limiting │ │ • Notifications │ │ │
│ │ │ • RBAC │ │ • Collaboration │ │ │
│ │ └──────────────────┘ └──────────────────┘ │ │
│ └───────────┬──────────────────────────────┬─────────────────────────┘ │
│ │ │ │
│ ┌───────────┴──────────────────────────────┴─────────────────────────┐ │
│ │ User Interface Layer │ │
│ │ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ │ │
│ │ │ Web UI │ │ Desktop │ │ CLI │ │ │
│ │ │ (React) │ │ (Electron) │ │ (Rich) │ │ │
│ │ │ │ │ │ │ │ │ │
│ │ │ • Dashboard │ │ • Native │ │ • Commands │ │ │
│ │ │ • Traffic │ │ • Offline │ │ • Scripts │ │ │
│ │ │ • Sessions │ │ • Export │ │ • Pipelines │ │ │
│ │ │ • Analysis │ │ • Reports │ │ • Automation│ │ │
│ │ └─────────────┘ └─────────────┘ └─────────────┘ │ │
│ └─────────────────────────────────────────────────────────────────────┘ │
│ │
│ ┌─────────────────────────────────────────────────────────────────────┐ │
│ │ External Integrations │ │
│ │ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │ │
│ │ │Wireshark │ │ Burp │ │ Threat │ │ Cloud │ │ │
│ │ │ │ │ Suite │ │ Intel │ │ Backup │ │ │
│ │ └──────────┘ └──────────┘ └──────────┘ └──────────┘ │ │
│ └─────────────────────────────────────────────────────────────────────┘ │
│ │
│ ┌─────────────────────────────────────────────────────────────────────┐ │
│ │ Monitoring & Observability │ │
│ │ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │ │
│ │ │Prometheus│ │ Grafana │ │ Sentry │ │ Alerts │ │ │
│ │ │ Metrics │ │ Dashbrd │ │ Errors │ │ Notifs │ │ │
│ │ └──────────┘ └──────────┘ └──────────┘ └──────────┘ │ │
│ └─────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

### Architecture Principles

1. **Fail-Fast Philosophy**: Validate ALL dependencies, configuration, and resources before ANY system modification
 - 16-step atomic startup sequence
 - Complete rollback on ANY failure
 - Exit with non-zero code and detailed error message

2. **Fail-Loud Errors**: ZERO silent failures; ALL errors reported with actionable solutions
 - Error messages include: what failed, why, exact solution steps, platform info
 - No generic errors - every failure has specific troubleshooting guidance
 - Errors logged to file AND displayed to user

3. **No Fallbacks for Core Dependencies**: Core features NEVER degrade silently
 - Missing core dependency → FAIL-FAST with installation instructions
 - Optional features enabled but missing → FAIL-FAST with clear error
 - Optional features disabled → Skip validation gracefully
 - Network issues for non-critical operations → FAIL-LOUD (queue + warn)
4. **Layered Architecture**: Clear separation between network, capture, processing, storage, and presentation
5. **Plugin Architecture**: Extensible processing pipeline for custom analysis
6. **Atomic Operations**: All system changes are reversible; state is always recoverable
7. **Observability First**: Comprehensive metrics, logging, and health checks built-in
8. **Security by Default**: Authentication, encryption, and access control enabled by default
9. **Concurrency Control**: Thread-safe operations with proper locking and transactions
10. **Resilience**: Network partition tolerance with fail-loud warnings, automatic recovery for non-critical failures

### Critical Design Requirements (World-Class Standards)

#### 1. Concurrency & Race Condition Prevention
- **All shared resources** protected with asyncio.Lock() or equivalent
- **Database transactions** use SERIALIZABLE isolation level
- **Message queue** (Redis) for event processing to prevent race conditions
- **Idempotent operations** using unique request IDs
- **Flow processing** serialized per session to prevent concurrent writes

#### 2. Certificate Security (HSM-Grade)
- **Private key encryption** at rest using system keyring (Linux: libsecret, WSL2: Windows DPAPI)
- **Key storage** in restricted directory with 0600 permissions
- **Key rotation** automatic yearly with 30-day grace period
- **External key store** support (HashiCorp Vault, AWS KMS, Azure Key Vault)
- **Compromised key** emergency revocation with certificate blacklist
- **Key backup** encrypted to secure location with recovery procedure

#### 3. Memory Management & Backpressure
- **Ring buffer** with fixed size for PCAP export (default: 10MB per session)
- **Backpressure signal** from PCAP writer to mitmproxy when buffer >80%
- **Circuit breaker** pauses capture if export fails 3 consecutive times
- **Memory watermarks**: warn at 80%, emergency cleanup at 95%
- **Per-session limits**: max 100MB buffered data, drop oldest if exceeded
- **Slow disk detection**: automatic buffer expansion or overflow to tmpfs

#### 4. Plugin Sandboxing & Security
- **Process isolation**: plugins run in separate process with ulimit restrictions
- **Seccomp filtering**: restrict syscalls (no network, no filesystem outside designated dirs)
- **Resource quotas**: CPU (10%), memory (256MB), disk I/O (10MB/s) per plugin
- **Signature verification**: GPG-signed plugins required in production mode
- **Permission model**: plugins declare required permissions (read_traffic, write_db, network_access)
- **Audit logging**: all plugin actions logged with timestamp and plugin ID
- **Automatic termination**: plugins exceeding quotas killed and restarted

#### 5. Database Migration Safety
- **Automatic backup** before any migration (stored in ./backups/)
- **Schema version** check on startup with fail-fast if mismatch detected
- **Dry-run mode**: migrations can be tested without applying
- **Rollback scripts**: every migration has automatic rollback
- **Zero-downtime**: read-replica support during migration for active captures
- **Validation**: post-migration data integrity checks
- **Fail-fast**: if migration fails, restore backup and exit

#### 6. Network Partition Resilience
- **Local DNS cache**: dnsmasq with 24h TTL for offline operation
- **Offline mode**: Core capture and analysis continue with FAIL-LOUD warnings
- **Retry queue**: Non-critical operations (cloud backup, threat intel) queued for retry (max 1000)
 * If queue full: FAIL-FAST with "Queue overflow" error for new items
- **Fail-fast for critical**: Database writes MUST succeed or fail-fast (no degradation)
- **Status indicator**: UI shows "⚠️ Offline Mode" banner with yellow alert
- **Automatic reconnect**: Retry internet connectivity every 60s, log each attempt
- **Explicit behavior**:
 * ✅ CONTINUE: Traffic capture, PCAP export, local analysis, web UI
 * ❌ FAIL-LOUD: Cloud backup (queued), threat intel (queued), license validation (cached)
 * ❌ FAIL-FAST: Database operations, configuration changes requiring validation

#### 7. Time Synchronization
- **NTP requirement**: fail-fast if system clock drift >1 second from NTP
- **Monotonic clock**: use CLOCK_MONOTONIC for all intervals and durations
- **Dual timestamps**: store both wall-clock time (for display) and monotonic time (for correlation)
- **Clock drift detection**: warn if drift >100ms, fail if >1s
- **Manual sync**: admin can trigger NTP sync from settings
- **Timezone handling**: all timestamps stored in UTC, converted for display

#### 8. IPv6 Support (Dual-Stack)
- **Dual-stack hotspot**: both IPv4 and IPv6 enabled by default
- **IPv6 iptables**: ip6tables rules parallel to iptables
- **DHCPv6**: dnsmasq configured for IPv6 address assignment
- **SLAAC support**: Router Advertisement for stateless autoconfiguration
- **IPv6 privacy**: support for RFC 4941 privacy extensions
- **Fail-fast**: if IPv6 enabled in config but kernel doesn't support, exit with error

#### 9. GDPR & Privacy Compliance
- **Automatic retention**: cron job deletes data older than configured period (default: 30 days)
- **Consent tracking**: first connection requires user consent (displayed via captive portal)
- **DSAR endpoint**: API for data subject access requests (export all data for a device)
- **Right to be forgotten**: API to delete all data for a specific device/MAC address
- **Data anonymization**: tool to replace IP addresses with cryptographic hashes
- **Audit log**: all data access logged with user ID and timestamp
- **Data minimization**: option to capture metadata only (no payload)

#### 10. Startup Orchestration (Atomic)
**Startup sequence** (all-or-nothing):
```
1. Platform detection → fail-fast if unsupported
2. Dependency validation → fail-fast if any missing
3. Configuration validation → fail-fast if invalid
4. Database initialization → fail-fast if schema mismatch
5. Certificate validation → fail-fast if expired/invalid
6. NTP sync check → fail-fast if clock drift >1s
7. Disk space check → fail-fast if <1GB available
8. Network interface check → fail-fast if WiFi adapter missing
9. Port availability → fail-fast if ports in use
10. Start database connection pool
11. Start WiFi hotspot → rollback all if fails
12. Start mitmproxy → rollback all if fails
13. Start API server → rollback all if fails
14. Start WebSocket server → rollback all if fails
15. Load and initialize plugins → rollback all if fails
16. Mark system as READY
```

**Rollback procedure**: If ANY step fails after step 10, execute shutdown in reverse order:
```
Failed at step 15 (plugins): Kill plugin processes, release resources
Failed at step 14 (WebSocket): Close all connections, stop server
Failed at step 13 (API server): Wait for in-flight requests (max 5s), stop server
Failed at step 12 (mitmproxy): Flush buffers to disk, stop proxy
Failed at step 11 (WiFi hotspot): Notify clients, stop hostapd/dnsmasq
Failed at step 10 (DB pool): Close all connections, rollback transactions

For ALL failures:
1. Remove all iptables rules (AX_TRAFFIC_ANALYZER chain)
2. Remove all ip6tables rules
3. Restore original network state
4. Clean up temp files
5. Release system resources (ports, interfaces)
6. Log detailed error with troubleshooting steps
7. Exit with non-zero code (exit code matches failed step number)
```

---

## Platform Support Strategy

### Supported Platforms

#### Primary: Native Linux
- **Distributions**: Ubuntu 20.04+, Debian 11+, Fedora 35+, Arch Linux
- **Kernel**: 5.4+ (for modern networking features)
- **Features**: Full feature set, optimal performance
- **Status**: Tier 1 support

#### Secondary: WSL2 (Windows Subsystem for Linux)
- **Requirements**: Windows 10 21H2+ or Windows 11, WSL2 enabled
- **Features**: Full feature set with WiFi adapter passthrough
- **Limitations**: Requires USB passthrough setup (usbipd-win)
- **Status**: Tier 1 support

#### Not Supported: Native Windows
- **Reason**: Lack of iptables, incompatible networking stack
- **Alternative**: Clear error message directing users to WSL2
- **Status**: Fail-fast with installation instructions

#### Future: Android (Experimental)
- **Requirements**: Rooted device, Termux, compatible WiFi adapter
- **Features**: Limited feature set
- **Status**: Future consideration (not in current scope)

### Platform Detection

```python
"""
@fileoverview Platform Detection Module
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Detects platform (Linux/WSL2/Windows) and system capabilities.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

class PlatformInfo:
 os: str # "Linux" or "Windows"
 is_wsl2: bool # True if WSL2
 is_native_linux: bool # True if native Linux
 is_native_windows: bool # True if native Windows (unsupported)
 wsl_distro: Optional[str] # WSL distribution name
 kernel_version: str # Kernel version
 architecture: str # x86_64, arm64, etc.
 distribution: str # Ubuntu, Debian, Fedora, etc.
 distribution_version: str # 22.04, 11, etc.
```

### Detection Logic

1. Check `platform.system()` → "Linux" or "Windows"
2. If Windows:
 - Check for `/proc/version` containing "microsoft" or "WSL"
 - Check for `/mnt/c/Windows` (Windows filesystem mount)
 - Check `$WSL_DISTRO_NAME` environment variable
 - If WSL2 → Continue with Linux path
 - If native Windows → **FAIL with WSL2 installation guide**
3. If Linux:
 - Detect distribution from `/etc/os-release`
 - Check kernel version
 - Validate kernel modules availability

---

## Core Components

### 1. Platform & Dependency Validation

**Module**: `src/core/platform/`
**License**: MIT License (Community Edition)
**Location**: `src/community/core/platform/`

**Responsibilities**:
- Detect operating system and environment
- Validate ALL dependencies before any system changes
- Provide actionable error messages for missing dependencies
- Check system capabilities (root access, WiFi adapter, disk space)

**Fail-Fast Checks**:
```python
# ALL must pass before proceeding (no exceptions)
1. Platform Detection
 - OS type and version
 - Python version (>= 3.11, < 3.13)
 - Kernel version (>= 5.4)
 - Distribution identification

2. System Tools Validation
 - hostapd (version >= 2.9)
 - dnsmasq (version >= 2.80)
 - iptables (version >= 1.8)
 - ip6tables (version >= 1.8)
 - tcpdump (version >= 4.9)
 - tshark (version >= 3.0)
 - ntpd OR chronyd (any recent version)
 - redis-server (version >= 6.0)
 - ip (iproute2)
 - systemctl (systemd)

3. Python Packages Validation
 - mitmproxy >= 10.0.0, < 11.0.0
 - fastapi >= 0.104.0, < 1.0.0
 - scapy >= 2.5.0, < 3.0.0
 - sqlalchemy >= 2.0.0, < 3.0.0
 - redis >= 4.5.0, < 5.0.0
 - All dependencies from requirements.txt with version bounds
 - Fail-fast if any package outside acceptable range
 - Warn if known security vulnerabilities exist

4. System Capabilities
 - Root/sudo access available
 - WiFi adapter exists
 - WiFi adapter supports AP mode
 - Kernel modules loaded (mac80211, cfg80211)
 - IP forwarding capability
 - Network namespaces available

5. Resource Availability
 - Disk space >= 1GB (FAIL if less)
 - Disk write speed >= 10MB/s (FAIL if slower, affects PCAP performance)
 - Memory >= 2GB (FAIL if less in production mode, WARN in dev mode)
 - CPU cores >= 2 (FAIL if less in production mode, WARN in dev mode)
 - Set mode via: --mode=production or --mode=dev (default: production)

6. Security Policies
 - SELinux:
 * If enforcing: Check for required permissions (network_admin, sys_admin)
 * If enforcing without policies: FAIL with policy installation guide
 * If permissive/disabled: WARN but continue
 - AppArmor:
 * If enabled: Check for ax-traffic profile or complain mode
 * If enabled without profile: FAIL with profile installation guide
 * If disabled: WARN but continue
 - Firewall rules don't conflict with required ports

7. Network State
 - No existing iptables rules in AX_TRAFFIC_ANALYZER chain
 - Configured ports available (8080, 8443, 9090)
 - No IP conflicts with hotspot range

8. Configuration Validation
 - config.json syntax valid
 - Schema validation passes
 - All paths exist and writable
 - WiFi channel is legal for region
 - Password meets WPA2 requirements
```

**Error Message Format**:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
❌ CRITICAL ERROR: Required dependency missing
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

COMPONENT: hostapd
VERSION REQ: >= 2.9
FOUND: Not installed
PLATFORM: Linux (Ubuntu 22.04 LTS)
REQUIRED FOR: WiFi hotspot creation

SOLUTION:
 Run the following commands:

 sudo apt-get update
 sudo apt-get install hostapd

 Then run AX-TrafficAnalyzer again.

DOCUMENTATION:
 https://docs.ax-traffic-analyzer.com/installation/dependencies

ALTERNATIVE:
 None - hostapd is a core dependency and cannot be substituted.

If you believe hostapd is installed but not detected:
 1. Check if it's in your PATH: which hostapd
 2. Set custom path in config: HOSTAPD_PATH=/path/to/hostapd
 3. Report this issue: https://github.com/ax/issues

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### 2. WiFi Hotspot Management

**Module**: `src/hotspot/`
**License**: MIT License (Community Edition)
**Location**: `src/community/hotspot/`

**Architecture**:
```
src/community/hotspot/
├── base.py # Abstract base class
├── linux.py # Linux implementation (hostapd + dnsmasq)
├── manager.py # Lifecycle management
├── monitor.py # Health monitoring
└── recovery.py # Auto-recovery on failure
```

**Features**:
- **hostapd** for WiFi access point
- **dnsmasq** for DHCP and DNS
- **systemd** service management (not subprocess)
- Automatic channel selection (scan for least crowded)
- Client connection tracking
- Bandwidth monitoring per client
- Automatic restart on failure
- Graceful shutdown with client notification

**Configuration**:
```json
{
 "hotspot": {
 "interface": "wlan0",
 "ssid": "AX-Traffic-Analyzer",
 "password": "SecurePassword123!",
 "channel": "auto",
 "frequency": "2.4GHz",
 "ip_range": "192.168.4.0/24",
 "gateway": "192.168.4.1",
 "dhcp_range": {
 "start": "192.168.4.10",
 "end": "192.168.4.250"
 },
 "dns": {
 "primary": "8.8.8.8",
 "secondary": "8.8.4.4"
 },
 "max_clients": 50,
 "hide_ssid": false,
 "encryption": "WPA2-PSK",
 "isolation": false
 }
}
```

**Process Management**:
```python
# Use systemd, not subprocess
systemd_service = """
[Unit]
Description=AX Traffic Analyzer Hotspot
After=network.target

[Service]
Type=forking
ExecStart=/usr/sbin/hostapd /etc/ax-traffic/hostapd.conf
ExecStop=/bin/kill -TERM $MAINPID
Restart=on-failure
RestartSec=5s
WatchdogSec=30s

[Install]
WantedBy=multi-user.target
"""
```

**Health Monitoring**:
- Process status check (every 5s)
- Client count monitoring
- Signal strength monitoring
- Automatic restart on crash
- Alert on suspicious client behavior

### 3. Traffic Capture Engine

**Module**: `src/capture/`
**License**: MIT License (Community Edition)
**Location**: `src/community/capture/`

**Architecture**:
```
src/community/capture/
├── mitm/
│ ├── proxy.py # mitmproxy integration
│ ├── addons.py # Custom mitmproxy addons
│ ├── cert_manager.py # Certificate management
│ └── pinning_detector.py # Detect certificate pinning
├── raw/
│ ├── tcpdump.py # tcpdump for UDP/non-HTTP
│ ├── airmon.py # 802.11 monitor mode
│ └── frame_capture.py # WiFi frame capture
├── pcap/
│ ├── exporter.py # Streaming PCAP export
│ ├── validator.py # PCAP file validation
│ └── manager.py # PCAP lifecycle
└── gps/
 ├── tracker.py # GPS integration (optional)
 └── location.py # Geolocation tagging
```

#### 3.1 mitmproxy Integration

**Transparent Mode Setup**:
```python
# iptables rules for transparent proxy
REDIRECT_RULES = [
 # Redirect HTTP to mitmproxy
 "iptables -t nat -A AX_TRAFFIC_PREROUTING -i wlan0 -p tcp --dport 80 -j REDIRECT --to-port 8080",

 # Redirect HTTPS to mitmproxy
 "iptables -t nat -A AX_TRAFFIC_PREROUTING -i wlan0 -p tcp --dport 443 -j REDIRECT --to-port 8080",
]
```

**Certificate Management**:
- Generate root CA certificate on first run
- Store in `./certs/ax-traffic-ca.pem`
- Generate per-domain certificates on-the-fly
- Automatic certificate rotation (yearly)
- Export certificate for client installation (QR code + download)

**Certificate Pinning Detection**:
```python
"""
@fileoverview Certificate Pinning Detector
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Detects certificate pinning in mobile applications.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

class PinningDetector(Addon):
 def tls_failed_client(self, data: TlsData):
 # Certificate validation failed
 self.log_pinning_detected(data)
 self.alert_user(data.context.client)
 # Continue without MITM for this connection
```

**Custom Addons**:
```python
"""
@fileoverview Traffic Logger Addon
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

mitmproxy addon for logging and processing traffic.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

class TrafficLogger(Addon):
 def request(self, flow: HTTPFlow):
 # Log request
 self.save_to_db(flow)
 self.emit_websocket_event(flow)
 self.run_plugins(flow)

 def response(self, flow: HTTPFlow):
 # Log response
 self.export_to_pcap(flow)
 self.analyze_response(flow)
```

#### 3.2 tcpdump Integration (UDP/Non-HTTP)

**Purpose**: Capture DNS, QUIC, UDP traffic not handled by mitmproxy

**Configuration**:
```python
tcpdump_config = {
 "enabled": True,
 "interface": "wlan0",
 "filters": "udp or icmp", # Exclude TCP (handled by mitmproxy)
 "output": "./captures/raw/udp_{timestamp}.pcap",
 "rotation": {
 "max_size_mb": 500,
 "max_duration_minutes": 60
 }
}
```

**File Rotation**:
```python
"""
@fileoverview TCPDump Manager
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Manages tcpdump process and file rotation.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

class TCPDumpManager:
 def rotate_if_needed(self):
 if self.current_file_size > self.max_size:
 self.rotate_file()
 if self.current_duration > self.max_duration:
 self.rotate_file()

 def rotate_file(self):
 # Send SIGHUP to tcpdump (graceful rotation)
 # Start new file
 # Compress old file
```

#### 3.3 PCAP Export

**Streaming Export** (not in-memory):
```python
"""
@fileoverview Streaming PCAP Exporter
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Streams HTTP flows to PCAP format with backpressure control.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

class StreamingPCAPExporter:
 def __init__(self, output_file: str):
 self.writer = libpcap.Writer(output_file)

 def export_flow(self, flow: HTTPFlow):
 # Convert HTTP flow to packets
 packets = self.reconstruct_tcp_stream(flow)

 # Write packets incrementally
 for packet in packets:
 self.writer.write_packet(packet)

 # Flush to disk (don't keep in memory)
 self.writer.flush()

 def reconstruct_tcp_stream(self, flow: HTTPFlow):
 # Build TCP/IP packets with correct:
 # - Sequence numbers
 # - Acknowledgments
 # - Checksums
 # - Timestamps
 return packets
```

**Performance**: Use `python-libpcap` instead of scapy (10x faster)

**Validation**:
```python
def validate_pcap(file_path: str) -> bool:
 # Open with tshark to verify validity
 result = subprocess.run(
 ["tshark", "-r", file_path, "-c", "1"],
 capture_output=True
 )
 return result.returncode == 0
```

### 4. Analysis & Processing

**Module**: `src/analysis/`
**License**: Mixed - MIT License (Community) + Proprietary (Enterprise)
**Locations**:
- Community: `src/community/analysis/` (protocol analyzers, passive scanning)
- Enterprise: `src/enterprise/analysis/` (active scanning, fuzzing, ML)

**Architecture** (Mixed - Community + Enterprise):

**Community Edition** (`src/community/analysis/`):
```
src/community/analysis/
├── protocol/
│ ├── http_analyzer.py # HTTP protocol analysis
│ ├── tls_analyzer.py # TLS/SSL analysis
│ ├── dns_analyzer.py # DNS analysis
│ └── custom_dissector.py # Custom protocol support
└── scanner/
 ├── passive.py # Passive vulnerability scanning
 └── rules_engine.py # Custom scanning rules (basic)
```

**Proprietary Edition** (`src/enterprise/analysis/`):
```
src/enterprise/analysis/
├── scanner/
│ ├── active.py # 🔒 Active vulnerability scanning
│ ├── advanced_rules.py # 🔒 Advanced scanning rules
│ └── exploit_validator.py # 🔒 Exploit validation
├── fuzzer/
│ ├── http_fuzzer.py # 🔒 HTTP request fuzzing
│ ├── mutation.py # 🔒 Advanced mutation strategies
│ └── payloads.py # 🔒 Fuzzing payload library
└── ml/
 ├── anomaly.py # 🔒 ML-based anomaly detection
 ├── classifier.py # 🔒 Traffic classification
 └── models/ # 🔒 Pre-trained ML models
```

#### 4.1 Protocol Analyzers

**HTTP Analyzer**:
```python
"""
@fileoverview HTTP Protocol Analyzer
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Analyzes HTTP requests and responses for security issues.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

class HTTPAnalyzer:
 def analyze(self, flow: HTTPFlow) -> HTTPAnalysisResult:
 return {
 "method": flow.request.method,
 "url": flow.request.pretty_url,
 "status_code": flow.response.status_code,
 "headers": self.analyze_headers(flow),
 "cookies": self.extract_cookies(flow),
 "auth": self.detect_auth_mechanism(flow),
 "sensitive_data": self.detect_sensitive_data(flow),
 "vulnerabilities": self.check_vulnerabilities(flow),
 "performance": self.measure_performance(flow),
 }

 def detect_sensitive_data(self, flow: HTTPFlow):
 # Detect:
 # - Passwords in cleartext
 # - API keys
 # - Credit card numbers
 # - Personal information
 # - OAuth tokens
 pass
```

**TLS Analyzer**:
```python
"""
@fileoverview TLS/SSL Analyzer
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Analyzes TLS connections for security vulnerabilities.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

class TLSAnalyzer:
 def analyze(self, connection: TLSConnection) -> TLSAnalysisResult:
 return {
 "version": connection.tls_version,
 "cipher_suite": connection.cipher_suite,
 "certificate_chain": self.analyze_certificates(connection),
 "vulnerabilities": self.check_tls_vulnerabilities(connection),
 "perfect_forward_secrecy": self.check_pfs(connection),
 "certificate_pinning": self.detect_pinning(connection),
 }
```

#### 4.2 Vulnerability Scanner

**Passive Scanning** (no active probing):
```python
"""
@fileoverview Passive Vulnerability Scanner
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Passively scans traffic for security vulnerabilities without active probing.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

class PassiveScanner:
 def scan(self, flow: HTTPFlow) -> List[Finding]:
 findings = []
 findings.extend(self.check_headers(flow))
 findings.extend(self.check_cookies(flow))
 findings.extend(self.check_content(flow))
 findings.extend(self.check_authentication(flow))
 return findings

 def check_headers(self, flow: HTTPFlow):
 # Check for:
 # - Missing security headers (CSP, HSTS, X-Frame-Options)
 # - Information disclosure (Server, X-Powered-By)
 # - Insecure cookies (no Secure, HttpOnly, SameSite)
 pass
```



### 5. Storage Layer

**Module**: `src/storage/`
**License**: MIT License (Community Edition)
**Location**: `src/community/storage/`

**Architecture**:
```
src/community/storage/
├── database.py # SQLite database
├── timeseries.py # Time-series metrics storage
├── pcap_store.py # PCAP file management
├── rotation.py # Log/PCAP rotation
└── cleanup.py # Automatic cleanup
```

**Database Schema**:
```sql
-- Sessions
CREATE TABLE sessions (
 id TEXT PRIMARY KEY,
 device_mac TEXT NOT NULL,
 device_ip TEXT NOT NULL,
 device_name TEXT,
 start_time TIMESTAMP NOT NULL,
 end_time TIMESTAMP,
 packets_count INTEGER DEFAULT 0,
 bytes_transferred INTEGER DEFAULT 0,
 pcap_file TEXT,
 INDEX idx_device_mac (device_mac),
 INDEX idx_start_time (start_time)
);

-- HTTP Flows
CREATE TABLE http_flows (
 id TEXT PRIMARY KEY,
 session_id TEXT NOT NULL,
 timestamp TIMESTAMP NOT NULL,
 method TEXT NOT NULL,
 url TEXT NOT NULL,
 status_code INTEGER,
 request_size INTEGER,
 response_size INTEGER,
 duration_ms INTEGER,
 request_headers JSON,
 response_headers JSON,
 vulnerability_findings JSON,
 FOREIGN KEY (session_id) REFERENCES sessions(id),
 INDEX idx_session_id (session_id),
 INDEX idx_timestamp (timestamp),
 INDEX idx_url (url)
);

-- PCAP Files
CREATE TABLE pcap_files (
 id TEXT PRIMARY KEY,
 file_path TEXT NOT NULL,
 file_type TEXT NOT NULL, -- 'raw' or 'decrypted'
 created_at TIMESTAMP NOT NULL,
 size_bytes INTEGER NOT NULL,
 packet_count INTEGER NOT NULL,
 start_time TIMESTAMP NOT NULL,
 end_time TIMESTAMP NOT NULL,
 device_macs JSON,
 INDEX idx_created_at (created_at),
 INDEX idx_file_type (file_type)
);

-- Devices
CREATE TABLE devices (
 mac_address TEXT PRIMARY KEY,
 first_seen TIMESTAMP NOT NULL,
 last_seen TIMESTAMP NOT NULL,
 ip_addresses JSON,
 hostnames JSON,
 manufacturer TEXT,
 device_type TEXT,
 total_bytes INTEGER DEFAULT 0,
 total_packets INTEGER DEFAULT 0
);

-- Findings (vulnerabilities, anomalies)
CREATE TABLE findings (
 id TEXT PRIMARY KEY,
 session_id TEXT NOT NULL,
 flow_id TEXT,
 timestamp TIMESTAMP NOT NULL,
 severity TEXT NOT NULL, -- 'critical', 'high', 'medium', 'low', 'info'
 category TEXT NOT NULL,
 title TEXT NOT NULL,
 description TEXT NOT NULL,
 recommendation TEXT,
 metadata JSON,
 FOREIGN KEY (session_id) REFERENCES sessions(id),
 INDEX idx_session_id (session_id),
 INDEX idx_severity (severity),
 INDEX idx_timestamp (timestamp)
);

-- Plugins Data
CREATE TABLE plugin_data (
 id TEXT PRIMARY KEY,
 plugin_name TEXT NOT NULL,
 session_id TEXT,
 timestamp TIMESTAMP NOT NULL,
 data JSON NOT NULL,
 INDEX idx_plugin_name (plugin_name),
 INDEX idx_session_id (session_id)
);
```

**Disk Space Management**:
```python
"""
@fileoverview Disk Space Manager
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Monitors disk space and performs automatic cleanup.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

class DiskSpaceManager:
 def monitor(self):
 # Check every minute
 while True:
 available = self.get_available_space()

 if available < CRITICAL_THRESHOLD: # 100MB
 self.emergency_shutdown()
 elif available < WARNING_THRESHOLD: # 500MB
 self.cleanup_old_files()
 self.warn_user()
 elif available < OPTIMAL_THRESHOLD: # 1GB
 self.compress_old_files()

 time.sleep(60)

 def cleanup_old_files(self):
 # Delete PCAPs older than retention period
 # Delete compressed logs
 # Delete processed sessions
 pass
```

**File Rotation**:
```python
"""
@fileoverview File Rotation Manager
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Manages PCAP file rotation and compression.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

class FileRotationManager:
 def rotate_pcap(self):
 # Rotate when:
 # - Size > max_size (500MB)
 # - Duration > max_duration (60 minutes)
 # - Manual trigger

 # Process:
 # 1. Close current file
 # 2. Start new file
 # 3. Compress old file (.pcap.gz)
 # 4. Update database
 pass
```

---

## Code Organization & Licensing

### Directory Structure

The codebase is physically separated into **Community Edition** (MIT License) and **Proprietary Edition** to maintain clear licensing boundaries and enable dual licensing distribution.

**Complete Project Structure**:
```
AX-TrafficAnalyzer/
├── LICENSE # Dual licensing overview
├── LICENSE-COMMUNITY # MIT License
├── LICENSING_GUIDE.md # Complete licensing guide
├── NOTICES.md # Third-party attributions
├── COPYRIGHT_TEMPLATE.md # File header templates
├── config/
│ └── config.json # Configuration
├── certs/ # Certificate storage
├── logs/ # Application logs
├── captures/ # PCAP files
├── src/
│ ├── community/ # MIT License (open source)
│ │ ├── core/ # Platform, config, validation
│ │ │ ├── platform/
│ │ │ ├── config/
│ │ │ └── dependencies/
│ │ ├── hotspot/ # WiFi AP management
│ │ │ ├── base.py
│ │ │ ├── linux.py
│ │ │ ├── manager.py
│ │ │ ├── monitor.py
│ │ │ └── recovery.py
│ │ ├── capture/ # Traffic capture
│ │ │ ├── mitm/
│ │ │ ├── raw/
│ │ │ ├── pcap/
│ │ │ └── gps/
│ │ ├── analysis/ # Basic analysis
│ │ │ ├── protocol/ # HTTP, TLS, DNS analyzers
│ │ │ └── scanner/ # Passive scanning only
│ │ ├── storage/ # Database, PCAP management
│ │ │ ├── database.py
│ │ │ ├── timeseries.py
│ │ │ └── pcap_store.py
│ │ ├── api/ # Core REST API
│ │ │ ├── routes/
│ │ │ ├── auth.py
│ │ │ └── websocket.py
│ │ ├── ui/ # Basic web dashboard
│ │ │ └── src/
│ │ │ ├── components/
│ │ │ └── pages/
│ │ └── plugins/ # Plugin framework
│ │ ├── base.py
│ │ └── manager.py
└── tests/
 ├── community/ # Tests for Community Edition
```

### File Naming Conventions

**Community Edition Files**:
- Standard Python naming: `module_name.py`
- Location: `src/community/[module]/`
- License header: MIT License (see COPYRIGHT_TEMPLATE.md)


### File Header Requirements

All source files **MUST** include appropriate copyright headers as specified in `COPYRIGHT_TEMPLATE.md`.

**Community Edition Example**:
```python
"""
@fileoverview HTTP Protocol Analyzer
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education
@version 1.0.0
@created 2025-11-18
@modified 2025-11-18

This file is part of AX-TrafficAnalyzer Community Edition.
Licensed under MIT License. See LICENSE-COMMUNITY for details.
"""
```


### Code Placement Decision Tree

When creating new code, use this decision tree to determine placement:

```
Is this feature in the licensing phasing plan as Enterprise?
│
└─ NO (Core features, passive analysis, basic UI, etc.)
 └─> Place in src/community/[appropriate-module]/
 License: MIT
 Distribution: Open source (GitHub)
```

### Feature-to-Edition Mapping

| Feature Category | Community (MIT) | Enterprise (Proprietary) |
|------------------|-----------------|--------------------------|
| **Platform & Core** | ✅ All | - |
| **WiFi Hotspot** | ✅ All | - |
| **Traffic Capture** | ✅ All (HTTP/HTTPS/UDP) | - |
| **PCAP Export** | ✅ All | - |
| **Protocol Analysis** | ✅ HTTP, TLS, DNS | - |
| **Vulnerability Scanning** | ✅ Passive only | 🔒 Active scanning |
| **HTTP Fuzzing** | ❌ None | 🔒 All fuzzing features |
| **ML/AI Analysis** | ❌ None | 🔒 Anomaly detection, classification |
| **Collaboration** | ❌ None | 🔒 Multi-user, real-time |
| **Multi-tenant** | ❌ None | 🔒 All multi-tenant features |
| **SSO/LDAP** | ❌ None | 🔒 All SSO features |
| **Compliance Reports** | ❌ None | 🔒 SOC2, ISO27001, GDPR, PCI-DSS |
| **Distributed Capture** | ❌ None | 🔒 Multi-node with consensus |
| **Hardware Acceleration** | ❌ None | 🔒 GPU, FPGA, DPDK |
| **Web Dashboard** | ✅ Basic UI | 🔒 Advanced features |
| **Desktop GUI** | ✅ All | ✅ All |
| **Mobile App** | ✅ Basic | 🔒 Advanced features |
| **Plugin System** | ✅ Framework | ✅ Framework |
| **API** | ✅ Core endpoints | 🔒 Enterprise endpoints |
| **Database** | ✅ All | ✅ All |
| **Authentication** | ✅ JWT | 🔒 SSO/LDAP |
| **RBAC** | ✅ Basic roles | 🔒 Advanced permissions |

### License Validation (Runtime)

**Community Edition**:
- No license key required
- All Community features available
- Source code accessible on GitHub
- Free for all uses (MIT License)


### Build & Distribution

**Community Edition**:
- **Build**: Standard Python package
- **Distribution**: GitHub releases, Docker Hub (public)
- **Installation**: `pip install ax-traffic-analyzer`
- **Source Code**: Available on GitHub
- **Updates**: GitHub releases, PyPI


### CI/CD Pipeline Separation

**Community Pipeline** (Public - GitHub Actions):
```yaml
- Build from src/community/
- Run community tests
- Check MIT license headers
- Publish to PyPI
- Push to Docker Hub (public)
- GitHub releases
```


---

## Implementation Phases

### Phase 0: Critical Infrastructure (Pre-Phase 1)
**License**: MIT License (Community Edition)
**Goal**: Critical infrastructure setup with fail-fast validation

**Deliverables**:
- ✅ Platform detection and validation
- ✅ Dependency management system
- ✅ Configuration framework
- ✅ Logging infrastructure
- ✅ Error handling framework

**Acceptance Criteria**:
- All critical dependencies validated
- Platform detection works correctly
- Configuration system operational
- Logging functional

---

### Phase 1: Foundation (Weeks 1-2)
**License**: MIT License (Community Edition)
**Goal**: Robust core infrastructure with fail-fast validation

**Deliverables**:
- ✅ Platform detection (Linux/WSL2/Windows)
- ✅ Comprehensive dependency validation
- ✅ Structured logging (structlog)
- ✅ Metrics export (Prometheus)
- ✅ Configuration management with JSON schema validation
- ✅ Basic WiFi hotspot (hostapd + dnsmasq)
- ✅ iptables management with automatic cleanup
- ✅ systemd service files
- ✅ Disk space monitoring
- ✅ Health check API endpoint

**Acceptance Criteria**:
- All dependency checks pass on clean Ubuntu 22.04
- Hotspot starts and accepts connections
- iptables rules are cleaned up on crash/exit
- Health check returns status in <100ms
- Disk space monitored every minute
- All errors include actionable solutions

### Phase 2: Traffic Capture (Weeks 3-4)
**License**: MIT License (Community Edition)
**Goal**: Complete traffic capture with HTTPS MITM and PCAP export

**Deliverables**:
- ✅ mitmproxy integration (transparent mode)
- ✅ Certificate generation and management
- ✅ Certificate pinning detection
- ✅ tcpdump integration (UDP/DNS traffic)
- ✅ Streaming PCAP export (python-libpcap)
- ✅ PCAP validation (tshark)
- ✅ Traffic logger (structured JSON)
- ✅ Session tracking
- ✅ Device identification (MAC/IP)
- ✅ Automatic file rotation

**Acceptance Criteria**:
- HTTPS traffic decrypted successfully
- PCAP files validated by Wireshark
- UDP/DNS traffic captured
- Certificate pinning detected and logged
- All traffic logged to database
- Files rotate automatically at size/time limits

### Phase 3: Storage & API (Weeks 5-6)
**License**: MIT License (Community Edition)
**Goal**: Persistent storage and comprehensive API

**Deliverables**:
- ✅ SQLite database with schema
- ✅ Database migrations (Alembic)
- ✅ Time-series metrics storage
- ✅ PCAP file metadata management
- ✅ REST API (FastAPI with OpenAPI docs)
- ✅ WebSocket server for real-time updates
- ✅ JWT authentication
- ✅ Role-based access control (RBAC)
- ✅ Rate limiting
- ✅ API documentation (auto-generated)

**Acceptance Criteria**:
- Database stores all traffic data
- API responds to all CRUD operations
- WebSocket streams real-time traffic
- Authentication required for all endpoints
- Rate limiting prevents abuse
- API documentation auto-generated

### Phase 4: Web UI (Weeks 7-8)
**License**: MIT License (Community Edition)
**Goal**: Professional web interface

**Deliverables**:
- ✅ React frontend (TypeScript + TailwindCSS)
- ✅ Dashboard with real-time metrics
- ✅ Traffic viewer (table with filtering)
- ✅ Session browser
- ✅ PCAP file manager (download, delete)
- ✅ Device list with statistics
- ✅ Charts and visualizations (Recharts)
- ✅ Search and filtering
- ✅ Export functionality (JSON, CSV, PCAP)
- ✅ Settings page

**Acceptance Criteria**:
- UI loads in <2 seconds
- Real-time updates via WebSocket
- Filter 10,000+ requests instantly
- Responsive design (mobile-friendly)
- Download PCAP files
- Dark mode support

### Phase 5: Analysis Features (Weeks 9-10)
**License**: MIT License (Community Edition)
**Goal**: Advanced traffic analysis

**Deliverables**:
- ✅ HTTP protocol analyzer
- ✅ TLS/SSL analyzer
- ✅ DNS analyzer
- ✅ Custom dissectors (tshark integration)
- ✅ Passive vulnerability scanner
- ✅ Active scanner engine
- ✅ Vulnerability rule engine
- ✅ Threat intelligence integration (VirusTotal, OTX)
- ✅ Traffic classification
- ✅ Report generation

**Acceptance Criteria**:
- Detects common vulnerabilities (OWASP Top 10)
- Integrates with threat intel APIs
- Generates PDF reports
- Custom rules supported
- Classification accuracy >90%

### Phase 6: Advanced Features (Weeks 11-12)
**License**: MIT License (Community Edition)
**Goal**: Extensibility and integrations

**Deliverables**:
- ✅ Plugin system architecture
- ✅ Plugin loader with hot-reload
- ✅ Request replay functionality
- ✅ HTTP fuzzer
- ✅ Mutation engine
- ✅ Wireshark integration helpers
- ✅ Burp Suite export format
- ✅ Cloud backup (S3/GCS)
- ✅ Automated tests (>80% coverage)
- ✅ Documentation (architecture, API, plugins)

**Acceptance Criteria**:
- Plugins load dynamically
- Request replay works correctly
- Fuzzer generates valid mutations
- Wireshark opens PCAPs with filters
- Tests pass on CI/CD
- Documentation complete

### Phase 7: Desktop & Mobile (Weeks 13-14) ✅ COMPLETE
**License**: Mixed - MIT License (Community) + Proprietary (Enterprise)
**Note**: This phase marks the beginning of dual licensing. See [Licensing Phasing Strategy](#licensing-phasing-strategy) for details.
**Status**: ✅ Complete (November 2025)

**Goal**: Desktop application, wireless security, and mobile monitoring

**Community Edition (MIT License)**:
- ✅ **Desktop GUI (Electron)** - Standalone app with bundled Python backend (PyInstaller)
 - Main process with fail-fast dependency checks
 - System tray integration with start/stop controls
 - Auto-update mechanism via electron-updater
 - IPC bridge for secure renderer communication
 - Native notifications for alerts
- ✅ **802.11 Monitor Mode** - Wireless security analysis
 - airmon-ng integration with fail-fast validation
 - WiFi frame capture (beacon, probe, data, deauth)
 - Frame analyzer with deauth attack detection
 - Rogue AP detection (evil twin identification)
 - WiFiFrameDB model with session tracking
- ✅ **GPS Tracking** - Location-tagged captures
 - gpsd integration with fail-fast validation
 - Background thread for continuous GPS polling
 - Location dataclass with altitude, speed, heading
 - GPS columns added to flows and sessions tables
 - Location tuple API for easy integration
- ✅ **Mobile App (React Native)** - Remote monitoring
 - Expo-based app for iOS/Android
 - Login screen with server URL configuration
 - Dashboard with real-time sessions and flows
 - Axios API client reusing web API
 - Zustand state management
 - SafeAreaProvider for proper layouts


**Implementation Details**:
- **Database**: 2 new migrations (WiFiFrameDB, GPS columns)
- **Tests**: 26 new tests, 482 community tests passing
- **Files**: 24 files created (desktop/, mobile/, wireless/, gps/)
- **Dependencies**: Electron 28, React Native 0.73, aircrack-ng, gpsd

**Acceptance Criteria**: ✅ ALL MET
- ✅ 802.11 frames captured and analyzed
- ✅ GPS coordinates tagged to traffic
- ✅ Desktop app bundles backend with PyInstaller
- ✅ Mobile app connects to API successfully
- ✅ Fail-fast validation for airmon-ng and gpsd
- ✅ All features disabled by default (non-breaking)
- ✅ No regressions in existing tests

### Phase 8: Production Ready (Weeks 15-16) ✅ COMPLETE
**License**: Mixed - MIT License (Community) + Proprietary (Enterprise)
**Note**: Dual licensing fully operational. See [Licensing Phasing Strategy](#licensing-phasing-strategy) for details.
**Status**: ✅ Complete (November 2025)

**Goal**: Production deployment readiness

**Community Edition (MIT License)**:
- ✅ **Docker Containerization** - Production-ready deployment
 - Multi-stage Dockerfile with fail-fast validation
 - docker-compose.yml for development
 - docker-compose.prod.yml with Prometheus + Grafana
 - Entrypoint script with dependency checking
 - Health checks and auto-restart
- ✅ **Load Testing** - Performance validation
 - Locust load test scenarios
 - API endpoint testing (health, sessions, flows, findings)
 - Target: 1000 req/s, <100ms p95 latency
 - run-load-test.sh automation script
- ✅ **Security Hardening** - Vulnerability management
 - security-scan.sh with pip-audit, Bandit, secret detection
 - GitHub Actions security workflow
 - SECURITY.md policy with response timelines
 - Automated scanning on push/PR/schedule
- ✅ **Kubernetes Deployment** - Scalable orchestration
 - Complete K8s manifests (deployment, service, configmap, pvc, rbac)
 - Privileged mode with hostNetwork for hotspot
 - Kustomize support for customization
 - Health/readiness/startup probes
- ✅ **Documentation** - Comprehensive guides
 - installation.md (Docker, manual, K8s)
 - troubleshooting.md (common issues + solutions)
 - Fail-fast error messages with solutions
- ✅ **Ansible Automation** - Infrastructure as Code
 - Complete playbook with 3 roles (common, ax-traffic, monitoring)
 - Inventory templates for production/staging
 - Fail-fast validation in playbook
 - Automated provisioning from git clone to running service


**Implementation Details**:
- **Docker**: 5 files (Dockerfile, 2 compose files, entrypoint, prometheus config)
- **Load Tests**: Locust with 10 task types, rapid testing mode
- **Security**: 3 scanning tools, GitHub Actions workflow, security policy
- **Kubernetes**: 7 manifest files, Kustomize support
- **Documentation**: 2 comprehensive guides with fail-fast focus
- **Ansible**: 1 playbook, 3 roles, inventory templates
- **Tests**: All 482 community tests passing

**Acceptance Criteria**: ✅ ALL MET
- ✅ Docker: One-command deployment (`docker-compose up -d`)
- ✅ Load test: Locust framework targeting 1000 req/s
- ✅ Security: Automated scanning with fail-fast on critical issues
- ✅ K8s: Complete manifests with proper RBAC and health checks
- ✅ Documentation: Installation and troubleshooting guides complete
- ✅ Ansible: Automated provisioning with fail-fast validation
- ✅ No breaking changes (482 tests passing)
- ✅ All features maintain fail-fast/fail-loud principles

---

## Technical Stack

### Backend

#### Core
- **Python 3.11+** - Main programming language
- **FastAPI** - Web framework for REST API
- **Uvicorn** - ASGI server
- **Pydantic** - Data validation
- **SQLAlchemy** - ORM
- **Alembic** - Database migrations

#### Network & Capture
- **mitmproxy** - HTTPS MITM proxy
- **scapy** - Packet manipulation
- **python-libpcap** - Fast PCAP writing
- **dpkt** - Fast packet parsing
- **pyroute2** - Network interface management
- **netifaces** - Network interface info
- **psutil** - System monitoring
- **redis** - Message queue for event processing
- **redis-py** - Redis client for Python

#### Monitoring & Logging
- **structlog** - Structured logging
- **prometheus-client** - Metrics export
- **sentry-sdk** - Error tracking

#### Security
- **cryptography** - Certificate management
- **python-jose** - JWT handling
- **passlib** - Password hashing
- **bcrypt** - Password encryption
- **keyring** - Secure key storage (system keyring integration)
- **hvac** - HashiCorp Vault client (optional, for external key store)

#### Analysis
- **scikit-learn** - ML models
- **numpy** - Numerical computing
- **pandas** - Data analysis

### Frontend

#### Core
- **React 18** - UI library
- **TypeScript** - Type safety
- **Vite** - Build tool
- **TailwindCSS** - Styling

#### UI Components
- **Shadcn/ui** - Component library
- **Lucide React** - Icons
- **Recharts** - Data visualization
- **React Query** - Data fetching
- **Zustand** - State management
- **React Router** - Routing

### System Tools

#### Required
- **hostapd** - WiFi AP daemon
- **dnsmasq** - DHCP/DNS server
- **iptables** - IPv4 packet filtering
- **ip6tables** - IPv6 packet filtering
- **tcpdump** - Packet capture
- **tshark** - Protocol dissection
- **systemd** - Service management
- **ntp** or **chrony** - Network time synchronization
- **redis-server** - Message queue backend
- **libsecret** (Linux) or **DPAPI** (WSL2) - Secure credential storage

#### Optional (Feature-Dependent)
**These are ONLY required if the corresponding feature is enabled in config.json:**

- **airmon-ng** - 802.11 monitor mode
 * Only if `config.capture.monitor_mode.enabled == true`
 * If enabled but airmon-ng not installed: FAIL-FAST
 * If disabled: Skip validation

- **gpsd** - GPS daemon for location tagging
 * Only if `config.gps.enabled == true`
 * If enabled but gpsd not running: FAIL-FAST
 * If disabled: Skip validation

- **nginx** - Reverse proxy for production deployment
 * Only if `config.deployment.reverse_proxy.enabled == true`
 * If enabled but nginx not installed: FAIL-FAST
 * If disabled: Direct access to FastAPI

**Fail-Fast Rule**: If feature enabled in config but dependency missing → FAIL-FAST with error

### Infrastructure

#### Deployment
- **Docker** - Containerization
- **Docker Compose** - Multi-container orchestration
- **Kubernetes** - Container orchestration
- **Ansible** - Configuration management

#### CI/CD
- **GitHub Actions** - CI/CD pipeline
- **pytest** - Testing framework
- **black** - Code formatting
- **ruff** - Linting
- **mypy** - Type checking

---

## Security Architecture

### Authentication

**JWT-based Authentication**:
```python
# Login flow
1. User provides username/password
2. Validate credentials
3. Generate JWT token (expires in 24h)
4. Return token to client
5. Client includes token in Authorization header

# Token structure
{
 "sub": "user_id",
 "role": "admin",
 "exp": 1700000000,
 "iat": 1699913600
}
```

**Role-Based Access Control**:
```python
Roles:
- admin: Full access
- analyst: Read + analyze
- viewer: Read-only

Permissions:
- sessions:read
- sessions:write
- sessions:delete
- pcaps:read
- pcaps:download
- pcaps:delete
- settings:read
- settings:write
- scanner:use
- fuzzer:use
```

### Certificate Management

**Root CA Certificate**:
- Generated on first run
- Stored in `./certs/ax-traffic-ca.pem`
- Private key encrypted with system key
- Automatic rotation (yearly)
- Backup to secure location

**Dynamic Certificates**:
- Generated per-domain on-the-fly
- Cached for performance
- Signed by root CA
- Valid for 1 year
- Cleaned up after expiry

**Client Installation**:
- QR code generation for mobile devices
- Download link with instructions
- Automatic detection of successful installation

### Data Protection

**Sensitive Data**:
- Passwords hashed with bcrypt (cost factor 12)
- API keys encrypted with Fernet
- PCAP files contain unencrypted traffic (warn user prominently)
- Database encrypted at rest:
 * **Production mode**: REQUIRED (fail-fast if encryption not configured)
 * **Dev mode**: Optional (warn if not encrypted)
 * Enable via: `config.database.encryption.enabled = true`

**Access Control**:
- Authentication required for all API endpoints
- Rate limiting (100 req/min per IP)
- HTTPS only for web UI
- CORS configured properly

### Network Security

**Firewall Rules**:
```bash
# Only allow necessary ports
iptables -A INPUT -p tcp --dport 8443 -j ACCEPT # Web UI
iptables -A INPUT -p tcp --dport 9090 -j ACCEPT # Metrics
iptables -A INPUT -p udp --dport 53 -j ACCEPT # DNS
iptables -A INPUT -p udp --dport 67 -j ACCEPT # DHCP
```

**Network Isolation**:
- Hotspot clients isolated from each other:
 * **Production mode**: REQUIRED (client isolation enforced)
 * **Dev mode**: Optional (configurable via `config.hotspot.client_isolation`)
- Management interface on separate network (REQUIRED in production)
- No direct internet access without proxy (enforced)

---

## Performance Requirements

### Throughput
- **Target**: 1000 HTTP requests/second
- **Concurrent Connections**: 50+ clients
- **Bandwidth**: 100 Mbps sustained
- **Packet Loss**: <0.1%

### Latency
- **API Response Time**: <100ms (p95)
- **WebSocket Latency**: <50ms
- **PCAP Export**: <1s for 1000 requests
- **Database Queries**: <10ms (indexed)

### Resource Usage
- **CPU**: <50% on 4-core system
- **Memory**: <2GB RAM
- **Disk I/O**: <100 MB/s write
- **Network I/O**: <200 Mbps

### Scalability
- **Sessions**: 10,000+ concurrent sessions
- **Traffic**: 1TB+ of captured data
- **Database**: 10M+ records
- **PCAP Files**: 10,000+ files

---

## Testing Strategy

### Unit Tests
- **Coverage**: >80%
- **Framework**: pytest
- **Mocking**: pytest-mock
- **Fixtures**: Reusable test data

### Integration Tests
- **Network Stack**: Mock WiFi adapter
- **Database**: SQLite in-memory
- **API**: TestClient from FastAPI
- **End-to-End**: Real hotspot (CI environment)

### Performance Tests
- **Load Testing**: Locust (1000 req/s)
- **Stress Testing**: Find breaking point
- **Endurance Testing**: 24h continuous operation
- **Spike Testing**: Sudden traffic bursts

### Security Tests
- **Dependency Scanning**: Safety, Snyk
- **SAST**: Bandit, Semgrep
- **DAST**: OWASP ZAP
- **Penetration Testing**: Manual testing

### Test Automation
```yaml
# GitHub Actions
on: [push, pull_request]

jobs:
 test:
 runs-on: ubuntu-latest
 steps:
 - uses: actions/checkout@v3
 - name: Run tests
 run: |
 pytest tests/ --cov=src --cov-report=xml
 - name: Upload coverage
 uses: codecov/codecov-action@v3
```

---

## Deployment Strategy

### Docker Deployment

**Dockerfile**:
```dockerfile
FROM ubuntu:22.04

# Install system dependencies
RUN apt-get update && apt-get install -y \
 hostapd dnsmasq iptables tcpdump tshark \
 python3.11 python3-pip

# Install Python dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy application
COPY src/ /app/src/
COPY config/ /app/config/

# Expose ports
EXPOSE 8443 9090

# Run as root (required for network operations)
USER root

CMD ["python3", "-m", "src.main"]
```

**Docker Compose**:
```yaml
version: '3.8'

services:
 ax-traffic:
 build: .
 container_name: ax-traffic-analyzer
 network_mode: host
 privileged: true
 cap_add:
 - NET_ADMIN
 - NET_RAW
 volumes:
 - ./config:/app/config
 - ./certs:/app/certs
 - ./logs:/app/logs
 - ./captures:/app/captures
 environment:
 - AX_ENV=production
 restart: unless-stopped

 prometheus:
 image: prom/prometheus
 volumes:
 - ./prometheus.yml:/etc/prometheus/prometheus.yml
 ports:
 - "9090:9090"

 grafana:
 image: grafana/grafana
 ports:
 - "3000:3000"
 environment:
 - GF_SECURITY_ADMIN_PASSWORD=admin
```

### Kubernetes Deployment

**Deployment Manifest**:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
 name: ax-traffic-analyzer
spec:
 replicas: 1
 selector:
 matchLabels:
 app: ax-traffic-analyzer
 template:
 metadata:
 labels:
 app: ax-traffic-analyzer
 spec:
 hostNetwork: true
 containers:
 - name: ax-traffic
 image: ax-traffic-analyzer:latest
 securityContext:
 privileged: true
 capabilities:
 add:
 - NET_ADMIN
 - NET_RAW
 volumeMounts:
 - name: config
 mountPath: /app/config
 - name: captures
 mountPath: /app/captures
 volumes:
 - name: config
 configMap:
 name: ax-traffic-config
 - name: captures
 persistentVolumeClaim:
 claimName: ax-traffic-captures
```

### Ansible Playbook

```yaml
---
- name: Deploy AX-TrafficAnalyzer
 hosts: traffic_analyzers
 become: yes

 tasks:
 - name: Install system dependencies
 apt:
 name:
 - hostapd
 - dnsmasq
 - iptables
 - tcpdump
 - tshark
 - python3.11
 - python3-pip
 state: present
 update_cache: yes

 - name: Install Python dependencies
 pip:
 requirements: /opt/ax-traffic/requirements.txt
 executable: pip3

 - name: Copy application files
 synchronize:
 src: ./src/
 dest: /opt/ax-traffic/src/

 - name: Copy systemd service
 copy:
 src: ./deployment/systemd/ax-traffic.service
 dest: /etc/systemd/system/

 - name: Start service
 systemd:
 name: ax-traffic
 state: started
 enabled: yes
 daemon_reload: yes
```

---

## Monitoring & Observability

### Metrics (Prometheus)

**Exported Metrics**:
```python
# System metrics
ax_traffic_uptime_seconds
ax_traffic_connected_clients
ax_traffic_total_bytes_transferred
ax_traffic_total_packets_captured

# Capture metrics
ax_traffic_pcap_files_total
ax_traffic_pcap_size_bytes
ax_traffic_sessions_active
ax_traffic_sessions_total

# Performance metrics
ax_traffic_request_duration_seconds
ax_traffic_request_rate
ax_traffic_pcap_export_duration_seconds

# Error metrics
ax_traffic_errors_total
ax_traffic_certificate_pinning_detected
ax_traffic_mitm_failures_total

# Resource metrics
ax_traffic_disk_space_available_bytes
ax_traffic_memory_usage_bytes
ax_traffic_cpu_usage_percent
```

### Logging

**Structured Logging**:
```python
import structlog

log = structlog.get_logger()

log.info(
 "client_connected",
 mac_address="aa:bb:cc:dd:ee:ff",
 ip_address="192.168.4.100",
 hostname="iPhone-12",
)

log.warning(
 "certificate_pinning_detected",
 domain="api.example.com",
 client="192.168.4.100",
)

log.error(
 "pcap_export_failed",
 session_id="abc123",
 error="Disk full",
 disk_space_available="10MB",
)
```

### Health Checks

**API Endpoint**: `GET /api/health`

```json
{
 "status": "healthy",
 "version": "1.0.0",
 "uptime_seconds": 86400,
 "components": {
 "hotspot": {
 "status": "healthy",
 "clients_connected": 5
 },
 "mitmproxy": {
 "status": "healthy",
 "active_connections": 12
 },
 "database": {
 "status": "healthy",
 "connections": 5
 },
 "disk_space": {
 "status": "warning",
 "available_gb": 0.8,
 "threshold_gb": 1.0
 }
 }
}
```

### Alerting

**Alert Rules**:
```yaml
groups:
 - name: ax_traffic_alerts
 rules:
 - alert: HighErrorRate
 expr: rate(ax_traffic_errors_total[5m]) > 0.1
 for: 5m
 annotations:
 summary: "High error rate detected"

 - alert: DiskSpaceLow
 expr: ax_traffic_disk_space_available_bytes < 1e9
 for: 1m
 annotations:
 summary: "Disk space critically low"

 - alert: HotspotDown
 expr: ax_traffic_connected_clients == 0
 for: 10m
 annotations:
 summary: "No clients connected to hotspot"
```

---

## Plugin System

### Plugin Architecture

**Base Plugin Class**:
```python
"""
@fileoverview Base Plugin Class
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

This file is part of AX-TrafficAnalyzer Community Edition.
Licensed under MIT License. See LICENSE-COMMUNITY for details.
"""

from abc import ABC, abstractmethod

class Plugin(ABC):
 """Base class for all plugins"""

 name: str
 version: str
 author: str
 description: str

 @abstractmethod
 def on_load(self):
 """Called when plugin is loaded"""
 pass

 @abstractmethod
 def on_request(self, flow: HTTPFlow) -> None:
 """Called for each HTTP request"""
 pass

 @abstractmethod
 def on_response(self, flow: HTTPFlow) -> None:
 """Called for each HTTP response"""
 pass

 @abstractmethod
 def analyze(self, data: bytes) -> AnalysisResult:
 """Custom analysis logic"""
 pass

 @abstractmethod
 def on_unload(self):
 """Called when plugin is unloaded"""
 pass
```

### Plugin Example

```python
"""
@fileoverview Threat Intelligence Plugin Example
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Example plugin for threat intelligence integration.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

class ThreatIntelPlugin(Plugin):
 name = "threat_intel"
 version = "1.0.0"
 author = "AdamChe 谢毅翔, 字:吉祥"
 publisher = "MMeTech (Macau) Ltd."
 description = "Integrates with threat intelligence feeds"

 def on_load(self):
 self.virustotal = VirusTotalAPI(api_key=self.config['api_key'])
 self.cache = {}

 def on_request(self, flow: HTTPFlow):
 domain = flow.request.host

 # Check cache
 if domain in self.cache:
 return

 # Query VirusTotal
 result = self.virustotal.check_domain(domain)

 if result.malicious:
 self.alert(
 severity="high",
 title="Malicious domain detected",
 domain=domain,
 score=result.score,
 )

 self.cache[domain] = result

 def on_response(self, flow: HTTPFlow):
 pass

 def analyze(self, data: bytes) -> AnalysisResult:
 # Custom analysis logic
 return AnalysisResult()

 def on_unload(self):
 self.cache.clear()
```

### Plugin Manager

```python
"""
@fileoverview Plugin Manager
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Manages plugin lifecycle: loading, reloading, and triggering.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

class PluginManager:
 def __init__(self, plugin_dir: str):
 self.plugin_dir = plugin_dir
 self.plugins = {}

 def load_all(self):
 """Load all plugins from plugin directory"""
 for file in os.listdir(self.plugin_dir):
 if file.endswith('.py'):
 self.load_plugin(file)

 def load_plugin(self, filename: str):
 """Load a single plugin"""
 # Dynamic import
 module = importlib.import_module(f"plugins.{filename[:-3]}")

 # Find Plugin class
 for name, obj in inspect.getmembers(module):
 if inspect.isclass(obj) and issubclass(obj, Plugin):
 plugin = obj()
 plugin.on_load()
 self.plugins[plugin.name] = plugin
 log.info(f"Loaded plugin: {plugin.name}")

 def reload_plugin(self, plugin_name: str):
 """Hot-reload a plugin"""
 if plugin_name in self.plugins:
 self.plugins[plugin_name].on_unload()
 del self.plugins[plugin_name]

 self.load_plugin(f"{plugin_name}.py")

 def trigger_on_request(self, flow: HTTPFlow):
 """Trigger on_request for all plugins"""
 for plugin in self.plugins.values():
 try:
 plugin.on_request(flow)
 except Exception as e:
 log.error(f"Plugin {plugin.name} error: {e}")
```

### Plugin Licensing Guidelines

The plugin system is part of the Community Edition (MIT License), but plugins themselves can be licensed under any compatible license.

**Plugin License Options**:

1. **Open Source Plugins** (MIT, Apache 2.0, BSD)
 - Can be freely distributed
 - Source code available
 - Can be included in Community Edition
 - No licensing fees

2. **Proprietary Plugins**
 - Created by AdamChe or third parties
 - May require separate license
 - Can be distributed as binaries
 - May have usage fees

 - Examples: ML models, advanced scanners, compliance modules

**Plugin Metadata**:
```python
class MyPlugin(Plugin):
 name = "my_plugin"
 version = "1.0.0"
 author = "AdamChe 谢毅翔, 字:吉祥" # or "Third Party Developer"
 publisher = "MMeTech (Macau) Ltd." # or "Third Party Company"
 license = "MIT" # or "Proprietary" or "Apache-2.0"
 requires_license = False # True for Enterprise plugins
 description = "Plugin description"
```

**Plugin Distribution**:

**Community Plugins** (MIT License):
- Location: `plugins/community/`
- Distribution: GitHub, PyPI
- Installation: `ax-traffic plugin install my_plugin`
- Cost: Free

**Enterprise Plugins** (Proprietary):
- Location: `plugins/enterprise/`
- Distribution: Private registry (Enterprise customers only)
- Installation: `ax-traffic plugin install my_plugin --enterprise`
- Cost: Included with Enterprise license or separate fee

**Third-Party Plugins**:
- Location: User's choice
- Distribution: Plugin author's choice
- Installation: Manual or via plugin marketplace
- Cost: Plugin author's choice

**Plugin Development Guidelines**:
- Community plugins: Must not depend on Enterprise features
- Enterprise plugins: Can use all features
- All plugins: Must declare dependencies and license
- Security: All plugins run in sandboxed environment (see Critical Design Requirements #4)

---

## API Specification

### REST API Endpoints

**Base URL**: `https://localhost:8443/api/v1`

All endpoints require JWT authentication (except `/auth/login`).

#### Authentication (Community - MIT)
- `POST /auth/login` - Login and get JWT token
- `POST /auth/logout` - Logout
- `POST /auth/refresh` - Refresh token
- `POST /auth/sso/login` - SSO login 🔒 **Enterprise**

#### Sessions (Community - MIT)
- `GET /sessions` - List all sessions
- `GET /sessions/{id}` - Get session details
- `DELETE /sessions/{id}` - Delete session
- `GET /sessions/{id}/flows` - Get HTTP flows for session
- `GET /sessions/{id}/pcap` - Get PCAP for session
- `GET /sessions/{id}/export` - Export session report 🔒 **Enterprise**

#### Traffic (Community - MIT)
- `GET /flows` - List all HTTP flows
- `GET /flows/{id}` - Get flow details
- `POST /flows/{id}/replay` - Replay request (basic)
- `POST /flows/{id}/replay/advanced` - Advanced replay with modifications 🔒 **Enterprise**

#### PCAP Files (Community - MIT)
- `GET /pcaps` - List all PCAP files
- `GET /pcaps/{id}` - Get PCAP metadata
- `GET /pcaps/{id}/download` - Download PCAP file
- `DELETE /pcaps/{id}` - Delete PCAP file

#### Devices (Community - MIT)
- `GET /devices` - List all devices
- `GET /devices/{mac}` - Get device details
- `DELETE /devices/{mac}/data` - Delete device data (GDPR)

#### Scanner (Mixed)
- `POST /scanner/passive` - Start passive scan **Community**
- `POST /scanner/active` - Start active scan 🔒 **Enterprise**
- `GET /scanner/findings` - Get scan findings **Community**
- `GET /scanner/findings/{id}` - Get finding details **Community**
- `POST /scanner/rules` - Add custom rules 🔒 **Enterprise**

#### Fuzzer (Enterprise Only) 🔒
- `POST /fuzzer/start` - Start fuzzing session 🔒 **Enterprise**
- `GET /fuzzer/results` - Get fuzzing results 🔒 **Enterprise**
- `POST /fuzzer/mutations` - Configure mutations 🔒 **Enterprise**

#### ML/AI (Enterprise Only) 🔒
- `POST /ml/anomaly/detect` - Run anomaly detection 🔒 **Enterprise**
- `GET /ml/models` - List available models 🔒 **Enterprise**
- `POST /ml/models/train` - Train custom model 🔒 **Enterprise**

#### Compliance (Enterprise Only) 🔒
- `GET /compliance/soc2/report` - Generate SOC2 report 🔒 **Enterprise**
- `GET /compliance/iso27001/report` - Generate ISO27001 report 🔒 **Enterprise**
- `GET /compliance/gdpr/report` - Generate GDPR report 🔒 **Enterprise**
- `GET /compliance/pci-dss/report` - Generate PCI-DSS report 🔒 **Enterprise**

#### Multi-tenant (Enterprise Only) 🔒
- `GET /tenants` - List tenants 🔒 **Enterprise**
- `POST /tenants` - Create tenant 🔒 **Enterprise**
- `GET /tenants/{id}` - Get tenant details 🔒 **Enterprise**

#### Collaboration (Enterprise Only) 🔒
- `POST /collaboration/sessions` - Start collaboration session 🔒 **Enterprise**
- `GET /collaboration/users` - List active users 🔒 **Enterprise**

#### Plugins (Community - MIT)
- `GET /plugins` - List all plugins
- `POST /plugins/{name}/reload` - Reload plugin
- `GET /plugins/{name}/status` - Get plugin status
- `POST /plugins/upload` - Upload plugin 🔒 **Enterprise**

#### Settings (Community - MIT)
- `GET /settings` - Get current settings
- `PUT /settings` - Update settings
- `GET /settings/license` - Get license information 🔒 **Enterprise**

#### Health & Metrics (Community - MIT)
- `GET /health` - Health check
- `GET /metrics` - Prometheus metrics
- `GET /status` - System status

### WebSocket API

**Endpoint**: `wss://localhost:8443/api/v1/ws`

**Events**:
```json
// Client connected
{
 "event": "client_connected",
 "data": {
 "mac": "aa:bb:cc:dd:ee:ff",
 "ip": "192.168.4.100",
 "hostname": "iPhone-12"
 }
}

// New HTTP flow
{
 "event": "http_flow",
 "data": {
 "id": "abc123",
 "method": "GET",
 "url": "https://api.example.com/users",
 "status_code": 200
 }
}

// Finding detected
{
 "event": "finding",
 "data": {
 "severity": "high",
 "title": "SQL Injection vulnerability",
 "url": "https://vulnerable.com/api"
 }
}
```

---

## User Interface Design

### Web UI Pages

1. **Dashboard**
 - Real-time metrics (clients, requests, bandwidth)
 - Recent activity
 - Quick actions

2. **Traffic Viewer**
 - Table of all HTTP flows
 - Filtering and search
 - Request/response details
 - Replay button

3. **Sessions**
 - List of all sessions
 - Device information
 - Session statistics
 - Link to PCAP

4. **Devices**
 - List of connected devices
 - Device fingerprinting
 - Traffic statistics per device

5. **PCAP Files**
 - List of all PCAP files
 - Download button
 - Delete button
 - Wireshark integration

6. **Findings**
 - Vulnerability scan results
 - Severity filtering
 - Details and recommendations

7. **Plugins**
 - List of installed plugins
 - Enable/disable
 - Configure
 - Reload

8. **Settings**
 - Hotspot configuration
 - Capture settings
 - API settings
 - User management

### Desktop GUI (Electron)

- Offline functionality
- Native file system access
- Better performance for large datasets
- Export to native formats

### CLI

```bash
# Start hotspot
ax-traffic start

# Stop hotspot
ax-traffic stop

# Status
ax-traffic status

# Export session to PCAP
ax-traffic export --session abc123 --output session.pcap

# Scan for vulnerabilities
ax-traffic scan --passive --session abc123

# Replay request
ax-traffic replay --flow def456
```

---

## Data Flow

### Traffic Capture Flow

```
1. Device connects to WiFi hotspot
 ↓
2. DHCP assigns IP address
 ↓
3. DNS queries handled by dnsmasq
 ↓
4. HTTP/HTTPS traffic redirected by iptables
 ↓
5. mitmproxy intercepts traffic
 ↓
6. Certificate generated on-the-fly
 ↓
7. Traffic decrypted (or pinning detected)
 ↓
8. Plugins process traffic
 ↓
9. Traffic logged to database
 ↓
10. PCAP exported (streaming)
 ↓
11. WebSocket event sent to UI
 ↓
12. Traffic forwarded to internet
```

### Analysis Flow

```
1. HTTP flow captured
 ↓
2. Protocol analyzer extracts data
 ↓
3. Passive scanner checks for vulnerabilities
 ↓
4. Plugins perform custom analysis
 ↓
5. Threat intel APIs queried
 ↓
6. ML classifier categorizes traffic
 ↓
7. Findings stored in database
 ↓
8. Alert triggered (if high severity)
 ↓
9. Report generated
```

---

## Error Handling & Recovery

### Fail-Fast Validation

**Pre-flight Checks**:
1. Platform detection
2. Dependency validation
3. Configuration validation
4. Resource availability check
5. Network state check

**Failure Response**:
- Print detailed error message
- Provide solution steps
- Exit with non-zero code
- No system changes made

### Automatic Recovery

**Hotspot Failures**:
```python
"""
@fileoverview Hotspot Monitor
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Monitors hotspot health and performs automatic recovery.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

class HotspotMonitor:
 def monitor(self):
 while True:
 if not self.is_hotspot_running():
 log.error("Hotspot crashed")
 self.attempt_recovery()
 time.sleep(5)

 def attempt_recovery(self):
 # 1. Clean up iptables rules
 # 2. Kill stale processes
 # 3. Restart hostapd
 # 4. Restart dnsmasq
 # 5. Reapply iptables rules
 # 6. Alert user if recovery fails
 pass
```

**mitmproxy Failures**:
- Automatic restart on crash
- Queue preservation
- Connection retry logic

**Disk Full**:
- Emergency cleanup of old files
- Alert user immediately
- Stop capture (preserve hotspot)

### Cleanup on Exit

```python
"""
@fileoverview Cleanup Manager
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Ensures proper cleanup of system resources on exit.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

class CleanupManager:
 def cleanup(self):
 # Always runs, even on crash

 # 1. Remove iptables rules
 self.remove_iptables_rules()

 # 2. Stop hostapd
 self.stop_hostapd()

 # 3. Stop dnsmasq
 self.stop_dnsmasq()

 # 4. Close PCAP files
 self.close_pcap_files()

 # 5. Save state to database
 self.save_state()

 log.info("Cleanup complete")

# Register cleanup
import atexit
atexit.register(cleanup_manager.cleanup)

# Handle signals
import signal
signal.signal(signal.SIGTERM, lambda s, f: cleanup_manager.cleanup())
signal.signal(signal.SIGINT, lambda s, f: cleanup_manager.cleanup())
```

---

## Compliance & Legal

### Privacy Considerations

**Warning to Users**:
```
⚠️ WARNING: Network Traffic Capture

This system captures and stores ALL network traffic from connected
devices, including potentially sensitive data such as:
- Passwords and credentials
- Personal information
- Financial data
- Private messages
- Location data

Legal Requirements:
- Only use on networks you own or have explicit permission to monitor
- Inform users that their traffic is being captured
- Comply with local privacy laws (GDPR, CCPA, etc.)
- Secure captured data appropriately
- Delete captured data when no longer needed

By using this software, you agree to use it responsibly and legally.
```

### Data Retention

**Default Policy**:
- PCAP files: 7 days
- Database records: 30 days
- Compressed archives: 90 days
- User configurable

### Compliance Features

- **Data encryption** at rest (optional)
- **Access logging** for audit trails
- **Data export** for GDPR requests
- **Data deletion** tools
- **Consent management** (display warning to connected clients)

---

## Future Roadmap

### Version 1.0 (Current Design)
- Core traffic capture
- HTTPS MITM
- PCAP export
- Web UI
- Basic analysis
- Plugin system

### Version 1.1 (Q1 2026)
- Mobile app (React Native)
- Enhanced ML models
- Advanced fuzzing
- Improved collaboration

### Version 1.2 (Q2 2026)
- Distributed capture
- Cloud-native deployment
- Enhanced threat intel
- Custom dissectors

### Version 2.0 (Q3 2026)
- Multi-platform support (macOS, more Linux distros)
- Enterprise features (SSO, LDAP)
- Advanced reporting
- Performance improvements

---

## Appendix

### Glossary

- **MITM**: Man-in-the-Middle
- **PCAP**: Packet Capture
- **AP**: Access Point
- **SSID**: Service Set Identifier
- **WPA2**: Wi-Fi Protected Access 2
- **DHCP**: Dynamic Host Configuration Protocol
- **DNS**: Domain Name System
- **JWT**: JSON Web Token
- **RBAC**: Role-Based Access Control

### References

- mitmproxy Documentation: https://docs.mitmproxy.org
- hostapd Documentation: https://w1.fi/hostapd/
- Wireshark Documentation: https://www.wireshark.org/docs/
- OWASP Top 10: https://owasp.org/www-project-top-ten/

### Contributing

See CONTRIBUTING.md for guidelines.

### License

**Copyright © 2025 MMeTech (Macau) Ltd.**
**Author**: AdamChe 谢毅翔, 字:吉祥
**Classification**: Enterprise Security Auditor and Education

**ALL RIGHTS RESERVED**

---

#### Dual Licensing Model

This project uses a **dual licensing model**:

1. **Community Edition**: MIT License (see [LICENSE-COMMUNITY](LICENSE-COMMUNITY))

See [LICENSING_GUIDE.md](LICENSING_GUIDE.md) for complete details.

---

#### Licensing Phasing Strategy

The dual licensing model is implemented through a **phased rollout approach**:

**Phase 0-6: Community Edition Only (Weeks 1-12)**
- **Status**: 100% MIT License
- **All Features**: Open source on GitHub under MIT License
- **Released Features**:
 - Phase 0: Critical Infrastructure
 - Phase 1: Foundation (Platform, Hotspot)
 - Phase 2: Traffic Capture (mitmproxy, PCAP)
 - Phase 3: Storage & API
 - Phase 4: Web UI
 - Phase 5: Basic Analysis
 - Phase 6: Basic Advanced Features
- **License**: All code released under MIT License
- **Distribution**: Public GitHub repository
- **Cost**: FREE

**Phase 7: First Enterprise Features (Weeks 13-14)**
- **Status**: Core MIT + Enterprise Add-ons (Dual licensing begins)
- **Community Edition (MIT)**:
 - Desktop GUI (Electron)
 - Basic mobile app
 - 802.11 monitor mode
 - GPS tracking

**Phase 8+: Production Ready + Enterprise Expansion (Weeks 15-18+)**
- **Status**: Dual licensing fully operational
- **Community Edition (MIT)**:
 - Performance optimization
 - Security hardening
 - Complete documentation
 - Docker/Kubernetes support
- **Release**: Community v1.1+ + Enterprise v1.1+
- **Ongoing Development**:
 - Community: Quarterly updates (bug fixes, security patches, minor improvements)
 - Enterprise: Monthly updates (new features, compliance modules, advanced capabilities)

**Key Principles:**
- ✅ **Core features remain MIT**: WiFi hotspot, traffic capture, basic analysis stay open source
- ✅ **Enterprise features are additive**: Proprietary features are new capabilities, not restrictions on Community Edition
- ✅ **Clear separation**: Code physically separated (`src/community/` vs `src/enterprise/`)
- ✅ **Upgrade path**: Community Edition users can seamlessly upgrade to Enterprise
- ✅ **No feature removal**: Features released as MIT in early phases remain MIT forever

---


#### Community Edition (MIT License)

**License Type**: MIT License
**Cost**: FREE (永久免費)
**Source Code**: Available on GitHub (open source)
**Redistribution**: Allowed under MIT License terms

**Community Edition Includes:**
- WiFi hotspot creation and management
- Transparent HTTPS MITM interception
- Traffic capture and logging
- Basic protocol analysis (HTTP, TLS, DNS)
- PCAP export for Wireshark
- Web dashboard (basic features)
- REST API (core endpoints)
- Session and device tracking
- Basic vulnerability scanning (passive)
- Plugin system (core framework)
- IPv6 dual-stack support
- Certificate management
- Time synchronization
- GDPR compliance tools

**MIT License Terms:**
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

**The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.**

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


---


---

#### License Compliance Notice

**Third-Party Components (MIT License):**
This software integrates the following MIT-licensed components:
- mitmproxy: Copyright (c) [year] mitmproxy contributors
- FastAPI: Copyright (c) [year] Sebastián Ramírez
- React: Copyright (c) [year] Facebook, Inc.
- And other dependencies listed in requirements.txt and [NOTICES.md](NOTICES.md)

All third-party copyright notices are preserved.

**AdamChe Proprietary Innovations:**

**Community Edition Innovations (MIT Licensed):**
- Integrated WiFi hotspot with zero-configuration
- Transparent HTTPS MITM with automatic certificate management
- Streaming PCAP export with backpressure control
- Atomic startup orchestration with rollback
- Network partition resilience
- IPv6 dual-stack architecture
- Plugin sandboxing with seccomp
- GDPR compliance framework
- Copyright (c) 2025 MMeTech (Macau) Ltd.


**Software Copyright Application:**
This design document describes a system with dual licensing:
- **Community Edition**: 30-40% original code (AdamChe innovations) - MIT License
- Clear separation of MIT vs proprietary code
- All innovations documented for copyright application

---

**For complete license terms, see:**
- [LICENSE](LICENSE) - Dual licensing overview
- [LICENSE-COMMUNITY](LICENSE-COMMUNITY) - MIT License terms
- [LICENSING_GUIDE.md](LICENSING_GUIDE.md) - Complete licensing guide

---

**End of Design Plan**

This document serves as the comprehensive blueprint for the AX-TrafficAnalyzer project. All implementation must follow this design to ensure consistency, quality, and completeness.

