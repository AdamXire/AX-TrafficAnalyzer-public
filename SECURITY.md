<!-- COMMUNITY-START -->
# Security Policy

**Copyright © 2025 MMeTech (Macau) Ltd.**  
**Author**: AdamChe 谢毅翔, 字:吉祥

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability, please report it responsibly.

### How to Report

1. **DO NOT** create a public GitHub issue for security vulnerabilities
2. Email: security@mmetech.com
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes

### Response Timeline

- **Initial Response**: Within 48 hours
- **Assessment**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: 24-72 hours
  - High: 7 days
  - Medium: 30 days
  - Low: Next release

### Security Measures

This project implements:

- **Fail-Fast Validation**: All dependencies validated at startup
- **Input Validation**: Pydantic models for all API inputs
- **Authentication**: JWT-based authentication
- **Authorization**: Role-based access control (RBAC)
- **Rate Limiting**: API rate limiting to prevent abuse
- **TLS**: HTTPS for all API communications
- **Secrets Management**: Secure keyring for sensitive data
- **Logging**: Structured logging without sensitive data

### Security Scanning

We use automated security scanning:

- **Dependency Scanning**: pip-audit, safety
- **SAST**: Bandit, Semgrep
- **Container Scanning**: Trivy
- **Secret Detection**: Custom patterns + Semgrep

### Known Security Considerations

1. **Network Privileges**: This application requires `NET_ADMIN` and `NET_RAW` capabilities for hotspot functionality. Run in isolated environments.

2. **HTTPS Interception**: By design, this tool intercepts HTTPS traffic. Use only on networks you own or have explicit permission to monitor.

3. **Root Access**: Some features require root privileges. Follow the principle of least privilege.

## Security Best Practices for Users

1. Change default credentials immediately
2. Use strong passwords
3. Keep the software updated
4. Run in isolated network environments
5. Regularly review captured data and delete when not needed
6. Enable TLS for API access
7. Use firewall rules to restrict access

## Acknowledgments

We thank all security researchers who help keep this project secure.
<!-- COMMUNITY-END -->

