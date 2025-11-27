<!-- COMMUNITY-START -->
# AX-TrafficAnalyzer Troubleshooting Guide

**Copyright © 2025 MMeTech (Macau) Ltd.**

## Quick Diagnostics

```bash
# Check health
curl http://localhost:8443/api/v1/health

# Check logs
docker-compose logs -f ax-traffic  # Docker
journalctl -u ax-traffic -f        # Systemd
tail -f logs/ax-traffic.log        # Manual
```

## Common Issues

### 1. Startup Fails: "hostapd not found"

**Error**:
```
DependencyValidationError: hostapd not found in PATH
```

**Solution**:
```bash
sudo apt-get install hostapd
```

### 2. Startup Fails: "Permission denied"

**Error**:
```
PermissionError: [Errno 13] Permission denied: '/etc/ax-traffic'
```

**Solution**: Run with root privileges:
```bash
sudo python -m src.community.main
# Or for Docker:
docker run --privileged ...
```

### 3. WiFi Hotspot Not Starting

**Error**:
```
NetworkError: Failed to start hostapd
```

**Solutions**:
1. Check WiFi interface supports AP mode:
   ```bash
   iw list | grep "AP"
   ```
2. Stop conflicting services:
   ```bash
   sudo systemctl stop NetworkManager
   sudo systemctl stop wpa_supplicant
   ```
3. Check interface is not in use:
   ```bash
   sudo ip link set wlan0 down
   ```

### 4. Database Migration Fails

**Error**:
```
alembic.util.exc.CommandError: Can't locate revision
```

**Solution**:
```bash
# Reset migrations
rm -f data/ax-traffic.db
alembic upgrade head
```

### 5. API Returns 401 Unauthorized

**Cause**: JWT token expired or invalid

**Solution**:
```bash
# Re-login to get new token
curl -X POST http://localhost:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin"}'
```

### 6. HTTPS Traffic Not Decrypted

**Causes**:
1. CA certificate not installed on device
2. Certificate pinning enabled in app

**Solutions**:
1. Install CA cert: `http://localhost:8443/cert`
2. Check pinning detection logs
3. Use Frida/Objection to bypass pinning

### 7. Docker Container Exits Immediately

**Check logs**:
```bash
docker-compose logs ax-traffic
```

**Common causes**:
- Missing `--privileged` flag
- Missing `network_mode: host`
- Port already in use

### 8. High Memory Usage

**Solution**: Adjust configuration:
```json
{
  "capture": {
    "max_size_mb": 50,
    "rotation_interval": 1800
  }
}
```

### 9. "Address already in use" Error

**Solution**:
```bash
# Find and kill process using port
sudo lsof -i :8443
sudo kill -9 <PID>
```

## Debug Mode

Enable debug logging:

```json
// config/config.json
{
  "logging": {
    "level": "DEBUG"
  }
}
```

Or via environment:
```bash
LOG_LEVEL=DEBUG python -m src.community.main
```

## Getting Help

1. Check logs for `[FAIL-FAST]` messages
2. Search existing issues on GitHub
3. Create new issue with:
   - Error message
   - Steps to reproduce
   - System info: `uname -a`, `python --version`
   - Logs (sanitized)

## Health Check Endpoints

| Endpoint | Purpose |
|----------|---------|
| `/api/v1/health` | Basic health |
| `/api/v1/health/ready` | Readiness probe |
| `/api/v1/health/live` | Liveness probe |
<!-- COMMUNITY-END -->

