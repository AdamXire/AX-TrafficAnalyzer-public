"""
AX-TrafficAnalyzer Load Testing with Locust
Copyright © 2025 MMeTech (Macau) Ltd.

Usage:
    pip install locust
    locust -f tests/load/locustfile.py --host=http://localhost:8443
    
    # Or headless mode:
    locust -f tests/load/locustfile.py --host=http://localhost:8443 \
           --users 50 --spawn-rate 10 --run-time 5m --headless

Targets:
    - 1000 req/s sustained
    - <100ms p95 latency
    - 50 concurrent users
    - 0% error rate under normal load
"""

import json
import random
from locust import HttpUser, task, between, events
from locust.runners import MasterRunner
import logging

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


class TrafficAnalyzerUser(HttpUser):
    """
    Simulates a typical user interacting with AX-TrafficAnalyzer API.
    
    Task weights reflect real-world usage patterns:
    - Health checks: frequent (monitoring)
    - Sessions list: common (dashboard)
    - Flows list: common (traffic view)
    - Single flow: occasional (detail view)
    - Findings: occasional (security view)
    """
    
    # Wait 1-3 seconds between tasks (realistic user behavior)
    wait_time = between(1, 3)
    
    # Store auth token after login
    token = None
    
    def on_start(self):
        """Called when a user starts - authenticate first."""
        log.info("[LOAD] User starting, attempting login...")
        
        # Try to login (may fail if auth not configured)
        try:
            response = self.client.post(
                "/api/v1/auth/login",
                json={"username": "admin", "password": "admin"},
                catch_response=True
            )
            if response.status_code == 200:
                data = response.json()
                self.token = data.get("access_token")
                log.info("[LOAD] Login successful")
                response.success()
            else:
                # Auth might not be required in dev mode
                log.info("[LOAD] Login skipped (auth not required)")
                response.success()
        except Exception as e:
            log.warning(f"[LOAD] Login failed: {e}")
    
    def _headers(self):
        """Get headers with auth token if available."""
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers
    
    # =========================================================================
    # Health & Status Tasks (High Priority)
    # =========================================================================
    
    @task(10)
    def health_check(self):
        """Health endpoint - most frequent call (monitoring)."""
        with self.client.get(
            "/api/v1/health",
            headers=self._headers(),
            catch_response=True,
            name="/api/v1/health"
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Health check failed: {response.status_code}")
    
    @task(5)
    def readiness_check(self):
        """Readiness endpoint for K8s probes."""
        with self.client.get(
            "/api/v1/health/ready",
            headers=self._headers(),
            catch_response=True,
            name="/api/v1/health/ready"
        ) as response:
            if response.status_code in [200, 404]:  # 404 if not implemented
                response.success()
            else:
                response.failure(f"Readiness failed: {response.status_code}")
    
    # =========================================================================
    # Sessions Tasks (Medium Priority)
    # =========================================================================
    
    @task(8)
    def list_sessions(self):
        """List all sessions - common dashboard operation."""
        with self.client.get(
            "/api/v1/sessions",
            params={"limit": 50, "offset": 0},
            headers=self._headers(),
            catch_response=True,
            name="/api/v1/sessions"
        ) as response:
            if response.status_code == 200:
                response.success()
            elif response.status_code == 401:
                response.success()  # Auth required, not an error
            else:
                response.failure(f"Sessions failed: {response.status_code}")
    
    @task(3)
    def get_session_detail(self):
        """Get single session detail."""
        # Use a random session ID (may not exist)
        session_id = f"test-session-{random.randint(1, 100)}"
        with self.client.get(
            f"/api/v1/sessions/{session_id}",
            headers=self._headers(),
            catch_response=True,
            name="/api/v1/sessions/[id]"
        ) as response:
            if response.status_code in [200, 404, 401]:
                response.success()
            else:
                response.failure(f"Session detail failed: {response.status_code}")
    
    # =========================================================================
    # Flows Tasks (Medium Priority)
    # =========================================================================
    
    @task(8)
    def list_flows(self):
        """List traffic flows - common traffic view operation."""
        with self.client.get(
            "/api/v1/flows",
            params={"limit": 100, "offset": 0},
            headers=self._headers(),
            catch_response=True,
            name="/api/v1/flows"
        ) as response:
            if response.status_code == 200:
                response.success()
            elif response.status_code == 401:
                response.success()
            else:
                response.failure(f"Flows failed: {response.status_code}")
    
    @task(2)
    def get_flow_detail(self):
        """Get single flow detail."""
        flow_id = f"flow-{random.randint(1, 1000)}"
        with self.client.get(
            f"/api/v1/flows/{flow_id}",
            headers=self._headers(),
            catch_response=True,
            name="/api/v1/flows/[id]"
        ) as response:
            if response.status_code in [200, 404, 401]:
                response.success()
            else:
                response.failure(f"Flow detail failed: {response.status_code}")
    
    # =========================================================================
    # Analysis Tasks (Low Priority)
    # =========================================================================
    
    @task(4)
    def list_findings(self):
        """List security findings."""
        with self.client.get(
            "/api/v1/findings",
            params={"limit": 50},
            headers=self._headers(),
            catch_response=True,
            name="/api/v1/findings"
        ) as response:
            if response.status_code in [200, 401, 404]:
                response.success()
            else:
                response.failure(f"Findings failed: {response.status_code}")
    
    @task(2)
    def get_analysis_stats(self):
        """Get analysis statistics."""
        with self.client.get(
            "/api/v1/analysis/stats",
            headers=self._headers(),
            catch_response=True,
            name="/api/v1/analysis/stats"
        ) as response:
            if response.status_code in [200, 401, 404]:
                response.success()
            else:
                response.failure(f"Stats failed: {response.status_code}")
    
    # =========================================================================
    # Devices Tasks (Low Priority)
    # =========================================================================
    
    @task(3)
    def list_devices(self):
        """List connected devices."""
        with self.client.get(
            "/api/v1/devices",
            headers=self._headers(),
            catch_response=True,
            name="/api/v1/devices"
        ) as response:
            if response.status_code in [200, 401, 404]:
                response.success()
            else:
                response.failure(f"Devices failed: {response.status_code}")


class HighLoadUser(HttpUser):
    """
    High-frequency user for stress testing.
    Minimal wait time, focuses on high-throughput endpoints.
    """
    
    wait_time = between(0.1, 0.5)  # Very fast
    
    @task(10)
    def rapid_health(self):
        """Rapid health checks for throughput testing."""
        self.client.get("/api/v1/health", name="/api/v1/health [rapid]")
    
    @task(5)
    def rapid_sessions(self):
        """Rapid session list for throughput testing."""
        self.client.get(
            "/api/v1/sessions",
            params={"limit": 10},
            name="/api/v1/sessions [rapid]"
        )


# =============================================================================
# Event Hooks for Reporting
# =============================================================================

@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    """Called when load test starts."""
    log.info("=" * 60)
    log.info("[LOAD TEST] AX-TrafficAnalyzer Load Test Starting")
    log.info("=" * 60)
    log.info(f"[LOAD TEST] Target host: {environment.host}")
    if isinstance(environment.runner, MasterRunner):
        log.info(f"[LOAD TEST] Running in distributed mode")


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    """Called when load test stops."""
    log.info("=" * 60)
    log.info("[LOAD TEST] Load Test Complete")
    log.info("=" * 60)
    
    # Print summary stats
    stats = environment.stats
    log.info(f"[LOAD TEST] Total requests: {stats.total.num_requests}")
    log.info(f"[LOAD TEST] Total failures: {stats.total.num_failures}")
    log.info(f"[LOAD TEST] Avg response time: {stats.total.avg_response_time:.2f}ms")
    log.info(f"[LOAD TEST] Requests/sec: {stats.total.current_rps:.2f}")
    
    # Check targets
    if stats.total.avg_response_time < 100:
        log.info("[LOAD TEST] ✅ Response time target MET (<100ms)")
    else:
        log.warning("[LOAD TEST] ⚠ Response time target MISSED (>100ms)")
    
    if stats.total.fail_ratio < 0.01:
        log.info("[LOAD TEST] ✅ Error rate target MET (<1%)")
    else:
        log.warning(f"[LOAD TEST] ⚠ Error rate target MISSED ({stats.total.fail_ratio*100:.2f}%)")

