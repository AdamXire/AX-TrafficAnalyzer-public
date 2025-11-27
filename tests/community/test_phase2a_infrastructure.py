"""
@fileoverview Phase 2a Infrastructure Tests
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Tests for Phase 2a critical infrastructure modules.
"""

import pytest
import pytest_asyncio
import asyncio
import tempfile
import os
from pathlib import Path

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from community.core import (
    get_platform_info,
    KeyringManager,
    CertificateSecurityManager,
    RingBuffer,
    BackpressureController,
    CircuitBreaker,
    MemoryWatermarkMonitor,
    AsyncLockManager,
    IdempotencyManager,
)
from community.core.errors import SecurityError, ConfigurationError


class TestKeyringManager:
    """Test KeyringManager."""
    
    @pytest.mark.skipif(
        not os.path.exists("/usr/bin/libsecret-tool"),
        reason="libsecret-tool not available"
    )
    def test_keyring_initialization(self):
        """Test keyring manager initialization."""
        platform = get_platform_info()
        manager = KeyringManager(platform)
        assert manager is not None
        print("✓ KeyringManager initialized")
    
    @pytest.mark.skipif(
        not os.path.exists("/usr/bin/libsecret-tool"),
        reason="libsecret-tool not available"
    )
    def test_key_storage_retrieval(self):
        """Test key storage and retrieval."""
        platform = get_platform_info()
        manager = KeyringManager(platform)
        
        test_key_id = "test-key-123"
        test_data = b"test-key-data"
        
        # Store key
        manager.store_key(test_key_id, test_data)
        print(f"✓ Key stored: {test_key_id}")
        
        # Retrieve key
        retrieved = manager.retrieve_key(test_key_id)
        assert retrieved == test_data
        print(f"✓ Key retrieved: {test_key_id}")
        
        # Cleanup
        manager.delete_key(test_key_id)
        print(f"✓ Key deleted: {test_key_id}")


class TestCertificateSecurityManager:
    """Test CertificateSecurityManager."""
    
    @pytest.mark.skipif(
        not os.path.exists("/usr/bin/libsecret-tool"),
        reason="libsecret-tool not available"
    )
    def test_cert_manager_initialization(self):
        """Test certificate security manager initialization."""
        platform = get_platform_info()
        keyring_mgr = KeyringManager(platform)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_mgr = CertificateSecurityManager(keyring_mgr, cert_dir=tmpdir)
            assert cert_mgr is not None
            assert Path(tmpdir).exists()
            assert os.access(tmpdir, os.W_OK)
            print(f"✓ CertificateSecurityManager initialized: {tmpdir}")
    
    @pytest.mark.skipif(
        not os.path.exists("/usr/bin/libsecret-tool"),
        reason="libsecret-tool not available"
    )
    def test_private_key_storage(self):
        """Test private key storage."""
        platform = get_platform_info()
        keyring_mgr = KeyringManager(platform)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_mgr = CertificateSecurityManager(keyring_mgr, cert_dir=tmpdir)
            
            key_id = "test-ca-key"
            key_pem = b"-----BEGIN PRIVATE KEY-----\ntest-key-data\n-----END PRIVATE KEY-----"
            
            # Store private key
            key_path = cert_mgr.store_private_key(key_id, key_pem)
            assert Path(key_path).exists()
            assert os.stat(key_path).st_mode & 0o777 == 0o600  # Check 0600 permissions
            print(f"✓ Private key stored: {key_path}")
            
            # Retrieve private key
            retrieved = cert_mgr.retrieve_private_key(key_id)
            assert retrieved == key_pem
            print(f"✓ Private key retrieved: {key_id}")


class TestRingBuffer:
    """Test RingBuffer."""
    
    def test_ring_buffer_initialization(self):
        """Test ring buffer initialization."""
        buffer = RingBuffer(max_size_mb=10)
        assert buffer.max_size_mb() == 10.0
        assert buffer.size_mb() == 0.0
        assert buffer.is_empty()
        print("✓ RingBuffer initialized")
    
    def test_ring_buffer_push_pop(self):
        """Test ring buffer push and pop."""
        buffer = RingBuffer(max_size_mb=1)  # 1MB for testing
        
        # Push data
        data1 = b"test data 1" * 1000
        result = buffer.push(data1)
        assert result is True
        assert not buffer.is_empty()
        print(f"✓ Data pushed: {len(data1)} bytes")
        
        # Pop data
        popped = buffer.pop()
        assert popped == data1
        assert buffer.is_empty()
        print(f"✓ Data popped: {len(popped)} bytes")
    
    def test_ring_buffer_backpressure(self):
        """Test ring buffer backpressure threshold."""
        buffer = RingBuffer(max_size_mb=1)  # 1MB
        
        # Fill to 80% threshold
        threshold_bytes = int(buffer.backpressure_threshold)
        data = b"x" * (threshold_bytes - 100)  # Just below threshold
        buffer.push(data)
        assert not buffer.is_full()
        print(f"✓ Below threshold: {buffer.size_mb():.2f}MB")
        
        # Push more to exceed threshold
        buffer.push(b"x" * 200)
        assert buffer.is_full()
        print(f"✓ Above threshold: {buffer.size_mb():.2f}MB")


class TestBackpressureController:
    """Test BackpressureController."""
    
    def test_backpressure_controller(self):
        """Test backpressure controller."""
        buffer = RingBuffer(max_size_mb=1)
        controller = BackpressureController(buffer)
        
        assert not controller.should_pause()
        print("✓ Backpressure controller initialized")
        
        # Fill buffer to trigger backpressure
        threshold_bytes = int(buffer.backpressure_threshold)
        buffer.push(b"x" * threshold_bytes)
        
        assert controller.should_pause()
        assert controller.is_paused()
        print("✓ Backpressure signal triggered")


class TestCircuitBreaker:
    """Test CircuitBreaker."""
    
    def test_circuit_breaker_initialization(self):
        """Test circuit breaker initialization."""
        breaker = CircuitBreaker(failure_threshold=3)
        assert breaker.failure_threshold == 3
        assert not breaker.should_open()
        print("✓ CircuitBreaker initialized")
    
    def test_circuit_breaker_failures(self):
        """Test circuit breaker failure tracking."""
        breaker = CircuitBreaker(failure_threshold=3)
        
        # Record 2 failures (should not open)
        breaker.record_failure()
        breaker.record_failure()
        assert not breaker.should_open()
        print("✓ 2 failures recorded, circuit still closed")
        
        # Record 3rd failure (should open)
        breaker.record_failure()
        assert breaker.should_open()
        print("✓ 3rd failure recorded, circuit opened")
        
        # Record success (should close)
        breaker.record_success()
        assert not breaker.should_open()
        print("✓ Success recorded, circuit closed")


class TestMemoryWatermarkMonitor:
    """Test MemoryWatermarkMonitor."""
    
    def test_memory_monitor_initialization(self):
        """Test memory watermark monitor initialization."""
        monitor = MemoryWatermarkMonitor()
        assert monitor.warning_threshold == 0.80
        assert monitor.emergency_threshold == 0.95
        print("✓ MemoryWatermarkMonitor initialized")
    
    def test_memory_check(self):
        """Test memory check."""
        monitor = MemoryWatermarkMonitor()
        status = monitor.check_memory()
        
        assert "usage_percent" in status
        assert "available_gb" in status
        assert "status" in status
        print(f"✓ Memory check: {status['usage_percent']*100:.1f}% used, status: {status['status']}")


class TestAsyncLockManager:
    """Test AsyncLockManager."""
    
    @pytest_asyncio.fixture
    async def lock_mgr(self):
        return AsyncLockManager()
    
    @pytest.mark.asyncio
    async def test_lock_acquisition(self, lock_mgr):
        """Test async lock acquisition."""
        async with lock_mgr.acquire("test-resource"):
            # Lock acquired
            assert lock_mgr.has_lock("test-resource")
            print("✓ Lock acquired")
        
        # Lock released
        print("✓ Lock released")
    
    @pytest.mark.asyncio
    async def test_concurrent_access(self, lock_mgr):
        """Test concurrent access protection."""
        counter = {"value": 0}
        
        async def increment():
            async with lock_mgr.acquire("counter"):
                counter["value"] += 1
        
        # Run 10 concurrent increments
        await asyncio.gather(*[increment() for _ in range(10)])
        
        assert counter["value"] == 10
        print(f"✓ Concurrent access protected: counter = {counter['value']}")


class TestIdempotencyManager:
    """Test IdempotencyManager."""
    
    def test_idempotency_manager(self):
        """Test idempotency manager."""
        manager = IdempotencyManager()
        
        # Generate IDs
        id1 = manager.generate_id()
        id2 = manager.generate_id()
        assert id1 != id2
        print(f"✓ Generated unique IDs: {id1[:8]}... != {id2[:8]}...")
        
        # Mark as processed
        assert not manager.is_processed(id1)
        manager.mark_processed(id1)
        assert manager.is_processed(id1)
        print(f"✓ ID marked as processed: {id1[:8]}...")


class TestDirectoryValidation:
    """Test directory validation."""
    
    def test_directory_creation(self):
        """Test directory creation and validation."""
        from community.core import DependencyValidator
        
        try:
            platform = get_platform_info()
        except Exception as e:
            pytest.skip(f"Platform detection failed: {e}")
        
        validator = DependencyValidator(platform)
        
        # Create minimal config
        config = {
            "hotspot": {"interface": "wlan0", "ssid": "Test", "password": "12345678"},
            "capture": {"enabled": True},
            "storage": {"pcap_dir": "./test_captures"},
            "api": {"host": "0.0.0.0", "port": 8443}
        }
        
        # Validate directories
        validator.validate_directories(config)
        
        # Check directories exist
        assert Path("./certs").exists()
        assert Path("./captures").exists()
        assert Path("./logs").exists()
        print("✓ Directories created and validated")


class TestIPTablesRedirect:
    """Test IPTables REDIRECT rules."""
    
    def test_redirect_rule_method_exists(self):
        """Test that add_redirect_rule method exists."""
        from community.network.iptables import IPTablesManager
        
        manager = IPTablesManager(interface="lo")  # Use loopback for testing
        assert hasattr(manager, "add_redirect_rule")
        assert callable(getattr(manager, "add_redirect_rule"))
        print("✓ add_redirect_rule method exists")


if __name__ == "__main__":
    print("\n" + "="*60)
    print("Phase 2a Infrastructure Tests")
    print("="*60 + "\n")
    
    # Run tests
    pytest.main([__file__, "-v", "-s"])

