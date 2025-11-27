"""
Tests for Phase 6 Features - Replay, Fuzzer, Integrations, Cloud.
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime


class TestRequestReplayer:
    """Tests for Request Replayer."""
    
    def test_replay_request_dataclass(self):
        """Test ReplayRequest dataclass."""
        from src.community.replay.replayer import ReplayRequest
        
        request = ReplayRequest(
            replay_id="replay-123",
            original_flow_id="flow-456",
            method="GET",
            url="https://example.com/api",
            headers={"User-Agent": "Test"}
        )
        
        assert request.replay_id == "replay-123"
        assert request.method == "GET"
    
    def test_replay_result_dataclass(self):
        """Test ReplayResult dataclass."""
        from src.community.replay.replayer import ReplayResult
        
        result = ReplayResult(
            replay_id="replay-123",
            original_flow_id="flow-456",
            success=True,
            status_code=200,
            duration_ms=50.5
        )
        
        assert result.success is True
        assert result.status_code == 200
        
        data = result.to_dict()
        assert "replay_id" in data
        assert "duration_ms" in data
    
    def test_replayer_initialization(self):
        """Test RequestReplayer initialization."""
        from src.community.replay.replayer import RequestReplayer
        
        replayer = RequestReplayer(
            db_manager=None,
            timeout_seconds=30,
            max_concurrent=10
        )
        
        assert replayer.timeout == 30
        assert replayer.max_concurrent == 10
    
    def test_replayer_build_request(self):
        """Test building replay request with modifications."""
        from src.community.replay.replayer import RequestReplayer
        
        replayer = RequestReplayer()
        
        flow = {
            "flow_id": "flow-123",
            "method": "GET",
            "url": "https://example.com/api",
            "request_headers": {"User-Agent": "Original"}
        }
        
        modifications = {
            "method": "POST",
            "headers": {"X-Custom": "value"}
        }
        
        request = replayer._build_request(flow, modifications)
        
        assert request.method == "POST"
        assert "X-Custom" in request.headers


class TestReplayQueueManager:
    """Tests for Replay Queue Manager."""
    
    def test_queued_replay_dataclass(self):
        """Test QueuedReplay dataclass."""
        from src.community.replay.queue import QueuedReplay
        
        job = QueuedReplay(
            job_id="job-123",
            flow_id="flow-456",
            modifications={"method": "POST"},
            priority=1
        )
        
        assert job.job_id == "job-123"
        assert job.priority == 1
        assert job.created_at is not None
    
    def test_queue_manager_initialization(self):
        """Test ReplayQueueManager initialization."""
        from src.community.replay.queue import ReplayQueueManager
        
        manager = ReplayQueueManager(
            redis_queue=None,
            config={"mode": "dev"},
            max_queue_size=500
        )
        
        assert manager.max_queue_size == 500
    
    @pytest.mark.asyncio
    async def test_get_queue_stats(self):
        """Test getting queue statistics."""
        from src.community.replay.queue import ReplayQueueManager
        
        manager = ReplayQueueManager(config={"mode": "dev"})
        
        stats = await manager.get_queue_stats()
        
        assert "queue_size" in stats
        assert "max_queue_size" in stats
        assert "has_redis" in stats


class TestMutationEngine:
    """Tests for Mutation Engine."""
    
    @pytest.fixture
    def engine(self):
        """Create mutation engine."""
        from src.community.fuzzer.mutation import MutationEngine
        return MutationEngine()
    
    def test_mutation_type_enum(self):
        """Test MutationType enum."""
        from src.community.fuzzer.mutation import MutationType
        
        assert MutationType.SQL_INJECTION.value == "sql_injection"
        assert MutationType.XSS.value == "xss"
    
    def test_engine_initialization(self, engine):
        """Test engine initialization."""
        assert engine is not None
        assert len(engine.mutation_types) > 0
    
    def test_mutate_headers(self, engine):
        """Test header mutations."""
        headers = {
            "User-Agent": "Mozilla/5.0",
            "Accept": "text/html"
        }
        
        mutations = engine.mutate_headers(headers)
        
        assert len(mutations) > 0
        assert "headers" in mutations[0]
        assert "mutation" in mutations[0]
    
    def test_mutate_params(self, engine):
        """Test URL parameter mutations."""
        url = "https://example.com/api?id=123&name=test"
        
        mutations = engine.mutate_params(url)
        
        assert len(mutations) > 0
        assert "url" in mutations[0]
    
    def test_mutate_json_body(self, engine):
        """Test JSON body mutations."""
        body = b'{"username": "admin", "password": "secret"}'
        content_type = "application/json"
        
        mutations = engine.mutate_body(body, content_type)
        
        assert len(mutations) > 0
        assert "body" in mutations[0]
    
    def test_mutate_form_body(self, engine):
        """Test form body mutations."""
        body = b"username=admin&password=secret"
        content_type = "application/x-www-form-urlencoded"
        
        mutations = engine.mutate_body(body, content_type)
        
        assert len(mutations) > 0
    
    def test_get_mutation_count(self, engine):
        """Test mutation count estimation."""
        count = engine.get_mutation_count(
            headers={"User-Agent": "Test"},
            url="https://example.com?id=1",
            body=b'{"test": "value"}',
            content_type="application/json"
        )
        
        assert count > 0


class TestHTTPFuzzer:
    """Tests for HTTP Fuzzer."""
    
    def test_fuzzing_strategy_enum(self):
        """Test FuzzingStrategy enum."""
        from src.community.fuzzer.http_fuzzer import FuzzingStrategy
        
        assert FuzzingStrategy.ALL.value == "all"
        assert FuzzingStrategy.HEADERS.value == "headers"
    
    def test_fuzzing_result_dataclass(self):
        """Test FuzzingResult dataclass."""
        from src.community.fuzzer.http_fuzzer import FuzzingResult
        from src.community.fuzzer.mutation import Mutation, MutationType
        
        mutation = Mutation(
            mutation_type=MutationType.SQL_INJECTION,
            original_value="test",
            mutated_value="' OR '1'='1",
            location="param",
            field_name="id",
            description="SQL injection in param id"
        )
        
        result = FuzzingResult(
            mutation=mutation,
            original_status=200,
            fuzzed_status=500,
            response_diff=True,
            error_detected=True,
            duration_ms=100.0,
            anomaly_score=0.8
        )
        
        assert result.anomaly_score == 0.8
        
        data = result.to_dict()
        assert "mutation_type" in data
        assert "anomaly_score" in data
    
    def test_fuzzing_session_dataclass(self):
        """Test FuzzingSession dataclass."""
        from src.community.fuzzer.http_fuzzer import FuzzingSession, FuzzingStrategy
        
        session = FuzzingSession(
            session_id="session-123",
            flow_id="flow-456",
            strategy=FuzzingStrategy.ALL,
            total_mutations=100
        )
        
        assert session.status == "running"
        
        data = session.to_dict()
        assert "progress_percent" in data
    
    def test_fuzzer_initialization(self):
        """Test HTTPFuzzer initialization."""
        from src.community.fuzzer.http_fuzzer import HTTPFuzzer
        from src.community.replay.replayer import RequestReplayer
        
        replayer = RequestReplayer()
        fuzzer = HTTPFuzzer(
            replayer=replayer,
            max_concurrent=5,
            delay_ms=50
        )
        
        assert fuzzer.max_concurrent == 5
        assert fuzzer.delay_ms == 50
    
    def test_calculate_anomaly_score(self):
        """Test anomaly score calculation."""
        from src.community.fuzzer.http_fuzzer import HTTPFuzzer
        from src.community.replay.replayer import RequestReplayer
        
        replayer = RequestReplayer()
        fuzzer = HTTPFuzzer(replayer=replayer)
        
        # Same status - low score
        score = fuzzer._calculate_anomaly_score(200, 200, False, 100)
        assert score < 0.3
        
        # Server error - high score
        score = fuzzer._calculate_anomaly_score(200, 500, True, 100)
        assert score > 0.5


class TestWiresharkHelper:
    """Tests for Wireshark Helper."""
    
    @pytest.fixture
    def helper(self):
        """Create Wireshark helper."""
        from src.community.integrations.wireshark import WiresharkHelper
        return WiresharkHelper()
    
    def test_helper_initialization(self, helper):
        """Test helper initialization."""
        assert helper is not None
    
    def test_generate_filter_for_ip(self, helper):
        """Test IP filter generation."""
        filter_str = helper.generate_filter_for_ip("192.168.1.100")
        
        assert "192.168.1.100" in filter_str
        assert "ip.addr" in filter_str
    
    def test_generate_filter_for_host(self, helper):
        """Test host filter generation."""
        filter_str = helper.generate_filter_for_host("example.com")
        
        assert "example.com" in filter_str
    
    def test_generate_filter_for_session(self, helper):
        """Test session filter generation."""
        filter_str = helper.generate_filter_for_session(
            client_ip="192.168.1.100",
            server_ips=["10.0.0.1", "10.0.0.2"]
        )
        
        assert "192.168.1.100" in filter_str
        assert "10.0.0.1" in filter_str
    
    def test_generate_filter_for_flow(self, helper):
        """Test flow filter generation."""
        filter_str = helper.generate_filter_for_flow(
            method="GET",
            host="api.example.com",
            path="/users"
        )
        
        assert "GET" in filter_str
        assert "api.example.com" in filter_str
    
    def test_generate_filter_for_port(self, helper):
        """Test port filter generation."""
        filter_str = helper.generate_filter_for_port(8080)
        
        assert "8080" in filter_str


class TestBurpExporter:
    """Tests for Burp Suite Exporter."""
    
    @pytest.fixture
    def exporter(self):
        """Create Burp exporter."""
        from src.community.integrations.burp import BurpExporter
        with tempfile.TemporaryDirectory() as tmpdir:
            yield BurpExporter(output_dir=tmpdir)
    
    def test_exporter_initialization(self, exporter):
        """Test exporter initialization."""
        assert exporter is not None
        assert exporter.output_dir.exists()
    
    def test_export_session(self, exporter):
        """Test session export."""
        flows = [
            {
                "flow_id": "flow-1",
                "session_id": "session-123",
                "method": "GET",
                "url": "https://example.com/api",
                "host": "example.com",
                "path": "/api",
                "status_code": 200,
                "request_headers": {"User-Agent": "Test"},
                "response_headers": {"Content-Type": "application/json"},
                "timestamp": datetime.utcnow()
            }
        ]
        
        output_file = exporter.export_session("session-123", flows)
        
        assert Path(output_file).exists()
        
        # Check XML content
        with open(output_file) as f:
            content = f.read()
            assert "example.com" in content
            assert "items" in content
    
    def test_extract_port(self, exporter):
        """Test port extraction from URL."""
        assert exporter._extract_port("https://example.com") == 443
        assert exporter._extract_port("http://example.com") == 80
        assert exporter._extract_port("http://example.com:8080") == 8080
    
    def test_extract_extension(self, exporter):
        """Test file extension extraction."""
        assert exporter._extract_extension("/api/users.json") == "json"
        assert exporter._extract_extension("/api/users") == ""
    
    def test_get_status_text(self, exporter):
        """Test HTTP status text."""
        assert exporter._get_status_text(200) == "OK"
        assert exporter._get_status_text(404) == "Not Found"
        assert exporter._get_status_text(500) == "Internal Server Error"


class TestCloudBackupManager:
    """Tests for Cloud Backup Manager."""
    
    def test_cloud_provider_enum(self):
        """Test CloudProvider enum."""
        from src.community.cloud.backup import CloudProvider
        
        assert CloudProvider.S3.value == "s3"
        assert CloudProvider.GCS.value == "gcs"
    
    def test_backup_job_dataclass(self):
        """Test BackupJob dataclass."""
        from src.community.cloud.backup import BackupJob, CloudProvider
        
        job = BackupJob(
            file_path="/tmp/test.pcap",
            provider=CloudProvider.S3,
            bucket="test-bucket",
            key="pcap/test.pcap"
        )
        
        assert job.file_path == "/tmp/test.pcap"
        assert job.attempts == 0
    
    def test_manager_initialization(self):
        """Test CloudBackupManager initialization."""
        from src.community.cloud.backup import CloudBackupManager
        
        manager = CloudBackupManager(
            provider="s3",
            config={"bucket": "test-bucket", "region": "us-east-1"}
        )
        
        assert manager.provider.value == "s3"
    
    def test_generate_key(self):
        """Test key generation."""
        from src.community.cloud.backup import CloudBackupManager
        
        manager = CloudBackupManager(provider="s3", config={})
        
        key = manager._generate_key(Path("/tmp/capture.pcap"))
        
        assert "pcap/" in key
        assert "capture.pcap" in key
    
    def test_get_stats(self):
        """Test getting backup statistics."""
        from src.community.cloud.backup import CloudBackupManager
        
        manager = CloudBackupManager(
            provider="s3",
            config={"bucket": "test-bucket"}
        )
        
        stats = manager.get_stats()
        
        assert "provider" in stats
        assert "bucket" in stats
        assert "retry_queue_size" in stats
    
    @pytest.mark.asyncio
    async def test_backup_nonexistent_file(self):
        """Test backup of nonexistent file."""
        from src.community.cloud.backup import CloudBackupManager
        
        manager = CloudBackupManager(provider="s3", config={})
        
        result = await manager.backup_file("/nonexistent/file.pcap")
        
        assert result is False

