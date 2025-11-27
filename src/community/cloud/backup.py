"""
@fileoverview Cloud Backup Manager - PCAP backup to cloud storage
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Cloud backup manager for uploading PCAP files to S3 or GCS.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

import asyncio
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from ..core.logging import get_logger
from ..core.errors import ResourceError

log = get_logger(__name__)


class CloudProvider(str, Enum):
    """Supported cloud providers."""
    S3 = "s3"
    GCS = "gcs"


@dataclass
class BackupJob:
    """Backup job for retry queue."""
    file_path: str
    provider: CloudProvider
    bucket: str
    key: str
    created_at: datetime = field(default_factory=datetime.utcnow)
    attempts: int = 0
    last_error: Optional[str] = None


class CloudBackupManager:
    """
    Cloud backup manager for PCAP files.
    
    Features:
    - S3 and GCS support
    - Retry queue with max size
    - Async uploads
    
    FAIL-FAST: Queue overflow (>1000 items) is fatal.
    """
    
    MAX_RETRY_QUEUE = 1000
    MAX_RETRY_ATTEMPTS = 3
    
    def __init__(
        self,
        provider: str,
        config: Dict[str, Any],
        redis_queue=None
    ):
        """
        Initialize cloud backup manager.
        
        Args:
            provider: Cloud provider ("s3" or "gcs")
            config: Provider configuration
            redis_queue: Optional Redis queue for persistence
        """
        self.provider = CloudProvider(provider)
        self.config = config
        self.redis_queue = redis_queue
        
        # Retry queue (in-memory, backed by Redis if available)
        self.retry_queue: List[BackupJob] = []
        
        # Provider-specific clients (lazy initialized)
        self._s3_client = None
        self._gcs_client = None
        
        log.info(
            "cloud_backup_manager_initialized",
            provider=provider,
            bucket=config.get("bucket", "")
        )
    
    async def backup_file(
        self,
        file_path: str,
        key: Optional[str] = None
    ) -> bool:
        """
        Backup file to cloud storage.
        
        Args:
            file_path: Local file path
            key: Remote key/path (auto-generated if None)
            
        Returns:
            True if successful
            
        Raises:
            ResourceError: If retry queue overflow
        """
        path = Path(file_path)
        if not path.exists():
            log.error("backup_file_not_found", path=file_path)
            return False
        
        if key is None:
            key = self._generate_key(path)
        
        bucket = self.config.get("bucket", "")
        
        job = BackupJob(
            file_path=file_path,
            provider=self.provider,
            bucket=bucket,
            key=key
        )
        
        success = await self._upload(job)
        
        if not success:
            await self._enqueue_retry(job)
        
        return success
    
    async def _upload(self, job: BackupJob) -> bool:
        """
        Upload file to cloud storage.
        
        Args:
            job: Backup job
            
        Returns:
            True if successful
        """
        job.attempts += 1
        
        try:
            if job.provider == CloudProvider.S3:
                return await self._upload_s3(job)
            elif job.provider == CloudProvider.GCS:
                return await self._upload_gcs(job)
            else:
                log.error("unknown_cloud_provider", provider=job.provider)
                return False
                
        except Exception as e:
            job.last_error = str(e)
            log.error(
                "cloud_upload_failed",
                file=job.file_path,
                provider=job.provider.value,
                error=str(e)
            )
            return False
    
    async def _upload_s3(self, job: BackupJob) -> bool:
        """Upload to S3."""
        try:
            import boto3
            from botocore.exceptions import ClientError
        except ImportError:
            log.error("boto3_not_installed")
            job.last_error = "boto3 not installed"
            return False
        
        if self._s3_client is None:
            self._s3_client = boto3.client(
                "s3",
                region_name=self.config.get("region", "us-east-1"),
                aws_access_key_id=self.config.get("access_key_id"),
                aws_secret_access_key=self.config.get("secret_access_key")
            )
        
        try:
            self._s3_client.upload_file(
                job.file_path,
                job.bucket,
                job.key
            )
            
            log.info(
                "s3_upload_success",
                file=job.file_path,
                bucket=job.bucket,
                key=job.key
            )
            return True
            
        except ClientError as e:
            job.last_error = str(e)
            return False
    
    async def _upload_gcs(self, job: BackupJob) -> bool:
        """Upload to Google Cloud Storage."""
        try:
            from google.cloud import storage
        except ImportError:
            log.error("google_cloud_storage_not_installed")
            job.last_error = "google-cloud-storage not installed"
            return False
        
        if self._gcs_client is None:
            credentials_file = self.config.get("credentials_file")
            if credentials_file:
                self._gcs_client = storage.Client.from_service_account_json(
                    credentials_file
                )
            else:
                self._gcs_client = storage.Client(
                    project=self.config.get("project_id")
                )
        
        try:
            bucket = self._gcs_client.bucket(job.bucket)
            blob = bucket.blob(job.key)
            blob.upload_from_filename(job.file_path)
            
            log.info(
                "gcs_upload_success",
                file=job.file_path,
                bucket=job.bucket,
                key=job.key
            )
            return True
            
        except Exception as e:
            job.last_error = str(e)
            return False
    
    async def _enqueue_retry(self, job: BackupJob) -> None:
        """
        Enqueue job for retry.
        
        FAIL-FAST: Raises ResourceError if queue overflow.
        """
        if len(self.retry_queue) >= self.MAX_RETRY_QUEUE:
            raise ResourceError(
                f"Cloud backup retry queue overflow ({len(self.retry_queue)}/{self.MAX_RETRY_QUEUE}).\n"
                "Check network connectivity or disable cloud backup.\n"
                "Solution: Clear queue or increase MAX_RETRY_QUEUE."
            )
        
        if job.attempts < self.MAX_RETRY_ATTEMPTS:
            self.retry_queue.append(job)
            log.warning(
                "backup_job_queued_for_retry",
                file=job.file_path,
                attempts=job.attempts,
                queue_size=len(self.retry_queue)
            )
        else:
            log.error(
                "backup_job_max_retries_exceeded",
                file=job.file_path,
                attempts=job.attempts,
                last_error=job.last_error
            )
    
    async def process_retry_queue(self) -> int:
        """
        Process retry queue.
        
        Returns:
            Number of successful retries
        """
        if not self.retry_queue:
            return 0
        
        successful = 0
        remaining = []
        
        for job in self.retry_queue:
            success = await self._upload(job)
            
            if success:
                successful += 1
            elif job.attempts < self.MAX_RETRY_ATTEMPTS:
                remaining.append(job)
        
        self.retry_queue = remaining
        
        log.info(
            "retry_queue_processed",
            successful=successful,
            remaining=len(remaining)
        )
        
        return successful
    
    def _generate_key(self, path: Path) -> str:
        """Generate cloud storage key from file path."""
        timestamp = datetime.utcnow().strftime("%Y/%m/%d")
        return f"pcap/{timestamp}/{path.name}"
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get backup statistics.
        
        Returns:
            Statistics dictionary
        """
        return {
            "provider": self.provider.value,
            "bucket": self.config.get("bucket", ""),
            "retry_queue_size": len(self.retry_queue),
            "max_retry_queue": self.MAX_RETRY_QUEUE,
            "queue_full": len(self.retry_queue) >= self.MAX_RETRY_QUEUE
        }

