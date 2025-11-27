"""
@fileoverview HTTP Fuzzer - Automated HTTP request fuzzing
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

HTTP fuzzer for automated security testing.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

import asyncio
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from uuid import uuid4
from enum import Enum
from .mutation import MutationEngine, Mutation, MutationType
from ..replay import RequestReplayer
from ..core.logging import get_logger

log = get_logger(__name__)


class FuzzingStrategy(str, Enum):
    """Fuzzing strategies."""
    HEADERS = "headers"
    PARAMS = "params"
    BODY = "body"
    ALL = "all"


@dataclass
class FuzzingResult:
    """Result of a single fuzzing attempt."""
    mutation: Mutation
    original_status: int
    fuzzed_status: int
    response_diff: bool
    error_detected: bool
    duration_ms: float
    anomaly_score: float = 0.0
    notes: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "mutation_type": self.mutation.mutation_type.value,
            "location": self.mutation.location,
            "field_name": self.mutation.field_name,
            "original_value": self.mutation.original_value,
            "mutated_value": self.mutation.mutated_value[:100],  # Truncate
            "original_status": self.original_status,
            "fuzzed_status": self.fuzzed_status,
            "response_diff": self.response_diff,
            "error_detected": self.error_detected,
            "duration_ms": self.duration_ms,
            "anomaly_score": self.anomaly_score,
            "notes": self.notes
        }


@dataclass
class FuzzingSession:
    """Fuzzing session tracking."""
    session_id: str
    flow_id: str
    strategy: FuzzingStrategy
    status: str = "running"
    total_mutations: int = 0
    completed_mutations: int = 0
    anomalies_found: int = 0
    results: List[FuzzingResult] = field(default_factory=list)
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "session_id": self.session_id,
            "flow_id": self.flow_id,
            "strategy": self.strategy.value,
            "status": self.status,
            "total_mutations": self.total_mutations,
            "completed_mutations": self.completed_mutations,
            "anomalies_found": self.anomalies_found,
            "progress_percent": (
                self.completed_mutations / self.total_mutations * 100
                if self.total_mutations > 0 else 0
            ),
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None
        }


class HTTPFuzzer:
    """
    HTTP fuzzer for automated security testing.
    
    Features:
    - Multiple fuzzing strategies (headers, params, body, all)
    - Anomaly detection (status code changes, errors, timing)
    - Session management
    - Rate limiting
    """
    
    def __init__(
        self,
        replayer: RequestReplayer,
        mutation_engine: Optional[MutationEngine] = None,
        max_concurrent: int = 5,
        delay_ms: int = 100
    ):
        """
        Initialize HTTP fuzzer.
        
        Args:
            replayer: Request replayer for sending mutations
            mutation_engine: Mutation engine (creates default if None)
            max_concurrent: Maximum concurrent requests
            delay_ms: Delay between requests in milliseconds
        """
        self.replayer = replayer
        self.mutation_engine = mutation_engine or MutationEngine()
        self.max_concurrent = max_concurrent
        self.delay_ms = delay_ms
        self._semaphore = asyncio.Semaphore(max_concurrent)
        
        # Active sessions
        self.sessions: Dict[str, FuzzingSession] = {}
        
        log.info(
            "http_fuzzer_initialized",
            max_concurrent=max_concurrent,
            delay_ms=delay_ms
        )
    
    async def fuzz_flow(
        self,
        flow_id: str,
        flow_data: Dict[str, Any],
        strategy: FuzzingStrategy = FuzzingStrategy.ALL
    ) -> FuzzingSession:
        """
        Fuzz a captured flow.
        
        Args:
            flow_id: ID of flow to fuzz
            flow_data: Flow data dictionary
            strategy: Fuzzing strategy
            
        Returns:
            FuzzingSession with results
        """
        session_id = str(uuid4())
        session = FuzzingSession(
            session_id=session_id,
            flow_id=flow_id,
            strategy=strategy
        )
        self.sessions[session_id] = session
        
        log.info(
            "fuzzing_started",
            session_id=session_id,
            flow_id=flow_id,
            strategy=strategy.value
        )
        
        try:
            # Generate mutations
            mutations = self._generate_mutations(flow_data, strategy)
            session.total_mutations = len(mutations)
            
            if not mutations:
                session.status = "completed"
                session.completed_at = datetime.utcnow()
                return session
            
            # Get baseline response
            baseline = await self.replayer.replay_flow(flow_id)
            baseline_status = baseline.status_code or 0
            
            # Execute mutations
            for mutation_data in mutations:
                if session.status == "stopped":
                    break
                
                result = await self._execute_mutation(
                    flow_data,
                    mutation_data,
                    baseline_status
                )
                
                session.results.append(result)
                session.completed_mutations += 1
                
                if result.anomaly_score > 0.5:
                    session.anomalies_found += 1
                
                # Rate limiting
                await asyncio.sleep(self.delay_ms / 1000)
            
            session.status = "completed"
            session.completed_at = datetime.utcnow()
            
        except Exception as e:
            log.error("fuzzing_failed", session_id=session_id, error=str(e))
            session.status = "failed"
            session.completed_at = datetime.utcnow()
        
        log.info(
            "fuzzing_completed",
            session_id=session_id,
            mutations=session.completed_mutations,
            anomalies=session.anomalies_found
        )
        
        return session
    
    def _generate_mutations(
        self,
        flow_data: Dict[str, Any],
        strategy: FuzzingStrategy
    ) -> List[Dict[str, Any]]:
        """Generate mutations based on strategy."""
        mutations = []
        
        headers = flow_data.get("request_headers", {}) or {}
        url = flow_data.get("url", "")
        body = flow_data.get("request_body")
        content_type = headers.get("Content-Type", "")
        
        if isinstance(body, str):
            body = body.encode("utf-8")
        
        if strategy in [FuzzingStrategy.HEADERS, FuzzingStrategy.ALL]:
            mutations.extend(self.mutation_engine.mutate_headers(headers))
        
        if strategy in [FuzzingStrategy.PARAMS, FuzzingStrategy.ALL]:
            mutations.extend(self.mutation_engine.mutate_params(url))
        
        if strategy in [FuzzingStrategy.BODY, FuzzingStrategy.ALL]:
            if body:
                mutations.extend(
                    self.mutation_engine.mutate_body(body, content_type)
                )
        
        return mutations
    
    async def _execute_mutation(
        self,
        flow_data: Dict[str, Any],
        mutation_data: Dict[str, Any],
        baseline_status: int
    ) -> FuzzingResult:
        """Execute a single mutation and analyze result."""
        mutation = mutation_data["mutation"]
        
        # Build modifications
        modifications = {}
        
        if "headers" in mutation_data:
            modifications["headers"] = mutation_data["headers"]
        
        if "url" in mutation_data:
            modifications["url"] = mutation_data["url"]
        
        if "body" in mutation_data:
            modifications["body"] = mutation_data["body"]
        
        # Execute replay with modifications
        async with self._semaphore:
            start_time = datetime.utcnow()
            
            result = await self.replayer.replay_flow(
                flow_data.get("flow_id", ""),
                modifications
            )
            
            duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        # Analyze result
        fuzzed_status = result.status_code or 0
        response_diff = fuzzed_status != baseline_status
        error_detected = fuzzed_status >= 500 or not result.success
        
        # Calculate anomaly score
        anomaly_score = self._calculate_anomaly_score(
            baseline_status,
            fuzzed_status,
            error_detected,
            duration_ms
        )
        
        notes = []
        if response_diff:
            notes.append(f"Status changed: {baseline_status} -> {fuzzed_status}")
        if error_detected:
            notes.append("Server error detected")
        if anomaly_score > 0.7:
            notes.append("High anomaly score - potential vulnerability")
        
        return FuzzingResult(
            mutation=mutation,
            original_status=baseline_status,
            fuzzed_status=fuzzed_status,
            response_diff=response_diff,
            error_detected=error_detected,
            duration_ms=duration_ms,
            anomaly_score=anomaly_score,
            notes=notes
        )
    
    def _calculate_anomaly_score(
        self,
        baseline_status: int,
        fuzzed_status: int,
        error_detected: bool,
        duration_ms: float
    ) -> float:
        """
        Calculate anomaly score for a mutation result.
        
        Score from 0.0 (normal) to 1.0 (highly anomalous).
        """
        score = 0.0
        
        # Status code change
        if fuzzed_status != baseline_status:
            score += 0.3
            
            # Server error is more significant
            if fuzzed_status >= 500:
                score += 0.3
            
            # Auth/forbidden might indicate bypass attempt
            if fuzzed_status in [401, 403]:
                score += 0.1
        
        # Error detection
        if error_detected:
            score += 0.2
        
        # Timing anomaly (very slow response)
        if duration_ms > 5000:
            score += 0.1
        
        return min(score, 1.0)
    
    def stop_session(self, session_id: str) -> bool:
        """
        Stop a fuzzing session.
        
        Args:
            session_id: Session ID to stop
            
        Returns:
            True if stopped, False if not found
        """
        if session_id not in self.sessions:
            return False
        
        self.sessions[session_id].status = "stopped"
        self.sessions[session_id].completed_at = datetime.utcnow()
        
        log.info("fuzzing_stopped", session_id=session_id)
        return True
    
    def get_session(self, session_id: str) -> Optional[FuzzingSession]:
        """Get session by ID."""
        return self.sessions.get(session_id)
    
    def get_session_results(
        self,
        session_id: str,
        min_anomaly_score: float = 0.0
    ) -> List[Dict[str, Any]]:
        """
        Get filtered results for a session.
        
        Args:
            session_id: Session ID
            min_anomaly_score: Minimum anomaly score to include
            
        Returns:
            List of result dictionaries
        """
        session = self.sessions.get(session_id)
        if not session:
            return []
        
        return [
            r.to_dict() for r in session.results
            if r.anomaly_score >= min_anomaly_score
        ]

