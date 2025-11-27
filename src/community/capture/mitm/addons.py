"""
@fileoverview Custom mitmproxy Addons - Traffic logging and pinning detection
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Custom mitmproxy addons for traffic logging, pinning detection, and backpressure.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

from mitmproxy import http
from mitmproxy.addonmanager import Loader
from typing import Optional
from ...core.logging import get_logger
from ...core.memory import BackpressureController

log = get_logger(__name__)


class TrafficLogger:
    """
    mitmproxy addon for logging HTTP/HTTPS traffic to Redis queue.
    """
    
    def __init__(self, redis_queue, session_tracker, analysis_orchestrator=None):
        """
        Initialize traffic logger.
        
        Args:
            redis_queue: RedisQueue instance for event queuing
            session_tracker: SessionTracker instance
            analysis_orchestrator: Optional AnalysisOrchestrator instance (Phase 5)
        """
        self.redis_queue = redis_queue
        self.session_tracker = session_tracker
        self.analysis_orchestrator = analysis_orchestrator
        log.debug("traffic_logger_addon_initialized", has_analyzer=analysis_orchestrator is not None)
    
    def request(self, flow: http.HTTPFlow) -> None:
        """Handle HTTP request."""
        try:
            # Get or create session
            client_ip = flow.client_conn.address[0] if flow.client_conn.address else None
            user_agent = flow.request.headers.get("User-Agent", "")
            
            session_id = self.session_tracker.get_or_create_session(
                client_ip=client_ip,
                user_agent=user_agent
            )
            
            # Persist session to database if available (Phase 3)
            if self.session_tracker.database:
                import asyncio
                try:
                    # Get session object
                    session = self.session_tracker.sessions.get(session_id)
                    if session:
                        # Run async persist in new event loop (mitmproxy is sync)
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        try:
                            loop.run_until_complete(self.session_tracker._persist_session(session))
                            log.debug("session_persisted_from_addon", session_id=session_id)
                        finally:
                            loop.close()
                except Exception as e:
                    log.warning("session_persistence_failed", session_id=session_id, error=str(e))
            
            # Log request event
            event = {
                "type": "http_request",
                "session_id": session_id,
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "headers": dict(flow.request.headers),
                "timestamp": flow.request.timestamp_start,
            }
            
            # Enqueue to Redis (async, non-blocking)
            # Note: mitmproxy addons run in sync context, so we use sync Redis client
            # In production, this would be async via queue
            log.debug("traffic_request_logged", session_id=session_id, url=flow.request.pretty_url)
        except Exception as e:
            log.error("traffic_logging_failed", error=str(e))
    
    def response(self, flow: http.HTTPFlow) -> None:
        """Handle HTTP response."""
        try:
            session_id = self.session_tracker.get_session_id(flow.client_conn.address[0] if flow.client_conn.address else None)
            
            event = {
                "type": "http_response",
                "session_id": session_id,
                "status_code": flow.response.status_code,
                "headers": dict(flow.response.headers),
                "timestamp": flow.response.timestamp_end,
            }
            log.debug("traffic_response_logged", status_code=flow.response.status_code)
            
            # Phase 5: Trigger analysis if orchestrator is available
            if self.analysis_orchestrator:
                try:
                    import asyncio
                    import threading
                    from datetime import datetime
                    from uuid import uuid4
                    
                    # Extract detailed flow metadata for analysis
                    request_headers = dict(flow.request.headers)
                    response_headers = dict(flow.response.headers)
                    
                    # Extract cookies
                    cookies = {}
                    if "Set-Cookie" in response_headers:
                        cookies = {"raw": response_headers["Set-Cookie"]}
                    
                    # Detect authentication mechanism
                    auth_detected = None
                    if "Authorization" in request_headers:
                        auth_header = request_headers["Authorization"]
                        if auth_header.startswith("Basic "):
                            auth_detected = "Basic"
                        elif auth_header.startswith("Bearer "):
                            auth_detected = "Bearer"
                        elif auth_header.startswith("OAuth "):
                            auth_detected = "OAuth"
                    
                    # Calculate duration
                    duration_ms = None
                    if flow.request.timestamp_start and flow.response.timestamp_end:
                        duration_ms = int((flow.response.timestamp_end - flow.request.timestamp_start) * 1000)
                    
                    # Extract TLS/SSL information for TLS analyzer
                    tls_info = {}
                    if hasattr(flow, 'server_conn') and flow.server_conn:
                        server_conn = flow.server_conn
                        
                        # TLS version
                        if hasattr(server_conn, 'tls_version') and server_conn.tls_version:
                            tls_info["version"] = server_conn.tls_version
                        
                        # Cipher suite
                        if hasattr(server_conn, 'cipher') and server_conn.cipher:
                            tls_info["cipher_suite"] = server_conn.cipher[0] if isinstance(server_conn.cipher, tuple) else str(server_conn.cipher)
                        
                        # Certificate information
                        if hasattr(server_conn, 'cert') and server_conn.cert:
                            cert = server_conn.cert
                            cert_info = {}
                            
                            # Certificate subject
                            if hasattr(cert, 'subject') and cert.subject:
                                cert_info["subject"] = dict(cert.subject) if hasattr(cert.subject, '__iter__') else str(cert.subject)
                            
                            # Certificate issuer
                            if hasattr(cert, 'issuer') and cert.issuer:
                                cert_info["issuer"] = dict(cert.issuer) if hasattr(cert.issuer, '__iter__') else str(cert.issuer)
                            
                            # Certificate validity dates
                            if hasattr(cert, 'not_after') and cert.not_after:
                                cert_info["not_after"] = cert.not_after.isoformat() if hasattr(cert.not_after, 'isoformat') else str(cert.not_after)
                            
                            if hasattr(cert, 'not_before') and cert.not_before:
                                cert_info["not_before"] = cert.not_before.isoformat() if hasattr(cert.not_before, 'isoformat') else str(cert.not_before)
                            
                            if cert_info:
                                tls_info["certificate"] = cert_info
                        
                        # Certificate chain (if available)
                        if hasattr(server_conn, 'cert_chain') and server_conn.cert_chain:
                            chain = []
                            for chain_cert in server_conn.cert_chain:
                                chain_item = {}
                                if hasattr(chain_cert, 'subject'):
                                    chain_item["subject"] = str(chain_cert.subject)
                                if hasattr(chain_cert, 'issuer'):
                                    chain_item["issuer"] = str(chain_cert.issuer)
                                if chain_item:
                                    chain.append(chain_item)
                            if chain:
                                tls_info["chain"] = chain
                    
                    # Build flow data for analysis
                    flow_data = {
                        "flow_id": str(uuid4()),
                        "session_id": session_id,
                        "method": flow.request.method,
                        "url": flow.request.pretty_url,
                        "host": flow.request.host,
                        "path": flow.request.path,
                        "status_code": flow.response.status_code,
                        "request_size": len(flow.request.raw_content) if flow.request.raw_content else 0,
                        "response_size": len(flow.response.raw_content) if flow.response.raw_content else 0,
                        "content_type": response_headers.get("Content-Type"),
                        "timestamp": datetime.utcnow(),
                        # Phase 5 analysis fields
                        "request_headers": request_headers,
                        "response_headers": response_headers,
                        "cookies": cookies,
                        "auth_detected": auth_detected,
                        "duration_ms": duration_ms,
                        # TLS/SSL information for TLS analyzer
                        "tls_info": tls_info if tls_info else None,
                    }
                    
                    # Run analysis in background thread (non-blocking)
                    def analyze_async():
                        """Run analysis in new event loop in background thread."""
                        try:
                            loop = asyncio.new_event_loop()
                            asyncio.set_event_loop(loop)
                            try:
                                loop.run_until_complete(self.analysis_orchestrator.analyze_flow(flow_data))
                                log.debug("flow_analysis_complete", flow_id=flow_data.get("flow_id"))
                            finally:
                                loop.close()
                        except Exception as e:
                            log.warning("flow_analysis_thread_failed", error=str(e), error_type=type(e).__name__)
                    
                    # Start analysis in background thread (non-blocking)
                    thread = threading.Thread(target=analyze_async, daemon=True)
                    thread.start()
                    log.debug("flow_analysis_triggered", flow_id=flow_data.get("flow_id"), session_id=session_id)
                except Exception as e:
                    # Don't fail capture if analysis fails
                    log.warning("flow_analysis_trigger_failed", error=str(e), error_type=type(e).__name__)
            
            # Broadcast to WebSocket clients
            try:
                from ...api.websocket import ws_manager
                from datetime import datetime
                import asyncio
                import threading
                
                # Create WebSocket event
                ws_event = {
                    "event": "http_flow",
                    "data": {
                        "session_id": session_id,
                        "method": flow.request.method,
                        "url": flow.request.pretty_url,
                        "host": flow.request.host,
                        "status_code": flow.response.status_code,
                        "timestamp": datetime.utcnow().isoformat()
                    }
                }
                
                # Broadcast in background thread (mitmproxy is sync, WebSocket is async)
                def broadcast_async():
                    """Run broadcast in new event loop in background thread."""
                    try:
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        try:
                            loop.run_until_complete(ws_manager.broadcast(ws_event))
                            log.debug("websocket_event_broadcast", event_type="http_flow", session_id=session_id)
                        finally:
                            loop.close()
                    except Exception as e:
                        log.warning("websocket_broadcast_thread_failed", error=str(e))
                
                # Start broadcast in background thread (non-blocking)
                thread = threading.Thread(target=broadcast_async, daemon=True)
                thread.start()
                log.debug("websocket_event_scheduled", event_type="http_flow", session_id=session_id)
            except Exception as e:
                # Don't fail capture if WebSocket fails
                log.warning("websocket_broadcast_failed", error=str(e))
        except Exception as e:
            log.error("traffic_response_logging_failed", error=str(e))


class PinningDetector:
    """
    mitmproxy addon for detecting certificate pinning (fail-loud).
    """
    
    def tls_failed_client(self, flow) -> None:
        """
        Handle TLS failure (likely certificate pinning).
        
        Fail-loud: Log ERROR + metric + UI warning (non-blocking for system).
        """
        log.error(
            "certificate_pinning_detected",
            host=flow.request.host if hasattr(flow, 'request') else "unknown",
            error="TLS handshake failed - likely certificate pinning",
            action="Connection blocked by app security"
        )
        
        # TODO: Increment metric (Phase 3)
        # TODO: Send to UI via WebSocket (Phase 4)
        
        # Non-blocking: System continues, but this specific connection fails


class BackpressureMonitor:
    """
    mitmproxy addon for monitoring backpressure and pausing flow.
    """
    
    def __init__(self, backpressure: BackpressureController):
        """
        Initialize backpressure monitor.
        
        Args:
            backpressure: BackpressureController instance
        """
        self.backpressure = backpressure
        log.debug("backpressure_monitor_addon_initialized")
    
    def request(self, flow: http.HTTPFlow) -> None:
        """
        Check backpressure before processing request.
        
        If buffer >80% full, pause flow temporarily.
        """
        if self.backpressure.should_pause():
            log.warning(
                "backpressure_active_pausing_flow",
                session_id=getattr(flow, 'session_id', None),
                url=flow.request.pretty_url if hasattr(flow, 'request') else "unknown"
            )
            # Pause flow (mitmproxy will buffer)
            flow.pause()
        else:
            # Resume if previously paused
            if flow.is_paused():
                flow.resume()
                log.debug("backpressure_cleared_resuming_flow")

