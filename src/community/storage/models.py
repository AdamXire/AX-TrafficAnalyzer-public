"""
@fileoverview Database Models - SQLAlchemy ORM models
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

SQLAlchemy models for persistent storage.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, Boolean, ForeignKey, Text, JSON, Float, LargeBinary
from sqlalchemy.orm import declarative_base, relationship
import bcrypt

Base = declarative_base()


class User(Base):
    """User model for authentication."""
    
    __tablename__ = "users"
    
    id = Column(String, primary_key=True)
    username = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="viewer", nullable=False)  # admin, analyst, viewer
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login = Column(DateTime, nullable=True)
    active = Column(Boolean, default=True, nullable=False)
    
    def verify_password(self, password: str) -> bool:
        """Verify password against hash."""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
        except Exception:
            return False
    
    def to_dict(self) -> dict:
        """Convert to dictionary (exclude password)."""
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "active": self.active
        }


class SessionDB(Base):
    """Session model for persistent storage."""
    
    __tablename__ = "sessions"
    
    session_id = Column(String, primary_key=True)
    client_ip = Column(String, nullable=False, index=True)
    mac_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    last_activity = Column(DateTime, default=datetime.utcnow, nullable=False)
    request_count = Column(Integer, default=0, nullable=False)
    
    # Relationships
    flows = relationship("FlowDB", back_populates="session", cascade="all, delete-orphan")
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "session_id": self.session_id,
            "client_ip": self.client_ip,
            "mac_address": self.mac_address,
            "user_agent": self.user_agent,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_activity": self.last_activity.isoformat() if self.last_activity else None,
            "request_count": self.request_count
        }


class FlowDB(Base):
    """HTTP flow model for persistent storage."""
    
    __tablename__ = "flows"
    
    flow_id = Column(String, primary_key=True)
    session_id = Column(String, ForeignKey("sessions.session_id"), nullable=False, index=True)
    method = Column(String, nullable=False)  # GET, POST, etc.
    url = Column(Text, nullable=False)
    host = Column(String, nullable=True, index=True)
    path = Column(String, nullable=True)
    status_code = Column(Integer, nullable=True)
    request_size = Column(Integer, default=0, nullable=False)
    response_size = Column(Integer, default=0, nullable=False)
    content_type = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Phase 5: Analysis fields
    request_headers = Column(JSON, nullable=True)  # HTTP request headers
    response_headers = Column(JSON, nullable=True)  # HTTP response headers
    cookies = Column(JSON, nullable=True)  # Cookies from Set-Cookie header
    auth_detected = Column(String, nullable=True, index=True)  # Basic, Bearer, OAuth, etc.
    sensitive_data_found = Column(Boolean, default=False, nullable=False, index=True)  # PII/credentials flag
    duration_ms = Column(Integer, nullable=True)  # Request/response duration
    
    # Relationships
    session = relationship("SessionDB", back_populates="flows")
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "flow_id": self.flow_id,
            "session_id": self.session_id,
            "method": self.method,
            "url": self.url,
            "host": self.host,
            "path": self.path,
            "status_code": self.status_code,
            "request_size": self.request_size,
            "response_size": self.response_size,
            "content_type": self.content_type,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            # Phase 5 fields
            "request_headers": self.request_headers,
            "response_headers": self.response_headers,
            "cookies": self.cookies,
            "auth_detected": self.auth_detected,
            "sensitive_data_found": self.sensitive_data_found,
            "duration_ms": self.duration_ms
        }


class FindingDB(Base):
    """Vulnerability/anomaly finding model for Phase 5 analysis."""
    
    __tablename__ = "findings"
    
    id = Column(String, primary_key=True)
    session_id = Column(String, ForeignKey("sessions.session_id", ondelete="CASCADE"), nullable=False, index=True)
    flow_id = Column(String, ForeignKey("flows.flow_id", ondelete="CASCADE"), nullable=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    severity = Column(String, nullable=False, index=True)  # critical, high, medium, low, info
    category = Column(String, nullable=False, index=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    recommendation = Column(Text, nullable=True)
    meta_data = Column(JSON, nullable=True)  # Renamed from 'metadata' (SQLAlchemy reserved)
    
    # Relationships
    session = relationship("SessionDB", backref="findings")
    flow = relationship("FlowDB", backref="findings")
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "session_id": self.session_id,
            "flow_id": self.flow_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "metadata": self.meta_data  # Map meta_data to metadata in API
        }


class AnalysisResultDB(Base):
    """Protocol analysis result model for Phase 5."""
    
    __tablename__ = "analysis_results"
    
    id = Column(String, primary_key=True)
    flow_id = Column(String, ForeignKey("flows.flow_id", ondelete="CASCADE"), nullable=False, index=True)
    analyzer_name = Column(String, nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    meta_data = Column(JSON, nullable=True)  # Renamed from 'metadata' (SQLAlchemy reserved)
    
    # Relationships
    flow = relationship("FlowDB", backref="analysis_results")
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "flow_id": self.flow_id,
            "analyzer_name": self.analyzer_name,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "metadata": self.meta_data  # Map meta_data to metadata in API
        }


class ThreatIntelCacheDB(Base):
    """Threat intelligence cache model for Phase 5."""
    
    __tablename__ = "threat_intel_cache"
    
    domain = Column(String, primary_key=True)
    source = Column(String, primary_key=True)  # virustotal, otx, etc.
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    reputation = Column(String, nullable=True, index=True)  # clean, suspicious, malicious
    meta_data = Column(JSON, nullable=True)  # Renamed from 'metadata' (SQLAlchemy reserved)
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "domain": self.domain,
            "source": self.source,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "reputation": self.reputation,
            "metadata": self.meta_data  # Map meta_data to metadata in API
        }


class DNSQueryDB(Base):
    """DNS query model for Phase 5 analysis."""
    
    __tablename__ = "dns_queries"
    
    id = Column(String, primary_key=True)
    session_id = Column(String, ForeignKey("sessions.session_id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    query = Column(String, nullable=False, index=True)  # domain name
    query_type = Column(String, nullable=False)  # A, AAAA, CNAME, etc.
    response = Column(JSON, nullable=True)  # resolved IPs, CNAME chain, etc.
    
    # Relationships
    session = relationship("SessionDB", backref="dns_queries")
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "session_id": self.session_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "query": self.query,
            "query_type": self.query_type,
            "response": self.response
        }


class PluginDataDB(Base):
    """Plugin data storage model (Phase 6)."""
    
    __tablename__ = "plugin_data"
    
    id = Column(String, primary_key=True)
    plugin_name = Column(String, nullable=False, index=True)
    session_id = Column(String, ForeignKey("sessions.session_id", ondelete="SET NULL"), nullable=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    data = Column(JSON, nullable=False)
    
    # Relationships
    session = relationship("SessionDB", backref="plugin_data")
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "plugin_name": self.plugin_name,
            "session_id": self.session_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "data": self.data
        }


class WiFiFrameDB(Base):
    """WiFi 802.11 frame model (Phase 7)."""
    
    __tablename__ = "wifi_frames"
    
    id = Column(String, primary_key=True)
    session_id = Column(String, ForeignKey("sessions.session_id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    frame_type = Column(String, nullable=False, index=True)  # beacon, probe_request, data, etc.
    source_mac = Column(String, nullable=False, index=True)
    dest_mac = Column(String, nullable=False)
    bssid = Column(String, nullable=True, index=True)
    ssid = Column(String, nullable=True, index=True)
    signal_strength = Column(Integer, nullable=True)  # dBm
    channel = Column(Integer, nullable=True)
    raw_data = Column(LargeBinary, nullable=True)
    
    # Relationships
    session = relationship("SessionDB", backref="wifi_frames")
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "session_id": self.session_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "frame_type": self.frame_type,
            "source_mac": self.source_mac,
            "dest_mac": self.dest_mac,
            "bssid": self.bssid,
            "ssid": self.ssid,
            "signal_strength": self.signal_strength,
            "channel": self.channel
        }

