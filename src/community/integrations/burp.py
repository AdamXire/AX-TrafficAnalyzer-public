"""
@fileoverview Burp Suite Exporter - Export traffic to Burp format
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Export captured traffic to Burp Suite XML format.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

import base64
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
from xml.etree import ElementTree as ET
from xml.dom import minidom
from ..core.logging import get_logger

log = get_logger(__name__)


class BurpExporter:
    """
    Export traffic to Burp Suite XML format.
    
    Generates Burp Suite compatible XML files that can be
    imported into Burp for further analysis.
    """
    
    def __init__(self, output_dir: str = "./exports"):
        """
        Initialize Burp exporter.
        
        Args:
            output_dir: Directory for exported files
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        log.info("burp_exporter_initialized", output_dir=str(self.output_dir))
    
    def export_session(
        self,
        session_id: str,
        flows: List[Dict[str, Any]],
        output_file: Optional[str] = None
    ) -> str:
        """
        Export session flows to Burp XML format.
        
        Args:
            session_id: Session ID
            flows: List of flow dictionaries
            output_file: Output file path (auto-generated if None)
            
        Returns:
            Path to exported file
        """
        if not output_file:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            output_file = str(self.output_dir / f"burp_export_{session_id}_{timestamp}.xml")
        
        # Create root element
        root = ET.Element("items")
        root.set("burpVersion", "2023.0")
        root.set("exportTime", datetime.utcnow().isoformat())
        
        for flow in flows:
            item = self._create_item_element(flow)
            root.append(item)
        
        # Write XML
        xml_str = ET.tostring(root, encoding="unicode")
        # nosec B318 - XML is generated internally, not from untrusted input
        pretty_xml = minidom.parseString(xml_str).toprettyxml(indent="  ")  # nosec B318
        
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(pretty_xml)
        
        log.info(
            "burp_export_complete",
            session_id=session_id,
            flows=len(flows),
            output=output_file
        )
        
        return output_file
    
    def export_flow(
        self,
        flow: Dict[str, Any],
        output_file: Optional[str] = None
    ) -> str:
        """
        Export single flow to Burp XML format.
        
        Args:
            flow: Flow dictionary
            output_file: Output file path
            
        Returns:
            Path to exported file
        """
        return self.export_session(
            flow.get("session_id", "unknown"),
            [flow],
            output_file
        )
    
    def _create_item_element(self, flow: Dict[str, Any]) -> ET.Element:
        """Create Burp item element from flow."""
        item = ET.Element("item")
        
        # Time
        time_elem = ET.SubElement(item, "time")
        timestamp = flow.get("timestamp")
        if isinstance(timestamp, datetime):
            time_elem.text = timestamp.isoformat()
        elif isinstance(timestamp, str):
            time_elem.text = timestamp
        else:
            time_elem.text = datetime.utcnow().isoformat()
        
        # URL
        url_elem = ET.SubElement(item, "url")
        url_elem.text = flow.get("url", "")
        
        # Host
        host = ET.SubElement(item, "host")
        host.set("ip", flow.get("server_ip", ""))
        host.text = flow.get("host", "")
        
        # Port
        port_elem = ET.SubElement(item, "port")
        port = self._extract_port(flow.get("url", ""))
        port_elem.text = str(port)
        
        # Protocol
        protocol_elem = ET.SubElement(item, "protocol")
        protocol_elem.text = "https" if flow.get("url", "").startswith("https") else "http"
        
        # Method
        method_elem = ET.SubElement(item, "method")
        method_elem.text = flow.get("method", "GET")
        
        # Path
        path_elem = ET.SubElement(item, "path")
        path_elem.text = flow.get("path", "/")
        
        # Extension
        extension_elem = ET.SubElement(item, "extension")
        extension_elem.text = self._extract_extension(flow.get("path", ""))
        
        # Request
        request_elem = ET.SubElement(item, "request")
        request_elem.set("base64", "true")
        request_data = self._build_raw_request(flow)
        request_elem.text = base64.b64encode(request_data).decode("ascii")
        
        # Status
        status_elem = ET.SubElement(item, "status")
        status_elem.text = str(flow.get("status_code", 0))
        
        # Response length
        responselength_elem = ET.SubElement(item, "responselength")
        responselength_elem.text = str(flow.get("response_size", 0))
        
        # MIME type
        mimetype_elem = ET.SubElement(item, "mimetype")
        mimetype_elem.text = flow.get("content_type", "")
        
        # Response
        response_elem = ET.SubElement(item, "response")
        response_elem.set("base64", "true")
        response_data = self._build_raw_response(flow)
        response_elem.text = base64.b64encode(response_data).decode("ascii")
        
        # Comment
        comment_elem = ET.SubElement(item, "comment")
        comment_elem.text = f"Exported from AX-TrafficAnalyzer - Flow ID: {flow.get('flow_id', '')}"
        
        return item
    
    def _build_raw_request(self, flow: Dict[str, Any]) -> bytes:
        """Build raw HTTP request from flow."""
        method = flow.get("method", "GET")
        path = flow.get("path", "/")
        host = flow.get("host", "")
        headers = flow.get("request_headers", {}) or {}
        body = flow.get("request_body")
        
        # Build request line
        lines = [f"{method} {path} HTTP/1.1"]
        
        # Add Host header if not present
        if "Host" not in headers and "host" not in headers:
            lines.append(f"Host: {host}")
        
        # Add headers
        for name, value in headers.items():
            lines.append(f"{name}: {value}")
        
        # Join with CRLF
        request = "\r\n".join(lines) + "\r\n\r\n"
        
        # Add body if present
        if body:
            if isinstance(body, str):
                request += body
            elif isinstance(body, bytes):
                return request.encode("utf-8") + body
        
        return request.encode("utf-8")
    
    def _build_raw_response(self, flow: Dict[str, Any]) -> bytes:
        """Build raw HTTP response from flow."""
        status_code = flow.get("status_code", 200)
        headers = flow.get("response_headers", {}) or {}
        body = flow.get("response_body")
        
        # Build status line
        status_text = self._get_status_text(status_code)
        lines = [f"HTTP/1.1 {status_code} {status_text}"]
        
        # Add headers
        for name, value in headers.items():
            lines.append(f"{name}: {value}")
        
        # Join with CRLF
        response = "\r\n".join(lines) + "\r\n\r\n"
        
        # Add body if present
        if body:
            if isinstance(body, str):
                response += body
            elif isinstance(body, bytes):
                return response.encode("utf-8") + body
        
        return response.encode("utf-8")
    
    def _extract_port(self, url: str) -> int:
        """Extract port from URL."""
        if not url:
            return 80
        
        if "://" in url:
            parts = url.split("://", 1)
            scheme = parts[0]
            rest = parts[1] if len(parts) > 1 else ""
        else:
            scheme = "http"
            rest = url
        
        # Check for explicit port
        if ":" in rest.split("/")[0]:
            host_port = rest.split("/")[0]
            port_str = host_port.split(":")[-1]
            try:
                return int(port_str)
            except ValueError:
                pass
        
        # Default ports
        return 443 if scheme == "https" else 80
    
    def _extract_extension(self, path: str) -> str:
        """Extract file extension from path."""
        if not path or "/" not in path:
            return ""
        
        filename = path.split("/")[-1].split("?")[0]
        if "." in filename:
            return filename.split(".")[-1]
        
        return ""
    
    def _get_status_text(self, status_code: int) -> str:
        """Get HTTP status text for code."""
        status_texts = {
            200: "OK",
            201: "Created",
            204: "No Content",
            301: "Moved Permanently",
            302: "Found",
            304: "Not Modified",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            405: "Method Not Allowed",
            500: "Internal Server Error",
            502: "Bad Gateway",
            503: "Service Unavailable"
        }
        return status_texts.get(status_code, "Unknown")

