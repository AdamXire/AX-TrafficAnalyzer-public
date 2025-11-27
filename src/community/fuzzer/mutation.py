"""
@fileoverview Mutation Engine - Generate mutations for HTTP requests
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Mutation engine for generating HTTP request variations.
This file is part of AX-TrafficAnalyzer Community Edition.
"""

import json
import urllib.parse
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
from ..core.logging import get_logger

log = get_logger(__name__)


class MutationType(str, Enum):
    """Types of mutations."""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    HEADER_INJECTION = "header_injection"
    PARAMETER_POLLUTION = "parameter_pollution"
    BOUNDARY_TEST = "boundary_test"


@dataclass
class Mutation:
    """A single mutation."""
    mutation_type: MutationType
    original_value: str
    mutated_value: str
    location: str  # "header", "param", "body", "path"
    field_name: str
    description: str


# Common payloads for different mutation types
PAYLOADS = {
    MutationType.SQL_INJECTION: [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "1' AND '1'='1",
        "1 OR 1=1",
        "' UNION SELECT NULL--",
        "admin'--",
        "1; SELECT * FROM users",
    ],
    MutationType.XSS: [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "'><script>alert('XSS')</script>",
        "<body onload=alert('XSS')>",
    ],
    MutationType.PATH_TRAVERSAL: [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc/passwd",
    ],
    MutationType.COMMAND_INJECTION: [
        "; ls -la",
        "| cat /etc/passwd",
        "$(whoami)",
        "`id`",
        "& dir",
        "|| ping -c 1 localhost",
    ],
    MutationType.HEADER_INJECTION: [
        "value\r\nX-Injected: header",
        "value%0d%0aX-Injected:%20header",
        "value\nSet-Cookie: injected=true",
    ],
    MutationType.PARAMETER_POLLUTION: [
        # These are added as duplicate parameters
        "duplicate_value",
    ],
    MutationType.BOUNDARY_TEST: [
        "",  # Empty
        "A" * 10000,  # Long string
        "0",
        "-1",
        "999999999999",
        "null",
        "undefined",
        "true",
        "false",
        "[]",
        "{}",
    ],
}


class MutationEngine:
    """
    Mutation engine for generating HTTP request variations.
    
    Generates mutations for:
    - Headers
    - URL parameters
    - Request body (JSON, form data)
    - Path segments
    """
    
    def __init__(self, mutation_types: Optional[List[MutationType]] = None):
        """
        Initialize mutation engine.
        
        Args:
            mutation_types: Types of mutations to generate (all if None)
        """
        self.mutation_types = mutation_types or list(MutationType)
        log.info("mutation_engine_initialized", types=len(self.mutation_types))
    
    def mutate_headers(
        self,
        headers: Dict[str, str]
    ) -> List[Dict[str, Any]]:
        """
        Generate header mutations.
        
        Args:
            headers: Original headers
            
        Returns:
            List of mutated header dictionaries with metadata
        """
        mutations = []
        
        for header_name, header_value in headers.items():
            # Skip certain headers
            if header_name.lower() in ["host", "content-length", "connection"]:
                continue
            
            for mutation_type in self.mutation_types:
                if mutation_type not in [
                    MutationType.XSS,
                    MutationType.SQL_INJECTION,
                    MutationType.HEADER_INJECTION
                ]:
                    continue
                
                for payload in PAYLOADS.get(mutation_type, []):
                    mutated_headers = headers.copy()
                    mutated_headers[header_name] = payload
                    
                    mutations.append({
                        "headers": mutated_headers,
                        "mutation": Mutation(
                            mutation_type=mutation_type,
                            original_value=header_value,
                            mutated_value=payload,
                            location="header",
                            field_name=header_name,
                            description=f"{mutation_type.value} in header {header_name}"
                        )
                    })
        
        return mutations
    
    def mutate_params(self, url: str) -> List[Dict[str, Any]]:
        """
        Generate URL parameter mutations.
        
        Args:
            url: Original URL
            
        Returns:
            List of mutated URLs with metadata
        """
        mutations = []
        
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        
        if not params:
            return mutations
        
        for param_name, param_values in params.items():
            original_value = param_values[0] if param_values else ""
            
            for mutation_type in self.mutation_types:
                for payload in PAYLOADS.get(mutation_type, []):
                    # Create mutated params
                    mutated_params = {k: v[0] for k, v in params.items()}
                    mutated_params[param_name] = payload
                    
                    # Rebuild URL
                    new_query = urllib.parse.urlencode(mutated_params)
                    mutated_url = urllib.parse.urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        new_query,
                        parsed.fragment
                    ))
                    
                    mutations.append({
                        "url": mutated_url,
                        "mutation": Mutation(
                            mutation_type=mutation_type,
                            original_value=original_value,
                            mutated_value=payload,
                            location="param",
                            field_name=param_name,
                            description=f"{mutation_type.value} in param {param_name}"
                        )
                    })
        
        return mutations
    
    def mutate_body(
        self,
        body: bytes,
        content_type: str
    ) -> List[Dict[str, Any]]:
        """
        Generate request body mutations.
        
        Args:
            body: Original request body
            content_type: Content-Type header value
            
        Returns:
            List of mutated bodies with metadata
        """
        mutations = []
        
        if not body:
            return mutations
        
        # Handle JSON bodies
        if "application/json" in content_type:
            mutations.extend(self._mutate_json_body(body))
        
        # Handle form data
        elif "application/x-www-form-urlencoded" in content_type:
            mutations.extend(self._mutate_form_body(body))
        
        return mutations
    
    def _mutate_json_body(self, body: bytes) -> List[Dict[str, Any]]:
        """Mutate JSON request body."""
        mutations = []
        
        try:
            data = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return mutations
        
        if not isinstance(data, dict):
            return mutations
        
        for field_name, field_value in data.items():
            if not isinstance(field_value, str):
                continue
            
            for mutation_type in self.mutation_types:
                for payload in PAYLOADS.get(mutation_type, []):
                    mutated_data = data.copy()
                    mutated_data[field_name] = payload
                    
                    mutations.append({
                        "body": json.dumps(mutated_data).encode("utf-8"),
                        "mutation": Mutation(
                            mutation_type=mutation_type,
                            original_value=str(field_value),
                            mutated_value=payload,
                            location="body",
                            field_name=field_name,
                            description=f"{mutation_type.value} in JSON field {field_name}"
                        )
                    })
        
        return mutations
    
    def _mutate_form_body(self, body: bytes) -> List[Dict[str, Any]]:
        """Mutate form-urlencoded request body."""
        mutations = []
        
        try:
            params = urllib.parse.parse_qs(
                body.decode("utf-8"),
                keep_blank_values=True
            )
        except UnicodeDecodeError:
            return mutations
        
        for field_name, field_values in params.items():
            original_value = field_values[0] if field_values else ""
            
            for mutation_type in self.mutation_types:
                for payload in PAYLOADS.get(mutation_type, []):
                    mutated_params = {k: v[0] for k, v in params.items()}
                    mutated_params[field_name] = payload
                    
                    mutations.append({
                        "body": urllib.parse.urlencode(mutated_params).encode("utf-8"),
                        "mutation": Mutation(
                            mutation_type=mutation_type,
                            original_value=original_value,
                            mutated_value=payload,
                            location="body",
                            field_name=field_name,
                            description=f"{mutation_type.value} in form field {field_name}"
                        )
                    })
        
        return mutations
    
    def get_mutation_count(
        self,
        headers: Dict[str, str],
        url: str,
        body: Optional[bytes] = None,
        content_type: str = ""
    ) -> int:
        """
        Get estimated number of mutations that would be generated.
        
        Args:
            headers: Request headers
            url: Request URL
            body: Request body
            content_type: Content-Type header
            
        Returns:
            Estimated mutation count
        """
        count = 0
        
        # Count header mutations
        mutable_headers = [
            h for h in headers.keys()
            if h.lower() not in ["host", "content-length", "connection"]
        ]
        count += len(mutable_headers) * sum(
            len(PAYLOADS.get(t, []))
            for t in self.mutation_types
            if t in [MutationType.XSS, MutationType.SQL_INJECTION, MutationType.HEADER_INJECTION]
        )
        
        # Count param mutations
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        count += len(params) * sum(len(PAYLOADS.get(t, [])) for t in self.mutation_types)
        
        # Count body mutations (estimate)
        if body:
            # Rough estimate based on body size
            count += 10 * sum(len(PAYLOADS.get(t, [])) for t in self.mutation_types)
        
        return count

