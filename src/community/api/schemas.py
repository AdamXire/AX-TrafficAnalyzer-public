"""
@fileoverview API Schemas - Pydantic models for request/response
@author AdamChe 谢毅翔, 字:吉祥
@company MMeTech (Macau) Ltd.
@copyright Copyright (c) 2025 MMeTech (Macau) Ltd.
@license MIT License
@classification Enterprise Security Auditor and Education

Pydantic schemas for API endpoints.
"""

from typing import List, Generic, TypeVar
from pydantic import BaseModel

T = TypeVar('T')

class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated response wrapper."""
    items: List[T]
    total: int
    limit: int
    offset: int
    has_more: bool
    
    @classmethod
    def create(cls, items: List[T], total: int, limit: int, offset: int):
        """Create paginated response."""
        return cls(
            items=items,
            total=total,
            limit=limit,
            offset=offset,
            has_more=(offset + limit) < total
        )

