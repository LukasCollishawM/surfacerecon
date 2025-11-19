"""ID inference module for recognizing and categorizing IDs."""

import re
import logging
from typing import Dict, List, Any, Set, Optional
from collections import defaultdict

from surfacerecon.settings import ID_PATTERNS, UUID_PATTERN

logger = logging.getLogger(__name__)


def is_integer_id(value: Any) -> bool:
    """Check if value is an integer ID."""
    if isinstance(value, int):
        return True
    if isinstance(value, str):
        return value.isdigit()
    return False


def is_uuid(value: Any) -> bool:
    """Check if value is a UUID."""
    if not isinstance(value, str):
        return False
    return bool(re.match(UUID_PATTERN, value, re.IGNORECASE))


def matches_id_pattern(name: str) -> bool:
    """Check if parameter name matches common ID patterns."""
    name_lower = name.lower()
    return any(pattern.lower() in name_lower for pattern in ID_PATTERNS)


class IDPool:
    """Represents a pool of IDs for a specific parameter."""
    
    def __init__(self, name: str, location: str):
        self.name = name
        self.location = location  # "path", "query", "body"
        self.integer_ids: Set[int] = set()
        self.uuid_ids: Set[str] = set()
        self.string_ids: Set[str] = set()
        self.inferred_type: Optional[str] = None
    
    def add(self, value: Any) -> None:
        """Add an ID value to the pool."""
        if is_integer_id(value):
            if isinstance(value, str):
                self.integer_ids.add(int(value))
            else:
                self.integer_ids.add(value)
        elif is_uuid(value):
            self.uuid_ids.add(str(value))
        else:
            self.string_ids.add(str(value))
        
        # Infer type based on what we have
        if self.integer_ids:
            self.inferred_type = "int"
        elif self.uuid_ids:
            self.inferred_type = "uuid"
        elif self.string_ids:
            self.inferred_type = "string"
    
    def get_all(self) -> List[Any]:
        """Get all IDs as a list."""
        result = list(self.integer_ids) + list(self.uuid_ids) + list(self.string_ids)
        return result[:50]  # Limit to 50
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "location": self.location,
            "type": self.inferred_type,
            "integer_ids": list(self.integer_ids)[:20],
            "uuid_ids": list(self.uuid_ids)[:20],
            "string_ids": list(self.string_ids)[:20],
            "count": len(self.integer_ids) + len(self.uuid_ids) + len(self.string_ids),
        }


def infer_ids_from_endpoint(endpoint: Dict[str, Any]) -> Dict[str, IDPool]:
    """
    Infer IDs from an endpoint model.
    
    Args:
        endpoint: Endpoint dictionary from har_parser
        
    Returns:
        Dictionary mapping parameter names to IDPool objects
    """
    id_pools: Dict[str, IDPool] = {}
    
    # Process path parameters
    path_params = endpoint.get("parameters", {}).get("path", {})
    for param_name, values in path_params.items():
        # Check if this looks like an ID parameter
        if matches_id_pattern(param_name) or any(is_integer_id(v) or is_uuid(v) for v in values):
            pool = IDPool(param_name, "path")
            for value in values:
                pool.add(value)
            id_pools[param_name] = pool
    
    # Process query parameters
    query_params = endpoint.get("parameters", {}).get("query", {})
    for param_name, values in query_params.items():
        if matches_id_pattern(param_name) or any(is_integer_id(v) or is_uuid(v) for v in values):
            pool = IDPool(param_name, "query")
            for value in values:
                pool.add(value)
            id_pools[param_name] = pool
    
    # Process body parameters
    body_params = endpoint.get("parameters", {}).get("body", {})
    for param_name, values in body_params.items():
        if matches_id_pattern(param_name) or any(is_integer_id(v) or is_uuid(v) for v in values):
            pool = IDPool(param_name, "body")
            for value in values:
                pool.add(value)
            id_pools[param_name] = pool
    
    # Also check sample bodies for nested IDs
    sample_bodies = endpoint.get("sample_bodies", [])
    for body in sample_bodies:
        if isinstance(body, dict):
            for key, value in body.items():
                if matches_id_pattern(key) and (is_integer_id(value) or is_uuid(value)):
                    pool_name = f"body.{key}"
                    if pool_name not in id_pools:
                        pool = IDPool(pool_name, "body")
                        id_pools[pool_name] = pool
                    id_pools[pool_name].add(value)
    
    return id_pools


def enhance_endpoints_with_ids(endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Enhance endpoint models with inferred ID pools.
    
    Args:
        endpoints: List of endpoint dictionaries
        
    Returns:
        Enhanced endpoints with id_pools added
    """
    enhanced = []
    
    for endpoint in endpoints:
        id_pools = infer_ids_from_endpoint(endpoint)
        
        # Convert ID pools to dictionaries
        endpoint["id_pools"] = {
            name: pool.to_dict() for name, pool in id_pools.items()
        }
        
        # Update observed_ids with inferred types
        observed_ids = endpoint.get("observed_ids", {})
        for pool_name, pool in id_pools.items():
            if pool_name in observed_ids:
                observed_ids[pool_name] = pool.get_all()
        
        enhanced.append(endpoint)
    
    logger.info(f"Enhanced {len(enhanced)} endpoints with ID inference")
    return enhanced

