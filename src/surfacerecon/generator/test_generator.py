"""Test generator for creating vulnerability test cases."""

import json
import logging
import random
from pathlib import Path
from typing import Dict, List, Any, Optional

from surfacerecon.settings import (
    DEFAULT_MAX_TESTS_PER_ENDPOINT,
    IDOR_TEST_COUNT,
    AUTH_BYPASS_TEST_COUNT,
    METHOD_CONFUSION_TEST_COUNT,
    MASS_ASSIGNMENT_TEST_COUNT,
    HTTP_METHODS,
    DESTRUCTIVE_METHODS,
    SUSPICIOUS_FIELDS,
)

logger = logging.getLogger(__name__)


class TestCase:
    """Represents a single test case."""
    
    def __init__(
        self,
        test_id: str,
        test_type: str,
        endpoint: str,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[Dict[str, Any]] = None,
        cookies: bool = True,
        description: str = "",
    ):
        self.test_id = test_id
        self.test_type = test_type
        self.endpoint = endpoint
        self.method = method
        self.url = url
        self.headers = headers or {}
        self.body = body
        self.cookies = cookies
        self.description = description
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "test_id": self.test_id,
            "test_type": self.test_type,
            "endpoint": self.endpoint,
            "method": self.method,
            "url": self.url,
            "headers": self.headers,
            "body": self.body,
            "cookies": self.cookies,
            "description": self.description,
        }


def generate_idor_tests(
    endpoint: Dict[str, Any],
    all_endpoints: List[Dict[str, Any]],
    count: int = IDOR_TEST_COUNT,
) -> List[TestCase]:
    """Generate IDOR (Insecure Direct Object Reference) tests."""
    tests = []
    endpoint_id_pools = endpoint.get("id_pools", {})
    
    if not endpoint_id_pools:
        return tests
    
    # Collect all ID pools from all endpoints
    all_id_pools: Dict[str, List[Any]] = {}
    for ep in all_endpoints:
        for pool_name, pool_data in ep.get("id_pools", {}).items():
            if pool_name not in all_id_pools:
                all_id_pools[pool_name] = []
            # Collect IDs from this pool
            pool_ids = []
            pool_ids.extend(pool_data.get("integer_ids", []))
            pool_ids.extend(pool_data.get("uuid_ids", []))
            pool_ids.extend(pool_data.get("string_ids", []))
            all_id_pools[pool_name].extend(pool_ids)
    
    # Generate tests by replacing IDs with IDs from other pools
    templated_path = endpoint.get("templated_path", "")
    method = endpoint.get("method", "GET")
    base_url = ""  # Will be constructed from endpoint
    
    for i in range(min(count, len(endpoint_id_pools) * 5)):  # Limit iterations
        # Pick a random ID parameter from this endpoint
        pool_names = list(endpoint_id_pools.keys())
        if not pool_names:
            break
        
        source_pool_name = random.choice(pool_names)
        source_pool = endpoint_id_pools[source_pool_name]
        
        # Get original ID value
        source_ids = []
        source_ids.extend(source_pool.get("integer_ids", []))
        source_ids.extend(source_pool.get("uuid_ids", []))
        source_ids.extend(source_pool.get("string_ids", []))
        
        if not source_ids:
            continue
        
        original_id = random.choice(source_ids)
        
        # Find a different ID from another pool (cross-pool IDOR)
        target_pool_name = None
        target_id = None
        
        for pool_name, pool_ids in all_id_pools.items():
            if pool_name != source_pool_name and pool_ids:
                # Make sure it's a different value
                candidate_ids = [id_val for id_val in pool_ids if id_val != original_id]
                if candidate_ids:
                    target_id = random.choice(candidate_ids)
                    target_pool_name = pool_name
                    break
        
        if not target_id:
            continue
        
        # Construct URL with replaced ID
        # This is simplified - in practice, we'd need to reconstruct the full URL
        test_url = templated_path.replace("{id:int}", str(target_id))
        test_url = test_url.replace("{id:uuid}", str(target_id))
        test_url = test_url.replace("{param}", str(target_id))
        
        # Also need to handle query params and body
        test_body = None
        if endpoint.get("sample_bodies"):
            test_body = endpoint["sample_bodies"][0].copy()
            # Replace ID in body if present
            for key in test_body:
                if key == source_pool_name or "id" in key.lower():
                    test_body[key] = target_id
        
        test = TestCase(
            test_id=f"idor_{endpoint.get('templated_path', '')}_{i}",
            test_type="IDOR",
            endpoint=templated_path,
            method=method,
            url=test_url,
            body=test_body,
            description=f"IDOR: Replace {source_pool_name}={original_id} with {target_pool_name}={target_id}",
        )
        tests.append(test)
    
    return tests[:count]


def generate_auth_bypass_tests(
    endpoint: Dict[str, Any],
    count: int = AUTH_BYPASS_TEST_COUNT,
) -> List[TestCase]:
    """Generate authentication bypass tests."""
    tests = []
    templated_path = endpoint.get("templated_path", "")
    method = endpoint.get("method", "GET")
    
    for i in range(count):
        test = TestCase(
            test_id=f"auth_bypass_{templated_path}_{i}",
            test_type="AUTH_BYPASS",
            endpoint=templated_path,
            method=method,
            url=templated_path,
            cookies=False,
            description="Auth bypass: Remove authentication cookies/headers",
        )
        tests.append(test)
    
    return tests


def generate_method_confusion_tests(
    endpoint: Dict[str, Any],
    allow_destructive: bool = False,
    count: int = METHOD_CONFUSION_TEST_COUNT,
) -> List[TestCase]:
    """Generate HTTP method confusion tests."""
    tests = []
    templated_path = endpoint.get("templated_path", "")
    original_method = endpoint.get("method", "GET")
    
    # Try alternative methods
    alternative_methods = [m for m in HTTP_METHODS if m != original_method]
    
    if not allow_destructive:
        alternative_methods = [m for m in alternative_methods if m not in DESTRUCTIVE_METHODS]
    
    # Limit to count
    alternative_methods = alternative_methods[:count]
    
    for method in alternative_methods:
        test_body = None
        if endpoint.get("sample_bodies"):
            test_body = endpoint["sample_bodies"][0].copy() if endpoint["sample_bodies"] else None
        
        test = TestCase(
            test_id=f"method_confusion_{templated_path}_{method}",
            test_type="METHOD_CONFUSION",
            endpoint=templated_path,
            method=method,
            url=templated_path,
            body=test_body,
            description=f"Method confusion: Try {method} instead of {original_method}",
        )
        tests.append(test)
    
    return tests


def generate_mass_assignment_tests(
    endpoint: Dict[str, Any],
    count: int = MASS_ASSIGNMENT_TEST_COUNT,
) -> List[TestCase]:
    """Generate mass assignment tests."""
    tests = []
    templated_path = endpoint.get("templated_path", "")
    method = endpoint.get("method", "GET")
    
    # Only test methods that typically have bodies
    if method not in ["POST", "PUT", "PATCH"]:
        return tests
    
    # Get sample body
    base_body = {}
    if endpoint.get("sample_bodies"):
        base_body = endpoint["sample_bodies"][0].copy()
    
    # Generate tests with suspicious fields
    suspicious_fields = SUSPICIOUS_FIELDS[:count]
    
    for i, field in enumerate(suspicious_fields):
        test_body = base_body.copy()
        
        # Add suspicious field with different values
        if "admin" in field.lower() or "is" in field.lower():
            test_body[field] = True
        elif "role" in field.lower():
            test_body[field] = "admin"
        elif "permission" in field.lower() or "access" in field.lower():
            test_body[field] = "full"
        else:
            test_body[field] = True
        
        test = TestCase(
            test_id=f"mass_assignment_{templated_path}_{i}",
            test_type="MASS_ASSIGNMENT",
            endpoint=templated_path,
            method=method,
            url=templated_path,
            body=test_body,
            description=f"Mass assignment: Add suspicious field {field}={test_body[field]}",
        )
        tests.append(test)
    
    return tests


def generate_tests(
    endpoints_file: Path,
    output_file: Path,
    max_tests: int = DEFAULT_MAX_TESTS_PER_ENDPOINT,
    allow_destructive: bool = False,
) -> None:
    """
    Generate test cases for all endpoints.
    
    Args:
        endpoints_file: Path to endpoints.json
        output_file: Path to save tests.json
        max_tests: Maximum tests per endpoint
        allow_destructive: Allow destructive DELETE tests
    """
    with open(endpoints_file, "r", encoding="utf-8") as f:
        endpoints = json.load(f)
    
    all_tests: List[TestCase] = []
    
    for endpoint in endpoints:
        endpoint_tests: List[TestCase] = []
        
        # Generate IDOR tests
        idor_tests = generate_idor_tests(endpoint, endpoints)
        endpoint_tests.extend(idor_tests)
        
        # Generate auth bypass tests
        auth_tests = generate_auth_bypass_tests(endpoint)
        endpoint_tests.extend(auth_tests)
        
        # Generate method confusion tests
        method_tests = generate_method_confusion_tests(endpoint, allow_destructive)
        endpoint_tests.extend(method_tests)
        
        # Generate mass assignment tests
        mass_tests = generate_mass_assignment_tests(endpoint)
        endpoint_tests.extend(mass_tests)
        
        # Limit to max_tests per endpoint
        if len(endpoint_tests) > max_tests:
            endpoint_tests = endpoint_tests[:max_tests]
        
        all_tests.extend(endpoint_tests)
        logger.info(
            f"Generated {len(endpoint_tests)} tests for {endpoint.get('templated_path', 'unknown')}"
        )
    
    # Save tests
    output_file.parent.mkdir(parents=True, exist_ok=True)
    tests_data = [test.to_dict() for test in all_tests]
    
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(tests_data, f, indent=2, ensure_ascii=False)
    
    logger.info(f"Generated {len(all_tests)} total tests, saved to {output_file}")

