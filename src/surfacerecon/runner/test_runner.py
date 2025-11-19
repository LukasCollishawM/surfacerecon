"""Test runner module for executing test cases."""

import asyncio
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

import httpx

from surfacerecon.settings import (
    DEFAULT_CONCURRENCY,
    DEFAULT_REQUESTS_PER_SECOND,
    DEFAULT_RESEARCHER_HEADER,
)

logger = logging.getLogger(__name__)


class RateLimiter:
    """Simple rate limiter using asyncio."""
    
    def __init__(self, requests_per_second: float):
        self.requests_per_second = requests_per_second
        self.min_interval = 1.0 / requests_per_second
        self.last_request_time = 0.0
    
    async def acquire(self) -> None:
        """Wait if necessary to respect rate limit."""
        current_time = asyncio.get_event_loop().time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.min_interval:
            await asyncio.sleep(self.min_interval - time_since_last)
        
        self.last_request_time = asyncio.get_event_loop().time()


async def run_single_test(
    test: Dict[str, Any],
    client: httpx.AsyncClient,
    cookies: Optional[List[Dict[str, Any]]] = None,
    headers: Optional[Dict[str, str]] = None,
    rate_limiter: Optional[RateLimiter] = None,
) -> Dict[str, Any]:
    """
    Run a single test case.
    
    Args:
        test: Test case dictionary
        client: httpx async client
        cookies: Optional cookies to apply
        headers: Optional headers to apply
        rate_limiter: Optional rate limiter
        
    Returns:
        Test result dictionary
    """
    if rate_limiter:
        await rate_limiter.acquire()
    
    test_id = test.get("test_id", "unknown")
    method = test.get("method", "GET")
    url = test.get("url", "")
    test_headers = test.get("headers", {}).copy()
    test_body = test.get("body")
    use_cookies = test.get("cookies", True)
    
    # Merge headers
    request_headers = {}
    if headers:
        request_headers.update(headers)
    if DEFAULT_RESEARCHER_HEADER:
        request_headers.update(DEFAULT_RESEARCHER_HEADER)
    request_headers.update(test_headers)
    
    # Prepare cookies
    cookie_dict = {}
    if use_cookies and cookies:
        for cookie in cookies:
            cookie_dict[cookie.get("name", "")] = cookie.get("value", "")
    
    result = {
        "test_id": test_id,
        "test_type": test.get("test_type", ""),
        "endpoint": test.get("endpoint", ""),
        "method": method,
        "url": url,
        "timestamp": datetime.now().isoformat(),
        "success": False,
        "error": None,
        "response": None,
    }
    
    try:
        # Prepare request kwargs
        request_kwargs = {
            "method": method,
            "url": url,
            "headers": request_headers,
            "timeout": 30.0,
        }
        
        if cookie_dict:
            request_kwargs["cookies"] = cookie_dict
        
        if test_body and method in ["POST", "PUT", "PATCH"]:
            request_kwargs["json"] = test_body
        
        # Make request
        response = await client.request(**request_kwargs)
        
        # Capture response
        try:
            response_body = response.text
            if len(response_body) > 20000:  # Truncate very long responses
                response_body = response_body[:20000] + "\n... (truncated)"
        except Exception:
            response_body = "(unable to read body)"
        
        result["response"] = {
            "status": response.status_code,
            "status_text": response.reason_phrase,
            "headers": dict(response.headers),
            "body": response_body,
        }
        result["success"] = True
        
    except httpx.TimeoutException:
        result["error"] = "Request timeout"
    except httpx.RequestError as e:
        result["error"] = f"Request error: {str(e)}"
    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)}"
        logger.warning(f"Error running test {test_id}: {e}")
    
    return result


async def run_tests(
    tests_file: Path,
    output_file: Path,
    cookies: Optional[List[Dict[str, Any]]] = None,
    headers: Optional[Dict[str, str]] = None,
    concurrency: int = DEFAULT_CONCURRENCY,
    rate: float = DEFAULT_REQUESTS_PER_SECOND,
) -> List[Dict[str, Any]]:
    """
    Run all test cases asynchronously with rate limiting.
    
    Args:
        tests_file: Path to tests.json
        output_file: Path to save test results
        cookies: Optional cookies to apply
        headers: Optional headers to apply
        concurrency: Maximum concurrent requests
        rate: Requests per second
        
    Returns:
        List of test results
    """
    with open(tests_file, "r", encoding="utf-8") as f:
        tests = json.load(f)
    
    logger.info(f"Running {len(tests)} tests with concurrency={concurrency}, rate={rate}/s")
    
    rate_limiter = RateLimiter(rate)
    semaphore = asyncio.Semaphore(concurrency)
    results: List[Dict[str, Any]] = []
    
    async def run_with_semaphore(test: Dict[str, Any]) -> Dict[str, Any]:
        async with semaphore:
            async with httpx.AsyncClient() as client:
                return await run_single_test(test, client, cookies, headers, rate_limiter)
    
    # Run tests with concurrency control
    tasks = [run_with_semaphore(test) for test in tests]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Handle exceptions
    processed_results = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            logger.error(f"Test {tests[i].get('test_id', 'unknown')} raised exception: {result}")
            processed_results.append({
                "test_id": tests[i].get("test_id", "unknown"),
                "success": False,
                "error": str(result),
            })
        else:
            processed_results.append(result)
    
    # Save results
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(processed_results, f, indent=2, ensure_ascii=False)
    
    successful = sum(1 for r in processed_results if r.get("success", False))
    logger.info(f"Completed {len(processed_results)} tests ({successful} successful)")
    
    return processed_results

