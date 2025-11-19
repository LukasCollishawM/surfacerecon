"""Playwright-based traffic capture module."""

import asyncio
import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Any
from urllib.parse import urlparse, urljoin

from playwright.async_api import async_playwright, Browser, Page, Request, Response

from surfacerecon.settings import (
    DEFAULT_NAVIGATION_DEPTH,
    DEFAULT_MAX_PAGES,
    MAX_BODY_SIZE,
    PAYMENT_KEYWORDS,
    DEFAULT_RESEARCHER_HEADER,
)

logger = logging.getLogger(__name__)


def truncate_body(body: str, max_size: int = MAX_BODY_SIZE) -> str:
    """Truncate body if it exceeds max_size."""
    if len(body) > max_size:
        return body[:max_size] + f"\n... (truncated, original size: {len(body)} bytes)"
    return body


def is_payment_route(url: str) -> bool:
    """Check if URL contains payment-related keywords."""
    url_lower = url.lower()
    return any(keyword in url_lower for keyword in PAYMENT_KEYWORDS)


class TrafficCapture:
    """Captures HTTP traffic using Playwright."""

    def __init__(
        self,
        cookies: Optional[List[Dict[str, Any]]] = None,
        headers: Optional[Dict[str, str]] = None,
        depth: int = DEFAULT_NAVIGATION_DEPTH,
        max_pages: int = DEFAULT_MAX_PAGES,
    ):
        self.cookies = cookies or []
        self.headers = headers or {}
        self.depth = depth
        self.max_pages = max_pages
        self.captured_requests: List[Dict[str, Any]] = []
        self.visited_urls: Set[str] = set()
        self.url_queue: List[tuple[str, int]] = []  # (url, depth)

    async def capture_session(
        self, whitelist_urls: List[str], output_dir: Path
    ) -> Path:
        """
        Capture traffic from whitelist URLs using BFS navigation.

        Args:
            whitelist_urls: List of starting URLs
            output_dir: Directory to save captured data

        Returns:
            Path to the requests.json file
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        requests_file = output_dir / "requests.json"

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()

            # Apply cookies
            if self.cookies:
                await context.add_cookies(self.cookies)

            # Apply headers
            if self.headers:
                await context.set_extra_http_headers(self.headers)
            elif DEFAULT_RESEARCHER_HEADER:
                await context.set_extra_http_headers(DEFAULT_RESEARCHER_HEADER)

            # Set up request/response listeners
            context.on("request", self._on_request)
            
            # Store response handler
            async def response_handler(response: Response):
                await self._on_response_async(response)
            
            context.on("response", response_handler)

            # Initialize queue with whitelist URLs
            for url in whitelist_urls:
                if not is_payment_route(url):
                    self.url_queue.append((url, 0))
                    self.visited_urls.add(url)

            # BFS navigation
            pages_visited = 0
            while self.url_queue and pages_visited < self.max_pages:
                url, current_depth = self.url_queue.pop(0)

                if current_depth > self.depth:
                    continue

                if is_payment_route(url):
                    logger.info(f"Skipping payment route: {url}")
                    continue

                try:
                    page = await context.new_page()
                    await page.goto(url, wait_until="networkidle", timeout=30000)

                    # Fill forms
                    await self._fill_forms(page)

                    # Extract links for BFS
                    if current_depth < self.depth:
                        links = await self._extract_links(page, url)
                        for link in links:
                            if link not in self.visited_urls and not is_payment_route(link):
                                self.visited_urls.add(link)
                                self.url_queue.append((link, current_depth + 1))

                    await page.close()
                    pages_visited += 1
                    logger.info(f"Captured page {pages_visited}: {url}")

                except Exception as e:
                    logger.warning(f"Error capturing {url}: {e}")
                    continue

            await browser.close()

        # Save captured requests
        with open(requests_file, "w", encoding="utf-8") as f:
            json.dump(self.captured_requests, f, indent=2, ensure_ascii=False)

        logger.info(f"Captured {len(self.captured_requests)} requests to {requests_file}")
        return requests_file

    def _on_request(self, request: Request) -> None:
        """Capture request details."""
        try:
            request_data = {
                "method": request.method,
                "url": request.url,
                "headers": request.headers,
                "post_data": truncate_body(request.post_data or ""),
                "timestamp": datetime.now().isoformat(),
            }
            # Store with request ID for matching with response
            request_data["_request_id"] = id(request)
            self.captured_requests.append(request_data)
        except Exception as e:
            logger.warning(f"Error capturing request: {e}")

    async def _on_response_async(self, response: Response) -> None:
        """Capture response details and match with request (async version)."""
        try:
            # Find matching request
            request_id = id(response.request)
            for req_data in reversed(self.captured_requests):
                if req_data.get("_request_id") == request_id:
                    try:
                        body = await response.text()
                        req_data["response"] = {
                            "status": response.status,
                            "status_text": response.status_text,
                            "headers": response.headers,
                            "body": truncate_body(body),
                        }
                    except Exception:
                        # If body can't be read, just capture status/headers
                        req_data["response"] = {
                            "status": response.status,
                            "status_text": response.status_text,
                            "headers": response.headers,
                            "body": "(unable to read body)",
                        }
                    break
        except Exception as e:
            logger.warning(f"Error capturing response: {e}")

    async def _fill_forms(self, page: Page) -> None:
        """Fill form inputs with safe defaults."""
        try:
            # Fill text inputs
            text_inputs = await page.query_selector_all("input[type='text'], input[type='email'], input[type='search']")
            for input_elem in text_inputs:
                try:
                    input_type = await input_elem.get_attribute("type")
                    name = await input_elem.get_attribute("name") or ""
                    placeholder = await input_elem.get_attribute("placeholder") or ""

                    if "email" in input_type or "email" in name.lower():
                        await input_elem.fill("test@example.com")
                    elif "search" in input_type or "search" in name.lower() or "search" in placeholder.lower():
                        await input_elem.fill("test")
                    else:
                        await input_elem.fill("test")
                except Exception:
                    continue

            # Fill textareas
            textareas = await page.query_selector_all("textarea")
            for textarea in textareas:
                try:
                    await textarea.fill("test")
                except Exception:
                    continue

            # Don't submit forms automatically to avoid unwanted actions
        except Exception as e:
            logger.debug(f"Error filling forms: {e}")

    async def _extract_links(self, page: Page, base_url: str) -> List[str]:
        """Extract all links from the page."""
        try:
            links = await page.evaluate("""() => {
                const links = [];
                document.querySelectorAll('a[href]').forEach(a => {
                    const href = a.getAttribute('href');
                    if (href) links.push(href);
                });
                return links;
            }""")

            # Resolve relative URLs
            resolved_links = []
            parsed_base = urlparse(base_url)

            for link in links:
                try:
                    # Skip javascript:, mailto:, tel:, etc.
                    if ":" in link and not link.startswith("http"):
                        continue

                    resolved = urljoin(base_url, link)
                    parsed = urlparse(resolved)

                    # Only include same-domain links
                    if parsed.netloc == parsed_base.netloc:
                        resolved_links.append(resolved)
                except Exception:
                    continue

            return list(set(resolved_links))
        except Exception as e:
            logger.debug(f"Error extracting links: {e}")
            return []


async def capture_session(
    whitelist_urls: List[str],
    output_dir: Path,
    cookies: Optional[List[Dict[str, Any]]] = None,
    headers: Optional[Dict[str, str]] = None,
    depth: int = DEFAULT_NAVIGATION_DEPTH,
    max_pages: int = DEFAULT_MAX_PAGES,
) -> Path:
    """
    Main entry point for capturing a session.

    Args:
        whitelist_urls: List of starting URLs
        output_dir: Directory to save captured data
        cookies: Optional cookies to apply
        headers: Optional headers to apply
        depth: Navigation depth for BFS
        max_pages: Maximum pages to visit

    Returns:
        Path to the requests.json file
    """
    capture = TrafficCapture(cookies=cookies, headers=headers, depth=depth, max_pages=max_pages)
    return await capture.capture_session(whitelist_urls, output_dir)

