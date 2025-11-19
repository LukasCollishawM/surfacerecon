"""HAR parser for extracting endpoint models from captured requests."""

import json
import logging
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)


def normalize_url(url: str) -> tuple[str, str]:
    """
    Normalize URL by removing query params for templating.
    
    Returns:
        (normalized_url, query_string) tuple
    """
    parsed = urlparse(url)
    return parsed.path, parsed.query


def detect_template_path(path: str, seen_paths: List[str]) -> str:
    """
    Detect template pattern from multiple similar paths.
    
    Example: /api/users/123, /api/users/456 -> /api/users/{id:int}
    """
    if not seen_paths:
        return path
    
    # Split path into segments
    segments = path.split("/")
    
    # Find common pattern
    template_segments = []
    for i, segment in enumerate(segments):
        # Check if this segment is numeric in any seen path
        is_numeric = False
        is_uuid = False
        
        for seen_path in seen_paths:
            seen_segments = seen_path.split("/")
            if i < len(seen_segments):
                seg = seen_segments[i]
                if seg.isdigit():
                    is_numeric = True
                elif re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", seg, re.IGNORECASE):
                    is_uuid = True
        
        if is_numeric:
            template_segments.append("{id:int}")
        elif is_uuid:
            template_segments.append("{id:uuid}")
        elif segment != segments[0] and any(
            seen_path.split("/")[i] != segment 
            for seen_path in seen_paths 
            if i < len(seen_path.split("/"))
        ):
            # Different non-numeric segments - use generic placeholder
            template_segments.append("{param}")
        else:
            template_segments.append(segment)
    
    return "/".join(template_segments)


def extract_query_params(query_string: str) -> Dict[str, List[str]]:
    """Extract query parameters from query string."""
    if not query_string:
        return {}
    return parse_qs(query_string)


def extract_json_body(body: str) -> Optional[Dict[str, Any]]:
    """Extract JSON body if present."""
    if not body or body == "(unable to read body)":
        return None
    
    try:
        # Try to parse as JSON
        return json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None


class EndpointModel:
    """Model representing an API endpoint."""
    
    def __init__(
        self,
        method: str,
        templated_path: str,
        parameters: Dict[str, Any],
        sample_bodies: List[Dict[str, Any]],
        observed_ids: Dict[str, List[Any]],
    ):
        self.method = method
        self.templated_path = templated_path
        self.parameters = parameters  # {location: {param_name: [values]}}
        self.sample_bodies = sample_bodies
        self.observed_ids = observed_ids  # {param_name: [id_values]}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "method": self.method,
            "templated_path": self.templated_path,
            "parameters": self.parameters,
            "sample_bodies": self.sample_bodies[:5],  # Limit samples
            "observed_ids": self.observed_ids,
        }


def parse_requests(requests_file: Path) -> List[EndpointModel]:
    """
    Parse requests.json and build endpoint models.
    
    Args:
        requests_file: Path to requests.json file
        
    Returns:
        List of EndpointModel objects
    """
    with open(requests_file, "r", encoding="utf-8") as f:
        requests_data = json.load(f)
    
    # Group requests by method + normalized path
    endpoint_groups: Dict[tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    
    for req in requests_data:
        if "response" not in req:
            continue  # Skip requests without responses
        
        method = req.get("method", "GET")
        url = req.get("url", "")
        path, query = normalize_url(url)
        
        # Group by method and path template (we'll refine templates later)
        endpoint_groups[(method, path)].append(req)
    
    endpoints: List[EndpointModel] = []
    
    for (method, base_path), requests in endpoint_groups.items():
        # Collect all paths for this endpoint to detect templates
        all_paths = [normalize_url(req.get("url", ""))[0] for req in requests]
        
        # Detect template
        templated_path = detect_template_path(base_path, all_paths)
        
        # Extract parameters
        parameters: Dict[str, Dict[str, List[str]]] = {
            "path": {},
            "query": {},
            "body": {},
        }
        
        # Extract query params
        query_params: Dict[str, Set[str]] = defaultdict(set)
        for req in requests:
            url = req.get("url", "")
            _, query = normalize_url(url)
            if query:
                parsed_qs = extract_query_params(query)
                for key, values in parsed_qs.items():
                    query_params[key].update(values)
        
        parameters["query"] = {k: list(v) for k, v in query_params.items()}
        
        # Extract path parameters (IDs in path)
        path_params: Dict[str, Set[str]] = defaultdict(set)
        for req in requests:
            url = req.get("url", "")
            path_segments = normalize_url(url)[0].split("/")
            base_segments = base_path.split("/")
            
            for i, (seg, base_seg) in enumerate(zip(path_segments, base_segments)):
                if seg != base_seg:
                    # This is a parameter
                    param_name = f"param_{i}" if i < len(base_segments) else "id"
                    path_params[param_name].add(seg)
        
        parameters["path"] = {k: list(v) for k, v in path_params.items()}
        
        # Extract body parameters
        sample_bodies: List[Dict[str, Any]] = []
        body_params: Dict[str, Set[Any]] = defaultdict(set)
        
        for req in requests:
            body_str = req.get("post_data", "") or ""
            if not body_str:
                # Try response body for some cases
                response = req.get("response", {})
                body_str = response.get("body", "")
            
            json_body = extract_json_body(body_str)
            if json_body:
                sample_bodies.append(json_body)
                # Extract all keys and sample values
                for key, value in json_body.items():
                    if isinstance(value, (str, int, float, bool)):
                        body_params[key].add(str(value))
        
        parameters["body"] = {k: list(v)[:10] for k, v in body_params.items()}  # Limit samples
        
        # Extract observed IDs (will be refined by id_inference)
        observed_ids: Dict[str, List[Any]] = {}
        
        # Collect IDs from path
        for param_name, values in parameters["path"].items():
            observed_ids[param_name] = values[:20]  # Limit
        
        # Collect IDs from query
        for param_name, values in parameters["query"].items():
            if any("id" in param_name.lower() for _ in [1]):  # ID-like params
                observed_ids[param_name] = values[:20]
        
        # Collect IDs from body
        for param_name, values in parameters["body"].items():
            if any("id" in param_name.lower() for _ in [1]):  # ID-like params
                observed_ids[param_name] = values[:20]
        
        endpoint = EndpointModel(
            method=method,
            templated_path=templated_path,
            parameters=parameters,
            sample_bodies=sample_bodies[:5],  # Limit samples
            observed_ids=observed_ids,
        )
        
        endpoints.append(endpoint)
    
    logger.info(f"Parsed {len(endpoints)} endpoints from {len(requests_data)} requests")
    return endpoints


def save_endpoints(endpoints: List[EndpointModel], output_file: Path) -> None:
    """Save endpoints to JSON file."""
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    endpoints_data = [endpoint.to_dict() for endpoint in endpoints]
    
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(endpoints_data, f, indent=2, ensure_ascii=False)
    
    logger.info(f"Saved {len(endpoints)} endpoints to {output_file}")

