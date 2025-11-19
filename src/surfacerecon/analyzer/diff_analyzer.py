"""Diff analyzer for comparing responses and detecting vulnerabilities."""

import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional

from deepdiff import DeepDiff

from surfacerecon.settings import (
    STATUS_CHANGE_HIGH,
    STATUS_CHANGE_MEDIUM,
    LENGTH_DIFF_THRESHOLD,
    SENSITIVE_FIELDS,
)

logger = logging.getLogger(__name__)


class Finding:
    """Represents a vulnerability finding."""
    
    def __init__(
        self,
        finding_id: str,
        severity: str,
        test_type: str,
        endpoint: str,
        test_id: str,
        description: str,
        baseline_status: int,
        test_status: int,
        diff_summary: str,
        curl_command: str,
    ):
        self.finding_id = finding_id
        self.severity = severity  # HIGH, MEDIUM, LOW
        self.test_type = test_type
        self.endpoint = endpoint
        self.test_id = test_id
        self.description = description
        self.baseline_status = baseline_status
        self.test_status = test_status
        self.diff_summary = diff_summary
        self.curl_command = curl_command
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "finding_id": self.finding_id,
            "severity": self.severity,
            "test_type": self.test_type,
            "endpoint": self.endpoint,
            "test_id": self.test_id,
            "description": self.description,
            "baseline_status": self.baseline_status,
            "test_status": self.test_status,
            "diff_summary": self.diff_summary,
            "curl_command": self.curl_command,
        }


def compare_responses(
    baseline: Dict[str, Any],
    test_result: Dict[str, Any],
) -> Optional[DeepDiff]:
    """
    Compare baseline and test responses using deepdiff.
    
    Args:
        baseline: Baseline response dictionary
        test_result: Test result dictionary with response
        
    Returns:
        DeepDiff object if differences found, None otherwise
    """
    if not test_result.get("success") or not test_result.get("response"):
        return None
    
    baseline_response = baseline.get("response", {})
    test_response = test_result.get("response", {})
    
    baseline_body = baseline_response.get("body", "")
    test_body = test_response.get("body", "")
    
    # Try to parse as JSON for better comparison
    baseline_json = None
    test_json = None
    
    try:
        if baseline_body and baseline_body != "(unable to read body)":
            baseline_json = json.loads(baseline_body)
    except (json.JSONDecodeError, ValueError):
        pass
    
    try:
        if test_body and test_body != "(unable to read body)":
            test_json = json.loads(test_body)
    except (json.JSONDecodeError, ValueError):
        pass
    
    # Compare JSON if both are JSON
    if baseline_json is not None and test_json is not None:
        diff = DeepDiff(baseline_json, test_json, ignore_order=True, verbose_level=2)
        if diff:
            return diff
    
    # Compare as strings if not both JSON
    if baseline_body != test_body:
        # Create a simple diff representation
        diff = DeepDiff(
            {"body": baseline_body},
            {"body": test_body},
            ignore_order=False,
            verbose_level=1,
        )
        return diff
    
    return None


def detect_sensitive_field_changes(diff: DeepDiff) -> List[str]:
    """Detect changes in sensitive fields."""
    changed_fields = []
    
    # Check dictionary item changes
    if "dictionary_item_added" in diff:
        for item in diff["dictionary_item_added"]:
            field_path = str(item)
            if any(sensitive in field_path.lower() for sensitive in SENSITIVE_FIELDS):
                changed_fields.append(field_path)
    
    if "dictionary_item_removed" in diff:
        for item in diff["dictionary_item_removed"]:
            field_path = str(item)
            if any(sensitive in field_path.lower() for sensitive in SENSITIVE_FIELDS):
                changed_fields.append(field_path)
    
    if "values_changed" in diff:
        for item in diff["values_changed"]:
            field_path = str(item)
            if any(sensitive in field_path.lower() for sensitive in SENSITIVE_FIELDS):
                changed_fields.append(field_path)
    
    return changed_fields


def calculate_severity(
    baseline_status: int,
    test_status: int,
    diff: Optional[DeepDiff],
    test_type: str,
) -> str:
    """
    Calculate severity based on status changes and differences.
    
    Returns:
        "HIGH", "MEDIUM", or "LOW"
    """
    # Check status changes
    if baseline_status in STATUS_CHANGE_HIGH:
        if test_status in STATUS_CHANGE_HIGH[baseline_status]:
            return "HIGH"
    
    if baseline_status in STATUS_CHANGE_MEDIUM:
        if test_status in STATUS_CHANGE_MEDIUM[baseline_status]:
            return "MEDIUM"
    
    # Check for sensitive field changes
    if diff:
        sensitive_changes = detect_sensitive_field_changes(diff)
        if sensitive_changes:
            return "HIGH"
        
        # Check length difference
        baseline_body_len = len(str(diff.get("old_value", "")))
        test_body_len = len(str(diff.get("new_value", "")))
        
        if baseline_body_len > 0:
            length_diff = abs(test_body_len - baseline_body_len) / baseline_body_len
            if length_diff > LENGTH_DIFF_THRESHOLD:
                return "MEDIUM"
    
    # Status unchanged but body different
    if baseline_status == test_status == 200 and diff:
        # Check if it's an IDOR read (same status, different content)
        if test_type == "IDOR":
            return "HIGH"
        return "MEDIUM"
    
    # Other differences
    if diff:
        return "LOW"
    
    return "LOW"


def generate_curl_command(test: Dict[str, Any], test_result: Dict[str, Any]) -> str:
    """Generate curl command for reproducing the test."""
    method = test.get("method", "GET")
    url = test_result.get("url", test.get("url", ""))
    headers = test_result.get("response", {}).get("headers", {})
    body = test.get("body")
    
    cmd_parts = ["curl", "-X", method]
    
    # Add headers
    for key, value in headers.items():
        if key.lower() not in ["content-length", "host"]:
            cmd_parts.append("-H")
            cmd_parts.append(f'"{key}: {value}"')
    
    # Add body if present
    if body and method in ["POST", "PUT", "PATCH"]:
        body_str = json.dumps(body)
        cmd_parts.append("-d")
        cmd_parts.append(f"'{body_str}'")
    
    cmd_parts.append(f'"{url}"')
    
    return " ".join(cmd_parts)


def analyze_results(
    requests_file: Path,
    test_results_file: Path,
    tests_file: Path,
    output_file: Path,
) -> List[Finding]:
    """
    Analyze test results against baseline and generate findings.
    
    Args:
        requests_file: Path to baseline requests.json
        test_results_file: Path to test_results.json
        tests_file: Path to tests.json
        output_file: Path to save findings.json
        
    Returns:
        List of Finding objects
    """
    # Load baseline requests
    with open(requests_file, "r", encoding="utf-8") as f:
        baseline_requests = json.load(f)
    
    # Load test results
    with open(test_results_file, "r", encoding="utf-8") as f:
        test_results = json.load(f)
    
    # Load tests for metadata
    with open(tests_file, "r", encoding="utf-8") as f:
        tests = json.load(f)
    
    # Create lookup for tests by test_id
    tests_by_id = {test["test_id"]: test for test in tests}
    
    # Create lookup for baseline requests by URL and method
    baseline_by_url_method: Dict[tuple[str, str], Dict[str, Any]] = {}
    for req in baseline_requests:
        url = req.get("url", "")
        method = req.get("method", "GET")
        baseline_by_url_method[(url, method)] = req
    
    findings: List[Finding] = []
    
    for test_result in test_results:
        if not test_result.get("success"):
            continue
        
        test_id = test_result.get("test_id", "")
        test = tests_by_id.get(test_id)
        if not test:
            continue
        
        test_url = test_result.get("url", test.get("url", ""))
        test_method = test.get("method", "GET")
        
        # Find matching baseline
        baseline = baseline_by_url_method.get((test_url, test_method))
        
        # If exact match not found, try to find by endpoint pattern
        if not baseline:
            # Try to find a similar baseline request
            for req in baseline_requests:
                if req.get("method") == test_method:
                    # Simple matching - could be improved
                    baseline = req
                    break
        
        if not baseline or "response" not in baseline:
            continue
        
        baseline_status = baseline["response"].get("status", 0)
        test_status = test_result["response"].get("status", 0)
        
        # Compare responses
        diff = compare_responses(baseline, test_result)
        
        # Calculate severity
        severity = calculate_severity(
            baseline_status,
            test_status,
            diff,
            test.get("test_type", ""),
        )
        
        # Generate diff summary
        diff_summary = ""
        if diff:
            diff_summary = str(diff)[:500]  # Truncate long diffs
        
        # Generate curl command
        curl_cmd = generate_curl_command(test, test_result)
        
        finding = Finding(
            finding_id=f"finding_{len(findings) + 1}",
            severity=severity,
            test_type=test.get("test_type", ""),
            endpoint=test.get("endpoint", ""),
            test_id=test_id,
            description=test.get("description", ""),
            baseline_status=baseline_status,
            test_status=test_status,
            diff_summary=diff_summary,
            curl_command=curl_cmd,
        )
        
        findings.append(finding)
    
    # Save findings
    output_file.parent.mkdir(parents=True, exist_ok=True)
    findings_data = [finding.to_dict() for finding in findings]
    
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(findings_data, f, indent=2, ensure_ascii=False)
    
    logger.info(f"Generated {len(findings)} findings, saved to {output_file}")
    
    return findings

