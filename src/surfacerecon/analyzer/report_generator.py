"""Report generator for creating markdown and JSON reports."""

import json
import logging
from pathlib import Path
from typing import Dict, List, Any
from collections import defaultdict

logger = logging.getLogger(__name__)


def generate_markdown_report(
    findings_file: Path,
    output_file: Path,
) -> None:
    """
    Generate markdown report from findings.
    
    Args:
        findings_file: Path to findings.json
        output_file: Path to save report.md
    """
    with open(findings_file, "r", encoding="utf-8") as f:
        findings = json.load(f)
    
    # Group findings by severity
    findings_by_severity: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        severity = finding.get("severity", "LOW")
        findings_by_severity[severity].append(finding)
    
    # Generate report
    report_lines = [
        "# surfacerecon Vulnerability Report",
        "",
        "## Executive Summary",
        "",
        f"**Total Findings:** {len(findings)}",
        f"- **HIGH:** {len(findings_by_severity.get('HIGH', []))}",
        f"- **MEDIUM:** {len(findings_by_severity.get('MEDIUM', []))}",
        f"- **LOW:** {len(findings_by_severity.get('LOW', []))}",
        "",
        "---",
        "",
    ]
    
    # High severity findings
    if findings_by_severity.get("HIGH"):
        report_lines.extend([
            "## HIGH Severity Findings",
            "",
        ])
        
        for i, finding in enumerate(findings_by_severity["HIGH"], 1):
            report_lines.extend([
                f"### Finding {i}: {finding.get('test_type', 'Unknown')}",
                "",
                f"**Endpoint:** `{finding.get('endpoint', 'N/A')}`",
                f"**Test Type:** {finding.get('test_type', 'N/A')}",
                f"**Description:** {finding.get('description', 'N/A')}",
                "",
                f"**Status Change:** {finding.get('baseline_status', 'N/A')} → {finding.get('test_status', 'N/A')}",
                "",
            ])
            
            if finding.get("diff_summary"):
                report_lines.extend([
                    "**Difference Summary:**",
                    "```",
                    finding.get("diff_summary", "")[:1000],  # Limit length
                    "```",
                    "",
                ])
            
            if finding.get("curl_command"):
                report_lines.extend([
                    "**Reproduction Command:**",
                    "```bash",
                    finding.get("curl_command", ""),
                    "```",
                    "",
                ])
            
            report_lines.append("---")
            report_lines.append("")
    
    # Medium severity findings
    if findings_by_severity.get("MEDIUM"):
        report_lines.extend([
            "## MEDIUM Severity Findings",
            "",
        ])
        
        for i, finding in enumerate(findings_by_severity["MEDIUM"], 1):
            report_lines.extend([
                f"### Finding {i}: {finding.get('test_type', 'Unknown')}",
                "",
                f"**Endpoint:** `{finding.get('endpoint', 'N/A')}`",
                f"**Test Type:** {finding.get('test_type', 'N/A')}",
                f"**Description:** {finding.get('description', 'N/A')}",
                "",
                f"**Status Change:** {finding.get('baseline_status', 'N/A')} → {finding.get('test_status', 'N/A')}",
                "",
            ])
            
            if finding.get("curl_command"):
                report_lines.extend([
                    "**Reproduction Command:**",
                    "```bash",
                    finding.get("curl_command", ""),
                    "```",
                    "",
                ])
            
            report_lines.append("---")
            report_lines.append("")
    
    # Low severity findings
    if findings_by_severity.get("LOW"):
        report_lines.extend([
            "## LOW Severity Findings",
            "",
            "| Endpoint | Test Type | Status Change |",
            "|----------|-----------|---------------|",
        ])
        
        for finding in findings_by_severity["LOW"]:
            endpoint = finding.get("endpoint", "N/A")
            test_type = finding.get("test_type", "N/A")
            status_change = f"{finding.get('baseline_status', 'N/A')} → {finding.get('test_status', 'N/A')}"
            report_lines.append(f"| `{endpoint}` | {test_type} | {status_change} |")
        
        report_lines.append("")
    
    # Write report
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))
    
    logger.info(f"Generated markdown report: {output_file}")


def generate_json_report(
    findings_file: Path,
    output_file: Path,
) -> None:
    """
    Generate structured JSON report from findings.
    
    Args:
        findings_file: Path to findings.json
        output_file: Path to save report.json
    """
    with open(findings_file, "r", encoding="utf-8") as f:
        findings = json.load(f)
    
    # Group by severity
    findings_by_severity: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    findings_by_type: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    
    for finding in findings:
        severity = finding.get("severity", "LOW")
        test_type = finding.get("test_type", "UNKNOWN")
        findings_by_severity[severity].append(finding)
        findings_by_type[test_type].append(finding)
    
    report = {
        "summary": {
            "total_findings": len(findings),
            "high": len(findings_by_severity.get("HIGH", [])),
            "medium": len(findings_by_severity.get("MEDIUM", [])),
            "low": len(findings_by_severity.get("LOW", [])),
        },
        "by_severity": {
            "HIGH": findings_by_severity.get("HIGH", []),
            "MEDIUM": findings_by_severity.get("MEDIUM", []),
            "LOW": findings_by_severity.get("LOW", []),
        },
        "by_type": {
            test_type: findings for test_type, findings in findings_by_type.items()
        },
        "all_findings": findings,
    }
    
    # Write report
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    logger.info(f"Generated JSON report: {output_file}")


def generate_reports(
    findings_file: Path,
    scenario_dir: Path,
) -> None:
    """
    Generate both markdown and JSON reports.
    
    Args:
        findings_file: Path to findings.json
        scenario_dir: Scenario directory to save reports
    """
    markdown_file = scenario_dir / "report.md"
    json_file = scenario_dir / "report.json"
    
    generate_markdown_report(findings_file, markdown_file)
    generate_json_report(findings_file, json_file)

