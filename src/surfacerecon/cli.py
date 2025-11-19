"""CLI module for surfacerecon."""

import asyncio
import json
import logging
from pathlib import Path
from typing import Optional

import click

from surfacerecon.capture.playwright_capture import capture_session
from surfacerecon.parser.har_parser import parse_requests, save_endpoints
from surfacerecon.parser.id_inference import enhance_endpoints_with_ids
from surfacerecon.generator.test_generator import generate_tests
from surfacerecon.runner.test_runner import run_tests
from surfacerecon.analyzer.diff_analyzer import analyze_results
from surfacerecon.analyzer.report_generator import generate_reports
from surfacerecon.settings import (
    DEFAULT_NAVIGATION_DEPTH,
    DEFAULT_CONCURRENCY,
    DEFAULT_REQUESTS_PER_SECOND,
    DEFAULT_MAX_TESTS_PER_ENDPOINT,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def load_json_file(file_path: Path) -> dict:
    """Load JSON file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        raise click.BadParameter(f"Failed to load JSON file {file_path}: {e}")


def load_whitelist(file_path: Path) -> list[str]:
    """Load whitelist URLs from file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        return urls
    except Exception as e:
        raise click.BadParameter(f"Failed to load whitelist file {file_path}: {e}")


@click.group()
def main():
    """surfacerecon - Automated web-API reconnaissance and vulnerability probing tool."""
    pass


@main.command()
@click.option("--whitelist", required=True, type=click.Path(exists=True), help="File with whitelist URLs (one per line)")
@click.option("--cookie", type=click.Path(exists=True), help="Cookie JSON file")
@click.option("--header", type=click.Path(exists=True), help="Header JSON file")
@click.option("--depth", type=int, default=DEFAULT_NAVIGATION_DEPTH, help="Navigation depth for BFS")
@click.option("--output", type=click.Path(), help="Output scenario directory (default: scenarios/<timestamp>)")
def capture(whitelist: str, cookie: Optional[str], header: Optional[str], depth: int, output: Optional[str]):
    """Capture API traffic using Playwright."""
    from datetime import datetime
    
    whitelist_path = Path(whitelist)
    urls = load_whitelist(whitelist_path)
    
    if not urls:
        raise click.BadParameter("Whitelist file is empty")
    
    cookies = None
    if cookie:
        cookies = load_json_file(Path(cookie))
        if not isinstance(cookies, list):
            raise click.BadParameter("Cookie file must contain a JSON array")
    
    headers = None
    if header:
        headers = load_json_file(Path(header))
        if not isinstance(headers, dict):
            raise click.BadParameter("Header file must contain a JSON object")
    
    if output:
        output_dir = Path(output)
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = Path("scenarios") / timestamp
    
    click.echo(f"Capturing traffic from {len(urls)} URLs...")
    click.echo(f"Output directory: {output_dir}")
    
    asyncio.run(capture_session(urls, output_dir, cookies, headers, depth))
    
    click.echo(f"Capture complete! Requests saved to {output_dir / 'requests.json'}")


@main.command()
@click.option("--scenario", required=True, type=click.Path(exists=True), help="Scenario directory path")
def parse(scenario: str):
    """Parse captured requests and extract endpoints."""
    scenario_dir = Path(scenario)
    requests_file = scenario_dir / "requests.json"
    
    if not requests_file.exists():
        raise click.BadParameter(f"requests.json not found in {scenario_dir}")
    
    click.echo(f"Parsing requests from {requests_file}...")
    
    endpoints = parse_requests(requests_file)
    
    # Enhance with ID inference
    endpoints_data = [endpoint.to_dict() for endpoint in endpoints]
    enhanced_endpoints = enhance_endpoints_with_ids(endpoints_data)
    
    endpoints_file = scenario_dir / "endpoints.json"
    with open(endpoints_file, "w", encoding="utf-8") as f:
        json.dump(enhanced_endpoints, f, indent=2, ensure_ascii=False)
    
    click.echo(f"Parsed {len(enhanced_endpoints)} endpoints, saved to {endpoints_file}")


@main.command()
@click.option("--scenario", required=True, type=click.Path(exists=True), help="Scenario directory path")
@click.option("--max-tests", type=int, default=DEFAULT_MAX_TESTS_PER_ENDPOINT, help="Maximum tests per endpoint")
@click.option("--allow-destructive", is_flag=True, help="Allow destructive DELETE tests")
def generate(scenario: str, max_tests: int, allow_destructive: bool):
    """Generate test cases from endpoints."""
    scenario_dir = Path(scenario)
    endpoints_file = scenario_dir / "endpoints.json"
    
    if not endpoints_file.exists():
        raise click.BadParameter(f"endpoints.json not found in {scenario_dir}")
    
    click.echo(f"Generating tests from {endpoints_file}...")
    
    tests_file = scenario_dir / "tests.json"
    generate_tests(endpoints_file, tests_file, max_tests, allow_destructive)
    
    click.echo(f"Tests generated, saved to {tests_file}")


@main.command()
@click.option("--scenario", required=True, type=click.Path(exists=True), help="Scenario directory path")
@click.option("--cookie", type=click.Path(exists=True), help="Cookie JSON file")
@click.option("--header", type=click.Path(exists=True), help="Header JSON file")
@click.option("--concurrency", type=int, default=DEFAULT_CONCURRENCY, help="Maximum concurrent requests")
@click.option("--rate", type=float, default=DEFAULT_REQUESTS_PER_SECOND, help="Requests per second")
def run(scenario: str, cookie: Optional[str], header: Optional[str], concurrency: int, rate: float):
    """Run test cases against the target."""
    scenario_dir = Path(scenario)
    tests_file = scenario_dir / "tests.json"
    
    if not tests_file.exists():
        raise click.BadParameter(f"tests.json not found in {scenario_dir}")
    
    cookies = None
    if cookie:
        cookies = load_json_file(Path(cookie))
        if not isinstance(cookies, list):
            raise click.BadParameter("Cookie file must contain a JSON array")
    
    headers = None
    if header:
        headers = load_json_file(Path(header))
        if not isinstance(headers, dict):
            raise click.BadParameter("Header file must contain a JSON object")
    
    click.echo(f"Running tests from {tests_file}...")
    click.echo(f"Concurrency: {concurrency}, Rate: {rate}/s")
    
    results_file = scenario_dir / "test_results.json"
    asyncio.run(run_tests(tests_file, results_file, cookies, headers, concurrency, rate))
    
    click.echo(f"Tests complete! Results saved to {results_file}")


@main.command()
@click.option("--scenario", required=True, type=click.Path(exists=True), help="Scenario directory path")
def analyze(scenario: str):
    """Analyze test results and generate findings."""
    scenario_dir = Path(scenario)
    requests_file = scenario_dir / "requests.json"
    test_results_file = scenario_dir / "test_results.json"
    tests_file = scenario_dir / "tests.json"
    
    for file_path, name in [
        (requests_file, "requests.json"),
        (test_results_file, "test_results.json"),
        (tests_file, "tests.json"),
    ]:
        if not file_path.exists():
            raise click.BadParameter(f"{name} not found in {scenario_dir}")
    
    click.echo("Analyzing test results...")
    
    findings_file = scenario_dir / "findings.json"
    analyze_results(requests_file, test_results_file, tests_file, findings_file)
    
    click.echo(f"Analysis complete! Findings saved to {findings_file}")
    
    # Generate reports
    click.echo("Generating reports...")
    generate_reports(findings_file, scenario_dir)
    click.echo("Reports generated: report.md and report.json")


@main.command()
@click.option("--whitelist", required=True, type=click.Path(exists=True), help="File with whitelist URLs (one per line)")
@click.option("--cookie", type=click.Path(exists=True), help="Cookie JSON file")
@click.option("--header", type=click.Path(exists=True), help="Header JSON file")
@click.option("--depth", type=int, default=DEFAULT_NAVIGATION_DEPTH, help="Navigation depth for BFS")
@click.option("--max-tests", type=int, default=DEFAULT_MAX_TESTS_PER_ENDPOINT, help="Maximum tests per endpoint")
@click.option("--concurrency", type=int, default=DEFAULT_CONCURRENCY, help="Maximum concurrent requests")
@click.option("--rate", type=float, default=DEFAULT_REQUESTS_PER_SECOND, help="Requests per second")
@click.option("--allow-destructive", is_flag=True, help="Allow destructive DELETE tests")
@click.option("--output", type=click.Path(), help="Output scenario directory (default: scenarios/<timestamp>)")
def full(
    whitelist: str,
    cookie: Optional[str],
    header: Optional[str],
    depth: int,
    max_tests: int,
    concurrency: int,
    rate: float,
    allow_destructive: bool,
    output: Optional[str],
):
    """Run the complete surfacerecon pipeline."""
    from datetime import datetime
    
    click.echo("=== surfacerecon Full Pipeline ===\n")
    
    # Step 1: Capture
    click.echo("[1/5] Capturing traffic...")
    whitelist_path = Path(whitelist)
    urls = load_whitelist(whitelist_path)
    
    cookies = None
    if cookie:
        cookies = load_json_file(Path(cookie))
    
    headers = None
    if header:
        headers = load_json_file(Path(header))
    
    if output:
        scenario_dir = Path(output)
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scenario_dir = Path("scenarios") / timestamp
    
    asyncio.run(capture_session(urls, scenario_dir, cookies, headers, depth))
    click.echo(f"✓ Capture complete\n")
    
    # Step 2: Parse
    click.echo("[2/5] Parsing endpoints...")
    requests_file = scenario_dir / "requests.json"
    endpoints = parse_requests(requests_file)
    endpoints_data = [endpoint.to_dict() for endpoint in endpoints]
    enhanced_endpoints = enhance_endpoints_with_ids(endpoints_data)
    endpoints_file = scenario_dir / "endpoints.json"
    with open(endpoints_file, "w", encoding="utf-8") as f:
        json.dump(enhanced_endpoints, f, indent=2, ensure_ascii=False)
    click.echo(f"✓ Parsed {len(enhanced_endpoints)} endpoints\n")
    
    # Step 3: Generate
    click.echo("[3/5] Generating tests...")
    tests_file = scenario_dir / "tests.json"
    generate_tests(endpoints_file, tests_file, max_tests, allow_destructive)
    click.echo("✓ Tests generated\n")
    
    # Step 4: Run
    click.echo("[4/5] Running tests...")
    results_file = scenario_dir / "test_results.json"
    asyncio.run(run_tests(tests_file, results_file, cookies, headers, concurrency, rate))
    click.echo("✓ Tests complete\n")
    
    # Step 5: Analyze
    click.echo("[5/5] Analyzing results...")
    findings_file = scenario_dir / "findings.json"
    analyze_results(requests_file, results_file, tests_file, findings_file)
    generate_reports(findings_file, scenario_dir)
    click.echo("✓ Analysis complete\n")
    
    click.echo(f"=== Pipeline Complete ===")
    click.echo(f"Results saved to: {scenario_dir}")
    click.echo(f"  - report.md")
    click.echo(f"  - report.json")
    click.echo(f"  - findings.json")


if __name__ == "__main__":
    main()

