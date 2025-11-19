# surfacerecon

**surfacerecon** is a complete automated web-API reconnaissance and vulnerability probing tool for bug-bounty researchers. It automatically captures API traffic, analyzes endpoints, generates test cases, and identifies potential vulnerabilities.

## Features

- **Automated Traffic Capture**: Uses Playwright to automatically navigate websites, fill forms, and capture all API requests/responses
- **Endpoint Discovery**: Parses captured traffic to identify API endpoints, parameters, and data patterns
- **ID Inference**: Automatically recognizes IDs (integers, UUIDs, common patterns) and builds ID pools for testing
- **Test Generation**: Generates comprehensive test cases for:
  - **IDOR** (Insecure Direct Object Reference)
  - **Auth Bypass** (Authentication/Authorization bypass)
  - **Method Confusion** (HTTP method tampering)
  - **Mass Assignment** (Parameter pollution)
- **Safe Execution**: Rate-limited, non-destructive test execution with researcher headers
- **Vulnerability Analysis**: Compares baseline vs test responses to detect vulnerabilities
- **Comprehensive Reporting**: Generates both Markdown and JSON reports with curl commands for reproduction

## Installation

### Prerequisites

- Python 3.11 or higher
- pip

### Setup

1. Clone or download this repository

2. Install the package:
```bash
pip install -e .
```

3. Install Playwright browsers:
```bash
playwright install chromium
```

## Quick Start

### Full Pipeline (Recommended)

Run the complete pipeline in one command:

```bash
surfacerecon full \
  --whitelist examples/whitelist_urls.txt \
  --cookie examples/sample_cookie.json \
  --header examples/sample_header.json
```

This will:
1. Capture API traffic from whitelisted URLs
2. Parse endpoints and infer IDs
3. Generate test cases
4. Execute tests safely
5. Analyze results and generate reports

### Step-by-Step Usage

You can also run each phase separately:

#### 1. Capture Traffic

```bash
surfacerecon capture \
  --whitelist examples/whitelist_urls.txt \
  --cookie examples/sample_cookie.json \
  --header examples/sample_header.json \
  --depth 3
```

This creates a timestamped scenario directory in `scenarios/` with captured requests.

#### 2. Parse Endpoints

```bash
surfacerecon parse --scenario scenarios/20251119_120000
```

Extracts endpoint models and identifies ID patterns.

#### 3. Generate Tests

```bash
surfacerecon generate \
  --scenario scenarios/20251119_120000 \
  --max-tests 30
```

Generates vulnerability test cases.

#### 4. Run Tests

```bash
surfacerecon run \
  --scenario scenarios/20251119_120000 \
  --cookie examples/sample_cookie.json \
  --concurrency 5 \
  --rate 2.0
```

Executes tests with rate limiting.

#### 5. Analyze Results

```bash
surfacerecon analyze --scenario scenarios/20251119_120000
```

Generates findings and reports (report.md and report.json).

## Configuration Files

### Whitelist URLs (`whitelist_urls.txt`)

One URL per line. Lines starting with `#` are comments.

```
https://example.com
https://example.com/api/v1/users
# https://example.com/payment  # This will be skipped
```

### Cookies (`sample_cookie.json`)

Standard Playwright cookie format:

```json
[
  {
    "name": "session",
    "value": "your-session-token",
    "domain": ".example.com",
    "path": "/",
    "expires": -1,
    "httpOnly": true,
    "secure": true
  }
]
```

### Headers (`sample_header.json`)

Simple key-value object:

```json
{
  "User-Agent": "surfacerecon/1.0",
  "X-Custom-Header": "value"
}
```

## Command Reference

### `capture`

Capture API traffic using Playwright.

**Options:**
- `--whitelist` (required): File with URLs to capture
- `--cookie`: Cookie JSON file
- `--header`: Header JSON file
- `--depth`: Navigation depth for BFS (default: 3)
- `--output`: Output directory (default: auto-generated timestamp)

### `parse`

Parse captured requests and extract endpoints.

**Options:**
- `--scenario` (required): Scenario directory path

### `generate`

Generate test cases from endpoints.

**Options:**
- `--scenario` (required): Scenario directory path
- `--max-tests`: Maximum tests per endpoint (default: 30)
- `--allow-destructive`: Allow destructive DELETE tests

### `run`

Execute test cases.

**Options:**
- `--scenario` (required): Scenario directory path
- `--cookie`: Cookie JSON file
- `--header`: Header JSON file
- `--concurrency`: Maximum concurrent requests (default: 5)
- `--rate`: Requests per second (default: 2.0)

### `analyze`

Analyze test results and generate findings.

**Options:**
- `--scenario` (required): Scenario directory path

### `full`

Run the complete pipeline.

**Options:**
- `--whitelist` (required): File with URLs to capture
- `--cookie`: Cookie JSON file
- `--header`: Header JSON file
- `--depth`: Navigation depth (default: 3)
- `--max-tests`: Maximum tests per endpoint (default: 30)
- `--concurrency`: Maximum concurrent requests (default: 5)
- `--rate`: Requests per second (default: 2.0)
- `--allow-destructive`: Allow destructive DELETE tests
- `--output`: Output directory (default: auto-generated timestamp)

## Output Structure

Each scenario creates a directory with:

```
scenarios/20251119_120000/
├── requests.json          # Captured API requests/responses
├── endpoints.json         # Parsed endpoint models
├── tests.json            # Generated test cases
├── test_results.json     # Test execution results
├── findings.json         # Vulnerability findings
├── report.md            # Markdown report
└── report.json          # Structured JSON report
```

## Report Format

### Markdown Report (`report.md`)

- Executive summary with total findings by severity
- Detailed sections for HIGH, MEDIUM, and LOW severity findings
- Reproduction curl commands for each finding
- Status change information

### JSON Report (`report.json`)

Structured data with:
- Summary statistics
- Findings grouped by severity
- Findings grouped by test type
- Complete finding details

## Safety Features

- **Rate Limiting**: Configurable requests per second to avoid overwhelming targets
- **Payment Route Detection**: Automatically skips payment/checkout URLs
- **Non-Destructive Defaults**: DELETE tests are disabled by default
- **Researcher Headers**: Includes identifiable headers for responsible disclosure
- **Body Truncation**: Large response bodies are truncated to prevent memory issues

## Test Types

### IDOR (Insecure Direct Object Reference)

Tests for unauthorized access by replacing IDs with IDs from other resource pools.

### Auth Bypass

Tests for authentication/authorization bypass by removing cookies and auth headers.

### Method Confusion

Tests for HTTP method tampering (e.g., using POST instead of GET, PUT instead of POST).

### Mass Assignment

Tests for parameter pollution by adding suspicious fields like `isAdmin`, `role`, `permissions`.

## Limitations

- Requires valid authentication cookies for protected endpoints
- May not capture all API endpoints if they're loaded dynamically
- Test generation is heuristic-based and may produce false positives
- Some endpoints may require manual verification

## Contributing

This is a research tool. Use responsibly and only on systems you have permission to test.

## License

MIT License

## Disclaimer

This tool is for authorized security testing only. Unauthorized use against systems you don't own or have explicit permission to test is illegal. The authors are not responsible for misuse of this tool.

