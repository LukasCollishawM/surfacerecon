"""Configuration settings for surfacerecon."""

from typing import List, Dict, Any

# Default navigation settings
DEFAULT_NAVIGATION_DEPTH: int = 3
DEFAULT_MAX_PAGES: int = 50

# Rate limiting defaults
DEFAULT_CONCURRENCY: int = 5
DEFAULT_REQUESTS_PER_SECOND: float = 2.0

# Test generation limits
DEFAULT_MAX_TESTS_PER_ENDPOINT: int = 30
IDOR_TEST_COUNT: int = 10
AUTH_BYPASS_TEST_COUNT: int = 5
METHOD_CONFUSION_TEST_COUNT: int = 10
MASS_ASSIGNMENT_TEST_COUNT: int = 5

# Body truncation
MAX_BODY_SIZE: int = 20 * 1024  # 20KB

# Payment route keywords (case-insensitive matching)
PAYMENT_KEYWORDS: List[str] = [
    "payment",
    "checkout",
    "pay",
    "billing",
    "credit-card",
    "creditcard",
    "purchase",
    "subscribe",
    "subscription",
    "upgrade",
    "premium",
]

# Suspicious field names for mass-assignment tests
SUSPICIOUS_FIELDS: List[str] = [
    "isAdmin",
    "is_admin",
    "admin",
    "role",
    "roles",
    "isOwner",
    "is_owner",
    "owner",
    "permissions",
    "permission",
    "accessLevel",
    "access_level",
    "privileges",
    "privilege",
    "superuser",
    "super_user",
    "isSuperuser",
    "is_superuser",
]

# Sensitive fields for diff analysis
SENSITIVE_FIELDS: List[str] = [
    "ownerId",
    "owner_id",
    "userId",
    "user_id",
    "email",
    "role",
    "roles",
    "isAdmin",
    "is_admin",
    "permissions",
    "accessLevel",
    "access_level",
]

# Researcher header (can be overridden)
DEFAULT_RESEARCHER_HEADER: Dict[str, str] = {
    "User-Agent": "surfacerecon/1.0",
}

# HTTP methods to test
HTTP_METHODS: List[str] = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"]

# Destructive methods (require explicit flag)
DESTRUCTIVE_METHODS: List[str] = ["DELETE"]

# ID patterns to recognize
ID_PATTERNS: List[str] = [
    "id",
    "Id",
    "ID",
    "userId",
    "user_id",
    "userID",
    "projectId",
    "project_id",
    "projectID",
    "accountId",
    "account_id",
    "accountID",
    "resourceId",
    "resource_id",
    "resourceID",
]

# UUID regex pattern (standard format)
UUID_PATTERN: str = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"

# Diff analysis thresholds
LENGTH_DIFF_THRESHOLD: float = 0.30  # 30% difference

# Severity mappings
STATUS_CHANGE_HIGH: Dict[int, List[int]] = {
    403: [200, 201, 204],
    401: [200, 201, 204],
    404: [200, 201, 204],  # MEDIUM, but can be HIGH in some contexts
}

STATUS_CHANGE_MEDIUM: Dict[int, List[int]] = {
    404: [200, 201, 204],
    400: [200, 201, 204],
}

