"""Official Python client for the isIPsafe IP reputation API (https://isipsafe.com)."""

from ._version import __version__
from .client import DEFAULT_BASE_URL, Client
from .errors import (
    APIError,
    AuthenticationError,
    IsIPsafeError,
    NetworkError,
    RateLimitError,
    ValidationError,
)
from .models import (
    BulkReportResult,
    Category,
    CheckResult,
    InvalidReport,
    NetworkResult,
    Report,
    ReportedAddress,
    ReportResult,
    ReportsPage,
)

__all__ = [
    "DEFAULT_BASE_URL",
    "APIError",
    "AuthenticationError",
    "BulkReportResult",
    "Category",
    "CheckResult",
    "Client",
    "InvalidReport",
    "IsIPsafeError",
    "NetworkError",
    "NetworkResult",
    "RateLimitError",
    "Report",
    "ReportResult",
    "ReportedAddress",
    "ReportsPage",
    "ValidationError",
    "__version__",
]
