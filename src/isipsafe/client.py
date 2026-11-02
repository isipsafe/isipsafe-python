from __future__ import annotations

import csv
import io
import ipaddress
import json
import os
import random
import time
from datetime import datetime, timezone
from email.message import Message
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union
from urllib import error as urlerror
from urllib import parse, request

from ._version import __version__
from .errors import (
    APIError,
    AuthenticationError,
    IsIPsafeError,
    NetworkError,
    RateLimitError,
    ValidationError,
)
from .models import (
    DEFAULT_MALICIOUS_THRESHOLD,
    BulkReportResult,
    Category,
    CheckResult,
    NetworkResult,
    ReportResult,
    ReportsPage,
)

DEFAULT_BASE_URL = "https://isipsafe.com/api/v1"
DEFAULT_TIMEOUT = 10.0
DEFAULT_MAX_RETRIES = 2
MAX_CATEGORIES = 12
MAX_COMMENT_LENGTH = 1024
MAX_BULK_ROWS = 10000
BLOCKLIST_FORMATS = ("json", "txt", "csv", "stix", "ipset", "nftables", "nginx", "apache", "mikrotik")
API_KEY_ENV_VARS = ("ISIPSAFE_API_KEY", "ISIPSAFE_KEY")

Categories = Union[str, int, Iterable[Union[str, int]]]
Timestamp = Union[str, datetime, None]
BulkRow = Union[Mapping[str, Any], Sequence[Any]]


def _env_api_key() -> Optional[str]:
    for name in API_KEY_ENV_VARS:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return None


def _normalize_categories(categories: Categories) -> List[str]:
    if isinstance(categories, (str, int)):
        items: Iterable[Union[str, int]] = str(categories).split(",")
    else:
        items = categories
    result: List[str] = []
    for item in items:
        value = str(item).strip()
        if value and value not in result:
            result.append(value)
    if not result:
        raise ValueError("at least one category is required, e.g. 'ssh,brute-force'")
    if len(result) > MAX_CATEGORIES:
        raise ValueError(f"at most {MAX_CATEGORIES} categories per report, got {len(result)}")
    return result


def _format_timestamp(value: Timestamp) -> Optional[str]:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return str(value)


def _validate_ip(ip: str) -> str:
    value = str(ip).strip()
    try:
        ipaddress.ip_address(value)
    except ValueError:
        raise ValueError(f"not a valid IPv4 or IPv6 address: {ip!r}") from None
    return value


def _validate_ip_or_network(ip: str) -> str:
    value = str(ip).strip()
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
    except ValueError:
        raise ValueError(f"not a valid IP address or CIDR network: {ip!r}") from None
    return value


def _parse_json(payload: bytes) -> Any:
    if not payload:
        return None
    try:
        return json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None


def _error_detail(body: Any, fallback: str) -> str:
    if isinstance(body, dict):
        errors = body.get("errors")
        if isinstance(errors, list) and errors and isinstance(errors[0], dict):
            detail = errors[0].get("detail")
            if detail:
                return str(detail)
        if body.get("detail"):
            return str(body["detail"])
    return fallback


def _retry_after(headers: Optional[Message]) -> Optional[float]:
    if headers is None:
        return None
    value = headers.get("Retry-After")
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        return None


class Client:
    """Client for the isIPsafe API (https://isipsafe.com/api).

    The API key is read from ``api_key`` or, when that is omitted, from the
    ``ISIPSAFE_API_KEY`` environment variable. Lookups work without a key;
    reporting, bulk uploads, the blocklist and clearing reports need one.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
        user_agent: Optional[str] = None,
    ) -> None:
        key = api_key.strip() if isinstance(api_key, str) else _env_api_key()
        self._api_key = key or None
        if not base_url.startswith(("https://", "http://")):
            raise ValueError("base_url must start with https:// or http://")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max(0, int(max_retries))
        self.user_agent = user_agent or f"isipsafe-python/{__version__}"
        self._opener = request.build_opener()
        self._sleep: Callable[[float], None] = time.sleep

    def __repr__(self) -> str:
        return f"Client(base_url={self.base_url!r}, has_api_key={self.has_api_key})"

    @property
    def has_api_key(self) -> bool:
        return self._api_key is not None

    def check(self, ip: str, *, max_age_in_days: Optional[int] = None, verbose: bool = False) -> CheckResult:
        """Reputation of one address: score, report counts, location and network."""
        data = self._get_json(
            "/check",
            {"ip": _validate_ip(ip), "maxAgeInDays": max_age_in_days, "verbose": verbose},
        )
        return CheckResult.from_dict(data)

    def is_malicious(self, ip: str, *, threshold: int = DEFAULT_MALICIOUS_THRESHOLD) -> bool:
        """True when the address has reports and a score of at least ``threshold`` (default 75)."""
        return self.check(ip).is_malicious(threshold)

    def report(
        self,
        ip: str,
        categories: Categories,
        *,
        comment: Optional[str] = None,
        timestamp: Timestamp = None,
    ) -> ReportResult:
        """Report an abusive address or CIDR network.

        ``categories`` takes slugs or numeric IDs, as a list or a comma separated
        string. The API accepts one report per address every 15 minutes from the
        same account; a repeat is returned with ``duplicate=True`` instead of
        raising. The comment is public, so leave out anything personal.
        """
        target = _validate_ip_or_network(ip)
        payload: Dict[str, Any] = {"ip": target, "categories": _normalize_categories(categories)}
        if comment:
            payload["comment"] = str(comment)[:MAX_COMMENT_LENGTH]
        formatted = _format_timestamp(timestamp)
        if formatted:
            payload["timestamp"] = formatted
        try:
            _, _, body = self._request(
                "POST",
                "/report",
                body=json.dumps(payload).encode("utf-8"),
                content_type="application/json",
                require_key=True,
            )
        except RateLimitError:
            return ReportResult(ip_address=target, abuse_confidence_score=None, link=None, duplicate=True)
        return ReportResult.from_dict(self._unwrap(body))

    def bulk_report(self, reports: Iterable[BulkRow]) -> BulkReportResult:
        """Upload up to 10,000 reports in one request.

        Each item is a mapping with ``ip``, ``categories`` and optional
        ``timestamp`` and ``comment``, or a ``(ip, categories, timestamp, comment)``
        sequence.
        """
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(["IP", "Categories", "ReportDate", "Comment"])
        count = 0
        for row in reports:
            if isinstance(row, Mapping):
                ip, cats, ts, comment = row.get("ip"), row.get("categories"), row.get("timestamp"), row.get("comment")
            else:
                padded = list(row) + [None] * (4 - len(row))
                ip, cats, ts, comment = padded[:4]
            if ip is None or cats is None:
                raise ValueError(f"row {count + 1}: ip and categories are required")
            writer.writerow(
                [
                    _validate_ip_or_network(str(ip)),
                    ",".join(_normalize_categories(cats)),
                    _format_timestamp(ts) or "",
                    str(comment or "")[:MAX_COMMENT_LENGTH],
                ]
            )
            count += 1
            if count > MAX_BULK_ROWS:
                raise ValueError(f"at most {MAX_BULK_ROWS} reports per bulk upload")
        if count == 0:
            raise ValueError("no reports to upload")
        return self.bulk_report_csv(buffer.getvalue())

    def bulk_report_csv(self, csv_text: Union[str, bytes]) -> BulkReportResult:
        """Upload a CSV with columns ``IP,Categories,ReportDate,Comment`` as-is."""
        body = csv_text.encode("utf-8") if isinstance(csv_text, str) else csv_text
        _, _, payload = self._request(
            "POST",
            "/bulk-report",
            body=body,
            content_type="text/csv",
            require_key=True,
            retry=False,
        )
        return BulkReportResult.from_dict(self._unwrap(payload))

    def reports(
        self,
        ip: str,
        *,
        max_age_in_days: Optional[int] = None,
        page: int = 1,
        per_page: int = 25,
    ) -> ReportsPage:
        """One page of reports for an address, newest first."""
        data = self._get_json(
            "/reports",
            {"ip": _validate_ip(ip), "maxAgeInDays": max_age_in_days, "page": page, "perPage": per_page},
        )
        return ReportsPage.from_dict(data)

    def check_block(self, network: str, *, max_age_in_days: Optional[int] = None) -> NetworkResult:
        """Reported addresses inside a network (IPv4 up to a /16, IPv6 up to a /48)."""
        value = str(network).strip()
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise ValueError(f"not a valid CIDR network: {network!r}") from None
        data = self._get_json("/check-block", {"network": value, "maxAgeInDays": max_age_in_days})
        return NetworkResult.from_dict(data)

    def blocklist(
        self,
        *,
        confidence_minimum: Optional[int] = None,
        limit: Optional[int] = None,
        days: Optional[int] = None,
        ip_version: Optional[int] = None,
        only_countries: Optional[Iterable[str]] = None,
        except_countries: Optional[Iterable[str]] = None,
    ) -> List[str]:
        """The highest-confidence addresses as a list of strings."""
        text = self.blocklist_raw(
            format="txt",
            confidence_minimum=confidence_minimum,
            limit=limit,
            days=days,
            ip_version=ip_version,
            only_countries=only_countries,
            except_countries=except_countries,
        )
        return [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]

    def blocklist_raw(
        self,
        *,
        format: str = "txt",
        confidence_minimum: Optional[int] = None,
        limit: Optional[int] = None,
        days: Optional[int] = None,
        ip_version: Optional[int] = None,
        only_countries: Optional[Iterable[str]] = None,
        except_countries: Optional[Iterable[str]] = None,
    ) -> str:
        """The blocklist in a firewall-ready format: json, txt, csv, stix, ipset,
        nftables, nginx, apache or mikrotik."""
        if format not in BLOCKLIST_FORMATS:
            raise ValueError(f"format must be one of {', '.join(BLOCKLIST_FORMATS)}")
        params = {
            "format": format,
            "confidenceMinimum": confidence_minimum,
            "limit": limit,
            "days": days,
            "ipVersion": ip_version,
            "onlyCountries": ",".join(only_countries) if only_countries else None,
            "exceptCountries": ",".join(except_countries) if except_countries else None,
        }
        _, _, body = self._request("GET", "/blocklist", params=params, require_key=True, accept="*/*")
        return body.decode("utf-8")

    def clear_address(self, ip: str) -> Dict[str, Any]:
        """Delete every report this account filed against an address."""
        _, _, body = self._request(
            "DELETE",
            "/clear-address",
            params={"ip": _validate_ip_or_network(ip)},
            require_key=True,
        )
        data = self._unwrap(body)
        return data if isinstance(data, dict) else {"result": data}

    def categories(self) -> List[Category]:
        """Every report category with its slug, name, group and numeric ID."""
        data = self._get_json("/categories")
        return [Category.from_dict(c) for c in data or []]

    def _get_json(self, path: str, params: Optional[Mapping[str, Any]] = None) -> Any:
        _, _, body = self._request("GET", path, params=params)
        return self._unwrap(body)

    @staticmethod
    def _unwrap(body: bytes) -> Any:
        parsed = _parse_json(body)
        if isinstance(parsed, dict) and "data" in parsed:
            return parsed["data"]
        if parsed is None:
            raise IsIPsafeError("the API returned a response that is not JSON")
        return parsed

    def _build_url(self, path: str, params: Optional[Mapping[str, Any]]) -> str:
        query: List[Tuple[str, str]] = []
        for name, value in (params or {}).items():
            if value is None or value is False:
                continue
            query.append((name, "true" if value is True else str(value)))
        url = f"{self.base_url}{path}"
        return f"{url}?{parse.urlencode(query)}" if query else url

    def _backoff(self, attempt: int, retry_after: Optional[float] = None) -> None:
        if retry_after is not None:
            delay = min(retry_after, 30.0)
        else:
            delay = min(0.5 * (2**attempt), 8.0) + random.uniform(0, 0.25)
        self._sleep(delay)

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        body: Optional[bytes] = None,
        content_type: Optional[str] = None,
        require_key: bool = False,
        retry: bool = True,
        accept: str = "application/json",
    ) -> Tuple[int, Message, bytes]:
        if require_key and not self._api_key:
            raise AuthenticationError(
                "this endpoint needs an API key; get a free one at https://isipsafe.com/login "
                "and pass api_key= or set ISIPSAFE_API_KEY",
                401,
            )
        url = self._build_url(path, params)
        headers = {"Accept": accept, "User-Agent": self.user_agent}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        if content_type:
            headers["Content-Type"] = content_type

        attempts = 1 + (self.max_retries if retry else 0)
        for attempt in range(attempts):
            req = request.Request(url, data=body, method=method, headers=headers)
            last_attempt = attempt == attempts - 1
            try:
                with self._opener.open(req, timeout=self.timeout) as response:
                    return response.status, response.headers, response.read()
            except urlerror.HTTPError as exc:
                payload = exc.read()
                if exc.code >= 500 and not last_attempt:
                    self._backoff(attempt)
                    continue
                raise self._api_error(exc.code, exc.headers, payload) from None
            except (urlerror.URLError, OSError) as exc:
                if not last_attempt:
                    self._backoff(attempt)
                    continue
                reason = getattr(exc, "reason", exc)
                raise NetworkError(f"could not reach {self.base_url}: {reason}") from exc
        raise NetworkError(f"could not reach {self.base_url}")

    @staticmethod
    def _api_error(status: int, headers: Optional[Message], payload: bytes) -> APIError:
        body = _parse_json(payload)
        message = _error_detail(body, f"HTTP {status}")
        if status == 401:
            return AuthenticationError(message, status, body)
        if status == 422 or status == 400:
            return ValidationError(message, status, body)
        if status == 429:
            return RateLimitError(message, status, body, _retry_after(headers))
        return APIError(message, status, body)
