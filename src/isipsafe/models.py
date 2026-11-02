from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

DEFAULT_MALICIOUS_THRESHOLD = 75


@dataclass(frozen=True)
class Report:
    reported_at: Optional[str]
    comment: Optional[str]
    categories: List[str]
    category_ids: List[int]
    reporter: Optional[str]
    reporter_type: Optional[str]
    reporter_country_code: Optional[str]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Report:
        return cls(
            reported_at=data.get("reportedAt"),
            comment=data.get("comment"),
            categories=list(data.get("categories") or []),
            category_ids=list(data.get("categoryIds") or []),
            reporter=data.get("reporter"),
            reporter_type=data.get("reporterType"),
            reporter_country_code=data.get("reporterCountryCode"),
        )


@dataclass(frozen=True)
class CheckResult:
    ip_address: str
    abuse_confidence_score: int
    confidence_band: Optional[str]
    total_reports: int
    num_distinct_users: int
    is_public: bool
    is_whitelisted: bool
    is_tor: bool
    ip_version: Optional[int]
    first_reported_at: Optional[str]
    last_reported_at: Optional[str]
    categories: List[str]
    category_ids: List[int]
    country_code: Optional[str]
    country_name: Optional[str]
    region: Optional[str]
    city: Optional[str]
    asn: Optional[int]
    isp: Optional[str]
    domain: Optional[str]
    usage_type: Optional[str]
    hostnames: List[str]
    link: Optional[str]
    reports: List[Report] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CheckResult:
        return cls(
            ip_address=data.get("ipAddress", ""),
            abuse_confidence_score=int(data.get("abuseConfidenceScore") or 0),
            confidence_band=data.get("confidenceBand"),
            total_reports=int(data.get("totalReports") or 0),
            num_distinct_users=int(data.get("numDistinctUsers") or 0),
            is_public=bool(data.get("isPublic", True)),
            is_whitelisted=bool(data.get("isWhitelisted", False)),
            is_tor=bool(data.get("isTor", False)),
            ip_version=data.get("ipVersion"),
            first_reported_at=data.get("firstReportedAt"),
            last_reported_at=data.get("lastReportedAt"),
            categories=list(data.get("categories") or []),
            category_ids=list(data.get("categoryIds") or []),
            country_code=data.get("countryCode"),
            country_name=data.get("countryName"),
            region=data.get("region"),
            city=data.get("city"),
            asn=data.get("asn"),
            isp=data.get("isp"),
            domain=data.get("domain"),
            usage_type=data.get("usageType"),
            hostnames=list(data.get("hostnames") or []),
            link=data.get("link"),
            reports=[Report.from_dict(r) for r in data.get("reports") or []],
            raw=data,
        )

    def is_malicious(self, threshold: int = DEFAULT_MALICIOUS_THRESHOLD) -> bool:
        """True when the address has been reported and its score reaches ``threshold``.

        Allowlisted addresses (public DNS resolvers and the like) and addresses with
        no reports are never considered malicious.
        """
        if self.is_whitelisted or self.total_reports == 0:
            return False
        return self.abuse_confidence_score >= threshold


@dataclass(frozen=True)
class ReportResult:
    ip_address: str
    abuse_confidence_score: Optional[int]
    link: Optional[str]
    duplicate: bool = False

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ReportResult:
        score = data.get("abuseConfidenceScore")
        return cls(
            ip_address=data.get("ipAddress", ""),
            abuse_confidence_score=int(score) if score is not None else None,
            link=data.get("link"),
        )


@dataclass(frozen=True)
class InvalidReport:
    row_number: Optional[int]
    input: Optional[str]
    error: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> InvalidReport:
        return cls(
            row_number=data.get("rowNumber"),
            input=data.get("input"),
            error=str(data.get("error", "")),
        )


@dataclass(frozen=True)
class BulkReportResult:
    saved_reports: int
    invalid_reports: List[InvalidReport]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> BulkReportResult:
        return cls(
            saved_reports=int(data.get("savedReports") or 0),
            invalid_reports=[InvalidReport.from_dict(r) for r in data.get("invalidReports") or []],
        )


@dataclass(frozen=True)
class ReportsPage:
    ip_address: str
    total: int
    page: int
    per_page: int
    last_page: int
    results: List[Report]
    next_page_url: Optional[str]
    previous_page_url: Optional[str]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ReportsPage:
        return cls(
            ip_address=data.get("ipAddress", ""),
            total=int(data.get("total") or 0),
            page=int(data.get("page") or 1),
            per_page=int(data.get("perPage") or 0),
            last_page=int(data.get("lastPage") or 1),
            results=[Report.from_dict(r) for r in data.get("results") or []],
            next_page_url=data.get("nextPageUrl"),
            previous_page_url=data.get("previousPageUrl"),
        )


@dataclass(frozen=True)
class ReportedAddress:
    ip_address: str
    abuse_confidence_score: int
    num_reports: int
    most_recent_report: Optional[str]
    country_code: Optional[str]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ReportedAddress:
        return cls(
            ip_address=data.get("ipAddress", ""),
            abuse_confidence_score=int(data.get("abuseConfidenceScore") or 0),
            num_reports=int(data.get("numReports") or 0),
            most_recent_report=data.get("mostRecentReport"),
            country_code=data.get("countryCode"),
        )


@dataclass(frozen=True)
class NetworkResult:
    network_address: str
    netmask: int
    min_address: Optional[str]
    max_address: Optional[str]
    num_possible_hosts: Optional[str]
    asn: Optional[int]
    isp: Optional[str]
    country_code: Optional[str]
    reported_addresses: List[ReportedAddress]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> NetworkResult:
        return cls(
            network_address=data.get("networkAddress", ""),
            netmask=int(data.get("netmask") or 0),
            min_address=data.get("minAddress"),
            max_address=data.get("maxAddress"),
            num_possible_hosts=data.get("numPossibleHosts"),
            asn=data.get("asn"),
            isp=data.get("isp"),
            country_code=data.get("countryCode"),
            reported_addresses=[ReportedAddress.from_dict(r) for r in data.get("reportedAddress") or []],
        )


@dataclass(frozen=True)
class Category:
    id: int
    slug: str
    name: str
    group: Optional[str]
    description: Optional[str]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Category:
        return cls(
            id=int(data.get("id") or 0),
            slug=data.get("slug", ""),
            name=data.get("name", ""),
            group=data.get("group"),
            description=data.get("description"),
        )
