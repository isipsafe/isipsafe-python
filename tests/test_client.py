from __future__ import annotations

from datetime import datetime, timezone

import pytest

from isipsafe import (
    APIError,
    AuthenticationError,
    Client,
    NetworkError,
    RateLimitError,
    ValidationError,
)

CHECK_BAD = {
    "data": {
        "ipAddress": "185.220.101.1",
        "abuseConfidenceScore": 86,
        "confidenceBand": "High",
        "totalReports": 41,
        "numDistinctUsers": 6,
        "isPublic": True,
        "isWhitelisted": False,
        "isTor": True,
        "ipVersion": 4,
        "categories": ["port-scan", "brute-force"],
        "categoryIds": [14, 18],
        "countryCode": "DE",
        "asn": 60729,
        "isp": "Example",
        "hostnames": [],
        "link": "https://isipsafe.com/ip/185.220.101.1",
        "reports": [{"reportedAt": "2026-11-02T07:37:29Z", "categories": ["ssh"], "comment": "x"}],
    }
}

CHECK_ALLOWLISTED = {
    "data": {
        "ipAddress": "8.8.8.8",
        "abuseConfidenceScore": 100,
        "confidenceBand": "High",
        "totalReports": 0,
        "isWhitelisted": True,
    }
}


def test_check_parses_response_and_sends_bearer(stub, client):
    stub.add("GET", "/api/v1/check", body=CHECK_BAD)
    result = client.check("185.220.101.1", max_age_in_days=90, verbose=True)

    assert result.ip_address == "185.220.101.1"
    assert result.abuse_confidence_score == 86
    assert result.is_tor is True
    assert result.categories == ["port-scan", "brute-force"]
    assert result.reports[0].categories == ["ssh"]
    assert result.is_malicious() is True
    assert result.is_malicious(threshold=90) is False

    req = stub.requests[0]
    assert req.query == {"ip": ["185.220.101.1"], "maxAgeInDays": ["90"], "verbose": ["true"]}
    assert req.headers["Authorization"] == "Bearer sl_test_key"
    assert req.headers["User-Agent"].startswith("isipsafe-python/")
    assert "key" not in req.query


def test_allowlisted_or_unreported_is_never_malicious(stub, client):
    stub.add("GET", "/api/v1/check", body=CHECK_ALLOWLISTED)
    assert client.is_malicious("8.8.8.8") is False


def test_check_rejects_invalid_ip_without_calling_api(stub, client):
    with pytest.raises(ValueError):
        client.check("not-an-ip")
    assert stub.requests == []


def test_lookups_work_without_key(stub, monkeypatch):
    monkeypatch.delenv("ISIPSAFE_API_KEY", raising=False)
    monkeypatch.delenv("ISIPSAFE_KEY", raising=False)
    anon = Client(base_url=stub.base_url)
    stub.add("GET", "/api/v1/check", body=CHECK_BAD)
    anon.check("185.220.101.1")
    assert "Authorization" not in stub.requests[0].headers


def test_key_is_read_from_environment(stub, monkeypatch):
    monkeypatch.setenv("ISIPSAFE_API_KEY", "  sl_env_key ")
    env_client = Client(base_url=stub.base_url)
    assert env_client.has_api_key
    assert "sl_env_key" not in repr(env_client)
    stub.add("GET", "/api/v1/check", body=CHECK_BAD)
    env_client.check("185.220.101.1")
    assert stub.requests[0].headers["Authorization"] == "Bearer sl_env_key"


def test_report_sends_json(stub, client):
    stub.add(
        "POST",
        "/api/v1/report",
        body={
            "data": {
                "ipAddress": "203.0.113.50",
                "abuseConfidenceScore": 87,
                "link": "https://isipsafe.com/ip/203.0.113.50",
            }
        },
    )
    when = datetime(2026, 11, 2, 7, 0, tzinfo=timezone.utc)
    result = client.report("203.0.113.50", "ssh, brute-force,ssh", comment="sshd: 212 failed logins", timestamp=when)

    assert result.abuse_confidence_score == 87
    assert result.duplicate is False
    req = stub.requests[0]
    assert req.headers["Content-Type"] == "application/json"
    assert req.json() == {
        "ip": "203.0.113.50",
        "categories": ["ssh", "brute-force"],
        "comment": "sshd: 212 failed logins",
        "timestamp": "2026-11-02T07:00:00Z",
    }


def test_report_accepts_numeric_ids_and_cidr(stub, client):
    stub.add("POST", "/api/v1/report", body={"data": {"ipAddress": "203.0.113.0/24"}})
    client.report("203.0.113.0/24", [22, 18])
    assert stub.requests[0].json()["categories"] == ["22", "18"]


def test_report_truncates_long_comment(stub, client):
    stub.add("POST", "/api/v1/report", body={"data": {"ipAddress": "203.0.113.50"}})
    client.report("203.0.113.50", "ssh", comment="x" * 5000)
    assert len(stub.requests[0].json()["comment"]) == 1024


def test_report_duplicate_within_15_minutes_is_not_an_error(stub, client):
    stub.add("POST", "/api/v1/report", status=429, body={"errors": [{"detail": "already reported", "status": 429}]})
    result = client.report("127.0.0.2", "ssh")
    assert result.duplicate is True


def test_report_requires_key(stub, monkeypatch):
    monkeypatch.delenv("ISIPSAFE_API_KEY", raising=False)
    monkeypatch.delenv("ISIPSAFE_KEY", raising=False)
    anon = Client(base_url=stub.base_url)
    with pytest.raises(AuthenticationError):
        anon.report("203.0.113.50", "ssh")
    assert stub.requests == []


def test_report_validates_categories(client):
    with pytest.raises(ValueError):
        client.report("203.0.113.50", "")
    with pytest.raises(ValueError):
        client.report("203.0.113.50", [str(i) for i in range(13)])


def test_bulk_report_builds_csv(stub, client):
    stub.add(
        "POST",
        "/api/v1/bulk-report",
        body={
            "data": {"savedReports": 1, "invalidReports": [{"rowNumber": 3, "input": "198.51.100.4", "error": "bad"}]}
        },
    )
    result = client.bulk_report(
        [
            {"ip": "203.0.113.50", "categories": ["ssh", "brute-force"], "comment": 'said "hi", twice'},
            ("198.51.100.4", "port-scan", "2026-11-02T07:00:00Z"),
        ]
    )
    assert result.saved_reports == 1
    assert result.invalid_reports[0].row_number == 3
    req = stub.requests[0]
    assert req.headers["Content-Type"] == "text/csv"
    assert req.body.decode() == (
        "IP,Categories,ReportDate,Comment\n"
        '203.0.113.50,"ssh,brute-force",,"said ""hi"", twice"\n'
        "198.51.100.4,port-scan,2026-11-02T07:00:00Z,\n"
    )


def test_bulk_report_is_not_retried(stub, client):
    stub.add("POST", "/api/v1/bulk-report", status=503, body={"errors": [{"detail": "down"}]})
    with pytest.raises(APIError) as info:
        client.bulk_report([("203.0.113.50", "ssh")])
    assert info.value.status == 503
    assert len(stub.requests) == 1


def test_validation_error_carries_detail(stub, client):
    stub.add(
        "GET",
        "/api/v1/check",
        status=422,
        body={"errors": [{"detail": "ip: that is not a valid IPv4 or IPv6 address", "status": 422}]},
    )
    with pytest.raises(ValidationError) as info:
        client.check("203.0.113.50")
    assert info.value.status == 422
    assert "not a valid" in str(info.value)


def test_wrong_key_raises_authentication_error(stub, client):
    stub.add("GET", "/api/v1/check", status=401, body={"errors": [{"detail": "invalid API key", "status": 401}]})
    with pytest.raises(AuthenticationError):
        client.check("203.0.113.50")


def test_rate_limit_exposes_retry_after(stub, client):
    stub.add(
        "GET", "/api/v1/check", status=429, body={"errors": [{"detail": "slow down"}]}, headers={"Retry-After": "42"}
    )
    with pytest.raises(RateLimitError) as info:
        client.check("203.0.113.50")
    assert info.value.retry_after == 42


def test_server_errors_are_retried_for_lookups(stub, client):
    stub.add("GET", "/api/v1/check", status=502, body={"errors": [{"detail": "bad gateway"}]})
    stub.add("GET", "/api/v1/check", body=CHECK_BAD)
    result = client.check("185.220.101.1")
    assert result.abuse_confidence_score == 86
    assert len(stub.requests) == 2


def test_server_errors_give_up_after_max_retries(stub, client):
    stub.add("GET", "/api/v1/check", status=500, body={"errors": [{"detail": "boom"}]})
    with pytest.raises(APIError):
        client.check("185.220.101.1")
    assert len(stub.requests) == 3


def test_unreachable_api_raises_network_error():
    offline = Client("k", base_url="http://127.0.0.1:9/api/v1", timeout=1, max_retries=1)
    offline._sleep = lambda _seconds: None
    with pytest.raises(NetworkError):
        offline.check("203.0.113.50")


def test_reports_page(stub, client):
    stub.add(
        "GET",
        "/api/v1/reports",
        body={
            "data": {
                "ipAddress": "185.220.101.1",
                "total": 24,
                "page": 1,
                "perPage": 2,
                "lastPage": 12,
                "nextPageUrl": "https://isipsafe.com/api/v1/reports?page=2",
                "previousPageUrl": None,
                "results": [{"reportedAt": "2026-11-02T07:37:29Z", "categories": ["c2"], "reporter": "Automated feed"}],
            }
        },
    )
    page = client.reports("185.220.101.1", per_page=2)
    assert page.total == 24
    assert page.last_page == 12
    assert page.results[0].reporter == "Automated feed"
    assert stub.requests[0].query["perPage"] == ["2"]


def test_check_block(stub, client):
    stub.add(
        "GET",
        "/api/v1/check-block",
        body={
            "data": {
                "networkAddress": "185.220.101.0",
                "netmask": 28,
                "reportedAddress": [
                    {"ipAddress": "185.220.101.11", "abuseConfidenceScore": 61, "numReports": 27, "countryCode": "DE"}
                ],
            }
        },
    )
    net = client.check_block("185.220.101.0/28")
    assert net.netmask == 28
    assert net.reported_addresses[0].num_reports == 27
    with pytest.raises(ValueError):
        client.check_block("nope")


def test_blocklist(stub, client):
    stub.add("GET", "/api/v1/blocklist", body=b"# isipsafe\n203.0.113.50\n\n198.51.100.4\n")
    ips = client.blocklist(confidence_minimum=90, except_countries=["GB", "IE"], ip_version=4)
    assert ips == ["203.0.113.50", "198.51.100.4"]
    q = stub.requests[0].query
    assert q["format"] == ["txt"]
    assert q["confidenceMinimum"] == ["90"]
    assert q["exceptCountries"] == ["GB,IE"]
    assert q["ipVersion"] == ["4"]
    with pytest.raises(ValueError):
        client.blocklist_raw(format="exe")


def test_clear_address_uses_delete(stub, client):
    stub.add("DELETE", "/api/v1/clear-address", body={"data": {"numReportsDeleted": 3}})
    assert client.clear_address("203.0.113.50") == {"numReportsDeleted": 3}
    assert stub.requests[0].method == "DELETE"


def test_categories(stub, client):
    stub.add(
        "GET",
        "/api/v1/categories",
        body={"data": [{"id": 22, "slug": "ssh", "name": "SSH", "group": "Authentication", "description": "d"}]},
    )
    cats = client.categories()
    assert cats[0].slug == "ssh"
    assert cats[0].id == 22
