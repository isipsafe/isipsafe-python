from __future__ import annotations

import json

import pytest

from isipsafe.cli import main

from .test_client import CHECK_ALLOWLISTED, CHECK_BAD


@pytest.fixture(autouse=True)
def _no_env_key(monkeypatch):
    monkeypatch.delenv("ISIPSAFE_API_KEY", raising=False)
    monkeypatch.delenv("ISIPSAFE_KEY", raising=False)


def test_check_human_output(stub, capsys):
    stub.add("GET", "/api/v1/check", body=CHECK_BAD)
    code = main(["--base-url", stub.base_url, "check", "185.220.101.1"])
    out = capsys.readouterr().out
    assert code == 0
    assert "MALICIOUS" in out
    assert "86/100" in out
    assert "Tor exit" in out


def test_check_fail_if_malicious_exit_codes(stub):
    stub.add("GET", "/api/v1/check", body=CHECK_BAD)
    assert main(["--base-url", stub.base_url, "check", "185.220.101.1", "--fail-if-malicious"]) == 1
    stub.routes.clear()
    stub.add("GET", "/api/v1/check", body=CHECK_ALLOWLISTED)
    assert main(["--base-url", stub.base_url, "check", "8.8.8.8", "--fail-if-malicious"]) == 0


def test_check_json(stub, capsys):
    stub.add("GET", "/api/v1/check", body=CHECK_BAD)
    main(["--base-url", stub.base_url, "check", "185.220.101.1", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["abuse_confidence_score"] == 86
    assert "raw" not in data


def test_report_without_key_fails_cleanly(stub, capsys):
    code = main(["--base-url", stub.base_url, "report", "203.0.113.50", "-c", "ssh"])
    assert code == 2
    assert "API key" in capsys.readouterr().err
    assert stub.requests == []


def test_report_with_key(stub, capsys):
    stub.add("POST", "/api/v1/report", body={"data": {"ipAddress": "203.0.113.50", "abuseConfidenceScore": 40}})
    code = main(
        [
            "--api-key",
            "sl_x",
            "--base-url",
            stub.base_url,
            "report",
            "203.0.113.50",
            "-c",
            "ssh,brute-force",
            "-m",
            "hi",
        ]
    )
    assert code == 0
    assert "new score 40/100" in capsys.readouterr().out
    assert stub.requests[0].json()["categories"] == ["ssh", "brute-force"]


def test_bulk_report_from_file(stub, tmp_path, capsys):
    stub.add("POST", "/api/v1/bulk-report", body={"data": {"savedReports": 2, "invalidReports": []}})
    csv_file = tmp_path / "reports.csv"
    csv_file.write_text("203.0.113.50,ssh,,\n198.51.100.4,port-scan,,\n")
    code = main(["--api-key", "sl_x", "--base-url", stub.base_url, "bulk-report", str(csv_file)])
    assert code == 0
    assert "saved 2 reports" in capsys.readouterr().out
    assert stub.requests[0].body == csv_file.read_bytes()


def test_blocklist_to_file(stub, tmp_path):
    stub.add("GET", "/api/v1/blocklist", body=b"203.0.113.50\n")
    out = tmp_path / "list.txt"
    code = main(["--api-key", "sl_x", "--base-url", stub.base_url, "blocklist", "--format", "nginx", "-o", str(out)])
    assert code == 0
    assert out.read_text() == "203.0.113.50\n"
    assert stub.requests[0].query["format"] == ["nginx"]


def test_invalid_ip_is_a_clean_error(stub, capsys):
    assert main(["--base-url", stub.base_url, "check", "999.1.1.1"]) == 2
    assert "not a valid" in capsys.readouterr().err
