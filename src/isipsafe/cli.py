from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from typing import Any, List, Optional, Sequence

from ._version import __version__
from .client import BLOCKLIST_FORMATS, DEFAULT_BASE_URL, Client
from .errors import IsIPsafeError
from .models import DEFAULT_MALICIOUS_THRESHOLD, CheckResult

EXIT_OK = 0
EXIT_MALICIOUS = 1
EXIT_ERROR = 2


def _plain(value: Any) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        data = dataclasses.asdict(value)
        data.pop("raw", None)
        return data
    if isinstance(value, list):
        return [_plain(v) for v in value]
    return value


def _print_json(value: Any) -> None:
    print(json.dumps(_plain(value), indent=2, default=str))


def _describe_check(result: CheckResult, threshold: int) -> str:
    verdict = "MALICIOUS" if result.is_malicious(threshold) else "not flagged"
    lines = [
        f"{result.ip_address}  {verdict}",
        f"  score       {result.abuse_confidence_score}/100 ({result.confidence_band or 'n/a'})",
        f"  reports     {result.total_reports} from {result.num_distinct_users} reporters",
    ]
    if result.last_reported_at:
        lines.append(f"  last seen   {result.last_reported_at}")
    if result.categories:
        lines.append(f"  categories  {', '.join(result.categories)}")
    network = " ".join(
        part
        for part in (
            result.country_code,
            f"AS{result.asn}" if result.asn else None,
            result.isp,
        )
        if part
    )
    if network:
        lines.append(f"  network     {network}")
    flags = [name for name, on in (("Tor exit", result.is_tor), ("allowlisted", result.is_whitelisted)) if on]
    if flags:
        lines.append(f"  flags       {', '.join(flags)}")
    if result.link:
        lines.append(f"  details     {result.link}")
    return "\n".join(lines)


def _countries(value: Optional[str]) -> Optional[List[str]]:
    if not value:
        return None
    return [c.strip().upper() for c in value.split(",") if c.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="isipsafe",
        description="Check and report IP addresses with isIPsafe (https://isipsafe.com).",
        epilog="Set ISIPSAFE_API_KEY to report or download the blocklist. Free key: https://isipsafe.com/login",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--api-key", help="API key (default: $ISIPSAFE_API_KEY)")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help=argparse.SUPPRESS)
    parser.add_argument("--timeout", type=float, default=10.0, help="request timeout in seconds (default 10)")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    check = sub.add_parser("check", help="reputation of an IP address")
    check.add_argument("ip")
    check.add_argument("--max-age", type=int, help="count reports from the last N days (1-365)")
    check.add_argument("--verbose", action="store_true", help="include the latest reports")
    check.add_argument(
        "--threshold",
        type=int,
        default=DEFAULT_MALICIOUS_THRESHOLD,
        help=f"score at which an address counts as malicious (default {DEFAULT_MALICIOUS_THRESHOLD})",
    )
    check.add_argument(
        "--fail-if-malicious",
        action="store_true",
        help="exit with status 1 when the address is malicious, for use in scripts",
    )
    check.add_argument("--json", action="store_true", help="print JSON")

    report = sub.add_parser("report", help="report an abusive IP address or network")
    report.add_argument("ip")
    report.add_argument("-c", "--categories", required=True, help="comma separated, e.g. ssh,brute-force")
    report.add_argument("-m", "--comment", help="public comment, up to 1024 characters")
    report.add_argument("--timestamp", help="when it happened (RFC 3339), default now")
    report.add_argument("--json", action="store_true", help="print JSON")

    bulk = sub.add_parser("bulk-report", help="upload a CSV of reports (IP,Categories,ReportDate,Comment)")
    bulk.add_argument("file", help="CSV file, or - for stdin")
    bulk.add_argument("--json", action="store_true", help="print JSON")

    reports = sub.add_parser("reports", help="list reports for an IP address")
    reports.add_argument("ip")
    reports.add_argument("--max-age", type=int, help="1-365 days, default 30")
    reports.add_argument("--page", type=int, default=1)
    reports.add_argument("--per-page", type=int, default=25)
    reports.add_argument("--json", action="store_true", help="print JSON")

    block = sub.add_parser("check-block", help="reported addresses inside a network")
    block.add_argument("network", help="CIDR, up to a /16 (IPv4) or /48 (IPv6)")
    block.add_argument("--max-age", type=int, help="1-365 days")
    block.add_argument("--json", action="store_true", help="print JSON")

    blocklist = sub.add_parser("blocklist", help="download the blocklist")
    blocklist.add_argument("--format", choices=BLOCKLIST_FORMATS, default="txt")
    blocklist.add_argument("--confidence-minimum", type=int, help="1-100, default 75")
    blocklist.add_argument("--limit", type=int, help="up to 500000, default 10000")
    blocklist.add_argument("--days", type=int, help="reported in the last N days (1-90), default 30")
    blocklist.add_argument("--ip-version", type=int, choices=(4, 6))
    blocklist.add_argument("--only-countries", help="ISO codes, e.g. CN,RU")
    blocklist.add_argument("--except-countries", help="ISO codes, e.g. GB,IE")
    blocklist.add_argument("-o", "--output", help="write to a file instead of stdout")

    clear = sub.add_parser("clear", help="delete your own reports for an address")
    clear.add_argument("ip")

    categories = sub.add_parser("categories", help="list report categories")
    categories.add_argument("--json", action="store_true", help="print JSON")
    return parser


def run(args: argparse.Namespace, client: Client) -> int:
    if args.command == "check":
        result = client.check(args.ip, max_age_in_days=args.max_age, verbose=args.verbose)
        if args.json:
            _print_json(result)
        else:
            print(_describe_check(result, args.threshold))
            for r in result.reports:
                print(f"  - {r.reported_at}  {', '.join(r.categories)}  {r.comment or ''}".rstrip())
        if args.fail_if_malicious and result.is_malicious(args.threshold):
            return EXIT_MALICIOUS
        return EXIT_OK

    if args.command == "report":
        rep = client.report(args.ip, args.categories, comment=args.comment, timestamp=args.timestamp)
        if args.json:
            _print_json(rep)
        elif rep.duplicate:
            print(f"{rep.ip_address} was already reported by this account in the last 15 minutes")
        else:
            print(f"reported {rep.ip_address}, new score {rep.abuse_confidence_score}/100  {rep.link or ''}".rstrip())
        return EXIT_OK

    if args.command == "bulk-report":
        if args.file == "-":
            text = sys.stdin.read()
        else:
            with open(args.file, encoding="utf-8") as handle:
                text = handle.read()
        bulk = client.bulk_report_csv(text)
        if args.json:
            _print_json(bulk)
        else:
            print(f"saved {bulk.saved_reports} reports, {len(bulk.invalid_reports)} rejected")
            for bad in bulk.invalid_reports:
                print(f"  row {bad.row_number}: {bad.input}: {bad.error}", file=sys.stderr)
        return EXIT_OK

    if args.command == "reports":
        page = client.reports(args.ip, max_age_in_days=args.max_age, page=args.page, per_page=args.per_page)
        if args.json:
            _print_json(page)
        else:
            print(f"{page.ip_address}: {page.total} reports (page {page.page} of {page.last_page})")
            for r in page.results:
                print(f"  {r.reported_at}  {', '.join(r.categories)}  {r.comment or ''}".rstrip())
        return EXIT_OK

    if args.command == "check-block":
        net = client.check_block(args.network, max_age_in_days=args.max_age)
        if args.json:
            _print_json(net)
        else:
            print(f"{net.network_address}/{net.netmask}: {len(net.reported_addresses)} reported addresses")
            for a in net.reported_addresses:
                print(f"  {a.ip_address:<39} score {a.abuse_confidence_score:>3}  {a.num_reports} reports")
        return EXIT_OK

    if args.command == "blocklist":
        text = client.blocklist_raw(
            format=args.format,
            confidence_minimum=args.confidence_minimum,
            limit=args.limit,
            days=args.days,
            ip_version=args.ip_version,
            only_countries=_countries(args.only_countries),
            except_countries=_countries(args.except_countries),
        )
        if args.output:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(text)
        else:
            sys.stdout.write(text)
        return EXIT_OK

    if args.command == "clear":
        cleared = client.clear_address(args.ip)
        print(json.dumps(cleared))
        return EXIT_OK

    if args.command == "categories":
        cats = client.categories()
        if args.json:
            _print_json(cats)
        else:
            for c in cats:
                print(f"{c.slug:<22} {c.name}")
        return EXIT_OK

    return EXIT_ERROR


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    client = Client(api_key=args.api_key, base_url=args.base_url, timeout=args.timeout)
    try:
        return run(args, client)
    except (IsIPsafeError, ValueError, OSError) as exc:
        print(f"isipsafe: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        return 130
