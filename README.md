# isipsafe

Official Python client and command-line tool for [isIPsafe](https://isipsafe.com), the free IP reputation and abuse reporting service.

- **Check** whether an IP address is malicious before you trust it
- **Report** attackers from your logs, one at a time or 10,000 at once
- **Download the blocklist** in a firewall-ready format (nftables, ipset, nginx, apache, MikroTik, STIX and more)

No dependencies outside the Python standard library. Python 3.9+.

```bash
pip install isipsafe
```

## Get an API key

Lookups work without a key (400 per day per address). Reporting, bulk uploads and the blocklist need a free key from [isipsafe.com/login](https://isipsafe.com/login). A key also raises the lookup limit to 10,000 per day.

```bash
export ISIPSAFE_API_KEY=sl_your_key_here
```

The client sends the key in an `Authorization` header, never in the URL, so it stays out of proxy and server logs.

## Python

```python
from isipsafe import Client

client = Client()  # reads ISIPSAFE_API_KEY, or pass Client("sl_...")

result = client.check("185.220.101.1")
print(result.abuse_confidence_score, result.total_reports, result.categories)

if result.is_malicious():  # score >= 75, has reports, not allowlisted
    block(result.ip_address)

client.report(
    "203.0.113.50",
    ["ssh", "brute-force"],
    comment="sshd: 212 failed logins in 10 minutes",
)
```

### Report many addresses at once

```python
result = client.bulk_report(
    [
        {"ip": "203.0.113.50", "categories": ["ssh", "brute-force"], "comment": "sshd"},
        {"ip": "198.51.100.4", "categories": "port-scan"},
    ]
)
print(result.saved_reports, result.invalid_reports)
```

### Blocklist

```python
ips = client.blocklist(confidence_minimum=90, except_countries=["GB"])
nft = client.blocklist_raw(format="nftables")
```

### Everything else

| Method | What it does |
| --- | --- |
| `check(ip, max_age_in_days=None, verbose=False)` | Score, report counts, location and network for one address |
| `is_malicious(ip, threshold=75)` | Shortcut that returns `True` or `False` |
| `report(ip, categories, comment=None, timestamp=None)` | Report an address or CIDR network |
| `bulk_report(rows)` / `bulk_report_csv(text)` | Up to 10,000 reports in one request |
| `reports(ip, page=1, per_page=25)` | Reports filed against an address, newest first |
| `check_block(network)` | Reported addresses inside a network (up to /16 or /48) |
| `blocklist(...)` / `blocklist_raw(format=...)` | The highest-confidence addresses |
| `clear_address(ip)` | Delete your own reports for an address |
| `categories()` | All report categories and their slugs |

### Errors

Every error inherits from `isipsafe.IsIPsafeError`.

| Exception | When |
| --- | --- |
| `AuthenticationError` | Missing or wrong API key (401) |
| `ValidationError` | Invalid input, or an allowlisted address was reported (422) |
| `RateLimitError` | Too many requests (429); see `.retry_after` |
| `APIError` | Any other error status; see `.status` |
| `NetworkError` | The API could not be reached |

Lookups are retried automatically on network errors and 5xx responses. Reporting the same address twice within 15 minutes is not an error: `report()` returns a result with `duplicate=True`.

## Command line

```console
$ isipsafe check 185.220.101.1
185.220.101.1  not flagged
  score       56/100 (Medium)
  reports     24 from 5 reporters
  categories  port-scan, hacking, vuln-scan, web-app-attack, c2
  network     DE AS60729 Stiftung Erneuerbare Freiheit
  flags       Tor exit
  details     https://isipsafe.com/ip/185.220.101.1

$ isipsafe report 203.0.113.50 -c ssh,brute-force -m "sshd: 212 failed logins"
$ isipsafe bulk-report reports.csv
$ isipsafe blocklist --format nftables --confidence-minimum 90 -o blocklist.nft
$ isipsafe check-block 185.220.101.0/24
$ isipsafe categories
```

Add `--json` to `check`, `report`, `reports`, `check-block` and `categories` for machine-readable output.

Use `--fail-if-malicious` in shell scripts. The command exits with status `1` when the address is malicious:

```bash
if ! isipsafe check "$IP" --fail-if-malicious --threshold 80 > /dev/null; then
    echo "blocking $IP"
fi
```

Exit codes: `0` success, `1` malicious (only with `--fail-if-malicious`), `2` error.

## Categories

Use the slug or the numeric ID. Common ones: `ssh`, `brute-force`, `port-scan`, `web-app-attack`, `sql-injection`, `vuln-scan`, `bad-bot`, `ddos`, `email-spam`, `phishing`. Run `isipsafe categories` for the full list, or see [isipsafe.com/categories](https://isipsafe.com/categories).

## Links

- Official Usage Page: [isipsafe.com/integrations/python](https://isipsafe.com/integrations/python)
- Website: [isipsafe.com](https://isipsafe.com)
- API reference: [isipsafe.com/api](https://isipsafe.com/api)
- Integrations: [isipsafe.com/integrations](https://isipsafe.com/integrations)

## Licence

The code in this repository is MIT licensed. Data returned by the isIPsafe API is covered by the [isIPsafe EULA](https://isipsafe.com/eula).
