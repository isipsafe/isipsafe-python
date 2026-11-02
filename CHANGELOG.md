# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-02

### Added

- `Client` with `check`, `is_malicious`, `report`, `bulk_report`, `bulk_report_csv`, `reports`, `check_block`, `blocklist`, `blocklist_raw`, `clear_address` and `categories`.
- `isipsafe` command-line tool.
- Typed results and exceptions, retries with backoff for lookups, API key sent as a Bearer header.
