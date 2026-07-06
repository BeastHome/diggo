# Changelog

## Unreleased

- Distinguished unavailable RDAP (HTTP 404 — TLD has no RDAP service or domain is unregistered) from transient RDAP failures in output and JSON (RDAPUnavailable flag).
- Fixed base-domain detection to use the Public Suffix List so multi-label TLDs (e.g. example.com.tr, example.co.uk) are treated as registrable domains rather than subdomains.

## 2.0.0 - 2026-04-12

- Added explicit DMARC lookup via TXT query to _dmarc.<domain>.
- Added Core Records block to prioritize copy-friendly operational fields.
- Added theme and color mode controls for terminal readability.
- Added resolver and timeout flags for DNS query control.
- Added separate --dns-timeout and --rdap-timeout flags with --timeout as fallback.
- Added DNS retry/backoff handling for transient transport errors, SERVFAIL, and REFUSED responses.
- Added JSON output mode and compare-resolver mode.
- Added deterministic sorting and record deduplication for stable output.
