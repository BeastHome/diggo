# Changelog

## Unreleased

- Added explicit DMARC lookup via TXT query to _dmarc.<domain>.
- Added Core Records block to prioritize copy-friendly operational fields.
- Added theme and color mode controls for terminal readability.
- Added resolver and timeout flags for DNS query control.
- Added separate --dns-timeout and --rdap-timeout flags with --timeout as fallback.
- Added DNS retry/backoff handling for transient transport errors, SERVFAIL, and REFUSED responses.
- Added JSON output mode and compare-resolver mode.
- Added deterministic sorting and record deduplication for stable output.
