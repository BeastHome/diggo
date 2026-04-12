# Output Contract

This document defines the intended human-readable output structure for diggo.

## Section Order

1. RDAP (if enabled)
2. Core Records
3. Subdomain A/AAAA (when input is a subdomain)
4. DNS for <domain>
5. A record(s)
6. SOA (if available)
7. Nameservers
8. MX
9. TXT (if present)
10. SPF (if present)
11. DMARC (if present)
12. CAA
13. Resolver Comparison (if compare-resolver is used)

## Core Records Fields

- Domain
- Nameservers
- Nameserver IPs
- A/AAAA
- MX
- TXT
- SPF status (OK or MISSING)
- DMARC status (OK or MISSING)
- CAA status (OK or MISSING)

## Behavioral Guarantees

- Multi-value fields are sorted deterministically where possible.
- Duplicate records are removed from output lists.
- DMARC records are queried from _dmarc.<domain> TXT.
- Color formatting is optional and should not change textual content semantics.
