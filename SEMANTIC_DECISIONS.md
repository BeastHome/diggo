# Semantic Decisions

This document captures behavior choices for diggo and the rationale behind them.

## SD-001: One domain input per invocation
- Status: accepted
- Decision: CLI accepts one domain argument and errors on multiples.
- Rationale: Keeps reports focused and avoids ambiguous flag/data grouping.

## SD-002: Domain argument may appear before or after flags
- Status: accepted
- Decision: Arguments are normalized so positional domain can be supplied flexibly.
- Rationale: Improves shell ergonomics without changing final parse rules.
- Note: A value-expecting flag supplied without its value (e.g. `diggo example.com --resolver`)
  lets the standard flag parser consume the domain as the flag value, surfacing as
  "no domain provided". This is treated as user error, consistent with stdlib flag behavior.

## SD-003: DNS and RDAP timeouts are independently configurable
- Status: accepted
- Decision: `--dns-timeout` and `--rdap-timeout` override shared fallback timeout.
- Rationale: DNS and RDAP failure modes differ; operators need independent control.

## SD-004: DNS query reliability favors bounded retries
- Status: accepted
- Decision: DNS client retries transient failures with capped attempts and backoff.
- Rationale: Improves practical reliability on unstable networks without unbounded wait.

## SD-005: UDP-first with TCP fallback, plus explicit TCP preference
- Status: accepted
- Decision: Normal path uses UDP with TCP fallback on truncation; `--prefer-tcp` flips transport priority.
- Rationale: Works for standard DNS paths while supporting restrictive VPN/firewall environments.

## SD-006: Subdomain handling reports both base-domain and subdomain context
- Status: accepted
- Decision: Input is split into base domain and subdomain indicator; subdomain A/AAAA is shown separately.
- Rationale: Keeps report sections understandable when querying hostnames instead of bare domains.
- Note: The base domain is resolved as the registrable domain (eTLD+1) using the
  Public Suffix List, so multi-label public suffixes such as `com.tr` and `co.uk`
  are handled correctly — `example.com.tr` is a base domain, while
  `mail.example.com.tr` is a subdomain of `example.com.tr`.

## SD-007: Record lists are normalized before rendering
- Status: accepted
- Decision: Sort and dedupe are applied to relevant record collections before output.
- Rationale: Stable, diff-friendly output and reduced noise.

## SD-008: RDAP failures are non-fatal to DNS reporting
- Status: accepted
- Decision: RDAP lookup failure sets report flags but does not stop DNS sections.
- Rationale: DNS inspection remains useful even when RDAP endpoint fails.
- Note: A 404 response (no RDAP service for the TLD, common for ccTLDs such as
  `.tr`, or an unregistered domain) is reported as "unavailable"
  (`RDAPUnavailable`) rather than a transient failure (`RDAPError`), so the
  distinction between a permanent gap and a retryable error is preserved in both
  text and JSON output.

## SD-009: Human and machine output are first-class modes
- Status: accepted
- Decision: Default and full textual renderers coexist with JSON output using the same report model.
- Rationale: Supports both terminal operators and automation tooling from one command.
