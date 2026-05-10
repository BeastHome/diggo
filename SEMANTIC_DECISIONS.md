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

## SD-007: Record lists are normalized before rendering
- Status: accepted
- Decision: Sort and dedupe are applied to relevant record collections before output.
- Rationale: Stable, diff-friendly output and reduced noise.

## SD-008: RDAP failures are non-fatal to DNS reporting
- Status: accepted
- Decision: RDAP lookup failure sets report flags but does not stop DNS sections.
- Rationale: DNS inspection remains useful even when RDAP endpoint fails.

## SD-009: Human and machine output are first-class modes
- Status: accepted
- Decision: Default and full textual renderers coexist with JSON output using the same report model.
- Rationale: Supports both terminal operators and automation tooling from one command.
