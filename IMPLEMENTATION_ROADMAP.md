# Implementation Roadmap

This roadmap is a retroactive snapshot of completed work plus plausible next steps.

## Phase 0 - Foundation (completed)
- [x] Project scaffold, module setup, and baseline CLI.
- [x] Metadata embedding and version output path.

## Phase 1 - DNS Collection Core (completed)
- [x] DNS client abstraction and resolver configuration.
- [x] Record collection for A, SOA, NS, MX, TXT, DMARC, CAA.
- [x] Host/IP expansion for NS and MX entries.

## Phase 2 - Reporting Model and Rendering (completed)
- [x] Central report model in `internal/model`.
- [x] Human-readable output sections for summary and full views.
- [x] Optional color output with theme variants.

## Phase 3 - Reliability and Operator Controls (completed)
- [x] Retry/backoff behavior for transient DNS issues.
- [x] Timeout controls (`--timeout`, `--dns-timeout`, `--rdap-timeout`).
- [x] Optional TCP preference for DNS transport.

## Phase 4 - RDAP and Derived Signals (completed)
- [x] RDAP integration for domain metadata.
- [x] Expiration and near-expiration warning flags.
- [x] Graceful behavior when RDAP is unavailable.

## Phase 5 - Automation and Comparison (completed)
- [x] JSON output mode.
- [x] Resolver comparison mode for core-record cross-checking.
- [x] Deterministic sorting and deduplication for stable outputs.

## Phase 6 - Next Improvements (planned)
- [ ] Expand output contract examples for each mode (default/full/json/compare).
- [ ] Add structured error codes for automation-friendly failure handling.
- [ ] Add optional query tracing or debug mode (timings, retries, transport path).
- [ ] Evaluate broader domain parsing rules for multi-part public suffixes.
