# diggo Charter

## Mission
Provide fast, practical DNS and RDAP inspection in a single command with output that is easy to read in terminals and easy to copy into operational workflows.

## Product Shape
- Single executable CLI tool focused on domain inspection.
- Combines DNS records, optional RDAP metadata, and derived health signals.
- Supports human-readable terminal output and JSON output for automation.

## Core Principles
- Prefer operational clarity over protocol trivia.
- Keep output stable and deterministic where possible (sorting and dedupe).
- Separate data acquisition from rendering so output formats can evolve safely.
- Keep network behavior explicit via resolver and timeout flags.

## Current Scope (v2.x)
- DNS queries across the standard record set defined in [OUTPUT_CONTRACT.md](OUTPUT_CONTRACT.md).
- Optional RDAP domain metadata lookup with expiration warnings.
- Subdomain detection and subdomain A/AAAA reporting.
- Core summary mode, full mode, and JSON output mode.
- Resolver comparison mode for side-by-side core DNS checks.

## Non-Goals (for now)
- Full authoritative DNS tracing.
- Zone transfer tooling.
- Continuous monitoring/daemon behavior.
- Historical storage and trend analytics.

## Platform and Tooling
- Language: Go.
- DNS library: miekg/dns.
- Primary environments: Windows and Linux; cross-platform behavior where dependencies support it.

## Evolution Policy
Output changes should preserve semantic meaning and stable section intent. New sections or fields should be additive when practical and reflected in `OUTPUT_CONTRACT.md`.
