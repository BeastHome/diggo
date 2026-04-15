# diggo

## Overview
`diggo` is a dig-like DNS inspection tool written in Go. It queries DNS records (A, MX, TXT, NS, CNAME, SOA, and more), fetches RDAP domain metadata, performs subdomain detection, and surfaces expiration warnings — all in a single command. Designed for quick, copy-friendly output on Windows hosting environments.

## Status
- Lifecycle: stable
- Primary language: Go
- Platforms: Windows / Linux / cross-platform

## Usage

```
diggo [options] domain
```

**Examples:**

```
diggo example.com
diggo example.com --no-rdap
diggo mail.example.com
diggo example.com --core
diggo example.com --full --color always
diggo example.com --json
diggo example.com --compare-resolver 8.8.8.8:53
```

**Options:**

| Flag | Default | Description |
|---|---|---|
| `--no-rdap` | false | Skip RDAP metadata lookup |
| `--core` | false | Show core records summary only |
| `--full` | false | Show full output including core records |
| `--json` | false | Emit JSON report output |
| `--color` | auto | Color mode: `auto`, `always`, or `never` |
| `--theme` | default | Output theme: `default`, `high-contrast`, or `minimal` |
| `--resolver` | 1.1.1.1:53 | DNS resolver to use (host:port) |
| `--compare-resolver` | — | Secondary resolver for core-record comparison |
| `--timeout` | 8s | Fallback timeout for DNS and RDAP |
| `--dns-timeout` | — | DNS-specific timeout (e.g. `4s`, `1200ms`) |
| `--rdap-timeout` | — | RDAP-specific timeout (e.g. `8s`, `2500ms`) |
| `--version` | — | Show version and exit |

## Build

```
go build -o diggo.exe .
```

## Notes
- Pre-commit hook is wired via `.githooks/pre-commit` (`core.hookspath=.githooks`). Run `git config core.hookspath .githooks` on fresh clones if not already set.
- Version metadata is embedded from `metadata.json` at build time.