<p align="center">
  <img src="https://img.shields.io/badge/version-3.0-blueviolet?style=for-the-badge" alt="Version 3.0">
  <img src="https://img.shields.io/badge/Go-1.25+-00ADD8?style=for-the-badge&logo=go" alt="Go 1.25+">
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" alt="MIT License">
  <img src="https://img.shields.io/badge/status-active-success?style=for-the-badge" alt="Active">
</p>

<p align="center">
  <pre>
   ██████╗  ██████╗ ███████╗██████╗ ██╗   ██╗██████╗ ███████╗██████╗
  ██╔════╝ ██╔═══██╗██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗
  ██║  ███╗██║   ██║███████╗██████╔╝ ╚████╔╝ ██║  ██║█████╗  ██████╔╝
  ██║   ██║██║   ██║╚════██║██╔═══╝   ╚██╔╝  ██║  ██║██╔══╝  ██╔══██╗
  ╚██████╔╝╚██████╔╝███████║██║        ██║   ██████╔╝███████╗██║  ██║
   ╚═════╝  ╚═════╝ ╚══════╝╚═╝        ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝
  </pre>
  <em>by nashedi_x_coder</em>
</p>

<p align="center">
  <strong>Modular Reconnaissance Framework written in Go</strong><br>
  Subdomain Enumeration · Port Scanning · WAF Detection · HTTP Probing ·<br>
  Technology Fingerprinting · Web Crawling · JavaScript Intelligence
</p>

---

## Table of Contents

- [Features](#features)
- [Engineering Audit](#engineering-audit)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Commands](#commands)
  - [Global Flags](#global-flags)
  - [enum — Subdomain Enumeration](#enum--subdomain-enumeration)
  - [ports — Port Scanning](#ports--port-scanning)
  - [fuzz — Directory Fuzzing](#fuzz--directory-fuzzing)
  - [waf — WAF Detection](#waf--waf-detection)
  - [http — HTTP Probing](#http--http-probing)
  - [live — Live Host Detection](#live--live-host-detection)
  - [tech — Technology Detection](#tech--technology-detection)
  - [crawl — Web Crawling](#crawl--web-crawling)
  - [js — JavaScript Intelligence](#js--javascript-intelligence)
  - [recon — Full Reconnaissance](#recon--full-reconnaissance)
  - [list — List Modules](#list--list-modules)
  - [help — Show Help](#help--show-help)
- [Architecture](#architecture)
- [JavaScript Analysis](#javascript-analysis)
- [Web Crawling Engine](#web-crawling-engine)
- [Workspace & Reporting](#workspace--reporting)
- [Development Roadmap](#development-roadmap)
- [Development](#development)
  - [Adding a New Module](#adding-a-new-module)
- [License](#license)

---

## Features

| Module | Description | Status |
|--------|-------------|--------|
| **enum** | Subdomain enumeration via active DNS brute-force and passive Certificate Transparency | ✅ |
| **ports** | TCP port scanning with banner grabbing and service/version detection | ✅ |
| **fuzz** | HTTP directory and path fuzzing with wildcard detection and response fingerprinting | ✅ |
| **waf** | WAF provider fingerprinting (Cloudflare, Akamai, Imperva, AWS WAF, Fastly, Sucuri) | ✅ |
| **http** | HTTP probing with status, title, headers, content length, and response time | ✅ |
| **live** | Live host detection from HTTP probe results | ✅ |
| **tech** | Technology fingerprinting for common web frameworks and servers (React, Angular, Vue, Nginx, Apache, etc.) | ✅ |
| **crawl** | Web crawling for URL discovery, parameter extraction, API detection, and JS file collection | ✅ |
| **js** | JavaScript file discovery, endpoint extraction, domain enumeration, and secret detection | ✅ |
| **recon** | Full reconnaissance pipeline running all modules in sequence | ✅ |

---

## Engineering Audit

This repository has undergone a comprehensive engineering audit. The following documents provide a detailed analysis of the project's architecture, features, and testing maturity:

- **[ARCHITECTURE.md](ARCHITECTURE.md)**: A detailed review of the project's architecture, code quality, and design patterns.
- **[FEATURE_MATRIX.md](FEATURE_MATRIX.md)**: A capability matrix evaluating each module's status and completion.
- **[FEATURE_COVERAGE.md](FEATURE_COVERAGE.md)**: A comparison of GoSpyder's features against other popular open-source reconnaissance tools.
- **[TESTS.md](TESTS.md)**: An audit of the existing tests and a roadmap for improving test coverage.
- **[ROADMAP.md](ROADMAP.md)**: A prioritized list of missing high-value features and a roadmap for future development.

---

## Installation

```bash
# Clone the repository
git clone https://github.com/NASHEDIxCODER/gospyder.git
cd gospyder

# Build from source
go build -o gospyder ./cmd/gospyder

# Or install with Go
go install github.com/NASHEDIxCODER/gospyder/cmd/gospyder@latest
```

**Requirements:**
- Go 1.25.4 or newer
- Network access for scan targets and DNS resolution

## Quick Start

```bash
# List available modules
./gospyder list

# Run a single module
./gospyder enum example.com
./gospyder ports example.com
./gospyder fuzz https://example.com

# Run full reconnaissance
./gospyder recon example.com

# Show help
./gospyder help
./gospyder help enum
```

## Commands

### Global Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-t` | Number of concurrent threads | 100 |
| `-timeout` | Timeout in seconds | 10 |
| `-v` | Enable verbose output | false |
| `-o` | Save report to file | (empty) |
| `-workspace` | Save results to workspace directory | true |

### enum — Subdomain Enumeration

Performs subdomain discovery using DNS brute-force and Certificate Transparency log sources.

**Usage:**
```bash
gospyder enum <domain> [options]
```

**Options:**
| Flag | Description | Default |
|------|-------------|---------|
| `-w` | Subdomain wordlist path | wordlists/subdomains.txt |
| `-mode` | Enumeration mode: `active`, `passive`, `both` | active |

**Examples:**
```bash
gospyder enum example.com
gospyder enum -w custom-wordlist.txt -mode both example.com
gospyder enum -t 200 -v example.com
```

### ports — Port Scanning

Performs TCP port scanning with concurrent connections, banner grabbing, and service/version detection. Automatically probes HTTP ports for web server fingerprinting.

**Usage:**
```bash
gospyder ports <domain> [options]
```

**Options:**
| Flag | Description | Default |
|------|-------------|---------|
| `--ports-list` | Comma-separated ports or ranges (e.g., `80,443,8000-8010`) | 22,80,443,8080,8443,3000,5000,9000 |
| `-retry` | Retry attempts per port | 2 |

**Examples:**
```bash
gospyder ports example.com
gospyder ports --ports-list=80,443,8080-8090 example.com
gospyder ports --ports-list=1-1000 -t 500 example.com
```

### fuzz — Directory Fuzzing

Performs HTTP path discovery with wildcard detection and response size fingerprinting to filter false positives.

**Usage:**
```bash
gospyder fuzz <url> [options]
```

**Options:**
| Flag | Description | Default |
|------|-------------|---------|
| `-fuzz-wordlist` | Path wordlist | wordlists/paths.txt |

**Examples:**
```bash
gospyder fuzz https://example.com
gospyder fuzz -fuzz-wordlist custom-paths.txt https://example.com
```

### waf — WAF Detection

Identifies Web Application Firewall providers by analyzing response headers, cookies, and server signatures.

**Usage:**
```bash
gospyder waf <domain> [options]
```

### http — HTTP Probing

Probes targets for HTTP/HTTPS availability and extracts response metadata including status codes, page titles, server headers, content length, and response times.

**Usage:**
```bash
gospyder http <domain-or-url> [options]
```

### live — Live Host Detection

Filters HTTP probe results to identify actively serving hosts. Automatically runs HTTP probing if no prior results are available.

**Usage:**
```bash
gospyder live <domain-or-url> [options]
```

### tech — Technology Detection

Detects web technologies, frameworks, and servers using response headers, HTML content, and JavaScript patterns.

**Usage:**
```bash
gospyder tech <domain-or-url> [options]
```

### crawl — Web Crawling

Recursively crawls a web application to discover URLs, extract query parameters, identify API endpoints, and collect JavaScript file references.

**Usage:**
```bash
gospyder crawl <url> [options]
```

**Options:**
| Flag | Description | Default |
|------|-------------|---------|
| `-depth` | Maximum crawl depth | 3 (from config) |

**Examples:**
```bash
gospyder crawl https://example.com
gospyder crawl -depth 5 https://example.com
```

### js — JavaScript Intelligence

Discovers JavaScript files from the target page, downloads them, and performs deep analysis including endpoint extraction, API discovery, domain enumeration, and secret detection.

**Usage:**
```bash
gospyder js <url> [options]
```

### recon — Full Reconnaissance

Executes the complete reconnaissance pipeline across all modules in sequence.

**Usage:**
```bash
gospyder recon <domain> [options]
```

---
## Architecture

A high-level overview of the architecture is available in [ARCHITECTURE.md](ARCHITECTURE.md).

```
cmd/
└── gospyder/
    ├── main.go                  # CLI entry point, banner, module registration
    └── handlers/
        ├── commands.go          # CLI flag parsing per command
        └── handler.go            # Module execution, result saving, workspace management

internal/
├── app/
│   └── context.go               # Application context / dependency injection container
├── config/
│   └── config.go                # Runtime configuration with sensible defaults
├── errors/
│   └── errors.go                # Error collection utilities
├── logger/
│   └── logger.go                # Structured logging
├── output/
│   └── formatter.go             # Output formatting (txt, json, csv) with color support
├── registry/
│   ├── module.go                # Module interface, Options, Result, Finding types
│   └── registry.go              # Module registration and lookup
├── target/
│   └── parser.go                # Target URL/host normalization
└── workspace/
    └── workspace.go             # Report storage and metadata tracking

pkg/
└── ... (modules)
```

## JavaScript Analysis

The JavaScript Intelligence module (`gospyder js`) performs a multi-phase analysis pipeline to discover endpoints, secrets, and other valuable information from JavaScript files.

## Web Crawling Engine

The crawler (`gospyder crawl`) provides concurrent recursive crawling to discover URLs, parameters, and other resources.

## Workspace & Reporting

Results are automatically saved to the workspace directory for persistence and later review.

## Development Roadmap

The development roadmap is maintained in [ROADMAP.md](ROADMAP.md). It contains a prioritized list of features for future development.

## Development

```bash
# Run tests
go test ./...

# Build the CLI
go build -o gospyder ./cmd/gospyder
```

### Adding a New Module

1. Create a new package under `pkg/`.
2. Implement the `registry.Module` interface.
3. Register the module in `cmd/gospyder/main.go`.
4. Add a command handler in `cmd/gospyder/handlers/commands.go`.
5. Add the command to the `main()` switch statement.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
