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

**Sample Output:**
```
═══════════════════════════════════════
SUBDOMAIN ENUMERATION
═══════════════════════════════════════
[FOUND] mail.example.com
[FOUND] www.example.com
[FOUND] api.example.com
[FOUND] admin.example.com
[FOUND] dev.example.com
[FOUND] blog.example.com
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

**Sample Output:**
```
═══════════════════════════════════════
PORT SCANNING
═══════════════════════════════════════
[OPEN] 22/tcp    SSH          OpenSSH 9.6
[OPEN] 80/tcp    HTTP         nginx 1.26.0
[OPEN] 443/tcp   HTTPS        nginx 1.26.0
[OPEN] 8080/tcp  HTTP-alt     Apache 2.4.58
[OPEN] 8443/tcp  HTTPS-alt    nginx 1.26.0
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

**Sample Output:**
```
═══════════════════════════════════════
DIRECTORY FUZZING
═══════════════════════════════════════
[FOUND] 200 /api
[FOUND] 200 /admin
[FOUND] 301 /backup
[FOUND] 200 /login
[FOUND] 403 /.git
[FOUND] 200 /dashboard
```

### waf — WAF Detection

Identifies Web Application Firewall providers by analyzing response headers, cookies, and server signatures. Supports detection of multi-layered WAF setups through correlation with technology fingerprinting and HTTP probe results.

**Supported WAFs:**
- Cloudflare
- Akamai
- Imperva / Incapsula
- AWS WAF
- Fastly
- Sucuri

**Usage:**
```bash
gospyder waf <domain> [options]
```

**Examples:**
```bash
gospyder waf example.com
```

**Sample Output:**
```
═══════════════════════════════════════
WAF DETECTION
═══════════════════════════════════════
[WAF] Cloudflare
Confidence: High
  Evidence: CF-RAY header present
  Evidence: Server: cloudflare
```

### http — HTTP Probing

Probes targets for HTTP/HTTPS availability and extracts response metadata including status codes, page titles, server headers, content length, and response times.

**Usage:**
```bash
gospyder http <domain-or-url> [options]
```

**Examples:**
```bash
gospyder http example.com
```

**Sample Output:**
```
═══════════════════════════════════════
HTTP PROBE
═══════════════════════════════════════
[LIVE] https://example.com 200 "Example Domain"
[LIVE] https://api.example.com 200 "API Documentation"
[LIVE] https://mail.example.com 302 "Redirect"
```

### live — Live Host Detection

Filters HTTP probe results to identify actively serving hosts. Automatically runs HTTP probing if no prior results are available.

**Usage:**
```bash
gospyder live <domain-or-url> [options]
```

**Examples:**
```bash
gospyder live example.com
```

**Sample Output:**
```
═══════════════════════════════════════
LIVE HOSTS
═══════════════════════════════════════
[LIVE] example.com
[LIVE] api.example.com
[LIVE] www.example.com
```

### tech — Technology Detection

Detects web technologies, frameworks, and servers using response headers, HTML content, and JavaScript patterns. Supports detection of:

- React, Angular, Vue.js
- WordPress, Django, Flask, FastAPI
- Nginx, Apache
- Cloudflare

**Usage:**
```bash
gospyder tech <domain-or-url> [options]
```

**Examples:**
```bash
gospyder tech example.com
```

**Sample Output:**
```
═══════════════════════════════════════
TECHNOLOGY DETECTION
═══════════════════════════════════════
[TECH] React (3 hosts)
[TECH] Nginx (2 hosts)
[TECH] Cloudflare (2 hosts)
[TECH] WordPress
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

**Sample Output:**
```
═══════════════════════════════════════
CRAWL RESULTS
═══════════════════════════════════════
URLs:
  https://example.com/
  https://example.com/about
  https://example.com/products
  https://example.com/contact

Parameters:
  /search?q
  /products?id
  /page?ref

APIs:
  /api/v1/users
  /api/v1/products
  /graphql

JS Files:
  https://example.com/js/app.js
  https://example.com/js/vendor.js

Statistics:
  URLs:       42
  Parameters: 12
  APIs:       5
  JS Files:   8
  Pages:      15
  Errors:     0
```

### js — JavaScript Intelligence

Discovers JavaScript files from the target page, downloads them, and performs deep analysis including endpoint extraction, API discovery, domain enumeration, and secret detection.

**Usage:**
```bash
gospyder js <url> [options]
```

**Examples:**
```bash
gospyder js https://example.com
```

**Sample Output:**
```
═══════════════════════════════════════
JAVASCRIPT ANALYSIS
═══════════════════════════════════════

JS Files:
[JS] https://example.com/js/app.js (245760 bytes)
[JS] https://example.com/js/chunk-vendors.js (1048576 bytes)
[JS] https://example.com/js/main.js (32768 bytes)

Endpoints:

  Authentication:
    - /api/auth/login
    - /api/auth/logout
    - /api/auth/register [POST]

  API:
    - /api/v1/users
    - /api/v1/products
    - /api/v1/orders

  GraphQL:
    - /graphql [POST]
    - /graphql/batch

  Admin:
    - /admin/dashboard
    - /admin/users

Domains:
[DOMAIN] api.example.com
[DOMAIN] cdn.cloudflare.com
[DOMAIN] ws.example.com [WS]

Potential Secrets:
[CRITICAL] AWS Access Key (HIGH) AKIA...ABCDEF12
[WARNING]  JWT Secret/Token (MEDIUM) eyJ...token
[WARNING]  Google API Key (MEDIUM) AIza...key

═══════════════════════════════════════
JAVASCRIPT STATISTICS
═══════════════════════════════════════
  JS Files:   3
  Endpoints:  15
  Domains:    5
  Secrets:    2
```

### recon — Full Reconnaissance

Executes the complete reconnaissance pipeline across all modules in sequence:

1. **enum** — Subdomain enumeration
2. **ports** — Port scanning with banner grabbing
3. **fuzz** — Directory fuzzing
4. **waf** — WAF detection
5. **http** — HTTP probing
6. **live** — Live host detection
7. **tech** — Technology fingerprinting
8. **js** — JavaScript analysis

Results from earlier modules (subdomains, HTTP probe data) are automatically fed into dependent modules for deeper analysis.

**Usage:**
```bash
gospyder recon <domain> [options]
```

**Options:**
| Flag | Description | Default |
|------|-------------|---------|
| `-w` | Subdomain wordlist | wordlists/subdomains.txt |
| `-fuzz-wordlist` | Path wordlist | wordlists/paths.txt |
| `-ports-list` | Ports to scan | Config defaults |

**Examples:**
```bash
gospyder recon example.com
gospyder recon -t 200 -ports-list 80,443,8080 example.com
```

**Sample Output:**
```
═══════════════════════════════════════
SUBDOMAIN ENUMERATION
═══════════════════════════════════════
[FOUND] mail.example.com
[FOUND] www.example.com
[FOUND] api.example.com
...

═══════════════════════════════════════
PORT SCANNING
═══════════════════════════════════════
[OPEN] 22/tcp    SSH       OpenSSH 9.6
[OPEN] 80/tcp    HTTP      nginx 1.26.0
[OPEN] 443/tcp   HTTPS     nginx 1.26.0
...

═══════════════════════════════════════
TECHNOLOGY DETECTION
═══════════════════════════════════════
[TECH] React (2 hosts)
[TECH] Nginx (2 hosts)

═══════════════════════════════════════
LIVE HOSTS
═══════════════════════════════════════
[LIVE] example.com
[LIVE] www.example.com
[LIVE] api.example.com

╔════════════════════════════════════╗
║          RECON SUMMARY             ║
╠════════════════════════════════════╣
║ Subdomains    │ 12                ║
║ Live Hosts    │ 3                 ║
║ Open Ports    │ 5                 ║
║ Paths         │ 23                ║
║ Technologies  │ 4                 ║
║ WAF           │ Cloudflare        ║
╚════════════════════════════════════╝

Results saved to:
reports/example.com/
```

### list — List Modules

Displays all registered modules with their descriptions.

```bash
gospyder list
```

**Sample Output:**
```
Available Modules:
==================
  crawl
    Web crawling for URL discovery, parameter extraction, API detection, and JS file collection
  enum
    Subdomain enumeration via active DNS brute-force and passive Certificate Transparency
  fuzz
    HTTP directory and path fuzzing with wildcard detection and response fingerprinting
  http
    HTTP probing with status, title, headers, length, and response time
  js
    JavaScript file discovery, endpoint extraction, domain enumeration, and secret detection
  live
    Live host detection from HTTP probe results
  ports
    TCP port scanning with banner grabbing and service/version detection
  tech
    Technology fingerprinting for common web frameworks and servers
  waf
    WAF provider fingerprinting and detection
```

### help — Show Help

Displays global usage or module-specific help.

```bash
gospyder help
gospyder help enum
```

## Architecture

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
├── crawl/
│   ├── crawler.go               # Concurrent web crawling engine
│   └── module.go                # Crawl module adapter
├── enum/
│   ├── engine.go                # DNS enumeration engine
│   ├── module.go                # Enum module adapter
│   ├── brute.go                 # Active brute-force logic
│   └── recursive.go             # Recursive enumeration
├── js/
│   ├── analyzer.go              # JS discovery, endpoint extraction, domain/secret detection
│   └── module.go                # JS analysis module adapter
├── models/
│   └── domain.go                # Shared domain models
├── resolver/
│   └── pool.go                  # DNS resolver pool
├── scanner/
│   ├── module.go                # Port scan, fuzz, WAF module adapters
│   ├── http_probe.go            # HTTP probing, live host, tech fingerprinting modules
│   ├── portscan.go              # TCP port scanner with banner grabbing
│   ├── fuzzer.go                # Directory fuzzer with wildcard detection
│   ├── waf.go                   # WAF detection engine
│   ├── banner.go                # Banner grabbing utilities
│   ├── fingerprint.go           # Tech detection patterns
│   ├── subdomain.go             # Subdomain discovery helpers
│   ├── interface.go             # Scanner interfaces
│   └── module_test.go           # Scanner tests
└── sources/
    └── certstream.go            # Certificate Transparency log source
```

### Module System & Registry

All reconnaissance capabilities are implemented as **modules** that satisfy the `registry.Module` interface:

```go
type Module interface {
    Name() string
    Description() string
    Run(ctx context.Context, opts Options) (*Result, error)
}
```

Modules are registered in `cmd/gospyder/main.go` via `registerModules()`:

```go
modules := []struct {
    name   string
    module interface{ Name() string }
}{
    {"enum", enumModule.NewModule()},
    {"ports", scannerModule.NewPortScanModule()},
    {"fuzz", scannerModule.NewFuzzerModule()},
    {"waf", scannerModule.NewWAFModule()},
    {"http", scannerModule.NewHTTPProbeModule()},
    {"live", scannerModule.NewLiveHostModule()},
    {"tech", scannerModule.NewTechModule()},
    {"crawl", crawlModule.NewCrawlModule()},
    {"js", jsModule.NewJSModule()},
}
```

Each module receives a shared `Options` struct providing access to configuration, logging, HTTP client, formatter, workspace, and module-specific flags. The `recon` command chains multiple modules together, passing results between them for context-aware analysis.

## JavaScript Analysis

The JavaScript Intelligence module (`gospyder js`) performs a multi-phase analysis pipeline:

### Phase 1: JS File Discovery
- Parses HTML `<script>` tags, module scripts (`type="module"`)
- Detects dynamic imports (`import()`)
- Finds ES module imports (`import ... from`)
- Discovers Web Workers (`new Worker()`, `SharedWorker`, `ServiceWorker`)
- Resolves relative URLs against the base page URL

### Phase 2: Endpoint Extraction
Scans JS content for API endpoint patterns:
- `fetch("/api/...")` calls
- `axios.get/post/put/delete(...)` calls
- `XMLHttpRequest.open()` patterns
- jQuery `$.ajax`, `$.get`, `$.post` calls
- WebSocket constructions (`new WebSocket(...)`)
- GraphQL endpoint references
- Common route patterns (`/auth`, `/admin`, `/api`, `/v1/`, etc.)

### Phase 3: API Discovery
- Groups endpoints into categories: Authentication, API, GraphQL, Uploads, Admin, User
- Infers HTTP methods from endpoint context (POST for login/register, DELETE for remove/destroy, etc.)
- Extracts surrounding code context for each endpoint

### Phase 4: Domain Extraction
- Extracts absolute URLs and WebSocket URLs from JS content
- Validates domain structures with FQDN rules
- Categorizes domains by type (HTTP URL, WebSocket)

### Phase 5: Secret Detection
Pattern-matches against known credential formats:
- **HIGH confidence**: AWS Access Keys, AWS Secret Keys, Stripe Live Keys, GitHub Tokens
- **MEDIUM confidence**: Google API Keys, Stripe Test Keys, JWT Tokens, Firebase URLs, GitHub OAuth Tokens
- False positive filtering for common non-secret patterns

## Web Crawling Engine

The crawler (`gospyder crawl`) provides concurrent recursive crawling:

- **Same-host crawling**: Only follows links within the target domain
- **Link discovery**: Extracts `<a href>`, `<form action>`, `<iframe src>` links
- **JS collection**: Captures all `<script src>` references (cross-origin included)
- **Parameter extraction**: Detects URL query parameters
- **API identification**: Recognizes patterns like `/api/`, `/graphql`, `/v1/`, `/swagger`
- **Configurable depth**: Controls crawl recursion level
- **Retry logic**: Configurable retries for failed requests

## Workspace & Reporting

Results are automatically saved to the workspace directory for persistence and later review:

```
reports/
└── example.com/
    ├── metadata.json          # Workspace metadata and module states
    ├── subdomains.txt         # Subdomain enumeration results
    ├── ports.txt              # Port scan results with banners
    ├── fuzz.txt               # Directory fuzzing results
    ├── waf.txt                # WAF detection results
    ├── http-probe.txt         # HTTP probe results
    ├── live-hosts.txt         # Live host detection results
    ├── technologies.txt       # Technology fingerprinting results
    ├── crawl.txt              # Crawl results
    ├── js-analysis.txt        # JavaScript analysis results
    └── recon-summary.txt      # Full reconnaissance summary
```

Each report includes:
- Module name, target, timestamp, and duration
- Number of findings with full details
- Metadata about the scan configuration

Use `-workspace=false` to disable workspace saving for a single run.

## Development Roadmap

### ✅ Implemented
- [x] **Subdomain Enumeration** — Active DNS brute-force + passive Certificate Transparency
- [x] **Port Scanning** — TCP connect scanning with banner grabbing and service detection
- [x] **Directory Fuzzing** — HTTP path discovery with wildcard detection
- [x] **WAF Detection** — Cloudflare, Akamai, Imperva, AWS WAF, Fastly, Sucuri
- [x] **HTTP Probing** — Status, title, server headers, content length, response times
- [x] **Live Host Detection** — Availability filtering from probe results
- [x] **Technology Detection** — React, Angular, Vue, WordPress, Nginx, Apache, etc.
- [x] **Web Crawling** — URL discovery, parameter extraction, API detection, JS collection
- [x] **JavaScript Intelligence** — Endpoint extraction, API discovery, domain/secret detection

### 🚧 Planned
- [ ] **TLS Analysis** — Certificate inspection, cipher suite enumeration, protocol support
- [ ] **DNS Intelligence** — Zone transfers, DNS record enumeration (MX, TXT, CNAME, NS)
- [ ] **Fingerprinting** — Advanced OS and service fingerprinting
- [ ] **Screenshot Capture** — Visual reconnaissance of web applications
- [ ] **ASN Intelligence** — Autonomous System enumeration and IP range discovery
- [ ] **Cloud Enumeration** — S3 buckets, Azure storage, GCP bucket discovery

## Development

```bash
# Run tests
go test ./...

# Build the CLI
go build -o gospyder ./cmd/gospyder

# Run with verbose output
./gospyder -v recon example.com
```

### Adding a New Module

1. Create a new package under `pkg/` or implement in `pkg/scanner/`
2. Implement the `registry.Module` interface:

```go
type ModuleAdapter struct{}

func (m *ModuleAdapter) Name() string {
    return "example"
}

func (m *ModuleAdapter) Description() string {
    return "Example reconnaissance module"
}

func (m *ModuleAdapter) Run(ctx context.Context, opts registry.Options) (*registry.Result, error) {
    target, ok := opts.Flags["target"].(string)
    if !ok {
        return nil, fmt.Errorf("target flag required")
    }

    opts.Logger.Info("Running example module for %s", target)

    return &registry.Result{
        Module:    m.Name(),
        Timestamp: time.Now(),
        Status:    "success",
        Target:    target,
        Findings:  []registry.Finding{},
        Metadata:  map[string]interface{}{},
    }, nil
}
```

3. Register it in `cmd/gospyder/main.go` inside `registerModules()`
4. Add a command handler in `cmd/gospyder/handlers/commands.go`
5. Add the case in `main()` switch statement

### Contribution Guidelines

- Fork the repository and create a feature branch
- Maintain backward compatibility with the module interface
- Add tests for new functionality
- Update the workspace file-naming in `handler.go` for new result types
- Submit a pull request with a clear description of changes

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.