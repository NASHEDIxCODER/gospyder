# GoSpyder Reconnaissance Framework - Analysis & Implementation Roadmap

## 📊 CURRENT STATE ANALYSIS

### Project Overview
- **Language**: Go 1.25.4
- **Status**: Production-ready scanner with 4 core modules
- **Current Capabilities**: Subdomain enumeration, Port scanning, WAF detection, Directory fuzzing
- **Code Quality**: Good foundation, modular design, but needs expansion

### Existing Architecture

```
gospyder/
├── cmd/gospyder/main.go                    # Single command entry point
├── pkg/
│   ├── enum/                               # Subdomain enumeration engine
│   │   ├── engine.go                       # Main orchestrator (Active/Passive/Both modes)
│   │   ├── active.go                       # Brute-force DNS
│   │   ├── passive.go                      # CertStream integration
│   │   └── brute.go                        # Brute-force logic
│   ├── models/
│   │   └── domain.go                       # Domain struct
│   ├── resolver/
│   │   └── pool.go                         # DNS resolver pool (multiple servers)
│   ├── scanner/
│   │   ├── interface.go                    # Module interface & Result struct
│   │   ├── portscan.go                     # TCP port scanner with retries
│   │   ├── fuzzer.go                       # Directory fuzzer (576 paths)
│   │   ├── waf.go                          # WAF detection (20+ providers)
│   │   └── subdomain.go                    # Subdomain scanner (interface impl)
│   └── sources/
│       └── certstream.go                   # CertStream WebSocket client
├── wordlists/
│   ├── subdomains.txt                      # ~50 common subdomains
│   └── paths.txt                           # 576 common paths
└── go.mod                                  # Minimal dependencies

```

### Current Features

| Module | Status | Capabilities |
|--------|--------|--------------|
| **Subdomain Enum** | ✅ Complete | Active brute-force, Passive CertStream, Hybrid mode |
| **Port Scanner** | ✅ Complete | 37 ports, retry logic, service detection, status output |
| **Directory Fuzzer** | ✅ Complete | 576 paths, status codes (200/300/401/403), protocol detection |
| **WAF Detection** | ✅ Complete | 20+ WAF providers, multi-indicator detection |
| **Export Formats** | ✅ Complete | TXT, JSON, CSV with sorting & deduplication |

### Current Strengths
1. ✅ **Clean modular architecture** - Easy to extend
2. ✅ **Good CLI structure** - Flags well-organized
3. ✅ **Comprehensive wordlists** - 576 paths is solid
4. ✅ **Production-ready** - Error handling, timeouts, retries
5. ✅ **Type safety** - Proper use of interfaces
6. ✅ **Concurrency patterns** - WaitGroups, channels, context awareness

### Current Limitations & Technical Debt

1. **Single Command Structure**
   - All features in one `main()` function
   - No subcommand architecture
   - Needs refactoring for multi-command support

2. **Missing HTTP Probe Capabilities**
   - No HTTP/HTTPS probing engine
   - No header extraction (Server, Title, Content-Type)
   - No response timing
   - No redirect tracking

3. **Limited Technology Detection**
   - No fingerprinting system
   - No framework detection (React, Angular, Django, etc.)
   - No infrastructure detection (Nginx, Apache, Cloudflare)

4. **No DNS Intelligence**
   - Only does subdomain brute-force
   - Missing A, AAAA, MX, TXT, NS records
   - No ASN intelligence

5. **Limited URL Discovery**
   - No Wayback Machine integration
   - No Common Crawl integration
   - No URL aggregation

6. **No JavaScript Analysis**
   - No JS file collection
   - No endpoint extraction from JS
   - No secret pattern detection

7. **No Screenshot Capability**
   - Can't capture visual reconnaissance
   - Missing browser automation

8. **No TLS/Certificate Analysis**
   - No certificate details extraction
   - No SAN parsing
   - No expiry checking

9. **Missing Security Features**
   - No subdomain takeover detection
   - No configuration file
   - No workspace management
   - No reporting system

10. **No Template System**
    - No vulnerability templates
    - No pattern matching

---

## 🎯 IMPLEMENTATION ROADMAP

### Phase 0: Architecture Refactoring (FOUNDATION)
**Goal**: Restructure for multi-command support

**Tasks**:
- [ ] Create subcommand architecture using `urfave/cli` or custom flag parsing
- [ ] Refactor `main.go` into command handlers
- [ ] Extract color utilities to separate package
- [ ] Create `internal/` directory for internal packages
- [ ] Set up `internal/config` for shared configuration
- [ ] Create `internal/output` for result formatting
- [ ] Create `internal/logger` for consistent logging

**Files to Create**:
```
internal/
├── config/
│   ├── config.go              # Configuration structure
│   └── defaults.go            # Default values
├── output/
│   ├── formatter.go           # Output formatting (JSON, CSV, TXT)
│   └── colors.go              # Color constants & utilities
├── logger/
│   └── logger.go              # Logging utilities
├── http/
│   └── client.go              # Shared HTTP client
├── context/
│   └── context.go             # Shared context utilities
└── errors/
    └── errors.go              # Custom error types

cmd/gospyder/
├── main.go                    # Entry point (minimal)
├── commands.go                # Command definitions
└── handlers/
    ├── enum.go                # Subdomain enumeration handler
    ├── ports.go               # Port scanning handler
    └── probe.go               # HTTP probe handler (NEW)
```

**CLI Structure After Refactoring**:
```bash
gospyder enum example.com              # Subdomain enumeration
gospyder ports example.com             # Port scanning
gospyder fuzz example.com              # Directory fuzzing
gospyder probe domains.txt             # HTTP probe (NEW)
gospyder waf example.com               # WAF detection
gospyder recon example.com             # Full reconnaissance (NEW)
```

---

### Phase 1: HTTP Probe Engine
**Goal**: Add comprehensive HTTP/HTTPS probing

**Features**:
- [ ] HTTP/HTTPS probing with status detection
- [ ] Title extraction from HTML
- [ ] Content length tracking
- [ ] Server header extraction
- [ ] Content-Type detection
- [ ] Redirect tracking
- [ ] Response timing measurement
- [ ] Batch probing from file
- [ ] Retry logic
- [ ] Concurrent workers

**Package**: `internal/probe`

**Files**:
```
internal/probe/
├── probe.go                   # Main probe engine
├── prober.go                  # Individual probe logic
└── result.go                  # Probe result structure
```

**CLI**:
```bash
gospyder probe -d example.com
gospyder probe -l domains.txt -o results.json
gospyder probe -d example.com -timeout 30 -retry 3
```

**Output**:
```
https://example.com

Status: 200
Title: Example Domain
Server: nginx
ContentType: text/html
Length: 1234
ResponseTime: 125ms
Location: 
```

---

### Phase 1.5: Live Host Detection
**Goal**: Detect live HTTP/HTTPS services

**Features**:
- [ ] HTTP probing
- [ ] HTTPS probing
- [ ] Protocol preference detection
- [ ] Concurrent workers
- [ ] Timeout controls
- [ ] Retry logic

**Package**: `internal/live`

**CLI**:
```bash
gospyder live -d example.com
gospyder live -l subdomains.txt
gospyder live -d example.com -proto https -timeout 10
```

---

### Phase 1.7: Technology Fingerprinting
**Goal**: Detect frameworks, languages, infrastructure

**Detect**:
- Frontend: React, Angular, Vue, Next.js, Svelte
- Backend: Django, Flask, FastAPI, Express, Laravel, Spring Boot, ASP.NET
- Infrastructure: Nginx, Apache, Cloudflare, Akamai, AWS
- CMS: WordPress, Drupal, Joomla
- JavaScript Frameworks: jQuery, Bootstrap, Webpack

**Package**: `internal/fingerprint`

**Files**:
```
internal/fingerprint/
├── fingerprint.go             # Main fingerprinting engine
├── detectors.go               # Technology detectors
├── patterns.go                # Detection patterns
└── database.go                # Technology database
```

**Data Sources**:
- HTTP Headers
- Cookie analysis
- HTML meta tags
- JavaScript includes
- CSS framework detection
- Wappalyzer-like patterns

**CLI**:
```bash
gospyder fingerprint -d example.com
gospyder fingerprint -l live-hosts.txt
gospyder fingerprint -d example.com -o tech-stack.json
```

---

### Phase 2: DNS Intelligence
**Goal**: Collect comprehensive DNS records

**Records to Collect**:
- [ ] A records
- [ ] AAAA records
- [ ] MX records
- [ ] TXT records
- [ ] NS records
- [ ] CNAME records
- [ ] SOA records
- [ ] CAA records

**Package**: `internal/dnsintel`

**CLI**:
```bash
gospyder dns example.com
gospyder dns example.com -record A,MX,TXT
gospyder dns example.com -o dns-records.json
```

---

### Phase 2.5: ASN Intelligence
**Goal**: Collect ASN and IP range information

**Information**:
- [ ] ASN number
- [ ] Organization name
- [ ] CIDR ranges
- [ ] Reverse DNS ranges

**Package**: `internal/asn`

**Dependencies**: Consider `github.com/projectdiscovery/asnmap`

**CLI**:
```bash
gospyder asn example.com
gospyder asn -asn 13335
```

---

### Phase 2.7: URL Discovery
**Goal**: Aggregate URLs from multiple sources

**Sources**:
- [ ] Wayback Machine API
- [ ] Common Crawl
- [ ] AlienVault OTX
- [ ] URLScan
- [ ] Google Custom Search (optional)

**Package**: `internal/urlcollector`

**CLI**:
```bash
gospyder urls example.com
gospyder urls example.com -sources wayback,commoncrawl
gospyder urls example.com -o urls.txt
```

---

### Phase 3: JavaScript Recon
**Goal**: Extract intelligence from JavaScript files

**Features**:
- [ ] Download JS files
- [ ] Parse JS content
- [ ] Extract URLs/endpoints
- [ ] Extract API paths
- [ ] Extract JWT patterns
- [ ] Extract AWS key patterns
- [ ] Extract Google API key patterns
- [ ] Extract Stripe/payment patterns
- [ ] Extract private IP patterns

**Package**: `internal/jsrecon`

**CLI**:
```bash
gospyder jsrecon -l live-hosts.txt
gospyder jsrecon -d example.com
gospyder jsrecon -l hosts.txt -o js-findings.json
```

---

### Phase 3.5: Parameter Discovery
**Goal**: Discover URL parameters

**Sources**:
- JS Recon findings
- Archived URLs (Wayback Machine)
- Directory fuzzing results
- Common parameter lists

**Package**: `internal/paramfinder`

**CLI**:
```bash
gospyder params -l urls.txt
gospyder params -js js-files.txt
gospyder params -d example.com -o parameters.txt
```

---

### Phase 3.7: GraphQL Discovery
**Goal**: Detect GraphQL endpoints

**Checks**:
- [ ] /graphql
- [ ] /graphiql
- [ ] /playground
- [ ] /api/graphql
- [ ] Safe schema detection

**Package**: `internal/graphql`

**CLI**:
```bash
gospyder graphql -l hosts.txt
gospyder graphql -d example.com
gospyder graphql -l hosts.txt -dump-schema
```

---

### Phase 4: Screenshot Capture
**Goal**: Visual reconnaissance

**Requirements**:
- [ ] Chrome/Chromium automation (chromedp)
- [ ] Screenshot capture
- [ ] Automatic naming and storage
- [ ] Batch processing

**Package**: `internal/screenshot`

**Directory Structure**:
```
screenshots/
├── example.com-80.png
├── admin.example.com.png
└── api.example.com.png
```

**CLI**:
```bash
gospyder screenshot -l live-hosts.txt
gospyder screenshot -d example.com
gospyder screenshot -l hosts.txt -output-dir screenshots/
```

---

### Phase 5: TLS Analyzer
**Goal**: Extract certificate intelligence

**Collects**:
- [ ] Issuer
- [ ] Expiry date
- [ ] SAN entries
- [ ] Wildcard status
- [ ] TLS version
- [ ] Cipher suites

**Package**: `internal/tlsanalyzer`

**CLI**:
```bash
gospyder tls example.com
gospyder tls -l hosts.txt
gospyder tls example.com -o tls-info.json
```

---

### Phase 5.5: Subdomain Takeover Detection
**Goal**: Find potential takeovers

**Providers**:
- AWS S3
- GitHub Pages
- Azure
- Netlify
- Vercel
- Heroku
- Render
- Firebase
- Surge.sh

**Package**: `internal/takeover`

**CLI**:
```bash
gospyder takeover -l subdomains.txt
gospyder takeover -d example.com
gospyder takeover -l subs.txt -o takeovers.json
```

---

### Phase 6: Content Discovery Upgrade
**Goal**: Enhance directory fuzzing

**Enhancements**:
- [ ] Support extensions: .php, .asp, .aspx, .jsp, .json, .yaml, .bak, .old, .zip, .tar.gz
- [ ] Auto-check: swagger.json, openapi.json, robots.txt, security.txt, sitemap.xml
- [ ] Better reporting
- [ ] Faster concurrency
- [ ] Caching

**Package**: Upgrade `internal/fuzzer`

---

### Phase 7: Recon Pipeline
**Goal**: Full reconnaissance workflow

**Pipeline**:
```
Input Domain
    ↓
Subdomain Enumeration
    ↓
Live Host Detection
    ↓
HTTP Probe (headers, titles)
    ↓
Technology Fingerprinting
    ↓
Port Scanning (optional)
    ↓
JS Recon + Parameter Discovery
    ↓
URL Discovery
    ↓
TLS Analysis
    ↓
WAF Detection
    ↓
Takeover Detection
    ↓
Report Generation
```

**Package**: `internal/pipeline`

**CLI**:
```bash
gospyder recon example.com
gospyder recon example.com -full
gospyder recon example.com -o report.json
gospyder recon example.com -output-dir reports/
```

---

### Phase 8: HTML Reporting
**Goal**: Generate comprehensive HTML reports

**Includes**:
- [ ] Executive summary
- [ ] Target overview
- [ ] Subdomains found
- [ ] Live hosts
- [ ] Technologies detected
- [ ] Open ports
- [ ] URLs discovered
- [ ] TLS information
- [ ] WAF detected
- [ ] Screenshots
- [ ] Potential takeovers
- [ ] Risk assessment

**Package**: `internal/report`

**CLI**:
```bash
gospyder report -json recon.json -o report.html
gospyder recon example.com -report
```

---

### Phase 9: Workspace Management
**Goal**: Project-based organization

**Structure**:
```
projects/
└── target-name/
    ├── metadata.json
    ├── subdomains.txt
    ├── live-hosts.txt
    ├── ports.txt
    ├── urls.txt
    ├── technologies.json
    ├── report.html
    ├── screenshots/
    └── cache/
```

**Package**: `internal/workspace`

**CLI**:
```bash
gospyder project create target-name
gospyder project open target-name
gospyder project list
gospyder project delete target-name
gospyder recon example.com -project target-name
```

---

### Phase 10: Template Scanning
**Goal**: Lightweight vulnerability templates

**Features**:
- [ ] YAML template format
- [ ] HTTP request/response matching
- [ ] Custom matchers
- [ ] Severity levels

**Package**: `internal/templates`

**Template Example**:
```yaml
id: exposed-git
name: Exposed .git Directory
severity: high

request:
  path: /.git/config

matchers:
  - type: word
    words:
      - repositoryformatversion
```

**CLI**:
```bash
gospyder template -l hosts.txt -templates templates/
gospyder template -d example.com -template-id exposed-git
```

---

### Phase 11: AI Analysis
**Goal**: AI-powered recon summary

**Support**:
- [ ] OpenAI GPT-4
- [ ] Ollama (local models)
- [ ] Custom model endpoints

**Features**:
- Attack surface analysis
- Risk prioritization
- Insight generation

**Package**: `internal/ai`

**CLI**:
```bash
gospyder ai -json recon.json -provider openai
gospyder ai -json recon.json -provider ollama
```

---

### Phase 12: Configuration System
**Goal**: YAML-based configuration

**Config File**: `gospel.yaml` or `.gospel/config.yaml`

**Example**:
```yaml
threads: 100
timeout: 10
retries: 2

http:
  timeout: 10
  user_agent: "GoSpyder/2.0"

probe:
  enabled: true
  follow_redirects: true

screenshot:
  enabled: false
  headless: true

report:
  enabled: true
  format: html
  include_screenshots: false

workspace:
  enabled: false
  project: default
```

**Package**: `internal/config`

**CLI**:
```bash
gospyder -config gospel.yaml recon example.com
gospyder config init
```

---

### Phase 13: Performance Optimization
**Goal**: Ensure scalability and speed

**Implementations**:
- [ ] Worker pools with backpressure
- [ ] Rate limiting per domain
- [ ] Connection pooling
- [ ] Context-based cancellation
- [ ] Graceful shutdown
- [ ] Progress bars (using `github.com/schollz/progressbar`)
- [ ] Error aggregation and reporting

**Package**: `internal/performance`

---

## 🏗️ NEW DIRECTORY STRUCTURE (FINAL)

```
gospyder/
├── cmd/
│   └── gospyder/
│       ├── main.go                    # Entry point
│       ├── commands.go                # Command definitions
│       └── handlers/
│           ├── enum.go
│           ├── ports.go
│           ├── fuzz.go
│           ├── probe.go
│           ├── waf.go
│           ├── fingerprint.go
│           ├── dnsintel.go
│           ├── asn.go
│           ├── urls.go
│           ├── jsrecon.go
│           ├── params.go
│           ├── graphql.go
│           ├── screenshot.go
│           ├── tls.go
│           ├── takeover.go
│           ├── template.go
│           ├── ai.go
│           ├── pipeline.go
│           ├── report.go
│           └── workspace.go
├── internal/
│   ├── config/
│   │   ├── config.go
│   │   └── defaults.go
│   ├── output/
│   │   ├── formatter.go
│   │   ├── colors.go
│   │   └── progress.go
│   ├── logger/
│   │   └── logger.go
│   ├── http/
│   │   ├── client.go
│   │   └── constants.go
│   ├── context/
│   │   └── context.go
│   ├── errors/
│   │   └── errors.go
│   ├── performance/
│   │   ├── pool.go
│   │   ├── limiter.go
│   │   └── backpressure.go
│   ├── cache/
│   │   └── cache.go
│   ├── probe/
│   │   ├── probe.go
│   │   ├── prober.go
│   │   └── result.go
│   ├── live/
│   │   ├── live.go
│   │   └── detector.go
│   ├── fingerprint/
│   │   ├── fingerprint.go
│   │   ├── detectors.go
│   │   ├── patterns.go
│   │   └── database.go
│   ├── dnsintel/
│   │   ├── dns.go
│   │   └── records.go
│   ├── asn/
│   │   ├── asn.go
│   │   └── ranges.go
│   ├── urlcollector/
│   │   ├── collector.go
│   │   ├── wayback.go
│   │   ├── commoncrawl.go
│   │   └── otx.go
│   ├── jsrecon/
│   │   ├── jsrecon.go
│   │   ├── parser.go
│   │   └── extractor.go
│   ├── paramfinder/
│   │   ├── finder.go
│   │   └── patterns.go
│   ├── graphql/
│   │   ├── graphql.go
│   │   └── detector.go
│   ├── screenshot/
│   │   ├── screenshot.go
│   │   └── browser.go
│   ├── tlsanalyzer/
│   │   ├── analyzer.go
│   │   └── certificate.go
│   ├── takeover/
│   │   ├── takeover.go
│   │   ├── fingerprints.go
│   │   └── detector.go
│   ├── templates/
│   │   ├── templates.go
│   │   ├── matcher.go
│   │   └── loader.go
│   ├── ai/
│   │   ├── ai.go
│   │   ├── openai.go
│   │   └── ollama.go
│   ├── pipeline/
│   │   ├── pipeline.go
│   │   └── orchestrator.go
│   ├── report/
│   │   ├── report.go
│   │   ├── html.go
│   │   └── templates.go
│   └── workspace/
│       ├── workspace.go
│       └── manager.go
├── pkg/
│   ├── enum/                          # Keep existing
│   ├── scanner/                       # Keep existing
│   ├── models/                        # Expand with new types
│   ├── resolver/                      # Keep existing
│   └── sources/                       # Keep existing
├── configs/
│   ├── gospel.yaml                    # Default config
│   └── templates/                     # Template library
│       ├── exposed-git.yaml
│       ├── exposed-aws.yaml
│       └── ...
├── templates/
│   ├── report.html                    # HTML report template
│   └── email.txt                      # Email template
├── wordlists/
│   ├── subdomains.txt                 # Keep existing
│   ├── paths.txt                      # Keep existing
│   ├── endpoints.txt                  # NEW
│   ├── parameters.txt                 # NEW
│   └── technologies.txt               # NEW
├── projects/                          # Workspace storage
├── reports/                           # Generated reports
├── screenshots/                       # Captured screenshots
├── tests/
│   ├── probe_test.go
│   ├── fingerprint_test.go
│   └── ...
├── go.mod
├── go.sum
├── README.md
├── ROADMAP.md                         # This file
├── ARCHITECTURE.md                    # Architecture decisions
└── CONTRIBUTING.md                   # Contribution guidelines

```

---

## 📦 DEPENDENCIES NEEDED

### New Dependencies to Add

```go
// HTTP & Networking
github.com/chromedp/chromedp              // Browser automation for screenshots
github.com/go-resty/resty/v2              // HTTP client (optional, for advanced features)

// Data Processing
github.com/antchfx/htmlquery              // HTML parsing & XPath
github.com/PuerkitoBio/goquery            // jQuery-like parsing
github.com/dlclark/regexp2                // Regex matching

// YAML & Config
gopkg.in/yaml.v3                          // YAML parsing

// Utilities
github.com/schollz/progressbar/v3         // Progress bars
github.com/fatih/color                    // Colors (alternative to custom)
github.com/google/uuid                    // UUID generation

// Optional (for advanced features)
github.com/projectdiscovery/asnmap        // ASN intelligence
github.com/projectdiscovery/goflags       // CLI flags (similar to urfave)

```

---

## 🔍 TECHNICAL DECISIONS

### 1. Command Architecture
**Decision**: Subcommand-based (vs single monolithic command)
**Rationale**: Better UX, scalability, each tool focuses on one task
**Implementation**: Custom flag parsing (keep lightweight) or urfave/cli

### 2. Concurrency Model
**Decision**: Worker pools with context cancellation
**Rationale**: Control resource usage, graceful shutdown
**Pattern**: errgroup.Group for coordinated goroutines

### 3. HTTP Client
**Decision**: Custom wrapper around `net/http.Client`
**Rationale**: Control, minimal dependencies
**Features**: Connection pooling, timeouts, retries, rate limiting

### 4. Configuration
**Decision**: YAML-based with CLI flag overrides
**Rationale**: Professional tool standard, easy to maintain
**Location**: `.gospel/config.yaml` or `-config gospel.yaml`

### 5. Storage
**Decision**: File-based workspace system
**Rationale**: Git-friendly, human-readable, portable
**Format**: JSON metadata, text results, directories

### 6. Fingerprinting
**Decision**: Pattern-based (vs regex-based)
**Rationale**: Performance, accuracy, maintainability
**Source**: Community fingerprints + custom patterns

### 7. Screenshots
**Decision**: Optional chromedp-based automation
**Rationale**: Fast, reliable, headless capability
**Fallback**: Graceful degradation if unavailable

---

## ✅ IMPLEMENTATION ORDER

### Strict Sequence (No Parallel Development)

1. **Phase 0** (Week 1): Architecture Refactoring
   - Subcommand support
   - Package reorganization
   - Internal utilities

2. **Phase 1** (Week 2): HTTP Probe Engine
   - Probe implementation
   - Live host detection
   - Technology fingerprinting

3. **Phase 2** (Week 3): DNS & Asset Discovery
   - DNS intelligence
   - ASN lookup
   - URL discovery from archives

4. **Phase 3** (Week 4): JavaScript & Content Analysis
   - JS file collection & parsing
   - Parameter discovery
   - GraphQL detection

5. **Phase 4-5** (Week 5): Visual & Security Intel
   - Screenshots
   - TLS analysis
   - Takeover detection

6. **Phase 6-7** (Week 6): Integration & Pipeline
   - Directory fuzzing upgrade
   - Unified recon pipeline
   - HTML reporting

7. **Phase 8-9** (Week 7): Management & Config
   - Workspace system
   - Configuration framework
   - Performance optimization

8. **Phase 10-13** (Week 8): Advanced Features
   - Template system
   - AI analysis
   - Final polish

---

## 🧪 TESTING STRATEGY

### Unit Tests
- Each module has `_test.go` file
- Test edge cases, error handling
- Mock external dependencies

### Integration Tests
- Test module combinations
- Pipeline orchestration
- File I/O operations

### CLI Tests
- Command parsing
- Flag handling
- Error messages

### Performance Tests
- Concurrency limits
- Memory usage
- Throughput benchmarks

---

## 📝 BACKWARD COMPATIBILITY

### Maintained
- ✅ All existing flags continue working
- ✅ Output formats unchanged
- ✅ Wordlists format same
- ✅ Port detection unchanged

### Migration Path
```bash
# Old way (still works)
gospyder -d example.com -enum -ports -fuzz -fuzz-url "example.com" -o results.json

# New way (recommended)
gospyder recon example.com -output results.json

# Old individual commands still available
gospyder enum example.com
gospyder ports example.com
gospyder fuzz -url example.com
```

---

## 🎯 SUCCESS CRITERIA

### For Each Phase
1. ✅ All new code is tested
2. ✅ Documentation updated
3. ✅ CLI examples added
4. ✅ Build succeeds
5. ✅ Backward compatible
6. ✅ Reviewed (if team)

### Final Deliverables
- Complete reconnaissance framework
- 13 major features implemented
- Full test coverage
- Comprehensive documentation
- Production-ready codebase
- Community contribution guidelines

---

## 📚 DOCUMENTATION REQUIREMENTS

After each phase:
1. Update README.md with new features
2. Add example commands
3. Document new packages
4. Add troubleshooting section
5. Update ARCHITECTURE.md
6. Create feature guides (if complex)

---

## 🚀 NEXT STEPS

1. **Approve this roadmap**
2. **Start Phase 0** - Architecture refactoring
3. **Implement incrementally** - One phase at a time
4. **Test thoroughly** - Each phase before proceeding
5. **Document everything** - README, examples, architecture
6. **Community feedback** - GitHub issues/discussions
7. **Iterate** - Based on user feedback

---

## 📊 ESTIMATED TIMELINE

- **Total Duration**: 8 weeks (with 1 developer)
- **Phase 0**: 5 days (architecture)
- **Phases 1-3**: 15 days (core features)
- **Phases 4-7**: 10 days (integration)
- **Phases 8-9**: 5 days (management)
- **Phases 10-13**: 5 days (advanced)
- **Polish & Review**: 3 days

---

**Ready to begin Phase 0 implementation?** ✅
