<div align="center">

# 🕷️ GoSpyder  
### 🚀 High-Performance Security Scanner in Go

A blazing-fast, concurrent security scanner for **subdomain enumeration, port scanning, WAF detection, and directory fuzzing** — built for bug bounty hunters and penetration testers who demand speed, accuracy, reliability, and comprehensive coverage.

<p>
  <b>🎯 Scan smarter. Hunt faster. Break responsibly.</b>
</p>

![Go](https://img.shields.io/badge/Go-1.18+-00ADD8?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Production--Ready-brightgreen?style=flat-square)

</div>

---

## 📋 Table of Contents
- [🌟 Features](#-features)
- [🚀 Quick Start](#-quick-start)
- [📦 Installation](#-installation)
- [🎯 Usage](#-usage)
- [⚙️ Advanced Usage](#-advanced-usage)
- [📊 Output Formats](#-output-formats)
- [🏗️ Architecture](#-architecture)
- [🔧 Development](#-development)
- [⚡ Performance](#-performance)
- [🐛 Troubleshooting](#-troubleshooting)
- [📝 License](#-license)

---

## 🌟 Features

### 🔍 Subdomain Enumeration (Enhanced)
- **Active brute-force DNS scanning** with custom wordlists
- **Passive discovery** via Certificate Transparency logs (CertStream)
- **Active + Passive hybrid mode** for comprehensive coverage
- **High-performance concurrent** resolution with multiple DNS servers
- **Customizable threading** for optimal speed/reliability balance

### 🌐 Port Scanning (Comprehensive)
- **37+ common service ports** by default (expanded from 14)
- **TCP connect scanning** with context-aware timeouts
- **Automatic service detection** for 30+ protocols (HTTP, HTTPS, SMTP, FTP, MySQL, MongoDB, Redis, Elasticsearch, etc.)
- **Smart retry logic** for unreliable networks (configurable retries)
- **Port range support** (e.g., `8000-9000`)
- **Custom port lists** via CLI

**Ports Scanned**: FTP, SSH, Telnet, SMTP, DNS, HTTP, POP3, IMAP, HTTPS, SMTPS, SMTP-TLS, IMAPS, POP3S, MSSQL, Oracle, MySQL, RDP, Flask, PostgreSQL, VNC, CouchDB, X11, Redis, Cassandra, HTTP-Proxy variants, ActiveMQ, Jupyter, SonarQube, Elasticsearch, MongoDB, Prometheus, Memcached, HDFS, and more.

### 🛡️ WAF Detection (20+ WAF Providers)
- Fingerprinting for popular WAF providers:
  - ☁️ **Cloudflare** | 🌐 **Akamai** | 🔒 **Imperva/Incapsula** | 🛡️ **Sucuri**
  - ☁️ **AWS WAF** | **F5 BIG-IP** | **Wordfence** | **ModSecurity**
  - **Barracuda** | And more...
- **Smart payload delivery** to trigger WAF detection rules
- **Multi-indicator detection** (headers, cookies, response content, status codes)

### 🗂️ Directory Fuzzing (576 Paths)
- **576 common paths** by default (expanded from 13 paths - 44x larger!)
- **Comprehensive path coverage**:
  - Admin interfaces (`/admin`, `/wp-admin`, `/phpmyadmin`)
  - API endpoints (`/api`, `/v1`, `/v2`, `/v3`, `/graphql`, `/rest`, `/soap`)
  - Authentication pages (`/login`, `/register`, `/auth`, `/oauth`, `/saml`, `/ldap`)
  - Configuration files (`/.env`, `/config`, `/secrets`, `/credentials`)
  - Backup files and archives
  - Development pages (`/dev`, `/test`, `/debug`)
  - Framework-specific paths (WordPress, Laravel, Django, etc.)
  - And many more...
- **HTTP status code detection**: Finds 2xx, 3xx, 401, and 403 responses
- **Multi-threaded fuzzing** with configurable concurrency
- **Custom wordlists** supported

### 🎨 Beautiful CLI
- ✨ **Colored output** with context-aware formatting
- 📊 **Live progress indicators** during scanning
- 📈 **Rich summary** with total findings count
- 🎯 **Status indicators** (✓ success, ✗ error, ℹ info, ⚠ warning)

### 🧩 Modular Architecture
- **Interface-based modules** for seamless expansion
- **Independent scanners** can be combined or run separately
- **Extensible design** for adding new features
- **Clean separation** of concerns

---

## 🚀 Quick Start

```bash
# Install
go install github.com/NASHEDIxCODER/gospyder/cmd/gospyder@latest

# Basic scan
gospyder -d example.com -enum -ports -service -waf -fuzz -fuzz-url "https://example.com" -o results.txt

# Full scan with JSON output
gospyder -d example.com -enum -active -passive -ports -service -waf -fuzz -fuzz-url "https://example.com" -format json -o results.json
```

---

## 📦 Installation

### 🔹 Method 1: Using `go install` (Recommended)

```bash
CGO_ENABLED=0 go install github.com/NASHEDIxCODER/gospyder/cmd/gospyder@latest
```

Ensure Go bin path is available:
```bash
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.bashrc
source ~/.bashrc
```

### 🔹 Method 2: Build from Source

```bash
git clone https://github.com/NASHEDIxCODER/gospyder.git
cd gospyder
go build -o gospyder ./cmd/gospyder/
sudo mv gospyder /usr/local/bin/
sudo chmod +x /usr/local/bin/gospyder
```

### 🔹 Method 3: Cross-Compilation

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o gospyder-linux ./cmd/gospyder/

# macOS
GOOS=darwin GOARCH=amd64 go build -o gospyder-mac ./cmd/gospyder/

# Windows
GOOS=windows GOARCH=amd64 go build -o gospyder.exe ./cmd/gospyder/
```

---

## 🎯 Usage

### Basic Commands

#### 1. Subdomain Enumeration
```bash
# Active only (default)
gospyder -d example.com -enum

# Passive only (fast, non-intrusive)
gospyder -d example.com -enum -passive

# Active + Passive (comprehensive)
gospyder -d example.com -enum -active -passive

# With custom wordlist
gospyder -d example.com -enum -w custom-domains.txt

# Verbose output
gospyder -d example.com -enum -v
```

#### 2. Port Scanning
```bash
# Scan default 37 ports
gospyder -d example.com -ports

# Scan with service detection
gospyder -d example.com -ports -service

# Scan specific ports
gospyder -d example.com -ports -ports-list "80,443,8080,8443"

# Scan port range
gospyder -d example.com -ports -ports-list "1000-2000,8000-9000"

# With retry logic (useful for unreliable networks)
gospyder -d example.com -ports -retry 3 -v
```

#### 3. WAF Detection
```bash
# Detect WAF on target
gospyder -d example.com -waf

# Verbose WAF detection
gospyder -d example.com -waf -v
```

#### 4. Directory Fuzzing
```bash
# Fuzz with default 576 paths
gospyder -d example.com -fuzz -fuzz-url "https://example.com"

# Custom wordlist
gospyder -d example.com -fuzz -fuzz-url "https://example.com" -fuzz-wordlist custom-paths.txt

# HTTP auto-detection (auto-converts domain to https://)
gospyder -d example.com -fuzz -fuzz-url "example.com"
```

### Complete Scanning

```bash
# Everything at once
gospyder -d example.com \
  -enum -active -passive \
  -ports -service \
  -waf \
  -fuzz -fuzz-url "https://example.com" \
  -o full-scan.txt

# With custom threading and timeout
gospyder -d example.com \
  -enum -ports -fuzz -fuzz-url "https://example.com" \
  -t 1000 \
  -timeout 30 \
  -o scan-results.txt
```

---

## ⚙️ Advanced Usage

### 📊 Output Formats

#### Text Output (Default)
```bash
gospyder -d example.com -ports -o results.txt
```

#### JSON Output
```bash
gospyder -d example.com -ports -format json -o results.json
# or
gospyder -d example.com -ports -json -o results.json
```

**JSON Structure:**
```json
{
  "timestamp": "2024-06-14T10:30:00Z",
  "total_findings": 15,
  "results": [
    "www.example.com",
    "api.example.com",
    "example.com:80 [HTTP]",
    "example.com:443 [HTTPS]"
  ]
}
```

#### CSV Output
```bash
gospyder -d example.com -ports -format csv -o results.csv
```

### 🔧 Performance Tuning

```bash
# High-speed scanning (aggressive)
gospyder -d example.com -enum -ports -fuzz -fuzz-url "https://example.com" \
  -t 2000 \
  -timeout 5 \
  -retry 1

# Stealth mode (slow, careful)
gospyder -d example.com -enum -passive -ports \
  -t 100 \
  -timeout 30 \
  -retry 3

# Balanced (default)
gospyder -d example.com -enum -ports -fuzz -fuzz-url "https://example.com" \
  -t 500 \
  -timeout 10 \
  -retry 2
```

### 🎯 Targeting Options

```bash
# Specific port list for targeted scanning
gospyder -d example.com -ports \
  -ports-list "80,443,8080,8443,3306,5432,27017,9200"

# Multiple domains (use in a loop)
for domain in example.com test.com; do
  gospyder -d $domain -enum -ports -o $domain-results.txt
done

# Subdomain-only scan
gospyder -d example.com -enum -passive -o subdomains.txt

# Infrastructure-only scan
gospyder -d example.com -ports -service -waf -o infrastructure.txt
```

---

## 📊 Output Formats

### Sample Text Output
```
 ██████╗  ██████╗ ███████╗██████╗ ██╗   ██╗██████╗ ███████╗██████╗ 
██╔════╝ ██╔═══██╗██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗
██║  ███╗██║   ██║███████╗██████╔╝ ╚████╔╝ ██║  ██║█████╗  ██████╔╝
██║   ██║██║   ██║╚════██║██╔═══╝   ╚██╔╝  ██║  ██║██╔══╝  ██╔══██╗
╚██████╔╝╚██████╔╝███████║██║        ██║   ██████╔╝███████╗██║  ██║
 ╚═════╝  ╚═════╝ ╚══════╝╚═╝        ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝

Target: example.com
Threads: 500 | Timeout: 10m

ℹ Starting subdomain enumeration...
Mode: active+passive
✓ www.example.com
✓ api.example.com
✓ blog.example.com
✓ Enumeration: 3 subdomains found

ℹ Starting port scan...
Ports: 37 to scan
✓ example.com:80 [HTTP]
✓ example.com:443 [HTTPS]
✓ Port scan: 2 open ports found

⚠ Starting WAF detection...
⚠ WAF detected: Cloudflare

ℹ Starting directory fuzzing...
URL: https://example.com
✓ https://example.com/admin [401]
✓ https://example.com/api [200]
✓ https://example.com/api/v1 [200]
✓ Fuzzing: 3 paths found

╔═══════════════════════════════════════════╗
║          SCAN SUMMARY                     ║
╚═══════════════════════════════════════════╝
Total findings: 11
✓ Results saved to full-scan.txt (txt format)
```

### Sample JSON Output
```json
{
  "timestamp": "2024-06-14T10:30:45Z",
  "total_findings": 11,
  "results": [
    "www.example.com",
    "api.example.com",
    "blog.example.com",
    "example.com:80 [HTTP]",
    "example.com:443 [HTTPS]",
    "WAF detected: Cloudflare",
    "https://example.com/admin [401]",
    "https://example.com/api [200]",
    "https://example.com/api/v1 [200]"
  ]
}
```

---

## 🏗️ Architecture

```
gospyder/
├── cmd/
│   └── gospyder/
│       └── main.go              # CLI entry point & orchestration
├── pkg/
│   ├── enum/
│   │   ├── engine.go            # Enumeration orchestrator
│   │   ├── active.go            # Active DNS brute-force
│   │   ├── passive.go           # Passive CertStream
│   │   └── brute.go             # Brute-force logic
│   ├── scanner/
│   │   ├── interface.go         # Scanner interfaces
│   │   ├── portscan.go          # Port scanner + retry logic
│   │   ├── fuzzer.go            # Directory fuzzer
│   │   └── waf.go               # WAF detection
│   ├── resolver/
│   │   └── pool.go              # DNS resolver pool
│   ├── sources/
│   │   └── certstream.go        # CertStream client
│   ├── models/
│   │   └── domain.go            # Domain struct
│   └── enum/
│       ├── recursive.go         # Recursive enumeration
│       └── engine.go            # Engine configuration
├── wordlists/
│   ├── subdomains.txt           # 50+ common subdomains
│   └── paths.txt                # 576 common paths
├── go.mod
├── go.sum
├── README.md
├── LICENSE
└── IMPROVEMENTS.md
```

---

## 🔧 Development

### Adding Custom Modules

```go
package scanner

type CustomScanner struct{}

func (cs *CustomScanner) Scan(ctx context.Context, target string) ([]string, error) {
    // Your scanning logic here
    return results, nil
}
```

Register in `main.go`:
```go
if *customPtr {
    wg.Add(1)
    go func() {
        defer wg.Done()
        customScanner := &scanner.CustomScanner{}
        results := customScanner.Scan(ctx, target)
        // Append to results
    }()
}
```

### Wordlist Management

Create custom wordlists in `wordlists/`:
```bash
# Custom subdomains
echo "subdomain1\nsubdomain2\nsubdomain3" > wordlists/custom-subs.txt
gospyder -d example.com -enum -w wordlists/custom-subs.txt

# Custom paths
echo "custom-path\nprivate\nadmin" > wordlists/custom-paths.txt
gospyder -d example.com -fuzz -fuzz-url "https://example.com" -fuzz-wordlist wordlists/custom-paths.txt
```

---

## ⚡ Performance

### Performance Metrics (Reference)

| Scenario | Time | Threads | Findings |
|----------|------|---------|----------|
| 37 ports (3 retries) | ~45s | 500 | Avg 3-5 ports |
| 576 paths (HTTP 3s timeout) | ~180s | 500 | Avg 5-20 paths |
| Full scan (all modules) | ~5m | 500 | 50-200 results |
| Subdomain enum (passive) | ~30s | 500 | 5-50 domains |

### Optimization Tips

| Goal | Settings |
|------|----------|
| **Speed** | `-t 2000 -timeout 5 -retry 1` |
| **Accuracy** | `-t 100 -timeout 30 -retry 3` |
| **Balanced** | `-t 500 -timeout 10 -retry 2` (default) |
| **Limited Network** | `-t 200 -timeout 20 -retry 2` |
| **Large Wordlist** | `-t 1000` (increase threads) |

---

## 🐛 Troubleshooting

### Port Scan Returns 0 Results
```bash
# Issue: All ports appear closed
# Solution 1: Increase timeout
gospyder -d example.com -ports -timeout 20

# Solution 2: Enable retries
gospyder -d example.com -ports -retry 3 -v

# Solution 3: Test specific ports
gospyder -d example.com -ports -ports-list "80,443" -v
```

### Fuzzing Returns Few Results
```bash
# Issue: Few paths found
# Solution 1: Verbose mode to see what's happening
gospyder -d example.com -fuzz -fuzz-url "https://example.com" -v

# Solution 2: Increase thread count
gospyder -d example.com -fuzz -fuzz-url "https://example.com" -t 1000

# Solution 3: Increase timeout per request
gospyder -d example.com -fuzz -fuzz-url "https://example.com" -timeout 20
```

### WAF Not Detected
```bash
# Issue: WAF present but not detected
# Solution: Use verbose mode
gospyder -d example.com -waf -v

# Manual verification:
curl -A "SQLi/1.0" "https://example.com/?id=1 AND 1=1"
```

### CertStream Connection Fails
```bash
# Issue: Passive enumeration fails
# Solution: Use active only
gospyder -d example.com -enum -active

# Or check network connectivity:
curl "https://certstream.calidog.io"
```

### Out of Memory
```bash
# Reduce threads and increase timeout
gospyder -d example.com -enum -ports -fuzz -fuzz-url "https://example.com" \
  -t 100 -timeout 30
```

---

## 🎓 CLI Reference

```
Usage of gospyder:
  -active
        Force active enumeration only
  -d string
        Target domain (required)
  -enum
        Enable subdomain enumeration
  -fuzz
        Enable directory fuzzing
  -fuzz-url string
        Base URL to fuzz
  -fuzz-wordlist string
        Wordlist for fuzzing (default "wordlists/paths.txt")
  -format string
        Output format: txt, json, csv (default "txt")
  -json
        Output as JSON
  -o string
        Output file (.txt/.json/.csv format)
  -passive
        Force passive enumeration only
  -ports
        Enable port scanning
  -ports-list string
        Ports to scan (default: 37 common ports)
  -retry int
        Number of retries for failed connections (default 2)
  -service
        Enable service detection on ports
  -t int
        Number of concurrent threads (default 500)
  -timeout int
        Timeout in minutes (default 10)
  -v
        Verbose output
  -w string
        Wordlist for subdomain enum (default "wordlists/subdomains.txt")
  -waf
        Enable WAF detection
```

---

## 📊 Statistics & Coverage

### Port Coverage
- **37 ports** scanned by default
- **30+ services** automatically detected
- **Retry logic** for unreliable networks
- Coverage: Common services, web servers, databases, caches, monitoring tools

### Path Coverage
- **576 paths** in default wordlist
- **44x expansion** from original 13 paths
- Categories: Admin, API, Auth, Config, Backup, Dev, Logs, Status, Security, etc.
- HTTP status detection: 2xx, 3xx, 401, 403

### WAF Coverage
- **20+ WAF providers** detected
- **Multi-indicator detection**: Headers, cookies, content, status codes
- **Smart payload delivery** to trigger detection rules

---

## 📝 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**nashedi_x_coder** - Security researcher and Go enthusiast

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

---

## ⚠️ Disclaimer

**gospyder** is designed for **authorized security testing only**. Unauthorized access to computer systems is illegal. Always obtain proper authorization before conducting security assessments.

---

<div align="center">

**Built with ❤️ for the security community**

[⭐ Star on GitHub](https://github.com/NASHEDIxCODER/gospyder) | [🐛 Report Issues](https://github.com/NASHEDIxCODER/gospyder/issues)

</div>
- Active-only scan for speed

---

## 🔒 Legal Notice
Use this tool only on targets you own or have explicit permission to test.

---

## 📄 License
MIT License — see `LICENSE` file

---

## 🤝 Contributing
1. Fork the repository
2. Create your branch
3. Add improvements/tests
4. Submit a Pull Request

---
<div align="center">

### 🧠 Author
Developed with ⚡ by **NASHEDIxCODER**  
Follow on Twitter: [@sonu_samrat_01]

---
</div> ```

> GoSpyder – Scan smarter. Hunt faster. Break responsibly.

