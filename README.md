<div align="center">

# 🕷️ GoSpyder  
### High-Performance Security Scanner in Go

A blazing-fast, concurrent security scanner for **subdomain enumeration, port scanning, WAF detection, and directory fuzzing** — built for bug bounty hunters and penetration testers who value speed, accuracy, and modular design.

<p>
  <b>Scan smarter. Hunt faster. Break responsibly.</b>
</p>

</div>

---

## 🚀 Features

### 🔍 Subdomain Enumeration
- Active brute-force DNS scanning  
- Passive discovery via Certificate Transparency logs  

### 🌐 Port Scanning
- High-performance TCP scanner  
- Service detection & banner grabbing  

### 🛡️ WAF Detection
- Fingerprinting for 20+ WAF providers  

### 🗂 Directory Fuzzing
- Multi-threaded, high-speed path discovery  

### 🎨 Beautiful CLI
- Colored output with live progress indicators  

### 🧩 Modular Architecture
- Interface-based modules for seamless expansion  
---

## 📦 Installation

### 🔹 Install via `go install` (Recommended)

```bash
CGO_ENABLED=0 go install github.com/NASHEDIxCODER/gospyder/cmd/gospyder@latest
```

Ensure Go bin path is available:

```bash
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.bashrc
source ~/.bashrc
```

Move to /usr/local/bin (Recommended):
```bash
sudo mv gospyder /usr/local/bin/
sudo chmod +x /usr/local/bin/gospyder
```

Run from anywhere:

```bash
gospyder -d example.com -enum
```

---
## 🎯 Usage

### Basic Subdomain Enumeration
```bash
gospyder -d example.com -enum -o results.txt
```

### Advanced Enumeration
```bash
# Active + Passive
gospyder -d example.com -enum -active -passive -o all-subdomains.txt

# Custom wordlist & threads
gospyder -d example.com -enum -w custom-wordlist.txt -t 1000 -o subs.txt

# Passive only
gospyder -d example.com -enum -passive -timeout 30 -o passive-subs.txt
```

### Port Scanning
```bash
# Common ports
gospyder -d example.com -ports -service -o ports.txt

# Specific range
gospyder -d example.com -ports -ports-list "21,22,80,443,8080-8090" -service -o custom-ports.txt
```

### WAF Detection
```bash
gospyder -d example.com -waf -v
```

### Directory Fuzzing
```bash
# Default wordlist
gospyder -d example.com -fuzz -fuzz-url "https://example.com" -o dirs.txt

# Custom wordlist
gospyder -d example.com -fuzz -fuzz-url "https://example.com" -fuzz-wordlist paths.txt -o custom-dirs.txt
```

### Full Security Scan
```bash
gospyder -d example.com   \
  -enum -active -passive   \
  -ports -service           \
  -waf                      \
  -fuzz -fuzz-url "https://example.com" \
  -o full-scan-results.txt
```

---

## 📊 Sample Output
```

 ██████╗  ██████╗ ███████╗██████╗ ██╗   ██╗██████╗ ███████╗██████╗ 
██╔════╝ ██╔═══██╗██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗
██║  ███╗██║   ██║███████╗██████╔╝ ╚████╔╝ ██║  ██║█████╗  ██████╔╝
██║   ██║██║   ██║╚════██║██╔═══╝   ╚██╔╝  ██║  ██║██╔══╝  ██╔══██╗
╚██████╔╝╚██████╔╝███████║██║        ██║   ██████╔╝███████╗██║  ██║
 ╚═════╝  ╚═════╝ ╚══════╝╚═╝        ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝

                by nashedi_x_coder


Target: example.com
Threads: 500 | Timeout: 10m

[ACTIVE] Found: www.example.com
[PASSIVE] Found: staging.example.com

Open Ports:
80  (HTTP)
443 (HTTPS)

WAF Detected: Cloudflare

Directories:
/admin
/api/v1

Results saved to: full-scan-results.txt
```

---

## 🏗️ Architecture
```
gospyder/
├── cmd/gospyder/main.go          # CLI entry point
├── pkg/
│   ├── enum/                # Subdomain enumeration engine
│   ├── scanner/             # Port scanning & WAF detection
│   ├── resolver/            # DNS resolver pool
│   ├── sources/             # Passive data sources
│   └── models/              # Shared structs
└── wordlists/               # Default wordlists
```

---

## 🛠️ Building from Source
```bash
GOOS=linux GOARCH=amd64 go build -o gospyder-linux cmd/cli/main.go
GOOS=darwin GOARCH=amd64 go build -o gospyder-mac cmd/cli/main.go
GOOS=windows GOARCH=amd64 go build -o gospyder.exe cmd/cli/main.go
```

---

## 🔧 Development

### Adding New Modules
```go
type Module interface {
    Name() string
    Scan(ctx context.Context, target string) ([]Result, error)
}
```
Register your module in the module runner inside `main.go`.

### Wordlists
Place custom lists inside `wordlists/`:
- `subdomains.txt`
- `paths.txt`

---

## ⚡ Performance Tips
- Increase threads: `-t 1000`
- Reduce timeout: `-timeout 2`
- Limit ports: `-ports-list "80,443"`
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

