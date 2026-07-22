package scanner

import (
	"regexp"
	"strings"
)

// DetectService identifies the service name from a port number and optional banner.
// This is an enhanced version of the simple serviceName() function that uses
// banner content for more accurate detection.
func DetectService(port int, banner string) (service string, version string) {
	// First, try banner-based detection (most accurate)
	if banner != "" {
		if svc, ver := detectFromBanner(banner); svc != "" {
			return svc, ver
		}
	}

	// Fall back to port-based detection
	return serviceFromPort(port), ""
}

// detectFromBanner matches banner text against known service fingerprints.
// Returns service name and version if detected.
func detectFromBanner(banner string) (string, string) {
	bannerLower := strings.ToLower(banner)

	// Check each service fingerprint
	for _, fp := range fingerprints {
		if fp.match(bannerLower) {
			version := extractVersion(banner, fp.versionPattern)
			return fp.service, version
		}
	}

	return "", ""
}

// ServiceFingerprint defines how to detect a service and extract its version.
type ServiceFingerprint struct {
	service        string
	identifiers    []string // patterns that identify this service (lowercase)
	versionPattern *regexp.Regexp
}

// match returns true if the banner matches any of the service identifiers.
func (fp *ServiceFingerprint) match(bannerLower string) bool {
	for _, id := range fp.identifiers {
		if strings.Contains(bannerLower, id) {
			return true
		}
	}
	return false
}

// fingerprints is the master list of service fingerprints for banner analysis.
var fingerprints = []ServiceFingerprint{
	// SSH - banner: SSH-2.0-OpenSSH_9.6
	{
		service:        "SSH",
		identifiers:    []string{"ssh-2.0", "ssh-1.99", "openssh"},
		versionPattern: regexp.MustCompile(`OpenSSH[_-]([\d.]+)`),
	},
	// FTP - banner: 220 ProFTPD 1.3.8
	{
		service:        "FTP",
		identifiers:    []string{"ftp", "proftpd", "vsftpd", "pure-ftpd", "filezilla"},
		versionPattern: regexp.MustCompile(`(?:ProFTPD|vsftpd|pure-ftpd|FileZilla)[\s/]*([\d.]+)`),
	},
	// SMTP - banner: 220 mail.example.com ESMTP Postfix
	{
		service:        "SMTP",
		identifiers:    []string{"smtp", "esmtp", "postfix", "sendmail", "exim", "qmail", "courier"},
		versionPattern: regexp.MustCompile(`(?:Postfix|Sendmail|Exim|Courier)[\s/]*([\d.]+)`),
	},
	// POP3 - banner: +OK POP3 server ready
	{
		service:        "POP3",
		identifiers:    []string{"pop3", "dovecot"},
		versionPattern: regexp.MustCompile(`Dovecot[\s/]*([\d.]+)`),
	},
	// IMAP - banner: * OK IMAP4rev1 server ready
	{
		service:        "IMAP",
		identifiers:    []string{"imap", "dovecot", "courier-imap"},
		versionPattern: regexp.MustCompile(`Dovecot[\s/]*([\d.]+)`),
	},
	// MySQL - banner: 8.0.32
	{
		service:        "MySQL",
		identifiers:    []string{"mysql", "mariadb"},
		versionPattern: regexp.MustCompile(`(\d+\.\d+\.\d+)[\x00-\x1f]?`),
	},
	// PostgreSQL - banner: PostgreSQL 16.1
	{
		service:        "PostgreSQL",
		identifiers:    []string{"postgresql", "postgres"},
		versionPattern: regexp.MustCompile(`PostgreSQL[\s]*([\d.]+)`),
	},
	// Redis - banner: -ERR unknown command or +OK, or Redis version string
	{
		service:        "Redis",
		identifiers:    []string{"redis_version", "redis"},
		versionPattern: regexp.MustCompile(`redis_version[:\s]*([\d.]+)`),
	},
	// MongoDB - banner: ok 1 or MongoDB version
	{
		service:        "MongoDB",
		identifiers:    []string{"mongodb", "mongo"},
		versionPattern: regexp.MustCompile(`(\d+\.\d+\.\d+)`),
	},
	// HTTP/HTTPS - detected via probe, not banner
	{
		service:        "HTTP",
		identifiers:    []string{"http", "nginx", "apache", "iis", "jetty", "tomcat"},
		versionPattern: regexp.MustCompile(`(?:Apache|nginx|IIS|Jetty|Tomcat)[/\s]*([\d.]+)`),
	},
	// DNS - banner detection is less common but possible
	{
		service:        "DNS",
		identifiers:    []string{"dns", "bind"},
		versionPattern: regexp.MustCompile(`BIND[\s]*([\d.]+)`),
	},
	// Telnet
	{
		service:        "Telnet",
		identifiers:    []string{"telnet"},
		versionPattern: nil,
	},
	// RDP
	{
		service:        "RDP",
		identifiers:    []string{"rdp", "terminal services", "terminal server"},
		versionPattern: nil,
	},
}

// extractVersion extracts a version string from the banner using the given regex pattern.
func extractVersion(banner string, pattern *regexp.Regexp) string {
	if pattern == nil {
		return ""
	}
	matches := pattern.FindStringSubmatch(banner)
	if len(matches) >= 2 {
		return matches[1]
	}
	return ""
}

// serviceFromPort returns the default service name for a port.
func serviceFromPort(port int) string {
	services := map[int]string{
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		25:    "SMTP",
		53:    "DNS",
		80:    "HTTP",
		110:   "POP3",
		143:   "IMAP",
		443:   "HTTPS",
		465:   "SMTPS",
		587:   "SMTP",
		993:   "IMAPS",
		995:   "POP3S",
		1433:  "MSSQL",
		1521:  "OracleDB",
		3306:  "MySQL",
		3389:  "RDP",
		5432:  "PostgreSQL",
		5900:  "VNC",
		5901:  "VNC",
		6379:  "Redis",
		8000:  "HTTP-alt",
		8080:  "HTTP-alt",
		8443:  "HTTPS-alt",
		9000:  "HTTP-alt",
		9090:  "HTTP-alt",
		27017: "MongoDB",
		27018: "MongoDB",
	}
	if svc, ok := services[port]; ok {
		return svc
	}
	return "unknown"
}

// HTTPProbeResult holds the result of HTTP probing with version info.
type HTTPProbeResult struct {
	Port    int
	Service string
	Version string
	Banner  string
}
