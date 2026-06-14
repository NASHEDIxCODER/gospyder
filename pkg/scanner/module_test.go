package scanner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/NASHEDIxCODER/gospyder/internal/config"
	"github.com/NASHEDIxCODER/gospyder/internal/logger"
	"github.com/NASHEDIxCODER/gospyder/internal/registry"
)

func testOptions(flags map[string]interface{}) registry.Options {
	cfg := config.DefaultConfig()
	cfg.Threads = 10
	cfg.Timeout = 2
	cfg.Scanner.DefaultPorts = []int{}
	return registry.Options{
		Config: cfg,
		Logger: logger.New(false),
		Flags:  flags,
	}
}

func TestPortScanModuleProducesOpenPortFinding(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	_, portRaw, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}

	result, err := NewPortScanModule().Run(context.Background(), testOptions(map[string]interface{}{
		"target":     "127.0.0.1",
		"ports-list": portRaw,
		"retry":      0,
	}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %#v, want one open port", result.Findings)
	}
	if result.Findings[0].Value != portRaw+"/tcp" {
		t.Fatalf("finding value = %q, want %s/tcp", result.Findings[0].Value, portRaw)
	}
}

func TestPortScanModuleAcceptsURLTarget(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	_, portRaw, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}

	result, err := NewPortScanModule().Run(context.Background(), testOptions(map[string]interface{}{
		"target":     "http://127.0.0.1:" + portRaw,
		"ports-list": portRaw,
		"retry":      0,
	}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %#v, want one open port for URL target", result.Findings)
	}
	if result.Metadata["scan_host"] != "127.0.0.1" {
		t.Fatalf("scan_host = %#v, want 127.0.0.1", result.Metadata["scan_host"])
	}
}

func TestFuzzerModuleProducesInterestingPathFinding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	wordlist := filepath.Join(t.TempDir(), "paths.txt")
	if err := os.WriteFile(wordlist, []byte("admin\nmissing\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	result, err := NewFuzzerModule().Run(context.Background(), testOptions(map[string]interface{}{
		"target":   server.URL,
		"wordlist": wordlist,
	}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %#v, want one path", result.Findings)
	}
	if got := result.Findings[0].Metadata["path"]; got != "/admin" {
		t.Fatalf("path metadata = %#v, want /admin", got)
	}
	if got := result.Findings[0].Metadata["status"]; got != 200 {
		t.Fatalf("status metadata = %#v, want 200", got)
	}
}

func TestWAFModuleProducesEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("CF-RAY", "test-ray")
		w.Header().Set("CF-Cache-Status", "DYNAMIC")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("cloudflare security check"))
	}))
	defer server.Close()

	result, err := NewWAFModule().Run(context.Background(), testOptions(map[string]interface{}{
		"target": server.URL,
	}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %#v, want WAF finding", result.Findings)
	}
	if result.Findings[0].Value != "Cloudflare" {
		t.Fatalf("WAF = %q, want Cloudflare", result.Findings[0].Value)
	}
	if len(result.Findings[0].Evidence) == 0 {
		t.Fatal("WAF evidence is empty")
	}
}

func TestHTTPProbeModuleCollectsResponseDetails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		_, _ = w.Write([]byte("<html><head><title>Probe Me</title></head><body>Hello</body></html>"))
	}))
	defer server.Close()

	result, err := NewHTTPProbeModule().Run(context.Background(), testOptions(map[string]interface{}{
		"target": server.URL,
	}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %#v, want one HTTP response", result.Findings)
	}
	finding := result.Findings[0]
	if finding.Metadata["url"] != server.URL {
		t.Fatalf("url = %#v, want %s", finding.Metadata["url"], server.URL)
	}
	if finding.Metadata["status_code"] != 200 {
		t.Fatalf("status = %#v, want 200", finding.Metadata["status_code"])
	}
	if finding.Metadata["title"] != "Probe Me" {
		t.Fatalf("title = %#v, want Probe Me", finding.Metadata["title"])
	}
	if _, ok := finding.Metadata["content_length"].(int64); !ok {
		t.Fatalf("content_length type = %T, want int64", finding.Metadata["content_length"])
	}
	if _, ok := finding.Metadata["response_time_ms"].(int64); !ok {
		t.Fatalf("response_time_ms type = %T, want int64", finding.Metadata["response_time_ms"])
	}
}

func TestLiveHostModuleUsesHTTPProbeResults(t *testing.T) {
	httpResult := &registry.Result{
		Module: "http",
		Findings: []registry.Finding{{
			Type:  "http_probe",
			Value: "http://127.0.0.1:8080",
			Metadata: map[string]interface{}{
				"url":         "http://127.0.0.1:8080",
				"status_code": 200,
			},
		}},
	}

	result, err := NewLiveHostModule().Run(context.Background(), testOptions(map[string]interface{}{
		"target": "127.0.0.1",
		"results": map[string]*registry.Result{
			"http": httpResult,
		},
	}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(result.Findings) != 1 || result.Findings[0].Value != "127.0.0.1:8080" {
		t.Fatalf("findings = %#v, want live host", result.Findings)
	}
}

func TestTechModuleDetectsRequestedTechnologies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.Header().Set("CF-RAY", "test")
		w.Header().Set("CF-Cache-Status", "DYNAMIC")
		_, _ = w.Write([]byte(`
			<div id="reactroot"></div>
			<script src="/angular.js"></script>
			<div data-v-test></div>
			<link href="/wp-content/theme.css">
			django csrftoken flask werkzeug fastapi uvicorn apache
		`))
	}))
	defer server.Close()

	result, err := NewTechModule().Run(context.Background(), testOptions(map[string]interface{}{
		"target": server.URL,
	}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	got := map[string]bool{}
	for _, finding := range result.Findings {
		got[finding.Value] = true
	}
	for _, want := range []string{"React", "Angular", "Vue", "WordPress", "Django", "Flask", "FastAPI", "Nginx", "Apache", "Cloudflare"} {
		if !got[want] {
			t.Fatalf("missing technology %q in findings %#v", want, result.Findings)
		}
	}
}

func TestPortScanModuleHonorsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	result, err := NewPortScanModule().Run(ctx, testOptions(map[string]interface{}{
		"target":     "192.0.2.1",
		"ports-list": "80",
		"retry":      0,
	}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancelled scan took too long")
	}
	if len(result.Findings) != 0 {
		t.Fatalf("findings = %#v, want none for cancelled scan", result.Findings)
	}
}

func TestPortsFromOptionsRejectsInvalidPort(t *testing.T) {
	_, err := portsFromOptions(testOptions(map[string]interface{}{
		"ports-list": "70000",
	}))
	if err == nil {
		t.Fatal("portsFromOptions() error = nil, want invalid port error")
	}
}

func TestParseFuzzFinding(t *testing.T) {
	path, status := parseFuzzFinding("", "http://example.com/admin [403]")
	if path != "/admin" || status != 403 {
		t.Fatalf("parseFuzzFinding() = (%q, %d), want (/admin, 403)", path, status)
	}
}

func TestServiceNameKnownAndUnknown(t *testing.T) {
	if serviceName(443) != "HTTPS" {
		t.Fatalf("serviceName(443) = %q, want HTTPS", serviceName(443))
	}
	port, err := strconv.Atoi(strings.TrimSpace(fmt.Sprint(65000)))
	if err != nil {
		t.Fatalf("Atoi() error = %v", err)
	}
	if serviceName(port) != "unknown" {
		t.Fatalf("serviceName(%d) = %q, want unknown", port, serviceName(port))
	}
}
