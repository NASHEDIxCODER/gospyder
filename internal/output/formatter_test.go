package output

import (
	"strings"
	"testing"
	"time"

	"github.com/NASHEDIxCODER/gospyder/internal/registry"
)

func TestFormatWAFDetected(t *testing.T) {
	formatter := New("txt", false, true)
	result := &registry.Result{
		Module:    "waf",
		Timestamp: time.Now(),
		Status:    "success",
		Target:    "example.com",
		Findings: []registry.Finding{{
			Type:     "waf",
			Value:    "Cloudflare",
			Evidence: []string{"Server: cloudflare", "CF-RAY header present"},
			Metadata: map[string]interface{}{
				"confidence": "High",
			},
		}},
	}

	out, err := formatter.Format(result)
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}
	for _, want := range []string{"Target: example.com", "WAF Detected: Cloudflare", "Confidence: High", "* Server: cloudflare"} {
		if !strings.Contains(out, want) {
			t.Fatalf("Format() missing %q in:\n%s", want, out)
		}
	}
}

func TestFormatNoWAF(t *testing.T) {
	formatter := New("txt", false, true)
	out, err := formatter.Format(&registry.Result{
		Module: "waf",
		Target: "example.com",
		Status: "success",
	})
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}
	if !strings.Contains(out, "No WAF detected") {
		t.Fatalf("Format() = %q, want no WAF message", out)
	}
}

func TestFormatReconSummary(t *testing.T) {
	formatter := New("txt", false, true)
	out, err := formatter.Format([]*registry.Result{
		{Module: "enum", Target: "example.com", Findings: []registry.Finding{{Value: "www.example.com"}}},
		{Module: "ports", Target: "example.com", Findings: []registry.Finding{{Value: "80/tcp"}}},
		{Module: "fuzz", Target: "https://example.com", Findings: []registry.Finding{{Value: "/admin"}}},
		{Module: "waf", Target: "example.com", Findings: []registry.Finding{{Value: "Cloudflare"}}},
	})
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}
	for _, want := range []string{"Subdomains: 1", "Open Ports: 1", "WAF: Cloudflare", "Interesting Paths: 1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("Format() missing %q in:\n%s", want, out)
		}
	}
}
