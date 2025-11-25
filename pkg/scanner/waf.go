package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type WAFScanner struct{}

func (ws *WAFScanner) Detect(ctx context.Context, target string) string {
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Multiple payloads to trigger different WAF rules
	payloads := []string{
		"?id=1 AND 1=1",
		"?q=<script>alert(1)</script>",
		"?file=../../etc/passwd",
		"?redirect=http://evil.com",
		"?cmd=cat /etc/passwd",
		"?exec=bash",
	}

	// Comprehensive WAF indicators
	wafIndicators := map[string]struct {
		name     string
		headers  []string
		content  []string
		cookies  []string
		statuses []int
	}{
		"cloudflare": {
			name:     "Cloudflare",
			headers:  []string{"cf-ray", "cf-cache-status", "server: cloudflare"},
			content:  []string{"cloudflare", "cf-browser-verification", "cloudflare-nginx"},
			cookies:  []string{"__cfduid", "cf_clearance", "__cf_bm"},
			statuses: []int{403, 503},
		},
		"akamai": {
			name:     "Akamai",
			headers:  []string{"akamai", "x-akamai", "server: akamaighost"},
			content:  []string{"akamai"},
			cookies:  []string{"ak_bmsc", "_abck"},
			statuses: []int{403},
		},
		"incapsula": {
			name:     "Incapsula (Imperva)",
			headers:  []string{"x-iinfo", "x-cdn: incapsula", "server: ipfo"},
			content:  []string{"incapsula", "visid_incap", "incap_ses"},
			cookies:  []string{"incap_ses", "visid_incap"},
			statuses: []int{403},
		},
		"sucuri": {
			name:     "Sucuri",
			headers:  []string{"x-sucuri-id", "server: sucuri"},
			content:  []string{"sucuri", "sucuri firewall"},
			cookies:  []string{"sucuricp"},
			statuses: []int{403},
		},
		"awselb": {
			name:     "AWS WAF",
			headers:  []string{"x-amzn-requestid", "x-amzn-trace-id", "server: awselb"},
			content:  []string{"aws-waf", "amazonwaf"},
			cookies:  []string{"aws-waf-token"},
			statuses: []int{403, 503},
		},
		"bigip": {
			name:     "F5 BIG-IP",
			headers:  []string{"x-waf-event", "server: bigip", "server: f5"},
			content:  []string{"f5", "the requested url was rejected"},
			cookies:  []string{"bigipserver"},
			statuses: []int{403, 503},
		},
		"wordfence": {
			name:     "Wordfence",
			headers:  []string{"x-wf-event"},
			content:  []string{"wordfence", "your access to this site has been limited"},
			cookies:  []string{"wfvt", "wordfence"},
			statuses: []int{403, 503},
		},
		"modsecurity": {
			name:     "ModSecurity",
			headers:  []string{"x-mod-security", "server: mod_security"},
			content:  []string{"mod_security", "modsecurity", "not acceptable"},
			statuses: []int{403, 406},
		},
		"barracuda": {
			name:     "Barracuda",
			headers:  []string{"server: barracuda"},
			content:  []string{"barracuda", "you are blocked"},
			statuses: []int{403},
		},
		"fortinet": {
			name:     "Fortinet FortiWeb",
			headers:  []string{"server: fortigate"},
			content:  []string{"fortigate", "fortinet"},
			statuses: []int{403},
		},
	}

	for _, payload := range payloads {
		url := fmt.Sprintf("https://%s/%s", target, payload)
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		headers := resp.Header

		for _, indicator := range wafIndicators {
			// Check status codes
			for _, status := range indicator.statuses {
				if resp.StatusCode == status {
					return indicator.name
				}
			}

			// Check headers
			for _, h := range indicator.headers {
				parts := strings.SplitN(h, ": ", 2)
				if len(parts) == 2 {
					headerName, headerValue := parts[0], parts[1]
					if strings.Contains(strings.ToLower(headers.Get(headerName)), headerValue) {
						return indicator.name
					}
				} else {
					for k, v := range headers {
						if strings.Contains(strings.ToLower(k), h) || 
						   strings.Contains(strings.ToLower(strings.Join(v, "")), h) {
							return indicator.name
						}
					}
				}
			}

			// Check response body
			for _, content := range indicator.content {
				if strings.Contains(strings.ToLower(bodyStr), content) {
					return indicator.name
				}
			}

			// Check cookies
			for _, cookie := range indicator.cookies {
				for _, c := range headers["Set-Cookie"] {
					if strings.Contains(strings.ToLower(c), cookie) {
						return indicator.name
					}
				}
			}
		}

		// Generic WAF detection
		if resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 503 {
			if strings.Contains(bodyStr, "blocked") || 
			   strings.Contains(bodyStr, "forbidden") ||
			   strings.Contains(bodyStr, "security") ||
			   strings.Contains(bodyStr, "waf") {
				return "Generic WAF"
			}
		}
	}

	return ""
}