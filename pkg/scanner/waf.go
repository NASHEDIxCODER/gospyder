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

type WAFDetection struct {
	Name       string
	Confidence string
	Evidence   []string
}

func (ws *WAFScanner) Detect(ctx context.Context, target string) string {
	detection := ws.DetectDetailed(ctx, target)

	return detection.Name
}

func (ws *WAFScanner) DetectDetailed(ctx context.Context, target string) WAFDetection {
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
		for _, baseURL := range wafBaseURLs(target) {
			reqURL := baseURL + payload
			req, _ := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
			req.Header.Set("User-Agent", "Mozilla/5.0")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			// fmt.Println("URL:", reqURL)
			// fmt.Println("STATUS:", resp.StatusCode)
			// fmt.Println("SERVER:", resp.Header.Get("Server"))
			// fmt.Println("CF-RAY:", resp.Header.Get("CF-RAY"))
			// fmt.Println("CF-Cache-Status:", resp.Header.Get("CF-Cache-Status"))
			// fmt.Println("--------------------------------")
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			bodyStr := string(body)
			headers := resp.Header

			cloudflareScore := 0
			var cloudflareEvidence []string

			server := strings.ToLower(headers.Get("Server"))

			if strings.Contains(server, "cloudflare") {
				cloudflareScore += 50
				cloudflareEvidence = append(
					cloudflareEvidence,
					fmt.Sprintf("Server: %s", headers.Get("Server")),
				)
			}

			if headers.Get("CF-RAY") != "" {
				cloudflareScore += 50
				cloudflareEvidence = append(
					cloudflareEvidence,
					"CF-RAY header present",
				)
			}

			if headers.Get("CF-Cache-Status") != "" {
				cloudflareScore += 40
				cloudflareEvidence = append(
					cloudflareEvidence,
					"CF-Cache-Status header present",
				)
			}

			for _, cookie := range headers["Set-Cookie"] {
				lc := strings.ToLower(cookie)

				if strings.Contains(lc, "__cf_bm") ||
					strings.Contains(lc, "cf_clearance") ||
					strings.Contains(lc, "_cfuvid") {

					cloudflareScore += 40

					cloudflareEvidence = append(
						cloudflareEvidence,
						"Cloudflare cookie present",
					)
				}
			}

			// body mentions are weak evidence only
			if strings.Contains(bodyStr, "cf-browser-verification") {
				cloudflareScore += 20
				cloudflareEvidence = append(
					cloudflareEvidence,
					"Cloudflare browser verification page",
				)
			}

			if cloudflareScore >= 50 {
				confidence := "Medium"

				if cloudflareScore >= 90 {
					confidence = "High"
				}

				return WAFDetection{
					Name:       "Cloudflare",
					Confidence: confidence,
					Evidence:   cloudflareEvidence,
				}
			}

			for _, indicator := range wafIndicators {
				var evidence []string
				specificEvidence := false
				// Check status codes
				for _, status := range indicator.statuses {
					if resp.StatusCode == status {
						evidence = append(evidence, fmt.Sprintf("Status code %d", resp.StatusCode))
					}
				}

				// Check headers
				for _, h := range indicator.headers {
					parts := strings.SplitN(h, ": ", 2)
					if len(parts) == 2 {
						headerName, headerValue := parts[0], parts[1]
						if strings.Contains(strings.ToLower(headers.Get(headerName)), headerValue) {
							evidence = append(evidence, fmt.Sprintf("%s: %s", headerName, headers.Get(headerName)))
							specificEvidence = true
						}
					} else {
						for k, v := range headers {
							if strings.Contains(strings.ToLower(k), h) ||
								strings.Contains(strings.ToLower(strings.Join(v, "")), h) {
								evidence = append(evidence, fmt.Sprintf("%s: %s", k, strings.Join(v, ",")))
								specificEvidence = true
							}
						}
					}
				}

				// Check response body
				for _, content := range indicator.content {
					if strings.Contains(strings.ToLower(bodyStr), content) {
						evidence = append(evidence, fmt.Sprintf("Response body contains %q", content))
						specificEvidence = true
					}
				}

				// Check cookies
				for _, cookie := range indicator.cookies {
					for _, c := range headers["Set-Cookie"] {
						if strings.Contains(strings.ToLower(c), cookie) {
							evidence = append(evidence, fmt.Sprintf("Set-Cookie contains %q", cookie))
							specificEvidence = true
						}
					}
				}

				if specificEvidence {
					confidence := "Medium"
					if len(evidence) >= 2 {
						confidence = "High"
					}
					return WAFDetection{Name: indicator.name, Confidence: confidence, Evidence: evidence}
				}
			}

			// Generic WAF detection
			if resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 503 {
				lowerBody := strings.ToLower(bodyStr)
				if strings.Contains(lowerBody, "blocked") ||
					strings.Contains(lowerBody, "forbidden") ||
					strings.Contains(lowerBody, "security") ||
					strings.Contains(lowerBody, "waf") {
					return WAFDetection{
						Name:       "Generic WAF",
						Confidence: "Medium",
						Evidence: []string{
							fmt.Sprintf("Status code %d", resp.StatusCode),
							"Response body contains blocking/security language",
						},
					}
				}
			}
		}
	}

	return WAFDetection{}
}

func wafBaseURLs(target string) []string {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return []string{target}
	}
	return []string{"https://" + target, "http://" + target}
}
