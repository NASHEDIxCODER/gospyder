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

	url := fmt.Sprintf("https://%s/?id=1 AND 1=1", target)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	indicators := map[string]string{
		"cloudflare": "Cloudflare", "akamai": "Akamai", "incapsula": "Incapsula",
		"sucuri": "Sucuri", "awselb": "AWS WAF", "bigip": "F5 BIG-IP",
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	for indicator, name := range indicators {
		for k, v := range resp.Header {
			if strings.Contains(strings.ToLower(k), indicator) || 
			   strings.Contains(strings.ToLower(strings.Join(v, "")), indicator) {
				return name
			}
		}
		if strings.Contains(strings.ToLower(bodyStr), indicator) {
			return name
		}
	}

	return ""
}