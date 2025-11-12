package scanner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

type SubdomainScanner struct{}

func (s *SubdomainScanner) Name() string {
	return "subdomain"
}

func (s *SubdomainScanner) Scan(ctx context.Context, domain string) ([]Result, error) {
	var results []Result
	var mu sync.Mutex
	var wg sync.WaitGroup

	// expand this list or load from file later
	wordlist := []string{"www", "api", "admin", "adm", "test", "dev", "main", "ftp"}

	client := &http.Client{
		Timeout: 5 * time.Second,
		// don't follow redirects automatically; we want to record 3xx
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// semaphore for concurrency
	semaphore := make(chan struct{}, 30)

	// helper: mark as found
	push := func(r Result) {
		mu.Lock()
		results = append(results, r)
		mu.Unlock()
	}

	for _, sub := range wordlist {
		wg.Add(1)
		go func(subdomain string) {
			defer wg.Done()

			// quick context check
			select {
			case <-ctx.Done():
				return
			default:
			}

			// first: DNS check to avoid many HTTP attempts
			fqdn := fmt.Sprintf("%s.%s", subdomain, domain)
			ips, err := net.LookupHost(fqdn)
			if err != nil || len(ips) == 0 {
				// no DNS A/AAAA records -> likely not present
				return
			}

			// acquire semaphore but respect ctx cancellation
			select {
			case semaphore <- struct{}{}:
				// acquired
			case <-ctx.Done():
				return
			}
			defer func() { <-semaphore }()

			// build request with context so cancellation propagates
			tryURLs := []string{
				fmt.Sprintf("https://%s", fqdn),
				fmt.Sprintf("http://%s", fqdn), // fallback if https fails
			}

			// set a simple user-agent to avoid some blocks
			for _, url := range tryURLs {
				// check once more if ctx cancelled before creating request
				if ctx.Err() != nil {
					return
				}
				req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
				if err != nil {
					continue
				}
				req.Header.Set("User-Agent", "gospyder/1.0 (+https://example.invalid)")

				resp, err := client.Do(req)
				if err != nil {
					// try next scheme (https -> http)
					continue
				}
				_ = resp.Body.Close()

				// treat 2xx, 3xx and common auth statuses as existence
				if (resp.StatusCode >= 200 && resp.StatusCode < 400) || resp.StatusCode == 401 || resp.StatusCode == 403 {
					push(Result{
						Vulnerability: "Exposed subdomain",
						Target:        url,
						Description:   fmt.Sprintf("status %d", resp.StatusCode),
						Severity:      "medium",
					})
					// if https succeeded we can stop trying http fallback
					return
				}
				// otherwise try next fallback (if any)
			}
		}(sub)
	}

	wg.Wait()
	return results, nil
}
