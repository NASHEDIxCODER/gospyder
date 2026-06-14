package scanner

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Fuzzer struct{}

func (f *Fuzzer) Scan(ctx context.Context, baseURL, wordlist string, threads int) []string {
	var found []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	file, err := os.Open(wordlist)
	if err != nil {
		return found
	}
	defer file.Close()

	// Create HTTP client with optimized transport
	transport := &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).Dial,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		MaxIdleConnsPerHost:   threads,
		DisableKeepAlives:     false,
		DisableCompression:    true,
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	sem := make(chan struct{}, threads)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return found
		default:
		}

		path := strings.TrimSpace(scanner.Text())
		if path == "" || strings.HasPrefix(path, "#") {
			continue
		}

		wg.Add(1)
		go func(p string) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			url := fmt.Sprintf("%s/%s", strings.TrimRight(baseURL, "/"), p)
			resp, err := client.Get(url)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			// Catch found pages (2xx, 3xx), auth pages (401, 403), and redirects
			switch resp.StatusCode {

			case 200, 204, 401, 403, 405:
				mu.Lock()
				found = append(found,
					fmt.Sprintf("%s [%d]", url, resp.StatusCode))
				mu.Unlock()
			}
		}(path)
	}

	wg.Wait()
	return found
}
