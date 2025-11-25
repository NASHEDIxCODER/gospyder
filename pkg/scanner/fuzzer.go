package scanner

import (
	"context"
	"bufio"
	"fmt"
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

	client := &http.Client{
		Timeout: 3 * time.Second,
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

			if resp.StatusCode < 400 {
				mu.Lock()
				found = append(found, url)
				mu.Unlock()
			}
		}(path)
	}

	wg.Wait()
	return found
}