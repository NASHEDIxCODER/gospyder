package enum

import (
	"bufio"
	"context"
	"os"
	"strings"
	"sync"

	"github.com/NASHEDIxCODER/gospyder/pkg/models"
	"github.com/NASHEDIxCODER/gospyder/pkg/resolver"
)

func BruteForce(ctx context.Context, pool *resolver.Pool, target string, wordlist string) (<-chan models.Domain, error) {
	out := make(chan models.Domain, 100)

	file, err := os.Open(wordlist)
	if err != nil {
		return nil, err
	}

	go func() {
		defer close(out)
		defer file.Close()

		scanner := bufio.NewScanner(file)
		var wg sync.WaitGroup
		sem := make(chan struct{}, 500)

		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
			}

			sub := strings.TrimSpace(scanner.Text())
			if sub == "" || strings.HasPrefix(sub, "#") {
				continue
			}

			fullDomain := sub + "." + target
			wg.Add(1)

			go func(domain string) {
				defer wg.Done()

				sem <- struct{}{}
				defer func() { <-sem }()

				_, err := pool.Lookup(ctx, domain)
				if err == nil {
					out <- models.Domain{
						Name:   domain,
						Source: "brute",
					}
				}
			}(fullDomain)
		}

		wg.Wait()
	}()

	return out, nil
}